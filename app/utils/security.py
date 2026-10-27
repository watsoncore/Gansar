"""Shared boundaries for untrusted provider observations and public URLs."""
from __future__ import annotations

import asyncio
from collections import OrderedDict
import ipaddress
import re
import socket
import json
import unicodedata
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SECRET_KEYS = re.compile(r"(?:api[_-]?key|authorization|access[_-]?token|auth[_-]?token|authClientToken|password|passwd|private[_-]?key|secret|seed[_-]?phrase|mnemonic)", re.I)
_SECRET_TEXT = re.compile(r"(?i)(\b(?:api[_-]?key|access[_-]?token|authorization|authClientToken|password|secret)\s*[=:]\s*)([^\s&,;\"']+)")
_BEARER_TEXT = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_OBSERVATION_URL = re.compile(r"https?://[^\s<>\"']+")
_DEEP_TAIL_ENCODING = "json_deep_provider_tail"
_DEEP_TAIL_DECODE_DEPTH = 512
_TEXT_CACHE_ENTRIES = 2048


def _deep_tail_payload(value: Any) -> dict | list | None:
    """Recognize only the exact codec emitted at the portable model boundary."""
    if (type(value) is not dict or len(value) != 2
            or any(type(key) is not str for key in value)
            or value.keys() != {"_gansar_encoding", "json"}
            or type(value["_gansar_encoding"]) is not str
            or value["_gansar_encoding"] != _DEEP_TAIL_ENCODING
            or type(value["json"]) is not str):
        return None
    duplicate_key = False

    def object_pairs(pairs):
        nonlocal duplicate_key
        result = {}
        for key, child in pairs:
            if key in result:
                duplicate_key = True
            result[key] = child
        return result

    def invalid_constant(value):
        raise ValueError("Non-JSON constant in provider-tail codec")

    try:
        payload = json.loads(value["json"], object_pairs_hook=object_pairs,
                             parse_constant=invalid_constant)
    except (ValueError, RecursionError):
        # Malformed, non-JSON or deeper-than-parser input keeps the ordinary
        # observation path; a provider cannot grant itself an opaque bypass.
        return None
    if duplicate_key or type(payload) not in (dict, list):
        return None
    # Some JSON accelerators accept nesting beyond Python's traversal limit.
    # Inspect iteratively before recursively redacting decoded codec contents.
    # Ineligible payloads remain ordinary strings, with every byte retained.
    pending = [(payload, 0)]
    while pending:
        current, depth = pending.pop()
        if type(current) in (dict, list):
            if depth >= _DEEP_TAIL_DECODE_DEPTH:
                return None
            pending.extend((child, depth + 1) for child in
                           (current.values() if type(current) is dict else current)
                           if type(child) in (dict, list))
    return payload


def sanitize_url(value: str) -> str:
    """Remove credentials and secret query values without losing public evidence paths."""
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.netloc:
            return value
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        if parts.port:
            host += f":{parts.port}"
        query = urlencode([(k, "[REDACTED]" if _SECRET_KEYS.search(k) else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)])
        return urlunsplit((parts.scheme, host, parts.path, query, parts.fragment))
    except ValueError:
        return "[INVALID URL]"


def sanitize_observation(value: Any) -> Any:
    """Return a secret-free copy; leave numeric/datetime objects intact."""
    # Provider histories repeat the same schema keys and short immutable strings.
    # Cache only pure checks within this call; never retain observations globally
    # or share mutable output containers. Full traversal/redaction is unchanged.
    key_checks: dict[str, bool] = {}
    text_results: OrderedDict[str, str] = OrderedDict()

    def visit_encoded_tail(original, payload):
        # Each JSON payload is bounded, but historical codecs can themselves
        # contain codecs. Walk those decoded trees without adding Python call
        # depth for each wrapper, preserving their original strings unless a
        # descendant actually needs redaction.
        result = {"_gansar_encoding": _DEEP_TAIL_ENCODING, "json": original["json"]}
        decoded = [None]
        changed = 0
        pending = [("finish", result, original["json"], decoded, 0),
                   ("visit", payload, decoded, 0)]
        while pending:
            task = pending.pop()
            if task[0] == "finish":
                _, output, encoded, decoded, before = task
                if changed != before:
                    output["json"] = json.dumps(decoded[0], ensure_ascii=False,
                                                default=str, separators=(",", ":"))
                continue
            _, current, parent, key = task
            if type(current) is dict:
                nested = _deep_tail_payload(current)
                if nested is not None:
                    output = {"_gansar_encoding": _DEEP_TAIL_ENCODING, "json": current["json"]}
                    parent[key] = output
                    decoded = [None]
                    pending.append(("finish", output, current["json"], decoded, changed))
                    pending.append(("visit", nested, decoded, 0))
                    continue
                output = {name: None for name in current}
                parent[key] = output
                for name, child in reversed(current.items()):
                    secret = key_checks.get(name)
                    if secret is None:
                        secret = bool(_SECRET_KEYS.search(name))
                        if len(key_checks) < 512:
                            key_checks[name] = secret
                    if secret:
                        output[name] = "[REDACTED]"
                        if child != "[REDACTED]":
                            changed += 1
                    else:
                        pending.append(("visit", child, output, name))
            elif type(current) is list:
                output = [None] * len(current)
                parent[key] = output
                pending.extend(("visit", child, output, index)
                               for index, child in reversed(list(enumerate(current))))
            else:
                clean = visit(current)
                parent[key] = clean
                if clean != current:
                    changed += 1
        return result

    def visit(item):
        if isinstance(item, dict):
            tail = _deep_tail_payload(item)
            if tail is not None:
                # The marker can be supplied by a provider too. Inspect its
                # decoded JSON with the same redaction, including older nested
                # codecs, before retaining the opaque representation. Preserve
                # already-safe public bytes (and historical wrapper layers).
                return visit_encoded_tail(item, tail)
            result = {}
            for key, child in item.items():
                name = str(key)
                secret = key_checks.get(name)
                if secret is None:
                    secret = bool(_SECRET_KEYS.search(name))
                    if len(key_checks) < 512:
                        key_checks[name] = secret
                result[name] = "[REDACTED]" if secret else visit(child)
            return result
        if isinstance(item, (list, tuple)):
            return [visit(child) for child in item]
        if isinstance(item, str):
            cacheable = len(item) <= 4096
            if cacheable:
                cached = text_results.get(item)
                if cached is not None:
                    text_results.move_to_end(item)
                    return cached
            clean = _BEARER_TEXT.sub("Bearer [REDACTED]", item)
            clean = _SECRET_TEXT.sub(r"\1[REDACTED]", clean)
            clean = _OBSERVATION_URL.sub(lambda match: sanitize_url(match.group()), clean)
            if cacheable and _TEXT_CACHE_ENTRIES > 0:
                if len(text_results) >= _TEXT_CACHE_ENTRIES:
                    text_results.popitem(last=False)
                text_results[item] = clean
            return clean
        return item

    try:
        return visit(value)
    finally:
        key_checks.clear()
        text_results.clear()


def portable_observation(value: Any, *, max_depth: int = 48) -> Any:
    """Preserve deeply decoded provider cells without exceeding model depth.

    Toncenter can decode linked TVM action cells into hundreds of nested `prev`
    objects. The JSON tree is acyclic but exceeds pydantic's serializer limit.
    Encode only such deep tails as redacted JSON strings with an explicit codec;
    every original field/value remains recoverable, rather than dropping data.
    """
    clean = sanitize_observation(value)
    def visit(item, depth):
        if _deep_tail_payload(item) is not None:
            # A prior model validation already bounded this subtree. Wrapping
            # its JSON string again doubles escaping at the same report path.
            return item
        if isinstance(item, (dict, list, tuple)) and depth >= max_depth:
            return {"_gansar_encoding": _DEEP_TAIL_ENCODING,
                    "json": json.dumps(item, ensure_ascii=False, default=str, separators=(",", ":"))}
        if isinstance(item, dict):
            # sanitize_observation already owns this detached container tree.
            # Bound its depth without allocating a second full set of copies.
            for key, child in item.items():
                item[key] = visit(child, depth+1)
            return item
        if isinstance(item, list):
            for index, child in enumerate(item):
                item[index] = visit(child, depth+1)
            return item
        if isinstance(item, tuple):
            return [visit(child, depth+1) for child in item]
        return item
    return visit(clean, 0)


def safe_public_url(value: Any, *, allow_ipfs: bool = False) -> str | None:
    """Lexical URL guard for rendering. Network consumers must also resolve DNS."""
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value) or "\\" in value:
        return None
    try:
        parts = urlsplit(value.strip())
        if allow_ipfs and parts.scheme == "ipfs" and parts.netloc and not parts.username:
            return value.strip()
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
            return None
        host = parts.hostname.rstrip(".").lower()
        if "%" in host:
            return None
        # Match browser/IDNA host interpretation before checking private IPs.
        host = unicodedata.normalize("NFKC", host).encode("idna").decode("ascii").lower().rstrip(".")
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan")) or "." not in host and ":" not in host:
            return None
        try:
            if not ipaddress.ip_address(host).is_global:
                return None
        except ValueError:
            # Browsers and OS resolvers may interpret non-canonical numeric IPv4
            # forms (octal/hex/shortened) as loopback even when ipaddress rejects it.
            if all(c in "0123456789.xabcdef" for c in host) and any(c.isdigit() for c in host):
                return None
        if parts.port is not None and not 1 <= parts.port <= 65535:
            return None
        return value.strip()
    except ValueError:
        return None


async def validate_public_url(value: str) -> str:
    """Reject private/loopback/link-local targets, including DNS aliases."""
    url = safe_public_url(value)
    if not url:
        raise ValueError("URL must use HTTP(S) and a public host without credentials")
    parts = urlsplit(url)
    addresses = await asyncio.get_running_loop().getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
        raise ValueError("URL resolved to a non-public address")
    return url
