"""Stable event identities and lossless source observation merges."""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
import hashlib
import base64
import binascii
import json
import math
from typing import Any

from app.utils.security import sanitize_observation
from app.utils.ton_normalize import ton_canonical_address


def canonical_hash(value: Any) -> str:
    """Canonical TON hash only when it is actually a 256-bit identifier."""
    value = str(value or "").strip()
    stripped = value.removeprefix("0x")
    if len(stripped) == 64 and all(c in "0123456789abcdefABCDEF" for c in stripped):
        return stripped.lower()
    if len(value) in {43, 44}:
        try:
            decoded = base64.b64decode(value.replace("-", "+").replace("_", "/") + "=" * (-len(value) % 4), validate=True)
            if len(decoded) == 32:
                return decoded.hex()
        except (ValueError, binascii.Error):
            pass
    return ""


def address_key(chain: str, address: str | None) -> str:
    value = (address or "").strip()
    if chain == "ton":
        return ton_canonical_address(value) or value
    return value.lower() if chain in {"eth", "bsc", "polygon", "arbitrum", "optimism", "avalanche"} else value


def event_identity(item: Any) -> str:
    explicit = getattr(item, "event_id", None)
    if explicit:
        return str(explicit)
    raw = getattr(item, "raw", {}) or {}
    chain = getattr(item, "chain", "ton")
    tx_hash = str(getattr(item, "tx_hash", None) or raw.get("tx_hash") or "")
    if chain == "ton":
        action = raw.get("action") or {}
        stable_action = raw.get("action_id") or (action.get("action_id") if isinstance(action, dict) else None)
        if stable_action:
            return f"ton:action:{stable_action}:{getattr(item, 'asset', None) or ''}"
        # Native message observations from different account transactions are
        # one physical payment when the immutable message hash agrees. Actions
        # remain separate interpretations and cannot replace physical messages.
        is_action = raw.get("action_index") is not None or raw.get("asset_type") == "action" or raw.get("provider") == "tonapi_events"
        message = raw.get("message") or ((raw.get("transaction") or {}).get("in_msg") if raw.get("message_index") == "in" else {}) or {}
        message_hash = canonical_hash(message.get("hash") or message.get("msg_hash")) if isinstance(message, dict) else ""
        if message_hash and not is_action:
            return f"ton:message:{message_hash}:{getattr(item, 'asset', None) or 'TON'}"
        stripped = tx_hash.removeprefix("0x")
        if len(stripped) == 64 and all(c in "0123456789abcdefABCDEF" for c in stripped):
            tx_hash = stripped.lower()
        elif len(tx_hash) in {43, 44}:
            try:
                decoded = base64.b64decode(tx_hash.replace("-", "+").replace("_", "/") + "=" * (-len(tx_hash) % 4), validate=True)
                if len(decoded) == 32:
                    tx_hash = decoded.hex()
            except (ValueError, binascii.Error):
                pass
    indexes = {k: raw[k] for k in ("lt", "logical_time", "log_index", "logIndex", "action_index", "message_index", "instruction_index", "token_id", "tokenID", "query_id", "message_hash") if raw.get(k) is not None}
    for name in ("logical_time", "action_index"):
        if getattr(item, name, None) is not None:
            indexes[name] = getattr(item, name)
    basis = {"chain": chain, "tx": tx_hash, "indexes": indexes,
             "type": getattr(item, "event_type", None) or raw.get("action_type") or raw.get("type"),
             "from": address_key(chain, getattr(item, "from_address", None)), "to": address_key(chain, getattr(item, "to_address", None)),
             "contract": address_key(chain, getattr(item, "nft_address", None) or raw.get("contract") or raw.get("token_contract")),
             "asset": getattr(item, "asset", None), "amount": str(getattr(item, "amount_decimal", None) or getattr(item, "amount", None)),
             "price": str(getattr(item, "price", None))}
    if not tx_hash:
        basis["timestamp"] = str(getattr(item, "timestamp", None))
    encoded = json.dumps(basis, sort_keys=True, default=str, separators=(",", ":"))
    return f"{chain}:event:{hashlib.sha256(encoded.encode()).hexdigest()}"


def observation(item: Any) -> dict:
    raw = sanitize_observation(getattr(item, "raw", {}) or {})
    return {"source": getattr(item, "source", "unknown"), "url": sanitize_observation(getattr(item, "url", None) or getattr(item, "evidence_url", None)),
            "raw_digest": hashlib.sha256(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest(), "raw": raw}


def _native_json(value: Any, active: set[int] | None = None) -> bool:
    """Limit aggregate proofs to exact JSON types, never coercive equality."""
    kind = type(value)
    if value is None or kind in (bool, int, str):
        return True
    if kind is float:
        return math.isfinite(value)
    if kind not in (dict, list):
        return False
    active = set() if active is None else active
    identity = id(value)
    if identity in active:
        return False
    active.add(identity)
    try:
        if kind is dict:
            return all(type(key) is str and _native_json(child, active)
                       for key, child in value.items())
        return all(_native_json(child, active) for child in value)
    finally:
        active.remove(identity)


def _same_native_json(left: Any, right: Any) -> bool:
    """Compare already checked JSON values, preserving numeric type and -0.0."""
    kind = type(left)
    if kind is not type(right):
        return False
    if kind is dict:
        return left.keys() == right.keys() and all(
            _same_native_json(value, right[key]) for key, value in left.items())
    if kind is list:
        return len(left) == len(right) and all(
            _same_native_json(a, b) for a, b in zip(left, right))
    if kind is float and left == 0.0 and right == 0.0:
        return math.copysign(1.0, left) == math.copysign(1.0, right)
    return left == right


def _retained_observation_covers(item: Any, candidate: dict, retained: list) -> bool:
    """Do not label a later raw setdefault-union as another provider response.

    The item's own prior records must already contain its source/public URL
    context and either its exact body or the exact top-level union of their
    bodies. A new context, changed/deleted value or unsupported type still
    captures a new observation. Historical records are never changed/pruned.
    """
    if not retained:
        return False
    try:
        original = getattr(item, "raw", {}) or {}
        raw = candidate["raw"]
        if not _native_json(original) or not _native_json(raw):
            return False
        matching_context = []
        for entry in retained:
            if type(entry) is not dict:
                continue
            source, url = entry.get("source"), sanitize_observation(entry.get("url"))
            if (_native_json(source) and _native_json(url)
                    and _same_native_json(source, candidate["source"])
                    and _same_native_json(url, candidate["url"])):
                matching_context.append(entry)
        if not matching_context:
            return False
        bodies = [entry["raw"] for entry in retained
                  if type(entry) is dict and "raw" in entry]
        native_bodies = [_native_json(body) for body in bodies]
        if any("raw" in entry and _native_json(entry["raw"])
               and _same_native_json(raw, entry["raw"])
               for entry in matching_context):
            return True
        if type(raw) is not dict or not bodies or not all(native_bodies):
            return False
        union = {}
        for body in bodies:
            if type(body) is not dict:
                return False
            for key, value in body.items():
                union.setdefault(key, value)
        return _same_native_json(raw, union)
    except RecursionError:
        # Inability to prove coverage must never discard a new observation.
        return False


def merge_provenance(current: Any, other: Any | None = None) -> None:
    current_prior = list(getattr(current, "provenance", []) or [])
    entries = list(current_prior)
    candidate = observation(current)
    if not _retained_observation_covers(current, candidate, current_prior):
        entries.append(candidate)
    if other is not None:
        other_prior = list(getattr(other, "provenance", []) or [])
        entries.extend(other_prior)
        candidate = observation(other)
        if not _retained_observation_covers(other, candidate, other_prior):
            entries.append(candidate)
    unique = {json.dumps(e, sort_keys=True, default=str): e for e in entries}
    if hasattr(current, "provenance"):
        current.provenance = list(unique.values())
    if other is not None:
        for key, value in (getattr(other, "raw", {}) or {}).items():
            current.raw.setdefault(key, value)


def decimal_amount(item: Any) -> Decimal | None:
    value = getattr(item, "amount_decimal", None)
    if value is None:
        value = getattr(item, "amount", None)
    try:
        amount = Decimal(str(value))
        return amount if amount.is_finite() else None
    except (InvalidOperation, ValueError, TypeError):
        return None


def transaction_success(item: Any) -> bool | None:
    value = getattr(item, "success", None)
    if value is not None:
        return value
    raw = getattr(item, "raw", {}) or {}
    if str(raw.get("is_error") or "") == "1" or raw.get("success") is False:
        return False
    status = str(raw.get("status") or raw.get("transaction_status") or "").lower()
    if status in {"failed", "failure", "error", "reverted", "fail"}:
        return False
    return True if status in {"ok", "success", "successful"} or raw.get("success") is True else None
