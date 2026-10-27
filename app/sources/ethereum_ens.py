from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import ipaddress
import json
import os
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, unquote_to_bytes, urljoin, urlsplit

import httpx
from ens_normalize import ens_normalize

from app.models.report import AddressReport, SourceHealth
from app.sources.base import Source
from app.utils.http import request_json, request_public_json, shared_async_client
from app.utils.keccak import keccak_256
from app.utils.security import safe_public_url, validate_public_url


ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
TEXT_RECORD_KEYS = (
    "avatar", "description", "url", "header", "com.github", "com.twitter",
    "com.x", "org.telegram", "com.telegram", "telegram", "email",
    "com.discord", "com.reddit", "org.reddit", "com.linkedin",
    "com.instagram", "com.youtube", "com.keybase", "notice", "keywords",
    "location", "display", "pronouns",
)
# SLIP-44 and ENSIP-11 types. Non-EVM formats are preserved as raw bytes;
# they are never guessed to be wallets controlled by the queried address.
ADDRESS_RECORD_TYPES = (
    (0, "btc"), (2, "ltc"), (3, "doge"), (60, "eth"),
    (118, "cosmos"), (195, "tron"), (501, "solana"), (607, "ton"),
    (0x80000000 | 10, "optimism"), (0x80000000 | 56, "bsc"),
    (0x80000000 | 137, "polygon"), (0x80000000 | 8453, "base"),
    (0x80000000 | 42161, "arbitrum"), (0x80000000 | 43114, "avalanche"),
)
MAX_RPC_CALLS = 80
MAX_TEXT_BYTES = 8192
MAX_ABI_BYTES = 131072
MAX_METADATA_BYTES = 262144


@dataclass
class _Lookup:
    client: httpx.AsyncClient
    rpc_url: str
    out: AddressReport
    block: str = "latest"
    rpc_calls: int = 0
    ccip_calls: int = 0
    ccip_verified: int = 0
    failure_status: str | None = None
    text_keys: list[str] = field(default_factory=list)
    coin_types: list[int] = field(default_factory=list)
    unavailable_methods: list[str] = field(default_factory=list)
    slots: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(4))
    retrieved_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolutions: dict[str, tuple[str, str, bool] | None] = field(default_factory=dict)


class EthereumEnsSource(Source):
    """ENS context using the existing public Ethereum RPC transport.

    Resolver publications, registration ownership, and verified primary names
    are separate claims. Social/address records do not prove common ownership.
    """
    name = "ethereum_ens"
    chain = "eth"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    def _rpc_url(self) -> str:
        return (os.getenv("ETHEREUM_RPC_URL") or os.getenv("GANSAR_ETHEREUM_RPC_URL")
                or os.getenv("WEB3_PROVIDER_URI") or "https://ethereum.publicnode.com").strip()

    async def resolve_name(self, name: str) -> AddressReport:
        return await self.fetch(name)

    async def fetch(self, address: str) -> AddressReport:
        target = address.strip()
        out = AddressReport(target_address=target, detected_chains=["eth"], sources_used=[self.name])
        profile: dict[str, Any] = {"lookup_status": "empty", "source": self.name,
            "retrieved_at": datetime.now(timezone.utc).isoformat(), "source_address": target,
            "coverage": {"rpc_calls": 0, "max_rpc_calls": MAX_RPC_CALLS, "max_concurrent_rpc": 4}}
        out.ens_profile = profile
        input_name = None
        if not ETH_RE.fullmatch(target):
            try:
                input_name = normalize_name(target)
                if not input_name.endswith(".eth"):
                    raise ValueError("input must be an Ethereum address or .eth name")
                profile["input_name"] = input_name
            except ValueError:
                self._warn(out, "invalid Ethereum address or ENS name")
                self._health(out, "error", "invalid address or ENS name")
                return out
        rpc_url = self._rpc_url()
        if not rpc_url:
            self._health(out, "skipped", "provider missing")
            return out
        lookup = None
        try:
            async with shared_async_client(min(self._timeout, 10.0)) as client:
                lookup = _Lookup(client, rpc_url, out)
                chain_response = await self._rpc(lookup, "eth_chainId", [])
                if chain_response.get("result") != "0x1":
                    raise ValueError("ENS provider must be Ethereum mainnet")
                block_response = await self._rpc(lookup, "eth_blockNumber", [])
                block = block_response.get("result")
                if not isinstance(block, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", block):
                    raise ValueError("provider did not return a snapshot block")
                lookup.block = block
                profile["provenance"] = {"network": "ethereum-mainnet", "chain_id": 1,
                    "block_number": int(block, 16), "block_tag": block,
                    "provider_host": urlsplit(rpc_url).hostname, "registry": ENS_REGISTRY,
                    "method": "eth_call", "verification": "onchain_resolver_response_via_provider",
                    "record_verification": "self_published_profile_record", "ownership_claim": False}
                reverse_avatar = None
                profile_name = input_name
                forward = None
                if input_name:
                    forward = await self._forward(lookup, input_name)
                    if forward:
                        target = forward
                        out.target_address = target
                        out.ens_name = input_name
                        out.ens_resolved_address = forward
                if ETH_RE.fullmatch(target):
                    reverse_name = f"{target[2:].lower()}.addr.reverse"
                    reverse_context = await self._find_resolver(lookup, reverse_name)
                    if reverse_context:
                        out.ens_reverse_resolver = reverse_context[0]
                        reverse_record, reverse_avatar = await asyncio.gather(
                            self._record_string(lookup, reverse_name, reverse_context, "name", ""),
                            self._record_string(lookup, reverse_name, reverse_context, "text", "avatar"))
                        candidate = self._clean_name(reverse_record)
                        if reverse_record and not candidate:
                            self._warn(out, "reverse record contains an invalid ENS name")
                        if candidate:
                            out.reverse_ens = candidate
                            resolved = forward if candidate == input_name else await self._forward(lookup, candidate)
                            out.ens_reverse_valid = bool(resolved and resolved.lower() == target.lower())
                            if out.ens_reverse_valid and not input_name:
                                profile_name = candidate
                                out.ens_name = candidate
                                out.ens_resolved_address = resolved
                            elif not out.ens_reverse_valid:
                                self._warn(out, f"reverse mismatch: {candidate} resolves to {resolved or 'unavailable'}")
                if profile_name:
                    context = await self._find_resolver(lookup, profile_name)
                    if context:
                        out.resolver = context[0]
                        out.ens_owner = await self._registry_address(lookup, "owner", namehash(profile_name))
                    # An unverified reverse name must not supply another name's
                    # text/avatar records as the queried wallet's profile.
                    if context and (input_name or out.ens_reverse_valid):
                        out.text_records, addresses = await asyncio.gather(
                            self._text_records(lookup, profile_name, context),
                            self._address_records(lookup, profile_name, context))
                        profile.update({"name": profile_name, "input_name": input_name,
                            "resolved_address": out.ens_resolved_address, "resolver": out.resolver,
                            "resolver_name": context[1], "resolution_method": "ensip10" if context[2] else "registry_resolver",
                            "registry_owner": out.ens_owner,
                            "registry_owner_role": "registry owner/controller; may be a wrapper contract",
                            "primary_name": out.reverse_ens if out.ens_reverse_valid else None,
                            "primary_verified": bool(out.ens_reverse_valid and out.reverse_ens == profile_name),
                            "forward_verified": bool(out.ens_resolved_address),
                            "records": dict(out.text_records), "addresses": addresses,
                            "source_url": _name_url(profile_name), "source_address": target})
                forward_avatar = out.text_records.get("avatar") if input_name or out.ens_reverse_valid else None
                avatar_record = forward_avatar if input_name else reverse_avatar or forward_avatar
                if avatar_record:
                    avatar = await self._avatar(lookup, avatar_record, target if ETH_RE.fullmatch(target) else None)
                    avatar["record_source"] = "reverse" if not input_name and reverse_avatar else "forward"
                    await self._avatar_thumbnail(lookup, avatar)
                    profile["avatar"] = avatar
                    out.avatar = avatar.get("url")
                self._health(out, lookup.failure_status or ("partial" if out.ens_warnings else "ok"),
                    f"found {out.ens_name}" if out.ens_name else "no verified primary name")
        except asyncio.CancelledError:
            raise
        except httpx.TimeoutException:
            self._warn(out, "rpc timeout")
            out.errors.append(f"{self.name}: timeout")
            self._health(out, "timeout", "rpc timeout; collected fields retained")
        except httpx.HTTPStatusError as exc:
            self._warn(out, f"rpc HTTP {exc.response.status_code}")
            self._health(out, "rate_limited" if exc.response.status_code == 429 else "unavailable", "public provider unavailable; no retry")
        except (httpx.HTTPError, ValueError):
            # Configured URLs/API credentials must never enter diagnostics.
            self._warn(out, "ENS lookup unavailable or malformed provider response")
            self._health(out, lookup.failure_status if lookup and lookup.failure_status else "error", "lookup unavailable; collected fields retained")
        profile["coverage"] = {"text_keys_queried": lookup.text_keys if lookup else [],
            "address_coin_types_queried": lookup.coin_types if lookup else [],
            "record_enumeration": "bounded known keys; arbitrary text keys are not enumerable through resolver calls",
            "ccip_read": "bounded HTTPS GET gateways; callback verified onchain; POST-only gateways unavailable",
            "rpc_calls": lookup.rpc_calls if lookup else 0, "ccip_gateway_calls": lookup.ccip_calls if lookup else 0,
            "rpc_call_count_semantics": "logical calls; shared cache/inflight reuse can avoid network requests",
            "cache_policy": "existing shared public RPC cache; block tag identifies the returned snapshot",
            "ccip_callbacks_verified": lookup.ccip_verified if lookup else 0,
            "unavailable_optional_methods": list(dict.fromkeys(lookup.unavailable_methods)) if lookup else [],
            "max_rpc_calls": MAX_RPC_CALLS, "max_concurrent_rpc": 4}
        return out

    async def _forward(self, lookup: _Lookup, name: str) -> str | None:
        context = await self._find_resolver(lookup, name)
        if not context:
            return None
        result = await self._record(lookup, name, context, "0x3b3b57de" + namehash(name), "addr")
        return self._decode_address(result, lookup.out, "addr")

    async def _find_resolver(self, lookup: _Lookup, name: str) -> tuple[str, str, bool] | None:
        if name in lookup.resolutions:
            return lookup.resolutions[name]
        labels = name.split(".")
        for index in range(len(labels) + 1):
            parent = ".".join(labels[index:])
            resolver = await self._registry_address(lookup, "resolver", namehash(parent))
            if not resolver:
                continue
            result = await self._eth_call(lookup, resolver, "0x01ffc9a7" + "9061b923".ljust(64, "0"), "supportsENSIP10")
            extended = bool(result and len(result) == 66 and int(result[2:], 16) == 1)
            if parent != name and not extended:
                self._warn(lookup.out, "parent resolver does not support ENSIP-10 wildcard resolution")
                lookup.resolutions[name] = None
                return None
            context = (resolver, parent, extended)
            lookup.resolutions[name] = context
            return context
        lookup.resolutions[name] = None
        return None

    async def _record(self, lookup: _Lookup, name: str, context: tuple[str, str, bool], data: str, label: str) -> str | None:
        if not context[2]:
            return await self._eth_call(lookup, context[0], data, label)
        encoded = "0x9061b923" + _abi_dynamic(_dns_encode(name), bytes.fromhex(data[2:])).hex()
        raw = self._decode_bytes(await self._eth_call(lookup, context[0], encoded, label), lookup.out, label)
        return "0x" + raw.hex() if raw is not None else None

    async def _record_string(self, lookup: _Lookup, name: str, context: tuple[str, str, bool], method: str, key: str) -> str | None:
        data = "0x691f3431" + namehash(name) if method == "name" else _text_call_data(namehash(name), key)
        label = "name" if method == "name" else "text:" + key
        return self._decode_string(await self._record(lookup, name, context, data, label), lookup.out, label)

    async def _text_records(self, lookup: _Lookup, name: str, context: tuple[str, str, bool]) -> dict[str, str]:
        async def load(key):
            if not lookup.failure_status:
                lookup.text_keys.append(key)
            return key, await self._record_string(lookup, name, context, "text", key)
        return {key: value for key, value in await asyncio.gather(*(load(key) for key in TEXT_RECORD_KEYS)) if value}

    async def _address_records(self, lookup: _Lookup, name: str, context: tuple[str, str, bool]) -> list[dict[str, Any]]:
        async def load(coin: int, chain: str):
            if not lookup.failure_status:
                lookup.coin_types.append(coin)
            data = "0xf1cb7e06" + namehash(name) + f"{coin:064x}"
            raw = self._decode_bytes(await self._record(lookup, name, context, data, f"addr:{coin}"), lookup.out, f"addr:{coin}")
            if not raw or not any(raw):
                return None
            evm = coin == 60 or coin >= 0x80000000
            return {"coin_type": coin, "chain": chain, "value": "0x" + raw.hex(),
                "encoding": "evm_address" if evm and len(raw) == 20 else "raw_bytes_hex",
                "verification": "self_published_address_record", "method": "addr(bytes32,uint256)",
                "resolver": context[0], "name": name, "retrieved_at": lookup.retrieved_at,
                "source_url": _name_url(name), "ownership_claim": False}
        return [item for item in await asyncio.gather(*(load(*pair) for pair in ADDRESS_RECORD_TYPES)) if item]

    async def _registry_address(self, lookup: _Lookup, method: str, node: str) -> str | None:
        selector = "0178b8bf" if method == "resolver" else "02571be3"
        return self._decode_address(await self._eth_call(lookup, ENS_REGISTRY, "0x" + selector + node, method), lookup.out, method)

    async def _rpc(self, lookup: _Lookup, method: str, params: list) -> dict:
        async with lookup.slots:
            if lookup.failure_status:
                return {"result": "0x"}
            if lookup.rpc_calls >= MAX_RPC_CALLS:
                lookup.failure_status = "partial"
                self._warn(lookup.out, "ENS request budget exceeded; remaining calls skipped")
                return {"result": "0x"}
            lookup.rpc_calls += 1
            try:
                response = await request_json(lookup.client, "POST", lookup.rpc_url,
                    json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, retries=0)
            except httpx.HTTPStatusError as exc:
                lookup.failure_status = "rate_limited" if exc.response.status_code == 429 else "unavailable"
                self._warn(lookup.out, f"rpc HTTP {exc.response.status_code}; remaining ENS calls skipped")
                return {"result": "0x"}
            except httpx.HTTPError as exc:
                lookup.failure_status = "timeout" if isinstance(exc, httpx.TimeoutException) else "unavailable"
                self._warn(lookup.out, f"rpc {lookup.failure_status}; remaining ENS calls skipped")
                return {"result": "0x"}
        if not isinstance(response, dict):
            lookup.failure_status = "unavailable"
            self._warn(lookup.out, "malformed RPC response; remaining calls skipped")
            return {"result": "0x"}
        return response

    async def _eth_call(self, lookup: _Lookup, to: str, data: str, label: str, depth: int = 0) -> str | None:
        response = await self._rpc(lookup, "eth_call", [{"to": to, "data": data}, lookup.block])
        error = response.get("error")
        if isinstance(error, dict):
            error_data = error.get("data")
            if isinstance(error_data, dict):
                error_data = error_data.get("data") or error_data.get("result")
            if isinstance(error_data, str) and error_data.startswith("0x556f1830"):
                return await self._ccip_read(lookup, to, error_data, label, depth)
            message = str(error.get("message") or error.get("code") or "rpc error")
            execution_failure = any(part in message.lower() for part in ("revert", "invalid opcode", "invalidfeopcode"))
            if execution_failure:
                lookup.unavailable_methods.append(f"{to}:{label}")
            else:
                self._warn(lookup.out, f"{label}: RPC error {error.get('code', 'unknown')}")
            return None
        result = response.get("result")
        if not isinstance(result, str) or not re.fullmatch(r"0x[0-9a-fA-F]*", result) or len(result) > MAX_ABI_BYTES * 2 + 2:
            self._warn(lookup.out, f"{label}: malformed or oversized RPC result")
            return None
        return result

    async def _avatar_thumbnail(self, lookup: _Lookup, avatar: dict[str, Any]) -> None:
        """Optional real raster thumbnail for safe offline report rendering."""
        url = avatar.get("url")
        if not url:
            return
        avatar["thumbnail_status"] = "unavailable"
        try:
            if url.startswith("data:image/"):
                raw = _data_uri_bytes(url, 1_000_000)
                media_type = url.partition(";")[0][5:]
            else:
                async with asyncio.timeout(min(self._timeout, 6.0)):
                    raw, media_type = await _public_image_bytes(lookup.client, url)
            thumbnail = await asyncio.to_thread(_thumbnail_png, raw)
            avatar.update({"thumbnail": thumbnail, "thumbnail_status": "available",
                "media_provenance": {"source_url": url if not url.startswith("data:") else "inline ENS avatar record",
                    "retrieved_at": datetime.now(timezone.utc).isoformat(), "source_bytes": len(raw),
                    "source_content_type": media_type, "source_sha256": hashlib.sha256(raw).hexdigest(),
                    "thumbnail_sha256": hashlib.sha256(base64.b64decode(thumbnail.partition(",")[2])).hexdigest(),
                    "transformation": "original public raster resized within 192x192; PNG; no generated pixels",
                    "verification": avatar.get("verification"), "ownership_claim": False}})
        except (TimeoutError, httpx.HTTPError, ValueError, OSError, ImportError):
            avatar["thumbnail_reason"] = "public image unavailable, unsafe, unsupported or exceeds limits"

    async def _ccip_read(self, lookup: _Lookup, to: str, error_data: str, label: str, depth: int) -> str | None:
        if depth >= 2 or lookup.ccip_calls >= 6:
            self._warn(lookup.out, f"{label}: CCIP-read limit reached")
            return None
        try:
            raw = _hex_bytes(error_data[10:])
            if len(raw) < 160 or any(raw[:12]) or "0x" + raw[12:32].hex() != to.lower():
                raise ValueError("OffchainLookup sender mismatch")
            array_offset = _word(raw, 32)
            count = _word(raw, array_offset)
            if count > 8:
                raise ValueError("CCIP gateway list too large")
            urls = [_dynamic_bytes(raw, array_offset + 32 + _word(raw, array_offset + 32 + 32 * i)).decode("utf-8") for i in range(count)]
            call_data = "0x" + _dynamic_bytes(raw, _word(raw, 64)).hex()
            callback, extra = raw[96:100], _dynamic_bytes(raw, _word(raw, 128))
            for template in urls[:3]:
                # GET-only subset. Existing metadata transport validates and
                # pins DNS on every hop, limits bytes and follows two redirects.
                if (len(template) > 2048 or template.count("{data}") != 1
                        or template.count("{sender}") > 1 or len(call_data) > 16384):
                    continue
                url = template.replace("{sender}", to.lower()).replace("{data}", call_data)
                if len(url) > 8192 or not _https_url(url) or lookup.ccip_calls >= 6:
                    continue
                lookup.ccip_calls += 1
                try:
                    async with lookup.slots:
                        payload = await request_public_json(lookup.client, url, max_bytes=65536, max_redirects=2, https_only=True)
                    response_data = payload.get("data") if isinstance(payload, dict) else None
                    if not isinstance(response_data, str) or not response_data.startswith("0x"):
                        continue
                    callback_data = "0x" + callback.hex() + _abi_dynamic(_hex_bytes(response_data[2:]), extra).hex()
                    result = await self._eth_call(lookup, to, callback_data, label + ":ccip_callback", depth + 1)
                    if result is not None:
                        lookup.ccip_verified += 1
                        return result
                except (ValueError, httpx.HTTPError):
                    continue
            self._warn(lookup.out, f"{label}: CCIP-read gateway unavailable or POST-only")
        except (ValueError, UnicodeError, IndexError):
            self._warn(lookup.out, f"{label}: invalid CCIP-read request")
        return None

    async def _avatar(self, lookup: _Lookup, record: str, owner_address: str | None) -> dict[str, Any]:
        result: dict[str, Any] = {"record": record, "status": "unavailable", "method": "ensip12"}
        url = media_url(record)
        if url:
            result.update({"url": url, "status": "resolved", "verification": "self_published_profile_record"})
            return result
        nft = re.fullmatch(r"eip155:(\d+)/(erc721|erc1155):(0x[a-fA-F0-9]{40})/(\d+)", record)
        if not nft:
            result["reason"] = "unsupported or unsafe avatar URI"
            return result
        chain, standard, contract, token = nft.groups()
        if chain != "1" or len(token) > 78 or int(token) >= 2**256 or not owner_address:
            result["reason"] = "NFT avatar requires supported mainnet chain and resolved address"
            return result
        token_id = int(token)
        result["nft"] = {"chain_id": 1, "standard": standard, "contract": contract, "token_id": token}
        result["ownership_verified"] = False
        try:
            if standard == "erc721":
                owned = self._decode_address(await self._eth_call(lookup, contract, "0x6352211e" + f"{token_id:064x}", "avatar:ownerOf"), lookup.out, "avatar:ownerOf")
                verified = bool(owned and owned.lower() == owner_address.lower())
                selector = "c87b56dd"
            else:
                balance = await self._eth_call(lookup, contract, "0x00fdd58e" + owner_address[2:].lower().zfill(64) + f"{token_id:064x}", "avatar:balanceOf")
                verified = bool(balance and len(balance) == 66 and int(balance[2:], 16) > 0)
                selector = "0e89341c"
            result["ownership_verified"] = verified
            if not verified:
                result["reason"] = "NFT ownership did not verify for resolved address"
                return result
            metadata_record = self._decode_string(await self._eth_call(lookup, contract, "0x" + selector + f"{token_id:064x}", "avatar:metadataURI"), lookup.out, "avatar:metadataURI")
            if not metadata_record:
                result["reason"] = "NFT metadata URI unavailable"
                return result
            if standard == "erc1155":
                metadata_record = metadata_record.replace("{id}", f"{token_id:064x}")
            result["metadata_uri"] = metadata_record
            if metadata_record.startswith("data:application/json"):
                metadata = json.loads(_data_uri_bytes(metadata_record, MAX_METADATA_BYTES))
            else:
                metadata_url = media_url(metadata_record, allow_data=False)
                if not metadata_url:
                    raise ValueError("unsafe metadata URI")
                metadata = await request_public_json(lookup.client, metadata_url, max_bytes=MAX_METADATA_BYTES, max_redirects=2, https_only=True)
            image = media_url(metadata.get("image")) if isinstance(metadata, dict) else None
            if image:
                result.update({"url": image, "status": "resolved", "verification": "nft_owner_verified_via_provider"})
            else:
                result["reason"] = "NFT metadata image unavailable or unsafe"
        except (httpx.HTTPError, ValueError, TypeError, UnicodeError):
            result["reason"] = "NFT metadata unavailable, malformed or exceeds limits"
        return result

    def _decode_address(self, result: str | None, out: AddressReport, label: str) -> str | None:
        if not result or result == "0x":
            return None
        try:
            raw = _hex_bytes(result[2:])
            if len(raw) != 32 or any(raw[:12]):
                raise ValueError("invalid address ABI")
            address = "0x" + raw[12:].hex()
            return address if address != ZERO_ADDRESS else None
        except ValueError:
            self._warn(out, f"{label}: malformed address record")
            return None

    def _decode_bytes(self, result: str | None, out: AddressReport, label: str) -> bytes | None:
        if not result or result == "0x":
            return None
        try:
            raw = _hex_bytes(result[2:])
            if len(raw) < 64 or _word(raw, 0) != 32:
                raise ValueError("invalid bytes ABI")
            return _dynamic_bytes(raw, 32)
        except ValueError:
            self._warn(out, f"{label}: malformed record")
            return None

    def _decode_string(self, result: str | None, out: AddressReport, label: str) -> str | None:
        raw = self._decode_bytes(result, out, label)
        if raw is None:
            return None
        if len(raw) > MAX_TEXT_BYTES:
            self._warn(out, f"{label}: record exceeds text size limit")
            return None
        try:
            value = raw.decode("utf-8").strip()
            if "\x00" in value:
                raise ValueError("NUL in text record")
            return value or None
        except (ValueError, UnicodeError):
            self._warn(out, f"{label}: invalid text record")
            return None

    def _clean_name(self, value: str | None) -> str | None:
        try:
            return normalize_name(value) if value else None
        except ValueError:
            return None

    def _warn(self, out: AddressReport, message: str) -> None:
        if message not in out.ens_warnings:
            out.ens_warnings.append(message)
        item = f"{self.name}: {message}"
        if item not in out.warnings:
            out.warnings.append(item)

    def _health(self, out: AddressReport, status: str, details: str) -> None:
        out.ens_profile["lookup_status"] = "empty" if status == "ok" and not out.ens_name and not out.avatar else status
        out.source_health.append(SourceHealth(source=self.name, status=status,
            timeout_seconds=self._timeout, retry_strategy="bounded Ethereum eth_call; no provider retry", details=details))


def normalize_name(name: str) -> str:
    if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 1024:
        raise ValueError("invalid ENS name length")
    try:
        value = ens_normalize(name.strip())
    except Exception as exc:
        raise ValueError("ENSIP-15 normalization failed") from exc
    labels = value.split(".")
    if not value or len(labels) > 16 or any(not label or len(label.encode("utf-8")) > 255 for label in labels):
        raise ValueError("ENS name exceeds bounded DNS encoding")
    return value


def namehash(name: str) -> str:
    node = b"\x00" * 32
    if name:
        for label in reversed(normalize_name(name).split(".")):
            node = keccak_256(node + keccak_256(label.encode("utf-8")))
    return node.hex()


def _name_url(name: str) -> str:
    return "https://app.ens.domains/" + quote(name, safe=".")


def _dns_encode(name: str) -> bytes:
    return b"".join(bytes([len(label.encode('utf-8'))]) + label.encode("utf-8") for label in name.split(".")) + b"\x00"


def _hex_bytes(value: str) -> bytes:
    if len(value) % 2 or len(value) > MAX_ABI_BYTES * 2:
        raise ValueError("malformed or oversized hex data")
    return bytes.fromhex(value)


def _word(raw: bytes, start: int) -> int:
    if start < 0 or start + 32 > len(raw):
        raise ValueError("ABI word out of range")
    return int.from_bytes(raw[start:start + 32], "big")


def _dynamic_bytes(raw: bytes, offset: int) -> bytes:
    length = _word(raw, offset)
    start = offset + 32
    if length > MAX_ABI_BYTES or start + length > len(raw):
        raise ValueError("ABI bytes out of range")
    return raw[start:start + length]


def _abi_dynamic(*values: bytes) -> bytes:
    head, tail = bytearray(), bytearray()
    for value in values:
        head.extend((32 * len(values) + len(tail)).to_bytes(32, "big"))
        tail.extend(len(value).to_bytes(32, "big"))
        tail.extend(value)
        tail.extend(b"\x00" * ((-len(value)) % 32))
    return bytes(head + tail)


def _text_call_data(node: str, key: str) -> str:
    raw = key.encode("utf-8")
    return "0x59d1d43c" + node + f"{64:064x}" + (len(raw).to_bytes(32, 'big') + raw + b"\x00" * ((-len(raw)) % 32)).hex()


def _https_url(value: Any) -> str | None:
    url = safe_public_url(value)
    return url if url and urlsplit(url).scheme.lower() == "https" else None


def _data_uri_bytes(value: str, limit: int) -> bytes:
    if len(value) > limit * 2:
        raise ValueError("data URI too large")
    header, sep, payload = value.partition(",")
    if not sep:
        raise ValueError("malformed data URI")
    raw = base64.b64decode(payload, validate=True) if header.endswith(";base64") else unquote_to_bytes(payload)
    if len(raw) > limit:
        raise ValueError("data URI too large")
    return raw


def media_url(value: Any, *, allow_data: bool = True) -> str | None:
    """Render-safe HTTPS/IPFS or bounded raster data URI. No script schemes."""
    if not isinstance(value, str) or not value or len(value) > MAX_METADATA_BYTES * 2:
        return None
    if value.startswith("ipfs://"):
        path = value[7:]
        if path.startswith("ipfs/"):
            path = path[5:]
        if not re.fullmatch(r"[A-Za-z0-9]+(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?", path) or any(part in {".", ".."} for part in path.split("/")):
            return None
        return _https_url("https://ipfs.io/ipfs/" + path)
    if allow_data and re.match(r"^data:image/(png|jpeg|gif|webp);base64,", value):
        try:
            _data_uri_bytes(value, MAX_METADATA_BYTES)
            return value
        except ValueError:
            return None
    return _https_url(value)


async def _public_image_bytes(client: httpx.AsyncClient, url: str) -> tuple[bytes, str]:
    """Image counterpart of existing request_public_json, with the same guard.

    Resolve every hop, require public IPs, pin the checked IP while retaining
    TLS SNI/Host. This also rejects an HTTPS redirect to an HTTP/private host.
    """
    for _ in range(3):
        if not _https_url(url):
            raise ValueError("unsafe avatar URL")
        url = await validate_public_url(url)
        parts = urlsplit(url)
        resolved = await asyncio.get_running_loop().getaddrinfo(parts.hostname, parts.port or 443, type=socket.SOCK_STREAM)
        if not resolved or any(not ipaddress.ip_address(item[4][0]).is_global for item in resolved):
            raise ValueError("avatar host resolved to a non-public address")
        pinned_url = httpx.URL(url).copy_with(host=resolved[0][4][0])
        async with client.stream("GET", pinned_url, headers={"Host": parts.netloc},
                extensions={"sni_hostname": parts.hostname}, follow_redirects=False) as response:
            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    raise ValueError("avatar redirect missing Location")
                url = urljoin(url, location)
                continue
            response.raise_for_status()
            media_type = response.headers.get("content-type", "").partition(";")[0].lower().strip()
            if media_type not in {"image/png", "image/jpeg", "image/webp"}:
                raise ValueError("avatar response is not an allowed raster image")
            length = response.headers.get("content-length")
            if length and int(length) > 1_000_000:
                raise ValueError("avatar exceeds media byte limit")
            chunks = bytearray()
            async for chunk in response.aiter_bytes():
                chunks.extend(chunk)
                if len(chunks) > 1_000_000:
                    raise ValueError("avatar exceeds media byte limit")
            return bytes(chunks), media_type
    raise ValueError("avatar redirect limit exceeded")


def _thumbnail_png(raw: bytes) -> str:
    # Pillow is an optional existing desktop/report dependency. Missing support
    # leaves the authentic URL and profile intact with an unavailable fallback.
    from PIL import Image, ImageOps
    try:
        with Image.open(io.BytesIO(raw)) as image:
            if image.format not in {"PNG", "JPEG", "WEBP"} or image.width * image.height > 16_000_000 or max(image.size) > 8192:
                raise ValueError("avatar format or pixel limit exceeded")
            image.seek(0)
            image = ImageOps.exif_transpose(image)
            image.thumbnail((192, 192), Image.Resampling.LANCZOS)
            image = image.convert("RGBA" if image.mode == "RGBA" or "transparency" in image.info else "RGB")
            output = io.BytesIO()
            image.save(output, format="PNG", optimize=True)
            encoded = "data:image/png;base64," + base64.b64encode(output.getvalue()).decode("ascii")
            if len(encoded) > 180000:
                raise ValueError("avatar thumbnail exceeds output limit")
            return encoded
    except Image.DecompressionBombError as exc:
        raise ValueError("avatar pixel bomb rejected") from exc
