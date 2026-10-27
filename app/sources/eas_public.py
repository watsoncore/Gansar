"""Bounded public EAS assertions; no identity or financial inference.

The documented Easscan index can include offchain signed messages. This
collector explicitly requests onchain records and validates that boundary.
Indexer assertions are not independently verified contract state or identity.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import re

import httpx

from app.models.report import AddressReport, SourceHealth
from app.sources.base import Source
from app.sources.public_context_http import public_json
from app.utils.http import shared_async_client
from app.utils.keccak import keccak_256
from app.utils.security import sanitize_observation

ENDPOINTS = {
    "eth": (1, "https://easscan.org/graphql"),
    "arbitrum": (42161, "https://arbitrum.easscan.org/graphql"),
    "optimism": (10, "https://optimism.easscan.org/graphql"),
    "polygon": (137, "https://polygon.easscan.org/graphql"),
}
DOCS = "https://docs.attest.org/docs/developer-tools/api"
MAX_RECORDS = 8
MAX_BYTES = 1_000_000
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_UID = re.compile(r"^0x[0-9a-fA-F]{64}$")


def _checksum(address: str) -> str:
    lower = address[2:].lower()
    digest = keccak_256(lower.encode("ascii")).hex()
    return "0x" + "".join(c.upper() if c in "abcdef" and int(digest[i], 16) >= 8 else c
                           for i, c in enumerate(lower))


def _query(address: str) -> dict:
    # Easscan comparisons are case sensitive. Both canonical lower and EIP-55
    # spellings describe this exact 20-byte target, not additional addresses.
    variants = list(dict.fromkeys([address.lower(), _checksum(address)]))
    return {"query": """query GansarAddressAttestations($addresses: [String!], $take: Int!) {
      attestations(take: $take, where: {isOffchain: {equals: false}, OR: [
        {attester: {in: $addresses}}, {recipient: {in: $addresses}}
      ]}, orderBy: {time: desc}) {
        id attester recipient schemaId time expirationTime revocationTime
        revoked txid isOffchain data decodedDataJson
        schema {id schema creator resolver revocable}
      }
    }""", "variables": {"addresses": variants, "take": MAX_RECORDS + 1}}


class EasAttestationSource(Source):
    """At most one read-only index query for the investigation target."""
    public_context_only = True

    def __init__(self, timeout_seconds: float = 6.0, chain: str = "eth"):
        if chain not in ENDPOINTS:
            raise ValueError("Unsupported documented EAS chain")
        self.chain = chain
        self.name = "eas_" + chain
        self._timeout = min(6.0, max(0.1, timeout_seconds))

    async def _request(self, address: str):
        _, endpoint = ENDPOINTS[self.chain]
        async with shared_async_client(self._timeout) as client:
            data, meta = await public_json(client, "POST", endpoint, json=_query(address),
                max_bytes=MAX_BYTES, cache_ttl=300.0, with_metadata=True)
        return data, meta

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=[self.chain], sources_used=[self.name])
        self._partial_report = out
        chain_id, endpoint = ENDPOINTS[self.chain]
        observed = datetime.now(timezone.utc).isoformat()
        outcome = {"source": self.name, "source_type": "public_attestation_index", "chain": self.chain,
                   "input": address, "status": "unknown", "retrieved_at": observed,
                   "source_url": endpoint, "claims": [], "coverage": {
                       "endpoint": endpoint, "docs": DOCS, "chain_id": chain_id,
                       "target_only": True, "maximum_records": MAX_RECORDS, "history_complete": False,
                       "onchain_only": True, "independent_onchain_verification": False,
                       "authentication": "none", "numeric_free_quota": "not published in EAS API documentation",
                       "limitations": ["A public attestation is an author's assertion, not an identity confirmation.",
                           "Indexer revocation/expiry and transaction values are reported, not independently checked onchain."]}}
        out.public_address_context = {"version": 1, "outcomes": [outcome]}
        status = "error"
        try:
            if not _ADDRESS.fullmatch(address):
                raise ValueError("EAS requires an exact EVM address")
            canonical = address.lower()
            async with asyncio.timeout(self._timeout):
                data, meta = await self._request(canonical)
                observed, cached = meta["retrieved_at"], meta["cache_hit"]
            outcome["retrieved_at"] = observed
            if not isinstance(data, dict):
                raise ValueError("EAS response is not an object")
            rows = (data.get("data") or {}).get("attestations")
            if not isinstance(rows, list):
                raise ValueError("EAS GraphQL attestation data unavailable")
            outcome["evidence"] = {"request": {"method": "POST", "url": endpoint, **_query(canonical)},
                                   "response": sanitize_observation(data)}
            coverage = outcome["coverage"]
            coverage.update(cache_hit=cached, transport_requests=0 if cached else 1,
                            response_bytes=meta.get("response_bytes"), response_sha256=meta.get("response_sha256"),
                            index_rows_received=len(rows), more_available=len(rows) > MAX_RECORDS,
                            graphql_errors=sanitize_observation(data.get("errors") or []))
            rejected, seen = [], set()
            now = int(datetime.now(timezone.utc).timestamp())
            for row in rows[:MAX_RECORDS]:
                if not isinstance(row, dict):
                    rejected.append("non-object result")
                    continue
                uid = row.get("id")
                attester, recipient = str(row.get("attester") or ""), str(row.get("recipient") or "")
                schema = row.get("schema") or {}
                if (not isinstance(uid, str) or not _UID.fullmatch(uid) or row.get("isOffchain") is not False
                    or not _ADDRESS.fullmatch(attester) or not _ADDRESS.fullmatch(recipient)
                    or canonical not in {attester.lower(), recipient.lower()}
                    or not isinstance(row.get("schemaId"), str) or not _UID.fullmatch(row["schemaId"])
                    or not isinstance(schema, dict) or schema.get("id") != row["schemaId"]):
                    rejected.append("result identity, target, onchain or schema boundary mismatch")
                    continue
                if uid in seen:
                    rejected.append("duplicate attestation UID")
                    continue
                seen.add(uid)
                times = [row.get(key) for key in ("time", "expirationTime", "revocationTime")]
                if any(type(value) is not int or value < 0 for value in times) or type(row.get("revoked")) is not bool:
                    rejected.append("invalid attestation time/state fields")
                    continue
                created, expiration, revocation = times
                state = "revoked" if row["revoked"] or revocation else "expired" if expiration and expiration <= now else "future_dated" if created > now else "not_revoked_not_expired_as_reported"
                role = "attester_and_recipient" if attester.lower() == recipient.lower() == canonical else "attester" if attester.lower() == canonical else "recipient"
                txid = row.get("txid")
                if not isinstance(txid, str) or not _UID.fullmatch(txid):
                    txid = None
                content = row.get("decodedDataJson")
                if isinstance(content, str):
                    try:
                        content = json.loads(content)
                    except ValueError:
                        pass
                value = {"uid": uid, "schema_uid": row["schemaId"], "schema": schema,
                         "attester": attester, "recipient": recipient, "target_role": role,
                         "time": created, "expiration_time": expiration, "revocation_time": revocation,
                         "revoked": row["revoked"], "temporal_status": state,
                         "transaction_hash": txid, "chain_id": chain_id, "indexed_onchain": True,
                         "independently_verified_onchain": False, "decoded_schema_context": content,
                         "raw_evidence_uid": uid}
                base_url = endpoint.removesuffix("/graphql")
                claim_url = base_url + "/attestation/view/" + uid
                outcome["claims"].append({"id": "eas:" + str(chain_id) + ":" + uid + ":" + role,
                    "object_id": "eas:" + str(chain_id) + ":" + uid, "object_type": "attestation",
                    "subject_address": canonical, "claim_type": "public_attestation",
                    "relation": "attestation_" + role, "value": sanitize_observation(value),
                    "claim_status": "provider_reported", "source_url": claim_url, "retrieved_at": observed})
            coverage["rejected_records"] = rejected
            status = "partial" if rejected or data.get("errors") or len(rows) > MAX_RECORDS else "ok" if outcome["claims"] else "empty"
            outcome["status"] = status
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            response = getattr(exc, "response", None)
            code = getattr(response, "status_code", None)
            status = "rate_limited" if code == 429 else "unavailable" if code in {401, 403, 404} else "timeout" if isinstance(exc, (TimeoutError, httpx.TimeoutException)) else "error"
            outcome.update(status=status, error={"type": type(exc).__name__, "http_status": code,
                          "detail": str(sanitize_observation(str(exc)))[:500]})
            out.warnings.append(self.name + ": " + status)
        out.public_address_context = {"version": 1, "outcomes": [outcome]}
        out.source_health.append(SourceHealth(source=self.name, status=status, partial=status != "ok",
            timeout_seconds=self._timeout, retry_strategy="one bounded target-only query; no retries; cache300s; cooldown after429/5xx",
            details="Public indexed attestations; no financial records or identity verification"))
        return out
