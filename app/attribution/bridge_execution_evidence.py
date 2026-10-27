"""Bounded public Wormhole evidence in the existing source collection wave.

Keeps actual RPC observations as non-financial context. The existing strict
cross_chain analyzer verifies the proof; this collector makes no inference and
never appends transactions, graph edges, owner claims, or payment allocations.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import json
from types import SimpleNamespace
import httpx

from app.models.report import SourceHealth
from app.sources.evm_rpc import (EthereumRpcSource, BscRpcSource, PolygonRpcSource,
    ArbitrumRpcSource, OptimismRpcSource, AvalancheRpcSource)
from app.utils.http import shared_async_client, request_json, _retry_after_seconds
from app.utils.security import sanitize_observation
from .normalize import CHAIN_IDS, canonical_address
from .cross_chain import _DEPLOYMENTS, _hex, _integer, analyze_cross_chain

API = "https://api.wormholescan.io/api/v1/operations"
DOCS = "https://wormhole.com/docs/products/messaging/guides/wormholescan-api/"
_RPC = {cls.chain: cls for cls in (EthereumRpcSource, BscRpcSource, PolygonRpcSource,
    ArbitrumRpcSource, OptimismRpcSource, AvalancheRpcSource)}
_BY_ID = {v["wormhole_chain_id"]: k for k, v in _DEPLOYMENTS.items()}


async def enrich_wormhole_executions(report, sources, source_manager, *, deadline=None,
                                     max_messages=2, max_seconds=8.0):
    """One address lookup, at most two receipt pairs, no polling or log scans."""
    target = canonical_address("eth", report.target_address)
    if not target or not set(report.detected_chains).intersection(_DEPLOYMENTS):
        return None
    loop = asyncio.get_running_loop()
    started = loop.time()
    stop = min(started + min(8.0, max(0.0, float(max_seconds))), deadline) if deadline is not None else started + min(8.0, max(0.0, float(max_seconds)))
    cap = min(2, max(0, int(max_messages)))
    previous = report.coverage.get("wormhole_execution_evidence")
    previous = previous if isinstance(previous, dict) else {}
    prior_records = previous.get("records")
    records = [r for r in prior_records if isinstance(r, dict)][:cap] if isinstance(prior_records, list) else []
    coverage = {"status": "PARTIAL", "history_complete": False, "records": records,
        "requests_or_cache_lookups": 0, "max_requests": 1 + cap * 2, "max_messages": cap,
        "max_seconds": max(0.0, stop - started), "errors": [], "rejected": [],
        "source_url": API, "documentation_url": DOCS, "financial_operations_added": 0,
        "limitations": ["At most five indexed operations and two exact receipt pairs are sampled; history is not complete.",
            "Indexer labels only discover candidate transactions. Verification requires exact successful RPC receipt events.",
            "Guardian signatures, chain finality, historical runtime and historical token mappings are not verified locally."]}
    report.coverage["wormhole_execution_evidence"] = coverage
    if not cap or loop.time() >= stop:
        coverage["status"] = "deadline"
        return coverage
    available = {s.chain: s for s in sources if isinstance(s, tuple(_RPC.values()))}

    async def get(name, method, url, *, params=None, body=None):
        optional_name = "wormhole_evidence_" + name
        remaining = min(stop - loop.time(), source_manager.timeout(optional_name, 5.0))
        if remaining <= 0 or coverage["requests_or_cache_lookups"] >= coverage["max_requests"]:
            raise TimeoutError("Bridge evidence request/deadline budget exhausted")
        if not source_manager.should_run(name, remaining) or not source_manager.should_run(optional_name, remaining):
            raise RuntimeError(f"SourceManager disabled {name}")
        coverage["requests_or_cache_lookups"] += 1
        try:
            async with asyncio.timeout(remaining), shared_async_client(remaining) as client:
                data = await request_json(client, method, url, params=params, json=body, retries=0, cache_ttl=45)
            encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            if len(encoded) > 2_000_000:
                raise ValueError("Bridge evidence response exceeds bounded decoded size")
            source_manager.record_success(optional_name)
            return data, {"source": name, "source_url": url, "method": method,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "response_sha256": hashlib.sha256(encoded).hexdigest(),
                "response_hash_scope": "canonical_decoded_json; may originate from existing 45-second cache"}
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            source_manager.record_fail(optional_name)
            if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 429:
                plan = source_manager.plan(optional_name, remaining)
                plan.enabled = False
                plan.recovery_seconds = max(plan.recovery_seconds, _retry_after_seconds(exc.response) or 60.0)
            raise

    async def execution(chain, tx_hash):
        source = available.get(chain) or _RPC[chain](max(.1, stop - loop.time()))
        body = [{"jsonrpc": "2.0", "id": 0, "method": "eth_chainId", "params": []},
                {"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt", "params": [tx_hash]},
                {"jsonrpc": "2.0", "id": 2, "method": "eth_getTransactionByHash", "params": [tx_hash]}]
        data, proof = await get(source.name, "POST", source.rpc_url, body=body)
        if not isinstance(data, list) or len(data) != 3 or not all(isinstance(r, dict) for r in data):
            raise ValueError("Invalid bridge RPC batch")
        by_id = {r.get("id"): r for r in data if type(r.get("id")) is int}
        if set(by_id) != {0, 1, 2} or any(r.get("error") for r in by_id.values()):
            raise ValueError("Bridge RPC error/missing/duplicate batch ID")
        chain_id = _integer(by_id[0].get("result"))
        receipt, native = by_id[1].get("result"), by_id[2].get("result")
        if (chain_id != CHAIN_IDS[chain] or not isinstance(receipt, dict) or not isinstance(native, dict)
                or _integer(receipt.get("status")) != 1
                or _hex(receipt.get("transactionHash"), 32) != tx_hash
                or _hex(native.get("hash"), 32) != tx_hash
                or not _hex(receipt.get("blockHash"), 32)
                or _hex(native.get("blockHash"), 32) != _hex(receipt.get("blockHash"), 32)
                or _integer(native.get("blockNumber")) != _integer(receipt.get("blockNumber"))):
            raise ValueError("Bridge receipt/transaction chain, hash, block or success mismatch")
        return native, receipt, chain_id, {**proof, "chain_id": chain_id}

    try:
        data, index_proof = await get("wormholescan", "GET", API, params={"address": target, "pageSize": 5})
        operations = data.get("operations") if isinstance(data, dict) else None
        if not isinstance(operations, list):
            raise ValueError("Wormholescan operations envelope missing")
        seen = {r.get("message_id") for r in records}
        for operation in operations[:5]:
            if len(records) >= cap or loop.time() >= stop:
                break
            if not isinstance(operation, dict):
                continue
            source_info, destination_info = operation.get("sourceChain") or {}, operation.get("targetChain") or {}
            source_chain = _BY_ID.get(_integer(source_info.get("chainId")))
            destination_chain = _BY_ID.get(_integer(destination_info.get("chainId")))
            source_hash = _hex((source_info.get("transaction") or {}).get("txHash"), 32)
            destination_hash = _hex((destination_info.get("transaction") or {}).get("txHash"), 32)
            message_id = operation.get("id")
            if (source_chain not in _RPC or destination_chain not in _RPC or source_chain == destination_chain
                    or not source_hash or not destination_hash or message_id in seen):
                continue
            try:
                native, receipt, chain_id, proof = await execution(source_chain, source_hash)
                # Reuse the existing decoder before requesting destination data.
                observation = {"chain": source_chain, "tx_hash": source_hash, "success": True,
                    "raw": {"receipt": receipt, "receipt_provenance": proof,
                            "wormhole_vaa": (operation.get("vaa") or {}).get("raw")}}
                decoded = analyze_cross_chain(SimpleNamespace(transactions=[observation], coverage={}), {}, max_records=600)
                messages = [m for m in decoded["messages"] if m["message_id"] == message_id and m["vaa_binding"]["body_matches_event"]]
                if len(messages) != 1:
                    raise ValueError("Indexer operation is not bound to the actual source message")
                message = messages[0]
                intent = message.get("intended_transfer") or {}
                if intent.get("recipient_wormhole_chain_id") != _DEPLOYMENTS[destination_chain]["wormhole_chain_id"]:
                    raise ValueError("Destination network differs from source payload")
                recipient_hex = intent.get("recipient_address_hex", "")
                recipient = "0x" + recipient_hex[-40:] if len(recipient_hex) == 64 and recipient_hex[:24] == "0" * 24 else None
                if canonical_address(source_chain, native.get("from")) != target and recipient != target:
                    coverage["rejected"].append({"message_id": message_id, "reason": "target_not_source_sender_or_exact_payload_recipient"})
                    continue
                record = {"message_id": message_id, "source_chain": source_chain, "source_rpc_chain_id": chain_id,
                    "source_transaction": native, "source_receipt": receipt, "source_provenance": proof,
                    "operation": operation, "operation_provenance": index_proof, "destination_chain": destination_chain,
                    "target_relevance": "exact_source_rpc_sender" if canonical_address(source_chain, native.get("from")) == target else "exact_protocol_recipient"}
                # Source evidence remains useful if destination RPC is unavailable.
                records.append(record)
                seen.add(message_id)
                dest_native, dest_receipt, dest_id, dest_proof = await execution(destination_chain, destination_hash)
                record.update(destination_transaction=dest_native, destination_receipt=dest_receipt,
                              destination_rpc_chain_id=dest_id, destination_provenance=dest_proof)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                coverage["errors"].append({"message_id": message_id, "error": str(sanitize_observation(f"{type(exc).__name__}: {exc}"))[:400]})
        coverage["status"] = "partial" if coverage["errors"] or loop.time() >= stop else "observed" if records else "empty_sample"
    except asyncio.CancelledError:
        coverage["status"] = "cancelled_partial"
        raise
    except Exception as exc:
        coverage["errors"].append({"error": str(sanitize_observation(f"{type(exc).__name__}: {exc}"))[:400]})
        coverage["status"] = "unavailable"
    finally:
        coverage["elapsed_seconds"] = loop.time() - started
        partial = bool(coverage["errors"]) or coverage["status"] in {"cancelled_partial", "deadline", "unavailable"}
        report.source_health.append(SourceHealth(source="wormholescan", status="partial" if partial else "ok" if records else "empty",
            timeout_seconds=coverage["max_seconds"], partial=True, retry_strategy="bounded optional evidence; no retries or polling",
            details=f"Wormhole evidence: {len(records)} retained records; financial operations added=0; errors={len(coverage['errors'])}"))
    return coverage


from app.sources.base import Source
from app.models.report import AddressReport


class WormholeExecutionEvidenceSource(Source):
    """Optional non-financial evidence collected in the normal source wave."""
    name = 'wormholescan'

    def __init__(self, timeout_seconds, *, chain, source_manager):
        self.chain = chain
        self._timeout = min(8.0, timeout_seconds)
        self._manager = source_manager

    async def fetch(self, address):
        out = AddressReport(target_address=address, detected_chains=[self.chain], sources_used=[self.name])
        self._partial_report = out
        await enrich_wormhole_executions(out, [], self._manager, max_seconds=min(8.0, self._timeout))
        return out
