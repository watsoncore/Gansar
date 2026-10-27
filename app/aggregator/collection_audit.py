"""Loss accounting for provider records, normalized operations and stored reports.

An operation row is not necessarily an account transaction. Counts remain typed;
page exhaustion describes the endpoint only, never completeness of the chain.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from app.utils.event_identity import canonical_hash, event_identity


def provider_record_key(kind: str, row: dict) -> str:
    """Stable provider-level key used to join incremental head to stored history."""
    if kind == "account_transactions":
        return canonical_hash(row.get("hash") or (row.get("transaction_id") or {}).get("hash"))
    if kind == "account_events":
        value = row.get("event_id") or row.get("id")
        return canonical_hash(value) or str(value or "")
    if kind == "action_events" and row.get("action_id"):
        return str(row["action_id"])
    fields = ("transaction_hash", "transaction_lt", "query_id", "source", "destination", "old_owner", "new_owner", "nft_address", "item_address", "jetton_master", "amount", "action_id", "trace_id", "type", "start_lt", "end_lt")
    basis = {key: row[key] for key in fields if row.get(key) is not None}
    if not basis:
        return ""
    return hashlib.sha256(json.dumps(basis, sort_keys=True, default=str).encode()).hexdigest()


def provider_record_order(kind: str, row: dict) -> int:
    if kind == "account_transactions" and not row.get("lt") and isinstance(row.get("transaction_id"), dict):
        row = {**row, "lt": row["transaction_id"].get("lt")}
    for field in (("lt",) if kind == "account_transactions" else ("lt", "end_lt", "start_lt", "transaction_lt", "end_utime", "timestamp")):
        try:
            value = int(row.get(field) or 0)
            if value:
                return value
        except (TypeError, ValueError):
            pass
    return 0


def transaction_digest(transactions) -> str:
    identities = sorted(event_identity(tx) for tx in transactions)
    return hashlib.sha256("\n".join(identities).encode()).hexdigest()


def record_kind(tx) -> str:
    raw = tx.raw or {}
    provider = str(raw.get("provider") or "")
    if tx.chain == "ton":
        if raw.get("nft_event_id") or raw.get("nft_intelligence"):
            return "nft_history_events"
        if raw.get("asset_type") == "nft" or raw.get("type") == "nft_transfer":
            return "nft_transfer_events"
        if raw.get("asset_type") == "jetton":
            return "jetton_transfer_events"
        if raw.get("action_index") is not None or raw.get("asset_type") == "action" or provider == "tonapi_events":
            return "action_events"
        if raw.get("message_index") is not None or raw.get("message"):
            return "physical_message_observations"
    return "transaction_operations"


def identity_counts(transactions) -> dict[str, int]:
    kinds = Counter()
    accounts, references, messages, actions = set(), set(), set(), set()
    for tx in transactions:
        raw = tx.raw or {}
        kind = record_kind(tx)
        kinds[kind] += 1
        if tx.chain == "ton":
            if kind in {"action_events", "nft_history_events", "nft_transfer_events", "jetton_transfer_events"}:
                actions.add(event_identity(tx))
                if canonical_hash(tx.tx_hash):
                    references.add(canonical_hash(tx.tx_hash))
            else:
                account = raw.get("transaction") or {}
                txid = canonical_hash(tx.tx_hash)
                if txid:
                    accounts.add((tx.chain, txid))
                for provenance in getattr(tx, "provenance", []) or []:
                    observed_raw = provenance.get("raw") or {}
                    observed_account = observed_raw.get("transaction") or {}
                    observed_hash = canonical_hash(observed_account.get("hash") or (observed_account.get("transaction_id") or {}).get("hash") or observed_raw.get("parent_hash"))
                    if observed_hash:
                        accounts.add((tx.chain, observed_hash))
                message = raw.get("message") or (account.get("in_msg") if raw.get("message_index") == "in" else {}) or {}
                digest = canonical_hash(message.get("hash") or message.get("msg_hash"))
                if digest:
                    messages.add(digest)
        elif tx.tx_hash:
            accounts.add((tx.chain, str(tx.tx_hash).lower() if tx.chain in {"eth", "bsc", "polygon", "arbitrum", "optimism", "avalanche"} else tx.tx_hash))
    return {**dict(kinds), "unique_account_transactions": len(accounts), "unique_physical_messages_with_hash": len(messages),
            "unique_action_events": len(actions), "referenced_transaction_hashes_from_actions": len(references), "operation_records": sum(kinds.values())}


def refresh_audit(report, stage: str = "model", **details) -> dict:
    audit = report.collection_audit
    audit.setdefault("schema", "collection_audit")
    audit.setdefault("streams", {})
    audit["identities"] = identity_counts(report.transactions)
    measurement = {"records": len(report.transactions), "event_ids_sha256": transaction_digest(report.transactions),
        "observed_at": datetime.now(timezone.utc).isoformat(), **details}
    if stage == "normalization" and details.get("source"):
        entry = audit.setdefault("stages", {}).setdefault(stage, {"sources": {}})
        entry.setdefault("sources", {})[details["source"]] = measurement
        entry["records"] = sum(item["records"] for item in entry["sources"].values())
    else:
        audit.setdefault("stages", {})[stage] = measurement
    audit["source_counts"] = dict(Counter(tx.source for tx in report.transactions))
    audit.setdefault("stages", {})["provider"] = {"measured_raw_records": sum(state.get("raw_records", 0) for streams in audit["streams"].values() for state in streams.values()), "measured_pages": sum(state.get("pages", 0) for streams in audit["streams"].values() for state in streams.values()), "record_types": dict(Counter({kind: sum(state.get("raw_records", 0) for streams in audit["streams"].values() for state in streams.values() if state.get("record_type") == kind) for kind in {state.get("record_type", "provider_records") for streams in audit["streams"].values() for state in streams.values()}})), "unmeasured_sources": sorted(set(audit["source_counts"]) - set(audit["streams"])), "note": "Raw record counters exist only for instrumented streams; missing counters are unknown, never zero."}
    audit["counting_note"] = "Operation rows, account transactions, messages and actions are distinct measurements; do not sum them as transactions."
    return audit


def merge_audit(base: dict, other: dict) -> None:
    """Merge stream state without erasing previously collected proof or cursors."""
    if not other:
        return
    base.setdefault("schema", "collection_audit")
    for source, streams in other.get("streams", {}).items():
        target = base.setdefault("streams", {}).setdefault(source, {})
        for stream, state in streams.items():
            existing = target.get(stream, {})
            target[stream] = {**existing, **state}
    for name in ("stages", "source_counts", "http"):
        for key, value in other.get(name, {}).items():
            if name == "stages" and key == "normalization" and isinstance(value, dict):
                entry = base.setdefault(name, {}).setdefault(key, {"sources": {}})
                entry.setdefault("sources", {}).update(value.get("sources", {}))
                entry["records"] = sum(item["records"] for item in entry["sources"].values())
            else:
                base.setdefault(name, {})[key] = value


def stream_state(report, source: str, stream: str, *, resume: dict | None = None, record_type: str = "provider_records") -> dict:
    states = report.collection_audit.setdefault("streams", {}).setdefault(source, {})
    state = states.setdefault(stream, dict(resume or {}))
    state.setdefault("pages", 0)
    state.setdefault("raw_records", 0)
    state.setdefault("record_type", record_type)
    state.setdefault("next_cursor", None)
    state.setdefault("exhausted", False)
    state.setdefault("unknown_total", True)
    state.setdefault("page_audit", [])
    state["page_audit"] = list(state["page_audit"])
    return state


def observe_page(state: dict, rows: list, cursor: Any, *, exhausted: bool, stop_reason: str | None = None) -> None:
    state["pages"] += 1
    state["raw_records"] += len(rows)
    state["next_cursor"] = cursor
    state["exhausted"] = exhausted
    state["stop_reason"] = stop_reason or ("endpoint_exhausted" if exhausted else "pagination_pending")
    state["observed_at"] = datetime.now(timezone.utc).isoformat()
    page = {"records": len(rows), "next_cursor": cursor,
            "raw_sha256": hashlib.sha256(json.dumps(rows, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()}
    state["page_audit"].append(page)

