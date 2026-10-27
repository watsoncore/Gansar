"""Merge source-scoped public assertions without financial/identity inference."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone


def scoped_public_context(context: dict, source: str, chain: str, address: str) -> dict:
    """Only the exact requested source/network/20-byte target may assert facts."""
    def same(left, right):
        left, right = str(left or ""), str(right or "")
        return left.lower() == right.lower() if left.startswith("0x") and right.startswith("0x") else left == right
    outcomes = [row for row in (context or {}).get("outcomes", []) if isinstance(row, dict)
        and row.get("source") == source and row.get("chain") == chain
        and same(row.get("input"), address) and isinstance(row.get("claims"), list)]
    return {"version": 1, "outcomes": deepcopy(outcomes)} if outcomes else {}


def merge_public_context(previous: dict, fresh: dict) -> dict:
    """A fresh source outcome, including failure, replaces its earlier claims.

    Different providers stay separate. Names never establish address identity,
    so conflicting assertions are retained rather than choosing a winner.
    """
    outcomes = {}
    for context in (previous or {}, fresh or {}):
        for outcome in context.get("outcomes", []):
            if not isinstance(outcome, dict):
                continue
            parts = [str(outcome.get(field) or "") for field in ("source", "chain", "input")]
            parts[2] = str(outcome.get("target_address") or parts[2])
            if parts[2].startswith("0x") and len(parts[2]) == 42:
                parts[2] = parts[2].lower()
            key = tuple(parts)
            if not all(key):
                continue
            outcomes[key] = deepcopy(outcome)
    return {"version": 1, "outcomes": list(outcomes.values())} if outcomes else {}


def failed_public_context(source: str, chain: str, address: str, status: str) -> dict:
    return {"version": 1, "outcomes": [{"source": source, "source_type": "public_api",
        "chain": chain, "input": address, "status": status,
        "retrieved_at": datetime.now(timezone.utc).isoformat(), "source_url": "",
        "coverage": {"complete": False, "reason": "Source lifecycle did not produce fresh public claims"},
        "claims": []}]}


def has_public_claims(report, source: str) -> bool:
    return any(isinstance(row, dict) and row.get("source") == source and row.get("claims")
        for row in (getattr(report, "public_address_context", {}) or {}).get("outcomes", []))
