"""Bounded, resumable page traversal for existing non-TON collectors."""
from __future__ import annotations

import asyncio
import hashlib
import json

from app.aggregator.collection_audit import stream_state, observe_page


def row_hash(row):
    if isinstance(row, str):
        return row
    for field in ("hash", "txid", "txID", "transaction_id", "transactionHash", "signature"):
        value = row.get(field)
        if isinstance(value, str):
            return value
    return ""


def operation_key(stream, row):
    """Provider operation identity scoped to one typed endpoint stream.

    One transaction can contain several logs/internal calls. Never join one
    stream to the source's undifferentiated transaction-hash set.
    """
    if isinstance(row, str):
        basis = {"stream": stream, "transaction": row}
    else:
        fields = ("hash", "txid", "txID", "transaction_id", "transactionHash", "signature",
                  "logIndex", "log_index", "event_index", "traceId", "trace_id",
                  "contractAddress", "contract_address", "tokenID", "tokenId",
                  "from", "to", "value", "amount", "token_info", "raw_data")
        basis = {"stream": stream, **{field: row[field] for field in fields if row.get(field) is not None}}
        if len(basis) == 1:
            return ""
    return hashlib.sha256(json.dumps(basis, sort_keys=True, default=str).encode()).hexdigest()


async def pages(source, out, stream, fetch, rows, advance, *, page_size, adjust_offset=False, legacy_pages=1):
    """Yield each genuine page immediately; transport failures never mean EOF.

    fetch(cursor) returns a provider response or None on failure. rows(response)
    must return a list, or None for malformed data. advance uses only public
    pagination fields, never trusts a provider redirect URL.
    """
    resume = getattr(source, "_resume_state", {})
    state = stream_state(out, source.name, stream, resume=resume.get(stream), record_type=stream)
    head_name = stream + "_refresh"
    old_head = resume.get(head_name, {})
    known = set(resume.get(stream, {}).get("observed_record_keys", []))
    if getattr(source, "_incremental", False) or (old_head and not old_head.get("exhausted")):
        head = stream_state(out, source.name, head_name, resume=old_head if old_head and not old_head.get("exhausted") else {}, record_type=stream)
        async for response in _window(source, out, head, fetch, rows, advance, page_size, known, legacy_pages):
            yield response
        if head.get("exhausted") and head.get("stop_reason") == "endpoint_exhausted":
            state.update({"exhausted": True, "stop_reason": "fresh_history_endpoint_exhausted"})
        elif head.get("exhausted") and adjust_offset and state.get("next_cursor"):
            cursor = dict(state["next_cursor"])
            cursor["offset"] = int(cursor.get("offset", 0)) + head.get("fresh_records", 0)
            state["next_cursor"] = cursor
        state["observed_record_keys"] = list(dict.fromkeys(state.get("observed_record_keys", []) + head.get("observed_record_keys", [])))
    if not state.get("exhausted"):
        async for response in _window(source, out, state, fetch, rows, advance, page_size, legacy_pages=legacy_pages):
            yield response


async def _window(source, out, state, fetch, rows, advance, page_size, known=None, legacy_pages=1):
    cursor = state.get("next_cursor") or {}
    seen_cursors, seen_pages = set(), set()
    recorded = set(state.get("observed_record_keys", []))
    for _ in range(1000 if getattr(source, "_continuous", False) else legacy_pages):
        if len(out.transactions) >= 100_000:
            state["stop_reason"] = "operation_memory_safety_ceiling"
            return
        try:
            data = await fetch(cursor)
        except asyncio.CancelledError:
            state["stop_reason"] = "session_stopped_or_deadline"
            raise
        except Exception as exc:
            state["stop_reason"] = "provider_error"
            out.errors.append(f"{source.name}: {state['record_type']}: {type(exc).__name__}: {exc}")
            return
        if data is None:
            state["stop_reason"] = "provider_error"
            return
        items = rows(data)
        if not isinstance(items, list):
            state["stop_reason"] = "malformed_page"
            out.errors.append(f"{source.name}: {state['record_type']}: record array missing")
            return
        digest = hashlib.sha256(json.dumps(items, sort_keys=True, default=str).encode()).hexdigest()
        if items and digest in seen_pages:
            state["stop_reason"] = "repeated_page"
            return
        seen_pages.add(digest)
        keys = [operation_key(state["record_type"], item) for item in items]
        overlap = known is not None and any(key and key in known for key in keys)
        exhausted = len(items) < page_size
        next_cursor = advance(data, items, cursor)
        observe_page(state, items, next_cursor, exhausted=exhausted or overlap,
                     stop_reason="overlap_stored_history" if overlap else None)
        if known is not None:
            state["fresh_records"] = state.get("fresh_records", 0) + sum(key not in known for key in keys)
        additions = [key for key in keys if key and key not in recorded]
        state.setdefault("observed_record_keys", []).extend(additions)
        recorded.update(additions)
        yield data
        if exhausted or overlap:
            return
        key = json.dumps(next_cursor, sort_keys=True, default=str)
        if not next_cursor or key in seen_cursors or next_cursor == cursor:
            state["exhausted"] = False
            state["stop_reason"] = "repeated_or_missing_cursor"
            return
        seen_cursors.add(key)
        cursor = next_cursor
        await asyncio.sleep(.15)
    state["stop_reason"] = "page_safety_ceiling"
