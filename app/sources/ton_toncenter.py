from __future__ import annotations

import httpx
import asyncio
import base64
import hashlib
import json
import os

from app.models.report import AddressReport, SourceHealth, Transaction
from app.sources.base import Source
from app.utils.http import http_error_message, json_list, json_object, retry_delay, shared_async_client
from app.utils.ton_normalize import ton_address, ton_address_text, ton_amount, ton_datetime, ton_direction, ton_amount_decimal


from app.aggregator.collection_audit import stream_state, observe_page, provider_record_order
from app.utils.event_identity import canonical_hash


class TonCenterSource(Source):
    name = "toncenter"
    chain = "ton"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    def _headers(self) -> dict[str, str] | None:
        key = (os.getenv("TONCENTER_API_KEY") or os.getenv("TON_CENTER_API_KEY") or "").strip()
        return {"X-API-Key": key} if key else None

    async def _load_transactions(self, client, address: str, archival: str, lt: str | None = None, tx_hash: str | None = None) -> dict:
        params = {"address": address, "limit": 100, "archival": archival}
        if lt and tx_hash:
            params.update({"lt": lt, "hash": tx_hash})
        for attempt in range(3):
            r = await client.get(
                "https://toncenter.com/api/v2/getTransactions",
                params=params,
                headers=self._headers(),
            )
            if r.status_code in {429, 500, 502, 503, 504} and attempt < 2:
                await asyncio.sleep(retry_delay(r, attempt, 0.55, cap=4.0))
                continue
            r.raise_for_status()
            return self._decode_page(r)
        return {}

    def _decode_page(self, response: httpx.Response) -> dict:
        try:
            return json_object(response.json())
        except UnicodeDecodeError:
            # Toncenter v2 sometimes serializes encrypted message bytes directly
            # into a JSON string declared UTF-8. Decode losslessly, then permit
            # binary only at explicit message payload fields, never identifiers.
            data = json_object(json.loads(response.content.decode("utf-8", errors="surrogateescape")))
            binary_fields = []

            def payload_path(path):
                if len(path) < 4 or path[0] != "result" or not isinstance(path[1], int):
                    return False
                tail = path[2:]
                if tail[0] == "in_msg":
                    tail = tail[1:]
                elif len(tail) > 1 and tail[0] == "out_msgs" and isinstance(tail[1], int):
                    tail = tail[2:]
                else:
                    return False
                return tail == ("message",) or tail in {("msg_data", "message"), ("msg_data", "text")}

            def convert(value, path=()):
                if isinstance(value, dict):
                    for key, child in list(value.items()):
                        if any(0xdc80 <= ord(char) <= 0xdcff for char in key):
                            raise ValueError("Invalid UTF-8 in Toncenter JSON field name")
                        value[key] = convert(child, path + (key,))
                elif isinstance(value, list):
                    for index, child in enumerate(value):
                        value[index] = convert(child, path + (index,))
                elif isinstance(value, str) and any(0xdc80 <= ord(char) <= 0xdcff for char in value):
                    if not payload_path(path):
                        raise ValueError(f"Invalid UTF-8 outside a message payload: {path}")
                    raw = value.encode("utf-8", errors="surrogateescape")
                    binary_fields.append(list(path))
                    return {"encoding": "base64", "data": base64.b64encode(raw).decode("ascii"),
                        "binary_payload": True, "decode_status": "invalid_utf8", "byte_length": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest()}
                return value

            convert(data)
            if not binary_fields:
                raise ValueError("Invalid UTF-8 response has no supported binary message payload")
            data["_gansar_binary_payloads"] = {"fields": binary_fields,
                "response_sha256": hashlib.sha256(response.content).hexdigest()}
            return data

    def _record_binary_warning(self, out: AddressReport, data: dict) -> None:
        detail = data.get("_gansar_binary_payloads")
        if detail:
            out.errors.append(f"{self.name}: binary_payload_warning: {len(detail['fields'])} invalid UTF-8 message fields retained as base64; response_sha256={detail['response_sha256']}")

    def _message_text(self, msg: dict) -> str | None:
        data = json_object(msg.get("msg_data"))
        if data.get("@type") == "msg.dataEncryptedText":
            return None
        plain = msg.get("message")
        if data.get("@type") == "msg.dataText" and isinstance(plain, str) and plain:
            return plain
        text = data.get("message") or data.get("text")
        if not isinstance(text, str) or not text:
            return None
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                return decoder(text + "=" * (-len(text) % 4)).decode("utf-8").strip("\x00") or None
            except (ValueError, UnicodeDecodeError):
                continue
        return None

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["ton"], sources_used=[self.name])
        self._partial_report = out
        resume = getattr(self, "_resume_state", {})
        state = stream_state(out, self.name, "account_transactions", resume=resume.get("account_transactions"), record_type="account_transactions")
        old_head = resume.get("account_transactions_refresh", {})
        if getattr(self, "_incremental", False) or (old_head and not old_head.get("exhausted")):
            head = stream_state(out, self.name, "account_transactions_refresh", resume=old_head if old_head and not old_head.get("exhausted") else {}, record_type="account_transactions")
            head.setdefault("overlap_boundary", getattr(self, "_known_boundaries", {}).get("account_transactions", 0))
            await self._fetch_window(address, out, head, stop_on_known=True)
            if head.get("exhausted") and head.get("stop_reason") == "endpoint_exhausted":
                state.update({"exhausted": True, "stop_reason": "fresh_history_endpoint_exhausted"})
        if not state.get("exhausted"):
            await self._fetch_window(address, out, state)
        return out

    async def _fetch_window(self, address: str, out: AddressReport, state: dict, *, stop_on_known: bool = False) -> AddressReport:
        if state.get("exhausted"):
            return out
        resume = state.get("next_cursor") or {}
        try:
            async with shared_async_client(min(self._timeout, 8.0)) as client:
                try:
                    data = await self._load_transactions(client, address, "true" if resume else "false", resume.get("lt"), resume.get("hash"))
                except httpx.HTTPStatusError as e:
                    if e.response.status_code in {500, 502, 503, 504}:
                        await asyncio.sleep(0.25)
                        data = await self._load_transactions(client, address, "true")
                    else:
                        raise
        except httpx.HTTPError as e:
            state["stop_reason"] = "provider_error"
            out.errors.append(f"{self.name}: {http_error_message(e)}")
            out.source_health.append(SourceHealth(source=self.name, status="error", timeout_seconds=min(self._timeout, 8.0), retry_strategy="standard request, then archival fallback"))
            return out
        except Exception as e:
            state["stop_reason"] = "provider_error"
            out.errors.append(f"{self.name}: {e}")
            out.source_health.append(SourceHealth(source=self.name, status="error", timeout_seconds=min(self._timeout, 8.0), retry_strategy="standard request, then archival fallback"))
            return out

        first_page = data.get("result") if isinstance(data, dict) else []
        if not isinstance(first_page, list):
            out.errors.append(f"{self.name}: unexpected_response")
            out.source_health.append(SourceHealth(source=self.name, status="partial", timeout_seconds=min(self._timeout, 8.0), retry_strategy="standard request, then archival fallback", details="unexpected response"))
            return out
        self._record_binary_warning(out, data)
        txs = list(first_page)
        self._parse_transactions(address, out, first_page)
        overlap = stop_on_known and any(canonical_hash((item.get("transaction_id") or {}).get("hash") or item.get("hash")) in getattr(self, "_known_hashes", set()) and (not state.get("overlap_boundary") or provider_record_order("account_transactions", item) <= state["overlap_boundary"]) for item in first_page)
        observe_page(state, first_page, dict(json_object(first_page[-1].get("transaction_id"))) if first_page else resume, exhausted=len(first_page) < 100 or overlap, stop_reason="overlap_stored_history" if overlap else None)
        lt = None
        tx_hash = None
        if first_page:
            last_id = json_object(first_page[-1].get("transaction_id"))
            lt = str(last_id.get("lt") or "") or None
            tx_hash = str(last_id.get("hash") or "") or None
        try:
            async with shared_async_client(min(self._timeout, 8.0)) as client:
                for _ in range(999 if getattr(self, "_continuous", False) else 5):
                    if state.get("exhausted") or not lt or not tx_hash:
                        break
                    await asyncio.sleep(0.18)
                    page_data = await self._load_transactions(client, address, "true", lt, tx_hash)
                    self._record_binary_warning(out, page_data)
                    page = page_data.get("result") if isinstance(page_data, dict) else []
                    if not isinstance(page, list):
                        state["stop_reason"] = "malformed_page"
                        break
                    if not page:
                        observe_page(state, [], {"lt": lt, "hash": tx_hash}, exhausted=True)
                        break
                    seen = {(json_object(item.get("transaction_id")).get("lt"), json_object(item.get("transaction_id")).get("hash")) for item in txs}
                    fresh = [item for item in page if (json_object(item.get("transaction_id")).get("lt"), json_object(item.get("transaction_id")).get("hash")) not in seen]
                    if not fresh:
                        state["stop_reason"] = "repeated_page"
                        break
                    txs.extend(fresh)
                    self._parse_transactions(address, out, fresh)
                    last_id = json_object(page[-1].get("transaction_id"))
                    next_lt = str(last_id.get("lt") or "") or None
                    next_hash = str(last_id.get("hash") or "") or None
                    overlap = stop_on_known and any(canonical_hash((item.get("transaction_id") or {}).get("hash") or item.get("hash")) in getattr(self, "_known_hashes", set()) and (not state.get("overlap_boundary") or provider_record_order("account_transactions", item) <= state["overlap_boundary"]) for item in page)
                    observe_page(state, page, {"lt": next_lt, "hash": next_hash}, exhausted=len(page) < 100 or overlap, stop_reason="overlap_stored_history" if overlap else None)
                    if next_lt == lt and next_hash == tx_hash:
                        state["stop_reason"] = "repeated_cursor"
                        break
                    lt, tx_hash = next_lt, next_hash
                    if len(page) < 100:
                        break
        except httpx.HTTPStatusError as e:
            detail = http_error_message(e)
            if e.response.status_code == 429:
                detail = "http 429 after retry"
            state["stop_reason"] = "provider_error"
            out.errors.append(f"{self.name}: archival_page: {detail}")
        except Exception as e:
            state["stop_reason"] = "provider_error"
            out.errors.append(f"{self.name}: archival_page: {e}")

        return out

    def _parse_transactions(self, address: str, out: AddressReport, txs: list[dict]) -> None:
        for tx in txs:
            try:
                txid = tx.get("transaction_id", {}).get("hash") or tx.get("hash")
                ts = tx.get("utime") or tx.get("now")
                dt = ton_datetime(ts)
                in_msg = json_object(tx.get("in_msg"))
                out_msgs = json_list(tx.get("out_msgs"))
                frm = ton_address_text(in_msg.get("source")) or ton_address_text(tx.get("account"))
                to = ton_address_text(in_msg.get("destination")) or address
                if not frm:
                    if sum(1 for item in out.errors if item == f"{self.name}: tx_parse_warning: empty from_address") < 2:
                        out.errors.append(f"{self.name}: tx_parse_warning: empty from_address")
                if not to:
                    if sum(1 for item in out.errors if item == f"{self.name}: tx_parse_warning: empty to_address") < 2:
                        out.errors.append(f"{self.name}: tx_parse_warning: empty to_address")
                value = in_msg.get("value")
                amount = ton_amount(value)
                direction = ton_direction(frm, to, address)
                if direction == "unknown" and out_msgs:
                    first = out_msgs[0] or {}
                    frm = address
                    to = ton_address_text(first.get("destination"))
                    value = first.get("value")
                    amount = ton_amount(value) if value is not None else amount
                    direction = "out"
                comment = self._message_text(in_msg)
                out.transactions.append(
                    Transaction(
                        chain="ton",
                        tx_hash=str(txid) if txid else "",
                        timestamp=dt,
                        from_address=frm,
                        to_address=to,
                        amount=amount,
                        amount_decimal=ton_amount_decimal(value),
                        asset="TON",
                        direction=direction,
                        source=self.name,
                        url=f"https://tonviewer.com/transaction/{txid}" if txid else None,
                        raw={"provider": "toncenter", "out_msgs": len(out_msgs), "comment": comment, "lt": tx.get("transaction_id", {}).get("lt") or tx.get("lt"), "message_index": "in", "transaction": tx},
                    )
                )
                for index, msg in enumerate(out_msgs):
                    msg = json_object(msg)
                    dest = ton_address_text(msg.get("destination"))
                    value = msg.get("value")
                    if not dest and value is None:
                        continue
                    out.transactions.append(
                        Transaction(
                            chain="ton",
                            tx_hash=str(txid) if txid else "",
                            timestamp=dt,
                            from_address=address,
                            to_address=dest,
                            amount=ton_amount(value),
                            amount_decimal=ton_amount_decimal(value),
                            asset="TON",
                            direction=ton_direction(address, dest, address),
                            source=self.name,
                            url=f"https://tonviewer.com/transaction/{txid}" if txid else None,
                            raw={"provider": "toncenter_out_msg", "parent_hash": txid, "message_index": index, "lt": tx.get("transaction_id", {}).get("lt") or tx.get("lt"), "message": msg, "comment": self._message_text(msg)},
                        )
                    )
            except Exception as e:
                out.errors.append(f"{self.name}: tx_parse: {e}")

