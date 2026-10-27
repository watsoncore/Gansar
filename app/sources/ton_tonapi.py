from __future__ import annotations

import logging
import asyncio
import base64
import os

import httpx

from app.models.report import AddressReport, Balance, Label, RiskFlag, TokenHolding, TonAsset, TonAssetEvent, Transaction
from app.sources.base import Source
from app.utils.http import http_error_message, json_list, json_object, retry_delay, shared_async_client
from app.utils.ton_assets import animation_url_from, asset_title, classify_asset, image_url_from, merge_asset, now_utc, related_addresses
from app.utils.ton_normalize import ton_address, ton_address_text, ton_amount, ton_canonical_address, ton_datetime, ton_direction, ton_text, ton_amount_decimal

from app.aggregator.collection_audit import stream_state, observe_page
from app.utils.event_identity import canonical_hash

logger = logging.getLogger(__name__)


class TonApiSource(Source):
    name = "tonapi"
    chain = "ton"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    def _warn(self, out: AddressReport, message: str, limit: int = 3) -> None:
        entry = f"{self.name}: {message}"
        if sum(1 for item in out.errors if item == entry) < limit:
            out.errors.append(entry)

    def _note(self, out: AddressReport, message: str, limit: int = 1) -> None:
        entry = f"{self.name}: {message}"
        if sum(1 for item in out.warnings if item == entry) < limit:
            out.warnings.append(entry)

    def _api_key(self) -> str:
        return (os.getenv("TONAPI_KEY") or os.getenv("TON_API_KEY") or "").strip()

    def _headers(self) -> dict[str, str] | None:
        key = self._api_key()
        return {"Authorization": f"Bearer {key}"} if key else None

    def _safe_address(self, value) -> str:
        found = ton_address_text(value)
        return found if ton_canonical_address(found) else ""

    def _address_from(self, value, *keys: str) -> str:
        if not keys:
            return self._safe_address(value)
        if isinstance(value, dict):
            for key in keys:
                found = self._safe_address(value.get(key))
                if found:
                    return found
                nested = value.get(key)
                if isinstance(nested, dict):
                    found = self._address_from(nested, "address", "account", "account_address", "user_friendly")
                    if found:
                        return found
        return ""

    def _addresses_from_payload(self, value) -> list[str]:
        out: list[str] = []
        if isinstance(value, dict):
            direct = self._safe_address(value)
            if direct:
                out.append(direct)
            for nested in value.values():
                out.extend(self._addresses_from_payload(nested))
        elif isinstance(value, list):
            for nested in value:
                out.extend(self._addresses_from_payload(nested))
        elif isinstance(value, str):
            direct = self._safe_address(value)
            if direct:
                out.append(direct)
        return list(dict.fromkeys(item for item in out if item))

    def _message_text(self, value) -> str | None:
        if not isinstance(value, dict):
            return None
        decoded = json_object(value.get("decoded_body"))
        for candidate in (decoded.get("text"), value.get("message"), value.get("comment")):
            found = ton_text(candidate)
            if found:
                return found
        raw_text = json_object(value.get("msg_data")).get("text") or value.get("raw_body")
        if isinstance(raw_text, str) and raw_text:
            for decoder in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    return decoder(raw_text + "=" * (-len(raw_text) % 4)).decode("utf-8", errors="ignore").strip("\x00") or None
                except Exception:
                    continue
        return None

    def _label_account(self, out: AddressReport, account, source_url: str | None = None, confidence: float = 0.72) -> None:
        if not isinstance(account, dict):
            return
        address = self._safe_address(account)
        name = ton_text(account.get("name") or account.get("domain"))
        if address and name:
            out.labels.append(Label(chain="ton", address=address, label=name[:120], source=self.name, confidence=confidence, raw={"url": source_url}))

    async def _get_json(self, client, url: str, out: AddressReport, label: str, params: dict | None = None, retries: int = 2) -> dict:
        last_error: Exception | None = None
        headers = self._headers()
        for attempt in range(retries + 1):
            try:
                gate = getattr(self, "_request_gate", None)
                if gate is not None:
                    async with gate:
                        r = await client.get(url, params=params, headers=headers)
                else:
                    r = await client.get(url, params=params, headers=headers)
                if r.status_code in {429, 500, 502, 503, 504} and attempt < retries:
                    if r.status_code == 429:
                        self._note(out, f"{label}: http 429 retry")
                    await asyncio.sleep(retry_delay(r, attempt, 0.55, cap=4.0))
                    continue
                if r.status_code >= 400:
                    detail = f"http {r.status_code}"
                    if r.status_code == 429:
                        detail = "http 429 after retry; fallback"
                    out.errors.append(f"{self.name}: {label}: {detail}")
                    return {}
                return json_object(r.json())
            except httpx.HTTPError as e:
                last_error = e
                if attempt < retries:
                    await asyncio.sleep(retry_delay(None, attempt, 0.55, cap=4.0))
                    continue
            except Exception as e:
                out.errors.append(f"{self.name}: {label}_parse: {type(e).__name__}: {e}")
                return {}
        if last_error is not None:
            detail = http_error_message(last_error)
            if detail == "http 429":
                detail = "http 429 after retry; fallback"
            out.errors.append(f"{self.name}: {label}: {detail}")
        return {}

    def _event_parties(self, address: str, event: dict, action: dict, details: dict) -> tuple[str, str]:
        source = self._address_from(details, "sender", "source", "old_owner", "owner", "seller", "from", "from_address")
        dest = self._address_from(details, "recipient", "destination", "new_owner", "buyer", "to", "to_address", "receiver")
        if not source:
            source = self._address_from(action, "sender", "source", "old_owner", "account", "from")
        if not dest:
            dest = self._address_from(action, "recipient", "destination", "new_owner", "to")
        return source, dest

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["ton"], sources_used=[self.name])
        self._partial_report = out
        self._request_gate = asyncio.Semaphore(2)
        base = "https://tonapi.io/v2"
        acc = {}
        txs = []

        async def load_account() -> dict:
            async with shared_async_client(min(self._timeout, 5.0)) as client:
                return await self._get_json(client, f"{base}/accounts/{address}", out, "account", retries=1)

        async def load_transactions() -> list:
            resume = getattr(self, "_resume_state", {})
            state = stream_state(out, self.name, "account_transactions", resume=resume.get("account_transactions"), record_type="account_transactions")
            collected = []
            old_head = resume.get("account_transactions_refresh", {})
            if getattr(self, "_incremental", False) or (old_head and not old_head.get("exhausted")):
                head = stream_state(out, self.name, "account_transactions_refresh", resume=old_head if old_head and not old_head.get("exhausted") else {}, record_type="account_transactions")
                head.setdefault("overlap_boundary", getattr(self, "_known_boundaries", {}).get("account_transactions", 0))
                collected.extend(await self._collect_transaction_window(address, out, head, stop_on_known=True))
                if head.get("exhausted") and head.get("stop_reason") == "endpoint_exhausted":
                    state.update({"exhausted": True, "stop_reason": "fresh_history_endpoint_exhausted", "next_cursor": head.get("next_cursor")})
            if not state.get("exhausted"):
                collected.extend(await self._collect_transaction_window(address, out, state))
            return collected

        async def enrichment() -> None:
            async def run(label, loader, limit):
                budget = self._timeout if label in {"nfts", "events"} else min(self._timeout, limit)
                try:
                    await asyncio.wait_for(loader(address, out), timeout=budget)
                except asyncio.TimeoutError:
                    out.errors.append(f"{self.name}: {label}: timeout; cursor retained")
                except Exception as exc:
                    out.errors.append(f"{self.name}: {label}: {exc}")
            await asyncio.gather(*(run(label, loader, limit) for label, loader, limit in
                (("nfts", self._fetch_nfts, 10.0), ("jettons", self._fetch_jettons, 8.0), ("events", self._fetch_events, 8.0), ("dns", self._fetch_dns, 4.0))))
        if getattr(self, "_continuous", False):
            # Independent streams advance fairly under the same session deadline.
            acc, txs, _ = await asyncio.gather(load_account(), load_transactions(), enrichment())
        else:
            acc, txs = await asyncio.gather(load_account(), load_transactions())

        if acc:
            try:
                bal = int(acc.get("balance", 0))
                out.balances.append(
                    Balance(
                        chain="ton",
                        address=address,
                        asset="TON",
                        amount=bal / 1e9,
                        amount_decimal=ton_amount_decimal(bal),
                        amount_base_units=bal,
                        decimals=9,
                        source=self.name,
                        url=f"https://tonviewer.com/{address}",
                        raw={"nanoton": bal},
                    )
                )
            except Exception as e:
                out.errors.append(f"{self.name}: balance_parse: {e}")

        async def bounded(label: str, coro, limit: float) -> None:
            try:
                await asyncio.wait_for(coro, timeout=limit)
            except asyncio.TimeoutError:
                out.errors.append(f"{self.name}: {label}: timeout")
            except Exception as e:
                out.errors.append(f"{self.name}: {label}: {http_error_message(e) if isinstance(e, httpx.HTTPError) else e}")

        for label, loader, limit in (() if getattr(self, "_continuous", False) else (
            ("nfts", self._fetch_nfts, min(self._timeout, 10.0)),
            ("jettons", self._fetch_jettons, min(self._timeout, 8.0)),
            ("events", self._fetch_events, min(self._timeout, 8.0)),
            ("dns", self._fetch_dns, min(self._timeout, 4.0)),
        )):
            await bounded(label, loader(address, out), limit)
            await asyncio.sleep(0.08)
        return out

    async def _collect_transaction_window(self, address: str, out: AddressReport, state: dict, *, stop_on_known: bool = False) -> list:
        collected = []
        before_lt = state.get("next_cursor")
        if state.get("exhausted"):
            return collected
        seen_cursors = set()
        try:
            async with shared_async_client(min(self._timeout, 6.0)) as client:
                for page_index in range(1000 if getattr(self, "_continuous", False) else 8):
                    params = {"limit": 100}
                    if before_lt:
                        params["before_lt"] = before_lt
                    data = await self._get_json(client, f"https://tonapi.io/v2/blockchain/accounts/{address}/transactions", out, "txs", params=params, retries=2)
                    if data and not isinstance(data.get("transactions"), list):
                        state["stop_reason"] = "malformed_page"
                        out.errors.append(f"{self.name}: txs: transactions array missing")
                        break
                    page = data.get("transactions") or []
                    page = [item for item in page if isinstance(item, dict)]
                    if not page:
                        if data:
                            observe_page(state, [], before_lt, exhausted=True)
                        else:
                            state["stop_reason"] = "provider_error_or_empty_response"
                        break
                    collected.extend(page)
                    self._parse_transactions(address, out, page)
                    next_lt = page[-1].get("lt") or page[-1].get("prev_trans_lt")
                    overlap = stop_on_known and any(canonical_hash(item.get("hash") or (item.get("transaction_id") or {}).get("hash")) in getattr(self, "_known_hashes", set()) and (not state.get("overlap_boundary") or int(item.get("lt") or 0) <= state["overlap_boundary"]) for item in page)
                    exhausted = len(page) < 100 or overlap
                    stalled = not next_lt or str(next_lt) in seen_cursors or str(next_lt) == str(before_lt)
                    observe_page(state, page, next_lt, exhausted=exhausted, stop_reason="overlap_stored_history" if overlap else "repeated_or_missing_cursor" if stalled and not exhausted else None)
                    if exhausted or stalled:
                        break
                    seen_cursors.add(str(next_lt))
                    before_lt = next_lt
                    await asyncio.sleep(0.12)
                else:
                    state["stop_reason"] = "page_safety_ceiling"
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: txs: {http_error_message(e)}")
        except Exception as e:
            out.errors.append(f"{self.name}: txs_parse: {e}")
        return collected

    def _parse_transactions(self, address: str, out: AddressReport, txs: list[dict]) -> None:
        for t in txs:
            try:
                txid = t.get("transaction_id", {}).get("hash") or t.get("hash") or t.get("id")
                utime = t.get("utime") or t.get("now") or t.get("timestamp")
                dt = ton_datetime(utime)
                in_msg = json_object(t.get("in_msg"))
                out_msgs = json_list(t.get("out_msgs"))
                self._label_account(out, t.get("account"))
                self._label_account(out, in_msg.get("source"))
                self._label_account(out, in_msg.get("destination"))
                # An external envelope has no on-chain sender or transferred
                # asset value. Keep its real account TX/raw observation without
                # turning account fallback and placeholder zero into a payment.
                message_type = in_msg.get("msg_type")
                external_envelope = bool(message_type) and message_type != "int_msg"
                frm = None if external_envelope else self._safe_address(in_msg.get("source")) or self._safe_address(t.get("account"))
                to = self._safe_address(in_msg.get("destination")) or address
                if not frm and out_msgs and not external_envelope:
                    frm = address
                if not frm and not external_envelope:
                    self._warn(out, "tx_parse_warning: empty from_address")
                if not to:
                    self._warn(out, "tx_parse_warning: empty to_address")
                val = None if external_envelope else ton_amount(in_msg.get("value"))
                direction = "unknown" if external_envelope else ton_direction(frm, to, address)
                out.transactions.append(
                    Transaction(
                        chain="ton",
                        tx_hash=str(txid) if txid else "",
                        timestamp=dt,
                        from_address=frm,
                        to_address=to,
                        amount=val,
                        amount_decimal=None if external_envelope else ton_amount_decimal(in_msg.get("value")),
                        amount_base_units=None if external_envelope else int(in_msg.get("value")) if str(in_msg.get("value") or "").isdigit() else None,
                        decimals=None if external_envelope else 9,
                        asset=None if external_envelope else "TON",
                        direction=direction,
                        source=self.name,
                        url=f"https://tonviewer.com/transaction/{txid}" if txid else None,
                        raw={"provider": "tonapi", "comment": self._message_text(in_msg), "lt": t.get("lt"), "prev_trans_lt": t.get("prev_trans_lt"), "message_index": "in", "transaction": t},
                    )
                )
                for index, msg in enumerate(out_msgs):
                    msg = json_object(msg)
                    self._label_account(out, msg.get("source"))
                    self._label_account(out, msg.get("destination"))
                    msg_to = self._safe_address(msg.get("destination"))
                    msg_value = ton_amount(msg.get("value"))
                    if not msg_to and msg_value is None:
                        continue
                    out.transactions.append(
                        Transaction(
                            chain="ton",
                            tx_hash=str(txid) if txid else "",
                            amount_decimal=ton_amount_decimal(msg.get("value")),
                            amount_base_units=int(msg.get("value")) if str(msg.get("value") or "").isdigit() else None,
                            decimals=9,
                            timestamp=dt,
                            from_address=address,
                            to_address=msg_to,
                            amount=msg_value,
                            asset="TON",
                            direction=ton_direction(address, msg_to, address),
                            source=self.name,
                            url=f"https://tonviewer.com/transaction/{txid}" if txid else None,
                            raw={"provider": "tonapi_out_msg", "parent_hash": txid, "message_index": index, "lt": t.get("lt"), "message": msg, "comment": self._message_text(msg)},
                        )
                    )
            except Exception as e:
                out.errors.append(f"{self.name}: tx_parse: {e}")


    async def _fetch_jettons(self, address: str, out: AddressReport) -> None:
        base = "https://tonapi.io/v2"
        url = f"{base}/accounts/{address}/jettons"
        try:
            async with shared_async_client(min(self._timeout, 5.0)) as client:
                data = await self._get_json(client, url, out, "jettons", params={"currencies": "ton"}, retries=2)
                if not data:
                    return
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: jettons: {http_error_message(e)}")
            return
        except Exception as e:
            out.errors.append(f"{self.name}: jettons: {e}")
            return

        balances = json_list(data.get("balances") or data.get("jettons"))
        for b in balances:
            try:
                jet = b.get("jetton") or {}
                sym = (jet.get("symbol") or jet.get("metadata", {}).get("symbol")) if isinstance(jet, dict) else None
                name = (jet.get("name") or jet.get("metadata", {}).get("name")) if isinstance(jet, dict) else None
                master = ton_address(jet)
                amount_raw = b.get("balance")
                jet_decimals = int(jet.get("decimals") if jet.get("decimals") is not None else jet.get("metadata", {}).get("decimals", 9)) if isinstance(jet, dict) else 9
                out.tokens.append(
                    TokenHolding(
                        chain="ton",
                        address=address,
                        contract=master,
                        symbol=sym,
                        name=name,
                        amount=ton_amount(amount_raw, jet_decimals),
                        amount_decimal=ton_amount_decimal(amount_raw, jet_decimals),
                        holding_status="current",
                        source=self.name,
                        url=url,
                        raw={"balance": amount_raw, "decimals": jet_decimals, "asset_type": "jetton", "verification": jet.get("verification") if isinstance(jet, dict) else None},
                    )
                )
                if master:
                    merge_asset(
                        out,
                        TonAsset(
                            asset_id=master,
                            type="jetton",
                            name=name,
                            title=sym or name,
                            collection="Jettons",
                            owner_address=address,
                            last_seen=now_utc(),
                            source=self.name,
                            external_url=f"https://tonviewer.com/{master}",
                            evidence_url=url,
                            collected_at=now_utc(),
                            confidence=0.78,
                            raw={"asset_type": "jetton", "balance": amount_raw, "verification": jet.get("verification") if isinstance(jet, dict) else None},
                        ),
                    )
            except Exception as e:
                out.errors.append(f"{self.name}: jetton_parse: {e}")

    async def _fetch_nfts(self, address: str, out: AddressReport) -> None:
        url = f"https://tonapi.io/v2/accounts/{address}/nfts"
        state = stream_state(out, self.name, "nft_inventory", record_type="nft_items")
        offset = 0  # Current ownership inventory is mutable and must be refreshed.
        async with shared_async_client(min(self._timeout, 10.0)) as client:
            for _ in range(100 if getattr(self, "_continuous", False) else 1):
                data = await self._get_json(client, url, out, "nfts", params={"limit": 100, "offset": offset}, retries=2)
                if not data:
                    state["stop_reason"] = "provider_error_or_empty_response"
                    break
                if not isinstance(data.get("nft_items", data.get("items")), list):
                    state["stop_reason"] = "malformed_page"
                    out.errors.append(f"{self.name}: nfts: NFT array missing")
                    break
                items = json_list(data.get("nft_items") or data.get("items"))
                self._parse_nfts(address, out, items, url)
                exhausted = len(items) < 100
                offset += len(items)
                observe_page(state, items, {"offset": offset}, exhausted=exhausted)
                if exhausted:
                    break
                await asyncio.sleep(0.12)
            else:
                state["stop_reason"] = "page_safety_ceiling"

    def _parse_nfts(self, address: str, out: AddressReport, items: list, url: str) -> None:
        for item in items:
            try:
                nft_address = ton_address(item)
                collection = item.get("collection") or {}
                metadata = item.get("metadata") or {}
                name = asset_title(item, nft_address)
                collection_address = ton_address(collection)
                collection_name = ton_text(collection.get("name")) if isinstance(collection, dict) else None
                asset_type = classify_asset(name, collection_name, "nft")
                out.tokens.append(
                    TokenHolding(
                        chain="ton",
                        address=address,
                        contract=nft_address,
                        symbol="NFT",
                        name=name[:120] if name else None,
                        amount=1,
                        holding_status="current" if ton_canonical_address(ton_address(item.get("owner"))) == ton_canonical_address(address) else "unknown",
                        source=self.name,
                        url=f"https://getgems.io/nft/{nft_address}" if nft_address else url,
                        raw={"asset_type": "nft", "collection_address": collection_address, "collection": collection, "metadata": metadata},
                    )
                )
                if nft_address:
                    merge_asset(
                        out,
                        TonAsset(
                            asset_id=nft_address,
                            type=asset_type,
                            name=name[:120] if name else None,
                            title=name[:120] if name else None,
                            collection=collection_name,
                            image_url=image_url_from(item),
                            animation_url=animation_url_from(item),
                            owner_address=ton_address(item.get("owner")) or "",
                            ownership_status="current" if ton_address(item.get("owner")) else "unknown",
                            ownership_observed_at=now_utc(),
                            last_seen=now_utc(),
                            marketplace=None,
                            source=self.name,
                            external_url=f"https://getgems.io/nft/{nft_address}",
                            evidence_url=url,
                            collected_at=now_utc(),
                            confidence=0.82,
                            related_addresses=related_addresses(collection_address, address),
                            raw={"asset_type": asset_type, "collection_address": collection_address, "metadata": metadata, "nft_item": item},
                        ),
                    )
                low = (name or "").lower()
                if ".ton" in low or "telegram" in low or "username" in low:
                    out.labels.append(Label(chain="ton", address=address, label=f"TON NFT: {name[:90]}", source=self.name, confidence=0.7, raw={"nft": nft_address}))
            except Exception as e:
                out.errors.append(f"{self.name}: nft_parse: {e}")

    async def _fetch_events(self, address: str, out: AddressReport) -> None:
        resume = getattr(self, "_resume_state", {})
        state = stream_state(out, self.name, "account_events", resume=resume.get("account_events"), record_type="action_events")
        old_head = resume.get("account_events_refresh", {})
        if getattr(self, "_incremental", False) or (old_head and not old_head.get("exhausted")):
            head = stream_state(out, self.name, "account_events_refresh", resume=old_head if old_head and not old_head.get("exhausted") else {}, record_type="action_events")
            head.setdefault("overlap_boundary", getattr(self, "_known_boundaries", {}).get("account_events", 0))
            await self._collect_event_window(address, out, head, stop_on_known=True)
            if head.get("exhausted") and head.get("stop_reason") == "endpoint_exhausted":
                state.update({"exhausted": True, "stop_reason": "fresh_history_endpoint_exhausted"})
        if not state.get("exhausted"):
            await self._collect_event_window(address, out, state)

    async def _collect_event_window(self, address: str, out: AddressReport, state: dict, *, stop_on_known: bool = False) -> None:
        url = f"https://tonapi.io/v2/accounts/{address}/events"
        events = []
        try:
            next_from = state.get("next_cursor")
            if state.get("exhausted"):
                return
            seen_cursors = set()
            async with shared_async_client(min(self._timeout, 8.0)) as client:
                for _ in range(1000 if getattr(self, "_continuous", False) else 5):
                    params = {"limit": 100}
                    if next_from:
                        params["before_lt"] = next_from
                    data = await self._get_json(client, url, out, "events", params=params, retries=2)
                    if not data:
                        state["stop_reason"] = "provider_error_or_empty_response"
                        break
                    if not isinstance(data.get("events"), list):
                        state["stop_reason"] = "malformed_page"
                        out.errors.append(f"{self.name}: events: events array missing")
                        break
                    page = json_list(data.get("events"))
                    if not page:
                        observe_page(state, [], next_from, exhausted=True)
                        break
                    self._parse_events(address, out, page, url)
                    events.extend(page)
                    cursor = data.get("next_from") or page[-1].get("lt")
                    known = getattr(self, "_known_records", {}).get("account_events", set())
                    overlap = stop_on_known and any((canonical_hash(item.get("event_id") or item.get("id")) or str(item.get("event_id") or item.get("id") or "")) in known and (not state.get("overlap_boundary") or int(item.get("lt") or 0) <= state["overlap_boundary"]) for item in page)
                    exhausted = len(page) < 100 or overlap
                    stalled = not cursor or str(cursor) in seen_cursors or str(cursor) == str(next_from)
                    observe_page(state, page, cursor, exhausted=exhausted, stop_reason="overlap_stored_history" if overlap else "repeated_or_missing_cursor" if stalled and not exhausted else None)
                    if exhausted or stalled:
                        break
                    seen_cursors.add(str(cursor))
                    next_from = cursor
                    await asyncio.sleep(0.12)
                else:
                    state["stop_reason"] = "page_safety_ceiling"
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: events: {http_error_message(e)}")
            return

    def _parse_events(self, address: str, out: AddressReport, events: list[dict], url: str) -> None:
        for event in events:
            actions = json_list(event.get("actions"))
            event_id = event.get("event_id") or event.get("id")
            ts = ton_datetime(event.get("timestamp") or event.get("utime"))
            for action_index, action in enumerate(actions):
                try:
                    action = json_object(action)
                    action_type = action.get("type") or action.get("action_type") or "ton_action"
                    details = json_object(action.get(action_type) or action.get("details") or action)
                    preview = json_object(action.get("simple_preview"))
                    for account in json_list(preview.get("accounts")):
                        self._label_account(out, account, confidence=0.7)
                    source, dest = self._event_parties(address, event, action, details)
                    if not source:
                        self._warn(out, "event_parse_warning: empty from_address")
                    if not dest:
                        self._warn(out, "event_parse_warning: empty to_address")
                    action_type_lower = str(action_type).lower()
                    asset = "TON" if action_type_lower in {"tontransfer", "ton_transfer"} else None
                    jetton_data = json_object(details.get("jetton") or details.get("jetton_master"))
                    decimals = int(jetton_data["decimals"]) if "jetton" in action_type_lower and jetton_data.get("decimals") is not None else 9 if asset == "TON" else None
                    amount_raw = details.get("amount") if details.get("amount") is not None else details.get("value")
                    amount = ton_amount(amount_raw, decimals) if decimals is not None else None
                    success = True if str(action.get("status") or "").lower() in {"ok", "success"} else False if str(action.get("status") or "").lower() in {"failed", "fail", "error"} else None
                    if "jetton" in action_type_lower:
                        master = ton_canonical_address(details.get('jetton') or details.get('jetton_master'))
                        asset = f"JETTON:{master}" if master else None
                    if "nft" in action_type_lower or "auction" in action_type_lower:
                        asset = f"NFT:{ton_address(details.get('nft') or details.get('item')) or ton_text(details.get('nft')) or ''}"
                        # TON consideration belongs to sale evidence; it is not
                        # the quantity of an NFT transfer or another money flow.
                        amount = None
                        amount_raw = None
                    if asset is None:
                        amount = None
                        amount_raw = None
                    direction = ton_direction(source, dest, address)
                    out.transactions.append(
                        Transaction(
                            chain="ton",
                            tx_hash=str(event_id) if event_id else "",
                            timestamp=ts,
                            amount_decimal=ton_amount_decimal(amount_raw, decimals) if decimals is not None else None,
                            amount_base_units=int(amount_raw) if str(amount_raw or "").isdigit() else None,
                            decimals=decimals,
                            success=success,
                            from_address=source,
                            to_address=dest,
                            amount=amount,
                            asset=asset,
                            direction=direction,
                            source=self.name,
                            url=f"https://tonviewer.com/transaction/{event_id}" if event_id else None,
                            raw={"provider": "tonapi_events", "action_type": action_type, "event_id": event_id, "action_index": action_index, "lt": event.get("lt"), "action": action, "comment": ton_text(details.get("comment") or preview.get("description"))},
                        )
                    )
                    nft_id = ton_address(details.get("nft") or details.get("item"))
                    if nft_id:
                        event_type = "sale" if action_type_lower in {"nftpurchase", "nftsale"} and success is True else "listing" if "listing" in action_type_lower else "mint" if "mint" in action_type_lower and success is not False else "transfer" if "transfer" in action_type_lower else "interaction"
                        asset_event = TonAssetEvent(
                            action_index=action_index,
                            logical_time=int(event["lt"]) if event.get("lt") is not None else None,
                            nft_address=nft_id,
                            event_type=event_type,
                            timestamp=ts,
                            amount_decimal=ton_amount_decimal(amount_raw, decimals),
                            success=success,
                            from_address=source,
                            to_address=dest,
                            price=ton_amount(details.get("price") or details.get("amount")) if event_type == "sale" else None,
                            price_decimal=ton_amount_decimal(details.get("price") or details.get("amount")) if event_type == "sale" else None,
                            asset="TON" if event_type == "sale" else f"NFT:{nft_id}",
                            tx_hash=str(event_id) if event_id else None,
                            marketplace=None,
                            source=self.name,
                            evidence_url=f"https://tonviewer.com/transaction/{event_id}" if event_id else None,
                            confidence=0.68,
                            raw={"action_type": action_type, "action_index": action_index, "lt": event.get("lt"), "action": action},
                        )
                        merge_asset(
                            out,
                            TonAsset(
                                asset_id=nft_id,
                                type=classify_asset(ton_text(details.get("domain")) or ton_text(details.get("nft")), None, "nft"),
                                title=ton_text(details.get("domain")) or ton_text(details.get("nft")) or nft_id,
                                owner_address="",
                                ownership_status="historical",
                                previous_owners=list(dict.fromkeys(a for a in (source, dest) if a)) if success is True else [],
                                source=self.name,
                                external_url=f"https://getgems.io/nft/{nft_id}",
                                evidence_url=f"https://tonviewer.com/transaction/{event_id}" if event_id else None,
                                evidence_tx=str(event_id) if event_id else None,
                                collected_at=now_utc(),
                                confidence=0.65,
                                transfer_history=[asset_event] if event_type == "transfer" else [],
                                history_events=[asset_event],
                                sale_history=[asset_event] if event_type == "sale" else [],
                                related_addresses=related_addresses(source, dest),
                                raw={"asset_type": "event_asset", "action_type": action_type},
                            ),
                        )
                except Exception as e:
                    out.errors.append(f"{self.name}: event_action_parse: {e}")

    async def _fetch_dns(self, address: str, out: AddressReport) -> None:
        base = "https://tonapi.io/v2"
        url = f"{base}/accounts/{address}/dns/backresolve"
        try:
            async with shared_async_client(min(self._timeout, 4.0)) as client:
                data = await self._get_json(client, url, out, "dns", retries=1)
                if not data:
                    return
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: dns: {http_error_message(e)}")
            return

        domains = data.get("domains") or data.get("names") or []
        if isinstance(domains, str):
            domains = [domains]
        for domain in domains[:20]:
            name = ton_text(domain)
            if name:
                out.labels.append(Label(chain="ton", address=address, label=f"TON DNS: {name}", source=self.name, confidence=0.85, raw={"domain": domain}))
                if "t.me" in name.lower() or "telegram" in name.lower():
                    out.risk_flags.append(
                        RiskFlag(
                            chain="ton",
                            address=address,
                            flag="telegram_linked_ton_dns",
                            severity="low",
                            source=self.name,
                            details=name,
                        )
                    )

