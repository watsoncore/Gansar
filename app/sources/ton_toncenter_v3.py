from __future__ import annotations

import httpx
import asyncio
import os

from app.models.report import AddressReport, Label, RiskFlag, SourceHealth, TokenHolding, TonAsset, TonAssetEvent, Transaction
from app.sources.base import Source
from app.utils.http import http_error_message, json_list, json_object, retry_delay, shared_async_client
from app.utils.ton_assets import asset_title, classify_asset, image_url_from, merge_asset, now_utc, related_addresses
from app.utils.ton_normalize import ton_address, ton_address_text, ton_amount, ton_amount_decimal, ton_datetime, ton_direction, ton_text, ton_canonical_address


from app.aggregator.collection_audit import stream_state, observe_page, provider_record_key, provider_record_order


class TonCenterV3Source(Source):
    name = "toncenter_v3"
    chain = "ton"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    def _headers(self) -> dict[str, str] | None:
        key = (os.getenv("TONCENTER_API_KEY") or os.getenv("TON_CENTER_API_KEY") or "").strip()
        return {"X-API-Key": key} if key else None

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["ton"], sources_used=[self.name])
        self._partial_report = out
        self._request_gate = asyncio.Semaphore(2)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(1.0, self._timeout - 0.5)
        loaders = (
            (self._address_information, 1.2),
            (self._address_book, 1.2),
            (self._transactions, 2.0),
            (self._jetton_transfers, 2.0),
            (self._nft_items, 2.0),
            (self._nft_transfers, 2.0),
            (self._actions, 2.0),
        )
        async with shared_async_client(min(self._timeout, 4.0)) as client:
            async def run_loader(loader, limit):
                remaining = deadline - loop.time()
                if remaining <= 0.2:
                    out.warnings.append(f"{self.name}: partial_timeout")
                    return
                try:
                    budget = remaining if getattr(self, "_continuous", False) else min(limit, remaining)
                    await asyncio.wait_for(loader(client, address, out), timeout=max(0.2, budget))
                except asyncio.TimeoutError:
                    out.warnings.append(f"{self.name}: {loader.__name__.lstrip('_')}: timeout; cursor retained")
                except Exception as exc:
                    out.errors.append(f"{self.name}: subrequest: {exc}")
            if getattr(self, "_continuous", False):
                # Fair request queue, rather than holding a semaphore for an
                # entire long history/inventory stream.
                await asyncio.gather(*(run_loader(loader, limit) for loader, limit in loaders))
            else:
                for loader, limit in loaders:
                    await run_loader(loader, limit)
                    await asyncio.sleep(0.12)
        if out.warnings or out.errors:
            out.source_health.append(
                SourceHealth(
                    source=self.name,
                    status="partial" if out.ton_assets or out.tokens or out.transactions or out.labels or out.risk_flags else "error",
                    timeout_seconds=self._timeout,
                    retry_strategy="bounded subrequests, partial return",
                    details=f"assets={len(out.ton_assets)} tokens={len(out.tokens)} tx={len(out.transactions)}",
                )
            )
        return out

    async def _get(self, client, path: str, params: dict) -> dict:
        for attempt in range(3):
            gate = getattr(self, "_request_gate", None)
            if gate is not None:
                async with gate:
                    r = await client.get(f"https://toncenter.com/api/v3/{path}", params=params, headers=self._headers())
            else:
                r = await client.get(f"https://toncenter.com/api/v3/{path}", params=params, headers=self._headers())
            if r.status_code in {429, 500, 502, 503, 504} and attempt < 2:
                await asyncio.sleep(retry_delay(r, attempt, 0.55, cap=4.0))
                continue
            r.raise_for_status()
            data = r.json()
            return json_object(data)
        return {}

    async def _pages(self, client, out: AddressReport, path: str, params: dict, key: str, kind: str):
        mutable = kind == "nft_inventory"
        resume = {} if mutable else getattr(self, "_resume_state", {}).get(kind, {})
        state = stream_state(out, self.name, kind, resume=resume, record_type=kind)
        head_kind = kind + "_refresh"
        old_head = getattr(self, "_resume_state", {}).get(head_kind, {})
        if not mutable and (getattr(self, "_incremental", False) or (old_head and not old_head.get("exhausted"))):
            head = stream_state(out, self.name, head_kind, resume=old_head if old_head and not old_head.get("exhausted") else {}, record_type=kind)
            head.setdefault("overlap_boundary", getattr(self, "_known_boundaries", {}).get(kind, 0))
            async for data in self._page_window(client, out, path, params, key, kind, head, stop_on_known=True):
                yield data
            if head.get("exhausted"):
                if head.get("stop_reason") == "endpoint_exhausted":
                    state.update({"exhausted": True, "stop_reason": "fresh_history_endpoint_exhausted"})
                elif state.get("next_cursor"):
                    state["next_cursor"] = {"offset": int(state["next_cursor"].get("offset", 0)) + head.get("fresh_records", 0)}
                    head["tail_offset_adjustment"] = head.get("fresh_records", 0)
        if state.get("exhausted") and not mutable:
            return
        async for data in self._page_window(client, out, path, params, key, kind, state):
            yield data

    async def _page_window(self, client, out: AddressReport, path: str, params: dict, key: str, kind: str, state: dict, *, stop_on_known: bool = False):
        offset = int((state.get("next_cursor") or {}).get("offset", 0))
        seen = set()
        known = getattr(self, "_known_records", {}).get(kind, set())
        boundary = state.get("overlap_boundary", 0)
        for _ in range(1000 if getattr(self, "_continuous", False) else 1):
            try:
                data = await self._get(client, path, {**params, "offset": offset})
            except Exception as exc:
                state["stop_reason"] = "provider_error"
                out.errors.append(f"{self.name}: {kind}: {http_error_message(exc) if isinstance(exc, httpx.HTTPError) else exc}")
                return
            if not isinstance(data.get(key), list):
                state["stop_reason"] = "malformed_page"
                out.errors.append(f"{self.name}: {kind}: {key} array missing")
                return
            rows = json_list(data.get(key))
            import hashlib, json
            digest = hashlib.sha256(json.dumps(rows, sort_keys=True, default=str).encode()).hexdigest()
            if rows and digest in seen:
                state["stop_reason"] = "repeated_page"
                return
            seen.add(digest)
            overlap = stop_on_known and any(provider_record_key(kind, row) in known and
                (not boundary or provider_record_order(kind, row) <= boundary) for row in rows)
            exhausted = len(rows) < int(params.get("limit", 50))
            offset += len(rows)
            if stop_on_known:
                state["fresh_records"] = state.get("fresh_records", 0) + sum(provider_record_key(kind, row) not in known for row in rows)
            observe_page(state, rows, {"offset": offset}, exhausted=exhausted or overlap, stop_reason="overlap_stored_history" if overlap else None)
            yield data
            if exhausted or overlap:
                return
            await asyncio.sleep(0.15)
        state["stop_reason"] = "page_safety_ceiling"

    def _append_ton_message(self, out: AddressReport, address: str, tx_hash: str | None, ts, source: str, destination: str, value, raw: dict) -> None:
        if not source and not destination:
            return
        out.transactions.append(
            Transaction(
                chain="ton",
                tx_hash=str(tx_hash) if tx_hash else "",
                timestamp=ton_datetime(ts),
                from_address=source,
                to_address=destination,
                amount=ton_amount(value),
                amount_decimal=ton_amount_decimal(value),
                amount_base_units=int(value) if str(value or "").isdigit() else None,
                decimals=9,
                asset="TON",
                direction=ton_direction(source, destination, address),
                source=self.name,
                url=f"https://tonviewer.com/transaction/{tx_hash}" if tx_hash else None,
                raw=raw,
            )
        )

    async def _address_information(self, client, address: str, out: AddressReport) -> None:
        try:
            data = await self._get(client, "addressInformation", {"address": address})
            status = data.get("status")
            code = data.get("code")
            if status or code:
                severity = "low" if code else "medium"
                out.risk_flags.append(
                    RiskFlag(
                        chain="ton",
                        address=address,
                        flag="ton_contract_account" if code else "ton_account_state",
                        severity=severity,
                        source=self.name,
                        details=f"status={status or '-'} code={'present' if code else 'empty'}",
                        raw={"status": status, "last_transaction_lt": data.get("last_transaction_lt")},
                    )
                )
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: address_info: {http_error_message(e)}")
        except Exception as e:
            out.errors.append(f"{self.name}: address_info_parse: {e}")

    async def _address_book(self, client, address: str, out: AddressReport) -> None:
        try:
            data = await self._get(client, "addressBook", {"address": address})
            entry = data.get(address) or next(iter(data.values()), None) if data else None
            if isinstance(entry, dict):
                name = entry.get("name") or entry.get("user_friendly") or entry.get("domain")
                if name:
                    out.labels.append(Label(chain="ton", address=address, label=str(name)[:120], source=self.name, confidence=0.8, raw=entry))
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: address_book: {http_error_message(e)}")
        except Exception as e:
            out.errors.append(f"{self.name}: address_book_parse: {e}")

    async def _transactions(self, client, address: str, out: AddressReport) -> None:
        async for data in self._pages(client, out, "transactions", {"account": address, "limit": 50, "sort": "desc"}, "transactions", "account_transactions"):
            transactions = json_list(data.get("transactions"))
            for tx in transactions:
                try:
                    tx = json_object(tx)
                    tx_hash = tx.get("hash")
                    ts = tx.get("now")
                    in_msg = json_object(tx.get("in_msg"))
                    self._append_ton_message(
                        out,
                        address,
                        tx_hash,
                        ts,
                        ton_address_text(in_msg.get("source")),
                        ton_address_text(in_msg.get("destination")) or address,
                        in_msg.get("value"),
                        {"provider": "toncenter_v3_transactions", "message_index": "in", "lt": tx.get("lt"), "transaction": tx},
                    )
                    for index, msg in enumerate(json_list(tx.get("out_msgs"))):
                        msg = json_object(msg)
                        self._append_ton_message(
                            out,
                            address,
                            tx_hash,
                            ts,
                            address,
                            ton_address_text(msg.get("destination")),
                            msg.get("value"),
                            {"provider": "toncenter_v3_transactions", "message_index": index, "lt": tx.get("lt"), "parent_hash": tx_hash, "message": msg},
                        )
                except Exception as e:
                    out.errors.append(f"{self.name}: transaction_parse: {e}")

    @staticmethod
    def _jetton_metadata(metadata: dict, master: str | None) -> dict:
        """Read provider metadata only when bound to the exact master."""
        canonical = ton_canonical_address(master)
        if not canonical:
            return {}
        record = next((json_object(value) for key, value in metadata.items()
                       if ton_canonical_address(key) == canonical), {})
        info = next((json_object(value) for value in json_list(record.get("token_info"))
                     if isinstance(value, dict) and value.get("valid") is True
                     and value.get("type") == "jetton_masters"), {})
        return {**record, **info, **json_object(info.get("extra"))}

    async def _jetton_transfers(self, client, address: str, out: AddressReport) -> None:
        async def transfer_pages():
            # One oldest incoming page supplements the ordinary descending
            # stream. It is an auxiliary sample, not a new pending cursor.
            state = {"status": "pending", "direction": "in", "row_limit": 100, "history_complete": False,
                "sample_kind": "oldest_returned_incoming", "additional_pages": 1}
            out.coverage["jetton_incoming_discovery"] = state
            try:
                incoming = await self._get(client, "jetton/transfers", {"owner_address": address, "direction": "in", "limit": 100, "sort": "asc"})
                if not isinstance(incoming.get("jetton_transfers"), list):
                    raise ValueError("jetton_transfers array missing")
                rows = json_list(incoming["jetton_transfers"])
                import hashlib, json
                state.update(status="partial", retained_provider_rows=len(rows),
                    raw_rows_sha256=hashlib.sha256(json.dumps(rows, sort_keys=True, default=str).encode()).hexdigest())
                yield incoming
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                state.update(status="unavailable", stop_reason="provider_error")
                out.errors.append(f"{self.name}: jetton_incoming_discovery: {http_error_message(exc) if isinstance(exc, httpx.HTTPError) else exc}")
            async for data in self._pages(client, out, "jetton/transfers", {"owner_address": address, "limit": 50, "sort": "desc"}, "jetton_transfers", "jetton_transfers"):
                yield data
        async for data in transfer_pages():
            transfers = json_list(data.get("jetton_transfers"))
            metadata = json_object(data.get("metadata"))
            seen = set()
            for item in transfers:
                try:
                    master = ton_canonical_address(item.get("jetton_master"))
                    source = ton_address_text(item.get("source"))
                    dest = ton_address_text(item.get("destination"))
                    tx_hash = item.get("transaction_hash") or item.get("trace_id")
                    raw_amount = item.get("amount")
                    direction = ton_direction(source, dest, address)
                    meta = self._jetton_metadata(metadata, master)
                    decimal_value = meta.get("decimals", meta.get("decimal"))
                    decimals = int(decimal_value) if decimal_value is not None else None
                    symbol = ton_text(meta.get("symbol") or meta.get("name"))
                    token_key = (master, symbol)
                    if master and token_key not in seen:
                        seen.add(token_key)
                        out.tokens.append(
                            TokenHolding(
                                chain="ton",
                                address=address,
                                contract=master,
                                symbol=symbol,
                                name=ton_text(meta.get("name")),
                                amount=None,
                                source=self.name,
                                url=f"https://tonviewer.com/{master}",
                                raw={"asset_type": "jetton", "metadata": meta},
                            )
                        )
                        merge_asset(
                            out,
                            TonAsset(
                                asset_id=master,
                                type="jetton",
                                name=ton_text(meta.get("name")) or symbol,
                                title=symbol,
                                collection="Jettons",
                                owner_address=address,
                                last_seen=ton_datetime(item.get("transaction_now")) or now_utc(),
                                source=self.name,
                                external_url=f"https://tonviewer.com/{master}",
                                evidence_url=f"https://toncenter.com/api/v3/jetton/transfers",
                                collected_at=now_utc(),
                                confidence=0.78,
                                raw={"asset_type": "jetton", "metadata": meta},
                            ),
                        )
                    if not source:
                        out.errors.append(f"{self.name}: jetton_transfer_warning: empty from_address")
                    if not dest:
                        out.errors.append(f"{self.name}: jetton_transfer_warning: empty to_address")
                    out.transactions.append(
                        Transaction(
                            chain="ton",
                            tx_hash=str(tx_hash) if tx_hash else "",
                            timestamp=ton_datetime(item.get("transaction_now")),
                            from_address=source,
                            to_address=dest,
                            amount=ton_amount(raw_amount, decimals) if decimals is not None else None,
                            amount_decimal=ton_amount_decimal(raw_amount, decimals) if decimals is not None else None,
                            amount_base_units=int(raw_amount) if str(raw_amount or "").isdigit() else None,
                            decimals=decimals,
                            asset=f"JETTON:{master}" if master else None,
                            direction=direction,
                            source=self.name,
                            url=f"https://tonviewer.com/transaction/{tx_hash}" if tx_hash else None,
                            raw={"asset_type": "jetton", "jetton_master": master, "contract": master, "decimals": decimals, "metadata": meta, "trace_id": item.get("trace_id"), "lt": item.get("transaction_lt"), "query_id": item.get("query_id"), "message_hash": item.get("message_hash"), "transfer": item},
                        )
                    )
                except Exception as e:
                    out.errors.append(f"{self.name}: jetton_transfer_parse: {e}")

    async def _nft_items(self, client, address: str, out: AddressReport) -> None:
        async for data in self._pages(client, out, "nft/items", {"owner_address": address, "include_on_sale": "true", "limit": 50}, "nft_items", "nft_inventory"):
            items = json_list(data.get("nft_items"))
            for item in items:
                try:
                    item = json_object(item)
                    content = json_object(item.get("content"))
                    collection = json_object(item.get("collection"))
                    nft_address = ton_address(item)
                    collection_address = ton_address(item.get("collection_address") or collection)
                    collection_name = ton_text(collection.get("name")) if isinstance(collection, dict) else None
                    name = asset_title(item, nft_address)
                    asset_type = classify_asset(name, collection_name, "nft")
                    out.tokens.append(
                        TokenHolding(
                            chain="ton",
                            address=address,
                            contract=nft_address,
                            symbol="NFT",
                            name=str(name)[:120] if name else None,
                            amount=1,
                            source=self.name,
                            url=f"https://getgems.io/nft/{nft_address}" if nft_address else None,
                            raw={"asset_type": "nft", "collection_address": collection_address, "on_sale": item.get("on_sale")},
                        )
                    )
                    if nft_address:
                        merge_asset(
                            out,
                            TonAsset(
                                asset_id=nft_address,
                                type=asset_type,
                                name=str(name)[:120] if name else None,
                                title=str(name)[:120] if name else None,
                                collection=collection_name,
                                image_url=image_url_from(item),
                                owner_address=ton_address(item.get("owner_address") or item.get("owner")) or "",
                                ownership_status="current" if ton_address(item.get("owner_address") or item.get("owner")) else "unknown",
                                ownership_observed_at=now_utc(),
                                last_seen=now_utc(),
                                marketplace="Getgems" if item.get("on_sale") else None,
                                source=self.name,
                                external_url=f"https://getgems.io/nft/{nft_address}",
                                evidence_url="https://toncenter.com/api/v3/nft/items",
                                collected_at=now_utc(),
                                confidence=0.84,
                                related_addresses=related_addresses(collection_address, address),
                                raw={"asset_type": asset_type, "collection_address": collection_address, "on_sale": item.get("on_sale")},
                            ),
                        )
                except Exception as e:
                    out.errors.append(f"{self.name}: nft_item_parse: {e}")

    async def _nft_transfers(self, client, address: str, out: AddressReport) -> None:
        async for data in self._pages(client, out, "nft/transfers", {"owner_address": address, "limit": 50, "sort": "desc"}, "nft_transfers", "nft_transfers"):
            transfers = json_list(data.get("nft_transfers"))
            for item in transfers:
                try:
                    item = json_object(item)
                    source = ton_address_text(item.get("old_owner") or item.get("source"))
                    dest = ton_address_text(item.get("new_owner") or item.get("destination"))
                    if not source:
                        out.errors.append(f"{self.name}: nft_transfer_warning: empty from_address")
                    if not dest:
                        out.errors.append(f"{self.name}: nft_transfer_warning: empty to_address")
                    tx_hash = item.get("transaction_hash") or item.get("trace_id")
                    direction = ton_direction(source, dest, address)
                    item_address = ton_address(item.get("item_address") or item.get("nft_item") or item.get("nft_address"))
                    collection_address = ton_address(item.get("collection_address"))
                    event = TonAssetEvent(
                        event_type="transfer",
                        nft_address=item_address,
                        logical_time=int(item["transaction_lt"]) if item.get("transaction_lt") is not None else None,
                        success=False if item.get("transaction_aborted") is True else True if item.get("transaction_aborted") is False else None,
                        timestamp=ton_datetime(item.get("transaction_now")),
                        from_address=source,
                        to_address=dest,
                        tx_hash=str(tx_hash) if tx_hash else None,
                        source=self.name,
                        evidence_url=f"https://tonviewer.com/transaction/{tx_hash}" if tx_hash else None,
                        confidence=0.86,
                        raw={"trace_id": item.get("trace_id"), "collection_address": collection_address, "lt": item.get("transaction_lt"), "query_id": item.get("query_id"), "transfer": item},
                    )
                    out.transactions.append(
                        Transaction(
                            chain="ton",
                            tx_hash=str(tx_hash) if tx_hash else "",
                            timestamp=ton_datetime(item.get("transaction_now")),
                            from_address=source,
                            to_address=dest,
                            amount=1,
                            asset=f"NFT:{item_address or ''}",
                            direction=direction,
                            source=self.name,
                            url=f"https://tonviewer.com/transaction/{tx_hash}" if tx_hash else None,
                            raw={"asset_type": "nft", "item_address": item_address, "contract": item_address, "collection_address": collection_address, "lt": item.get("transaction_lt"), "query_id": item.get("query_id"), "transfer": item},
                        )
                    )
                    if item_address:
                        merge_asset(
                            out,
                            TonAsset(
                                asset_id=item_address,
                                type="nft",
                                owner_address="",
                                ownership_status="historical",
                                previous_owners=[source] if source else [],
                                acquisition_tx=str(tx_hash) if dest == address and tx_hash else None,
                                transfer_history=[event],
                                source=self.name,
                                external_url=f"https://getgems.io/nft/{item_address}",
                                evidence_url=f"https://tonviewer.com/transaction/{tx_hash}" if tx_hash else None,
                                evidence_tx=str(tx_hash) if tx_hash else None,
                                collected_at=now_utc(),
                                confidence=0.86,
                                related_addresses=related_addresses(source, dest, collection_address),
                                raw={"asset_type": "nft_transfer", "collection_address": collection_address},
                            ),
                        )
                except Exception as e:
                    out.errors.append(f"{self.name}: nft_transfer_parse: {e}")

    async def _actions(self, client, address: str, out: AddressReport) -> None:
        async for data in self._pages(client, out, "actions", {"account": address, "include_accounts": "true", "include_transactions": "true", "limit": 50, "sort": "desc"}, "actions", "action_events"):
            actions = json_list(data.get("actions"))
            metadata = json_object(data.get("metadata"))
            for action_index, action in enumerate(actions):
                try:
                    action = json_object(action)
                    action_type = action.get("type") or action.get("action_type") or action.get("action")
                    details = json_object(action.get("details"))
                    accounts = [ton_address(item) for item in json_list(action.get("accounts"))]
                    accounts = [item for item in accounts if item]
                    related = [item for item in accounts if item != address]
                    source = ton_address_text(details.get("source") or details.get("sender") or details.get("old_owner"))
                    dest = ton_address_text(details.get("destination") or details.get("recipient") or details.get("receiver") or details.get("new_owner"))
                    if not source:
                        out.errors.append(f"{self.name}: action_warning: empty from_address")
                    if not dest:
                        out.errors.append(f"{self.name}: action_warning: empty to_address")
                    txs = json_list(action.get("transactions"))
                    tx_hash = ton_text(txs[0]) if txs else action.get("trace_id") or action.get("action_id")
                    action_kind = str(action_type or "").lower()
                    raw_amount = next((details.get(key) for key in ("amount", "value", "ton_amount") if details.get(key) is not None), None)
                    asset = "TON" if action_kind in {"tontransfer", "ton_transfer"} else None
                    decimals = 9 if asset == "TON" else None
                    master = None
                    if "jetton" in action_kind:
                        master = ton_canonical_address(details.get('jetton_master') or details.get('jetton') or details.get('asset'))
                        asset = f"JETTON:{master}" if master else None
                        meta = self._jetton_metadata(metadata, master)
                        decimal_value = meta.get("decimals", meta.get("decimal"))
                        decimals = int(decimal_value) if decimal_value is not None else None
                    amount = ton_amount(raw_amount, decimals) if decimals is not None else None
                    if "nft" in action_kind or "auction" in action_kind or "dns" in action_kind:
                        asset = f"NFT:{ton_address(details.get('item_address') or details.get('nft_item')) or ton_text(details.get('domain')) or ''}"
                    out.transactions.append(
                        Transaction(
                            chain="ton",
                            tx_hash=str(tx_hash) if tx_hash else "",
                            timestamp=ton_datetime(action.get("end_utime") or action.get("start_utime")),
                            from_address=source,
                            to_address=dest,
                            amount=amount,
                            amount_decimal=ton_amount_decimal(raw_amount, decimals) if decimals is not None else None,
                            amount_base_units=int(raw_amount) if str(raw_amount or "").isdigit() else None,
                            decimals=decimals,
                            asset=asset,
                            direction=ton_direction(source, dest, address),
                            source=self.name,
                            url=f"https://tonviewer.com/transaction/{tx_hash}" if tx_hash else None,
                            raw={"asset_type": "action", "action_type": action_type, "action_index": action_index, "jetton_master": master, "contract": master, "decimals": decimals, "trace_id": action.get("trace_id"), "accounts": accounts[:20], "action": action},
                        )
                    )
                    item_address = ton_address(details.get("item_address") or details.get("nft_item") or details.get("nft"))
                    if item_address:
                        success = action.get("success") if isinstance(action.get("success"), bool) else None
                        event_type = "sale" if str(action_type).lower() in {"nft_sale", "nft_purchase", "nftsaledetails", "nftpurchase"} and success is True else "transfer" if "transfer" in str(action_type).lower() else "interaction"
                        event = TonAssetEvent(
                            event_type=event_type,
                            action_index=action_index,
                            nft_address=item_address,
                            success=success,
                            timestamp=ton_datetime(action.get("end_utime") or action.get("start_utime")),
                            from_address=source,
                            to_address=dest,
                            price=amount if event_type == "sale" else None,
                            asset="TON" if event_type == "sale" else f"NFT:{item_address}",
                            tx_hash=str(tx_hash) if tx_hash else None,
                            marketplace="Fragment" if action_type and "auction" in action_type else None,
                            source=self.name,
                            evidence_url=f"https://tonviewer.com/transaction/{tx_hash}" if tx_hash else None,
                            confidence=0.7,
                            raw={"action_type": action_type, "action_index": action_index, "trace_id": action.get("trace_id"), "action": action},
                        )
                        merge_asset(
                            out,
                            TonAsset(
                                asset_id=item_address,
                                type=classify_asset(ton_text(details.get("domain")) or item_address, None, "nft"),
                                title=ton_text(details.get("domain")) or item_address,
                                owner_address="",
                                ownership_status="historical",
                                previous_owners=[source] if source else [],
                                acquisition_tx=str(tx_hash) if dest == address and tx_hash else None,
                                transfer_history=[event] if event_type != "sale" else [],
                                sale_history=[event] if event_type == "sale" else [],
                                marketplace=event.marketplace,
                                source=self.name,
                                external_url=f"https://getgems.io/nft/{item_address}",
                                evidence_url=f"https://tonviewer.com/transaction/{tx_hash}" if tx_hash else None,
                                evidence_tx=str(tx_hash) if tx_hash else None,
                                collected_at=now_utc(),
                                confidence=0.7,
                                related_addresses=related_addresses(source, dest, accounts),
                                raw={"asset_type": "action_asset", "action_type": action_type},
                            ),
                        )
                    if action_type in {"nft_mint", "auction_bid", "change_dns", "renew_dns"}:
                        out.risk_flags.append(
                            RiskFlag(
                                chain="ton",
                                address=address,
                                flag=f"ton_ecosystem_action:{action_type}",
                                severity="low",
                                source=self.name,
                                details=str(action.get("trace_id") or action.get("action_id")),
                            )
                        )
                    for full_tx in json_list(action.get("transactions_full")):
                        full_tx = json_object(full_tx)
                        full_hash = full_tx.get("hash") or tx_hash
                        full_ts = full_tx.get("now") or action.get("end_utime") or action.get("start_utime")
                        in_msg = json_object(full_tx.get("in_msg"))
                        self._append_ton_message(
                            out,
                            address,
                            full_hash,
                            full_ts,
                            ton_address_text(in_msg.get("source")),
                            ton_address_text(in_msg.get("destination")),
                            in_msg.get("value"),
                            {"provider": "toncenter_v3_action_transactions", "message_index": "in", "lt": full_tx.get("lt"), "transaction": full_tx},
                        )
                        for index, msg in enumerate(json_list(full_tx.get("out_msgs"))):
                            msg = json_object(msg)
                            self._append_ton_message(
                                out,
                                address,
                                full_hash,
                                full_ts,
                                ton_address_text(msg.get("source")) or full_tx.get("account") or address,
                                ton_address_text(msg.get("destination")),
                                msg.get("value"),
                                {"provider": "toncenter_v3_action_transactions", "message_index": index, "lt": full_tx.get("lt"), "message": msg},
                            )
                except Exception as e:
                    out.errors.append(f"{self.name}: action_parse: {e}")
