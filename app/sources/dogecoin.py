from __future__ import annotations

from app.sources.pagination import pages
from app.aggregator.collection_audit import stream_state

import asyncio
import os
from collections import Counter
from datetime import datetime, timezone
from typing import Any

import httpx

from app.models.report import AddressReport, Balance, SourceHealth, Transaction
from app.sources.base import Source
from app.utils.detect import is_dogecoin_address
from app.utils.http import create_async_client, http_error_message, json_list, json_object


BLOCKCHAIR_API = "https://api.blockchair.com/dogecoin"
BLOCKCHAIR_EXPLORER = "https://blockchair.com/dogecoin"
DOGECHAIN_EXPLORER = "https://dogechain.info"
DOGE_DUST_THRESHOLD = 1.0


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _doge(value: Any) -> float:
    return _int(value) / 100_000_000


def _amount(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value:,.8f}".rstrip("0").rstrip(".")


def _same_address(left: str | None, right: str | None) -> bool:
    return str(left or "").lower() == str(right or "").lower()


def _parse_time(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        pass
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _confirmations(block_id: Any, tip_height: int | None) -> int | None:
    height = _int(block_id)
    if not height or tip_height is None:
        return None
    return max(0, tip_height - height + 1)


def _short(value: str | None) -> str:
    text = str(value or "")
    return f"{text[:10]}...{text[-6:]}" if len(text) > 22 else text


def _io_summary(items: list[dict]) -> str:
    parts = []
    for item in items[:3]:
        label = "target" if item.get("target") else _short(str(item.get("address") or "coinbase"))
        parts.append(f"{label} {_amount(item.get('value'))} DOGE".strip())
    if len(items) > 3:
        parts.append(f"+{len(items) - 3}")
    return ", ".join(parts)


def _address_from_io(item: dict) -> str:
    return str(item.get("recipient") or item.get("address") or "").strip()


def _tx_view(tx_hash: str, payload: dict, address: str, tip_height: int | None) -> dict:
    tx_info = json_object(payload.get("transaction"))
    inputs = []
    outputs = []
    target_input_sats = 0
    target_output_sats = 0
    input_total = 0
    output_total = 0

    for index, item in enumerate(json_list(payload.get("inputs"))):
        addr = _address_from_io(item)
        value_sats = _int(item.get("value"))
        input_total += value_sats
        is_target = _same_address(addr, address)
        if is_target:
            target_input_sats += value_sats
        if addr or value_sats:
            inputs.append(
                {
                    "address": addr,
                    "value": _doge(value_sats),
                    "value_sats": value_sats,
                    "index": item.get("index", index),
                    "target": is_target,
                    "tx_hash": item.get("transaction_hash") or "",
                    "vout": item.get("index"),
                    "coinbase": bool(item.get("is_from_coinbase")),
                    "spent": bool(item.get("is_spent")),
                }
            )

    for index, item in enumerate(json_list(payload.get("outputs"))):
        addr = _address_from_io(item)
        value_sats = _int(item.get("value"))
        output_total += value_sats
        is_target = _same_address(addr, address)
        if is_target:
            target_output_sats += value_sats
        outputs.append(
            {
                "address": addr,
                "value": _doge(value_sats),
                "value_sats": value_sats,
                "index": item.get("index", index),
                "target": is_target,
                "spent": bool(item.get("is_spent")),
                "spending_tx_hash": item.get("spending_transaction_hash") or "",
            }
        )

    net_sats = target_output_sats - target_input_sats
    if target_input_sats and target_output_sats and net_sats == 0:
        direction = "self"
    elif net_sats > 0:
        direction = "in"
    elif net_sats < 0:
        direction = "out"
    elif target_input_sats:
        direction = "out"
    elif target_output_sats:
        direction = "in"
    else:
        direction = "unknown"

    fee_sats = tx_info.get("fee")
    if fee_sats is None and input_total >= output_total and input_total:
        fee_sats = input_total - output_total
    block_id = tx_info.get("block_id")
    return {
        "tx_hash": tx_hash,
        "time": _parse_time(tx_info.get("time")),
        "inputs": inputs,
        "outputs": outputs,
        "direction": direction,
        "amount": _doge(abs(net_sats)) if target_input_sats or target_output_sats else None,
        "fee": _doge(fee_sats) if fee_sats is not None else None,
        "fee_sats": _int(fee_sats) if fee_sats is not None else None,
        "confirmations": _confirmations(block_id, tip_height),
        "target_input": _doge(target_input_sats),
        "target_output": _doge(target_output_sats),
        "input_summary": _io_summary(inputs),
        "output_summary": _io_summary(outputs),
        "input_count": _int(tx_info.get("input_count")) or len(inputs),
        "output_count": _int(tx_info.get("output_count")) or len(outputs),
        "input_total": _doge(tx_info.get("input_total")) if tx_info.get("input_total") is not None else _doge(input_total),
        "output_total": _doge(tx_info.get("output_total")) if tx_info.get("output_total") is not None else _doge(output_total),
        "block_id": block_id,
        "dust_output_count": sum(1 for item in outputs if 0 < float(item.get("value") or 0) < DOGE_DUST_THRESHOLD),
    }


def _utxo_view(item: dict, tip_height: int | None, source: str) -> dict:
    txid = str(item.get("transaction_hash") or item.get("txid") or item.get("tx_hash") or "")
    block_id = item.get("block_id")
    return {
        "tx_hash": txid,
        "txid": txid,
        "vout": item.get("index") if item.get("index") is not None else item.get("vout"),
        "value": _doge(item.get("value")),
        "value_sats": _int(item.get("value")),
        "confirmations": _confirmations(block_id, tip_height),
        "status": "unspent",
        "url": f"{BLOCKCHAIR_EXPLORER}/transaction/{txid}" if txid else "",
        "source": source,
        "raw": item,
    }


def _first_last(address_info: dict, tx_views: list[dict]) -> tuple[datetime | None, datetime | None]:
    stamps = [
        _parse_time(address_info.get("first_seen_receiving")),
        _parse_time(address_info.get("first_seen_spending")),
        *[item.get("time") for item in tx_views],
    ]
    stamps = [item for item in stamps if item]
    first_seen = min(stamps) if stamps else None
    stamps = [
        _parse_time(address_info.get("last_seen_receiving")),
        _parse_time(address_info.get("last_seen_spending")),
        *[item.get("time") for item in tx_views],
    ]
    stamps = [item for item in stamps if item]
    last_seen = max(stamps) if stamps else None
    return first_seen, last_seen


def _dogecoin_summary(address: str, source: str, address_info: dict, tx_views: list[dict], utxos: list[dict], tip_height: int | None, warnings: list[str]) -> dict:
    first_seen, last_seen = _first_last(address_info, tx_views)
    total_received = _doge(address_info.get("received"))
    total_sent = _doge(address_info.get("spent"))
    tx_amounts = [float(item.get("amount") or 0) for item in tx_views if item.get("amount") is not None]
    incoming = [item for item in tx_views if item.get("direction") == "in"]
    outgoing = [item for item in tx_views if item.get("direction") == "out"]
    active_days = len({item.get("time").date().isoformat() for item in tx_views if item.get("time")})
    fee_total = sum(float(item.get("fee") or 0) for item in tx_views)
    all_outputs = [output for item in tx_views for output in item.get("outputs") or []]
    dust_outputs = [output for output in all_outputs if 0 < float(output.get("value") or 0) < DOGE_DUST_THRESHOLD]
    amount_counts = Counter(round(float(output.get("value") or 0), 8) for output in all_outputs if 0 < float(output.get("value") or 0) < DOGE_DUST_THRESHOLD)
    return {
        "address": address,
        "chain": "dogecoin",
        "balance": _doge(address_info.get("balance")),
        "balance_sats": _int(address_info.get("balance")),
        "balance_usd": address_info.get("balance_usd"),
        "total_received": total_received,
        "total_received_sats": _int(address_info.get("received")),
        "total_sent": total_sent,
        "total_sent_sats": _int(address_info.get("spent")),
        "tx_count": _int(address_info.get("transaction_count")),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "output_count": _int(address_info.get("output_count")),
        "spent_outputs": max(0, _int(address_info.get("output_count")) - _int(address_info.get("unspent_output_count"))),
        "unspent_outputs": _int(address_info.get("unspent_output_count")) if address_info else len(utxos),
        "utxos": [_utxo_view(item, tip_height, source) for item in utxos],
        "tx_details_count": len(tx_views),
        "active_days": active_days,
        "average_tx_amount": sum(tx_amounts) / len(tx_amounts) if tx_amounts else None,
        "largest_incoming": max([float(item.get("amount") or 0) for item in incoming], default=0),
        "largest_outgoing": max([float(item.get("amount") or 0) for item in outgoing], default=0),
        "fee_total": fee_total,
        "dust_outputs": len(dust_outputs),
        "repeated_dust_amounts": [f"{amount:g} x{count}" for amount, count in amount_counts.most_common(5) if count >= 2],
        "explorer_links": {
            "blockchair": f"{BLOCKCHAIR_EXPLORER}/address/{address}",
            "dogechain": f"{DOGECHAIN_EXPLORER}/address/{address}",
        },
        "sources": [source],
        "warnings": list(dict.fromkeys(warnings)),
        "partial": bool(warnings),
    }


class DogecoinBlockchairSource(Source):
    name = "blockchair_dogecoin"
    chain = "doge"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def _get_json(self, client: httpx.AsyncClient, path: str, params: dict | None = None) -> Any:
        response = await client.get(f"{BLOCKCHAIR_API}{path}", params=params)
        response.raise_for_status()
        return response.json()

    async def _stats(self, client: httpx.AsyncClient, out: AddressReport) -> dict:
        try:
            return json_object(json_object(await self._get_json(client, "/stats")).get("data"))
        except Exception as exc:
            out.warnings.append(f"{self.name}: stats: {http_error_message(exc)}")
            return {}

    async def _address_dashboard(self, client: httpx.AsyncClient, address: str, out: AddressReport) -> dict:
        try:
            payload = json_object(await self._get_json(client, f"/dashboards/address/{address}", {"limit": "100,100"}))
            return json_object(json_object(payload.get("data")).get(address))
        except Exception as exc:
            out.errors.append(f"{self.name}: address_lookup: {http_error_message(exc)}")
            return {}

    async def _transaction_detail(self, client: httpx.AsyncClient, tx_hash: str, out: AddressReport) -> dict:
        try:
            payload = json_object(await self._get_json(client, f"/dashboards/transaction/{tx_hash}"))
            return json_object(json_object(payload.get("data")).get(tx_hash))
        except Exception as exc:
            if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 429:
                self._history_paused = True
            out.warnings.append(f"{self.name}: transaction {tx_hash}: {http_error_message(exc)}")
            return {}

    async def _transaction_details(self, client: httpx.AsyncClient, tx_hashes: list[str], out: AddressReport, limit: int = 30, on_detail=None) -> list[tuple[str, dict]]:
        semaphore = asyncio.Semaphore(4)

        async def load(tx_hash: str) -> tuple[str, dict]:
            async with semaphore:
                if getattr(self, "_continuous", False) and (getattr(self, "_detail_requests", 0) >= 1500 or getattr(self, "_history_paused", False)):
                    result = (tx_hash, {})
                else:
                    self._detail_requests = getattr(self, "_detail_requests", 0) + 1
                    result = (tx_hash, await self._transaction_detail(client, tx_hash, out))
                if on_detail is not None:
                    on_detail(*result)
                return result

        return await asyncio.gather(*(load(tx_hash) for tx_hash in (tx_hashes if getattr(self, "_continuous", False) else tx_hashes[:limit]) if tx_hash))

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["doge"], sources_used=[self.name])
        self._partial_report = out
        if not is_dogecoin_address(address):
            out.source_health.append(SourceHealth(source=self.name, status="error", timeout_seconds=self._timeout, retry_strategy="dogecoin base58 validation", details="invalid dogecoin address"))
            out.errors.append(f"{self.name}: invalid dogecoin address")
            return out
        if getattr(self, "_continuous", False):
            return await self._fetch_continuous(address, out)
        async with create_async_client(self._timeout) as client:
            stats = await self._stats(client, out)
            tip_height = _int(stats.get("best_block_height") or stats.get("blocks")) or None
            dashboard = await self._address_dashboard(client, address, out)
            address_info = json_object(dashboard.get("address"))
            tx_hashes = [str(item) for item in json_list(dashboard.get("transactions")) if item]
            utxos = json_list(dashboard.get("utxo"))
            details = await self._transaction_details(client, tx_hashes, out) if tx_hashes else []

        if address_info:
            balance = _doge(address_info.get("balance"))
            out.balances.append(
                Balance(
                    chain="doge",
                    address=address,
                    asset="DOGE",
                    amount=balance,
                    source=self.name,
                    url=f"{BLOCKCHAIR_EXPLORER}/address/{address}",
                    raw={
                        "sats": _int(address_info.get("balance")),
                        "balance_usd": address_info.get("balance_usd"),
                        "total_received_sats": _int(address_info.get("received")),
                        "total_sent_sats": _int(address_info.get("spent")),
                    },
                )
            )

        tx_views = []
        for tx_hash, payload in details:
            if not payload:
                continue
            try:
                view = _tx_view(tx_hash, payload, address, tip_height)
                tx_views.append(view)
                inputs = view["inputs"]
                outputs = view["outputs"]
                from_address = ""
                to_address = ""
                if view["direction"] == "in":
                    from_address = next((item.get("address") for item in inputs if not item.get("target") and item.get("address")), "")
                    to_address = address
                elif view["direction"] == "out":
                    from_address = address
                    to_address = next((item.get("address") for item in outputs if not item.get("target") and item.get("address")), address)
                elif view["direction"] == "self":
                    from_address = address
                    to_address = address
                else:
                    from_address = next((item.get("address") for item in inputs if item.get("address")), "")
                    to_address = next((item.get("address") for item in outputs if item.get("address")), "")
                out.transactions.append(
                    Transaction(
                        tx_hash=tx_hash,
                        chain="doge",
                        timestamp=view["time"],
                        from_address=from_address,
                        to_address=to_address,
                        amount=view["amount"],
                        asset="DOGE",
                        direction=view["direction"],
                        fee=view["fee"],
                        confirmations=view["confirmations"],
                        inputs=inputs,
                        outputs=outputs,
                        source=self.name,
                        url=f"{BLOCKCHAIR_EXPLORER}/transaction/{tx_hash}",
                        raw={
                            "provider": self.name,
                            "type": "doge_utxo_transfer",
                            "block_id": view["block_id"],
                            "confirmations": view["confirmations"],
                            "fee": view["fee"],
                            "fee_sats": view["fee_sats"],
                            "input_count": view["input_count"],
                            "output_count": view["output_count"],
                            "input_total": view["input_total"],
                            "output_total": view["output_total"],
                            "input_summary": view["input_summary"],
                            "output_summary": view["output_summary"],
                            "target_input": view["target_input"],
                            "target_output": view["target_output"],
                            "dust_output_count": view["dust_output_count"],
                            "mempool": view["confirmations"] == 0,
                        },
                    )
                )
            except Exception as exc:
                out.errors.append(f"{self.name}: tx_parse {tx_hash}: {exc}")

        out.dogecoin = _dogecoin_summary(address, self.name, address_info, tx_views, utxos, tip_height, out.warnings)
        if out.errors:
            status = "partial" if address_info or out.transactions else "error"
        elif not address_info or (_int(address_info.get("transaction_count")) == 0 and _int(address_info.get("balance")) == 0):
            status = "empty"
        elif out.warnings:
            status = "partial"
        else:
            status = "ok"
        details_text = "address data collected" if status in {"ok", "partial"} else "empty address" if status == "empty" else "address lookup failed"
        out.source_health.append(SourceHealth(source=self.name, status=status, timeout_seconds=self._timeout, retry_strategy="bounded blockchair dashboard requests", details=details_text))
        return out

    def _parse_detail_rows(self, address, out, details, tip_height):
        tx_views = []
        for tx_hash, payload in details:
            if not payload:
                continue
            try:
                view = _tx_view(tx_hash, payload, address, tip_height)
                tx_views.append(view)
                inputs = view["inputs"]
                outputs = view["outputs"]
                from_address = ""
                to_address = ""
                if view["direction"] == "in":
                    from_address = next((item.get("address") for item in inputs if not item.get("target") and item.get("address")), "")
                    to_address = address
                elif view["direction"] == "out":
                    from_address = address
                    to_address = next((item.get("address") for item in outputs if not item.get("target") and item.get("address")), address)
                elif view["direction"] == "self":
                    from_address = address
                    to_address = address
                else:
                    from_address = next((item.get("address") for item in inputs if item.get("address")), "")
                    to_address = next((item.get("address") for item in outputs if item.get("address")), "")
                out.transactions.append(
                    Transaction(
                        tx_hash=tx_hash,
                        chain="doge",
                        timestamp=view["time"],
                        from_address=from_address,
                        to_address=to_address,
                        amount=view["amount"],
                        asset="DOGE",
                        direction=view["direction"],
                        fee=view["fee"],
                        confirmations=view["confirmations"],
                        inputs=inputs,
                        outputs=outputs,
                        source=self.name,
                        url=f"{BLOCKCHAIR_EXPLORER}/transaction/{tx_hash}",
                        raw={
                            "provider": self.name, "provider_record": payload,
                            "type": "doge_utxo_transfer",
                            "block_id": view["block_id"],
                            "confirmations": view["confirmations"],
                            "fee": view["fee"],
                            "fee_sats": view["fee_sats"],
                            "input_count": view["input_count"],
                            "output_count": view["output_count"],
                            "input_total": view["input_total"],
                            "output_total": view["output_total"],
                            "input_summary": view["input_summary"],
                            "output_summary": view["output_summary"],
                            "target_input": view["target_input"],
                            "target_output": view["target_output"],
                            "dust_output_count": view["dust_output_count"],
                            "mempool": view["confirmations"] == 0,
                        },
                    )
                )
            except Exception as exc:
                out.errors.append(f"{self.name}: tx_parse {tx_hash}: {exc}")

        return tx_views

    async def _fetch_continuous(self, address, out):
        self._detail_requests = 0
        self._history_paused = False
        address_info, utxos, tx_views = {}, [], []
        state = stream_state(out, self.name, "account_transactions", resume=getattr(self, "_resume_state", {}).get("account_transactions"), record_type="account_transactions")
        pending = set(state.get("pending_details", []))
        async with create_async_client(min(self._timeout, 10.0)) as client:
            stats = await self._stats(client, out)
            tip_height = _int(stats.get("best_block_height") or stats.get("blocks")) or None
            dashboard = await self._address_dashboard(client, address, out)
            address_info = json_object(dashboard.get("address"))
            utxos = json_list(dashboard.get("utxo"))
            if address_info:
                balance = _doge(address_info.get("balance"))
                out.balances.append(
                    Balance(
                        chain="doge",
                        address=address,
                        asset="DOGE",
                        amount=balance,
                        source=self.name,
                        url=f"{BLOCKCHAIR_EXPLORER}/address/{address}",
                        raw={
                            "sats": _int(address_info.get("balance")),
                            "balance_usd": address_info.get("balance_usd"),
                            "total_received_sats": _int(address_info.get("received")),
                            "total_sent_sats": _int(address_info.get("spent")),
                        },
                    )
                )


            def retain(tx_hash, payload):
                if payload:
                    tx_views.extend(self._parse_detail_rows(address, out, [(tx_hash, payload)], tip_height))
                    pending.discard(tx_hash)
                else:
                    pending.add(tx_hash)
                    out.transactions.append(Transaction(chain="doge", tx_hash=tx_hash, asset="DOGE", source=self.name,
                        url=f"{BLOCKCHAIR_EXPLORER}/transaction/{tx_hash}", raw={"type": "doge_transaction_reference", "decoded": False}))
                state["pending_details"] = sorted(pending)
            if pending:
                await self._transaction_details(client, sorted(pending), out, on_detail=retain)
            first = True
            async def fetch(cursor):
                nonlocal first
                if first and not cursor:
                    first = False
                    return dashboard if dashboard else None
                payload = json_object(await self._get_json(client, f"/dashboards/address/{address}", {"limit": "100,100", "offset": f"{int(cursor.get('offset', 0))},0"}))
                if json_object(payload.get("context")).get("error"):
                    out.errors.append(f"{self.name}: address history API error")
                    return None
                return json_object(json_object(payload.get("data")).get(address)) or None
            def advance(data, items, cursor):
                return {"offset": int(cursor.get("offset", 0)) + len(items)}
            async for page in pages(self, out, "account_transactions", fetch, lambda data: data.get("transactions"), advance, page_size=100, adjust_offset=True):
                hashes = [str(item) for item in page.get("transactions", [])]
                pending.update(hashes)
                state["pending_details"] = sorted(pending)
                await self._transaction_details(client, hashes, out, on_detail=retain)
                if self._detail_requests >= 1500 or self._history_paused:
                    state["stop_reason"] = "request_safety_ceiling_or_provider_limit"
                    break
        out.dogecoin = _dogecoin_summary(address, self.name, address_info, tx_views, utxos, tip_height, out.warnings)
        out.source_health.append(SourceHealth(source=self.name, status="partial" if out.errors or out.warnings or pending or not address_info else "ok", timeout_seconds=self._timeout,
            retry_strategy="resume dashboard offset and pending detail IDs", details="Public dashboard coverage; endpoint exhaustion is not a completeness guarantee"))
        return out



class DogecoinSoChainSource(Source):
    name = "sochain_dogecoin"
    chain = "doge"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["doge"], sources_used=[self.name])
        key = (os.getenv("SOCHAIN_API_KEY") or os.getenv("CHAIN_SO_API_KEY") or "").strip()
        if not key:
            out.source_health.append(SourceHealth(source=self.name, status="skipped", timeout_seconds=self._timeout, retry_strategy="key_required", details="SoChain API key is not configured"))
            return out
        async with create_async_client(self._timeout) as client:
            try:
                response = await client.get(f"https://chain.so/api/v3/address_summary/DOGE/{address}", headers={"API-KEY": key})
                if response.status_code in {401, 403}:
                    out.source_health.append(SourceHealth(source=self.name, status="skipped", timeout_seconds=self._timeout, retry_strategy="key_required", details=f"http {response.status_code}"))
                    return out
                response.raise_for_status()
                payload = json_object(response.json())
            except Exception as exc:
                out.source_health.append(SourceHealth(source=self.name, status="error", timeout_seconds=self._timeout, retry_strategy="authenticated SoChain request", details=http_error_message(exc)))
                return out
        data = json_object(payload.get("data"))
        balance = data.get("confirmed_balance") or data.get("balance")
        try:
            if balance is not None:
                out.balances.append(Balance(chain="doge", address=address, asset="DOGE", amount=float(balance), source=self.name, url=f"https://chain.so/address/DOGE/{address}", raw=data))
        except (TypeError, ValueError):
            pass
        out.dogecoin = {
            "address": address,
            "chain": "dogecoin",
            "balance": float(balance) if balance is not None else None,
            "explorer_links": {"sochain": f"https://chain.so/address/DOGE/{address}"},
            "sources": [self.name],
        }
        out.source_health.append(SourceHealth(source=self.name, status="ok" if out.balances else "partial", timeout_seconds=self._timeout, retry_strategy="authenticated SoChain request", details="address summary returned"))
        return out


class DogecoinOklinkSource(Source):
    name = "oklink_dogecoin"
    chain = "doge"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["doge"], sources_used=[self.name])
        key = (os.getenv("OKLINK_API_KEY") or os.getenv("OKLINK_KEY") or "").strip()
        if not key:
            out.source_health.append(SourceHealth(source=self.name, status="skipped", timeout_seconds=self._timeout, retry_strategy="key_required", details="OKLink API key is not configured"))
            return out
        async with create_async_client(self._timeout) as client:
            try:
                response = await client.get(
                    "https://www.oklink.com/api/v5/explorer/address/address-summary",
                    params={"chainShortName": "DOGE", "address": address},
                    headers={"Ok-Access-Key": key},
                )
                if response.status_code in {401, 403}:
                    out.source_health.append(SourceHealth(source=self.name, status="skipped", timeout_seconds=self._timeout, retry_strategy="key_required", details=f"http {response.status_code}"))
                    return out
                response.raise_for_status()
                payload = json_object(response.json())
            except Exception as exc:
                out.source_health.append(SourceHealth(source=self.name, status="error", timeout_seconds=self._timeout, retry_strategy="authenticated OKLink request", details=http_error_message(exc)))
                return out
        rows = json_list(payload.get("data"))
        row = json_object(rows[0]) if rows else {}
        balance = row.get("balance") or row.get("balanceSymbol")
        try:
            if balance is not None:
                out.balances.append(Balance(chain="doge", address=address, asset="DOGE", amount=float(balance), source=self.name, url=f"https://www.oklink.com/doge/address/{address}", raw=row))
        except (TypeError, ValueError):
            pass
        out.dogecoin = {"address": address, "chain": "dogecoin", "explorer_links": {"oklink": f"https://www.oklink.com/doge/address/{address}"}, "sources": [self.name]}
        out.source_health.append(SourceHealth(source=self.name, status="ok" if row else "empty", timeout_seconds=self._timeout, retry_strategy="authenticated OKLink request", details="address summary returned" if row else "empty response"))
        return out


class DogechainExplorerSource(Source):
    name = "dogechain_explorer"
    chain = "doge"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["doge"], sources_used=[self.name])
        out.dogecoin = {"address": address, "chain": "dogecoin", "explorer_links": {"dogechain": f"{DOGECHAIN_EXPLORER}/address/{address}"}, "sources": [self.name]}
        async with create_async_client(self._timeout) as client:
            try:
                response = await client.get(f"{DOGECHAIN_EXPLORER}/address/{address}")
                if response.status_code in {401, 403, 429}:
                    out.source_health.append(SourceHealth(source=self.name, status="unavailable", timeout_seconds=self._timeout, retry_strategy="public explorer page", details=f"http {response.status_code}"))
                    return out
                response.raise_for_status()
            except Exception as exc:
                out.source_health.append(SourceHealth(source=self.name, status="unavailable", timeout_seconds=self._timeout, retry_strategy="public explorer page", details=http_error_message(exc)))
                return out
        out.source_health.append(SourceHealth(source=self.name, status="partial", timeout_seconds=self._timeout, retry_strategy="public explorer page", details="explorer page available; structured parser not available"))
        return out


class DogecoinCoreRpcSource(Source):
    name = "dogecoin_core_rpc"
    chain = "doge"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["doge"], sources_used=[self.name])
        rpc_url = (os.getenv("DOGE_RPC_URL") or os.getenv("DOGECOIN_RPC_URL") or "").strip()
        rpc_user = (os.getenv("DOGE_RPC_USER") or os.getenv("DOGECOIN_RPC_USER") or "").strip()
        rpc_password = (os.getenv("DOGE_RPC_PASSWORD") or os.getenv("DOGECOIN_RPC_PASSWORD") or "").strip()
        if not rpc_url:
            out.source_health.append(SourceHealth(source=self.name, status="skipped", timeout_seconds=self._timeout, retry_strategy="optional local RPC", details="DOGE RPC is not configured"))
            return out
        async with create_async_client(self._timeout) as client:
            try:
                response = await client.post(rpc_url, json={"jsonrpc": "1.0", "id": "gansar", "method": "getblockchaininfo", "params": []}, auth=(rpc_user, rpc_password) if rpc_user or rpc_password else None)
                response.raise_for_status()
                payload = json_object(response.json())
            except Exception as exc:
                out.source_health.append(SourceHealth(source=self.name, status="error", timeout_seconds=self._timeout, retry_strategy="optional local RPC", details=http_error_message(exc)))
                return out
        result = json_object(payload.get("result"))
        details = f"blocks={result.get('blocks')}" if result else "RPC responded"
        out.source_health.append(SourceHealth(source=self.name, status="partial", timeout_seconds=self._timeout, retry_strategy="optional local RPC", details=f"{details}; address index not assumed"))
        return out


class DogecoinBitquerySource(Source):
    name = "bitquery_dogecoin"
    chain = "doge"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["doge"], sources_used=[self.name])
        key = (os.getenv("BITQUERY_API_KEY") or os.getenv("BITQUERY_TOKEN") or "").strip()
        status = "skipped" if not key else "unavailable"
        details = "Bitquery API key is not configured" if not key else "adapter skeleton; not executed without a DOGE query profile"
        out.source_health.append(SourceHealth(source=self.name, status=status, timeout_seconds=self._timeout, retry_strategy="key_required", details=details))
        return out


class DogecoinGetBlockSource(Source):
    name = "getblock_dogecoin"
    chain = "doge"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["doge"], sources_used=[self.name])
        key = (os.getenv("GETBLOCK_API_KEY") or os.getenv("GETBLOCK_TOKEN") or "").strip()
        status = "skipped" if not key else "unavailable"
        details = "GetBlock API key is not configured" if not key else "adapter skeleton; DOGE RPC endpoint is not configured"
        out.source_health.append(SourceHealth(source=self.name, status=status, timeout_seconds=self._timeout, retry_strategy="key_required", details=details))
        return out
