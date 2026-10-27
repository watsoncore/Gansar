from __future__ import annotations

import asyncio
from app.sources.pagination import pages

from datetime import datetime, timezone
from typing import Any

import httpx

from app.models.report import AddressReport, Balance, SourceHealth, Transaction
from app.sources.base import Source
from app.utils.http import create_async_client, http_error_message, json_list, json_object


MEMPOOL_EXPLORER = "https://mempool.space"


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _btc(value: Any) -> float:
    return _int(value) / 100_000_000


def _amount(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value:,.8f}".rstrip("0").rstrip(".")


def _same_address(left: str | None, right: str | None) -> bool:
    return str(left or "").lower() == str(right or "").lower()


def _short(value: str | None) -> str:
    text = str(value or "")
    return f"{text[:10]}...{text[-6:]}" if len(text) > 22 else text


def _confirmations(status: dict, tip_height: int | None) -> int | None:
    if not status.get("confirmed"):
        return 0
    block_height = _int(status.get("block_height"))
    if not block_height or tip_height is None:
        return None
    return max(0, tip_height - block_height + 1)


def _status_time(status: dict) -> datetime | None:
    ts = _int(status.get("block_time"))
    return datetime.fromtimestamp(ts, tz=timezone.utc) if ts else None


def _stats(data: dict) -> tuple[int, int, int]:
    chain = json_object(data.get("chain_stats"))
    mempool = json_object(data.get("mempool_stats"))
    funded = _int(chain.get("funded_txo_sum")) + _int(mempool.get("funded_txo_sum"))
    spent = _int(chain.get("spent_txo_sum")) + _int(mempool.get("spent_txo_sum"))
    tx_count = _int(chain.get("tx_count")) + _int(mempool.get("tx_count"))
    return funded, spent, tx_count


def _unspent_count(data: dict) -> int:
    chain = json_object(data.get("chain_stats"))
    mempool = json_object(data.get("mempool_stats"))
    funded = _int(chain.get("funded_txo_count")) + _int(mempool.get("funded_txo_count"))
    spent = _int(chain.get("spent_txo_count")) + _int(mempool.get("spent_txo_count"))
    return max(0, funded - spent)


def _io_summary(items: list[dict]) -> str:
    parts = []
    for item in items[:3]:
        label = "target" if item.get("target") else _short(str(item.get("address") or "coinbase"))
        parts.append(f"{label} {_amount(item.get('value'))} BTC".strip())
    if len(items) > 3:
        parts.append(f"+{len(items) - 3}")
    return ", ".join(parts)


def _btc_tx_view(tx: dict, address: str, tip_height: int | None = None) -> dict:
    inputs = []
    outputs = []
    target_input_sats = 0
    target_output_sats = 0
    input_total = 0
    output_total = 0

    for index, item in enumerate(json_list(tx.get("vin"))):
        prevout = json_object(item.get("prevout"))
        txid = str(item.get("txid") or "")
        addr = str(prevout.get("scriptpubkey_address") or "")
        value_sats = _int(prevout.get("value"))
        input_total += value_sats
        is_target = _same_address(addr, address)
        if is_target:
            target_input_sats += value_sats
        if addr or value_sats or item.get("is_coinbase"):
            inputs.append(
                {
                    "address": addr,
                    "value": _btc(value_sats),
                    "value_sats": value_sats,
                    "index": index,
                    "target": is_target,
                    "tx_hash": txid,
                    "vout": item.get("vout"),
                    "coinbase": bool(item.get("is_coinbase")),
                }
            )

    for index, item in enumerate(json_list(tx.get("vout"))):
        addr = str(item.get("scriptpubkey_address") or "")
        value_sats = _int(item.get("value"))
        output_total += value_sats
        is_target = _same_address(addr, address)
        if is_target:
            target_output_sats += value_sats
        outputs.append(
            {
                "address": addr,
                "value": _btc(value_sats),
                "value_sats": value_sats,
                "index": index,
                "target": is_target,
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

    fee_sats = tx.get("fee")
    if fee_sats is None and input_total >= output_total and input_total:
        fee_sats = input_total - output_total
    status = json_object(tx.get("status"))
    return {
        "inputs": inputs,
        "outputs": outputs,
        "direction": direction,
        "amount": _btc(abs(net_sats)) if target_input_sats or target_output_sats else None,
        "fee": _btc(fee_sats) if fee_sats is not None else None,
        "fee_sats": _int(fee_sats) if fee_sats is not None else None,
        "confirmations": _confirmations(status, tip_height),
        "target_input": _btc(target_input_sats),
        "target_output": _btc(target_output_sats),
        "input_summary": _io_summary(inputs),
        "output_summary": _io_summary(outputs),
    }


def _utxo_view(item: dict, tip_height: int | None, source: str) -> dict:
    txid = str(item.get("txid") or "")
    status = json_object(item.get("status"))
    confirmations = _confirmations(status, tip_height)
    return {
        "tx_hash": txid,
        "txid": txid,
        "vout": item.get("vout"),
        "value": _btc(item.get("value")),
        "value_sats": _int(item.get("value")),
        "confirmations": confirmations,
        "status": "confirmed" if status.get("confirmed") else "mempool",
        "url": f"{MEMPOOL_EXPLORER}/tx/{txid}" if txid else "",
        "source": source,
        "raw": item,
    }


def _bitcoin_summary(address: str, source: str, data: dict, txs: list[dict], utxos: list[dict], tip_height: int | None, warnings: list[str]) -> dict:
    funded, spent, tx_count = _stats(data)
    stamps = [_status_time(json_object(tx.get("status"))) for tx in txs]
    stamps = [stamp for stamp in stamps if stamp]
    source_warnings = list(dict.fromkeys(warnings))
    if tx_count and txs and len(txs) < tx_count:
        source_warnings.append(f"{source}: first_seen limited to fetched transactions")
    utxo_views = [_utxo_view(item, tip_height, source) for item in utxos]
    unspent_outputs = len(utxo_views) if utxo_views else _unspent_count(data)
    return {
        "address": address,
        "chain": "bitcoin",
        "balance": _btc(funded - spent),
        "balance_sats": funded - spent,
        "total_received": _btc(funded),
        "total_received_sats": funded,
        "total_sent": _btc(spent),
        "total_sent_sats": spent,
        "tx_count": tx_count,
        "first_seen": min(stamps) if stamps else None,
        "last_seen": max(stamps) if stamps else None,
        "unspent_outputs": unspent_outputs,
        "utxos": utxo_views,
        "confirmations": None,
        "explorer_links": {
            "mempool": f"{MEMPOOL_EXPLORER}/address/{address}",
            "blockstream": f"https://blockstream.info/address/{address}",
        },
        "sources": [source],
        "warnings": source_warnings,
        "partial": bool(source_warnings),
    }


class BitcoinEsploraSource(Source):
    name = "bitcoin_esplora"
    chain = "btc"
    api_base = ""

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def _get_json(self, client: httpx.AsyncClient, path: str) -> Any:
        response = await client.get(f"{self.api_base}{path}")
        response.raise_for_status()
        return response.json()

    async def _tip_height(self, client: httpx.AsyncClient, out: AddressReport) -> int | None:
        try:
            return _int(await self._get_json(client, "/blocks/tip/height"))
        except Exception as exc:
            out.warnings.append(f"{self.name}: tip_height: {http_error_message(exc)}")
            return None

    async def _address_data(self, client: httpx.AsyncClient, address: str, out: AddressReport) -> dict:
        try:
            return json_object(await self._get_json(client, f"/address/{address}"))
        except Exception as exc:
            out.errors.append(f"{self.name}: address_lookup: {http_error_message(exc)}")
            return {}

    async def _address_txs(self, client: httpx.AsyncClient, address: str, out: AddressReport, limit: int = 100) -> list[dict]:
        txs = []
        self._pending_btc_txs = txs
        async def fetch(cursor):
            suffix = "/chain/" + cursor["last_txid"] if cursor.get("last_txid") else ""
            result = await self._get_json(client, f"/address/{address}/txs{suffix}")
            return result if isinstance(result, list) else None
        def advance(data, items, cursor):
            return {"last_txid": str(items[-1].get("txid") or "")} if items else None
        async for page in pages(self, out, "account_transactions", fetch, lambda data: data, advance, page_size=25, legacy_pages=4):
            txs.extend(page)
            if getattr(self, "_continuous", False):
                self._parse_btc_transactions(out, address, page, getattr(self, "_tip", None))
            elif len(txs) >= limit:
                break
        return txs

    async def _address_utxos(self, client: httpx.AsyncClient, address: str, out: AddressReport) -> list[dict]:
        try:
            return json_list(await self._get_json(client, f"/address/{address}/utxo"))
        except Exception as exc:
            out.warnings.append(f"{self.name}: utxo: {http_error_message(exc)}")
            return []

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["btc"], sources_used=[self.name])
        self._partial_report = out
        self._pending_btc_txs = []
        tip_height, data, txs, utxos = None, {}, [], []
        try:
            async with create_async_client(min(self._timeout, 10.0)) as client:
                tip_height = await self._tip_height(client, out)
                self._tip = tip_height
                data = await self._address_data(client, address, out)
                txs = await self._address_txs(client, address, out)
                utxos = await self._address_utxos(client, address, out)
        except asyncio.CancelledError:
            out.warnings.append(f"{self.name}: collection cancelled; available observations retained")
            raise
        finally:
            # SourceManager's deadline must not discard completed address/pages.
            self._finish_address_report(out, address, data, txs or self._pending_btc_txs, utxos, tip_height)
        return out

    def _finish_address_report(self, out: AddressReport, address: str, data: dict,
                               txs: list[dict], utxos: list[dict], tip_height: int | None) -> AddressReport:
        if data:
            try:
                funded, spent, _ = _stats(data)
                out.balances.append(
                    Balance(
                        chain="btc",
                        address=address,
                        asset="BTC",
                        amount=_btc(funded - spent),
                        source=self.name,
                        url=f"{MEMPOOL_EXPLORER}/address/{address}",
                        raw={"sats": funded - spent, "total_received_sats": funded, "total_sent_sats": spent},
                    )
                )
            except Exception as exc:
                out.errors.append(f"{self.name}: balance_parse: {exc}")

        if not getattr(self, "_continuous", False):
            self._parse_btc_transactions(out, address, txs, tip_height)

        out.bitcoin = _bitcoin_summary(address, self.name, data, txs, utxos, tip_height, out.warnings) if data or txs or utxos else {}
        if out.bitcoin and not data:
            # A missing account lookup is not a confirmed zero balance.
            for key in ("balance", "balance_sats", "total_received", "total_received_sats", "total_sent", "total_sent_sats"):
                out.bitcoin[key] = None
        status = "partial" if out.errors or out.warnings else "ok"
        details = "partial data returned" if status == "partial" else "address data collected"
        out.source_health.append(SourceHealth(source=self.name, status=status, timeout_seconds=self._timeout, retry_strategy="bounded esplora request", details=details))
        return out

    def _parse_btc_transactions(self, out, address, txs, tip_height):
        for tx in txs:
            txid = str(tx.get("txid") or "")
            if not txid:
                out.warnings.append(f"{self.name}: malformed transaction without txid")
                continue
            try:
                status = json_object(tx.get("status"))
                view = _btc_tx_view(tx, address, tip_height)
                out.transactions.append(
                    Transaction(
                        tx_hash=txid,
                        chain="btc",
                        timestamp=_status_time(status),
                        amount=view["amount"],
                        asset="BTC",
                        direction=view["direction"],
                        fee=view["fee"],
                        confirmations=view["confirmations"],
                        inputs=view["inputs"],
                        outputs=view["outputs"],
                        source=self.name,
                        url=f"{MEMPOOL_EXPLORER}/tx/{txid}",
                        raw={
                            "provider": self.name, "provider_record": tx,
                            "confirmed": bool(status.get("confirmed")),
                            "block_height": status.get("block_height"),
                            "block_time": status.get("block_time"),
                            "confirmations": view["confirmations"],
                            "fee": view["fee"],
                            "fee_sats": view["fee_sats"],
                            "input_count": len(view["inputs"]),
                            "output_count": len(view["outputs"]),
                            "input_summary": view["input_summary"],
                            "output_summary": view["output_summary"],
                            "target_input": view["target_input"],
                            "target_output": view["target_output"],
                        },
                    )
                )
            except Exception as exc:
                out.errors.append(f"{self.name}: tx_parse: {exc}")



class BitcoinMempoolSource(BitcoinEsploraSource):
    name = "mempool_space"
    api_base = "https://mempool.space/api"
