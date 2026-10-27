from __future__ import annotations

from app.sources.pagination import pages

import logging
import asyncio
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx

from app.models.report import AddressReport, Balance, SourceHealth, TokenHolding, Transaction
from app.sources.base import Source
from app.utils.detect import is_tron_address, looks_like_tron_address
from app.utils.http import create_async_client, http_error_message, json_list, json_object, shared_async_client, request_json, _retry_after_seconds

logger = logging.getLogger(__name__)

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, rem = divmod(number, 58)
        encoded = BASE58_ALPHABET[rem] + encoded
    pad = 0
    for byte in raw:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + (encoded or "1")


def _tron_address(value) -> str | None:
    if not isinstance(value, str) or not value:
        return value if isinstance(value, str) else None
    raw = value.strip()
    if raw.startswith("T"):
        return raw
    if len(raw) == 42 and raw.startswith("41"):
        try:
            payload = bytes.fromhex(raw)
            checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            return _base58_encode(payload + checksum)
        except ValueError:
            return raw
    return raw


def _amount(value: Any, decimals: int = 6) -> float | None:
    try:
        return float(value) / (10 ** max(decimals, 0))
    except Exception:
        return None


def _int_value(value: Any) -> int | None:
    try:
        return int(str(value))
    except Exception:
        return None


def _direction(target: str, frm: str | None, to: str | None) -> str:
    target = target.lower()
    frm = (frm or "").lower()
    to = (to or "").lower()
    if frm == target and to == target:
        return "self"
    if frm == target:
        return "out"
    if to == target:
        return "in"
    return "unknown"


class TronGridSource(Source):
    name = "trongrid"
    chain = "tron"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds
        self._execution_receipts = {}
        self._execution_receipt_attempted = set()
        self._execution_receipt_stopped = False
        self._execution_receipt_not_before = 0.0
        self._native_receipt_probed = self._trc20_receipt_probed = False

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["tron"], sources_used=[self.name])
        self._partial_report = out
        self._execution_receipts = {}
        self._execution_receipt_attempted = set()
        self._execution_receipt_stopped = False
        self._native_receipt_probed = self._trc20_receipt_probed = False
        if not looks_like_tron_address(address):
            out.errors.append(f"{self.name}: invalid tron address format")
            out.source_health.append(SourceHealth(source=self.name, status="error", timeout_seconds=self._timeout, retry_strategy="tron base58 validation", details="invalid tron address format"))
            return out
        if not is_tron_address(address):
            out.warnings.append("tron: invalid address checksum")
            out.source_health.append(SourceHealth(source=self.name, status="error", timeout_seconds=self._timeout, retry_strategy="tron base58 validation", details="invalid address checksum"))
            return out
        base = "https://api.trongrid.io/v1"
        try:
            async with create_async_client(min(self._timeout, 10.0)) as client:
                r = await client.get(f"{base}/accounts/{address}")
                if r.status_code == 429:
                    out.warnings.append(f"{self.name}: rate_limited: http 429")
                    out.source_health.append(SourceHealth(source=self.name, status="rate_limited", timeout_seconds=self._timeout, retry_strategy="public trongrid request", details="http 429"))
                    return out
                r.raise_for_status()
                data = json_object(r.json())
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: {http_error_message(e)}")
            return out

        try:
            accounts = json_list(data.get("data"))
            acc = json_object(accounts[0] if accounts else {})
            bal_sun = _int_value(acc.get("balance"))
            if bal_sun is not None and bal_sun >= 0:
                out.balances.append(
                    Balance(
                        chain="tron",
                        address=address,
                        asset="TRX",
                        amount=bal_sun / 1e6,
                        source=self.name,
                        url=f"https://tronscan.org/#/address/{address}",
                        raw={"sun": bal_sun},
                    )
                )
            elif bal_sun is not None:
                out.warnings.append(f"{self.name}: trx balance unavailable: negative source value")
            resources = {}
            for key in ("free_net_usage", "net_usage", "net_window_size", "account_resource", "frozenV2", "delegated_frozenV2_balance_for_bandwidth", "acquired_delegated_frozenV2_balance_for_energy"):
                if acc.get(key) not in (None, "", [], {}):
                    resources[key] = acc.get(key)
            permissions = {}
            for key in ("owner_permission", "active_permission", "ownerPermission", "activePermissions", "active_permissions"):
                if acc.get(key) not in (None, "", [], {}):
                    permissions[key] = acc.get(key)
            out.tron = {
                **(out.tron or {}),
                "address": address,
                "resources": resources,
                "permissions": permissions or (out.tron or {}).get("permissions") or {},
                "explorer_links": {"tronscan": f"https://tronscan.org/#/address/{address}"},
                "sources": list(dict.fromkeys(list((out.tron or {}).get("sources") or []) + [self.name])),
            }
        except Exception as e:
            out.errors.append(f"{self.name}: balance_parse: {e}")

        async with create_async_client(min(self._timeout, 10.0)) as client:
            async for data in self._history_pages(client, address, out, "transactions"):
                self._parse_native_transactions(address, out, json_list(data.get("data")))
                if not self._native_receipt_probed:
                    self._native_receipt_probed = True
                    await self._enrich_execution_receipts(out, max_new=1)

        await self._fetch_trc20(address, out)
        for tx in out.transactions:
            if tx.tx_hash in self._execution_receipts:
                tx.raw["solidified_execution_evidence"] = self._execution_receipts[tx.tx_hash]
        status = "partial" if out.errors or out.warnings else "ok"
        if not any(item.source == self.name for item in out.source_health):
            out.source_health.append(SourceHealth(source=self.name, status=status, timeout_seconds=self._timeout, retry_strategy="public trongrid requests", details="partial data collected" if status == "partial" else "address data collected"))
        out.tron = {
            **(out.tron or {}),
            "warnings": list(dict.fromkeys(list((out.tron or {}).get("warnings") or []) + [item for item in out.warnings if str(item).startswith(("tron:", self.name))])),
            "partial": bool(out.errors or out.warnings or (out.tron or {}).get("partial")),
            "sources": list(dict.fromkeys(list((out.tron or {}).get("sources") or []) + [self.name])),
        }
        return out

    async def _wait_execution_cooldown(self) -> None:
        delay = self._execution_receipt_not_before - asyncio.get_running_loop().time()
        if delay > 0:
            await asyncio.sleep(delay)

    async def _enrich_execution_receipts(self, out: AddressReport, *, max_new: int) -> None:
        """Early, bounded raw evidence; no new transfer or normalized value."""
        receipts, attempted = self._execution_receipts, self._execution_receipt_attempted
        coverage = out.coverage.setdefault("trongrid_execution_receipts", {
            "history_complete": False, "lookup_limit": 3,
            "scope": "solidified evidence for already observed TX; original history streams unchanged",
            "cache_policy": "existing request_json in-memory cache, TTL 45 seconds",
        })
        if self._execution_receipt_stopped:
            return
        url = "https://api.trongrid.io/walletsolidity/gettransactioninfobyid"
        selected = sorted(out.transactions, key=lambda tx: (
            0 if (tx.raw or {}).get("type") == "trc20_transfer"
            or (tx.raw or {}).get("native_contract_type") == "TriggerSmartContract" else 1
        ))
        new_lookups = 0
        try:
            async with asyncio.timeout(min(self._timeout, 5.0)):
                async with shared_async_client(min(self._timeout, 2.0)) as client:
                    for tx in selected:
                        if new_lookups >= max_new or len(attempted) >= 3:
                            break
                        txid = tx.tx_hash
                        if txid in attempted or len(txid) != 64 or any(c not in "0123456789abcdefABCDEF" for c in txid):
                            continue
                        # Separate the auxiliary request from the last history
                        # request, and its successor, through the same source.
                        self._execution_receipt_not_before = max(self._execution_receipt_not_before, asyncio.get_running_loop().time() + 1.1)
                        await self._wait_execution_cooldown()
                        attempted.add(txid)
                        new_lookups += 1
                        try:
                            data = json_object(await request_json(client, "POST", url,
                                json={"value": txid}, retries=0, cache_ttl=45.0))
                            if data.get("Error") or data.get("error"):
                                out.errors.append(f"{self.name}: execution_receipt: provider returned an error")
                                self._execution_receipt_stopped = True
                                coverage["stop_reason"] = "provider_error"
                                break
                            if str(data.get("id") or "").lower() != txid.lower():
                                out.warnings.append(f"{self.name}: execution_receipt: no matching solidified receipt for {txid}")
                                continue
                            receipts[txid] = {"source": self.name, "source_url": url,
                                "request": {"value": txid}, "observed_at": datetime.now(timezone.utc).isoformat(),
                                "confirmation_scope": "solidified", "transaction_info": data}
                        except httpx.HTTPStatusError as exc:
                            status = exc.response.status_code
                            coverage["stop_reason"] = f"http_{status}"
                            self._execution_receipt_stopped = True
                            if status == 429:
                                delay = _retry_after_seconds(exc.response)
                                delay = 5.0 if delay is None else max(0.0, delay)
                                self._execution_receipt_not_before = asyncio.get_running_loop().time() + delay
                                coverage.update(retry_after=exc.response.headers.get("Retry-After"),
                                    cooldown_seconds=delay,
                                    cooldown_until_utc=(datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat())
                                out.warnings.append(f"{self.name}: execution_receipt: http 429; auxiliary lookup stopped; history honors cooldown")
                                out.source_health.append(SourceHealth(source=self.name, status="rate_limited", partial=True,
                                    timeout_seconds=self._timeout, retry_strategy="stop auxiliary lookups; preserve Retry-After for following history",
                                    details="execution_receipt: http 429"))
                            else:
                                out.errors.append(f"{self.name}: execution_receipt: http {status}; lookup stopped")
                            break
                        except (httpx.HTTPError, ValueError) as exc:
                            out.errors.append(f"{self.name}: execution_receipt: {http_error_message(exc)}")
                            self._execution_receipt_stopped = True
                            break
                        finally:
                            self._execution_receipt_not_before = max(self._execution_receipt_not_before, asyncio.get_running_loop().time() + 1.1)
        except TimeoutError:
            out.warnings.append(f"{self.name}: execution_receipt: bounded enrichment deadline; history retained")
            coverage["stop_reason"] = "enrichment_deadline"
            self._execution_receipt_stopped = True
        finally:
            for tx in out.transactions:
                if tx.tx_hash in receipts:
                    tx.raw["solidified_execution_evidence"] = receipts[tx.tx_hash]
            coverage.update(lookups_attempted=len(attempted), receipts_observed=len(receipts), observed_txids=sorted(receipts))

    def _parse_native_transactions(self, address, out, txs):
        for t in txs:
            try:
                txid = t.get("txID") or t.get("tx_id")
                ts = t.get("block_timestamp")
                dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc) if ts else None
                owner = None
                to = None
                value = None
                asset = "TRX"
                raw_data = json_object(t.get("raw_data"))
                contracts = json_list(raw_data.get("contract"))
                contract_name = str(json_object(contracts[0]).get("type") or "") if contracts else ""
                operation_type = "resource" if contract_name in {"DelegateResourceContract", "UnDelegateResourceContract"} else "permission_update" if contract_name == "AccountPermissionUpdateContract" else "transfer"
                if contracts:
                    param = json_object(json_object(contracts[0]).get("parameter")).get("value", {})
                    param = json_object(param)
                    owner = _tron_address(param.get("owner_address") or param.get("ownerAddress"))
                    to = _tron_address(param.get("to_address") or param.get("toAddress") or param.get("receiver_address"))
                    value = param.get("amount")
                ret = json_list(t.get("ret"))
                ret0 = json_object(ret[0] if ret else {})
                fee = _amount(ret0.get("fee") or t.get("fee") or t.get("net_fee") or 0, 6)
                out.transactions.append(
                    Transaction(
                        chain="tron",
                        tx_hash=str(txid),
                        timestamp=dt,
                        from_address=owner,
                        to_address=to,
                        amount=_amount(value, 6),
                        asset=asset,
                        direction=_direction(address, owner, to),
                        fee=fee,
                        confirmations=1 if ret0.get("contractRet") == "SUCCESS" else None,
                        source=self.name,
                        url=f"https://tronscan.org/#/transaction/{txid}" if txid else None,
                        raw={"provider": "trongrid", "provider_record": t, "type": operation_type, "native_contract_type": contract_name, "status": ret0.get("contractRet"), "fee": fee},
                    )
                )
            except Exception as e:
                out.errors.append(f"{self.name}: tx_parse: {e}")

    async def _history_pages(self, client, address, out, stream):
        path = "transactions/trc20" if stream == "trc20_transfers" else "transactions"
        async def fetch(cursor):
            params = {"limit": 50, "order_by": "block_timestamp,desc"}
            if cursor.get("fingerprint"):
                params["fingerprint"] = cursor["fingerprint"]
            await self._wait_execution_cooldown()
            response = await client.get(f"https://api.trongrid.io/v1/accounts/{address}/{path}", params=params)
            if response.status_code == 429:
                delay = _retry_after_seconds(response)
                delay = 5.0 if delay is None else max(0.0, delay)
                self._execution_receipt_not_before = max(self._execution_receipt_not_before, asyncio.get_running_loop().time() + delay)
                out.coverage["trongrid_provider_cooldown"] = {
                    "stream": stream, "http_status": 429,
                    "retry_after": response.headers.get("Retry-After"), "cooldown_seconds": delay,
                    "cooldown_until_utc": (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat(),
                }
                out.warnings.append(f"{self.name}: {stream}: rate_limited: http 429")
                out.source_health.append(SourceHealth(source=self.name, status="rate_limited", timeout_seconds=self._timeout, retry_strategy="resume saved fingerprint", details="http 429"))
                return None
            response.raise_for_status()
            return json_object(response.json())
        def advance(data, items, cursor):
            fingerprint = json_object(data.get("meta")).get("fingerprint")
            return {"fingerprint": fingerprint} if fingerprint else None
        async for data in pages(self, out, stream, fetch, lambda data: data.get("data"), advance, page_size=50):
            yield data

    async def _fetch_trc20(self, address: str, out: AddressReport) -> None:
        async with create_async_client(min(self._timeout, 10.0)) as client:
            async for data in self._history_pages(client, address, out, "trc20_transfers"):
                self._parse_trc20_page(address, out, data)
                if not self._trc20_receipt_probed:
                    self._trc20_receipt_probed = True
                    await self._enrich_execution_receipts(out, max_new=2)

    def _parse_trc20_page(self, address, out, data):
        contracts: dict[str, dict] = {}
        for t in json_list(data.get("data")):
            t = json_object(t)
            ti = json_object(t.get("token_info"))
            c = ti.get("address") or t.get("token_address")
            if not c:
                continue
            contracts[c] = ti
            try:
                decimals = _int_value(ti.get("decimals")) or 6
                frm = _tron_address(t.get("from"))
                to = _tron_address(t.get("to"))
                txid = str(t.get("transaction_id") or t.get("tx_id") or "")
                symbol = str(ti.get("symbol") or "TRC20").upper()
                out.transactions.append(
                    Transaction(
                        chain="tron",
                        tx_hash=txid,
                        timestamp=datetime.fromtimestamp(float(t.get("block_timestamp")) / 1000, tz=timezone.utc) if t.get("block_timestamp") else None,
                        from_address=frm,
                        to_address=to,
                        amount=_amount(t.get("value"), decimals),
                        asset=symbol,
                        direction=_direction(address, frm, to),
                        confirmations=1 if t.get("confirmed") is True else None,
                        source=self.name,
                        url=f"https://tronscan.org/#/transaction/{txid}" if txid else None,
                        raw={"provider": self.name, "provider_record": t, "type": "trc20_transfer", "contract": c, "token_info": ti, "status": "SUCCESS" if t.get("confirmed") else "", "tokenLogo": ti.get("logo_url") or ti.get("icon_url"), "logo_url": ti.get("logo_url") or ti.get("icon_url")},
                    )
                )
            except Exception as e:
                out.errors.append(f"{self.name}: trc20_tx_parse: {e}")
        for c, ti in list(contracts.items()):
            out.tokens.append(
                TokenHolding(
                    chain="tron",
                    address=address,
                    contract=c,
                    symbol=ti.get("symbol"),
                    name=ti.get("name"),
                    amount=None,
                    source=self.name,
                    url=f"https://tronscan.org/#/token20/{c}",
                    raw={"asset_type": "trc20", "token_info": ti, "tokenLogo": ti.get("logo_url") or ti.get("icon_url"), "logo_url": ti.get("logo_url") or ti.get("icon_url"), "decimals": _int_value(ti.get("decimals")) or 6, "price": ti.get("price") or ti.get("price_usd"), "token_age": ti.get("issue_time") or ti.get("create_time"), "holder_count": ti.get("holder_count") or ti.get("holders_count"), "verified": ti.get("verified")},
                )
            )

