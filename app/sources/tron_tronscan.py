from __future__ import annotations

import asyncio
from app.sources.pagination import pages

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx

from app.models.report import AddressReport, Balance, Label, SourceHealth, TokenHolding, Transaction
from app.sources.base import Source
from app.utils.detect import is_tron_address, looks_like_tron_address
from app.utils.http import http_error_message, json_list, json_object, shared_async_client


USDT_TRC20_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


def _dt_ms(value: Any) -> datetime | None:
    try:
        number = int(str(value))
        if number <= 0:
            return None
        if number < 10_000_000_000:
            number *= 1000
        return datetime.fromtimestamp(number / 1000, tz=timezone.utc)
    except Exception:
        return None


def _int_value(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value))
    except Exception:
        return None


def _amount(value: Any, decimals: int = 6) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(Decimal(str(value)) / (Decimal(10) ** max(decimals, 0)))
    except (InvalidOperation, ValueError, TypeError, OverflowError):
        try:
            return float(value)
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


def _text(value: Any) -> str:
    return str(value or "").strip()


def _decode_memo(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    try:
        raw = bytes.fromhex(text)
        decoded = raw.decode("utf-8", errors="ignore").strip("\x00").strip()
        return decoded if decoded and all(ch.isprintable() for ch in decoded) else text
    except Exception:
        return text


def _resource_value(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return value[:20]
    if isinstance(value, dict):
        return {key: value[key] for key in sorted(value)[:20]}
    return str(value)


class TronScanSource(Source):
    name = "tronscan"
    chain = "tron"
    base_url = "https://apilist.tronscanapi.com"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["tron"], sources_used=[self.name])
        self._partial_report = out
        if not looks_like_tron_address(address):
            self._health(out, "error", "invalid tron address format")
            out.errors.append(f"{self.name}: invalid tron address format")
            return out
        if not is_tron_address(address):
            out.warnings.append("tron: invalid address checksum")
            self._health(out, "error", "invalid address checksum")
            return out

        async with shared_async_client(min(self._timeout, 10.0)) as client:
            account = await self._get(client, "/api/account", {"address": address}, out, "account")
            if account:
                self._parse_account(address, account, out)
            async def collect(path, parameters, key, label, parser):
                async def fetch(cursor):
                    return await self._get(client, path, {**parameters, "start": str(cursor.get("offset", 0))}, out, label)
                def advance(data, items, cursor):
                    return {"offset": int(cursor.get("offset", 0)) + len(items)}
                async for data in pages(self, out, label, fetch, lambda data: data.get(key), advance, page_size=50, adjust_offset=True):
                    parser(address, data, out)
            loaders = (collect("/api/transaction", {"sort": "-timestamp", "count": "true", "limit": "50", "address": address}, "data", "transactions", self._parse_transactions), collect("/api/token_trc20/transfers", {"limit": "50", "sort": "-timestamp", "relatedAddress": address}, "token_transfers", "trc20_transfers", self._parse_trc20_transfers))
            if getattr(self, "_continuous", False):
                await asyncio.gather(*loaders)
            else:
                for loader in loaders:
                    await loader

        tron_txs = [tx.timestamp for tx in out.transactions if tx.chain == "tron" and tx.timestamp]
        if tron_txs:
            data = dict(out.tron or {})
            data["first_seen"] = min([item for item in [data.get("first_seen"), *tron_txs] if item], default=None)
            data["last_seen"] = max([item for item in [data.get("last_seen"), *tron_txs] if item], default=None)
            out.tron = data

        if not any(item.source == self.name for item in out.source_health):
            produced = bool(out.balances or out.transactions or out.tokens or out.tron)
            status = "partial" if out.errors or out.warnings else "ok" if produced else "partial"
            details = "partial data collected" if status == "partial" else "address data collected"
            self._health(out, status, details)
        self._refresh_tron_state(out)
        return out

    async def _get(self, client: httpx.AsyncClient, path: str, params: dict[str, Any], out: AddressReport, label: str) -> dict:
        try:
            response = await client.get(f"{self.base_url}{path}", params=params)
            if response.status_code == 429:
                out.warnings.append(f"{self.name}: {label}: rate_limited: http 429")
                self._health(out, "rate_limited", f"{label}: http 429")
                return {}
            if response.status_code >= 400:
                out.errors.append(f"{self.name}: {label}: http {response.status_code}")
                return {}
            data = response.json()
        except httpx.TimeoutException as exc:
            out.errors.append(f"{self.name}: {label}: {http_error_message(exc)}")
            self._health(out, "timeout", label)
            return {}
        except httpx.HTTPError as exc:
            out.errors.append(f"{self.name}: {label}: {http_error_message(exc)}")
            return {}
        except ValueError as exc:
            out.errors.append(f"{self.name}: {label}: malformed response: {exc}")
            return {}
        return json_object(data)

    def _parse_account(self, address: str, account: dict, out: AddressReport) -> None:
        raw_balance = _int_value(account.get("balance"))
        if raw_balance is not None and raw_balance >= 0:
            out.balances.append(
                Balance(
                    chain="tron",
                    address=address,
                    asset="TRX",
                    amount=raw_balance / 1_000_000,
                    source=self.name,
                    url=f"https://tronscan.org/#/address/{address}",
                    raw={"sun": raw_balance, "explorer": "tronscan"},
                )
            )
        elif raw_balance is not None:
            out.warnings.append(f"{self.name}: trx balance unavailable: negative source value")

        label = _text(account.get("addressTag") or account.get("name"))
        if label:
            out.labels.append(Label(chain="tron", address=address, label=label[:120], source=self.name, confidence=0.72, raw={"url": f"https://tronscan.org/#/address/{address}"}))

        for token in json_list(account.get("trc20token_balances"))[:120]:
            self._add_token_holding(address, json_object(token), out, include_amount=True)

        first_seen = _dt_ms(account.get("date_created"))
        resources = {}
        for key in (
            "bandwidth",
            "freeNetLimit",
            "freeNetUsed",
            "netLimit",
            "netUsed",
            "energyLimit",
            "energyUsed",
            "frozen",
            "frozenForBandWidth",
            "frozenForEnergy",
            "delegateFrozenForBandWidth",
            "delegateFrozenForEnergy",
            "acquiredDelegateFrozenForBandWidth",
            "acquiredDelegateFrozenForEnergy",
            "delegated",
            "accountResource",
            "totalFrozen",
        ):
            if key in account and account.get(key) not in (None, "", [], {}):
                resources[key] = _resource_value(account.get(key))

        permissions = {}
        for key in ("ownerPermission", "owner_permission", "activePermissions", "active_permissions", "activePermission", "active_permission"):
            if account.get(key) not in (None, "", [], {}):
                permissions[key] = _resource_value(account.get(key))

        out.tron = {
            **(out.tron or {}),
            "address": address,
            "tx_count": _int_value(account.get("totalTransactionCount")) or _int_value(account.get("transactions")),
            "first_seen": first_seen,
            "resources": resources,
            "permissions": permissions or (out.tron or {}).get("permissions") or {},
            "explorer_links": {"tronscan": f"https://tronscan.org/#/address/{address}"},
            "sources": list(dict.fromkeys(list((out.tron or {}).get("sources") or []) + [self.name])),
        }

    def _parse_transactions(self, address: str, payload: dict, out: AddressReport) -> None:
        data = json_list(payload.get("data"))
        if payload.get("rangeTotal") is not None or payload.get("total") is not None:
            current = dict(out.tron or {})
            current["tx_count"] = _int_value(payload.get("rangeTotal")) or _int_value(payload.get("total")) or current.get("tx_count")
            out.tron = current
        for item in data:
            item = json_object(item)
            tx_hash = _text(item.get("hash"))
            if not tx_hash:
                out.warnings.append(f"{self.name}: transaction_without_hash")
                continue
            contract_data = json_object(item.get("contractData"))
            token_info = json_object(item.get("tokenInfo"))
            frm = _text(item.get("ownerAddress") or contract_data.get("owner_address") or contract_data.get("from_address"))
            to = _text(item.get("toAddress") or contract_data.get("to_address") or contract_data.get("receiver_address"))
            if not to:
                to_list = json_list(item.get("toAddressList"))
                to = _text(to_list[0] if to_list else "")
            decimals = _int_value(token_info.get("tokenDecimal")) or 6
            token_type = _text(item.get("tokenType") or token_info.get("tokenType")).lower()
            symbol = _text(token_info.get("tokenAbbr")).upper()
            asset = "TRX" if symbol in {"", "TRX"} or token_info.get("tokenId") == "_" else symbol
            amount_raw = item.get("amount")
            if amount_raw in (None, ""):
                amount_raw = contract_data.get("amount")
            amount = _amount(amount_raw, decimals)
            cost = json_object(item.get("cost"))
            fee = _amount(cost.get("fee") or item.get("fee"), 6)
            status = _text(item.get("contractRet") or item.get("result") or item.get("finalResult"))
            memo = _decode_memo(item.get("data"))
            tx_type = "trc20_transfer" if token_type == "trc20" else "resource" if _int_value(item.get("contractType")) in {57, 58} else "transfer"
            out.transactions.append(
                Transaction(
                    tx_hash=tx_hash,
                    chain="tron",
                    timestamp=_dt_ms(item.get("timestamp")),
                    from_address=frm or None,
                    to_address=to or None,
                    amount=amount,
                    asset=asset,
                    direction=_direction(address, frm, to),
                    fee=fee,
                    confirmations=1 if item.get("confirmed") is True else None,
                    source=self.name,
                    url=f"https://tronscan.org/#/transaction/{tx_hash}",
                    raw={
                        "provider": self.name, "provider_record": item,
                        "type": tx_type,
                        "status": status,
                        "confirmed": item.get("confirmed"),
                        "contract_type": item.get("contractType"),
                        "memo": memo,
                        "fee": fee,
                        "token_info": token_info,
                        "contract": token_info.get("tokenId") if token_type == "trc20" else "",
                    },
                )
            )

    def _parse_trc20_transfers(self, address: str, payload: dict, out: AddressReport) -> None:
        for item in json_list(payload.get("token_transfers")):
            item = json_object(item)
            token_info = json_object(item.get("tokenInfo"))
            contract = _text(item.get("contract_address") or token_info.get("tokenId"))
            tx_hash = _text(item.get("transaction_id"))
            if not tx_hash:
                continue
            self._add_token_holding(address, {**token_info, "tokenId": contract or token_info.get("tokenId")}, out, include_amount=False)
            decimals = _int_value(token_info.get("tokenDecimal")) or 6
            symbol = _text(token_info.get("tokenAbbr")).upper() or "TRC20"
            frm = _text(item.get("from_address"))
            to = _text(item.get("to_address"))
            status = _text(item.get("finalResult") or item.get("contractRet") or item.get("event_type"))
            out.transactions.append(
                Transaction(
                    tx_hash=tx_hash,
                    chain="tron",
                    timestamp=_dt_ms(item.get("block_ts")),
                    from_address=frm or None,
                    to_address=to or None,
                    amount=_amount(item.get("quant"), decimals),
                    asset=symbol,
                    direction=_direction(address, frm, to),
                    confirmations=1 if item.get("confirmed") is True else None,
                    source=self.name,
                    url=f"https://tronscan.org/#/transaction/{tx_hash}",
                    raw={
                        "provider": self.name, "provider_record": item,
                        "type": "trc20_transfer",
                        "status": status,
                        "contract": contract,
                        "token_info": token_info,
                        "tokenLogo": token_info.get("tokenLogo") or token_info.get("logo_url") or token_info.get("icon_url"),
                        "logo_url": token_info.get("tokenLogo") or token_info.get("logo_url") or token_info.get("icon_url"),
                        "event_type": item.get("event_type"),
                        "method": json_object(item.get("trigger_info")).get("methodName") or json_object(item.get("trigger_info")).get("method"),
                        "confirmed": item.get("confirmed"),
                        "risk_transaction": item.get("riskTransaction"),
                    },
                )
            )

    def _add_token_holding(self, address: str, token: dict, out: AddressReport, *, include_amount: bool) -> None:
        token_type = _text(token.get("tokenType") or token.get("tokenType2")).lower()
        if token_type and token_type != "trc20":
            return
        contract = _text(token.get("tokenId") or token.get("address") or token.get("contract_address"))
        if not contract or contract == "_":
            return
        decimals = _int_value(token.get("tokenDecimal") or token.get("decimals")) or 6
        symbol = _text(token.get("tokenAbbr") or token.get("symbol")).upper() or None
        name = _text(token.get("tokenName") or token.get("name")) or None
        amount = _amount(token.get("balance"), decimals) if include_amount else None
        raw = {
            "asset_type": "trc20",
            "raw_balance": token.get("balance"),
            "decimals": decimals,
            "tokenLogo": token.get("tokenLogo") or token.get("logo_url") or token.get("icon_url"),
            "logo_url": token.get("tokenLogo") or token.get("logo_url") or token.get("icon_url"),
            "price": token.get("price") or token.get("priceInTrx") or token.get("priceInUsd"),
            "token_age": token.get("issue_time") or token.get("date_created") or token.get("create_time"),
            "holder_count": token.get("nrOfTokenHolders") or token.get("holder_count") or token.get("holders_count"),
            "verified": token.get("vip") or token.get("verified") or token.get("isOfficial"),
            "token_info": token,
            "is_usdt": contract == USDT_TRC20_CONTRACT or symbol == "USDT",
        }
        out.tokens.append(
            TokenHolding(
                chain="tron",
                address=address,
                contract=contract,
                symbol=symbol,
                name=name,
                amount=amount,
                source=self.name,
                url=f"https://tronscan.org/#/token20/{contract}",
                raw=raw,
            )
        )

    def _refresh_tron_state(self, out: AddressReport) -> None:
        data = dict(out.tron or {})
        data["warnings"] = list(dict.fromkeys(list(data.get("warnings") or []) + [item for item in out.warnings if str(item).startswith(("tron:", self.name))]))
        data["partial"] = bool(out.errors or out.warnings or data.get("partial"))
        data["sources"] = list(dict.fromkeys(list(data.get("sources") or []) + [self.name]))
        out.tron = data

    def _health(self, out: AddressReport, status: str, details: str) -> None:
        if any(item.source == self.name and item.status == status and item.details == details for item in out.source_health):
            return
        out.source_health.append(
            SourceHealth(
                source=self.name,
                status=status,
                timeout_seconds=self._timeout,
                retry_strategy="bounded public tronscan requests",
                details=details,
            )
        )
