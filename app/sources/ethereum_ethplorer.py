from __future__ import annotations

import os
import asyncio
from decimal import Decimal,localcontext
from app.attribution.normalize import canonical_address
from app.utils.event_identity import canonical_hash
from datetime import datetime, timezone
from typing import Any

import httpx

from app.models.report import AddressReport, Balance, Label, SourceHealth, TokenHolding, Transaction
from app.sources.base import Source
from app.utils.http import shared_async_client


class EthereumEthplorerSource(Source):
    name = "ethplorer"
    chain = "eth"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    def _api_key(self) -> str:
        return (os.getenv("ETHPLORER_API_KEY") or os.getenv("GANSAR_ETHPLORER_API_KEY") or "freekey").strip()

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["eth"], sources_used=[self.name])
        key = self._api_key()
        async with shared_async_client(self._timeout) as client:
            await self._fetch_info(client, address, key, out)
            await self._fetch_transactions(client, address, key, out)
            await asyncio.sleep(0.55)
            await self._fetch_token_history(client,address,key,out)
        return out

    async def _get(self, client: httpx.AsyncClient, path: str, params: dict[str, Any], out: AddressReport) -> dict[str, Any] | list | None:
        url = f"https://api.ethplorer.io/{path.lstrip('/')}"
        params = {"apiKey": self._api_key(), **params}
        try:
            r = await client.get(url, params=params)
            if r.status_code == 429:
                self._rate_limited(out, "http 429")
                return None
            if r.status_code >= 400:
                out.errors.append(f"{self.name}: http {r.status_code}")
                return None
            data = r.json()
        except httpx.TimeoutException:
            out.errors.append(f"{self.name}: timeout")
            return None
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: {e}")
            return None
        except ValueError as e:
            out.errors.append(f"{self.name}: invalid response: {e}")
            return None
        if isinstance(data, dict) and isinstance(data.get("error"), dict):
            message = str(data["error"].get("message") or data["error"])
            if "limit" in message.lower() or "suspend" in message.lower():
                self._rate_limited(out, message)
            else:
                out.errors.append(f"{self.name}: {message}")
            return None
        return data

    def _rate_limited(self, out: AddressReport, detail: str) -> None:
        item = f"{self.name}: rate_limited: {detail}"
        if item not in out.warnings:
            out.warnings.append(item)
        out.source_health.append(
            SourceHealth(
                source=self.name,
                status="rate_limited",
                timeout_seconds=min(self._timeout, 4.0),
                retry_strategy="public freekey or configured key, fallback sources",
                details=detail,
            )
        )

    async def _fetch_info(self, client: httpx.AsyncClient, address: str, key: str, out: AddressReport) -> None:
        data = await self._get(client, f"getAddressInfo/{address}", {"apiKey": key, "showETHTotals": "true"}, out)
        if not isinstance(data, dict):
            return
        eth = data.get("ETH")
        if isinstance(eth, dict):
            try:
                out.balances.append(
                    Balance(
                        chain="eth",
                        address=address,
                        asset="ETH",
                        amount=float(eth.get("balance") or 0),
                        source=self.name,
                        url=f"https://ethplorer.io/address/{address}",
                        raw={"total_in": eth.get("totalIn"), "total_out": eth.get("totalOut"), "txs_count": data.get("countTxs")},
                    )
                )
            except Exception as e:
                out.errors.append(f"{self.name}: balance_parse: {e}")
        if isinstance(data.get("contractInfo"), dict):
            info = data["contractInfo"]
            name = str(info.get("name") or info.get("symbol") or "").strip()
            if name:
                out.labels.append(
                    Label(
                        chain="eth",
                        address=address,
                        label=f"Contract: {name}",
                        source=self.name,
                        confidence=0.7,
                        raw={"url": f"https://ethplorer.io/address/{address}", "contract_info": info},
                    )
                )
        tokens = data.get("tokens")
        if isinstance(tokens, list):
            for item in tokens[:80]:
                if not isinstance(item, dict):
                    continue
                token_info = item.get("tokenInfo") if isinstance(item.get("tokenInfo"), dict) else {}
                try:
                    decimals = int(str(token_info.get("decimals") or "0"))
                except Exception:
                    decimals = 0
                raw_balance = str(item.get("rawBalance") or item.get("balance") or "0")
                amount = self._amount(raw_balance, decimals)
                contract = str(token_info.get("address") or "").strip()
                symbol = str(token_info.get("symbol") or "").strip() or None
                name = str(token_info.get("name") or "").strip() or None
                out.tokens.append(
                    TokenHolding(
                        chain="eth",
                        address=address,
                        contract=contract or None,
                        symbol=symbol,
                        name=name,
                        amount=amount,
                        source=self.name,
                        url=f"https://ethplorer.io/address/{contract}" if contract else f"https://ethplorer.io/address/{address}",
                        raw={
                            "asset_type": "erc20",
                            "raw_balance": raw_balance,
                            "decimals": decimals,
                            "price": token_info.get("price"),
                            "image": token_info.get("image"),
                        },
                    )
                )

    async def _fetch_transactions(self, client: httpx.AsyncClient, address: str, key: str, out: AddressReport) -> None:
        data = await self._get(client, f"getAddressTransactions/{address}", {"apiKey": key, "limit": "50"}, out)
        if not isinstance(data, list):
            return
        for item in data[:50]:
            if not isinstance(item, dict):
                continue
            try:
                tx_hash = str(item.get("hash") or "")
                frm = str(item.get("from") or "").strip()
                to = str(item.get("to") or "").strip()
                value = item.get("value")
                amount = float(value) if value is not None else None
                out.transactions.append(
                    Transaction(
                        chain="eth",
                        tx_hash=tx_hash,
                        timestamp=self._dt(item.get("timestamp")),
                        from_address=frm,
                        to_address=to,
                        amount=amount,
                        asset="ETH",
                        direction=self._direction(address, frm, to),
                        source=self.name,
                        url=f"https://etherscan.io/tx/{tx_hash}" if tx_hash else f"https://ethplorer.io/address/{address}",
                        raw={
                            "provider": self.name,
                            "provider_record": item,
                            "input": item.get("input"),
                            "success": item.get("success"),
                            "usd_value": item.get("usdValue"),
                            "usd_price": item.get("usdPrice"),
                            "type": "contract_call" if item.get("input") else "transfer",
                        },
                    )
                )
            except Exception as e:
                out.errors.append(f"{self.name}: tx_parse: {e}")

    async def _fetch_token_history(self,client,address,key,out):
        """Retain actual ERC20 operations from the existing provider's history API.

        One public-key response is capped at 100. It is explicitly partial, even
        when shorter, because the provider/key history window may be limited.
        """
        data=await self._get(client,f"getAddressHistory/{address}",{"apiKey":key,"type":"transfer","limit":"100"},out)
        rows=data.get("operations") if isinstance(data,dict) else None
        coverage={"status":"unavailable","history_complete":False,"row_limit":100,"retained_operations":0,
            "limitation":"Provider/key history window and response cap are not proof of complete token history."}
        out.coverage["ethplorer_token_history"]=coverage
        if not isinstance(rows,list):return
        coverage["status"]="partial";coverage["source_rows"]=len(rows)
        for item in rows[:100]:
            if not isinstance(item,dict) or item.get("type")!="transfer":continue
            token=item.get("tokenInfo") or {}
            if not isinstance(token,dict):continue
            contract=canonical_address("eth",token.get("address"));frm=canonical_address("eth",item.get("from"));to=canonical_address("eth",item.get("to"))
            tx_hash=item.get("transactionHash");decimals=token.get("decimals");raw_value=item.get("value")
            if not contract or not frm or not to or canonical_address("eth",address) not in {frm,to} or not canonical_hash(tx_hash):continue
            try:
                decimals=int(str(decimals))
                if not 0<=decimals<=36 or not isinstance(raw_value,str) or len(raw_value)>100 or not raw_value.isdecimal():continue
                units=int(raw_value)
                with localcontext() as ctx:
                    ctx.prec=max(100,len(raw_value)+decimals+2);exact=format(Decimal(units).scaleb(-decimals),"f")
                stamp=self._dt(item.get("timestamp"))
                if stamp is None:continue
                out.transactions.append(Transaction(chain="eth",tx_hash=tx_hash,timestamp=stamp,from_address=frm,to_address=to,
                    amount=float(exact),amount_decimal=exact,amount_base_units=units,decimals=decimals,
                    asset=str(token.get("symbol") or "ERC20"),direction=self._direction(address,frm,to),source=self.name,
                    url=f"https://etherscan.io/tx/{tx_hash}",raw={"provider":self.name,"provider_record":item,
                        "type":"erc20_transfer","asset_type":"erc20","token_contract":contract,"token_info":token,
                        "raw_value":raw_value,"decimals":decimals,"source_amount_unit":"token_base_units"}))
                coverage["retained_operations"]+=1
            except (ValueError,TypeError,OverflowError) as exc:out.errors.append(f"{self.name}: token_history_parse: {exc}")

    def _amount(self, value: str, decimals: int) -> float | None:
        try:
            number = int(str(value or "0"))
            return number / (10**max(decimals, 0))
        except Exception:
            try:
                return float(value)
            except Exception:
                return None

    def _dt(self, value: Any) -> datetime | None:
        try:
            return datetime.fromtimestamp(int(str(value)), tz=timezone.utc)
        except Exception:
            return None

    def _direction(self, address: str, frm: str, to: str) -> str:
        target = address.lower()
        from_key = (frm or "").lower()
        to_key = (to or "").lower()
        if from_key == target and to_key == target:
            return "self"
        if from_key == target:
            return "out"
        if to_key == target:
            return "in"
        return "unknown"
