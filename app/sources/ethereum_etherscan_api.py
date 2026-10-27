from __future__ import annotations

import os
import asyncio
from app.sources.pagination import pages
from datetime import datetime, timezone
from typing import Any

import httpx

from app.models.report import AddressReport, Balance, Label, SourceHealth, TokenHolding, Transaction
from app.sources.base import Source
from app.utils.http import shared_async_client


class EthereumEtherscanApiSource(Source):
    name = "etherscan_api"
    chain = "eth"

    def __init__(self, timeout_seconds: float, chain: str = "eth"):
        self._timeout = timeout_seconds
        networks = {"eth": ("1", "ETH", "https://etherscan.io"), "bsc": ("56", "BNB", "https://bscscan.com"), "polygon": ("137", "POL", "https://polygonscan.com"), "arbitrum": ("42161", "ETH", "https://arbiscan.io"), "optimism": ("10", "ETH", "https://optimistic.etherscan.io"), "avalanche": ("43114", "AVAX", "https://snowtrace.io")}
        self.chain = chain
        self._chain_id, self._native_asset, self._explorer = networks[chain]
        if chain != "eth":
            self.name = "etherscan_api_" + chain


    def _api_key(self) -> str:
        return (
            os.getenv("ETHERSCAN_API_KEY")
            or os.getenv("ETHERSCAN_KEY")
            or os.getenv("GANSAR_ETHERSCAN_API_KEY")
            or ""
        ).strip()

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=[self.chain], sources_used=[self.name])
        self._partial_report = out
        self._request_gate = asyncio.Semaphore(2)
        key = self._api_key()
        if not key:
            out.warnings.append(f"{self.name}: api key missing")
            out.source_health.append(
                SourceHealth(
                    source=self.name,
                    status="skipped",
                    timeout_seconds=min(self._timeout, 5.0),
                    retry_strategy="optional api key",
                    details="api key missing",
                )
            )
            return out

        async with shared_async_client(min(self._timeout, 10.0)) as client:
            await self._fetch_balance(client, address, key, out)
            loaders = (self._fetch_normal_txs(client, address, key, out), self._fetch_normal_txs(client, address, key, out, action="txlistinternal"), self._fetch_token_transfers(client, address, key, out, "tokentx", "erc20"), self._fetch_token_transfers(client, address, key, out, "tokennfttx", "erc721"), self._fetch_token_transfers(client, address, key, out, "token1155tx", "erc1155"), self._fetch_contract(client, address, key, out))
            if getattr(self, "_continuous", False):
                await asyncio.gather(*loaders)
            else:
                for loader in loaders:
                    await loader
        return out

    async def _request(self, client: httpx.AsyncClient, params: dict[str, Any], out: AddressReport) -> dict[str, Any] | None:
        url = "https://api.etherscan.io/v2/api"
        params = {"chainid": self._chain_id, **params}
        try:
            gate = getattr(self, "_request_gate", None)
            if gate is not None:
                async with gate:
                    r = await client.get(url, params=params)
            else:
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
        message = str(data.get("message") or "")
        result = data.get("result")
        if str(data.get("status")) == "0":
            detail = f"{message} {result}".strip()
            low = detail.lower()
            if "no transactions found" in low or "no records found" in low:
                data["result"] = []
                return data
            if "rate" in low or "max calls" in low:
                self._rate_limited(out, detail or "rate limited")
                return None
            out.errors.append(f"{self.name}: {detail or 'not ok'}")
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
                timeout_seconds=min(self._timeout, 5.0),
                retry_strategy="bounded request, fallback sources",
                details=detail,
            )
        )

    async def _fetch_balance(self, client: httpx.AsyncClient, address: str, key: str, out: AddressReport) -> None:
        data = await self._request(
            client,
            {"module": "account", "action": "balance", "address": address, "tag": "latest", "apikey": key},
            out,
        )
        if not data:
            return
        try:
            wei = int(str(data.get("result") or "0"))
            out.balances.append(
                Balance(
                    chain=self.chain,
                    address=address,
                    asset=self._native_asset,
                    amount=wei / 1e18,
                    source=self.name,
                    url=f"{self._explorer}/address/{address}",
                    raw={"wei": wei},
                )
            )
        except Exception as e:
            out.errors.append(f"{self.name}: balance_parse: {e}")

    async def _history_pages(self, client, address, key, out, action):
        async def fetch(cursor):
            return await self._request(client, {"module": "account", "action": action, "address": address, "startblock": "0", "endblock": str(cursor.get("anchor_block", "999999999")), "page": str(cursor.get("page", 1)), "offset": "100", "sort": "desc", "apikey": key}, out)
        def advance(data, items, cursor):
            anchor = cursor.get("anchor_block") or max((int(item.get("blockNumber") or 0) for item in items), default=0)
            return {"page": int(cursor.get("page", 1)) + 1, "anchor_block": anchor}
        async for data in pages(self, out, action, fetch, lambda data: data.get("result"), advance, page_size=100):
            yield data

    async def _fetch_normal_txs(self, client: httpx.AsyncClient, address: str, key: str, out: AddressReport, action: str = "txlist") -> None:
        async for data in self._history_pages(client, address, key, out, action):
            for item in self._items(data):
                try:
                    tx_hash = str(item.get("hash") or "")
                    frm = self._addr(item.get("from"))
                    to = self._addr(item.get("to"))
                    value = int(str(item.get("value") or "0")) / 1e18
                    gas_used = int(str(item.get("gasUsed") or item.get("gas") or "0"))
                    gas_price = int(str(item.get("gasPrice") or "0"))
                    raw = {
                        "block_number": item.get("blockNumber"),
                        "gas_used": gas_used,
                        "gas_price": gas_price,
                        "gas_fee_eth": (gas_used * gas_price) / 1e18 if gas_used and gas_price else None,
                        "method_id": item.get("methodId"),
                        "function_name": item.get("functionName"),
                        "input": item.get("input"),
                        "is_error": item.get("isError"),
                        "txreceipt_status": item.get("txreceipt_status"),
                        "contract_address": item.get("contractAddress"),
                        "provider_record": item,
                        "log_index": item.get("logIndex"),
                        "trace_id": item.get("traceId"),
                        "provider": self.name,
                        "type": "internal_transfer" if action == "txlistinternal" else "contract_call" if self._is_contract_call(item) else "transfer",
                    }
                    out.transactions.append(
                        Transaction(
                            chain=self.chain,
                            event_id=f"{self.chain}:trace:{tx_hash}:{item['traceId']}" if action == "txlistinternal" and item.get("traceId") is not None else None,
                            amount_base_units=int(str(item.get("value") or "0")), decimals=18,
                            tx_hash=tx_hash,
                            timestamp=self._dt(item.get("timeStamp")),
                            from_address=frm,
                            to_address=to,
                            amount=value if value else None,
                            asset=self._native_asset,
                            direction=self._direction(address, frm, to),
                            source=self.name,
                            url=f"{self._explorer}/tx/{tx_hash}" if tx_hash else None,
                            raw=raw,
                        )
                    )
                except Exception as e:
                    out.errors.append(f"{self.name}: tx_parse: {e}")

    async def _fetch_token_transfers(self, client: httpx.AsyncClient, address: str, key: str, out: AddressReport, action: str, asset_type: str) -> None:
        async for data in self._history_pages(client, address, key, out, action):
            seen_tokens: set[tuple[str, str]] = set()
            for item in self._items(data):
                try:
                    tx_hash = str(item.get("hash") or "")
                    frm = self._addr(item.get("from"))
                    to = self._addr(item.get("to"))
                    contract = self._addr(item.get("contractAddress"))
                    symbol = str(item.get("tokenSymbol") or asset_type.upper()).strip() or asset_type.upper()
                    name = str(item.get("tokenName") or "").strip() or None
                    token_id = str(item.get("tokenID") or item.get("tokenId") or "").strip()
                    decimals = int(str(item.get("tokenDecimal") or "0")) if asset_type == "erc20" else 0
                    raw_value = str(item.get("value") or item.get("tokenValue") or "0")
                    amount = self._token_amount(raw_value, decimals, asset_type)
                    nft_suffix = token_id or (contract[-6:] if contract else "unknown")
                    asset = symbol if asset_type == "erc20" else f"NFT:{symbol}:{nft_suffix}"
                    raw = {
                        "asset_type": asset_type,
                        "token_contract": contract,
                        "token_name": name,
                        "token_symbol": symbol,
                        "token_id": token_id,
                        "token_decimal": decimals,
                        "raw_value": raw_value,
                        "provider_record": item,
                        "log_index": item.get("logIndex"),
                        "trace_id": item.get("traceId"),
                        "provider": self.name,
                        "type": "nft_transfer" if asset_type in {"erc721", "erc1155"} else "token_transfer",
                    }
                    out.transactions.append(
                        Transaction(
                            chain=self.chain,
                            amount_base_units=int(raw_value), decimals=decimals,
                            tx_hash=tx_hash,
                            timestamp=self._dt(item.get("timeStamp")),
                            from_address=frm,
                            to_address=to,
                            amount=amount,
                            asset=asset,
                            direction=self._direction(address, frm, to),
                            source=self.name,
                            url=f"{self._explorer}/tx/{tx_hash}" if tx_hash else None,
                            raw=raw,
                        )
                    )
                    token_key = (asset_type, contract or symbol)
                    if token_key not in seen_tokens:
                        seen_tokens.add(token_key)
                        out.tokens.append(
                            TokenHolding(
                                chain=self.chain,
                                address=address,
                                contract=contract,
                                symbol=symbol,
                                name=name,
                                amount=None if asset_type != "erc20" else amount,
                                source=self.name,
                                url=f"{self._explorer}/token/{contract}?a={address}" if contract else f"{self._explorer}/address/{address}",
                                raw=raw,
                            )
                        )
                except Exception as e:
                    out.errors.append(f"{self.name}: {asset_type}_parse: {e}")

    async def _fetch_contract(self, client: httpx.AsyncClient, address: str, key: str, out: AddressReport) -> None:
        data = await self._request(
            client,
            {"module": "contract", "action": "getsourcecode", "address": address, "apikey": key},
            out,
        )
        if not data:
            return
        for item in self._items(data)[:1]:
            name = str(item.get("ContractName") or "").strip()
            abi = str(item.get("ABI") or "").strip()
            if name:
                out.labels.append(
                    Label(
                        chain=self.chain,
                        address=address,
                        label=f"Contract: {name}",
                        source=self.name,
                        confidence=0.82,
                        raw={"url": f"{self._explorer}/address/{address}", "contract_name": name},
                    )
                )
            if name or (abi and abi != "Contract source code not verified"):
                out.tokens.append(
                    TokenHolding(
                        chain=self.chain,
                        address=address,
                        contract=address,
                        symbol=None,
                        name=name or "Ethereum contract",
                        amount=None,
                        source=self.name,
                        url=f"{self._explorer}/address/{address}",
                        raw={"asset_type": "contract", "contract_name": name, "verified": bool(abi and abi != "Contract source code not verified"),
                             "proxy": item.get("Proxy"), "implementation": item.get("Implementation"),
                             "creator": item.get("ContractCreator")},
                    )
                )

    def _items(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        result = data.get("result")
        return [item for item in result if isinstance(item, dict)] if isinstance(result, list) else []

    def _dt(self, value: Any) -> datetime | None:
        try:
            return datetime.fromtimestamp(int(str(value)), tz=timezone.utc)
        except Exception:
            return None

    def _addr(self, value: Any) -> str:
        return str(value or "").strip()

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

    def _token_amount(self, raw_value: str, decimals: int, asset_type: str) -> float | None:
        try:
            value = int(str(raw_value or "0"))
        except Exception:
            return None
        if asset_type == "erc20":
            return value / (10**max(decimals, 0))
        if asset_type == "erc1155":
            return float(value)
        return 1.0

    def _is_contract_call(self, item: dict[str, Any]) -> bool:
        input_data = str(item.get("input") or "")
        function_name = str(item.get("functionName") or "")
        return bool(function_name or (input_data and input_data != "0x"))
