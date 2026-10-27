from __future__ import annotations

import asyncio

from app.sources.pagination import pages

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx

from app.models.report import AddressReport, Balance, Label, RiskFlag, SourceHealth, TokenHolding, Transaction
from app.sources.base import Source
from app.utils.http import request_json, shared_async_client


BSC_RPC_URL = "https://bsc-rpc.publicnode.com"
BSC_EXPLORER = "https://bscscan.com"
BSC_CHAIN_ID = "56"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
APPROVAL_FOR_ALL_TOPIC = "0x17307eab39ab610e8899849849f1139a96f0c7eafda7f4ac0f45c5b8087a4e6c"
TRANSFER_SINGLE_TOPIC = "0xc3d58168c5ae7397731d063d5bbf3d2c8d1c6c3212f29722fcd1e4c1ff7b7c5"
TRANSFER_BATCH_TOPIC = "0x4a39dc06d4c0dbc64b70ffb5469fcb8146ac2d0e57cedbe7047f64f5a90b9d36"
MAX_UINT_HINT = (1 << 255)

STABLE_TOKENS = {
    "0x55d398326f99059ff775485246999027b3197955": {"symbol": "USDT", "name": "Tether USD", "decimals": 18},
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": {"symbol": "USDC", "name": "USD Coin", "decimals": 18},
    "0xe9e7cea3dedca5984780bafc599bd69add087d56": {"symbol": "BUSD", "name": "Binance Pegged BUSD", "decimals": 18},
    "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3": {"symbol": "DAI", "name": "Dai Token", "decimals": 18},
    "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409": {"symbol": "FDUSD", "name": "First Digital USD", "decimals": 18},
}

KNOWN_BSC_ENTITIES = {
    "0x10ed43c718714eb63d5aa57b78b54704e256024e": ("PancakeSwap V2 Router", "service"),
    "0x13f4ea83d0bd40e75c8222255bc855a974568dd4": ("PancakeSwap V3 Router", "service"),
    "0x1b81d678ffb9c0263b24a97847620c99d213eb14": ("PancakeSwap Smart Router", "service"),
    "0xca143ce32fe78f1f7019d7d551a6402fc5350c73": ("PancakeSwap V2 Factory", "service"),
    "0x0bfbcf9fa4f9c56b0f40a671ad40e0805a091865": ("PancakeSwap V3 Factory", "service"),
    "0x8894e0a0c962cb723c1976a4421c95949be2d4e3": ("Binance hot wallet", "exchange"),
}

METHOD_NAMES = {
    "0x095ea7b3": "approve",
    "0xa9059cbb": "transfer",
    "0x23b872dd": "transferFrom",
    "0xa22cb465": "setApprovalForAll",
    "0x38ed1739": "swapExactTokensForTokens",
    "0x7ff36ab5": "swapExactETHForTokens",
    "0x18cbafe5": "swapExactTokensForETH",
    "0xf305d719": "addLiquidityETH",
    "0xe8e33700": "addLiquidity",
    "0xbaa2abde": "removeLiquidity",
}


def _addr(value: Any) -> str:
    return str(value or "").strip()


def _key(value: str | None) -> str:
    return str(value or "").strip().lower()


def _topic_address(topic: str | None) -> str:
    text = str(topic or "")
    if len(text) >= 42:
        return "0x" + text[-40:]
    return ""


def _address_topic(address: str) -> str:
    return "0x" + ("0" * 24) + address.lower().removeprefix("0x")


def _int_hex(value: Any, default: int = 0) -> int:
    try:
        text = str(value or "")
        return int(text, 16) if text.startswith("0x") else int(text)
    except Exception:
        return default


def _dt_from_hex_timestamp(value: Any) -> datetime | None:
    number = _int_hex(value, -1)
    if number < 0:
        return None
    return datetime.fromtimestamp(number, tz=timezone.utc)


def _decimal_amount(raw_value: int | str | None, decimals: int | None) -> float | None:
    try:
        value = Decimal(str(raw_value or "0"))
        scale = Decimal(10) ** Decimal(max(int(decimals or 0), 0))
        return float(value / scale)
    except (InvalidOperation, ValueError, TypeError):
        return None


def _json_items(data: dict[str, Any] | None) -> list[dict[str, Any]]:
    result = (data or {}).get("result")
    return [item for item in result if isinstance(item, dict)] if isinstance(result, list) else []


def _first_image(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text.lower().startswith(("https://", "http://", "ipfs://", "data:image/")):
            return text
    return ""


class BscScanApiSource(Source):
    name = "bscscan_api"
    chain = "bsc"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds
        self._key_required = False

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["bsc"], sources_used=[self.name])
        self._partial_report = out
        self._request_gate = asyncio.Semaphore(2)
        async with shared_async_client(min(self._timeout, 10.0)) as client:
            balance_data = await self._request(client, {"module": "account", "action": "balance", "address": address, "tag": "latest"}, out)
            if self._key_required:
                out.bsc = {
                    "address": address,
                    "explorer_links": {"address": f"{BSC_EXPLORER}/address/{address}"},
                    "source_status": {"bscscan_api": "key_required"},
                    "warnings": ["bscscan_api: key_required"],
                    "partial": True,
                }
                return out
            if balance_data:
                self._parse_balance(balance_data, address, out)
            loaders = (self._fetch_txs(client, address, out, "txlist", "normal"), self._fetch_txs(client, address, out, "txlistinternal", "internal"), self._fetch_token_txs(client, address, out, "tokentx", "bep20"), self._fetch_token_txs(client, address, out, "tokennfttx", "bep721"), self._fetch_token_txs(client, address, out, "token1155tx", "bep1155"), self._fetch_contract(client, address, out))
            if getattr(self, "_continuous", False):
                await asyncio.gather(*loaders)
            else:
                for loader in loaders:
                    await loader
        return out

    async def _request(self, client: httpx.AsyncClient, params: dict[str, Any], out: AddressReport) -> dict[str, Any] | None:
        params = {"chainid": BSC_CHAIN_ID, **params}
        try:
            gate = getattr(self, "_request_gate", None)
            if gate is not None:
                async with gate:
                    data = await request_json(client, "GET", "https://api.etherscan.io/v2/api", params=params, retries=1)
            else:
                data = await request_json(client, "GET", "https://api.etherscan.io/v2/api", params=params, retries=1)
        except httpx.TimeoutException:
            out.errors.append(f"{self.name}: timeout")
            return None
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: {e}")
            return None
        except ValueError as e:
            out.errors.append(f"{self.name}: invalid response: {e}")
            return None
        detail = f"{data.get('message') or ''} {data.get('result') or ''}".strip()
        low = detail.lower()
        if str(data.get("status")) == "0":
            if "no transactions found" in low or "no records found" in low:
                data["result"] = []
                return data
            if "free api access is not supported" in low or "api key" in low or "upgrade your api plan" in low:
                self._key_required = True
                out.warnings.append(f"{self.name}: key_required")
                out.source_health.append(SourceHealth(source=self.name, status="skipped", timeout_seconds=self._timeout, retry_strategy="key_required", details="key_required"))
                return None
            if "rate" in low or "max calls" in low:
                out.warnings.append(f"{self.name}: rate_limited: {detail}")
                out.source_health.append(SourceHealth(source=self.name, status="rate_limited", timeout_seconds=self._timeout, retry_strategy="bounded request", details=detail))
                return None
            out.errors.append(f"{self.name}: {detail or 'not ok'}")
            return None
        return data

    def _parse_balance(self, data: dict[str, Any], address: str, out: AddressReport) -> None:
        try:
            wei = int(str(data.get("result") or "0"))
            out.balances.append(Balance(chain="bsc", address=address, asset="BNB", amount=wei / 1e18, source=self.name, url=f"{BSC_EXPLORER}/address/{address}", raw={"wei": wei}))
        except Exception as e:
            out.errors.append(f"{self.name}: balance_parse: {e}")

    async def _history_pages(self, client, address, out, action):
        async def fetch(cursor):
            return await self._request(client, {"module": "account", "action": action, "address": address, "startblock": "0", "endblock": str(cursor.get("anchor_block", "999999999")), "page": str(cursor.get("page", 1)), "offset": "100", "sort": "desc"}, out)
        def advance(data, items, cursor):
            return {"page": int(cursor.get("page", 1)) + 1, "anchor_block": cursor.get("anchor_block") or max((int(item.get("blockNumber") or 0) for item in items), default=0)}
        async for data in pages(self, out, action, fetch, lambda data: data.get("result"), advance, page_size=100):
            yield data

    async def _fetch_txs(self, client: httpx.AsyncClient, address: str, out: AddressReport, action: str, tx_type: str) -> None:
        async for data in self._history_pages(client, address, out, action):
            for item in _json_items(data):
                try:
                    tx_hash = str(item.get("hash") or "")
                    frm = _addr(item.get("from"))
                    to = _addr(item.get("to"))
                    value = int(str(item.get("value") or "0")) / 1e18
                    gas_used = int(str(item.get("gasUsed") or item.get("gas") or "0"))
                    gas_price = int(str(item.get("gasPrice") or "0"))
                    raw = {
                        "type": "internal_transfer" if tx_type == "internal" else "contract_call" if self._is_contract_call(item) else "transfer",
                        "block_number": item.get("blockNumber"),
                        "nonce": item.get("nonce"),
                        "gas_used": gas_used,
                        "gas_price": gas_price,
                        "fee": (gas_used * gas_price) / 1e18 if gas_used and gas_price else None,
                        "method_id": item.get("methodId"),
                        "function_name": item.get("functionName"),
                        "method": item.get("functionName") or METHOD_NAMES.get(str(item.get("methodId") or "").lower()),
                        "input": item.get("input"),
                        "is_error": item.get("isError"),
                        "txreceipt_status": item.get("txreceipt_status"),
                        "parent_tx_hash": item.get("hash") if tx_type == "internal" else None,
                        "trace_id": item.get("traceId"),
                        "provider": self.name, "provider_record": item, "log_index": item.get("logIndex"),
                    }
                    out.transactions.append(
                        Transaction(
                            chain="bsc",
                            event_id=f"bsc:trace:{tx_hash}:{item['traceId']}" if tx_type == "internal" and item.get("traceId") is not None else None,
                            amount_base_units=int(str(item.get("value") or "0")), decimals=18,
                            tx_hash=tx_hash,
                            timestamp=self._dt(item.get("timeStamp")),
                            from_address=frm,
                            to_address=to,
                            amount=value if value else None,
                            asset="BNB",
                            direction=self._direction(address, frm, to),
                            fee=raw["fee"],
                            source=self.name,
                            url=f"{BSC_EXPLORER}/tx/{tx_hash}" if tx_hash else None,
                            raw=raw,
                        )
                    )
                except Exception as e:
                    out.errors.append(f"{self.name}: {tx_type}_parse: {e}")

    async def _fetch_token_txs(self, client: httpx.AsyncClient, address: str, out: AddressReport, action: str, asset_type: str) -> None:
        async for data in self._history_pages(client, address, out, action):
            seen: set[tuple[str, str]] = set()
            for item in _json_items(data):
                try:
                    tx_hash = str(item.get("hash") or "")
                    frm = _addr(item.get("from"))
                    to = _addr(item.get("to"))
                    contract = _addr(item.get("contractAddress"))
                    symbol = str(item.get("tokenSymbol") or asset_type.upper()).strip() or asset_type.upper()
                    name = str(item.get("tokenName") or "").strip() or None
                    token_id = str(item.get("tokenID") or item.get("tokenId") or "").strip()
                    decimals = int(str(item.get("tokenDecimal") or "0")) if asset_type == "bep20" else 0
                    raw_value = str(item.get("value") or item.get("tokenValue") or "0")
                    amount = _decimal_amount(raw_value, decimals) if asset_type == "bep20" else float(raw_value or 1) if asset_type == "bep1155" else 1.0
                    nft_suffix = token_id or (contract[-6:] if contract else "unknown")
                    asset = symbol if asset_type == "bep20" else f"NFT:{symbol}:{nft_suffix}"
                    raw = {
                        "asset_type": asset_type,
                        "type": "nft_transfer" if asset_type in {"bep721", "bep1155"} else "bep20_transfer",
                        "token_contract": contract,
                        "token_name": name,
                        "token_symbol": symbol,
                        "token_id": token_id,
                        "decimals": decimals,
                        "raw_value": raw_value,
                        "provider": self.name, "provider_record": item, "log_index": item.get("logIndex"),
                    }
                    out.transactions.append(
                        Transaction(
                            chain="bsc",
                            amount_base_units=int(raw_value), decimals=decimals,
                            tx_hash=tx_hash,
                            timestamp=self._dt(item.get("timeStamp")),
                            from_address=frm,
                            to_address=to,
                            amount=amount,
                            asset=asset,
                            direction=self._direction(address, frm, to),
                            source=self.name,
                            url=f"{BSC_EXPLORER}/tx/{tx_hash}" if tx_hash else None,
                            raw=raw,
                        )
                    )
                    token_key = (asset_type, contract or symbol)
                    if token_key not in seen:
                        seen.add(token_key)
                        out.tokens.append(
                            TokenHolding(
                                chain="bsc",
                                address=address,
                                contract=contract,
                                symbol=symbol,
                                name=name,
                                amount=None if asset_type != "bep20" else amount,
                                source=self.name,
                                url=f"{BSC_EXPLORER}/token/{contract}?a={address}" if contract else f"{BSC_EXPLORER}/address/{address}",
                                raw=raw,
                            )
                        )
                except Exception as e:
                    out.errors.append(f"{self.name}: {asset_type}_parse: {e}")

    async def _fetch_contract(self, client: httpx.AsyncClient, address: str, out: AddressReport) -> None:
        data = await self._request(client, {"module": "contract", "action": "getsourcecode", "address": address}, out)
        if not data:
            return
        for item in _json_items(data)[:1]:
            name = str(item.get("ContractName") or "").strip()
            abi = str(item.get("ABI") or "").strip()
            verified = bool(abi and abi != "Contract source code not verified")
            raw = {
                "asset_type": "bsc_contract",
                "contract_name": name,
                "verified": verified,
                "compiler_version": item.get("CompilerVersion"),
                "proxy": item.get("Proxy"),
                "implementation": item.get("Implementation"),
                "creator": item.get("ContractCreator"),
                "creation_tx": item.get("TxHash"),
                "source_available": verified,
            }
            if name:
                out.labels.append(Label(chain="bsc", address=address, label=f"Contract: {name}", source=self.name, confidence=0.82, raw=raw))
            if name or verified:
                out.tokens.append(TokenHolding(chain="bsc", address=address, contract=address, name=name or "BNB Chain contract", amount=None, source=self.name, url=f"{BSC_EXPLORER}/address/{address}", raw=raw))

    def _dt(self, value: Any) -> datetime | None:
        try:
            return datetime.fromtimestamp(int(str(value)), tz=timezone.utc)
        except Exception:
            return None

    def _direction(self, address: str, frm: str, to: str) -> str:
        target = address.lower()
        if frm.lower() == target and to.lower() == target:
            return "self"
        if frm.lower() == target:
            return "out"
        if to.lower() == target:
            return "in"
        return "unknown"

    def _is_contract_call(self, item: dict[str, Any]) -> bool:
        input_data = str(item.get("input") or "")
        return bool(item.get("functionName") or (input_data and input_data != "0x"))


class BscIntelSource(Source):
    name = "bsc_intel"
    chain = "bsc"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds
        self._block_time_cache: dict[int, datetime | None] = {}
        self._token_cache: dict[str, dict[str, Any]] = {}
        self._kind_cache: dict[str, str] = {}

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["bsc"], sources_used=[self.name])
        bsc_data = {
            "address": address,
            "chain": "bsc",
            "explorer_links": {"address": f"{BSC_EXPLORER}/address/{address}"},
            "source_status": {},
            "security": [],
            "dex_pairs": [],
            "approvals": [],
            "stablecoins": [],
            "warnings": [],
            "partial": True,
        }
        async with shared_async_client(self._timeout) as client:
            latest_block = await self._latest_block(client, out)
            await self._rpc_overview(client, address, out, bsc_data)
            token_list = await self._pancakeswap_tokens(client, out, bsc_data)
            is_contract = bool(bsc_data.get("is_contract"))
            token_candidates = {} if is_contract else dict(STABLE_TOKENS)
            if _key(address) in token_list:
                token_candidates[_key(address)] = token_list[_key(address)]
            if _key(address) in STABLE_TOKENS:
                token_candidates[_key(address)] = STABLE_TOKENS[_key(address)]
            logs = await self._transfer_logs(client, address, latest_block, is_contract, out, bsc_data)
            token_contracts = self._contracts_from_logs(logs)
            for contract in token_contracts:
                token_candidates.setdefault(contract, token_list.get(contract, {}))
            if not is_contract:
                await self._token_balances(client, address, token_candidates, token_list, out, bsc_data)
            await self._parse_transfer_logs(client, address, logs, token_list, out, bsc_data)
            approval_logs = await self._approval_logs(client, address, latest_block, out, bsc_data)
            await self._parse_approval_logs(client, address, approval_logs, token_list, out, bsc_data)
            enrichment_contracts = self._enrichment_contracts(address, out, bsc_data)
            await self._goplus(client, enrichment_contracts, out, bsc_data)
            if is_contract:
                await self._honeypot(client, enrichment_contracts, out, bsc_data)
                await self._dexscreener(client, enrichment_contracts, token_list, out, bsc_data)
            else:
                bsc_data["source_status"]["honeypot"] = "skipped"
                bsc_data["source_status"]["dexscreener"] = "skipped"
        self._finalize_bsc_data(out, bsc_data)
        out.bsc = bsc_data
        return out

    async def _rpc(self, client: httpx.AsyncClient, method: str, params: list[Any]) -> Any:
        data = await request_json(client, "POST", BSC_RPC_URL, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, retries=1)
        if isinstance(data, dict) and data.get("error"):
            raise RuntimeError(str((data.get("error") or {}).get("message") or data.get("error")))
        return data.get("result") if isinstance(data, dict) else None

    async def _latest_block(self, client: httpx.AsyncClient, out: AddressReport) -> int | None:
        try:
            return _int_hex(await self._rpc(client, "eth_blockNumber", []), None)
        except Exception as e:
            out.warnings.append(f"{self.name}: latest_block unavailable: {e}")
            return None

    async def _rpc_overview(self, client: httpx.AsyncClient, address: str, out: AddressReport, bsc_data: dict[str, Any]) -> None:
        try:
            balance_hex = await self._rpc(client, "eth_getBalance", [address, "latest"])
            nonce_hex = await self._rpc(client, "eth_getTransactionCount", [address, "latest"])
            code = str(await self._rpc(client, "eth_getCode", [address, "latest"]) or "0x")
            wei = _int_hex(balance_hex)
            tx_count = _int_hex(nonce_hex)
            is_contract = code not in {"", "0x", "0X"}
            code_size = max(0, (len(code) - 2) // 2)
            out.balances.append(
                Balance(
                    chain="bsc",
                    address=address,
                    asset="BNB",
                    amount=wei / 1e18,
                    source=self.name,
                    url=f"{BSC_EXPLORER}/address/{address}",
                    raw={"wei": wei, "tx_count": tx_count, "is_contract": is_contract, "code_size": code_size, "rpc": BSC_RPC_URL},
                )
            )
            bsc_data.update({"balance": wei / 1e18, "balance_wei": wei, "tx_count": tx_count, "is_contract": is_contract, "code_size": code_size})
            if is_contract:
                out.labels.append(Label(chain="bsc", address=address, label="Contract", source=self.name, confidence=0.7, raw={"code_size": code_size, "url": f"{BSC_EXPLORER}/address/{address}"}))
            known = KNOWN_BSC_ENTITIES.get(_key(address))
            if known:
                out.labels.append(Label(chain="bsc", address=address, label=known[0], source="bsc_known_entities", confidence=0.78, raw={"category": known[1], "url": f"{BSC_EXPLORER}/address/{address}"}))
        except Exception as e:
            out.errors.append(f"{self.name}: rpc_overview: {e}")
            bsc_data["warnings"].append(f"rpc_overview: {e}")

    async def _pancakeswap_tokens(self, client: httpx.AsyncClient, out: AddressReport, bsc_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        try:
            data = await request_json(client, "GET", "https://tokens.pancakeswap.finance/pancakeswap-extended.json", retries=1)
            tokens = {}
            for item in data.get("tokens") or []:
                if isinstance(item, dict) and int(item.get("chainId") or 0) == 56 and item.get("address"):
                    tokens[_key(item.get("address"))] = item
            bsc_data["source_status"]["pancakeswap_token_list"] = "ok"
            return tokens
        except Exception as e:
            out.warnings.append(f"{self.name}: pancakeswap_token_list unavailable: {e}")
            bsc_data["source_status"]["pancakeswap_token_list"] = "unavailable"
            bsc_data["warnings"].append("pancakeswap_token_list unavailable")
            return {}

    async def _token_metadata(self, client: httpx.AsyncClient, contract: str, token_list: dict[str, dict[str, Any]]) -> dict[str, Any]:
        key = _key(contract)
        if key in self._token_cache:
            return self._token_cache[key]
        base = dict(token_list.get(key) or STABLE_TOKENS.get(key) or {})
        base.setdefault("address", contract)
        for name, selector in (("symbol", "0x95d89b41"), ("name", "0x06fdde03"), ("decimals", "0x313ce567")):
            if base.get(name) not in (None, ""):
                continue
            value = await self._safe_eth_call(client, contract, selector)
            decoded = self._decode_call_value(value, name)
            if decoded not in (None, ""):
                base[name] = decoded
        if "decimals" in base:
            try:
                base["decimals"] = int(base["decimals"])
            except Exception:
                base["decimals"] = 0
        base["asset_type"] = await self._contract_kind(client, contract, base)
        self._token_cache[key] = base
        return base

    async def _contract_kind(self, client: httpx.AsyncClient, contract: str, metadata: dict[str, Any]) -> str:
        key = _key(contract)
        if key in self._kind_cache:
            return self._kind_cache[key]
        if key in STABLE_TOKENS:
            self._kind_cache[key] = "bep20"
            return "bep20"
        erc721 = await self._supports_interface(client, contract, "80ac58cd")
        if erc721:
            self._kind_cache[key] = "bep721"
            return "bep721"
        erc1155 = await self._supports_interface(client, contract, "d9b67a26")
        if erc1155:
            self._kind_cache[key] = "bep1155"
            return "bep1155"
        self._kind_cache[key] = "bep20" if metadata.get("decimals") is not None else "bsc_contract"
        return self._kind_cache[key]

    async def _safe_eth_call(self, client: httpx.AsyncClient, to: str, data: str) -> str:
        try:
            return str(await self._rpc(client, "eth_call", [{"to": to, "data": data}, "latest"]) or "")
        except Exception:
            return ""

    async def _supports_interface(self, client: httpx.AsyncClient, contract: str, interface_id: str) -> bool:
        data = "0x01ffc9a7" + ("0" * 56) + interface_id
        value = await self._safe_eth_call(client, contract, data)
        return value.lower().endswith("1")

    def _decode_call_value(self, value: str, kind: str) -> Any:
        text = str(value or "")
        if not text.startswith("0x") or text in {"0x", "0x0"}:
            return None
        if kind == "decimals":
            return _int_hex(text)
        raw = bytes.fromhex(text[2:])
        try:
            if len(raw) >= 96:
                offset = int.from_bytes(raw[:32], "big")
                length = int.from_bytes(raw[offset:offset + 32], "big")
                return raw[offset + 32:offset + 32 + length].decode("utf-8", errors="ignore").strip("\x00 ")
            return raw.rstrip(b"\x00").decode("utf-8", errors="ignore").strip("\x00 ")
        except Exception:
            return None

    async def _token_balance(self, client: httpx.AsyncClient, contract: str, address: str) -> int | None:
        data = "0x70a08231" + ("0" * 24) + address.lower().removeprefix("0x")
        value = await self._safe_eth_call(client, contract, data)
        if not value:
            return None
        return _int_hex(value)

    async def _token_balances(self, client: httpx.AsyncClient, address: str, candidates: dict[str, dict[str, Any]], token_list: dict[str, dict[str, Any]], out: AddressReport, bsc_data: dict[str, Any]) -> None:
        seen = set()
        for contract in list(candidates)[:90]:
            if contract in seen:
                continue
            seen.add(contract)
            metadata = await self._token_metadata(client, contract, token_list)
            raw_balance = await self._token_balance(client, contract, address)
            if raw_balance in (None, 0):
                continue
            asset_type = str(metadata.get("asset_type") or "bep20")
            decimals = int(metadata.get("decimals") or 0)
            amount = _decimal_amount(raw_balance, decimals) if asset_type == "bep20" else float(raw_balance)
            raw = {
                "asset_type": asset_type,
                "token_contract": metadata.get("address") or contract,
                "token_symbol": metadata.get("symbol"),
                "token_name": metadata.get("name"),
                "decimals": decimals,
                "raw_value": str(raw_balance),
                "logoURI": metadata.get("logoURI"),
                "image": metadata.get("image") or metadata.get("logoURI"),
                "source_list": "pancakeswap" if contract in token_list else "stablecoin_probe",
            }
            out.tokens.append(
                TokenHolding(
                    chain="bsc",
                    address=address,
                    contract=metadata.get("address") or contract,
                    symbol=metadata.get("symbol"),
                    name=metadata.get("name"),
                    amount=amount,
                    source=self.name,
                    url=f"{BSC_EXPLORER}/token/{metadata.get('address') or contract}?a={address}",
                    raw=raw,
                )
            )
            if (metadata.get("symbol") or "").upper() in {"USDT", "USDC", "BUSD", "DAI", "FDUSD"}:
                bsc_data["stablecoins"].append({"symbol": metadata.get("symbol"), "contract": metadata.get("address") or contract, "balance": amount})

    async def _transfer_logs(self, client: httpx.AsyncClient, address: str, latest_block: int | None, is_contract: bool, out: AddressReport, bsc_data: dict[str, Any]) -> list[dict[str, Any]]:
        if latest_block is None:
            return []
        if is_contract:
            logs = await self._logs(client, max(0, latest_block - 100), latest_block, [TRANSFER_TOPIC], address=address, cap=70)
        else:
            target_topic = _address_topic(address)
            logs = []
            stable_logs = []
            for contract in STABLE_TOKENS:
                stable_logs.extend(await self._logs(client, max(0, latest_block - 1000), latest_block, [TRANSFER_TOPIC, None, target_topic], address=contract, cap=6))
                stable_logs.extend(await self._logs(client, max(0, latest_block - 1000), latest_block, [TRANSFER_TOPIC, target_topic], address=contract, cap=6))
            logs.extend(stable_logs)
        if not logs:
            bsc_data["warnings"].append("recent transfer logs unavailable or empty")
        return sorted({(item.get("transactionHash"), item.get("logIndex")): item for item in logs}.values(), key=lambda item: _int_hex(item.get("blockNumber")), reverse=True)[:120]

    async def _approval_logs(self, client: httpx.AsyncClient, address: str, latest_block: int | None, out: AddressReport, bsc_data: dict[str, Any]) -> list[dict[str, Any]]:
        if latest_block is None:
            return []
        if bsc_data.get("is_contract"):
            return []
        target_topic = _address_topic(address)
        logs = []
        for contract in list(STABLE_TOKENS)[:3]:
            logs.extend(await self._logs(client, max(0, latest_block - 100), latest_block, [APPROVAL_TOPIC, target_topic], address=contract, cap=4))
        return sorted({(item.get("transactionHash"), item.get("logIndex")): item for item in logs}.values(), key=lambda item: _int_hex(item.get("blockNumber")), reverse=True)[:60]

    async def _logs(self, client: httpx.AsyncClient, start: int, end: int, topics: list[Any], address: str | None = None, cap: int = 80) -> list[dict[str, Any]]:
        logs: list[dict[str, Any]] = []
        cursor = end
        chunk = min(5000, max(500, end - start + 1))
        while cursor >= start and len(logs) < cap:
            left = max(start, cursor - chunk + 1)
            params = {"fromBlock": hex(left), "toBlock": hex(cursor), "topics": topics}
            if address:
                params["address"] = address
            try:
                result = await self._rpc(client, "eth_getLogs", [params])
                if isinstance(result, list):
                    logs.extend([item for item in result if isinstance(item, dict)])
            except Exception:
                if chunk > 500:
                    chunk = max(500, chunk // 2)
                    continue
                break
            cursor = left - 1
        return logs[:cap]

    def _contracts_from_logs(self, logs: list[dict[str, Any]]) -> set[str]:
        return {_key(item.get("address")) for item in logs if item.get("address")}

    async def _block_time(self, client: httpx.AsyncClient, block_number: int) -> datetime | None:
        if block_number in self._block_time_cache:
            return self._block_time_cache[block_number]
        try:
            data = await self._rpc(client, "eth_getBlockByNumber", [hex(block_number), False])
            stamp = _dt_from_hex_timestamp((data or {}).get("timestamp") if isinstance(data, dict) else None)
            self._block_time_cache[block_number] = stamp
            return stamp
        except Exception:
            self._block_time_cache[block_number] = None
            return None

    async def _parse_transfer_logs(self, client: httpx.AsyncClient, address: str, logs: list[dict[str, Any]], token_list: dict[str, dict[str, Any]], out: AddressReport, bsc_data: dict[str, Any]) -> None:
        target = _key(address)
        bep20_count = 0
        nft_count = 0
        for item in logs[:120]:
            topics = item.get("topics") or []
            if len(topics) < 3:
                continue
            contract = _addr(item.get("address"))
            metadata = await self._token_metadata(client, contract, token_list)
            asset_type = str(metadata.get("asset_type") or "bep20")
            frm = _topic_address(topics[1])
            to = _topic_address(topics[2])
            raw_value = _int_hex(item.get("data"))
            token_id = str(raw_value) if asset_type in {"bep721", "bep1155"} else ""
            amount = 1.0 if asset_type == "bep721" else _decimal_amount(raw_value, int(metadata.get("decimals") or 0))
            symbol = str(metadata.get("symbol") or ("NFT" if asset_type in {"bep721", "bep1155"} else "BEP20"))
            asset = symbol if asset_type == "bep20" else f"NFT:{symbol}:{token_id or contract[-6:]}"
            direction = "out" if _key(frm) == target else "in" if _key(to) == target else "unknown"
            block_number = _int_hex(item.get("blockNumber"))
            timestamp = await self._block_time(client, block_number)
            raw = {
                "type": "nft_transfer" if asset_type in {"bep721", "bep1155"} else "bep20_transfer",
                "asset_type": asset_type,
                "token_contract": contract,
                "token_symbol": metadata.get("symbol"),
                "token_name": metadata.get("name"),
                "token_id": token_id,
                "decimals": int(metadata.get("decimals") or 0),
                "raw_value": str(raw_value),
                "block_number": block_number,
                "log_index": _int_hex(item.get("logIndex")),
                "logoURI": metadata.get("logoURI"),
                "image": metadata.get("image") or metadata.get("logoURI"),
                "provider": self.name,
            }
            tx_hash = _addr(item.get("transactionHash"))
            out.transactions.append(
                Transaction(
                    chain="bsc",
                    tx_hash=tx_hash,
                    timestamp=timestamp,
                    from_address=frm,
                    to_address=to,
                    amount=amount,
                    asset=asset,
                    direction=direction,
                    source=self.name,
                    url=f"{BSC_EXPLORER}/tx/{tx_hash}" if tx_hash else None,
                    raw=raw,
                )
            )
            if asset_type == "bep20":
                bep20_count += 1
            else:
                nft_count += 1
                out.tokens.append(
                    TokenHolding(
                        chain="bsc",
                        address=address,
                        contract=contract,
                        symbol=metadata.get("symbol"),
                        name=metadata.get("name"),
                        amount=None,
                        source=self.name,
                        url=f"{BSC_EXPLORER}/token/{contract}?a={address}",
                        raw=raw,
                    )
                )
        bsc_data["bep20_transfers_count"] = bep20_count
        bsc_data["nft_transfers_count"] = nft_count

    async def _parse_approval_logs(self, client: httpx.AsyncClient, address: str, logs: list[dict[str, Any]], token_list: dict[str, dict[str, Any]], out: AddressReport, bsc_data: dict[str, Any]) -> None:
        target = _key(address)
        for item in logs[:60]:
            topics = item.get("topics") or []
            if len(topics) < 3:
                continue
            topic0 = str(topics[0]).lower()
            contract = _addr(item.get("address"))
            metadata = await self._token_metadata(client, contract, token_list)
            owner = _topic_address(topics[1])
            spender = _topic_address(topics[2])
            if _key(owner) != target:
                continue
            raw_value = _int_hex(item.get("data"))
            method = "setApprovalForAll" if topic0 == APPROVAL_FOR_ALL_TOPIC else "approve"
            unlimited = raw_value >= MAX_UINT_HINT or (method == "setApprovalForAll" and raw_value == 1)
            block_number = _int_hex(item.get("blockNumber"))
            timestamp = await self._block_time(client, block_number)
            tx_hash = _addr(item.get("transactionHash"))
            symbol = metadata.get("symbol") or "BEP20"
            amount = None if method == "setApprovalForAll" else _decimal_amount(raw_value, int(metadata.get("decimals") or 0))
            raw = {
                "type": "approval",
                "asset_type": metadata.get("asset_type") or "bep20",
                "token_contract": contract,
                "spender": spender,
                "owner": owner,
                "method": method,
                "method_id": "0xa22cb465" if method == "setApprovalForAll" else "0x095ea7b3",
                "raw_value": str(raw_value),
                "unlimited": unlimited,
                "block_number": block_number,
                "log_index": _int_hex(item.get("logIndex")),
                "provider": self.name,
            }
            out.transactions.append(
                Transaction(
                    chain="bsc",
                    tx_hash=tx_hash,
                    timestamp=timestamp,
                    from_address=owner,
                    to_address=spender,
                    amount=amount,
                    asset=symbol,
                    direction="out",
                    source=self.name,
                    url=f"{BSC_EXPLORER}/tx/{tx_hash}" if tx_hash else None,
                    raw=raw,
                )
            )
            approval = {"spender": spender, "token": contract, "symbol": symbol, "method": method, "unlimited": unlimited, "tx": tx_hash, "source": self.name}
            bsc_data["approvals"].append(approval)
            if unlimited:
                out.risk_flags.append(
                    RiskFlag(
                        chain="bsc",
                        address=spender,
                        flag="possible_unlimited_approval",
                        severity="medium",
                        source=self.name,
                        details=f"risk hint: unlimited approval to {spender} for {symbol}",
                        raw=approval,
                    )
                )
        bsc_data["approvals_count"] = len(bsc_data["approvals"])

    def _enrichment_contracts(self, address: str, out: AddressReport, bsc_data: dict[str, Any]) -> list[str]:
        contracts = []
        if bsc_data.get("is_contract"):
            contracts.append(address)
        for token in out.tokens:
            if token.chain == "bsc" and token.contract:
                contracts.append(token.contract)
        for item in bsc_data.get("stablecoins") or []:
            if item.get("contract"):
                contracts.append(item["contract"])
        limit = 5 if bsc_data.get("is_contract") else 3
        return list(dict.fromkeys(_key(item) for item in contracts if item))[:limit]

    async def _goplus(self, client: httpx.AsyncClient, contracts: list[str], out: AddressReport, bsc_data: dict[str, Any]) -> None:
        if not contracts:
            bsc_data["source_status"]["goplus"] = "skipped"
            return
        try:
            data = await request_json(client, "GET", f"https://api.gopluslabs.io/api/v1/token_security/{BSC_CHAIN_ID}", params={"contract_addresses": ",".join(contracts[:5])}, retries=1)
            result = data.get("result") or {}
            if not isinstance(result, dict) or not result:
                bsc_data["source_status"]["goplus"] = "unavailable"
                return
            bsc_data["source_status"]["goplus"] = "ok"
            for contract, item in result.items():
                if not isinstance(item, dict):
                    continue
                contract_key = _key(contract)
                symbol = item.get("token_symbol")
                name = item.get("token_name")
                raw = {"asset_type": "bep20", "token_contract": contract, "token_symbol": symbol, "token_name": name, "goplus": item}
                out.tokens.append(TokenHolding(chain="bsc", address=out.target_address, contract=contract, symbol=symbol, name=name, amount=None, source=self.name, url=f"{BSC_EXPLORER}/token/{contract}", raw=raw))
                bsc_data["security"].append(self._security_row("goplus", contract, item))
                owner = item.get("owner_address")
                creator = item.get("creator_address")
                if owner:
                    out.labels.append(Label(chain="bsc", address=owner, label=f"Token owner: {symbol or contract_key[:10]}", source="goplus", confidence=0.54, raw={"token": contract}))
                if creator:
                    out.labels.append(Label(chain="bsc", address=creator, label=f"Token creator: {symbol or contract_key[:10]}", source="goplus", confidence=0.54, raw={"token": contract}))
                self._goplus_risks(contract, item, out)
                if contract_key == _key(out.target_address):
                    bsc_data["contract_name"] = name or bsc_data.get("contract_name")
                    bsc_data["token_symbol"] = symbol or bsc_data.get("token_symbol")
                    bsc_data["verified"] = item.get("is_open_source") == "1"
                    bsc_data["creator"] = creator
                    bsc_data["owner"] = owner
                    bsc_data["holder_count"] = item.get("holder_count")
        except Exception as e:
            out.warnings.append(f"{self.name}: goplus unavailable: {e}")
            bsc_data["source_status"]["goplus"] = "unavailable"

    def _security_row(self, source: str, contract: str, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "source": source,
            "contract": contract,
            "honeypot": item.get("is_honeypot"),
            "buy_tax": item.get("buy_tax"),
            "sell_tax": item.get("sell_tax"),
            "transfer_tax": item.get("transfer_tax"),
            "blacklist": item.get("is_blacklisted"),
            "whitelist": item.get("is_whitelisted"),
            "mintable": item.get("is_mintable"),
            "proxy": item.get("is_proxy"),
            "owner": item.get("owner_address"),
            "creator": item.get("creator_address"),
            "holder_count": item.get("holder_count"),
        }

    def _goplus_risks(self, contract: str, item: dict[str, Any], out: AddressReport) -> None:
        checks = [
            ("is_honeypot", "honeypot_confirmed", "high", "honeypot status confirmed by GoPlus"),
            ("cannot_buy", "cannot_buy", "high", "risk hint: token cannot be bought"),
            ("is_blacklisted", "blacklist_function_or_state", "medium", "risk hint: blacklist related flag"),
            ("is_whitelisted", "whitelist_function_or_state", "medium", "risk hint: whitelist related flag"),
            ("hidden_owner", "hidden_owner_risk", "medium", "risk hint: hidden owner flag"),
            ("is_mintable", "mintable_token", "medium", "risk hint: mint function available"),
            ("transfer_pausable", "pausable_transfer", "medium", "risk hint: transfers can be paused"),
            ("slippage_modifiable", "tax_modifiable", "medium", "risk hint: tax/slippage can be modified"),
            ("is_proxy", "proxy_contract", "low", "proxy contract"),
        ]
        for field, flag, severity, details in checks:
            if str(item.get(field)) == "1":
                out.risk_flags.append(RiskFlag(chain="bsc", address=contract, flag=flag, severity=severity, source="goplus", details=details, raw={"field": field, "value": item.get(field)}))
        for field, label in (("buy_tax", "buy tax"), ("sell_tax", "sell tax"), ("transfer_tax", "transfer tax")):
            try:
                value = float(item.get(field) or 0)
            except Exception:
                continue
            if value >= 20:
                out.risk_flags.append(RiskFlag(chain="bsc", address=contract, flag=f"high_{field}", severity="high", source="goplus", details=f"risk hint: {label} {value}", raw={"field": field, "value": value}))
            elif value >= 5:
                out.risk_flags.append(RiskFlag(chain="bsc", address=contract, flag=f"elevated_{field}", severity="medium", source="goplus", details=f"risk hint: {label} {value}", raw={"field": field, "value": value}))

    async def _honeypot(self, client: httpx.AsyncClient, contracts: list[str], out: AddressReport, bsc_data: dict[str, Any]) -> None:
        if not contracts:
            bsc_data["source_status"]["honeypot"] = "skipped"
            return
        ok = False
        for contract in contracts[:3]:
            try:
                data = await request_json(client, "GET", "https://api.honeypot.is/v2/IsHoneypot", params={"address": contract, "chainID": BSC_CHAIN_ID}, retries=1)
                ok = True
                row = {"source": "honeypot.is", "contract": contract, "summary": data.get("summary"), "honeypotResult": data.get("honeypotResult"), "simulationResult": data.get("simulationResult"), "pair": data.get("pair"), "router": data.get("router")}
                bsc_data["security"].append(row)
                result = data.get("honeypotResult") or {}
                simulation = data.get("simulationResult") or {}
                if result.get("isHoneypot") is True:
                    out.risk_flags.append(RiskFlag(chain="bsc", address=contract, flag="honeypot_confirmed", severity="high", source="honeypot.is", details="honeypot status confirmed by Honeypot.is simulation", raw=row))
                for field in ("buyTax", "sellTax", "transferTax"):
                    try:
                        value = float(simulation.get(field) or 0)
                    except Exception:
                        continue
                    if value >= 20:
                        out.risk_flags.append(RiskFlag(chain="bsc", address=contract, flag=f"high_{field.lower()}", severity="high", source="honeypot.is", details=f"risk hint: {field} {value}", raw=row))
                    elif value >= 5:
                        out.risk_flags.append(RiskFlag(chain="bsc", address=contract, flag=f"elevated_{field.lower()}", severity="medium", source="honeypot.is", details=f"risk hint: {field} {value}", raw=row))
                pair = data.get("pair") or {}
                pair_data = pair.get("pair") if isinstance(pair.get("pair"), dict) else pair
                if isinstance(pair_data, dict) and pair_data.get("address"):
                    bsc_data["dex_pairs"].append(self._honeypot_pair_row(pair_data, data))
            except Exception as e:
                out.warnings.append(f"{self.name}: honeypot unavailable for {contract}: {e}")
        bsc_data["source_status"]["honeypot"] = "ok" if ok else "unavailable"

    def _honeypot_pair_row(self, pair: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
        return {
            "source": "honeypot.is",
            "dex": pair.get("name") or pair.get("type") or "DEX",
            "pair_address": pair.get("address") or data.get("pairAddress"),
            "url": f"{BSC_EXPLORER}/address/{pair.get('address')}" if pair.get("address") else "",
            "liquidity_usd": (data.get("pair") or {}).get("liquidity"),
            "base": pair.get("token0"),
            "quote": pair.get("token1"),
            "created_at": pair.get("createdAtTimestamp"),
        }

    async def _dexscreener(self, client: httpx.AsyncClient, contracts: list[str], token_list: dict[str, dict[str, Any]], out: AddressReport, bsc_data: dict[str, Any]) -> None:
        if not contracts:
            bsc_data["source_status"]["dexscreener"] = "skipped"
            return
        ok = False
        for contract in contracts[:3]:
            try:
                data = await request_json(client, "GET", f"https://api.dexscreener.com/latest/dex/tokens/{contract}", retries=1)
                pairs = [item for item in (data.get("pairs") or []) if isinstance(item, dict) and str(item.get("chainId") or "").lower() == "bsc"]
                if not pairs:
                    continue
                ok = True
                pairs.sort(key=lambda item: float(((item.get("liquidity") or {}).get("usd") or 0)), reverse=True)
                for pair in pairs[:8]:
                    row = self._dex_pair_row(pair)
                    bsc_data["dex_pairs"].append(row)
                    pair_address = row.get("pair_address")
                    raw = {"asset_type": "dex_pair", "dex": row.get("dex"), "pair": row, "image": _first_image((pair.get("info") or {}).get("imageUrl"), (pair.get("info") or {}).get("openGraph"))}
                    out.tokens.append(
                        TokenHolding(
                            chain="bsc",
                            address=out.target_address,
                            contract=pair_address,
                            symbol=row.get("symbol"),
                            name=row.get("name"),
                            amount=row.get("liquidity_usd"),
                            source=self.name,
                            url=row.get("url") or f"{BSC_EXPLORER}/address/{pair_address}" if pair_address else None,
                            raw=raw,
                        )
                    )
                    if pair_address:
                        out.labels.append(Label(chain="bsc", address=pair_address, label=f"{row.get('dex') or 'DEX'} pair", source="dexscreener", confidence=0.7, raw=row))
                info = pairs[0].get("info") or {}
                image = _first_image(info.get("imageUrl"), info.get("openGraph"))
                if image:
                    for token in out.tokens:
                        if token.chain == "bsc" and _key(token.contract) == _key(contract):
                            token.raw.setdefault("image", image)
            except Exception as e:
                out.warnings.append(f"{self.name}: dexscreener unavailable for {contract}: {e}")
        bsc_data["source_status"]["dexscreener"] = "ok" if ok else "unavailable"

    def _dex_pair_row(self, pair: dict[str, Any]) -> dict[str, Any]:
        base = pair.get("baseToken") or {}
        quote = pair.get("quoteToken") or {}
        txns = pair.get("txns") or {}
        h24 = txns.get("h24") or {}
        liquidity = pair.get("liquidity") or {}
        symbol = f"{base.get('symbol') or '?'} / {quote.get('symbol') or '?'}"
        return {
            "source": "dexscreener",
            "dex": pair.get("dexId"),
            "pair_address": pair.get("pairAddress"),
            "symbol": symbol,
            "name": f"{pair.get('dexId') or 'DEX'} {symbol}",
            "url": pair.get("url"),
            "price_usd": pair.get("priceUsd"),
            "liquidity_usd": liquidity.get("usd"),
            "volume_24h": (pair.get("volume") or {}).get("h24"),
            "fdv": pair.get("fdv"),
            "market_cap": pair.get("marketCap"),
            "buy_count_24h": h24.get("buys"),
            "sell_count_24h": h24.get("sells"),
            "base": base,
            "quote": quote,
            "pair_created_at": pair.get("pairCreatedAt"),
        }

    def _finalize_bsc_data(self, out: AddressReport, bsc_data: dict[str, Any]) -> None:
        bsc_txs = [tx for tx in out.transactions if tx.chain == "bsc"]
        times = [tx.timestamp for tx in bsc_txs if tx.timestamp]
        bsc_data["first_seen"] = min(times) if times else None
        bsc_data["last_seen"] = max(times) if times else None
        bsc_data["transactions_sample_count"] = len(bsc_txs)
        bsc_data["normal_transactions_count"] = bsc_data.get("normal_transactions_count")
        bsc_data["internal_transactions_count"] = bsc_data.get("internal_transactions_count")
        bsc_data["tokens_count"] = len([token for token in out.tokens if token.chain == "bsc"])
        bsc_data["risk_count"] = len([flag for flag in out.risk_flags if flag.chain == "bsc"])
        bsc_data["warnings"] = list(dict.fromkeys(bsc_data.get("warnings") or []))[:16]
        if not bsc_data.get("source_status"):
            bsc_data["source_status"] = {"bsc_intel": "partial"}
        out.source_health.append(SourceHealth(source=self.name, status="partial" if bsc_data["warnings"] else "ok", timeout_seconds=self._timeout, retry_strategy="bounded RPC logs and public enrichers", details="partial BSC investigation layer"))
