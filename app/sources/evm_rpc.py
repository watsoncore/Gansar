from __future__ import annotations

import httpx

from app.models.report import AddressReport, Balance, Chain, Label, RiskFlag
from app.sources.base import Source
from app.utils.http import create_async_client, request_json
from app.attribution.fingerprints import evm_code_fingerprint
from datetime import datetime, timezone


class EvmRpcBalanceSource(Source):
    name: str
    chain: Chain
    asset: str
    rpc_url: str
    explorer_url: str

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=[self.chain], sources_used=[self.name])
        try:
            async with create_async_client(self._timeout) as client:
                balance = await request_json(
                    client,
                    "POST",
                    self.rpc_url,
                    json={"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]},
                )
                nonce = await request_json(
                    client,
                    "POST",
                    self.rpc_url,
                    json={"jsonrpc": "2.0", "id": 2, "method": "eth_getTransactionCount", "params": [address, "latest"]},
                )
                code = await request_json(
                    client,
                    "POST",
                    self.rpc_url,
                    json={"jsonrpc": "2.0", "id": 3, "method": "eth_getCode", "params": [address, "latest"]},
                )
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: {e}")
            return out
        except Exception as e:
            out.errors.append(f"{self.name}: rpc: {e}")
            return out

        try:
            for name, payload in (("balance", balance), ("nonce", nonce), ("code", code)):
                if not isinstance(payload, dict) or payload.get("error") is not None or "result" not in payload or payload["result"] is None:
                    raise ValueError(f"JSON-RPC {name} returned error or missing result")
            wei = int((balance.get("result") or "0x0"), 16)
            tx_count = int((nonce.get("result") or "0x0"), 16)
            bytecode = str(code.get("result") or "0x")
            is_contract = bytecode not in {"", "0x", "0X"}
            out.balances.append(
                Balance(
                    chain=self.chain,
                    address=address,
                    asset=self.asset,
                    amount=wei / 1e18,
                    source=self.name,
                    url=f"{self.explorer_url}/address/{address}",
                        raw={"wei": wei, "tx_count": tx_count, "rpc": self.rpc_url, "is_contract": is_contract,
                             "contract_fingerprint": evm_code_fingerprint(bytecode),
                             "observed_at": datetime.now(timezone.utc).isoformat(),
                             "code_size": max(0, (len(bytecode) - 2) // 2)},
                )
            )
            if is_contract:
                out.labels.append(
                    Label(
                        chain=self.chain,
                        address=address,
                        label="Contract",
                        source=self.name,
                        confidence=0.7,
                        raw={"code_size": max(0, (len(bytecode) - 2) // 2), "url": f"{self.explorer_url}/address/{address}"},
                    )
                )
            if tx_count >= 5000:
                out.risk_flags.append(
                    RiskFlag(
                        chain=self.chain,
                        address=address,
                        flag="very_high_evm_nonce",
                        severity="low",
                        source=self.name,
                        details=f"Address nonce/activity count: {tx_count}",
                    )
                )
        except Exception as e:
            out.errors.append(f"{self.name}: balance_parse: {e}")
        return out


class EthereumRpcSource(EvmRpcBalanceSource):
    name = "ethereum_rpc"
    chain = "eth"
    asset = "ETH"
    rpc_url = "https://ethereum.publicnode.com"
    explorer_url = "https://etherscan.io"


class BscRpcSource(EvmRpcBalanceSource):
    name = "bsc_rpc"
    chain = "bsc"
    asset = "BNB"
    rpc_url = "https://bsc-dataseed.bnbchain.org"
    explorer_url = "https://bscscan.com"


class PolygonRpcSource(EvmRpcBalanceSource):
    name = "polygon_rpc"
    chain = "polygon"
    asset = "POL"
    rpc_url = "https://polygon.drpc.org"
    explorer_url = "https://polygonscan.com"


class ArbitrumRpcSource(EvmRpcBalanceSource):
    name = "arbitrum_rpc"
    chain = "arbitrum"
    asset = "ETH"
    rpc_url = "https://arb1.arbitrum.io/rpc"
    explorer_url = "https://arbiscan.io"


class OptimismRpcSource(EvmRpcBalanceSource):
    name = "optimism_rpc"
    chain = "optimism"
    asset = "ETH"
    rpc_url = "https://mainnet.optimism.io"
    explorer_url = "https://optimistic.etherscan.io"


class AvalancheRpcSource(EvmRpcBalanceSource):
    name = "avalanche_rpc"
    chain = "avalanche"
    asset = "AVAX"
    rpc_url = "https://api.avax.network/ext/bc/C/rpc"
    explorer_url = "https://snowtrace.io"
