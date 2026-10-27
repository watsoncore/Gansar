from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from app.models.report import AddressReport, Balance, SourceHealth, TokenHolding, Transaction
from app.sources.base import Source
from app.utils.http import create_async_client, json_list, json_object

logger = logging.getLogger(__name__)


class EthereumBlockchairSource(Source):
    name = "blockchair_ethereum"
    chain = "eth"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["eth"], sources_used=[self.name])
        addr_key = address.lower()
        url = f"https://api.blockchair.com/ethereum/dashboards/address/{addr_key}"
        params = {"limit": 50}
        try:
            async with create_async_client(self._timeout) as client:
                r = await client.get(url, params=params)
                if r.status_code == 429:
                    out.warnings.append(f"{self.name}: rate_limited: http 429")
                    out.source_health.append(
                        SourceHealth(source=self.name, status="rate_limited", timeout_seconds=min(self._timeout, 4.0), retry_strategy="bounded request, fallback sources", details="http 429")
                    )
                    return out
                r.raise_for_status()
                data = json_object(r.json())
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: {e}")
            return out

        try:
            a = data["data"][addr_key]["address"]
            balance_wei = float(a.get("balance", 0))
            out.balances.append(
                Balance(
                    chain="eth",
                    address=address,
                    asset="ETH",
                    amount=balance_wei / 1e18,
                    source=self.name,
                    url=url,
                    raw={"balance_wei": a.get("balance")},
                )
            )
        except Exception as e:
            out.errors.append(f"{self.name}: balance_parse: {e}")

        calls = []
        try:
            calls = json_list(data["data"][addr_key].get("calls"))[:50]
        except Exception:
            calls = []

        seen_contracts: set[str] = set()
        for c in calls[:50]:
            try:
                h = c.get("transaction_hash")
                ts = c.get("time")
                dt = None
                if ts:
                    dt = datetime.fromisoformat(str(ts)).replace(tzinfo=timezone.utc)
                frm = c.get("sender")
                to = c.get("recipient")
                value = float(c.get("value", 0)) / 1e18
                direction = "unknown"
                if isinstance(frm, str) and frm.lower() == address.lower() and isinstance(to, str) and to.lower() == address.lower():
                    direction = "self"
                elif isinstance(frm, str) and frm.lower() == address.lower():
                    direction = "out"
                elif isinstance(to, str) and to.lower() == address.lower():
                    direction = "in"
                out.transactions.append(
                    Transaction(
                        chain="eth",
                        tx_hash=str(h),
                        timestamp=dt,
                        from_address=frm,
                        to_address=to,
                        amount=value if value != 0 else None,
                        asset="ETH",
                        direction=direction,
                        source=self.name,
                        url=f"https://etherscan.io/tx/{h}" if h else None,
                        raw={
                            "block_id": c.get("block_id"),
                            "index": c.get("index"),
                            "method": c.get("method"),
                            "gas_used": c.get("gas_used"),
                            "fee": c.get("fee"),
                            "provider": self.name,
                            "type": "contract_call" if c.get("method") or value == 0 else "transfer",
                        },
                    )
                )
                if isinstance(to, str) and to.lower() != address.lower() and to.startswith("0x") and c.get("transferred") and value == 0:
                    if to not in seen_contracts:
                        seen_contracts.add(to)
                        out.tokens.append(
                            TokenHolding(
                                chain="eth",
                                address=address,
                                contract=to,
                                symbol=None,
                                name=None,
                                amount=None,
                                source=self.name,
                                url=None,
                                raw={"hint": "contract_interaction_from_blockchair_calls"},
                            )
                        )
            except Exception as e:
                out.errors.append(f"{self.name}: call_parse: {e}")

        return out

