from __future__ import annotations

import httpx

from app.models.report import AddressReport, RiskFlag
from app.sources.base import Source
from app.utils.http import create_async_client, json_list, json_object


class CryptoScamDbSource(Source):
    name = "cryptoscamdb"
    chain = "multi"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, sources_used=[self.name])
        url = f"https://api.cryptoscamdb.org/v1/check/{address}"
        try:
            async with create_async_client(self._timeout) as client:
                r = await client.get(url)
                if r.status_code == 404:
                    return out
                r.raise_for_status()
                data = json_object(r.json())
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: {e}")
            return out

        entries = json_list(json_object(data.get("result")).get("entries") or data.get("entries"))
        if entries:
            out.risk_flags.append(
                RiskFlag(
                    chain="multi",
                    address=address,
                    flag="reported_scam_indicator",
                    severity="high",
                    source="cryptoscamdb",
                    details="Matched in CryptoScamDB check endpoint",
                    raw={"entries_count": len(entries)},
                )
            )
        return out

