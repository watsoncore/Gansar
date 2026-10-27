from __future__ import annotations

import os

from app.models.report import AddressReport, SourceHealth
from app.sources.ton_tonapi import TonApiSource


class TonConsoleSource(TonApiSource):
    name = "tonconsole"

    def _api_key(self) -> str:
        return (os.getenv("TONCONSOLE_API_KEY") or os.getenv("TON_CONSOLE_API_KEY") or "").strip()

    async def fetch(self, address: str) -> AddressReport:
        if not self._api_key():
            return AddressReport(
                target_address=address,
                detected_chains=["ton"],
                sources_used=[self.name],
                warnings=[f"{self.name}: optional_api_key_missing"],
                source_health=[SourceHealth(source=self.name, status="partial", timeout_seconds=min(self._timeout, 8.0), retry_strategy="optional api key", details="optional api key missing")],
            )
        return await super().fetch(address)
