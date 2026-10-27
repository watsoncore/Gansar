from __future__ import annotations

import os
from typing import Any

import httpx

from app.models.report import AddressReport, Label, SourceHealth
from app.sources.base import Source
from app.utils.http import shared_async_client


class EthereumLabelsSource(Source):
    name = "ethereum_labels"
    chain = "eth"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    def _api_key(self) -> str:
        return (
            os.getenv("WALLETLABELS_API_KEY")
            or os.getenv("ETHEREUM_LABELS_API_KEY")
            or os.getenv("GANSAR_ETHEREUM_LABELS_API_KEY")
            or ""
        ).strip()

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["eth"], sources_used=[self.name])
        key = self._api_key()
        if not key:
            out.warnings.append(f"{self.name}: api key missing")
            out.source_health.append(
                SourceHealth(
                    source=self.name,
                    status="skipped",
                    timeout_seconds=min(self._timeout, 4.0),
                    retry_strategy="optional labels api key",
                    details="api key missing",
                )
            )
            return out

        url = f"https://api.walletlabels.xyz/api/ethereum/label/{address}"
        try:
            async with shared_async_client(self._timeout) as client:
                r = await client.get(url, params={"apikey": key, "limit": "20"})
                if r.status_code == 429:
                    out.warnings.append(f"{self.name}: rate_limited: http 429")
                    out.source_health.append(
                        SourceHealth(source=self.name, status="rate_limited", timeout_seconds=min(self._timeout, 4.0), retry_strategy="bounded request, fallback sources", details="http 429")
                    )
                    return out
                if r.status_code >= 400:
                    out.errors.append(f"{self.name}: http {r.status_code}")
                    return out
                data = r.json()
        except httpx.TimeoutException:
            out.errors.append(f"{self.name}: timeout")
            return out
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: {e}")
            return out
        except ValueError as e:
            out.errors.append(f"{self.name}: invalid response: {e}")
            return out

        rows = data.get("data") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            out.warnings.append(f"{self.name}: unsupported response")
            return out
        for item in rows[:20]:
            if not isinstance(item, dict):
                continue
            for value in self._labels(item):
                out.labels.append(
                    Label(
                        chain="eth",
                        address=address,
                        label=value[:120],
                        source=self.name,
                        confidence=0.72,
                        raw={"url": url, "label": item},
                    )
                )
        return out

    def _labels(self, item: dict[str, Any]) -> list[str]:
        values = []
        name = str(item.get("address_name") or "").strip()
        label = str(item.get("label") or "").strip()
        label_type = str(item.get("label_type") or "").strip()
        label_subtype = str(item.get("label_subtype") or "").strip()
        if name:
            values.append(name)
        if label:
            values.append(label)
        detail = " / ".join(part for part in (label_type, label_subtype) if part)
        if detail:
            values.append(detail)
        return list(dict.fromkeys(values))
