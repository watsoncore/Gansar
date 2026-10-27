from __future__ import annotations

import logging
import re

import httpx

from app.models.report import AddressReport, Balance, Label
from app.parsers.html_extract import first_text, meta_content, parse_html
from app.sources.base import Source
from app.utils.http import shared_async_client

logger = logging.getLogger(__name__)


class _ScanHtmlBase(Source):
    base_site: str
    asset: str

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, sources_used=[self.name])
        url = f"https://{self.base_site}/address/{address}"
        try:
            async with shared_async_client(self._timeout) as client:
                r = await client.get(url)
                if r.status_code >= 400:
                    out.errors.append(f"{self.name}: http {r.status_code}")
                    return out
                html = r.text
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: {e}")
            return out

        try:
            doc = parse_html(html)
            h1 = first_text(doc, ("h1", "#ContentPlaceHolder1_divSummary h1", ".card-header-title", ".hash-tag"))
            h1 = re.sub(r"\s+", " ", h1).strip()
            if not h1:
                h1 = meta_content(doc, ("og:title", "twitter:title")) or first_text(doc, ("title",))
                h1 = re.sub(r"\s*(Address|Explorer|Scan|Blockchain).*", "", h1, flags=re.IGNORECASE).strip(" -|")
            if h1 and "Address" not in h1 and address.lower() not in h1.lower():
                out.labels.append(
                    Label(
                        chain=self.chain,
                        address=address,
                        label=h1[:120],
                        source=self.name,
                        confidence=0.55,
                        raw={"url": url},
                    )
                )
        except Exception:
            pass

        out.detected_chains = [self.chain]
        return out


class BscScanHtmlSource(_ScanHtmlBase):
    name = "bscscan_html"
    chain = "bsc"
    base_site = "bscscan.com"
    asset = "BNB"


class PolygonScanHtmlSource(_ScanHtmlBase):
    name = "polygonscan_html"
    chain = "polygon"
    base_site = "polygonscan.com"
    asset = "MATIC"


class ArbiscanHtmlSource(_ScanHtmlBase):
    name = "arbiscan_html"
    chain = "arbitrum"
    base_site = "arbiscan.io"
    asset = "ETH"


class OptimisticEtherscanHtmlSource(_ScanHtmlBase):
    name = "optimistic_etherscan_html"
    chain = "optimism"
    base_site = "optimistic.etherscan.io"
    asset = "ETH"


class SnowtraceHtmlSource(_ScanHtmlBase):
    name = "snowtrace_html"
    chain = "avalanche"
    base_site = "snowtrace.io"
    asset = "AVAX"

