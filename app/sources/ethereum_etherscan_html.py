from __future__ import annotations

import logging
import re
from urllib.parse import urljoin

import httpx

from app.models.report import AddressReport, Label, SourceHealth, TokenHolding
from app.parsers.html_extract import attr, first_text, meta_content, parse_html, text
from app.sources.base import Source
from app.utils.http import shared_async_client

logger = logging.getLogger(__name__)


class EthereumEtherscanHtmlSource(Source):
    name = "etherscan_html"
    chain = "eth"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["eth"], sources_used=[self.name])
        url = f"https://etherscan.io/address/{address}"
        try:
            async with shared_async_client(self._timeout) as client:
                r = await client.get(url)
                if r.status_code == 429:
                    out.warnings.append(f"{self.name}: rate_limited: http 429")
                    out.source_health.append(
                        SourceHealth(source=self.name, status="rate_limited", timeout_seconds=min(self._timeout, 4.0), retry_strategy="lightweight html fallback", details="http 429")
                    )
                    return out
                r.raise_for_status()
                html = r.text
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: {e}")
            return out

        doc = parse_html(html)
        label_text = ""
        try:
            label_text = first_text(doc, ("h1", "#ContentPlaceHolder1_divSummary h1", ".card-header-title", ".hash-tag"))
        except Exception:
            label_text = ""

        label_text = re.sub(r"\s+", " ", label_text).strip()
        if not label_text:
            label_text = meta_content(doc, ("og:title", "twitter:title")) or first_text(doc, ("title",))
            label_text = re.sub(r"\s*(Address|Etherscan|Ethereum).*", "", label_text, flags=re.IGNORECASE).strip(" -|")
        if label_text and "Address" not in label_text and address.lower() not in label_text.lower():
            out.labels.append(
                Label(chain="eth", address=address, label=label_text[:120], source=self.name, confidence=0.6, raw={"url": url})
            )

        await self._fetch_token_holdings(address, out)
        return out

    async def _fetch_token_holdings(self, address: str, out: AddressReport) -> None:
        url = f"https://etherscan.io/tokenholdings?a={address}"
        try:
            async with shared_async_client(self._timeout) as client:
                r = await client.get(url)
                if r.status_code >= 400:
                    return
                html = r.text
        except httpx.HTTPError:
            return

        doc = parse_html(html)
        table = doc.css_first("table")
        if table is None:
            return
        rows = table.css("tbody tr")
        for row in rows[:50]:
            cols = row.css("td")
            if len(cols) < 2:
                continue
            token_col = text(cols[0])
            bal_col = text(cols[1])
            contract = None
            a = row.css_first("a")
            if a is not None:
                href = attr(a, "href")
                m = re.search(r"/token/(0x[a-fA-F0-9]{40})", href)
                if m:
                    contract = m.group(1)
            image = None
            img = row.css_first("img")
            if img is not None:
                image_src = attr(img, "src") or attr(img, "data-src")
                image = urljoin("https://etherscan.io", image_src) if image_src else None
            sym = None
            name = None
            if " " in token_col:
                parts = token_col.split(" ")
                sym = parts[-1].strip("()")
                name = " ".join(parts[:-1]).strip()
            out.tokens.append(
                TokenHolding(
                    chain="eth",
                    address=address,
                    contract=contract,
                    symbol=sym,
                    name=name,
                    amount=None,
                    source=self.name,
                    url=url,
                    raw={"balance_text": bal_col, "image": image},
                )
            )
