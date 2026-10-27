from __future__ import annotations

import re
import asyncio

import httpx

from app.models.report import AddressReport, TonAsset
from app.parsers.html_extract import parse_html, text
from app.sources.base import Source
from app.utils.http import fetch_json, fetch_text, http_error_message, json_list, json_object
from app.utils.ton_assets import classify_asset, image_url_from, merge_asset, now_utc, related_addresses
from app.utils.ton_normalize import ton_address, ton_text


class FragmentPublicSource(Source):
    name = "fragment_public"
    chain = "ton"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["ton"], sources_used=[self.name])
        candidates = await self._candidate_assets(address, out)
        if not candidates:
            return out
        for item in candidates[:5]:
            url = self._fragment_url(item)
            if not url:
                continue
            try:
                html = await asyncio.wait_for(fetch_text(min(self._timeout, 2.5), url), timeout=min(self._timeout, 3.0))
                asset = self._parse_page(address, item, url, html)
                if asset:
                    merge_asset(out, asset)
            except httpx.HTTPError as e:
                out.errors.append(f"{self.name}: {http_error_message(e)}")
            except asyncio.TimeoutError:
                out.errors.append(f"{self.name}: timeout {url}")
            except Exception as e:
                out.errors.append(f"{self.name}: page_parse: {type(e).__name__}")
        return out

    async def _candidate_assets(self, address: str, out: AddressReport) -> list[dict]:
        try:
            data = json_object(await fetch_json(self._timeout, f"https://tonapi.io/v2/accounts/{address}/nfts", params={"limit": 100}))
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: candidates: {http_error_message(e)}")
            return []
        except Exception as e:
            out.errors.append(f"{self.name}: candidates: {type(e).__name__}")
            return []
        items = json_list(data.get("nft_items") or data.get("items"))
        filtered = []
        for item in items:
            if not isinstance(item, dict):
                continue
            item = json_object(item)
            metadata = json_object(item.get("metadata"))
            collection = json_object(item.get("collection"))
            name = ton_text(metadata.get("name")) or ton_text(item.get("name")) or ton_text(collection.get("name"))
            collection_name = ton_text(collection.get("name"))
            asset_type = classify_asset(name, collection_name, "nft")
            if asset_type in {"username", "domain", "gift", "collectible"}:
                item["_asset_type"] = asset_type
                item["_asset_name"] = name
                item["_collection_name"] = collection_name
                filtered.append(item)
        return filtered

    def _fragment_url(self, item: dict) -> str | None:
        asset_type = item.get("_asset_type")
        name = item.get("_asset_name") or ""
        if asset_type == "username":
            m = re.search(r"@?([A-Za-z0-9_]{4,32})", name)
            if m:
                return f"https://fragment.com/username/{m.group(1)}"
        if asset_type == "domain":
            m = re.search(r"([A-Za-z0-9_-]+\.ton)", name, flags=re.IGNORECASE)
            if m:
                return f"https://fragment.com/domain/{m.group(1)}"
        asset_id = ton_address(item)
        if asset_type in {"gift", "collectible"} and asset_id:
            return f"https://fragment.com/nft/{asset_id}"
        return None

    def _parse_page(self, address: str, item: dict, url: str, html: str) -> TonAsset | None:
        doc = parse_html(html)
        page_title = self._meta(doc, "og:title") or text(doc.css_first("title"))
        if not page_title:
            return None
        description = self._meta(doc, "og:description") or self._meta(doc, "description") or ""
        image = self._meta(doc, "og:image") or image_url_from(item)
        body = text(doc.css_first("body"))
        price = self._price(body + " " + description)
        nft_address = ton_address(item)
        metadata = json_object(item.get("metadata"))
        name = item.get("_asset_name") or ton_text(metadata.get("name")) or page_title
        collection = item.get("_collection_name")
        asset_type = item.get("_asset_type") or classify_asset(name, collection, "nft")
        if not nft_address:
            nft_address = f"fragment:{url.rsplit('/', 1)[-1]}"
        return TonAsset(
            asset_id=nft_address,
            type=asset_type,
            name=name[:120] if name else page_title[:120],
            title=page_title[:140],
            collection=collection,
            image_url=image,
            owner_address="",
            ownership_status="unknown",
            last_seen=now_utc(),
            floor_price=None,
            marketplace="Fragment",
            source=self.name,
            external_url=url,
            evidence_url=url,
            collected_at=now_utc(),
            confidence=0.62,
            related_addresses=related_addresses(address, item.get("collection")),
            raw={"description": description[:500], "page_title": page_title},
        )

    def _meta(self, doc, key: str) -> str | None:
        node = doc.css_first(f'meta[property="{key}"]') or doc.css_first(f'meta[name="{key}"]')
        if node is None:
            return None
        value = node.attributes.get("content")
        return value if value else None

    def _price(self, value: str) -> float | None:
        m = re.search(r"([0-9][0-9\s.,]*)\s*TON", value, flags=re.IGNORECASE)
        if not m:
            return None
        raw = m.group(1).replace(" ", "").replace(",", ".")
        try:
            return float(raw)
        except ValueError:
            return None
