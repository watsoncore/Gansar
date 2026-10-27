from __future__ import annotations

import re
import asyncio
from typing import Any

import httpx

from app.models.report import AddressReport, TelegramEvidence, TelegramIdentity, TonAsset
from app.parsers.html_extract import parse_html, text
from app.sources.base import Source
from app.utils.http import fetch_json, fetch_text, http_error_message, json_list, json_object, retry_delay, shared_async_client
from app.utils.telegram_identity import merge_identity, now_utc
from app.utils.ton_assets import classify_asset, image_url_from, merge_asset, related_addresses
from app.utils.ton_normalize import ton_address, ton_text


USERNAME_RE = re.compile(r"(?<![A-Za-z0-9_])@?([A-Za-z][A-Za-z0-9_]{3,31})(?![A-Za-z0-9_])")
DOMAIN_RE = re.compile(r"([A-Za-z0-9_-]{2,64}\.ton)", re.IGNORECASE)
TG_ID_RE = re.compile(r"(?:telegram|tg|user)[\s_-]*(?:id|uid)\D{0,12}([0-9]{5,})", re.IGNORECASE)


class TelegramIdentitySource(Source):
    name = "telegram_identity"
    chain = "ton"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["ton"], sources_used=[self.name])
        async with shared_async_client(self._timeout) as client:
            await self._bounded("dns", self._from_tonapi_dns(client, address, out), out, min(self._timeout, 3.0))
            items = await self._bounded_items("nfts", self._from_tonapi_nfts(client, address, out), out, min(self._timeout, 5.0))
            await asyncio.gather(
                self._bounded("fragment", self._from_fragment_pages(client, address, out, items), out, min(self._timeout, 4.0)),
                self._bounded("marketplace", self._from_marketplace_pages(client, address, out, items), out, min(self._timeout, 4.0)),
                self._bounded("explorers", self._from_explorer_pages(client, address, out), out, min(self._timeout, 4.0)),
            )
        if not out.telegram_identities:
            out.telegram_identities.append(TelegramIdentity(wallet_address=address, confidence="unknown", source=self.name, collected_at=now_utc()))
        return out

    async def _bounded(self, label: str, coro, out: AddressReport, timeout: float) -> None:
        try:
            await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            out.errors.append(f"{self.name}: {label}: timeout")
        except asyncio.CancelledError:
            out.errors.append(f"{self.name}: {label}: cancelled")
        except Exception as e:
            out.errors.append(f"{self.name}: {label}: {type(e).__name__}")

    async def _bounded_items(self, label: str, coro, out: AddressReport, timeout: float) -> list[dict]:
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            out.errors.append(f"{self.name}: {label}: timeout")
        except asyncio.CancelledError:
            out.errors.append(f"{self.name}: {label}: cancelled")
        except Exception as e:
            out.errors.append(f"{self.name}: {label}: {type(e).__name__}")
        return []

    async def _from_tonapi_dns(self, client, address: str, out: AddressReport) -> None:
        url = f"https://tonapi.io/v2/accounts/{address}/dns/backresolve"
        try:
            r = None
            for attempt in range(2):
                r = await client.get(url)
                if r.status_code in {429, 500, 502, 503, 504} and attempt < 1:
                    await asyncio.sleep(retry_delay(r, attempt, 0.5, cap=3.0))
                    continue
                break
            if r is None:
                return
            if r.status_code >= 400:
                return
            data = json_object(r.json())
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: dns: {http_error_message(e)}")
            return
        domains = data.get("domains") or data.get("names") or []
        if isinstance(domains, str):
            domains = [domains]
        domains = json_list(domains)
        for domain in domains:
            value = ton_text(domain)
            if not value or not any(marker in value.lower() for marker in ("t.me", "telegram")):
                continue
            evidence = TelegramEvidence(source=self.name, evidence_url=url, parser_source="tonapi_dns", details=value, collected_at=now_utc(), confidence="weak", raw={"domain": domain})
            merge_identity(
                out,
                TelegramIdentity(
                    wallet_address=address,
                    confidence="weak",
                    domains=[value],
                    evidence=[evidence],
                    source=self.name,
                    evidence_url=url,
                    collected_at=now_utc(),
                ),
            )

    async def _from_tonapi_nfts(self, client, address: str, out: AddressReport) -> list[dict]:
        url = f"https://tonapi.io/v2/accounts/{address}/nfts"
        try:
            data = json_object(await fetch_json(self._timeout, url, params={"limit": 100}))
        except httpx.HTTPError as e:
            out.errors.append(f"{self.name}: nfts: {http_error_message(e)}")
            return []
        items = [item for item in json_list(data.get("nft_items") or data.get("items")) if isinstance(item, dict)]
        for item in items:
            metadata = json_object(item.get("metadata"))
            collection = json_object(item.get("collection"))
            name = ton_text(metadata.get("name")) or ton_text(item.get("name")) or ton_text(collection.get("name"))
            collection_name = ton_text(collection.get("name"))
            asset_type = classify_asset(name, collection_name, "nft")
            nft_contract = ton_address(item)
            public_text = " ".join(str(part or "") for part in [name, collection_name, metadata.get("description"), metadata.get("attributes")])
            username = (self._username_from_asset_name(name) or self._extract_username(public_text)) if asset_type == "username" else None
            tg_id = self._extract_tg_id(metadata, public_text)
            if username or tg_id or asset_type in {"gift", "username", "domain"}:
                evidence = TelegramEvidence(
                    source=self.name,
                    evidence_url=url,
                    nft_contract=nft_contract,
                    parser_source="tonapi_nft_metadata",
                    details=name or collection_name,
                    collected_at=now_utc(),
                    confidence="weak" if nft_contract else "likely",
                    raw={"asset_type": asset_type, "metadata": metadata},
                )
                merge_identity(
                    out,
                    TelegramIdentity(
                        wallet_address=address,
                        username=username,
                        telegram_user_id=tg_id,
                        confidence=evidence.confidence,
                        asset_ids=[nft_contract] if nft_contract else [],
                        gifts=[name] if asset_type == "gift" and name else [],
                        evidence=[evidence],
                        source=self.name,
                        evidence_url=url,
                        collected_at=now_utc(),
                    ),
                )
                if nft_contract:
                    merge_asset(
                        out,
                        TonAsset(
                            asset_id=nft_contract,
                            type=asset_type,
                            name=name[:120] if name else None,
                            title=(f"@{username}" if username and asset_type == "username" else name)[:120] if (username or name) else None,
                            collection=collection_name,
                            image_url=image_url_from(item),
                            owner_address=ton_address(item.get("owner")) or "",
                            ownership_status="current" if ton_address(item.get("owner")) else "unknown",
                            ownership_observed_at=now_utc(),
                            source=self.name,
                            external_url=f"https://getgems.io/nft/{nft_contract}",
                            evidence_url=url,
                            collected_at=now_utc(),
                            confidence=0.78 if evidence.confidence == "confirmed" else 0.58,
                            related_addresses=related_addresses(address, collection),
                            raw={"asset_type": asset_type, "metadata": metadata},
                        ),
                    )
        return items

    async def _from_fragment_pages(self, client, address: str, out: AddressReport, items: list[dict]) -> None:
        for item in items[:8]:
            metadata = json_object(item.get("metadata"))
            collection = json_object(item.get("collection"))
            name = ton_text(metadata.get("name")) or ton_text(item.get("name")) or ton_text(collection.get("name"))
            collection_name = ton_text(collection.get("name"))
            asset_type = classify_asset(name, collection_name, "nft")
            urls = []
            username = self._extract_username(name or "")
            domain = self._extract_domain(name or "")
            if username and asset_type == "username":
                urls.append(("username", username, f"https://fragment.com/username/{username}"))
            if domain:
                urls.append(("domain", domain, f"https://fragment.com/domain/{domain}"))
            for kind, value, url in urls:
                try:
                    page_text = self._page_text(await asyncio.wait_for(fetch_text(min(self._timeout, 2.5), url), timeout=min(self._timeout, 3.0)))
                except httpx.HTTPError as e:
                    out.errors.append(f"{self.name}: fragment: {http_error_message(e)}")
                    continue
                except asyncio.TimeoutError:
                    out.errors.append(f"{self.name}: fragment timeout {url}")
                    continue
                except Exception as e:
                    out.errors.append(f"{self.name}: fragment: {type(e).__name__}")
                    continue
                tg_id = self._extract_tg_id({}, page_text)
                evidence = TelegramEvidence(source=self.name, evidence_url=url, nft_contract=ton_address(item), parser_source="fragment_public_page", details=value, collected_at=now_utc(), confidence="weak", raw={"kind": kind})
                merge_identity(
                    out,
                    TelegramIdentity(
                        wallet_address=address,
                        username=value if kind == "username" else None,
                        telegram_user_id=tg_id,
                        confidence="weak",
                        domains=[value] if kind == "domain" else [],
                        asset_ids=[ton_address(item)] if ton_address(item) else [],
                        evidence=[evidence],
                        source=self.name,
                        evidence_url=url,
                        collected_at=now_utc(),
                    ),
                )

    async def _from_marketplace_pages(self, client, address: str, out: AddressReport, items: list[dict]) -> None:
        for item in items[:5]:
            nft_contract = ton_address(item)
            if not nft_contract:
                continue
            url = f"https://getgems.io/nft/{nft_contract}"
            try:
                page_text = self._page_text(await asyncio.wait_for(fetch_text(min(self._timeout, 2.5), url), timeout=min(self._timeout, 3.0)))
            except httpx.HTTPError as e:
                out.errors.append(f"{self.name}: getgems: {http_error_message(e)}")
                continue
            except asyncio.TimeoutError:
                out.errors.append(f"{self.name}: getgems timeout {url}")
                continue
            except Exception as e:
                out.errors.append(f"{self.name}: getgems: {type(e).__name__}")
                continue
            username = self._extract_username(page_text) if "username" in page_text.lower() or "telegram" in page_text.lower() else None
            tg_id = self._extract_tg_id({}, page_text)
            if username or tg_id:
                evidence = TelegramEvidence(source=self.name, evidence_url=url, nft_contract=nft_contract, parser_source="getgems_public_page", details=username or tg_id, collected_at=now_utc(), confidence="weak")
                merge_identity(
                    out,
                    TelegramIdentity(
                        wallet_address=address,
                        username=username,
                        telegram_user_id=tg_id,
                        confidence="weak",
                        asset_ids=[nft_contract],
                        evidence=[evidence],
                        source=self.name,
                        evidence_url=url,
                        collected_at=now_utc(),
                    ),
                )

    async def _from_explorer_pages(self, client, address: str, out: AddressReport) -> None:
        for url, parser_source in (
            (f"https://tonviewer.com/{address}", "tonviewer_public"),
            (f"https://tonscan.org/address/{address}", "tonscan_public"),
        ):
            try:
                page_text = self._page_text(await asyncio.wait_for(fetch_text(min(self._timeout, 2.5), url), timeout=min(self._timeout, 3.0)))
            except httpx.HTTPError as e:
                out.errors.append(f"{self.name}: {parser_source}: {http_error_message(e)}")
                continue
            except asyncio.TimeoutError:
                out.errors.append(f"{self.name}: {parser_source}: timeout")
                continue
            except Exception as e:
                out.errors.append(f"{self.name}: {parser_source}: {type(e).__name__}")
                continue
            username = self._extract_username(page_text) if "telegram" in page_text.lower() or "username" in page_text.lower() else None
            tg_id = self._extract_tg_id({}, page_text)
            if username or tg_id:
                evidence = TelegramEvidence(source=self.name, evidence_url=url, parser_source=parser_source, details=username or tg_id, collected_at=now_utc(), confidence="weak")
                merge_identity(
                    out,
                    TelegramIdentity(
                        wallet_address=address,
                        username=username,
                        telegram_user_id=tg_id,
                        confidence="weak",
                        evidence=[evidence],
                        source=self.name,
                        evidence_url=url,
                        collected_at=now_utc(),
                    ),
                )

    def _page_text(self, html: str) -> str:
        doc = parse_html(html)
        parts = [text(doc.css_first("title")), text(doc.css_first("body"))]
        for key in ("og:title", "og:description", "description", "twitter:title", "twitter:description"):
            node = doc.css_first(f'meta[property="{key}"]') or doc.css_first(f'meta[name="{key}"]')
            if node is not None and node.attributes.get("content"):
                parts.append(node.attributes["content"])
        return " ".join(part for part in parts if part)

    def _extract_username(self, value: str) -> str | None:
        direct = re.search(r"(?<![A-Za-z0-9_])@([A-Za-z][A-Za-z0-9_]{3,31})(?![A-Za-z0-9_])", value or "")
        if direct:
            return direct.group(1)
        explicit = re.search(r"(?:telegram\s+username|username|fragment)\D{0,12}@?([A-Za-z][A-Za-z0-9_]{3,31})", value or "", flags=re.IGNORECASE)
        if explicit:
            candidate = explicit.group(1)
            if candidate.lower() not in {"telegram", "username", "fragment", "account", "owner", "collection", "gift", "domain", "ton"}:
                return candidate
        return None

    def _username_from_asset_name(self, value: str | None) -> str | None:
        if not value:
            return None
        match = re.fullmatch(r"@?([A-Za-z][A-Za-z0-9_]{3,31})", value.strip())
        if not match:
            return None
        candidate = match.group(1)
        if candidate.lower() in {"telegram", "username", "fragment", "account", "owner", "collection", "gift", "domain", "ton"}:
            return None
        return candidate

    def _extract_domain(self, value: str) -> str | None:
        m = DOMAIN_RE.search(value or "")
        return m.group(1) if m else None

    def _extract_tg_id(self, metadata: dict[str, Any], public_text: str) -> str | None:
        for key, value in metadata.items():
            low = str(key).lower()
            if "telegram" in low or low in {"tg_id", "telegram_id", "user_id", "telegram_user_id"}:
                if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
                    return str(value)
        m = TG_ID_RE.search(public_text or "")
        return m.group(1) if m else None
