from __future__ import annotations

from urllib.parse import urlsplit
from app.utils.security import safe_public_url
from app.utils.event_identity import event_identity

import base64
import json
import re
import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx

from app.models.report import AddressReport, Balance, Label, SourceHealth, TelegramEvidence, TelegramIdentity, TokenHolding, TonAsset, TonAssetEvent
from app.parsers.html_extract import all_texts, attr, first_text, hrefs, meta_content, parse_html, text
from app.sources.base import Source
from app.utils.http import fetch_json, fetch_text, http_error_message, json_list, json_object, request_json, retry_delay, shared_async_client
from app.utils.ton_assets import add_asset_event, classify_asset, image_url_from, merge_asset, now_utc, related_addresses
from app.utils.telegram_identity import merge_identity
from app.utils.ton_normalize import ton_address, ton_amount, ton_canonical_address, ton_text


TON_ADDRESS_RE = re.compile(r"(?:-?\d:[0-9a-fA-F]{64}|[A-Za-z0-9_-]{48})")
TON_DOMAIN_RE = re.compile(r"\b[A-Za-z0-9_-]{2,64}\.ton\b", re.IGNORECASE)
USERNAME_RE = re.compile(r"(?<![A-Za-z0-9_])@[A-Za-z][A-Za-z0-9_]{3,31}(?![A-Za-z0-9_])")


class TonPublicPageSource(Source):
    chain = "ton"
    base_url: str
    page_kind: str

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["ton"], sources_used=[self.name])
        url = self.base_url.format(address=address)
        html = ""
        async with shared_async_client(self._timeout) as client:
            last_error: Exception | None = None
            for attempt in range(3):
                try:
                    r = await client.get(url)
                    if r.status_code in {429, 500, 502, 503, 504} and attempt < 2:
                        if r.status_code == 429:
                            warning = f"{self.name}: http 429 retry"
                            if warning not in out.warnings:
                                out.warnings.append(warning)
                        await asyncio.sleep(retry_delay(r, attempt, 0.5, cap=3.0))
                        continue
                    if r.status_code >= 400:
                        detail = f"http {r.status_code}"
                        if r.status_code == 429:
                            detail = "http 429 after retry"
                        out.errors.append(f"{self.name}: {detail}")
                        return out
                    html = r.text
                    break
                except httpx.HTTPError as e:
                    last_error = e
                    if attempt < 2:
                        await asyncio.sleep(retry_delay(None, attempt, 0.5, cap=3.0))
                        continue
                except Exception as e:
                    out.errors.append(f"{self.name}: {type(e).__name__}: {e}")
                    return out
            if not html:
                if last_error is not None:
                    out.errors.append(f"{self.name}: {http_error_message(last_error)}")
                return out
        self._parse_page(address, url, html, out)
        return out

    def _parse_page(self, address: str, url: str, html: str, out: AddressReport) -> None:
        title = self._title(html)
        if title and address.lower() not in title.lower():
            out.labels.append(Label(chain="ton", address=address, label=title[:120], source=self.name, confidence=0.45, raw={"url": url, "kind": self.page_kind}))
        doc = parse_html(html)
        snippets = [title or "", text(doc.css_first("body"))[:2000]]
        for key in ("og:title", "og:description", "description", "twitter:title", "twitter:description"):
            node = doc.css_first(f'meta[property="{key}"]') or doc.css_first(f'meta[name="{key}"]')
            if node is not None and node.attributes.get("content"):
                snippets.append(node.attributes["content"])
        page_text = " ".join(snippets)
        for domain in sorted(set(TON_DOMAIN_RE.findall(page_text)))[:8]:
            out.labels.append(Label(chain="ton", address=address, label=f"TON DNS: {domain}", source=self.name, confidence=0.5, raw={"url": url, "parser": "public_page_domain"}))
        for username in sorted(set(USERNAME_RE.findall(page_text)))[:8]:
            out.labels.append(Label(chain="ton", address=address, label=f"Telegram marker: {username}", source=self.name, confidence=0.38, raw={"url": url, "parser": "public_page_username"}))
        service_markers = ("tonkeeper", "fragment", "getgems", "ston.fi", "dedust", "telegram", "wallet", "exchange")
        lowered = page_text.lower()
        for marker in service_markers:
            if marker in lowered:
                out.labels.append(Label(chain="ton", address=address, label=f"Service signal: {marker}", source=self.name, confidence=0.34, raw={"url": url, "parser": "public_page_service"}))
        for linked in self._linked_addresses(html, address)[:12]:
            out.labels.append(Label(chain="ton", address=linked, label=f"Linked on {self.page_kind} page", source=self.name, confidence=0.3, raw={"url": url, "target": address}))

    def _linked_addresses(self, html: str, target: str) -> list[str]:
        target_key = ton_canonical_address(target)
        out = []
        for match in TON_ADDRESS_RE.findall(html):
            key = ton_canonical_address(match)
            if key and key != target_key and match not in out:
                out.append(match)
        return out

    def _title(self, html: str) -> str | None:
        doc = parse_html(html)
        value = meta_content(doc, ("og:title", "twitter:title"))
        if value:
            return value
        title = first_text(doc, ("title", "h1", '[data-testid*="title"]'))
        return title if title else None

    def _next_payload(self, html: str) -> dict:
        match = re.search(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', html, flags=re.IGNORECASE | re.DOTALL)
        if not match:
            return {}
        try:
            data = json.loads(match.group(1))
        except Exception:
            return {}
        encoded = json_object(json_object(data.get("props")).get("pageProps")).get("data")
        if not isinstance(encoded, str) or len(encoded) < 8:
            return {}
        for trim in (2, 0):
            try:
                raw = base64.b64decode(encoded[trim:] + "=" * (-len(encoded[trim:]) % 4))
                payload = json.loads(raw.decode("utf-8", errors="ignore"))
                if isinstance(payload, dict):
                    return payload
            except Exception:
                continue
        return {}


class TonviewerPublicSource(TonPublicPageSource):
    name = "tonviewer_public"
    base_url = "https://tonviewer.com/{address}"
    page_kind = "explorer"

    def __init__(self, timeout_seconds: float):
        super().__init__(timeout_seconds)
        self._username_history_cache: dict[str, str | None] = {}
        self._username_history_api_cache: dict[str, dict | None] = {}
        self._tonviewer_api_host = "https://tonapi.io"
        self._tonviewer_api_token = ""

    async def fetch(self, address: str) -> AddressReport:
        out = await super().fetch(address)
        await self._enrich_username_history(out)
        return out

    def _parse_page(self, address: str, url: str, html: str, out: AddressReport) -> None:
        super()._parse_page(address, url, html, out)
        self._remember_tonviewer_runtime(html)
        payload = self._next_payload(html)
        if not payload:
            return
        account = json_object(payload.get("account") or payload.get("wallet"))
        balance = account.get("balance")
        if balance is not None:
            try:
                out.balances.append(Balance(chain="ton", address=address, asset="TON", amount=float(balance) / 1e9, source=self.name, url=url, raw={"provider": "tonviewer_next"}))
            except Exception:
                pass
        if account.get("interfaces"):
            for item in json_list(account.get("interfaces"))[:8]:
                out.labels.append(Label(chain="ton", address=address, label=f"TON interface: {item}", source=self.name, confidence=0.55, raw={"url": url}))
        jettons = json_list(json_object(payload.get("jettons")).get("balances"))
        for item in jettons[:50]:
            item = json_object(item)
            jetton = json_object(item.get("jetton"))
            master = ton_address(jetton)
            symbol = ton_text(jetton.get("symbol"))
            name = ton_text(jetton.get("name"))
            decimals = int(jetton.get("decimals") or 9)
            raw_balance = item.get("balance")
            amount = None
            try:
                amount = float(raw_balance) / (10**decimals)
            except Exception:
                amount = None
            out.tokens.append(TokenHolding(chain="ton", address=address, contract=master, symbol=symbol, name=name, amount=amount, source=self.name, url=url, raw={"asset_type": "jetton", "verification": jetton.get("verification")}))
            if master:
                merge_asset(
                    out,
                    TonAsset(
                        asset_id=master,
                        type="jetton",
                        name=name,
                        title=symbol or name,
                        collection="Jettons",
                        image_url=jetton.get("image"),
                        owner_address=address,
                        last_seen=now_utc(),
                        source=self.name,
                        external_url=f"https://tonviewer.com/{master}",
                        evidence_url=url,
                        collected_at=now_utc(),
                        confidence=0.72,
                        raw={"asset_type": "jetton", "verification": jetton.get("verification")},
                    ),
                )
        nfts = json_list(json_object(payload.get("nfts")).get("nft_items"))
        for item in nfts[:80]:
            self._merge_nft_item(out, address, url, item)
        single_nft = json_object(payload.get("nft"))
        if single_nft:
            asset = self._merge_nft_item(out, address, url, single_nft)
            if asset and asset.type == "username":
                self._apply_username_history_payload(asset, payload, url, html)

    def _merge_nft_item(self, out: AddressReport, address: str, url: str, item: Any) -> TonAsset | None:
        item = json_object(item)
        nft_address = ton_address(item)
        if not nft_address:
            return None
        collection = json_object(item.get("collection"))
        metadata = json_object(item.get("metadata"))
        name = ton_text(metadata.get("name")) or ton_text(item.get("name")) or nft_address
        collection_name = ton_text(collection.get("name"))
        asset_type = classify_asset(name, collection_name, "nft")
        image = image_url_from(item)
        owner = ton_address(item.get("owner")) or ""
        asset = merge_asset(
            out,
            TonAsset(
                asset_id=nft_address,
                type=asset_type,
                name=name[:120] if name else None,
                title=name[:120] if name else None,
                collection=collection_name,
                image_url=image,
                owner_address=owner,
                ownership_status="current" if owner else "unknown",
                ownership_observed_at=now_utc(),
                last_seen=now_utc(),
                marketplace="Fragment" if asset_type in {"username", "domain", "gift"} else "Getgems",
                source=self.name,
                external_url=f"https://tonviewer.com/{nft_address}",
                evidence_url=url,
                collected_at=now_utc(),
                confidence=0.78,
                related_addresses=related_addresses(collection, owner, address),
                raw={"asset_type": asset_type, "collection": collection, "metadata": metadata},
            ),
        )
        if asset_type in {"username", "domain", "gift"}:
            details = ton_text(metadata.get("description")) or name or ""
            username_match = USERNAME_RE.search(details) or USERNAME_RE.search(name or "")
            domains = sorted(set(TON_DOMAIN_RE.findall(details)))
            evidence = TelegramEvidence(source=self.name, evidence_url=url, nft_contract=nft_address, parser_source="tonviewer_next_data", details=name, collected_at=now_utc(), confidence="weak", raw={"asset_type": asset_type})
            merge_identity(
                out,
                TelegramIdentity(
                    wallet_address=owner or address,
                    username=username_match.group(0).lstrip("@") if username_match and asset_type == "username" else None,
                    domains=domains,
                    gifts=[name] if asset_type == "gift" and name else [],
                    asset_ids=[nft_address],
                    confidence="weak",
                    evidence=[evidence],
                    source=self.name,
                    evidence_url=url,
                    collected_at=now_utc(),
                ),
            )
        return asset

    async def _enrich_username_history(self, out: AddressReport) -> None:
        assets: list[TonAsset] = []
        seen: set[str] = set()
        for asset in out.ton_assets:
            if asset.type != "username" or not asset.asset_id:
                continue
            key = ton_canonical_address(asset.asset_id) or asset.asset_id
            if key in seen:
                continue
            seen.add(key)
            assets.append(asset)
        if not assets:
            return
        timeout = min(self._timeout, 3.0)
        semaphore = asyncio.Semaphore(3)
        load_status: dict[str, str] = {}

        async def load(asset: TonAsset) -> None:
            async with semaphore:
                status = await self._load_username_history(asset, timeout)
                load_status[asset.asset_id] = status

        await asyncio.gather(*(load(asset) for asset in assets[:8]))
        missing = [asset for asset in assets[:8] if not self._asset_has_history(asset)]
        wallet_fallback = False
        wallet_found = 0
        wallet_status = ""
        if missing:
            wallet_fallback = True
            wallet_status, wallet_found = await self._load_wallet_history_fallback(out.target_address, missing, timeout)
        counts = {"found": 0, "unavailable": 0, "timeout": 0, "error": 0}
        for asset in assets[:8]:
            if self._asset_has_history(asset):
                counts["found"] += 1
                continue
            status = load_status.get(asset.asset_id) or wallet_status or "unavailable"
            counts[status if status in counts else "unavailable"] += 1
        if counts["timeout"] and not counts["found"] and not counts["unavailable"]:
            status = "timeout"
        elif counts["error"] and not counts["found"] and not counts["unavailable"]:
            status = "error"
        elif counts["found"]:
            status = "ok"
        else:
            status = "partial"
        details = f"checked={sum(counts.values())}; found={counts['found']}; unavailable={counts['unavailable']}; timeout={counts['timeout']}; wallet_fallback={1 if wallet_fallback else 0}; wallet_found={wallet_found}"
        out.source_health.append(SourceHealth(source="tonviewer_username_history", status=status, timeout_seconds=timeout, retry_strategy="bounded nft history api; wallet fallback", details=details, partial=status != "ok"))
        if counts["timeout"]:
            out.warnings.append("tonviewer_username_history: timeout")
        if counts["error"]:
            out.warnings.append("tonviewer_username_history: partial")

    def _asset_has_history(self, asset: TonAsset) -> bool:
        return bool((getattr(asset, "history_events", []) or []) or (asset.transfer_history or []) or (asset.sale_history or []))

    def _remember_tonviewer_runtime(self, html: str) -> None:
        match = re.search(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', html or "", flags=re.IGNORECASE | re.DOTALL)
        if not match:
            return
        try:
            data = json.loads(match.group(1))
        except Exception:
            return
        runtime = json_object(data.get("runtimeConfig"))
        host = runtime.get("host")
        token = runtime.get("authClientToken")
        if safe_public_url(host) and urlsplit(host).scheme == "https" and urlsplit(host).hostname in {"tonapi.io", "api.tonapi.io"}:
            self._tonviewer_api_host = host.rstrip("/")
        if isinstance(token, str) and token:
            self._tonviewer_api_token = token

    async def _apply_tonviewer_nft_history_api(self, asset: TonAsset, html: str, timeout: float, evidence_url: str) -> int:
        self._remember_tonviewer_runtime(html)
        payloads = [
            await self._tonviewer_api_json(f"/v2/accounts/{asset.asset_id}/events", {"limit": 25, "sort_order": "desc"}, timeout),
            await self._tonviewer_api_json(f"/v2/nfts/{asset.asset_id}/history", {"limit": 20}, timeout),
        ]
        events: list[TonAssetEvent] = []
        seen: set[tuple] = set()
        for payload in payloads:
            for event in self._history_events_from_tonapi_payload(payload or {}, asset, evidence_url, asset.owner_address, require_match=False):
                key = event_identity(event)
                if key in seen:
                    continue
                seen.add(key)
                events.append(event)
        for event in events[:12]:
            add_asset_event(asset, event)
        if events:
            asset.history_status = "found"
            asset.history_evidence_url = evidence_url
            asset.raw.update({"history_source": "tonviewer", "history_api": "tonapi_nft_history", "history_evidence_url": evidence_url, "history_status": "found", "history_events_count": len(getattr(asset, "history_events", []) or [])})
        return len(events)

    async def _load_wallet_history_fallback(self, wallet_address: str, assets: list[TonAsset], timeout: float) -> tuple[str, int]:
        if not wallet_address or not assets:
            return "unavailable", 0
        wallet_url = f"https://tonviewer.com/{wallet_address}"
        try:
            payload = await self._tonviewer_api_json(f"/v2/accounts/{wallet_address}/events", {"limit": 50, "sort_order": "desc"}, timeout)
        except asyncio.TimeoutError:
            return "timeout", 0
        except Exception:
            return "error", 0
        found = 0
        for asset in assets:
            events = self._history_events_from_tonapi_payload(payload or {}, asset, wallet_url, wallet_address, require_match=True)
            if not events:
                continue
            for event in events[:12]:
                add_asset_event(asset, event)
            asset.history_status = "found"
            asset.history_evidence_url = asset.history_evidence_url or wallet_url
            asset.raw.update({"history_source": "tonviewer", "history_api": "tonapi_wallet_events", "history_evidence_url": asset.history_evidence_url, "history_status": "found", "history_events_count": len(getattr(asset, "history_events", []) or [])})
            found += 1
        return "found" if found else "unavailable", found

    async def _tonviewer_api_json(self, path: str, params: dict, timeout: float) -> dict | None:
        if not self._tonviewer_api_token:
            return None
        host = (self._tonviewer_api_host or "https://tonapi.io").rstrip("/")
        url = f"{host}{path}"
        cache_key = json.dumps({"url": url, "params": params}, sort_keys=True, default=str)
        if cache_key in self._username_history_api_cache:
            return self._username_history_api_cache[cache_key]
        headers = {"Accept": "application/json", "Authorization": f"Bearer {self._tonviewer_api_token}"}
        try:
            async with shared_async_client(timeout) as client:
                payload = await asyncio.wait_for(request_json(client, "GET", url, params=params, headers=headers, retries=1), timeout=timeout + 0.5)
        except asyncio.TimeoutError:
            self._username_history_api_cache[cache_key] = None
            raise
        except Exception:
            self._username_history_api_cache[cache_key] = None
            return None
        data = json_object(payload)
        self._username_history_api_cache[cache_key] = data
        return data

    async def _load_username_history(self, asset: TonAsset, timeout: float) -> str:
        url = f"https://tonviewer.com/{asset.asset_id}"
        existing_status = asset.raw.get("history_status")
        existing_url = asset.raw.get("history_evidence_url")
        if asset.raw.get("history_source") == "tonviewer" and existing_status == "found" and existing_url and self._asset_has_history(asset):
            return "found"
        asset.raw.setdefault("history_source", "tonviewer")
        asset.raw.setdefault("history_evidence_url", url)
        asset.raw.setdefault("history_status", "unavailable")
        asset.history_evidence_url = asset.history_evidence_url or url
        asset.history_status = asset.history_status or "unavailable"
        cached = self._username_history_cache.get(url)
        if cached is not None:
            if cached:
                self._remember_tonviewer_runtime(cached)
                self._apply_username_history_payload(asset, self._next_payload(cached), url, cached)
                await self._apply_tonviewer_nft_history_api(asset, cached, timeout, url)
                return "found" if self._asset_has_history(asset) else "unavailable"
            return "unavailable"
        try:
            html = await asyncio.wait_for(fetch_text(timeout, url, retries=1), timeout=timeout + 0.5)
        except asyncio.TimeoutError:
            self._username_history_cache[url] = None
            return "timeout"
        except httpx.HTTPError:
            self._username_history_cache[url] = None
            return "error"
        except Exception:
            self._username_history_cache[url] = None
            return "error"
        self._username_history_cache[url] = html
        self._remember_tonviewer_runtime(html)
        self._apply_username_history_payload(asset, self._next_payload(html), url, html)
        await self._apply_tonviewer_nft_history_api(asset, html, timeout, url)
        return "found" if self._asset_has_history(asset) else "unavailable"

    def _apply_username_history_payload(self, asset: TonAsset, payload: dict, url: str, html: str = "") -> None:
        nft = json_object(payload.get("nft"))
        if nft:
            owner = ton_address(nft.get("owner"))
            if owner:
                asset.owner_address = owner
            metadata = json_object(nft.get("metadata"))
            name = ton_text(metadata.get("name")) or ton_text(nft.get("name"))
            if name and not asset.title:
                asset.title = name[:120]
            image = image_url_from(nft)
            if image and not asset.image_url:
                asset.image_url = image
        asset_title = asset.title or asset.name or asset.asset_id
        events = self._history_events_from_payload(payload, asset.asset_id, url, asset.owner_address, asset_title)
        if not events and html:
            for script_payload in self._script_payloads(html):
                events.extend(self._history_events_from_payload(script_payload, asset.asset_id, url, asset.owner_address, asset_title))
                if events:
                    break
        if not events and html:
            events = self._history_events_from_html(html, url, asset.asset_id, asset.owner_address, asset_title)
        for event in events[:12]:
            add_asset_event(asset, event)
        status = "found" if self._asset_has_history(asset) else "unavailable"
        asset.history_status = status
        asset.history_evidence_url = url
        asset.raw.update(
            {
                "history_source": "tonviewer",
                "history_evidence_url": url,
                "history_status": status,
                "history_events_count": len(getattr(asset, "history_events", []) or []),
            }
        )

    def _history_events_from_tonapi_payload(self, payload: dict, asset: TonAsset, url: str, target_account: str = "", require_match: bool = True) -> list[TonAssetEvent]:
        events: list[TonAssetEvent] = []
        seen: set[tuple] = set()
        for item in json_list(json_object(payload).get("events"))[:80]:
            item = json_object(item)
            if require_match and not self._tonapi_event_matches_asset(item, asset):
                continue
            for event in self._events_from_tonapi_event(item, asset, url, target_account):
                key = event_identity(event)
                if key in seen:
                    continue
                seen.add(key)
                events.append(event)
                if len(events) >= 20:
                    return events
        return events

    def _tonapi_event_matches_asset(self, event: dict, asset: TonAsset) -> bool:
        asset_key = ton_canonical_address(asset.asset_id) or str(asset.asset_id or "").lower()
        blob = json.dumps(event, ensure_ascii=False, default=str)
        for raw in TON_ADDRESS_RE.findall(blob):
            if (ton_canonical_address(raw) or raw.lower()) == asset_key:
                return True
        return False

    def _events_from_tonapi_event(self, event: dict, asset: TonAsset, url: str, target_account: str = "") -> list[TonAssetEvent]:
        timestamp = self._parse_timestamp(event.get("timestamp"))
        username = self._username_from_text(" ".join([asset.title or "", asset.name or "", json.dumps(event, ensure_ascii=False, default=str)[:1200]]))
        suspicious = self._tonapi_suspicious_label(event)
        out: list[TonAssetEvent] = []
        for action_index, action in enumerate(json_list(event.get("actions"))):
            action = dict(json_object(action))
            action["_action_index"] = action_index
            if not self._tonapi_event_matches_asset(action, asset):
                continue
            parsed = self._event_from_tonapi_action(event, action, asset, url, target_account, timestamp, username, suspicious)
            if parsed:
                out.append(parsed)
        return out

    def _event_from_tonapi_action(self, event: dict, action: dict, asset: TonAsset, url: str, target_account: str, timestamp: datetime | None, username: str, suspicious: str) -> TonAssetEvent | None:
        action_type = str(action.get("type") or "")
        if not action_type:
            return None
        data = json_object(action.get(action_type))
        lowered = json.dumps({"event": event, "action": action}, ensure_ascii=False, default=str).lower()
        tx_hash = self._tonapi_tx_hash(event, action)
        evidence = f"https://tonviewer.com/transaction/{tx_hash}" if tx_hash else url
        source_ref = target_account or asset.owner_address or asset.asset_id
        amount, currency = self._tonapi_amount(data, action_type)
        marketplace = self._marketplace_from_tonapi_action(data, action)
        label = self._tonapi_action_label(action)
        from_address = ""
        to_address = ""
        counterparty = ""
        counterparty_label = ""
        direction = "unknown"
        event_type = "unknown_activity"
        if action_type == "NftItemTransfer":
            from_account = json_object(data.get("sender"))
            to_account = json_object(data.get("recipient"))
            from_address = ton_address(from_account) or ""
            to_address = ton_address(to_account) or ""
            direction = self._event_direction(source_ref, from_address, to_address)
            event_type = "received_nft" if direction == "in" else "sent_nft" if direction == "out" else "transfer"
            label = "Received NFT" if direction == "in" else "Sent NFT" if direction == "out" else label or "NFT Transfer"
            counterparty = from_address if direction == "in" else to_address if direction == "out" else from_address or to_address
            counterparty_label = self._account_label(from_account if direction == "in" else to_account if direction == "out" else from_account or to_account)
        elif action_type == "TonTransfer":
            from_account = json_object(data.get("sender"))
            to_account = json_object(data.get("recipient"))
            from_address = ton_address(from_account) or ""
            to_address = ton_address(to_account) or ""
            direction = self._event_direction(source_ref, from_address, to_address)
            if direction == "unknown":
                direction = self._event_direction(asset.asset_id, from_address, to_address)
            event_type = "received_ton" if direction == "in" else "sent_ton" if direction == "out" else "unknown_activity"
            label = "Received TON" if direction == "in" else "Sent TON" if direction == "out" else label or "Ton Transfer"
            counterparty = from_address if direction == "in" else to_address if direction == "out" else to_address or from_address
            counterparty_label = self._account_label(from_account if direction == "in" else to_account if direction == "out" else to_account or from_account)
        elif action_type in {"AuctionBid", "NftPurchase", "NftSale"} or any(token in action_type.lower() for token in ("auction", "purchase", "sale", "bid")):
            bidder = json_object(data.get("bidder") or data.get("buyer"))
            seller = json_object(data.get("seller"))
            auction = json_object(data.get("auction"))
            from_address = ton_address(bidder or seller) or ""
            to_address = ton_address(auction or seller) or ""
            direction = self._event_direction(source_ref, from_address, to_address)
            event_type = "marketplace_purchase" if "purchase" in action_type.lower() else "marketplace_sale" if "sale" in action_type.lower() else "unknown_activity"
            counterparty = from_address or to_address
            counterparty_label = self._account_label(bidder or seller or auction)
            label = label or action_type
        else:
            if amount is None or not any(token in lowered for token in ("nft", "sale", "purchase", "auction", "bid", "marketplace", "portals", "fragment")):
                return None
            label = label or action_type
        if not any((from_address, to_address, tx_hash, timestamp, amount is not None)):
            return None
        if not marketplace:
            marketplace = counterparty_label if counterparty_label.lower() in {"fragment", "getgems", "portals marketplace"} else None
        success = True if str(action.get("status") or "").lower() in {"ok", "success"} else False if str(action.get("status") or "").lower() in {"failed", "fail", "error"} else None
        if event_type in {"marketplace_sale", "marketplace_purchase"} and success is not True:
            event_type = "interaction"
        raw = {
            "action_index": action.get("_action_index"),
            "lt": event.get("lt"),
            "action": action,
            "direction": direction,
            "title": label,
            "asset_title": asset.title or asset.name or asset.asset_id,
            "username": username,
            "nft_address": asset.asset_id,
            "from": from_address,
            "to": to_address,
            "counterparty": counterparty,
            "counterparty_label": counterparty_label,
            "amount": amount,
            "currency": currency,
            "tx_hash": tx_hash,
            "marketplace": marketplace or "",
            "suspicious_label": suspicious,
            "event_label": label,
            "event_id": str(event.get("event_id") or ""),
            "action_type": action_type,
            "evidence_url": evidence,
            "source": "tonviewer_tonapi",
        }
        return TonAssetEvent(
            event_type=event_type,
            timestamp=timestamp,
            direction=direction if direction in {"in", "out", "self", "unknown"} else "unknown",
            title=label,
            username=username or None,
            nft_address=asset.asset_id,
            from_address=from_address,
            to_address=to_address,
            counterparty=counterparty or None,
            counterparty_label=counterparty_label or None,
            amount=amount,
            currency=currency or None,
            price=amount if event_type in {"marketplace_sale", "marketplace_purchase"} and success is True else None,
            success=success,
            action_index=action.get("_action_index"),
            asset=asset.asset_id,
            tx_hash=tx_hash or None,
            marketplace=marketplace,
            suspicious_label=suspicious or None,
            source="tonviewer",
            evidence_url=evidence,
            confidence=0.82,
            raw=raw,
        )

    def _tonapi_tx_hash(self, event: dict, action: dict) -> str:
        for holder in (action, event):
            for value in (holder.get("base_transactions"), holder.get("transactions")):
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and len(item) >= 32:
                            return item
            for key in ("tx_hash", "transaction_hash", "hash"):
                value = holder.get(key)
                if isinstance(value, str) and len(value) >= 32:
                    return value
        value = event.get("ext_msg_hash")
        return value if isinstance(value, str) and len(value) >= 32 else ""

    def _tonapi_amount(self, data: dict, action_type: str) -> tuple[float | None, str]:
        value = data.get("amount")
        currency = "TON" if action_type == "TonTransfer" else ""
        if isinstance(value, dict):
            currency = str(value.get("token_name") or value.get("currency") or value.get("symbol") or currency or "TON")
            parsed = ton_amount(value, int(value.get("decimals") or 9))
            return parsed, currency
        if value in (None, ""):
            return None, currency
        try:
            number = float(str(value).replace(",", "."))
        except Exception:
            return None, currency
        if action_type == "TonTransfer" or number > 1_000_000:
            number = number / 1_000_000_000
            currency = currency or "TON"
        return number, currency

    def _tonapi_action_label(self, action: dict) -> str:
        preview = json_object(action.get("simple_preview"))
        name = ton_text(preview.get("name"))
        if name:
            return name[:80]
        action_type = str(action.get("type") or "")
        return re.sub(r"(?<!^)([A-Z])", r" \1", action_type).strip()[:80]

    def _account_label(self, account: Any) -> str:
        account = json_object(account)
        name = ton_text(account.get("name"))
        return (name or "")[:80]

    def _marketplace_from_tonapi_action(self, data: dict, action: dict) -> str | None:
        explicit = self._find_text(data, ("marketplace", "platform", "source"))
        if explicit:
            return explicit[:80]
        candidates = []
        for key in ("sender", "recipient", "bidder", "buyer", "seller", "auction"):
            label = self._account_label(data.get(key))
            if label:
                candidates.append(label)
        preview = json_object(action.get("simple_preview"))
        for account in json_list(preview.get("accounts")):
            label = self._account_label(account)
            if label:
                candidates.append(label)
        lowered = " ".join(candidates).lower()
        if "portals marketplace" in lowered or "portals" in lowered:
            return "Portals Marketplace"
        if "fragment" in lowered:
            return "Fragment"
        if "getgems" in lowered:
            return "Getgems"
        return None

    def _tonapi_suspicious_label(self, event: dict) -> str:
        if event.get("is_scam") is True:
            return "SUSPICIOUS"
        return "SUSPICIOUS" if '"is_scam": true' in json.dumps(event, ensure_ascii=False, default=str).lower() else ""

    def _history_events_from_payload(self, payload: dict, asset_id: str, url: str, owner_address: str = "", asset_title: str = "") -> list[TonAssetEvent]:
        events: list[TonAssetEvent] = []
        seen: set[tuple] = set()
        for item, path in self._iter_event_dicts(payload):
            event = self._event_from_dict(item, path, asset_id, url, owner_address, asset_title)
            if not event:
                continue
            key = (event.event_type, event.tx_hash, event.from_address, event.to_address, event.timestamp, event.price)
            if key in seen:
                continue
            seen.add(key)
            events.append(event)
            if len(events) >= 20:
                break
        return events

    def _script_payloads(self, html: str) -> list[dict]:
        out = []
        for match in re.finditer(r"<script[^>]*>(.*?)</script>", html, flags=re.IGNORECASE | re.DOTALL):
            raw = match.group(1).strip()
            if not raw or not any(token in raw.lower() for token in ("history", "event", "activity", "transfer", "received", "sent", "sale")):
                continue
            if raw.startswith("{") or raw.startswith("["):
                try:
                    data = json.loads(raw)
                    if isinstance(data, dict):
                        out.append(data)
                    elif isinstance(data, list):
                        out.append({"items": data})
                except Exception:
                    pass
            if len(out) >= 4:
                break
        return out

    def _iter_event_dicts(self, value: Any, path: str = "", depth: int = 0):
        if depth > 8:
            return
        if isinstance(value, dict):
            lowered = path.lower()
            blob = " ".join(str(key).lower() for key in value.keys())
            eventish = any(token in lowered or token in blob for token in ("history", "event", "activity", "action", "transfer", "sale", "transaction", "auction", "listing"))
            if eventish:
                yield value, path
            for key, nested in value.items():
                yield from self._iter_event_dicts(nested, f"{path}.{key}" if path else str(key), depth + 1)
        elif isinstance(value, list):
            for nested in value[:120]:
                yield from self._iter_event_dicts(nested, path, depth + 1)

    def _event_from_dict(self, item: dict, path: str, asset_id: str, url: str, owner_address: str = "", asset_title: str = "") -> TonAssetEvent | None:
        blob = json.dumps(item, ensure_ascii=False, default=str)[:2500]
        lowered = f"{path} {blob}".lower()
        if not any(token in lowered for token in ("history", "event", "activity", "transfer", "sale", "sold", "auction", "listing", "owner")):
            return None
        if any(token in lowered for token in ("sale", "sold", "purchase", "buy", "auction")):
            event_type = "sale"
        elif "listing" in lowered or "listed" in lowered:
            event_type = "listing"
        elif "mint" in lowered:
            event_type = "mint"
        elif "owner" in lowered and ("change" in lowered or "previous" in lowered):
            event_type = "owner_change"
        elif "transfer" in lowered or "sent" in lowered or "received" in lowered:
            event_type = "transfer"
        else:
            event_type = None
        from_address = self._find_address(item, ("from", "from_address", "sender", "source", "seller", "old_owner", "previous_owner", "owner_from"))
        to_address = self._find_address(item, ("to", "to_address", "receiver", "destination", "buyer", "new_owner", "owner_to"))
        tx_hash = self._find_text(item, ("tx_hash", "transaction_hash", "hash", "trace_id", "event_id", "lt_hash"))
        timestamp = self._find_timestamp(item)
        price = self._find_price(item)
        currency = self._find_text(item, ("currency", "symbol", "asset", "token"))
        marketplace = self._marketplace_from(item, lowered)
        direction = self._event_direction(owner_address, from_address, to_address)
        if event_type is None and (from_address or to_address):
            event_type = "transfer"
        if event_type is None or not any((from_address, to_address, tx_hash, timestamp, price is not None)):
            return None
        evidence = f"https://tonviewer.com/transaction/{tx_hash}" if tx_hash else url
        username = self._username_from_text(asset_title or blob)
        counterparty = from_address if direction == "in" else to_address if direction == "out" else to_address or from_address
        event_label = self._event_label(lowered, event_type, direction, currency, price)
        suspicious = "SUSPICIOUS" if "suspicious" in lowered else ""
        success = item.get("success") if isinstance(item.get("success"), bool) else None
        if event_type == "sale" and success is not True:
            event_type = "interaction"
        return TonAssetEvent(
            event_type=event_type,
            timestamp=timestamp,
            from_address=from_address,
            to_address=to_address,
            price=price if event_type == "sale" and success is True else None,
            success=success,
            asset=asset_id,
            tx_hash=tx_hash or None,
            marketplace=marketplace,
            source="tonviewer",
            evidence_url=evidence,
            confidence=0.72,
            raw={
                "direction": direction,
                "asset_title": asset_title,
                "username": username,
                "nft_address": asset_id,
                "counterparty": counterparty,
                "amount": price,
                "currency": currency or ("TON" if price is not None else ""),
                "marketplace": marketplace,
                "suspicious_label": suspicious,
                "event_label": event_label,
                "path": path,
                "evidence_url": url,
            },
        )

    def _history_events_from_html(self, html: str, url: str, asset_id: str = "", owner_address: str = "", asset_title: str = "") -> list[TonAssetEvent]:
        body = text(parse_html(html).css_first("body"))
        lowered = body.lower()
        if not any(token in lowered for token in ("history", "activity", "transfer", "sale", "sold")):
            return []
        events: list[TonAssetEvent] = []
        for match in re.finditer(r"(?i)(sale|sold|transfer|received|sent).{0,360}", body):
            snippet = match.group(0)
            addresses = []
            for raw in TON_ADDRESS_RE.findall(snippet):
                addr = ton_address(raw)
                if addr and addr not in addresses:
                    addresses.append(addr)
            timestamp = self._parse_timestamp(next(iter(re.findall(r"\b20\d{2}[-/.]\d{1,2}[-/.]\d{1,2}(?:[ T]\d{1,2}:\d{2}(?::\d{2})?)?\b", snippet)), None))
            if len(addresses) < 2 or not timestamp:
                continue
            event_type = "interaction" if match.group(1).lower() in {"sale", "sold"} else "transfer"
            direction = self._event_direction(owner_address, addresses[0], addresses[1])
            username = self._username_from_text(asset_title or snippet)
            events.append(
                TonAssetEvent(
                    event_type=event_type,
                    timestamp=timestamp,
                    from_address=addresses[0],
                    to_address=addresses[1],
                    source="tonviewer",
                    evidence_url=url,
                    confidence=0.55,
                    raw={"parser": "visible_html", "direction": direction, "asset_title": asset_title, "username": username, "nft_address": asset_id, "counterparty": addresses[0] if direction == "in" else addresses[1] if direction == "out" else "", "event_label": self._event_label(snippet.lower(), event_type, direction, "", None), "evidence_url": url},
                )
            )
            if len(events) >= 8:
                break
        return events

    def _event_direction(self, owner_address: str, from_address: str, to_address: str) -> str:
        owner = ton_canonical_address(owner_address)
        from_key = ton_canonical_address(from_address)
        to_key = ton_canonical_address(to_address)
        if owner and to_key == owner and from_key == owner:
            return "self"
        if owner and to_key == owner:
            return "in"
        if owner and from_key == owner:
            return "out"
        return "unknown"

    def _username_from_text(self, value: str) -> str:
        match = USERNAME_RE.search(value or "")
        if match:
            return match.group(0).lstrip("@")
        return ""

    def _event_label(self, lowered: str, event_type: str, direction: str, currency: str, price: float | None) -> str:
        if "received ton" in lowered:
            return "Received TON"
        if "sent ton" in lowered:
            return "Sent TON"
        if "received nft" in lowered:
            return "Received NFT"
        if "sent nft" in lowered:
            return "Sent NFT"
        if "ton" in str(currency or "").lower() and price is not None:
            return "Received TON" if direction == "in" else "Sent TON" if direction == "out" else "TON"
        if event_type in {"sale", "listing", "transfer", "owner_change", "mint"}:
            return "Received NFT" if direction == "in" else "Sent NFT" if direction == "out" else "NFT transfer"
        return ""

    def _find_address(self, item: dict, keys: tuple[str, ...]) -> str:
        for key, value in item.items():
            key_l = str(key).lower()
            if key_l in keys or key_l.replace("-", "_") in keys:
                addr = self._address_value(value)
                if addr:
                    return addr
        return ""

    def _address_value(self, value: Any) -> str:
        addr = ton_address(value)
        if addr:
            return addr
        if isinstance(value, dict):
            for key in ("address", "account", "wallet", "owner"):
                addr = ton_address(value.get(key))
                if addr:
                    return addr
        return ""

    def _find_text(self, item: dict, keys: tuple[str, ...]) -> str:
        for key, value in item.items():
            key_l = str(key).lower()
            if key_l in keys or key_l.replace("-", "_") in keys:
                if isinstance(value, dict):
                    value = value.get("hash") or value.get("id") or value.get("symbol") or value.get("name")
                if isinstance(value, (str, int, float)):
                    text_value = str(value).strip()
                    if text_value:
                        return text_value[:160]
        return ""

    def _find_timestamp(self, item: dict) -> datetime | None:
        for key, value in item.items():
            key_l = str(key).lower()
            if key_l in {"timestamp", "time", "utime", "date", "created_at", "updated_at", "event_time", "now", "transaction_now"}:
                parsed = self._parse_timestamp(value)
                if parsed:
                    return parsed
            if isinstance(value, dict):
                parsed = self._find_timestamp(value)
                if parsed:
                    return parsed
        return None

    def _parse_timestamp(self, value: Any) -> datetime | None:
        if value in (None, ""):
            return None
        if isinstance(value, (int, float)):
            raw = float(value)
            if raw > 10_000_000_000:
                raw = raw / 1000
            if raw > 900_000_000:
                try:
                    return datetime.fromtimestamp(raw, timezone.utc)
                except Exception:
                    return None
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.isdigit():
                return self._parse_timestamp(float(stripped))
            try:
                return datetime.fromisoformat(stripped.replace("Z", "+00:00"))
            except Exception:
                return None
        return None

    def _find_price(self, item: dict) -> float | None:
        for key, value in item.items():
            key_l = str(key).lower()
            if key_l not in {"price", "amount", "value", "ton_amount", "cost"}:
                continue
            raw = value
            if isinstance(value, dict):
                raw = value.get("value") or value.get("amount") or value.get("price")
            try:
                number = float(str(raw).replace(",", "."))
            except Exception:
                continue
            if number > 1_000_000_000:
                number = number / 1_000_000_000
            return number
        return None

    def _marketplace_from(self, item: dict, lowered: str) -> str | None:
        explicit = self._find_text(item, ("marketplace", "platform", "source"))
        if explicit:
            return explicit[:80]
        if "portals marketplace" in lowered or "portals" in lowered:
            return "Portals Marketplace"
        if "fragment" in lowered:
            return "Fragment"
        if "getgems" in lowered:
            return "Getgems"
        if "tonviewer" in lowered:
            return "Tonviewer"
        return None


class TonscanPublicSource(TonPublicPageSource):
    name = "tonscan_public"
    base_url = "https://tonscan.org/address/{address}"
    page_kind = "explorer"


class DtonPublicSource(TonPublicPageSource):
    name = "dton_public"
    base_url = "https://dton.io/a/{address}"
    page_kind = "analytics"


class GetgemsPublicSource(Source):
    name = "getgems_public"
    chain = "ton"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["ton"], sources_used=[self.name])
        items = await self._candidate_assets(address, out)
        if not items:
            return out
        for item in items[:5]:
            nft_address = ton_address(item)
            if not nft_address:
                continue
            url = f"https://getgems.io/nft/{nft_address}"
            try:
                html = await asyncio.wait_for(fetch_text(min(self._timeout, 2.5), url), timeout=min(self._timeout, 3.0))
                asset = self._parse_asset(address, item, url, html)
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
        return [item for item in json_list(data.get("nft_items") or data.get("items")) if isinstance(item, dict)]

    def _parse_asset(self, address: str, item: dict, url: str, html: str) -> TonAsset | None:
        nft_address = ton_address(item)
        if not nft_address:
            return None
        doc = parse_html(html)
        title = self._meta(doc, "og:title") or text(doc.css_first("title"))
        description = self._meta(doc, "og:description") or ""
        image = self._meta(doc, "og:image") or image_url_from(item)
        metadata = json_object(item.get("metadata"))
        collection = json_object(item.get("collection"))
        name = ton_text(metadata.get("name")) or ton_text(item.get("name")) or title
        collection_name = ton_text(collection.get("name"))
        asset_type = classify_asset(name, collection_name, "nft")
        price = self._price(description + " " + text(doc.css_first("body")))
        return TonAsset(
            asset_id=nft_address,
            type=asset_type,
            name=name[:120] if name else None,
            title=title[:140] if title else name,
            collection=collection_name,
            image_url=image,
            owner_address="",
            ownership_status="unknown",
            last_seen=now_utc(),
            floor_price=None,
            marketplace="Getgems",
            source=self.name,
            external_url=url,
            evidence_url=url,
            collected_at=now_utc(),
            confidence=0.64,
            related_addresses=related_addresses(address, collection),
            raw={"description": description[:500], "unverified_page_amount_hint": price},
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
