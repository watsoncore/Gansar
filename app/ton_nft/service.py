from __future__ import annotations

from collections import Counter, OrderedDict
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable
import inspect
import re
import time
import uuid
from urllib.parse import urlsplit

from app.utils.security import safe_public_url, sanitize_observation
from app.utils.ton_normalize import ton_canonical_address, ton_datetime

from .analytics import (analyze_report, canonical_hash, event_identity, merge_event,
                        money_from_price)
from .discovery import (KNOWN_COLLECTIONS, NormalizedQuery, discover_named_asset,
                        normalize_nft_query, registry_entry)
from .models import (CollectionCoverage, CoverageStatus, DiscoveryCandidate, DiscoveryResult,
                     IntelligenceEvidence, InvestigationBudget, NFTOwnershipAssertion,
                     NFTAsset, NFTCollection, NFTEvent, NFTIntelligenceReport, NFTListing,
                     NFTMarketObservation, NFTMetadataSnapshot, TelegramCollectible, VerificationStatus, utcnow)
from .protocol import collection_data, content_uri, nft_data, stack_address, stack_boc, ton_dns_item_index
from .providers import (BudgetExceeded, Payload, ProviderError, RequestController,
                        TonAPIProvider, ToncenterProvider, TelegramPublicProvider, redact)
from .storage import InvestigationStore, content_hash, load_investigation, validate_investigation_id


def _address(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("address") or value.get("account_address")
    return ton_canonical_address(value)


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (ValueError, TypeError):
        return None


class NFTInvestigator:
    def __init__(self, report: NFTIntelligenceReport, store: InvestigationStore,
                 providers: dict[str, Any] | None = None, *, incremental: bool = False,
                 use_api_keys: bool = False, registry: dict | None = None,
                 on_target_resolved: Callable[[dict, NFTIntelligenceReport], Any] | None = None,
                 on_progress: Callable[[dict], None] | None = None,
                 priority_scheduling: bool = False, checkpoint_interval_seconds: float = 0,
                 continuous: bool = False, on_checkpoint: Callable[[NFTIntelligenceReport], Any] | None = None):
        self.report, self.store, self.incremental = report, store, incremental
        self.report_run_started = utcnow()
        self.registry = registry or KNOWN_COLLECTIONS
        self.on_target_resolved, self.on_progress = on_target_resolved, on_progress
        self.priority_scheduling = priority_scheduling
        self.continuous, self.on_checkpoint = continuous, on_checkpoint
        self._pending_streams = OrderedDict()
        self._tail_aliases = {}
        self._resume_tail_states = dict(report.checkpoints.get("retained_history_tails", {}))
        self._detail_attempted: set[str] = set()
        self._detail_requests = 0
        self._last_report_checkpoint = float("-inf")
        self.checkpoint_interval_seconds = max(0.0, float(checkpoint_interval_seconds))
        self._last_snapshot_at: float | None = None
        self._target_notified = False
        self._callback_error: Exception | None = None
        self.controller = RequestController(report.budget, self.observe, progress=self.provider_progress)
        providers = providers or {}
        self.tonapi = providers.get("tonapi") or TonAPIProvider(use_api_keys=use_api_keys)
        self.toncenter = providers.get("toncenter") or ToncenterProvider(use_api_keys=use_api_keys)
        self.telegram_public = providers.get("telegram_public") or TelegramPublicProvider()
        for provider in (self.tonapi, self.toncenter, self.telegram_public):
            provider.controller = self.controller
        self.assets = {a.address: a for a in report.assets}
        report.input_resolution = {}
        report.owner_analysis_snapshot = None
        self._owner_accounts: dict[str, dict] = {}
        # A persisted verified assertion is historical evidence. It is not a
        # fresh current assertion until this run's getter succeeds, even when
        # a deadline prevents the asset from being inspected at all.
        for asset in self.assets.values():
            asset.current_owner_status = VerificationStatus.UNVERIFIED
            asset.owner_corroboration = {}
            asset.owner_account = {}
            asset.listings = []
        self.collections = {c.address: c for c in report.collections}
        self.events = {e.event_id: e for e in report.events}
        self.observations = {o.observation_id: o for o in report.observations}
        self.evidence_ids = {e.evidence_id for e in report.evidence}
        self.raw_records = report.stats.get("raw_event_records", 0)
        self.duplicates = report.stats.get("duplicate_observations", 0)
        self._verified_this_run: set[str] = set()
        self._collection_this_run: set[str] = set()
        if incremental:
            # Refresh the head without losing a previously unfinished tail.
            # Inventory offsets are mutable; only historical stream cursors
            # are resumed, with their source/ordering limitations retained.
            self._resume_tail_states.update({stream: dict(state) for stream, state in report.checkpoints.items()
                if stream.startswith("history:") and not stream.endswith(":retained_tail")
                and isinstance(state, dict) and not state.get("exhausted") and state.get("cursor") is not None})
            report.checkpoints = {"retained_history_tails": dict(self._resume_tail_states)}
            report.coverage = []

    def provider_progress(self, event: dict) -> None:
        if self.on_progress:
            try:
                self.on_progress(sanitize_observation({"investigation_id": self.report.investigation_id,
                    "assets": len(self.assets), "events": len(self.events), **event}))
            except Exception as exc:
                self._callback_error = exc
                raise

    def progress(self, phase: str, status: str = "started", **details: Any) -> None:
        event = sanitize_observation({"stage": "nft." + phase, "phase": phase, "status": status,
            "timestamp": utcnow().isoformat(),
            "elapsed_seconds": self.report.budget.max_seconds-self.controller.remaining(),
            "requests": self.controller.requests, "assets": len(self.assets), "events": len(self.events), **details})
        self.report.stats.setdefault("stage_timings", []).append(event)
        self.provider_progress(event)

    async def notify_target_resolved(self, wallet: str | None = None) -> None:
        if self._target_notified:
            return
        self.snapshot(force=True)
        resolution = resolve_verified_nft_owner(self.report)
        if resolution:
            target = {**resolution, "scope": "item", "analysis_address": resolution["owner_address"]}
        elif wallet and self.report.scope == "wallet" and ton_canonical_address(wallet):
            target = {"status": "resolved", "scope": "wallet", "analysis_address": ton_canonical_address(wallet),
                "original_query": self.report.query, "object_type": "ton_account",
                "note": "Validated TON account; wallet contract classification is not asserted"}
        else:
            return
        self._target_notified = True
        self.progress("target_resolved", "resolved", analysis_address=target["analysis_address"], scope=target["scope"])
        # The caller can start its ordinary analysis task here and return at once.
        # This hook does not create another NFT investigation or change budgets.
        if self.on_target_resolved:
            try:
                result = self.on_target_resolved(target, self.report)
                if inspect.isawaitable(result):
                    await result
            except Exception as exc:
                self._callback_error = exc
                raise

    def observe(self, observation) -> None:
        raw_ref = self.store.save_observation(self.report.investigation_id, observation)
        # Raw observations are resolvable from SQLite; snapshots carry references.
        compact = observation.model_copy(update={"raw": None, "raw_ref": raw_ref})
        self.report.observations.append(compact)
        self.observations[compact.observation_id] = compact

    def evidence(self, payload: Payload, relation: str, explanation: str,
                 *, status: VerificationStatus = VerificationStatus.PROVIDER_REPORTED,
                 transaction_hash: str | None = None, logical_time: int | None = None) -> str:
        eid = "ton:nft:evidence:" + content_hash({"observation": payload.observation_id,
                                                "relation": relation, "explanation": explanation})
        if eid not in self.evidence_ids:
            self.evidence_ids.add(eid)
            self.report.evidence.append(IntelligenceEvidence(evidence_id=eid, source=payload.source,
                upstream=payload.upstream, observation_id=payload.observation_id, relation=relation,
                status=status, explanation=explanation, url=payload.endpoint,
                transaction_hash=transaction_hash, logical_time=logical_time,
                confidence="high" if status == VerificationStatus.VERIFIED_ONCHAIN else "medium"))
        return eid

    async def optional(self, awaitable: Awaitable, purpose: str) -> Payload | None:
        try:
            return await awaitable
        except BudgetExceeded:
            raise
        except ProviderError as exc:
            if self._callback_error is not None:
                raise
            self.report.warnings.append(f"{purpose}: {exc}")
        except (ValueError, KeyError, TypeError) as exc:
            if self._callback_error is not None:
                raise
            self.report.warnings.append(f"{purpose}: {type(exc).__name__}; preserved raw observation")
        return None

    async def get_method(self, address: str, method: str, stack: list | None = None) -> Payload | None:
        result = await self.optional(self.toncenter.get_method(address, method, stack), method)
        if result is not None:
            return result
        self.controller.emit_progress("getter_fallback", source=self.tonapi.name,
                                      method_name=method, address=address)
        return await self.optional(self.tonapi.get_method(address, method, stack), method + " independent fallback")

    def snapshot(self, *, force: bool = False) -> None:
        self.report.assets = list(self.assets.values())
        self.report.collections = list(self.collections.values())
        self.report.events = list(self.events.values())
        self.report.stats.update({"requests_this_run": self.controller.requests,
                                 "raw_event_records": self.raw_records,
                                 "duplicate_observations": self.duplicates,
                                 "elapsed_seconds_this_run": self.report.budget.max_seconds-self.controller.remaining()})
        self.report.input_resolution = resolve_verified_nft_owner(self.report) or {}
        # Refresh the in-memory report at every boundary, but avoid repeatedly
        # serializing/sanitizing a growing portfolio within one request burst.
        # Raw provider observations are persisted immediately by observe().
        now = time.monotonic()
        if (force or self._last_snapshot_at is None or self.checkpoint_interval_seconds == 0
                or now - self._last_snapshot_at >= self.checkpoint_interval_seconds):
            self.store.save_snapshot(self.report)
            self._last_snapshot_at = time.monotonic()

    async def notify_checkpoint(self, *, force=False):
        if self.on_checkpoint and (force or time.monotonic()-self._last_report_checkpoint >= 20):
            self._last_report_checkpoint = time.monotonic()
            result = self.on_checkpoint(self.report)
            if inspect.isawaitable(result):
                await result

    async def drain_priority_streams(self):
        """Round-robin saved cursors, item state and exact transaction details.

        One page is a scheduling slice, not the end of a deep investigation.
        Every stream retains the same request/page/item/time safety ceilings.
        """
        while True:
            progressed = False
            if self._pending_streams:
                _, parameters = self._pending_streams.popitem(last=False)
                await self.page_stream(*parameters[:5], cursor_kind=parameters[5])
                progressed = True
            pending = next((address for address in self.assets if address not in self._verified_this_run), None)
            if pending:
                await self.inspect_item(pending)
                # An unavailable getter is attempted once per run. It remains
                # unverified; retry belongs to resume, not an infinite loop.
                self._verified_this_run.add(pending)
                progressed = True
            before = len(self._detail_attempted)
            await self.enrich_transactions(max_per_turn=1)
            progressed = progressed or len(self._detail_attempted) > before
            await self.notify_checkpoint()
            if not progressed:
                break
            if self.controller.remaining() <= 0:
                raise BudgetExceeded("Deep investigation deadline reached; pending cursors retained")

    def defer_asset_enrichment(self, address: str, payload: Payload) -> None:
        """Retain a lightweight identity/provenance pointer when detail capacity is full.

        Provider responses were committed to SQLite before parsing. History
        events still retain their exact NFT address and full event evidence;
        only construction of additional heavy current-state models is deferred.
        """
        pending = self.report.stats.setdefault("asset_enrichment_pending", {})
        maximum = min(self.report.budget.max_events,
            self.report.budget.max_pages*self.report.budget.page_size*2,
            self.report.budget.max_requests*self.report.budget.page_size)
        if address not in pending and len(pending) < maximum:
            pending[address] = {"source": payload.source, "observation_id": payload.observation_id,
                "raw_reference": "sqlite:observations/"+self.report.investigation_id+"/"+payload.observation_id,
                "status": "pending_item_detail_budget"}
        self.report.stats["asset_enrichment_pending_count"] = len(pending)
        self.report.stats["asset_enrichment_deferred_observations"] = self.report.stats.get("asset_enrichment_deferred_observations", 0)+1
        notice = "NFT item detail ceiling reached; inventory cursors and raw observations retained while history/events continue"
        if notice not in self.report.warnings:
            self.report.warnings.append(notice)

    def upsert_item(self, row: dict, payload: Payload, *, current: bool = True) -> NFTAsset | None:
        address = _address(row.get("address"))
        if not address:
            return None
        asset = self.assets.get(address)
        if asset is None:
            if len(self.assets) >= self.report.budget.max_items:
                self.defer_asset_enrichment(address, payload)
                return None
            asset = NFTAsset(asset_id="ton:nft:" + address, address=address)
            self.assets[address] = asset
            pending = self.report.stats.get("asset_enrichment_pending", {})
            pending.pop(address, None)
            if "asset_enrichment_pending_count" in self.report.stats:
                self.report.stats["asset_enrichment_pending_count"] = len(pending)
        asset.raw[payload.observation_id] = redact(row)
        collection = _address(row.get("collection_address") or row.get("collection"))
        if collection:
            if asset.collection_address and asset.collection_address != collection:
                asset.warnings.append("Provider collection claims conflict; getter verification required")
            elif not asset.collection_address:
                asset.collection_address = collection
        if asset.index is None:
            asset.index = _integer(row.get("index"))
        meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else row.get("content")
        if isinstance(meta, dict):
            snapshot = NFTMetadataSnapshot(source=payload.source, observation_ids=[payload.observation_id],
                raw=redact(meta), normalized=redact(meta), uri=str(meta.get("uri")) if meta.get("uri") else None,
                content_hash=content_hash(meta))
            if not any(m.content_hash == snapshot.content_hash and m.source == snapshot.source for m in asset.metadata):
                asset.metadata.append(snapshot)
            for field in ("name", "description"):
                if not getattr(asset, field) and isinstance(meta.get(field), str):
                    setattr(asset, field, meta[field])
            if isinstance(meta.get("attributes"), (list, dict)):
                asset.attributes = meta["attributes"]
            asset.image_url = safe_public_url(meta.get("image"), allow_ipfs=True) or asset.image_url
            asset.metadata_uri = safe_public_url(meta.get("uri"), allow_ipfs=True) or asset.metadata_uri
            asset.animation_url = (safe_public_url(meta.get("animation_url"), allow_ipfs=True)
                or safe_public_url(meta.get("lottie"), allow_ipfs=True) or asset.animation_url)
            image = safe_public_url(meta.get("image"), allow_ipfs=True)
            if image:
                media = {"url": image, "source": payload.source, "observation_id": payload.observation_id,
                    "role": "metadata_image"}
                if media not in asset.image_sources:
                    asset.image_sources.append(media)
        # TonAPI previews are renditions of this exact item, including DNS
        # items with no metadata.image. Never borrow the collection's image.
        previews = []
        for preview in row.get("previews", []) if isinstance(row.get("previews"), list) else []:
            if not isinstance(preview, dict) or not (url := safe_public_url(preview.get("url"))):
                continue
            size = re.fullmatch(r"(\d{1,5})x(\d{1,5})", str(preview.get("resolution", "")))
            if not size:
                continue
            width, height = map(int, size.groups())
            if width <= 0 or height <= 0:
                continue
            media = {"url": url, "resolution": preview["resolution"], "source": payload.source,
                "observation_id": payload.observation_id, "role": "provider_preview"}
            if media not in asset.image_sources:
                asset.image_sources.append(media)
            previews.append((width * height, url))
        if previews:
            usable = [preview for preview in previews if preview[0] >= 100 * 100]
            asset.thumbnail_url = min(usable or previews)[1]
            if not asset.image_url:
                asset.image_url = max(previews)[1]
        elif asset.image_url and not asset.thumbnail_url:
            asset.thumbnail_url = asset.image_url
        if isinstance(row.get("dns"), str) and row["dns"]:
            asset.dns.update({"name": row["dns"], "status": "provider_reported",
                "source": payload.source, "observation_ids": [payload.observation_id]})
        asset.code_hash = row.get("code_hash") or asset.code_hash
        asset.data_hash = row.get("data_hash") or asset.data_hash
        if "init" in row:
            asset.initialized = bool(row["init"])
        owner = _address(row.get("owner_address") or row.get("owner"))
        if owner and current:
            eid = self.evidence(payload, "provider_current_owner", "Indexed current NFT contract owner; on-chain getter is checked separately")
            assertion = NFTOwnershipAssertion(asset_address=address, owner_address=owner,
                method="indexed_nft_item", status=VerificationStatus.PROVIDER_REPORTED,
                logical_time=_integer(row.get("last_transaction_lt")), evidence_ids=[eid],
                beneficial_owner=_address(row.get("real_owner")), source=payload.source,
                upstream=payload.upstream, observation_ids=[payload.observation_id])
            asset.ownership.append(assertion)
            asset.evidence_ids.append(eid)
            if asset.current_owner_status != VerificationStatus.VERIFIED_ONCHAIN:
                asset.current_owner, asset.current_owner_status = owner, VerificationStatus.PROVIDER_REPORTED
        sale = row.get("sale")
        if isinstance(sale, dict) and current:
            price = money_from_price(sale.get("price"))
            listing = NFTListing(asset_address=address,
                listing_id="ton:nft:listing:" + str(_address(sale.get("address")) or content_hash(sale)),
                status="unknown", price=price, seller_address=_address(sale.get("owner")),
                marketplace=(sale.get("market") or {}).get("name"), marketplace_address=_address(sale.get("market")),
                sale_contract=_address(sale.get("address")), raw=redact(sale),
                evidence_ids=[self.evidence(payload, "current_listing", "Provider sale contract observation; listing price is not a realized sale")])
            if not any(l.listing_id == listing.listing_id for l in asset.listings):
                asset.listings.append(listing)
        if current and row.get("on_sale") is True:
            sale_address = _address(row.get("sale_contract_address") or row.get("auction_contract_address"))
            if sale_address:
                listing = NFTListing(asset_address=address, listing_id="ton:nft:listing:" + sale_address,
                    status="active", seller_address=_address(row.get("real_owner")), sale_contract=sale_address,
                    raw=redact({"on_sale": True, "auction_contract_address": row.get("auction_contract_address"),
                                "sale_contract_address": row.get("sale_contract_address")}),
                    evidence_ids=[self.evidence(payload, "indexed_current_listing", "Toncenter current on_sale flag and sale contract; realized sale not asserted")])
                if not any(l.listing_id == listing.listing_id for l in asset.listings):
                    asset.listings.append(listing)
        return asset

    async def inspect_item(self, address: str, *, row: dict | None = None, payload: Payload | None = None) -> NFTAsset | None:
        if row is not None and payload is not None:
            asset = self.upsert_item(row, payload)
        else:
            asset = self.assets.get(address)
        if address in self._verified_this_run:
            return asset
        self._verified_this_run.add(address)
        if asset and self.incremental:
            asset.current_owner_status = VerificationStatus.UNVERIFIED
            asset.listings = []
        # Independent upstream indexed records retain all unknown provider fields.
        for provider in (self.toncenter, self.tonapi):
            result = await self.optional(provider.item(address, fresh=self.incremental), "NFT item metadata")
            if result:
                rows = result.data.get("nft_items") if provider is self.toncenter else [result.data]
                for item in rows or []:
                    if _address(item.get("address")) == address:
                        asset = self.upsert_item(item, result)
        getter = await self.get_method(address, "get_nft_data")
        if getter:
            try:
                state = nft_data(getter.data)
                if asset is None:
                    if len(self.assets) >= self.report.budget.max_items:
                        self.defer_asset_enrichment(address, getter)
                        return None
                    asset = NFTAsset(asset_id="ton:nft:" + address, address=address)
                    self.assets[address] = asset
                asset.contract_state = {**state, "block_reference": getter.data.get("block_id"),
                                        "last_transaction_id": getter.data.get("last_transaction_id"),
                                        "observed_at": utcnow().isoformat()}
                asset.initialized, asset.index = state["initialized"], state["index"]
                asset.standard, asset.standard_status = "TEP-62 get_nft_data", VerificationStatus.VERIFIED_ONCHAIN
                asset.collection_address = state["collection_address"]
                eid = self.evidence(getter, "onchain_current_owner", "get_nft_data initialized/index/collection/owner decoded from TVM stack",
                                    status=VerificationStatus.VERIFIED_ONCHAIN)
                asset.evidence_ids.append(eid)
                owner = state["owner_address"] if state["initialized"] else None
                asset.ownership.append(NFTOwnershipAssertion(asset_address=address, owner_address=owner,
                    status=VerificationStatus.VERIFIED_ONCHAIN if owner else VerificationStatus.UNVERIFIED,
                    method="get_nft_data", evidence_ids=[eid], block_reference=getter.data.get("block_id"),
                    source=getter.source, upstream=getter.upstream, observation_ids=[getter.observation_id],
                    logical_time=_integer((getter.data.get("last_transaction_id") or {}).get("lt"))))
                asset.current_owner = owner
                asset.current_owner_status = VerificationStatus.VERIFIED_ONCHAIN if owner else VerificationStatus.UNVERIFIED
                if state["collection_address"]:
                    collection = await self.inspect_collection(state["collection_address"])
                    expected = await self.get_method(state["collection_address"],
                        "get_nft_address_by_index", [["num", str(state["index"])]])
                    if expected:
                        resolved = stack_address(expected.data["stack"][0])
                        status = VerificationStatus.VERIFIED_ONCHAIN if resolved == address else VerificationStatus.CONFLICT
                        asset.collection_status = status
                        asset.evidence_ids.append(self.evidence(expected, "collection_membership",
                            "Collection get_nft_address_by_index equals item" if resolved == address else "Collection returns a different NFT item for this index", status=status))
                    content = await self.get_method(state["collection_address"], "get_nft_content",
                        [["num", str(state["index"])], ["cell", {"bytes": state["individual_content_boc"]}]])
                    if content and content.data.get("stack"):
                        boc = stack_boc(content.data["stack"][0])
                        try:
                            uri = content_uri(boc)
                        except ValueError:
                            uri = None
                        asset.metadata.append(NFTMetadataSnapshot(source=content.source,
                            observation_ids=[content.observation_id], content_boc=boc,
                            uri=safe_public_url(uri, allow_ipfs=True), raw={"get_nft_content": redact(content.data)}))
                        asset.metadata_uri = safe_public_url(uri, allow_ipfs=True) or asset.metadata_uri
                self.classify_collectible(asset)
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                self.report.warnings.append(f"{address}: unsupported NFT get stack ({type(exc).__name__}); raw preserved")
                if asset:
                    asset.warnings.append("NFT getter stack is unsupported; on-chain owner/collection not asserted")
        elif asset:
            asset.warnings.append("Current owner is provider-reported; get_nft_data verification unavailable")
            self.classify_collectible(asset)
        if asset:
            if asset.kind == "domain":
                await self.enrich_domain_metadata(asset)
            self.corroborate_owner(asset)
            if asset.current_owner and asset.current_owner_status == VerificationStatus.VERIFIED_ONCHAIN:
                await self.inspect_owner_account(asset)
            await self.enrich_market_contracts(asset)
        self.snapshot()
        return asset

    def corroborate_owner(self, asset: NFTAsset) -> None:
        """Compare independent indexed claims without promoting them to getters."""
        current_observations = set(self.observations)
        indexed = [claim for claim in asset.ownership if claim.method == "indexed_nft_item"
                   and any(oid in current_observations for oid in claim.observation_ids)]
        # Only claims obtained in this run may corroborate fresh ownership.
        indexed = [claim for claim in indexed if claim.observed_at >= self.report_run_started]
        matches = [claim for claim in indexed if claim.owner_address == asset.current_owner]
        conflicts = [claim for claim in indexed if claim.owner_address != asset.current_owner]
        upstreams = sorted({claim.upstream for claim in matches if claim.upstream})
        asset.owner_corroboration = {"status": "conflict" if conflicts else "corroborated" if len(upstreams) >= 2 else "single_upstream" if upstreams else "unavailable",
            "matching_upstreams": upstreams, "independent_upstream_count": len(upstreams),
            "evidence_ids": list(dict.fromkeys(eid for claim in matches for eid in claim.evidence_ids)),
            "conflicting_claims": [claim.model_dump(mode="json") for claim in conflicts],
            "note": "Indexer agreement corroborates current getter; independent cryptographic state proof is not performed"}
        if conflicts and asset.current_owner_status == VerificationStatus.VERIFIED_ONCHAIN:
            asset.warnings.append("Indexed owner differs from fresh get_nft_data; possible stale index/state change, getter retained")

    async def inspect_owner_account(self, asset: NFTAsset) -> None:
        owner = asset.current_owner
        if owner in self._owner_accounts:
            asset.owner_account = self._owner_accounts[owner]
            asset.raw["owner_account"] = asset.owner_account
            return
        payload = await self.optional(self.tonapi.account(owner), "NFT owner account classification")
        account = {"address": owner, "account_type": "unknown", "classification_status": "unknown"}
        if payload and _address(payload.data.get("address")) == owner:
            eid = self.evidence(payload, "owner_account_classification",
                "TonAPI account interfaces/is_wallet classification; not proof of person or wallet control")
            is_wallet = payload.data.get("is_wallet")
            account.update({"account_type": "wallet" if is_wallet is True else "contract" if is_wallet is False and payload.data.get("status") == "active" else "unknown",
                "classification_status": "provider_reported", "source": payload.source, "upstream": payload.upstream,
                "evidence_ids": [eid], "observation_id": payload.observation_id,
                "status": payload.data.get("status"), "interfaces": payload.data.get("interfaces") or [],
                "is_wallet": is_wallet, "raw": payload.data})
        self._owner_accounts[owner] = account
        asset.owner_account = account
        asset.raw["owner_account"] = account

    async def enrich_market_contracts(self, asset: NFTAsset) -> None:
        for listing in asset.listings:
            if not listing.sale_contract or listing.raw.get("sale_contract_enriched"):
                continue
            payload = await self.optional(self.toncenter.sale_contract(listing.sale_contract), "NFT sale/auction contract state")
            if not payload:
                continue
            rows = [row for row in payload.data.get("nft_sales", []) if _address(row.get("nft_address")) == asset.address
                    and _address(row.get("address")) == listing.sale_contract]
            for row in rows:
                eid = self.evidence(payload, "indexed_sale_contract_state", "Current Getgems sale/auction contract state; not a completed sale history")
                listing.evidence_ids = list(dict.fromkeys(listing.evidence_ids + [eid]))
                listing.marketplace_address = _address(row.get("marketplace_address")) or listing.marketplace_address
                listing.seller_address = _address(row.get("nft_owner_address")) or listing.seller_address
                listing.raw["sale_contract_enriched"] = redact(row)
                # details schemas vary by marketplace/version. Preserve every
                # field without guessing price units or completion semantics.
                asset.market_observations.append(NFTMarketObservation(kind="auction" if "auction" in str(row.get("type", "")).lower() else "listing",
                    source=payload.source, evidence_ids=[eid], raw=redact(row)))

    async def inspect_collection(self, address: str) -> NFTCollection:
        collection = self.collections.get(address)
        if collection is None:
            collection = NFTCollection(address=address)
            self.collections[address] = collection
        if address in self._collection_this_run:
            return collection
        self._collection_this_run.add(address)
        for provider in (self.tonapi, self.toncenter):
            result = await self.optional(provider.collection(address), "NFT collection metadata")
            if result:
                rows = result.data.get("nft_collections") if provider is self.toncenter else [result.data]
                for row in rows or []:
                    if _address(row.get("address")) != address:
                        continue
                    collection.raw[result.observation_id] = redact(row)
                    meta = row.get("metadata") or row.get("collection_content") or {}
                    collection.metadata.update(redact(meta))
                    collection.name = meta.get("name") or collection.name
                    collection.code_hash = row.get("code_hash") or collection.code_hash
                    collection.next_item_index = _integer(row.get("next_item_index"))
                    collection.owner_address = _address(row.get("owner_address") or row.get("owner"))
                    collection.content_boc = row.get("raw_collection_content") or collection.content_boc
        getter = await self.get_method(address, "get_collection_data")
        if getter:
            try:
                state = collection_data(getter.data)
                collection.next_item_index, collection.owner_address = state["next_item_index"], state["owner_address"]
                collection.content_boc, collection.verification = state["content_boc"], VerificationStatus.VERIFIED_ONCHAIN
                collection.evidence_ids.append(self.evidence(getter, "onchain_collection_data",
                    "Collection get_collection_data TVM stack decoded", status=VerificationStatus.VERIFIED_ONCHAIN))
            except (ValueError, TypeError, IndexError):
                self.report.warnings.append(f"{address}: specialized collection getter layout unsupported")
        known = registry_entry(address, self.registry)
        if known:
            kind, data = known
            collection.known_registry_kind, collection.registry_source = kind, data["source"]
            collection.name = collection.name or data["name"]
        return collection

    async def enrich_domain_metadata(self, asset: NFTAsset) -> None:
        """DNS destination and expiry are records, never NFT ownership proof."""
        name = asset.dns.get("name") or asset.name
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.ton", name.lower()):
            return
        details = await self.optional(self.tonapi.domain(name.lower()), "TON DNS metadata")
        if not details or _address((details.data.get("item") or {}).get("address")) != asset.address:
            return
        asset.dns.update({"name": name.lower(), "status": "provider_reported", "source": details.source,
            "observation_ids": list(dict.fromkeys(asset.dns.get("observation_ids", []) + [details.observation_id]))})
        if details.data.get("expiring_at") is not None:
            asset.dns["expiring_at"] = details.data["expiring_at"]
        resolution = await self.optional(self.tonapi.resolve_domain(name.lower()), "TON DNS resolution")
        if resolution:
            asset.dns.update({"resolution": redact(resolution.data), "resolution_source": resolution.source,
                "resolution_observation_id": resolution.observation_id,
                "resolution_role": "DNS destination; distinct from NFT owner"})

    def classify_collectible(self, asset: NFTAsset) -> None:
        known = registry_entry(asset.collection_address, self.registry)
        if not known or asset.collection_status != VerificationStatus.VERIFIED_ONCHAIN:
            return
        kind, entry = known
        asset.kind = "gift" if kind.startswith("gift:") else kind
        asset.category_provenance = {"kind": asset.kind, "collection_address": asset.collection_address,
            "registry_source": entry["source"], "collection_status": str(asset.collection_status),
            "note": "Category derives from trusted collection and existing onchain membership getter"}
        if asset.kind not in {"gift", "username"}:
            return
        collectible = TelegramCollectible(asset_address=asset.address, kind=asset.kind, collection_verified=True,
            ownership_evidence_ids=[e for a in asset.ownership if a.status == VerificationStatus.VERIFIED_ONCHAIN for e in a.evidence_ids],
            notes=["NFT ownership does not establish Telegram assignment, profile display, or personal control",
                   "Trusted collection registry attribution: " + entry["source"]])
        if asset.kind == "username":
            name = (asset.name or "").lstrip("@").removesuffix(".t.me")
            if name and all(c.isalnum() or c == "_" for c in name):
                collectible.username = name
                collectible.public_url = "https://fragment.com/username/" + name
        else:
            number = re.search(r"#(\d{1,20})\s*$", asset.name or "")
            if number:
                collectible.gift_number = int(number[1])
            for snapshot in asset.metadata:
                meta = snapshot.normalized
                url = meta.get("external_url") or meta.get("external_link")
                parsed = urlsplit(url) if safe_public_url(url) else None
                if (safe_public_url(url) and parsed and parsed.scheme == "https" and parsed.hostname == "t.me"
                        and parsed.port in (None, 443)
                        and re.fullmatch(r"/nft/[A-Za-z][A-Za-z0-9]*-\d+", parsed.path)
                        and not parsed.query and not parsed.fragment):
                    collectible.public_url = url
                    collectible.collectible_id = str(url).split("/nft/", 1)[-1]
                attrs = meta.get("attributes") or []
                if isinstance(attrs, list):
                    for attr in attrs:
                        if isinstance(attr, dict):
                            trait = str(attr.get("trait_type") or attr.get("type") or "")
                            if not trait or attr.get("value") is None:
                                continue
                            collectible.gift_attributes[trait] = attr.get("value")
                            for key in ("rarity", "rarity_percentage", "rarity_per_mille"):
                                if key in attr:
                                    collectible.rarity[trait] = {key: attr[key], "status": "provider_metadata", "source": snapshot.source}
                elif isinstance(attrs, dict):
                    collectible.gift_attributes.update(attrs)
        asset.telegram = collectible

    def add_event(self, event: NFTEvent) -> None:
        self.raw_records += 1
        if event.event_id in self.events:
            merge_event(self.events[event.event_id], event)
            self.duplicates += 1
        else:
            if len(self.events) >= self.report.budget.max_events:
                raise BudgetExceeded("NFT event budget reached")
            self.events[event.event_id] = event

    def parse_transfer(self, row: dict, payload: Payload, occurrence: int = 0) -> None:
        asset = _address(row.get("nft_address"))
        if not asset:
            return
        if asset not in self.assets:
            self.upsert_item({"address": asset, "collection_address": row.get("nft_collection")}, payload, current=False)
        tx, lt = canonical_hash(row.get("transaction_hash")), _integer(row.get("transaction_lt"))
        aborted = row.get("transaction_aborted")
        status = "success" if aborted is False else "failed" if aborted is True else "unknown"
        eid = self.evidence(payload, "indexed_nft_transfer",
            "Toncenter indexed transfer, old/new owner, hash/LT and aborted status; not a sale",
            transaction_hash=tx, logical_time=lt)
        event = NFTEvent(event_id=event_identity(payload.source, asset, "transfer", transaction_hash=tx,
            logical_time=lt, message_hash=row.get("message_hash"), query_id=str(row.get("query_id")) if row.get("query_id") is not None else None,
            raw=row, occurrence=occurrence), asset_address=asset, event_type="transfer", status=status,
            from_address=_address(row.get("old_owner")), to_address=_address(row.get("new_owner")),
            timestamp=ton_datetime(row.get("transaction_now")), transaction_hash=tx,
            logical_time=lt, trace_id=canonical_hash(row.get("trace_id")), message_hash=row.get("message_hash"),
            query_id=str(row.get("query_id")) if row.get("query_id") is not None else None,
            money=money_from_price(row.get("forward_amount"), default_currency="TON", default_decimals=9),
            evidence_ids=[eid], observation_ids=[payload.observation_id], raw=redact(row))
        self.add_event(event)

    def parse_operation(self, row: dict, payload: Payload, occurrence: int = 0) -> None:
        item = row.get("item") or {}
        asset = _address(item.get("address"))
        if not asset:
            return
        self.upsert_item(item, payload, current=False)
        operation = str(row.get("operation", "")).lower()
        kind = "transfer" if operation == "transfer" else "mint" if operation in {"mint", "deploy"} else "unknown"
        tx, lt = canonical_hash(row.get("transaction_hash")), _integer(row.get("lt"))
        eid = self.evidence(payload, "nft_operation", "TonAPI indexed NFT operation; does not imply current holding or sale",
                            transaction_hash=tx, logical_time=lt)
        # This schema does not expose aborted/success explicitly; unknown is
        # intentional. Independent Toncenter transfers provide completed state.
        self.add_event(NFTEvent(event_id=event_identity(payload.source + ":operation", asset, kind,
            transaction_hash=tx, logical_time=lt, raw=row, occurrence=occurrence), asset_address=asset,
            event_type=kind, status="unknown", timestamp=ton_datetime(row.get("utime")),
            transaction_hash=tx, logical_time=lt, from_address=_address(row.get("source")),
            to_address=_address(row.get("destination")), evidence_ids=[eid], observation_ids=[payload.observation_id], raw=redact(row)))

    def parse_action_event(self, row: dict, payload: Payload, occurrence: int = 0,
                           *, item_context: str | None = None) -> None:
        trace = canonical_hash(row.get("event_id"))
        for index, action in enumerate(row.get("actions") or []):
            action_type = str(action.get("type", ""))
            details = action.get(action_type) or {}
            if not isinstance(details, dict):
                continue
            if action_type == "NftItemTransfer":
                asset = _address(details.get("nft"))
                kind, sender, recipient = "transfer", _address(details.get("sender")), _address(details.get("recipient"))
                price = None  # NFT transfers are never priced from unrelated TON actions.
            elif action_type == "NftPurchase":
                nft = details.get("nft") or {}
                asset = _address(nft.get("address")) if isinstance(nft, dict) else _address(nft)
                if asset and isinstance(nft, dict):
                    self.upsert_item(nft, payload, current=False)
                kind, sender, recipient = "sale", _address(details.get("seller")), _address(details.get("buyer"))
                price = money_from_price(details.get("amount"))
            elif action_type in {"NftItemMint", "NftMint"}:
                asset = _address(details.get("nft"))
                kind, sender, recipient = "mint", None, _address(details.get("recipient"))
                price = None
            else:
                # Unrecognized NFT actions retain their exact item association
                # if present, without inventing semantics from summary text.
                asset = _address(details.get("nft") or details.get("item"))
                kind, sender, recipient, price = "unknown", None, None, None
                if not asset and item_context:
                    parties = {_address(details.get(key)) for key in ("sender", "recipient", "contract", "executor", "account", "address")}
                    if item_context in parties:
                        asset, kind = item_context, "contract_interaction"
                        sender, recipient = _address(details.get("sender")), _address(details.get("recipient") or details.get("contract"))
                        if action_type == "TonTransfer":
                            price = money_from_price(details.get("amount"), default_currency="TON", default_decimals=9)
                if not asset:
                    continue
            if not asset:
                continue
            if asset not in self.assets:
                self.upsert_item({"address": asset}, payload, current=False)
            progress = row.get("in_progress")
            status = "pending" if progress is True else "success" if action.get("status") == "ok" else "failed" if action.get("status") == "failed" else "unknown"
            if kind == "sale" and not (sender and recipient and price):
                status = "unknown"
            transactions = action.get("base_transactions") or []
            tx = canonical_hash(transactions[0]) if len(transactions) == 1 else None
            lt = _integer(row.get("lt"))
            eid = self.evidence(payload, "provider_nft_" + kind,
                "TonAPI trace interpretation action " + str(index) + "; action schema can change; transaction hash is not trace ID",
                transaction_hash=tx, logical_time=lt)
            self.add_event(NFTEvent(event_id=event_identity(payload.source + ":action", asset, kind,
                transaction_hash=tx, trace_id=trace, logical_time=lt, action_index=index,
                raw=action, occurrence=occurrence), asset_address=asset, event_type=kind, status=status,
                from_address=sender, to_address=recipient, timestamp=ton_datetime(row.get("timestamp")),
                transaction_hash=tx, trace_id=trace, logical_time=lt, action_index=index,
                money=price, marketplace=details.get("auction_type"),
                evidence_ids=[eid], observation_ids=[payload.observation_id],
                provider_event_ids=[str(row.get("event_id"))] if row.get("event_id") else [], raw=redact({"action": action,
                    "in_progress": progress, "base_transactions": transactions, "event_extra": row.get("extra")})))

    def coverage(self, stream: str, provider: Any) -> CollectionCoverage:
        existing = next((c for c in self.report.coverage if c.scope == stream and c.source == provider.name), None)
        if existing:
            return existing
        out = CollectionCoverage(scope=stream, source=provider.name, upstream=provider.upstream,
                                 status=CoverageStatus.PARTIAL, coverage_status="PARTIAL",
                                 limit=self.report.budget.max_pages,
                                 notes=["Indexer pagination exhaustion does not establish full blockchain history"])
        self.report.coverage.append(out)
        return out

    async def page_stream(self, stream: str, provider: Any, fetch, row_key: str, parser,
                          *, cursor_kind: str = "offset") -> None:
        self._pending_streams.pop(stream, None)
        if self.continuous and stream in self._resume_tail_states:
            tail = stream + ":retained_tail"
            self.report.checkpoints[tail] = self._resume_tail_states.pop(stream)
            self._tail_aliases[tail] = stream
            self._pending_streams[tail] = (tail, provider, fetch, row_key, parser, cursor_kind)
        checkpoint = self.report.checkpoints.get(stream, {})
        if checkpoint.get("exhausted"):
            return
        coverage = self.coverage(stream, provider)
        cursor = checkpoint.get("cursor", 0 if cursor_kind == "offset" else None)
        previous_hash = checkpoint.get("page_hash")
        inventory_stream = stream.startswith("inventory:")
        if inventory_stream and len(self.assets) >= self.report.budget.max_items:
            coverage.status, coverage.coverage_status = CoverageStatus.BUDGET_LIMIT, "TRUNCATED"
            coverage.gap_reason = "Inventory item-detail ceiling reached; other history streams continue"
            coverage.next_cursor = str(cursor) if cursor is not None else None
            self.report.checkpoints[stream] = {**checkpoint, "cursor": cursor, "exhausted": False,
                "item_detail_limit_reached": True}
            self.snapshot()
            return
        if self.continuous and coverage.pages >= self.report.budget.max_pages:
            coverage.status, coverage.coverage_status = CoverageStatus.BUDGET_LIMIT, "TRUNCATED"
            coverage.gap_reason = "Per-stream page ceiling reached; cursor retained"
            self.snapshot()
            return
        for _ in range(self.report.budget.max_pages):
            try:
                payload = await fetch(cursor, self.report.budget.page_size)
                rows = payload.data.get(row_key)
                if not isinstance(rows, list):
                    coverage.status, coverage.coverage_status = CoverageStatus.ERROR, "UNAVAILABLE"
                    coverage.gap_reason = "Provider response does not contain expected " + row_key + " array"
                    break
                digest = content_hash(rows)
                if rows and previous_hash == digest:
                    coverage.status, coverage.coverage_status = CoverageStatus.PARTIAL, "PARTIAL"
                    coverage.gap_reason = "Repeated page; cursor did not progress"
                    break
                coverage.pages += 1
                coverage.observation_ids.append(payload.observation_id)
                # Ordinal is per identical complete record within one page; no
                # transaction/action is discarded merely for sharing tx hash.
                occurrences: Counter = Counter()
                event_count_before, duplicates_before = len(self.events), self.duplicates
                inventory_overflow_index = None
                for row_index, row in enumerate(rows):
                    if (inventory_stream and inventory_overflow_index is None and len(self.assets) >= self.report.budget.max_items
                            and (address := _address(row.get("address"))) and address not in self.assets):
                        inventory_overflow_index = row_index
                    fingerprint = content_hash(row)
                    parser(row, payload, occurrences[fingerprint])
                    occurrences[fingerprint] += 1
                    coverage.records += 1
                    lt = _integer(row.get("transaction_lt", row.get("lt")))
                    date = ton_datetime(row.get("transaction_now", row.get("timestamp", row.get("utime"))))
                    if lt is not None:
                        coverage.oldest_lt = min(coverage.oldest_lt, lt) if coverage.oldest_lt is not None else lt
                        coverage.newest_lt = max(coverage.newest_lt, lt) if coverage.newest_lt is not None else lt
                    if date:
                        coverage.oldest_timestamp = min(coverage.oldest_timestamp, date) if coverage.oldest_timestamp else date
                        coverage.newest_timestamp = max(coverage.newest_timestamp, date) if coverage.newest_timestamp else date
                coverage.unique_events += len(self.events)-event_count_before
                coverage.duplicate_records += self.duplicates-duplicates_before
                if cursor_kind == "offset":
                    next_cursor = int(cursor or 0) + len(rows)
                    exhausted = len(rows) < self.report.budget.page_size
                    coverage.notes = list(dict.fromkeys(coverage.notes + ["Offset pagination may shift during live ownership changes; missing ranges are UNKNOWN"]))
                else:
                    next_cursor = _integer(payload.data.get("next_from"))
                    exhausted = not rows or not next_cursor
                    if rows and next_cursor and cursor is not None and next_cursor >= int(cursor):
                        coverage.gap_reason = "Non-decreasing logical-time cursor"
                        exhausted = False
                        next_cursor = cursor
                if inventory_overflow_index is not None:
                    # The provider page is durable, but not every row received
                    # a heavy asset model. Resume this exact page if the caller
                    # later raises the detail ceiling; never claim exhaustion.
                    exhausted = False
                    next_cursor = cursor
                coverage.next_cursor = None if exhausted else str(next_cursor)
                self.report.checkpoints[stream] = {"cursor": next_cursor, "exhausted": exhausted,
                                                    "page_hash": previous_hash if inventory_overflow_index is not None else digest,
                                                    "pages": coverage.pages}
                if inventory_overflow_index is not None:
                    self.report.checkpoints[stream].update({"item_detail_limit_reached": True,
                        "resume_row_index": inventory_overflow_index,
                        "raw_page_observation_id": payload.observation_id})
                    coverage.status, coverage.coverage_status = CoverageStatus.BUDGET_LIMIT, "TRUNCATED"
                    coverage.gap_reason = "Inventory item-detail ceiling reached within durable provider page; history continues"
                if stream in self._tail_aliases:
                    tails = self.report.checkpoints.setdefault("retained_history_tails", {})
                    base = self._tail_aliases[stream]
                    if exhausted:
                        tails.pop(base, None)
                    else:
                        tails[base] = dict(self.report.checkpoints[stream])
                if exhausted:
                    coverage.status, coverage.coverage_status = CoverageStatus.INDEXER_EXHAUSTED, "PARTIAL"
                    coverage.gap_reason = "Indexer exhausted; chain completeness not guaranteed"
                sliced = self.priority_scheduling and not exhausted and next_cursor != cursor
                if sliced:
                    coverage.status, coverage.coverage_status = CoverageStatus.PARTIAL, "TRUNCATED"
                    coverage.gap_reason = ("Cooperative page slice; continuation queued in this investigation"
                        if self.continuous else "Priority time slice after one page; next cursor saved for resume while other streams are collected")
                    if self.continuous:
                        self._pending_streams[stream] = (stream, provider, fetch, row_key, parser, cursor_kind)
                self.snapshot()
                await self.notify_checkpoint()
                self.controller.emit_progress("page_collected", source=provider.name, scope=stream,
                    pages=coverage.pages, records=coverage.records, unique_events=coverage.unique_events,
                    cursor=coverage.next_cursor, coverage_status=coverage.coverage_status,
                    exhausted=exhausted)
                if exhausted or next_cursor == cursor or sliced:
                    break
                previous_hash, cursor = digest, next_cursor
            except ProviderError as exc:
                coverage.status, coverage.coverage_status = CoverageStatus.ERROR, "PARTIAL" if coverage.records else "UNAVAILABLE"
                coverage.gap_reason = str(exc)
                self.report.warnings.append(str(exc))
                self.snapshot()
                self.controller.emit_progress("stream_stopped", source=provider.name, scope=stream,
                    pages=coverage.pages, records=coverage.records, cursor=coverage.next_cursor,
                    coverage_status=coverage.coverage_status, status=exc.status)
                break
            except BudgetExceeded:
                coverage.status, coverage.coverage_status = CoverageStatus.BUDGET_LIMIT, "TRUNCATED"
                coverage.gap_reason = "Item/event/request/deadline budget reached; resume checkpoint preserved"
                self.snapshot()
                self.controller.emit_progress("stream_stopped", source=provider.name, scope=stream,
                    pages=coverage.pages, records=coverage.records, cursor=coverage.next_cursor,
                    coverage_status=coverage.coverage_status, status="budget_limit")
                raise
        else:
            coverage.status, coverage.coverage_status = CoverageStatus.BUDGET_LIMIT, "TRUNCATED"
            coverage.gap_reason = "Page budget reached; next cursor saved"
            self.snapshot()

    async def history(self, address: str, scope: str) -> None:
        tc_stream = f"history:{scope}:{address}:toncenter"
        await self.page_stream(tc_stream, self.toncenter,
            lambda cursor, limit: self.toncenter.transfers(address, scope=scope, offset=int(cursor or 0), limit=limit),
            "nft_transfers", self.parse_transfer)
        # Events retain all actions of each trace and explicit market prices.
        # Only exact NFT addresses inside supported actions become NFT events.
        await self.page_stream(f"history:{scope}:{address}:tonapi_events", self.tonapi,
            lambda cursor, limit: self.tonapi.events(address, before_lt=cursor, limit=limit),
            "events", lambda row, payload, occurrence: self.parse_action_event(row, payload, occurrence,
                         item_context=address if scope == "item" else None), cursor_kind="lt")
        await self.page_stream(f"history:{scope}:{address}:tonapi_operations", self.tonapi,
            lambda cursor, limit: self.tonapi.operations(address, before_lt=cursor, limit=limit),
            "operations", self.parse_operation, cursor_kind="lt")

    async def inventory(self, address: str, scope: str) -> None:
        for provider in (self.toncenter, self.tonapi):
            await self.page_stream(f"inventory:{scope}:{address}:{provider.name}", provider,
                lambda cursor, limit, p=provider: p.items(address, scope=scope, offset=int(cursor or 0), limit=limit),
                "nft_items", lambda row, payload, occurrence: self.upsert_item(row, payload))

    async def resolve_address_scope(self, query: NormalizedQuery, forced: str) -> str:
        if forced != "auto":
            return "item" if forced == "trace" else forced
        if query.scope != "auto":
            return query.scope
        item = await self.optional(self.toncenter.item(query.value), "NFT item identification")
        if item and any(_address(row.get("address")) == query.value for row in item.data.get("nft_items", [])):
            return "item"
        collection = await self.optional(self.toncenter.collection(query.value), "NFT collection identification")
        if collection and any(_address(row.get("address")) == query.value for row in collection.data.get("nft_collections", [])):
            return "collection"
        # Indexed absence isn't sufficient to reject a specialized NFT item.
        getter = await self.get_method(query.value, "get_nft_data")
        if getter:
            try:
                nft_data(getter.data)
                return "item"
            except ValueError:
                pass
        collection_getter = await self.get_method(query.value, "get_collection_data")
        if collection_getter:
            try:
                collection_data(collection_getter.data)
                return "collection"
            except ValueError:
                pass
        self.report.warnings.append("Contract was not identified as indexed/standard NFT or collection; investigating available wallet inventory without asserting wallet contract type")
        return "wallet"

    async def run(self, query: NormalizedQuery, scope: str) -> None:
        wallet = None
        if query.kind == "address":
            actual_scope = await self.resolve_address_scope(query, scope)
            self.report.scope = actual_scope if scope != "trace" else "trace"
            self.report.discovery = DiscoveryResult(normalized_query=query.value, query_kind="address", status="resolved",
                candidates=[DiscoveryCandidate(address=query.value, reason="validated TON contract address; scope " + actual_scope)])
            if actual_scope == "item":
                asset = await self.inspect_item(query.value)
                if asset is None:
                    self.report.discovery.status = "unresolved"
                    self.report.status = "unresolved"
                    self.report.warnings.append("Requested item was not identified as an NFT; generic account events are not treated as NFT history")
                    self.snapshot(force=True)
                    return
                self.snapshot()
                await self.notify_target_resolved()
                self.progress("primary_history", address=query.value)
                await self.history(query.value, "item")
                if self.report.mode == "deep":
                    wallet = await self.primary_owner_inventory()
                if wallet:
                    self.progress("owner_history", address=wallet)
                    await self.history(wallet, "wallet")
            elif actual_scope == "collection":
                await self.inspect_collection(query.value)
                await self.inventory(query.value, "collection")
                await self.history(query.value, "collection")
            else:
                wallet = query.value
                await self.notify_target_resolved(wallet)
                if self.priority_scheduling:
                    self.progress("wallet_history", address=wallet)
                    await self.history(wallet, "wallet")
                    self.progress("wallet_inventory", address=wallet)
                    await self.inventory(wallet, "wallet")
                else:
                    self.progress("wallet_inventory", address=wallet)
                    await self.inventory(wallet, "wallet")
                    self.progress("wallet_history", address=wallet)
                    await self.history(wallet, "wallet")
        else:
            public_candidates = await self.public_gift(query) if query.kind == "gift" else []
            if public_candidates:
                discovery = DiscoveryResult(normalized_query=query.value, query_kind="gift",
                    status="resolved" if len(public_candidates) == 1 else "ambiguous", candidates=public_candidates)
            else:
                discovery = await discover_named_asset(query, self.toncenter, self.tonapi, self.evidence,
                    registry=self.registry, max_pages=self.report.budget.max_pages, page_size=self.report.budget.page_size,
                    get_method=self.get_method)
            self.report.discovery = discovery
            self.report.warnings.extend(discovery.warnings)
            if discovery.status != "resolved":
                self.report.status = "unresolved"
                self.snapshot(force=True)
                return
            for candidate in discovery.candidates:
                asset = await self.inspect_item(candidate.address)
                if asset:
                    candidate.collection_address, candidate.index = asset.collection_address, asset.index
                    candidate.verification = asset.collection_status
                    asset.evidence_ids = list(dict.fromkeys(asset.evidence_ids + candidate.evidence_ids))
                    if asset.initialized is not True or asset.collection_status != VerificationStatus.VERIFIED_ONCHAIN:
                        discovery.status = "unresolved"
                        discovery.warnings.append("Named NFT candidate is not verified initialized with consistent collection; preserved as candidate only")
                    if query.kind == "username":
                        expected = ton_canonical_address(self.registry["username"]["address"])
                        if asset.collection_address != expected or asset.collection_status != VerificationStatus.VERIFIED_ONCHAIN:
                            discovery.status = "unresolved"
                            discovery.warnings.append("Username item not verified against trusted collectible username collection")
                    if query.kind == "domain":
                        expected = ton_canonical_address(self.registry["domain"]["address"])
                        if asset.collection_address != expected or asset.collection_status != VerificationStatus.VERIFIED_ONCHAIN:
                            discovery.status = "unresolved"
                            discovery.warnings.append("Domain item not verified against trusted .ton DNS collection")
                        try:
                            expected_index = ton_dns_item_index(query.value)
                        except ValueError:
                            discovery.status = "unresolved"
                            asset.raw["input_name_binding"] = {"query": query.value, "status": "unknown",
                                "reason": "Specialized/delegated subdomain index proof is unsupported"}
                            discovery.warnings.append("Domain-to-item binding is UNKNOWN for specialized/delegated subdomains; no owner selected for this name")
                        else:
                            matches = asset.standard_status == VerificationStatus.VERIFIED_ONCHAIN and asset.index == expected_index
                            asset.raw["input_name_binding"] = {"query": query.value,
                                "method": "official DNS slice_hash(label)", "expected_index": expected_index,
                                "observed_index": asset.index, "status": "verified_onchain" if matches else "conflict"}
                            if not matches:
                                discovery.status = "unresolved"
                                candidate.verification = VerificationStatus.CONFLICT
                                discovery.warnings.append("Indexed domain candidate does not match deterministic .ton name index; no owner selected for this name")
                    if query.kind == "gift" and asset.standard_status == VerificationStatus.VERIFIED_ONCHAIN:
                        asset.kind = "gift"
                        asset.telegram = asset.telegram or TelegramCollectible(asset_address=asset.address, kind="gift",
                            collection_verified=asset.collection_status == VerificationStatus.VERIFIED_ONCHAIN,
                            notes=["Public gift-to-NFT link verified separately from profile display; no personal identity attribution"])
                        asset.telegram.public_url = query.public_url
                        asset.telegram.collectible_id = query.value
                        public_row = next((r for r in self.report.public_collectibles if r.get("identifier") == query.value), {})
                        asset.telegram.gift_attributes.update(public_row.get("attributes", {}))
                        asset.telegram.metadata_associations.extend(public_row.get("public_profile_mentions", []))
                    self.report.scope = "trace" if scope == "trace" else "item"
                    self.snapshot()
                    await self.notify_target_resolved()
                    self.progress("primary_history", address=asset.address)
                    await self.history(asset.address, "item")
                    if self.report.mode == "deep" and discovery.status == "resolved":
                        wallet = await self.primary_owner_inventory()
                    if wallet:
                        self.progress("owner_history", address=wallet)
                        await self.history(wallet, "wallet")
                else:
                    discovery.status = "unresolved"
                    discovery.warnings.append("Exact candidate could not be verified as an active NFT; no owner selected")
        # Inventories/history may reveal historical items: fresh getter determines
        # current holding separately; an old transfer never supplies current owner.
        self.progress("item_verification")
        for address in list(self.assets):
            if address not in self._verified_this_run:
                await self.inspect_item(address)
                if self.continuous:
                    break
        if self.report.mode == "deep" and self.report.scope == "collection":
            # The collection contract's own traces do not include all item
            # marketplace actions. Deep mode follows discovered item contracts.
            for address in list(self.assets):
                await self.history(address, "item")
        self.progress("transaction_details")
        await self.enrich_transactions(max_per_turn=1 if self.continuous else None)
        # An ordinary wallet inventory/history does not authorize collecting
        # every counterparty's unrelated NFT activity. Explicit item tracing
        # remains available in the existing engine and shared request budget.
        if (scope == "trace" or self.report.mode == "deep" and self.report.scope == "item") and self.report.budget.trace_depth:
            self.progress("related_wallet_tracing")
            await self.trace_related_wallets()
        elif self.report.scope == "wallet":
            self.report.stats["related_wallet_tracing"] = {
                "status": "not_requested", "scope": "target_wallet_only",
                "note": "Current inventory and NFT history concern the target wallet; unrelated counterparty NFT histories are not collected. Target source coverage remains partial."}
        if self.continuous:
            self.progress("continuous_streams", streams=len(self._pending_streams))
            await self.drain_priority_streams()
        self.snapshot()

        self.progress("analytics")
        analyze_report(self.report, wallet)
        self.events = {event.event_id: event for event in self.report.events}
        if self.report.portfolio:
            self.report.portfolio.intersections = self.store.find_intersections(wallet,
                self.report.portfolio.current_holdings + self.report.portfolio.historical_holdings,
                exclude_id=self.report.investigation_id)
        self.report.status = "unresolved" if self.report.discovery and self.report.discovery.status != "resolved" else "partial" if (self.report.warnings or any(not c.complete for c in self.report.coverage)) else "completed"
        self.report.warnings = list(dict.fromkeys(self.report.warnings))
        self.snapshot()

    async def primary_owner_inventory(self) -> str | None:
        """Deep item searches share one budget/snapshot with owner inventory."""
        self.snapshot()
        resolution = resolve_verified_nft_owner(self.report)
        if not resolution:
            return None
        self.report.input_resolution = resolution
        owner = resolution["owner_address"]
        self.progress("owner_inventory", address=owner)
        await self.inventory(owner, "wallet")
        return owner

    async def public_gift(self, query: NormalizedQuery) -> list[DiscoveryCandidate]:
        """Exact official gift page, with an explicit blockchain link only.

        An HTML table labelled Owner is retained as a public profile mention,
        never as the on-chain owner and never as wallet/person attribution.
        """
        from selectolax.parser import HTMLParser
        from urllib.parse import urlsplit, unquote
        result = await self.optional(self.telegram_public.gift(query.gift_slug or "", query.gift_number or ""),
                                     "public Telegram collectible page")
        if result is None:
            return []
        tree = HTMLParser(result.data.get("html", ""))
        attributes, mentions, candidates = {}, [], {}
        for tr in tree.css(".tgme_gift_table tr"):
            header, cell = tr.css_first("th"), tr.css_first("td")
            if not header or not cell:
                continue
            key, value = header.text(strip=True), cell.text(separator=" ", strip=True)
            if key.lower() == "owner":
                mentions.append(value)
            else:
                attributes[key] = value
        eid = self.evidence(result, "public_gift_association",
            "Official Telegram collectible page attributes/profile display; not NFT ownership or person control")
        self.report.public_collectibles.append({"identifier": query.value, "url": query.public_url,
            "attributes": attributes, "public_profile_mentions": mentions, "evidence_ids": [eid],
            "identity_status": "unverified", "onchain_export_status": "unknown"})
        for anchor in tree.css("a[href]"):
            href = safe_public_url(anchor.attributes.get("href"))
            if not href:
                continue
            url = urlsplit(href)
            if url.hostname not in {"tonviewer.com", "tonscan.org", "getgems.io"}:
                continue
            parts = [unquote(p) for p in url.path.split("/") if p]
            addresses = [raw for p in parts if (raw := ton_canonical_address(p))]
            if len(addresses) == 1:
                candidates[addresses[0]] = DiscoveryCandidate(address=addresses[0],
                    reason="Explicit blockchain NFT link on exact official Telegram gift page; getter verification required",
                    evidence_ids=[eid])
        if candidates:
            self.report.public_collectibles[-1]["onchain_export_status"] = "public_contract_link"
        else:
            self.report.warnings.append("Telegram gift page exposes no NFT contract link; profile Owner field is not on-chain ownership")
        return list(candidates.values())

    async def trace_related_wallets(self) -> None:
        seed = set(self.assets)
        visited = set(self.report.checkpoints.get("trace:visited", []))
        frontier = {address for e in self.events.values() if e.asset_address in seed and e.status == "success"
                    and e.event_type in {"transfer", "sale", "mint"}
                    for address in (e.from_address, e.to_address) if address}
        for depth in range(self.report.budget.trace_depth):
            next_frontier = set()
            for wallet in sorted(frontier - visited):
                if len(visited) >= self.report.budget.max_wallets:
                    self.report.warnings.append("Trace wallet budget reached; frontier retained in checkpoint")
                    self.report.checkpoints["trace:frontier"] = sorted(frontier - visited)
                    return
                await self.history(wallet, "wallet")
                visited.add(wallet)
                self.report.checkpoints["trace:visited"] = sorted(visited)
                self.report.checkpoints["trace:depth"] = depth + 1
                self.snapshot()
                next_frontier.update(address for e in self.events.values() if e.asset_address in seed and e.status == "success"
                                     and e.event_type in {"transfer", "sale", "mint"}
                                     for address in (e.from_address, e.to_address) if address)
            frontier = next_frontier

    async def enrich_transactions(self, *, max_per_turn: int | None = None) -> None:
        """Collect transaction fees/block/state/messages for ownership/market events.

        Contract-only activity is retained but does not consume an unbounded
        transaction fanout. Each tx is downloaded once; fee scope is transaction.
        """
        by_hash: dict[str, list[NFTEvent]] = {}
        for event in self.events.values():
            if event.transaction_hash and event.event_type in {"transfer", "sale", "mint"}:
                by_hash.setdefault(event.transaction_hash, []).append(event)
        done = set(self.report.checkpoints.get("transaction_details:done", []))
        coverage = self.coverage("transaction_details", self.toncenter)
        requested = 0
        for tx_hash, events in by_hash.items():
            if tx_hash in done or (self.continuous and tx_hash in self._detail_attempted):
                continue
            if max_per_turn is not None and requested >= max_per_turn:
                return
            if (self._detail_requests if self.continuous else requested) >= self.report.budget.max_transaction_details:
                coverage.status, coverage.coverage_status = CoverageStatus.BUDGET_LIMIT, "TRUNCATED"
                coverage.gap_reason = "Transaction detail budget reached"
                coverage.next_cursor = tx_hash
                self.snapshot()
                return
            requested += 1
            self._detail_requests += 1
            self._detail_attempted.add(tx_hash)
            try:
                result = await self.toncenter.transaction(tx_hash)
            except ProviderError as exc:
                coverage.status, coverage.coverage_status = CoverageStatus.ERROR, "PARTIAL" if coverage.records else "UNAVAILABLE"
                coverage.gap_reason = str(exc)
                self.report.warnings.append("NFT transaction enrichment: " + str(exc))
                continue
            coverage.pages += 1
            coverage.observation_ids.append(result.observation_id)
            matched = [row for row in result.data.get("transactions", []) if canonical_hash(row.get("hash")) == tx_hash]
            if len(matched) != 1:
                coverage.gap_reason = "Transaction lookup missing/ambiguous; indexed history retained"
                continue
            transaction = matched[0]
            coverage.records += 1
            account = _address(transaction.get("account"))
            description = transaction.get("description") or {}
            aborted = description.get("aborted")
            emulated = transaction.get("emulated")
            for event in events:
                eid = self.evidence(result, "nft_transaction_details",
                    "Indexed exact transaction hash; fees are for transaction, block/state/messages preserved",
                    transaction_hash=tx_hash, logical_time=_integer(transaction.get("lt")))
                event.evidence_ids = list(dict.fromkeys(event.evidence_ids + [eid]))
                event.observation_ids = list(dict.fromkeys(event.observation_ids + [result.observation_id]))
                event.fee = money_from_price(transaction.get("total_fees"), default_currency="TON", default_decimals=9)
                event.raw["fee_scope"] = "transaction; shared by actions in this transaction"
                event.raw["transaction_details"] = redact(transaction)
                event.raw["transaction_is_emulated"] = emulated
                event.raw["block_reference"] = transaction.get("block_ref")
                event.raw["message_indexes"] = [{"index": index, "hash": message.get("hash"),
                    "created_lt": message.get("created_lt"), "opcode": message.get("opcode")}
                    for index, message in enumerate(transaction.get("out_msgs") or [])]
                if aborted is True or emulated is True:
                    event.status = "failed" if aborted is True else "unknown"
                    event.verification = VerificationStatus.UNVERIFIED
                elif aborted is False and account == event.asset_address and event.event_type == "transfer":
                    event.raw["transaction_aborted"] = False
                    event.raw["transaction_is_emulated"] = emulated
                    inbound = transaction.get("in_msg") or {}
                    event.message_hash = canonical_hash(inbound.get("hash")) or event.message_hash
                if account == event.asset_address and account in self.assets:
                    state = transaction.get("account_state_after") or {}
                    self.assets[account].raw["historical_account_state:" + tx_hash] = redact(state)
            done.add(tx_hash)
            self.report.checkpoints["transaction_details:done"] = sorted(done)
            self.snapshot()
        if coverage.status != CoverageStatus.ERROR:
            coverage.status, coverage.coverage_status = CoverageStatus.INDEXER_EXHAUSTED, "PARTIAL"
            coverage.gap_reason = "Available collected-event hashes enriched; not full account transaction history"
        self.snapshot()


async def investigate_ton_nft(query: str, mode: str = "standard", scope: str = "auto", *,
                              budget: InvestigationBudget | dict | None = None,
                              investigation_id: str | None = None, resume: bool = False,
                              store_path: str | Path | None = None, providers: dict | None = None,
                              incremental: bool = False, use_api_keys: bool = False,
                              registry: dict | None = None,
                              on_target_resolved: Callable[[dict, NFTIntelligenceReport], Any] | None = None,
                              on_progress: Callable[[dict], None] | None = None,
                              priority_scheduling: bool = False,
                              checkpoint_interval_seconds: float = 0,
                              continuous: bool = False,
                              on_checkpoint: Callable[[NFTIntelligenceReport], Any] | None = None,
                              _resume_report: NFTIntelligenceReport | None = None) -> NFTIntelligenceReport:
    """Investigate with optional genuine progress and an early target handoff.

    on_target_resolved(target, report) is awaited once after exact fresh NFT
    ownership proof or validated account-scope resolution, before deep history
    and inventory. A caller can start its address-analysis task and return from
    the callback promptly. The existing request/deadline budget is unchanged.
    on_progress receives synchronous timestamped stage/request/page facts.
    priority_scheduling gives every paginated stream one page per turn while
    preserving resume cursors. checkpoint_interval_seconds coalesces only full
    snapshot writes; fresh report state and raw observations remain immediate.
    """
    if scope not in {"auto", "item", "collection", "wallet", "trace"}:
        raise ValueError("scope must be auto, item, collection, wallet or trace")
    normalized = normalize_nft_query(query)
    selected_budget = InvestigationBudget.model_validate(budget) if budget is not None else InvestigationBudget.for_mode(mode)
    store = InvestigationStore(store_path)
    investigator = None
    try:
        if resume or incremental:
            if not investigation_id:
                raise ValueError("resume/incremental requires investigation_id")
            if _resume_report is not None:
                if not isinstance(_resume_report, NFTIntelligenceReport) or _resume_report.investigation_id != investigation_id:
                    raise ValueError("Loaded resume snapshot does not match investigation ID")
                report = _resume_report
            else:
                report = store.load_snapshot(investigation_id)
            if normalize_nft_query(report.query).value != normalized.value:
                raise ValueError("investigation query differs from saved snapshot")
            report.budget, report.mode, report.status = selected_budget, mode, "running"
        else:
            inv_id = validate_investigation_id(investigation_id or str(uuid.uuid4()))
            report = NFTIntelligenceReport(investigation_id=inv_id, query=sanitize_observation(query), mode=mode, scope=scope, budget=selected_budget)
        investigator = NFTInvestigator(report, store, providers, incremental=incremental,
                                       use_api_keys=use_api_keys, registry=registry,
                                       on_target_resolved=on_target_resolved, on_progress=on_progress,
                                       priority_scheduling=priority_scheduling,
                                       checkpoint_interval_seconds=checkpoint_interval_seconds,
                                       continuous=continuous, on_checkpoint=on_checkpoint)
        investigator.progress("input_resolution", query_kind=normalized.kind)
        try:
            await investigator.run(normalized, scope)
        except asyncio.CancelledError:
            # A managed stop retains all observations and page cursors before
            # the owner closes this SQLite connection. No background work is
            # started; ordinary cancellation semantics remain for old callers.
            report.status = "partial"
            report.warnings.append("Investigation stopped; obtained observations and unfinished cursors saved")
            report.stats["stopped"] = True
            investigator.snapshot(force=True)
            if not continuous:
                raise
            analyze_report(report, normalized.value if report.scope == "wallet" else report.input_resolution.get("owner_address"))
            investigator.events = {event.event_id: event for event in report.events}
        except BudgetExceeded as exc:
            report.status = "partial"
            report.warnings.append(str(exc))
            investigator.snapshot()
            await investigator.notify_target_resolved()
            analyze_report(report, normalized.value if report.scope == "wallet" else report.input_resolution.get("owner_address") if report.mode == "deep" else None)
            investigator.events = {event.event_id: event for event in report.events}
        except Exception as exc:
            if investigator._callback_error is not None:
                raise investigator._callback_error
            # Preserve everything collected before parser/contract/transport failure.
            report.status = "partial" if investigator.assets or investigator.events else "error"
            report.errors.append(type(exc).__name__ + "; see raw observations for reproducible provider response")
            investigator.snapshot()
            analyze_report(report, normalized.value if report.scope == "wallet" else report.input_resolution.get("owner_address") if report.mode == "deep" else None)
            investigator.events = {event.event_id: event for event in report.events}
        investigator.progress("finished", report.status)
        investigator.snapshot(force=True)
        return report
    finally:
        store.close()


def resolve_verified_nft_owner(report: NFTIntelligenceReport) -> dict[str, Any] | None:
    """Return one exact NFT's freshly verified owner, never a DNS wallet hint.

    An owner may itself be a smart contract. Account classification and indexer
    corroboration remain separately labelled observations. Resume invalidates
    saved current_owner_status before collecting state, so old assertions alone
    cannot satisfy this contract.
    """
    discovery = report.discovery
    if not discovery or discovery.status != "resolved" or len(discovery.candidates) != 1:
        return None
    address = ton_canonical_address(discovery.candidates[0].address)
    asset = next((item for item in report.assets if item.address == address), None)
    if (asset is None or asset.initialized is not True or asset.standard_status != VerificationStatus.VERIFIED_ONCHAIN
            or asset.current_owner_status != VerificationStatus.VERIFIED_ONCHAIN):
        return None
    owner = ton_canonical_address(asset.current_owner)
    if not owner or asset.collection_address and asset.collection_status != VerificationStatus.VERIFIED_ONCHAIN:
        return None
    if discovery.query_kind == "domain":
        try:
            expected_index = ton_dns_item_index(discovery.normalized_query)
        except ValueError:
            return None
        if (asset.index != expected_index or asset.collection_address != ton_canonical_address(KNOWN_COLLECTIONS["domain"]["address"])):
            return None
    evidence = {item.evidence_id: item for item in report.evidence}
    assertions = [claim for claim in asset.ownership if claim.method == "get_nft_data"
        and claim.asset_address == address and claim.owner_address == owner and claim.status == VerificationStatus.VERIFIED_ONCHAIN
        and any(eid in evidence and evidence[eid].status == VerificationStatus.VERIFIED_ONCHAIN
                and evidence[eid].relation == "onchain_current_owner" for eid in claim.evidence_ids)]
    if not assertions:
        return None
    assertion = max(assertions, key=lambda claim: claim.observed_at)
    refs = list(dict.fromkeys(assertion.evidence_ids + asset.evidence_ids))
    return {"status": "verified", "original_query": report.query, "object_type": asset.kind,
        "nft_address": address, "nft_item_address": address, "collection_address": asset.collection_address,
        "owner_address": owner, "ownership_status": "verified_onchain", "observed_at": assertion.observed_at.isoformat(),
        "block_reference": assertion.block_reference, "logical_time": assertion.logical_time,
        "evidence_ids": refs, "evidence": [evidence[eid].model_dump(mode="json") for eid in refs if eid in evidence],
        "owner_corroboration": asset.owner_corroboration, "owner_account": asset.owner_account,
        "account_type": asset.owner_account.get("account_type", "unknown"),
        "note": "NFT owner address is distinct from DNS resolution, Telegram identity and beneficial ownership"}


def report_to_address_report(report: NFTIntelligenceReport, *, include_owner_snapshot: bool = True):
    """Project collected NFT facts into the original report without inventing balances.

    The complete versioned report remains attached. Legacy numeric amount fields
    describe money transfers only; NFT consideration is preserved separately from
    NFT movement, so the wallet graph cannot mistake a sale price for NFT quantity.
    """
    import math
    from app.models.report import (AddressReport, AssetPath, Counterparty, SourceHealth,
        TelegramEvidence, TelegramIdentity, TonAsset, TonAssetEvent, Transaction, WalletTimeline)
    from .analytics import event_sort_key

    address = report.portfolio.wallet_address if report.portfolio else report.query
    if report.input_resolution.get("status") == "verified":
        address = report.input_resolution["owner_address"]
    elif report.discovery and report.discovery.status == "resolved" and len(report.discovery.candidates) == 1 and not report.portfolio:
        address = report.discovery.candidates[0].address
    target = ton_canonical_address(address)
    evidence = {item.evidence_id: item for item in report.evidence}
    observations = {item.observation_id: item for item in report.observations}
    collections = {item.address: item for item in report.collections}
    by_asset: dict[str, list[NFTEvent]] = {}
    for event in sorted(report.events, key=event_sort_key):
        by_asset.setdefault(event.asset_address, []).append(event)
    out = AddressReport(target_address=address, detected_chains=["ton"],
        nft_intelligence=report.model_dump(mode="json", exclude={"owner_analysis_snapshot"} if not include_owner_snapshot else None),
        input_resolution=report.input_resolution,
        coverage={"ton_nft": [item.model_dump(mode="json") for item in report.coverage]})

    # Provider raw evidence is retained once in nft_intelligence. Legacy rows
    # carry typed facts and stable references, rather than re-embedding the same
    # transaction body in the asset history, transfer history and TX table.
    def event_summary(event):
        summary = event.model_dump(mode="json", exclude={"raw"})
        summary["raw_reference"] = {"collection": "events", "id": event.event_id}
        corroborating = event.raw.get("corroborating_observations") or []
        if corroborating:
            fields = {"trace_id", "action_index", "asset_address", "from_address", "to_address",
                "event_id", "transaction_hash", "logical_time", "message_hash"}
            summary["raw"] = {"corroborating_observations": [{key: value for key, value in row.items() if key in fields}
                for row in corroborating if isinstance(row, dict)]}
        return summary

    event_summaries = {event.event_id: event_summary(event) for event in report.events}

    # The item owner's verified state is distinct from ownership by this target.
    # Keep every discovered item in the intelligence evidence; project only the
    # target's inventory/history into its legacy portfolio and activity views.
    relationships = {}
    related_owners = {ton_canonical_address(value) for event in report.events
        for value in ([event.to_address] if ton_canonical_address(event.from_address) == target
                      else [event.from_address] if ton_canonical_address(event.to_address) == target else [])}
    for asset in report.assets:
        owner = ton_canonical_address(asset.current_owner)
        target_history = any(event.status == "success" and event.verification == VerificationStatus.VERIFIED_ONCHAIN
            and target in {ton_canonical_address(event.from_address), ton_canonical_address(event.to_address)}
            for event in by_asset.get(asset.address, [])) if target else False
        inventory = any((observation := observations.get(oid)) and
            (ton_canonical_address(observation.request_parameters.get("owner_address")) == target
             or observation.endpoint.endswith("/accounts/" + str(target) + "/nfts"))
            for claim in asset.ownership for oid in claim.observation_ids) if target else False
        relationship = ("current" if target and owner == target and asset.current_owner_status == VerificationStatus.VERIFIED_ONCHAIN
            else "reported" if target and owner == target and asset.current_owner_status == VerificationStatus.PROVIDER_REPORTED
            else "unknown" if target and owner == target else "historical" if target_history
            else "counterparty" if owner and owner in related_owners else "related_activity" if owner
            else "unknown")
        relationships[asset.address] = {"category": relationship, "target_address": target,
            "target_inventory_observed": inventory, "current_owner_address": owner,
            "owner_state_verified": asset.current_owner_status == VerificationStatus.VERIFIED_ONCHAIN,
            "target_ownership_verified": relationship == "current"}
    out.nft_intelligence["ownership_scope"] = {category: [address for address, relation in relationships.items()
        if relation["category"] == category] for category in
        ("current", "reported", "historical", "counterparty", "related_activity", "unknown")}
    for record in out.nft_intelligence.get("assets", []):
        record["wallet_relationship"] = relationships.get(record["address"], {})

    def number(value):
        if value is None:
            return None
        converted = float(value)
        return converted if math.isfinite(converted) else None

    def provenance(eids, oids=()):
        rows = [evidence[eid].model_dump(mode="json") for eid in eids if eid in evidence]
        linked = list(dict.fromkeys(list(oids) + [row["observation_id"] for row in rows]))
        rows.extend({"source": observations[oid].source, "upstream": observations[oid].upstream,
            "observation_id": oid, "raw_ref": observations[oid].raw_ref,
            "content_hash": observations[oid].content_hash, "url": observations[oid].endpoint,
            "collected_at": observations[oid].collected_at.isoformat()} for oid in linked if oid in observations)
        return rows

    def source_url(rows):
        source = next((row.get("source") for row in rows if row.get("source")), "ton_nft_intelligence")
        url = next((url for row in rows if (url := safe_public_url(row.get("url")))), None)
        return source, url

    def direction(event):
        sender, recipient = ton_canonical_address(event.from_address), ton_canonical_address(event.to_address)
        return "self" if target and sender == target == recipient else "out" if target and sender == target else "in" if target and recipient == target else "unknown"

    mapped_types = {"transfer": "transfer", "sale": "sale", "mint": "mint", "listing": "listing",
                    "unknown": "unknown_activity"}
    for asset in report.assets:
        relationship = relationships[asset.address]
        if relationship["category"] in {"counterparty", "related_activity"} or (
                relationship["category"] == "unknown" and not relationship["target_inventory_observed"]):
            continue
        rows = provenance(asset.evidence_ids)
        source, url = source_url(rows)
        verified = relationship["target_ownership_verified"]
        current = [claim for claim in asset.ownership if claim.owner_address == asset.current_owner
                   and claim.status == asset.current_owner_status]
        observed_at = max((claim.observed_at for claim in current), default=None)
        collection = collections.get(asset.collection_address)
        metadata = asset.metadata[-1].normalized if asset.metadata else {}
        events, transfers, sales = [], [], []
        for event in by_asset.get(asset.address, []):
            event_rows = provenance(event.evidence_ids, event.observation_ids)
            event_source, event_url = source_url(event_rows)
            status = True if event.status == "success" else False if event.status == "failed" else None
            price = event.money.amount if event.event_type == "sale" and event.money else None
            raw = {"original_reference": {"collection": "events", "id": event.event_id}}
            raw.update({"nft_event_type": event.event_type, "status": event.status,
                "verification": str(event.verification), "nft_address": event.asset_address,
                "trace_id": event.trace_id, "message_hash": event.message_hash, "query_id": event.query_id,
                "money": event.money.model_dump(mode="json") if event.money else None,
                "fee": event.fee.model_dump(mode="json") if event.fee else None,
                "evidence_ids": event.evidence_ids, "observation_ids": event.observation_ids,
                "provider_event_ids": event.provider_event_ids, "nft_intelligence": event_summaries[event.event_id]})
            history = TonAssetEvent(event_id=event.event_id, event_type=mapped_types.get(event.event_type, "interaction"),
                timestamp=event.timestamp, logical_time=event.logical_time, action_index=event.action_index,
                success=status, direction=direction(event), title=asset.name, nft_address=asset.address,
                from_address=event.from_address or "", to_address=event.to_address or "",
                amount=number(event.money.amount) if event.money and event.event_type == "contract_interaction" else None,
                amount_decimal=event.money.amount if event.money and event.event_type == "contract_interaction" else None,
                price=number(price), price_decimal=price, currency=event.money.currency if event.money else None,
                tx_hash=event.transaction_hash, marketplace=event.marketplace, source=event_source,
                evidence_url=event_url, confidence=1 if event.verification == VerificationStatus.VERIFIED_ONCHAIN else 0.5,
                provenance=event_rows, raw=raw)
            events.append(history)
            if status is True and event.event_type in {"transfer", "mint"} and event.verification == VerificationStatus.VERIFIED_ONCHAIN:
                transfers.append(history)
            if status is True and event.event_type == "sale":
                sales.append(history)
        raw = {"original_reference": {"collection": "assets", "id": asset.address}}
        active_listing = next((listing for listing in asset.listings if listing.status == "active"), None)
        raw.update({"address": asset.address, "nft_address": asset.address, "collection_address": asset.collection_address,
            "index": asset.index, "metadata": metadata, "attributes": asset.attributes,
            "description": asset.description, "metadata_uri": asset.metadata_uri,
            "ownership_assertions": [claim.model_dump(mode="json") for claim in asset.ownership],
            "evidence_ids": asset.evidence_ids, "listing_status": active_listing.status if active_listing else None,
            "nft_intelligence": {**asset.model_dump(mode="json", exclude={"raw"}),
                "raw_reference": {"collection": "assets", "id": asset.address}}})
        previous = list(dict.fromkeys(row["address"] for row in asset.historical_owners
                        if row.get("address") and row["address"] != asset.current_owner))
        times = [event.timestamp for event in events if event.timestamp]
        kind = asset.kind if asset.kind in {"username", "gift", "domain", "nft"} else "collectible" if asset.kind == "number" else "nft"
        projected = TonAsset(asset_id=asset.address, type=kind, name=asset.name, title=asset.name or asset.address,
            image_url=safe_public_url(asset.image_url, allow_ipfs=True),
            collection=collection.name if collection and collection.name else asset.collection_address,
            owner_address=ton_canonical_address(asset.current_owner) or "", ownership_status="current" if verified else "historical" if relationship["category"] == "historical" else "unknown",
            ownership_verified=verified, ownership_observed_at=observed_at, previous_owners=previous,
            first_seen=min(times) if times else None, last_seen=max(times) if times else None,
            acquisition_tx=asset.ownership_summary.get("first_observed_transaction"), history_events=events,
            transfer_history=transfers, sale_history=sales, history_status=str(asset.ownership_summary.get("history_status") or "unknown"),
            history_evidence_url=url, last_sale_price=number(asset.last_confirmed_sale.amount) if asset.last_confirmed_sale else None,
            marketplace=active_listing.marketplace if active_listing else (sales[-1].marketplace if sales else None),
            source=source, external_url=asset.telegram.public_url if asset.telegram else url,
            evidence_url=url, collected_at=report.updated_at, confidence=1 if verified else 0.4,
            related_addresses=list(dict.fromkeys(addr for event in events for addr in (event.from_address, event.to_address) if addr)),
            provenance=rows, raw=raw)
        out.ton_assets.append(projected)
        out.asset_paths.append(AssetPath(asset_id=asset.address, asset_type=kind, title=projected.title,
            current_owner=asset.current_owner or "" if verified else "", previous_owners=previous,
            tx_chain=[event.tx_hash for event in transfers if event.tx_hash], source=source))
        out.warnings.extend(asset.warnings)
        if asset.telegram:
            telegram = asset.telegram
            claims = [TelegramEvidence(source=row.get("source", source), upstream=row.get("upstream"),
                evidence_url=row.get("url"), evidence_tx=row.get("transaction_hash"), nft_contract=asset.address,
                claim_type="onchain_nft_ownership" if verified else "unverified_metadata_association",
                confidence="weak", details="Collectible ownership is separate from Telegram assignment/person identity", raw=row)
                for row in provenance(telegram.ownership_evidence_ids)]
            out.telegram_identities.append(TelegramIdentity(wallet_address=asset.current_owner or "",
                username=telegram.username, asset_ids=[asset.address], gifts=[asset.name or asset.address] if telegram.kind == "gift" else [],
                association_type="collectible_nft_ownership" if verified else "unverified_metadata_association",
                identity_verified=False, confidence="unknown", evidence=claims, source=source,
                evidence_url=telegram.public_url, collected_at=report.updated_at, raw={"collectible": telegram.model_dump(mode="json")}))

    for event in sorted(report.events, key=event_sort_key):
        rows = provenance(event.evidence_ids, event.observation_ids)
        source, url = source_url(rows)
        money_transfer = event.event_type == "contract_interaction" and event.money is not None
        money = event.money if money_transfer else None
        raw = {"original_reference": {"collection": "events", "id": event.event_id}}
        raw.update({"type": "nft_" + event.event_type, "nft_event_type": event.event_type,
            "nft_event_id": event.event_id, "nft_address": event.asset_address, "lt": event.logical_time,
            "action_index": event.action_index, "trace_id": event.trace_id, "message_hash": event.message_hash,
            "status": event.status, "verification": str(event.verification),
            "amount_role": "money_transfer" if money_transfer else "sale_consideration" if event.event_type == "sale" else "attached_amount",
            "money": event.money.model_dump(mode="json") if event.money else None,
            "fee_money": event.fee.model_dump(mode="json") if event.fee else None,
            "provider_event_ids": event.provider_event_ids, "evidence_ids": event.evidence_ids,
            "observation_ids": event.observation_ids, "nft_intelligence": event_summaries[event.event_id]})
        out.transactions.append(Transaction(event_id=event.event_id, tx_hash=event.transaction_hash or "", chain="ton",
            timestamp=event.timestamp, from_address=event.from_address, to_address=event.to_address,
            direction=direction(event), amount=number(money.amount) if money else None,
            amount_decimal=money.amount if money else None, amount_base_units=money.base_units if money else None,
            decimals=money.decimals if money else None, asset=money.currency if money else "NFT:" + event.asset_address,
            fee=number(event.fee.amount) if event.fee and event.fee.currency == "TON" else None,
            success=True if event.status == "success" else False if event.status == "failed" else None,
            provenance=rows, source=source, url=url, raw=raw))
    for collectible in report.public_collectibles:
        rows = provenance(collectible.get("evidence_ids", []))
        source, url = source_url(rows)
        out.telegram_identities.append(TelegramIdentity(wallet_address="", identity_verified=False, confidence="unknown",
            association_type="public_gift_association", gifts=[str(collectible.get("identifier") or report.query)],
            source=source, evidence_url=collectible.get("url") or url, collected_at=report.updated_at,
            evidence=[TelegramEvidence(source=row.get("source", source), claim_type="public_gift_association",
                confidence="weak", evidence_url=row.get("url"), raw=row) for row in rows], raw={"public_collectible": collectible}))
    for coverage in report.coverage:
        status = "ok" if coverage.complete and coverage.coverage_status == "COMPLETE" else "unavailable" if coverage.coverage_status == "UNAVAILABLE" else "skipped" if coverage.status == CoverageStatus.UNSUPPORTED else "partial"
        out.source_health.append(SourceHealth(source=coverage.source, status=status,
            timeout_seconds=report.budget.request_timeout, partial=status != "ok", retry_strategy="resume saved checkpoints within configured budget",
            details=f"{coverage.scope}: {coverage.coverage_status}; records={coverage.records}; pages={coverage.pages}; " + (coverage.gap_reason or "History completeness is unknown")))
    if report.portfolio:
        for item in report.portfolio.counterparties:
            out.counterparties.append(Counterparty(address=item["address"], chain="ton", tx_count=item.get("event_count", 0)))
    times = [event.timestamp for event in report.events if event.timestamp]
    out.wallet_timeline = WalletTimeline(first_activity=min(times) if times else None, last_activity=max(times) if times else None,
        active_days=len({time.date() for time in times}))
    out.sources_used = list(dict.fromkeys([row.source for row in report.observations] + [row.source for row in report.evidence] + [row.source for row in report.coverage]))
    out.warnings.extend(report.warnings)
    out.errors.extend(report.errors)
    out.warnings = list(dict.fromkeys(out.warnings))
    out.errors = list(dict.fromkeys(out.errors))
    # Every appended ObservationModel has already validated/redacted its own
    # fields. Revalidating the whole expanded report repeats multiple traversals
    # of identical evidence and provides no additional schema guarantee.
    out.warnings = sanitize_observation(out.warnings)
    out.errors = sanitize_observation(out.errors)
    out.sources_used = sanitize_observation(out.sources_used)
    return out


def _nft_bridge_transaction_keys(transaction):
    """Match explicit IDs or exact provider action positions, never a hash alone."""
    raw = transaction.raw or {}
    keys = {("event", transaction.event_id)} if transaction.event_id else set()
    records = [raw.get("nft_intelligence") or {}]
    records.extend((raw.get("nft_intelligence") or {}).get("raw", {}).get("corroborating_observations", []))
    if raw.get("provider") == "tonapi_events":
        records.append({"trace_id": raw.get("event_id"), "action_index": raw.get("action_index"),
            "asset_address": str(transaction.asset or "").removeprefix("NFT:"),
            "from_address": transaction.from_address, "to_address": transaction.to_address})
    for record in records:
        trace, index = canonical_hash(record.get("trace_id")), record.get("action_index")
        nft = ton_canonical_address(record.get("asset_address"))
        if trace and index is not None and nft:
            keys.add(("tonapi_action", trace, index, nft, ton_canonical_address(record.get("from_address")), ton_canonical_address(record.get("to_address"))))
    return keys


def attach_nft_intelligence(existing, report: NFTIntelligenceReport):
    """Add NFT projection in place while preserving the existing wallet analysis."""
    from app.utils.event_identity import merge_provenance
    # The parent already holds its ordinary dossier. Keep the full historical
    # owner in the NFT model/SQLite and standalone/machine exports, rather than
    # revalidating and embedding another entire owner body in this projection.
    saved_owner = getattr(report, "owner_analysis_snapshot", None)
    saved_target = ton_canonical_address(saved_owner.get("target_address")) if saved_owner else None
    parent_target = ton_canonical_address(existing.target_address)
    same_target = bool(saved_target and parent_target and saved_target == parent_target)
    projected = report_to_address_report(report, include_owner_snapshot=bool(saved_owner and not same_target))
    if saved_owner and same_target:
        projected.nft_intelligence["owner_analysis_reference"] = {
            "location": "parent_address_report",
            "investigation_id": report.investigation_id, "exclude": ["nft_intelligence"]}
    existing.nft_intelligence = projected.nft_intelligence
    if not existing.input_resolution and projected.input_resolution:
        existing.input_resolution = projected.input_resolution
    existing.coverage["ton_nft"] = projected.coverage["ton_nft"]
    if "ton" not in existing.detected_chains:
        existing.detected_chains.append("ton")
    transaction_lookup = {key: transaction for transaction in existing.transactions for key in _nft_bridge_transaction_keys(transaction)}
    for transaction in projected.transactions:
        keys = _nft_bridge_transaction_keys(transaction)
        matches = {id(transaction_lookup[key]): transaction_lookup[key] for key in keys if key in transaction_lookup}
        if len(matches) == 1:
            current = next(iter(matches.values()))
            merge_provenance(current, transaction)
            current.raw["nft_intelligence"] = transaction.raw["nft_intelligence"]
            current.raw["nft_event_id"] = transaction.event_id
        else:
            existing.transactions.append(transaction)
            current = transaction
        transaction_lookup.update({key: current for key in keys})
    # A prior checkpoint may already contain the old unscoped projection.
    # All observations stay in nft_intelligence; remove only those legacy cards
    # whose exact item is now classified outside this wallet's portfolio.
    scoped_items = {ton_canonical_address(asset.asset_id) for asset in projected.ton_assets}
    known_items = {asset.address for asset in report.assets}
    existing.ton_assets = [asset for asset in existing.ton_assets
        if (ton_canonical_address(asset.asset_id) not in known_items
            or ton_canonical_address(asset.asset_id) in scoped_items)]
    existing.asset_paths = [path for path in existing.asset_paths
        if ton_canonical_address(path.asset_id) not in known_items]
    existing.telegram_identities = [identity for identity in existing.telegram_identities
        if not ((identity.raw or {}).get("collectible")
            and identity.association_type in {"collectible_nft_ownership", "unverified_metadata_association"}
            and identity.asset_ids and all(ton_canonical_address(item) in known_items
                for item in identity.asset_ids))]
    assets = {ton_canonical_address(asset.asset_id) or asset.asset_id: asset for asset in existing.ton_assets}
    for asset in projected.ton_assets:
        key = ton_canonical_address(asset.asset_id) or asset.asset_id
        current = assets.get(key)
        if current is None:
            existing.ton_assets.append(asset)
            assets[key] = asset
            continue
        merge_provenance(current, asset)
        if (not asset.ownership_verified or not current.ownership_verified or current.ownership_observed_at is None or asset.ownership_observed_at and asset.ownership_observed_at >= current.ownership_observed_at):
            if (current.owner_address, current.ownership_verified, current.ownership_observed_at) != (asset.owner_address, asset.ownership_verified, asset.ownership_observed_at):
                current.raw.setdefault("prior_ownership_observations", []).append({"owner_address": current.owner_address,
                    "ownership_verified": current.ownership_verified, "observed_at": current.ownership_observed_at.isoformat() if current.ownership_observed_at else None})
            current.owner_address, current.ownership_status = asset.owner_address, asset.ownership_status
            current.ownership_verified, current.ownership_observed_at = asset.ownership_verified, asset.ownership_observed_at
        for field in ("name", "title", "collection", "image_url", "external_url", "evidence_url", "history_status", "history_evidence_url", "last_sale_price", "marketplace"):
            if getattr(current, field) in (None, ""):
                setattr(current, field, getattr(asset, field))
        for field in ("history_events", "transfer_history", "sale_history"):
            lookup = {event.event_id: event for event in getattr(current, field)}
            for event in getattr(asset, field):
                if event.event_id in lookup:
                    merge_provenance(lookup[event.event_id], event)
                else:
                    getattr(current, field).append(event)
                    lookup[event.event_id] = event
        current.previous_owners = list(dict.fromkeys(current.previous_owners + asset.previous_owners))
        current.related_addresses = list(dict.fromkeys(current.related_addresses + asset.related_addresses))
        if asset.first_seen and (current.first_seen is None or asset.first_seen < current.first_seen):
            current.first_seen = asset.first_seen
        if asset.last_seen and (current.last_seen is None or asset.last_seen > current.last_seen):
            current.last_seen = asset.last_seen
        current.raw["nft_intelligence"] = asset.raw["nft_intelligence"]
        current.raw["ownership_assertions"] = asset.raw["ownership_assertions"]
    identities = {(item.wallet_address, item.association_type, tuple(item.asset_ids), tuple(item.gifts), item.username) for item in existing.telegram_identities}
    for item in projected.telegram_identities:
        key = (item.wallet_address, item.association_type, tuple(item.asset_ids), tuple(item.gifts), item.username)
        if key not in identities:
            existing.telegram_identities.append(item)
            identities.add(key)
    counterparties = {(item.chain, ton_canonical_address(item.address) or item.address) for item in existing.counterparties}
    existing.counterparties.extend(item for item in projected.counterparties if (item.chain, ton_canonical_address(item.address) or item.address) not in counterparties)
    paths = {item.asset_id for item in existing.asset_paths}
    existing.asset_paths.extend(item for item in projected.asset_paths if item.asset_id not in paths)
    health = {(item.source, item.status, item.details) for item in existing.source_health}
    existing.source_health.extend(item for item in projected.source_health if (item.source, item.status, item.details) not in health)
    existing.sources_used = list(dict.fromkeys(existing.sources_used + projected.sources_used))
    existing.warnings = list(dict.fromkeys(existing.warnings + projected.warnings))
    existing.errors = list(dict.fromkeys(existing.errors + projected.errors))
    return existing
