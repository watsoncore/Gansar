from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.models.report import AddressReport, TonAsset, TonAssetEvent
from app.utils.ton_normalize import ton_address, ton_text
from app.utils.ton_normalize import ton_canonical_address
from app.utils.event_identity import event_identity, merge_provenance
from app.utils.security import safe_public_url


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def classify_asset(name: str | None, collection: str | None, raw_type: str | None = None) -> str:
    text = " ".join([name or "", collection or "", raw_type or ""]).lower()
    if "gift" in text or "telegram gift" in text or "collectible gift" in text:
        return "gift"
    if "username" in text or "telegram username" in text:
        return "username"
    if ".ton" in text or "ton dns" in text or "domain" in text:
        return "domain"
    if raw_type == "jetton":
        return "jetton"
    if "collectible" in text:
        return "collectible"
    return "nft"


def image_url_from(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    metadata = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
    content = value.get("content") if isinstance(value.get("content"), dict) else {}
    candidates = [
        metadata.get("image"),
        metadata.get("image_url"),
        metadata.get("preview"),
        content.get("image"),
        content.get("image_url"),
        value.get("image"),
        value.get("image_url"),
    ]
    previews = value.get("previews") or metadata.get("previews") or []
    if isinstance(previews, list):
        for preview in reversed(previews):
            if isinstance(preview, dict):
                candidates.append(preview.get("url") or preview.get("image_url"))
    for item in candidates:
        if isinstance(item, str) and item:
            return safe_public_url(item, allow_ipfs=True)
    return None


def animation_url_from(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    metadata = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
    content = value.get("content") if isinstance(value.get("content"), dict) else {}
    for item in (metadata.get("animation_url"), metadata.get("video"), content.get("animation_url"), value.get("animation_url")):
        if isinstance(item, str) and item:
            return safe_public_url(item, allow_ipfs=True)
    return None


def related_addresses(*values: Any) -> list[str]:
    out = []
    for value in values:
        if isinstance(value, list):
            for nested in value:
                addr = ton_address(nested)
                if addr and addr not in out:
                    out.append(addr)
            continue
        addr = ton_address(value)
        if addr and addr not in out:
            out.append(addr)
    return out


def merge_asset(report: AddressReport, asset: TonAsset) -> TonAsset:
    key = ton_canonical_address(asset.asset_id) or asset.asset_id
    existing = next((item for item in report.ton_assets if (ton_canonical_address(item.asset_id) or item.asset_id) == key), None)
    if existing is None:
        events = list(asset.history_events) + list(asset.transfer_history) + list(asset.sale_history)
        asset.history_events, asset.transfer_history, asset.sale_history = [], [], []
        for event in events:
            add_asset_event(asset, event)
        merge_provenance(asset)
        report.ton_assets.append(asset)
        return asset
    merge_provenance(existing, asset)
    # Historical destination hints cannot replace a current account-state assertion.
    if asset.ownership_status == "current" and (existing.ownership_status != "current" or (asset.ownership_observed_at and (existing.ownership_observed_at is None or asset.ownership_observed_at >= existing.ownership_observed_at))):
        if existing.owner_address and existing.owner_address != asset.owner_address:
            existing.raw.setdefault("ownership_conflicts", []).append({"owner": existing.owner_address, "source": existing.source, "status": existing.ownership_status})
        existing.owner_address = asset.owner_address
        existing.ownership_status = "current"
        existing.ownership_verified = asset.ownership_verified
        existing.ownership_observed_at = asset.ownership_observed_at
    for field in (
        "name",
        "title",
        "collection",
        "image_url",
        "animation_url",
        "acquisition_tx",
        "history_status",
        "history_evidence_url",
        "floor_price",
        "last_sale_price",
        "marketplace",
        "external_url",
        "evidence_url",
        "evidence_tx",
        "collected_at",
    ):
        if getattr(existing, field) in (None, "") and getattr(asset, field) not in (None, ""):
            setattr(existing, field, getattr(asset, field))
    if asset.first_seen and (existing.first_seen is None or asset.first_seen < existing.first_seen):
        existing.first_seen = asset.first_seen
    if asset.last_seen and (existing.last_seen is None or asset.last_seen > existing.last_seen):
        existing.last_seen = asset.last_seen
    for addr in asset.previous_owners:
        if addr and addr not in existing.previous_owners:
            existing.previous_owners.append(addr)
    for addr in asset.related_addresses:
        if addr and addr not in existing.related_addresses:
            existing.related_addresses.append(addr)
    for event in getattr(asset, "history_events", []) or []:
        add_asset_event(existing, event)
    for event in asset.transfer_history:
        add_asset_event(existing, event)
    for event in asset.sale_history:
        add_asset_event(existing, event)
    existing.confidence = max(existing.confidence, asset.confidence)
    existing.raw.update({k: v for k, v in asset.raw.items() if k not in existing.raw})
    return existing


def add_asset_event(asset: TonAsset, event: TonAssetEvent) -> None:
    event.event_id = event_identity(event)
    merge_provenance(event)
    key = event.event_id
    history = getattr(asset, "history_events", None)
    if history is not None:
        existing = next((item for item in history if event_identity(item) == key), None)
        if existing is None:
            history.append(event)
        else:
            merge_provenance(existing, event)
    if event.event_type not in {"received_ton", "sent_ton", "unknown_activity"}:
        is_sale = event.event_type in {"sale", "marketplace_sale", "marketplace_purchase"}
        is_transfer = event.event_type in {"transfer", "mint", "first_owner", "owner_change", "received_nft", "sent_nft"}
        target = asset.sale_history if is_sale and event.success is True else asset.transfer_history if is_transfer else None
        if target is not None and not any(event_identity(item) == key for item in target):
            target.append(event)
    for addr in (event.from_address, event.to_address):
        if addr and addr not in asset.related_addresses:
            asset.related_addresses.append(addr)
    if event.success is True and event.event_type in {"transfer", "owner_change", "sale", "received_nft", "sent_nft", "marketplace_sale", "marketplace_purchase"} and event.from_address and event.from_address != asset.owner_address and event.from_address not in asset.previous_owners:
        asset.previous_owners.append(event.from_address)
    if event.timestamp and (asset.first_seen is None or event.timestamp < asset.first_seen):
        asset.first_seen = event.timestamp
    if event.timestamp and (asset.last_seen is None or event.timestamp > asset.last_seen):
        asset.last_seen = event.timestamp
    if event.event_type == "sale" and event.success is True and event.price is not None:
        asset.last_sale_price = event.price
        asset.marketplace = event.marketplace or asset.marketplace


def asset_title(value: dict, fallback: str | None = None) -> str | None:
    metadata = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
    content = value.get("content") if isinstance(value.get("content"), dict) else {}
    return ton_text(metadata.get("name")) or ton_text(content.get("name")) or ton_text(value.get("name")) or fallback
