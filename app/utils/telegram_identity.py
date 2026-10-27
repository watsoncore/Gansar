from __future__ import annotations

from datetime import datetime, timezone

from app.models.report import AddressReport, TelegramEvidence, TelegramIdentity


CONFIDENCE_RANK = {"unknown": 0, "weak": 1, "likely": 2, "confirmed": 3}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def merge_identity(report: AddressReport, identity: TelegramIdentity) -> TelegramIdentity:
    key = (identity.wallet_address, identity.username or "", identity.telegram_user_id or "")
    existing = next((item for item in report.telegram_identities if (item.wallet_address, item.username or "", item.telegram_user_id or "") == key), None)
    if existing is None:
        report.telegram_identities.append(identity)
        return identity
    if CONFIDENCE_RANK[identity.confidence] > CONFIDENCE_RANK[existing.confidence]:
        existing.confidence = identity.confidence
    if existing.evidence_url is None and identity.evidence_url:
        existing.evidence_url = identity.evidence_url
    if existing.collected_at is None and identity.collected_at:
        existing.collected_at = identity.collected_at
    for field in ("domains", "asset_ids", "gifts"):
        merged = list(dict.fromkeys(getattr(existing, field) + getattr(identity, field)))
        setattr(existing, field, merged)
    for evidence in identity.evidence:
        add_evidence(existing, evidence)
    # Multiple parsers can share one upstream; repetition is not identity proof.
    existing.raw.update({k: v for k, v in identity.raw.items() if k not in existing.raw})
    return existing


def add_evidence(identity: TelegramIdentity, evidence: TelegramEvidence) -> None:
    key = (evidence.source, evidence.evidence_url, evidence.evidence_tx, evidence.nft_contract, evidence.details)
    if not any((item.source, item.evidence_url, item.evidence_tx, item.nft_contract, item.details) == key for item in identity.evidence):
        identity.evidence.append(evidence)
    if CONFIDENCE_RANK[evidence.confidence] > CONFIDENCE_RANK[identity.confidence]:
        identity.confidence = evidence.confidence
