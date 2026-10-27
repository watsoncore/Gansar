from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Record(BaseModel):
    model_config = ConfigDict(extra="allow")


class VerificationStatus(StrEnum):
    VERIFIED_ONCHAIN = "verified_onchain"
    PROVIDER_REPORTED = "provider_reported"
    UNVERIFIED = "unverified"
    CONFLICT = "conflict"
    UNSUPPORTED = "unsupported"


class CoverageStatus(StrEnum):
    UNKNOWN = "unknown"
    PARTIAL = "partial"
    INDEXER_EXHAUSTED = "indexer_exhausted"
    BUDGET_LIMIT = "budget_limit"
    ERROR = "error"
    UNSUPPORTED = "unsupported"


class InvestigationBudget(Record):
    max_requests: int = Field(default=100, ge=1, le=100000)
    max_pages: int = Field(default=8, ge=1, le=10000)
    max_items: int = Field(default=100, ge=1, le=100000)
    max_events: int = Field(default=3000, ge=1, le=1000000)
    max_seconds: float = Field(default=180, ge=1, le=86400)
    request_timeout: float = Field(default=15, ge=1, le=120)
    page_size: int = Field(default=100, ge=1, le=1000)
    concurrency: int = Field(default=2, ge=1, le=16)
    requests_per_second: float = Field(default=1.0, gt=0, le=20)
    trace_depth: int = Field(default=1, ge=0, le=5)
    max_wallets: int = Field(default=8, ge=1, le=1000)
    max_transaction_details: int = Field(default=100, ge=0, le=10000)
    retries: int = Field(default=2, ge=0, le=5)

    @classmethod
    def for_mode(cls, mode: str) -> "InvestigationBudget":
        if mode == "deep":
            return cls(max_requests=1500, max_pages=100, max_items=1000,
                       max_events=100000, max_seconds=3600, trace_depth=2,
                       max_wallets=30, max_transaction_details=1000)
        if mode != "standard":
            raise ValueError("mode must be standard or deep")
        return cls()


class IntelligenceEvidence(Record):
    evidence_id: str
    source: str
    upstream: str
    observation_id: str
    relation: str
    status: VerificationStatus = VerificationStatus.PROVIDER_REPORTED
    explanation: str
    url: str | None = None
    transaction_hash: str | None = None
    logical_time: int | None = None
    collected_at: datetime = Field(default_factory=utcnow)
    confidence: Literal["high", "medium", "low", "unknown"] = "unknown"


class SourceObservation(Record):
    observation_id: str
    source: str
    upstream: str
    endpoint: str
    request_method: Literal["GET", "POST"] | None = None
    request_parameters: dict[str, Any] = Field(default_factory=dict)
    request_body: dict[str, Any] | None = None
    requested_at: datetime | None = None
    collected_at: datetime = Field(default_factory=utcnow)
    content_hash: str
    status: Literal["ok", "error", "timeout", "rate_limited", "not_found"] = "ok"
    raw: dict[str, Any] | list[Any] | None = None
    raw_ref: str | None = None
    error: str | None = None


class CollectionCoverage(Record):
    scope: str
    source: str
    upstream: str
    status: CoverageStatus = CoverageStatus.UNKNOWN
    coverage_status: Literal["COMPLETE", "PARTIAL", "TRUNCATED", "UNAVAILABLE", "UNKNOWN"] = "UNKNOWN"
    pages: int = 0
    records: int = 0
    unique_events: int = 0
    duplicate_records: int = 0
    oldest_timestamp: datetime | None = None
    newest_timestamp: datetime | None = None
    oldest_lt: int | None = None
    newest_lt: int | None = None
    next_cursor: str | None = None
    limit: int | None = None
    gap_reason: str | None = None
    missing_ranges: list[dict[str, Any]] = Field(default_factory=list)
    complete: bool = False
    observation_ids: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class NFTMetadataSnapshot(Record):
    observed_at: datetime = Field(default_factory=utcnow)
    source: str
    observation_ids: list[str] = Field(default_factory=list)
    uri: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    normalized: dict[str, Any] = Field(default_factory=dict)
    content_boc: str | None = None
    content_hash: str | None = None


class NFTOwnershipAssertion(Record):
    asset_address: str
    owner_address: str | None = None
    status: VerificationStatus = VerificationStatus.UNVERIFIED
    observed_at: datetime = Field(default_factory=utcnow)
    logical_time: int | None = None
    block_reference: Any | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    method: str
    custodial: bool | None = None
    beneficial_owner: str | None = None
    source: str | None = None
    upstream: str | None = None
    observation_ids: list[str] = Field(default_factory=list)


class Money(Record):
    currency: str
    token_contract: str | None = None
    base_units: int | None = None
    decimals: int | None = None
    amount: Decimal | None = None


class NFTEvent(Record):
    event_id: str
    asset_address: str
    event_type: Literal["transfer", "sale", "mint", "listing", "listing_cancel",
                        "bid", "auction", "contract_interaction", "unknown"]
    status: Literal["success", "failed", "pending", "unknown"] = "unknown"
    from_address: str | None = None
    to_address: str | None = None
    timestamp: datetime | None = None
    transaction_hash: str | None = None
    trace_id: str | None = None
    logical_time: int | None = None
    action_index: int | None = None
    message_hash: str | None = None
    query_id: str | None = None
    money: Money | None = None
    fee: Money | None = None
    marketplace: str | None = None
    marketplace_address: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    observation_ids: list[str] = Field(default_factory=list)
    provider_event_ids: list[str] = Field(default_factory=list)
    verification: VerificationStatus = VerificationStatus.PROVIDER_REPORTED
    raw: dict[str, Any] = Field(default_factory=dict)


class NFTListing(Record):
    asset_address: str
    listing_id: str
    status: Literal["active", "cancelled", "completed", "unknown"] = "unknown"
    price: Money | None = None
    seller_address: str | None = None
    marketplace: str | None = None
    marketplace_address: str | None = None
    sale_contract: str | None = None
    observed_at: datetime = Field(default_factory=utcnow)
    evidence_ids: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class NFTMarketObservation(Record):
    kind: Literal["floor", "estimate", "listing", "auction", "offer", "royalty"]
    value: Money | None = None
    source: str
    evidence_ids: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class TelegramCollectible(Record):
    asset_address: str
    kind: Literal["username", "gift", "number", "unknown"]
    username: str | None = None
    public_url: str | None = None
    collectible_id: str | None = None
    gift_number: int | None = None
    collection_verified: bool = False
    ownership_evidence_ids: list[str] = Field(default_factory=list)
    assignment_status: Literal["publicly_verified", "unverified", "unknown"] = "unknown"
    assigned_entity: str | None = None
    assignment_evidence_ids: list[str] = Field(default_factory=list)
    identity_status: Literal["unverified", "unknown"] = "unknown"
    metadata_associations: list[str] = Field(default_factory=list)
    gift_attributes: dict[str, Any] = Field(default_factory=dict)
    rarity: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


class NFTAsset(Record):
    asset_id: str
    address: str
    collection_address: str | None = None
    index: int | None = None
    kind: Literal["nft", "domain", "username", "gift", "number", "unknown"] = "nft"
    name: str | None = None
    description: str | None = None
    image_url: str | None = None
    thumbnail_url: str | None = None
    animation_url: str | None = None
    image_sources: list[dict[str, Any]] = Field(default_factory=list)
    dns: dict[str, Any] = Field(default_factory=dict)
    category_provenance: dict[str, Any] = Field(default_factory=dict)
    metadata_uri: str | None = None
    attributes: list[Any] | dict[str, Any] = Field(default_factory=list)
    metadata: list[NFTMetadataSnapshot] = Field(default_factory=list)
    contract_state: dict[str, Any] = Field(default_factory=dict)
    code_hash: str | None = None
    data_hash: str | None = None
    initialized: bool | None = None
    standard: str | None = None
    standard_status: VerificationStatus = VerificationStatus.UNVERIFIED
    collection_status: VerificationStatus = VerificationStatus.UNVERIFIED
    ownership: list[NFTOwnershipAssertion] = Field(default_factory=list)
    current_owner: str | None = None
    current_owner_status: VerificationStatus = VerificationStatus.UNVERIFIED
    owner_corroboration: dict[str, Any] = Field(default_factory=dict)
    owner_account: dict[str, Any] = Field(default_factory=dict)
    event_ids: list[str] = Field(default_factory=list)
    historical_owners: list[dict[str, Any]] = Field(default_factory=list)
    ownership_summary: dict[str, Any] = Field(default_factory=dict)
    listings: list[NFTListing] = Field(default_factory=list)
    market_observations: list[NFTMarketObservation] = Field(default_factory=list)
    last_confirmed_sale: Money | None = None
    telegram: TelegramCollectible | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class NFTCollection(Record):
    address: str
    name: str | None = None
    owner_address: str | None = None
    next_item_index: int | None = None
    verification: VerificationStatus = VerificationStatus.UNVERIFIED
    known_registry_kind: str | None = None
    registry_source: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    content_boc: str | None = None
    code_hash: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class NFTPortfolio(Record):
    wallet_address: str
    current_holdings: list[str] = Field(default_factory=list)
    reported_holdings: list[str] = Field(default_factory=list)
    historical_holdings: list[str] = Field(default_factory=list)
    received_assets: list[str] = Field(default_factory=list)
    sent_assets: list[str] = Field(default_factory=list)
    by_collection: dict[str, list[str]] = Field(default_factory=dict)
    by_kind: dict[str, list[str]] = Field(default_factory=dict)
    counterparties: list[dict[str, Any]] = Field(default_factory=list)
    financial_totals: dict[str, dict[str, Decimal]] = Field(default_factory=dict)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    intersections: list[dict[str, Any]] = Field(default_factory=list)
    coverage_status: CoverageStatus = CoverageStatus.UNKNOWN
    notes: list[str] = Field(default_factory=list)


class DiscoveryCandidate(Record):
    address: str
    collection_address: str | None = None
    index: int | None = None
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)
    verification: VerificationStatus = VerificationStatus.UNVERIFIED


class DiscoveryResult(Record):
    normalized_query: str
    query_kind: str
    status: Literal["resolved", "ambiguous", "not_found", "unresolved", "unsupported", "error"] = "unresolved"
    candidates: list[DiscoveryCandidate] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class NFTIntelligenceReport(Record):
    schema_version: str = "1.0.0"
    investigation_id: str
    query: str
    mode: str = "standard"
    scope: str = "auto"
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    status: Literal["running", "completed", "partial", "unresolved", "error"] = "running"
    budget: InvestigationBudget = Field(default_factory=InvestigationBudget)
    discovery: DiscoveryResult | None = None
    input_resolution: dict[str, Any] = Field(default_factory=dict)
    assets: list[NFTAsset] = Field(default_factory=list)
    collections: list[NFTCollection] = Field(default_factory=list)
    events: list[NFTEvent] = Field(default_factory=list)
    evidence: list[IntelligenceEvidence] = Field(default_factory=list)
    observations: list[SourceObservation] = Field(default_factory=list)
    coverage: list[CollectionCoverage] = Field(default_factory=list)
    portfolio: NFTPortfolio | None = None
    signals: list[dict[str, Any]] = Field(default_factory=list)
    related_wallets: list[str] = Field(default_factory=list)
    public_collectibles: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    checkpoints: dict[str, Any] = Field(default_factory=dict)
