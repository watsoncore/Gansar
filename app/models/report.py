from __future__ import annotations

from datetime import datetime
from decimal import Decimal, localcontext
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator
from app.utils.security import sanitize_observation, portable_observation


class ObservationModel(BaseModel):
    @model_validator(mode="before")
    @classmethod
    def protect_secrets(cls, value: Any) -> Any:
        return portable_observation(value) if isinstance(value, dict) else value


Chain = Literal["btc", "doge", "eth", "bsc", "polygon", "tron", "ton", "solana", "arbitrum", "optimism", "avalanche"]
TonAssetType = Literal["username", "gift", "nft", "domain", "jetton", "collectible"]
TonAssetEventType = Literal["mint", "first_owner", "transfer", "sale", "listing", "owner_change", "current_owner", "interaction", "received_nft", "sent_nft", "received_ton", "sent_ton", "marketplace_sale", "marketplace_purchase", "unknown_activity"]
IdentityConfidence = Literal["confirmed", "likely", "weak", "unknown"]
TonActivityLevel = Literal["high", "medium", "low", "not_detected", "insufficient_data"]
TronActivityLevel = Literal["high", "medium", "low", "not_detected", "insufficient_data"]
DogecoinActivityLevel = Literal["high", "medium", "low", "not_detected", "insufficient_data"]
WalletActivityLevel = Literal["high", "medium", "low", "not_detected", "insufficient_data"]


class Balance(ObservationModel):
    amount_decimal: Decimal | None = None
    amount_base_units: int | None = None
    decimals: int | None = None
    chain: Chain
    address: str
    asset: str
    amount: float
    source: str
    url: str | None = None
    raw: dict = Field(default_factory=dict)


class Transaction(ObservationModel):
    event_id: str | None = None
    amount_decimal: Decimal | None = None
    amount_base_units: int | None = None
    decimals: int | None = None
    success: bool | None = None
    provenance: list[dict[str, Any]] = Field(default_factory=list)
    tx_hash: str
    chain: Chain
    timestamp: datetime | None = None
    from_address: str | None = None
    to_address: str | None = None
    amount: float | None = None
    asset: str | None = None
    direction: Literal["in", "out", "self", "unknown"] = "unknown"
    fee: float | None = None
    confirmations: int | None = None
    inputs: list[dict] = Field(default_factory=list)
    outputs: list[dict] = Field(default_factory=list)
    source: str
    url: str | None = None
    raw: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def exact_amount_when_available(self):
        if self.amount_base_units is not None and self.decimals is not None and 0 <= self.decimals <= 255:
            with localcontext() as context:
                context.prec = max(80, len(str(abs(self.amount_base_units))) + self.decimals + 2)
                self.amount_decimal = Decimal(self.amount_base_units).scaleb(-self.decimals)
        return self


class TokenHolding(ObservationModel):
    holding_status: Literal["current", "historical", "unknown", "metadata"] = "unknown"
    amount_decimal: Decimal | None = None
    provenance: list[dict[str, Any]] = Field(default_factory=list)
    chain: Chain
    address: str
    contract: str | None = None
    symbol: str | None = None
    name: str | None = None
    amount: float | None = None
    source: str
    url: str | None = None
    raw: dict = Field(default_factory=dict)


class TonAssetEvent(ObservationModel):
    event_id: str | None = None
    logical_time: int | None = None
    action_index: int | None = None
    success: bool | None = None
    amount_decimal: Decimal | None = None
    price_decimal: Decimal | None = None
    provenance: list[dict[str, Any]] = Field(default_factory=list)
    event_type: TonAssetEventType
    timestamp: datetime | None = None
    direction: Literal["in", "out", "self", "unknown"] = "unknown"
    title: str | None = None
    username: str | None = None
    nft_address: str | None = None
    from_address: str = ""
    to_address: str = ""
    counterparty: str | None = None
    counterparty_label: str | None = None
    amount: float | None = None
    currency: str | None = None
    price: float | None = None
    asset: str | None = None
    tx_hash: str | None = None
    marketplace: str | None = None
    suspicious_label: str | None = None
    source: str
    evidence_url: str | None = None
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    raw: dict = Field(default_factory=dict)


class TonAsset(ObservationModel):
    ownership_status: Literal["current", "historical", "unknown"] = "unknown"
    ownership_verified: bool = False
    ownership_observed_at: datetime | None = None
    provenance: list[dict[str, Any]] = Field(default_factory=list)
    asset_id: str
    type: TonAssetType
    name: str | None = None
    title: str | None = None
    collection: str | None = None
    image_url: str | None = None
    animation_url: str | None = None
    owner_address: str = ""
    previous_owners: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    acquisition_tx: str | None = None
    history_events: list[TonAssetEvent] = Field(default_factory=list)
    history_status: str | None = None
    history_evidence_url: str | None = None
    transfer_history: list[TonAssetEvent] = Field(default_factory=list)
    sale_history: list[TonAssetEvent] = Field(default_factory=list)
    floor_price: float | None = None
    last_sale_price: float | None = None
    marketplace: str | None = None
    source: str
    external_url: str | None = None
    related_addresses: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    evidence_url: str | None = None
    evidence_tx: str | None = None
    collected_at: datetime | None = None
    raw: dict = Field(default_factory=dict)


class TonActivitySignal(ObservationModel):
    title: str
    activity: TonActivityLevel
    observation: str
    facts: dict[str, object] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low"] = "low"
    source: list[str] = Field(default_factory=list)
    status: Literal["ok", "not_detected", "insufficient_data"] = "ok"
    raw: dict = Field(default_factory=dict)


class TronActivitySignal(ObservationModel):
    title: str
    activity: TronActivityLevel
    observation: str
    facts: dict[str, object] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low"] = "low"
    source: list[str] = Field(default_factory=list)
    status: Literal["ok", "not_detected", "insufficient_data"] = "ok"
    raw: dict = Field(default_factory=dict)


class DogecoinActivitySignal(ObservationModel):
    title: str
    activity: DogecoinActivityLevel
    observation: str
    facts: dict[str, object] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low"] = "low"
    source: list[str] = Field(default_factory=list)
    status: Literal["ok", "not_detected", "insufficient_data"] = "ok"
    raw: dict = Field(default_factory=dict)


class WalletMigrationSignal(ObservationModel):
    title: str = "Wallet Migration Activity"
    activity: WalletActivityLevel
    observation: str
    facts: dict[str, object] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low"] = "low"
    source: list[str] = Field(default_factory=list)
    status: Literal["ok", "not_detected", "insufficient_data"] = "ok"
    raw: dict = Field(default_factory=dict)


class BehavioralFingerprint(ObservationModel):
    status: Literal["ok", "insufficient_data"] = "insufficient_data"
    first_activity: datetime | None = None
    last_activity: datetime | None = None
    active_weekdays: list[int] = Field(default_factory=list)
    active_hours: list[int] = Field(default_factory=list)
    peak_activity_window: str | None = None
    average_transfer_amount: float | None = None
    median_transfer_amount: float | None = None
    dominant_asset: str | None = None
    tx_per_day: float | None = None
    active_days: int = 0
    unique_counterparties: int = 0
    asset_count: int = 0
    nft_count: int = 0
    gift_count: int = 0
    marketplace_interactions: int = 0
    defi_interactions: int = 0
    heatmap: list[dict[str, int]] = Field(default_factory=list)
    fingerprint_hash: str | None = None
    source: list[str] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)


class TelegramEvidence(ObservationModel):
    claim_type: str = "unverified_metadata_association"
    upstream: str | None = None
    source: str
    evidence_url: str | None = None
    evidence_tx: str | None = None
    nft_contract: str | None = None
    parser_source: str | None = None
    details: str | None = None
    collected_at: datetime | None = None
    confidence: IdentityConfidence = "weak"
    raw: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def confidence_matches_claim(self):
        if self.claim_type == "unverified_metadata_association" and self.confidence in {"confirmed", "likely"}:
            self.confidence = "weak"
        return self


class TelegramIdentity(ObservationModel):
    association_type: str = "unverified_metadata_association"
    identity_verified: bool = False
    wallet_address: str
    username: str | None = None
    telegram_user_id: str | None = None
    confidence: IdentityConfidence = "unknown"
    domains: list[str] = Field(default_factory=list)
    asset_ids: list[str] = Field(default_factory=list)
    gifts: list[str] = Field(default_factory=list)
    evidence: list[TelegramEvidence] = Field(default_factory=list)
    source: str
    evidence_url: str | None = None
    collected_at: datetime | None = None
    raw: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def avoid_person_attribution(self):
        if not self.identity_verified and self.confidence == "confirmed":
            self.confidence = "weak"
        return self


class Label(ObservationModel):
    chain: Chain
    address: str
    label: str
    source: str
    confidence: float = Field(ge=0.0, le=1.0)
    raw: dict = Field(default_factory=dict)


class RiskFlag(ObservationModel):
    chain: Chain | Literal["multi"]
    address: str
    flag: str
    severity: Literal["low", "medium", "high"]
    source: str
    details: str | None = None
    raw: dict = Field(default_factory=dict)


class Counterparty(ObservationModel):
    address: str
    chain: Chain
    total_in: float = 0.0
    total_out: float = 0.0
    amounts_by_asset: dict[str, dict[str, Decimal]] = Field(default_factory=dict)
    aggregate_amount_valid: bool = True
    tx_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    labels: list[str] = Field(default_factory=list)
    risk_flags: list[str] = Field(default_factory=list)


class ActivityChain(ObservationModel):
    chain_type: Literal["recurring_counterparty", "asset_path", "routing_loop", "jetton_path", "nft_path"]
    title: str
    summary: str
    addresses: list[str] = Field(default_factory=list)
    asset: str | None = None
    tx_hashes: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source: str
    evidence_url: str | None = None
    confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    raw: dict = Field(default_factory=dict)


class SourceHealth(ObservationModel):
    source: str
    status: Literal["ok", "partial", "empty", "timeout", "error", "experimental", "skipped", "rate_limited", "unavailable"]
    timeout_seconds: float | None = None
    retry_strategy: str | None = None
    details: str | None = None
    partial: bool = True


class InactivityPeriod(ObservationModel):
    from_time: datetime
    to_time: datetime
    days: int


class ActivityBurst(ObservationModel):
    chain: Chain
    start_time: datetime
    end_time: datetime
    tx_count: int


class WalletTimeline(ObservationModel):
    first_activity: datetime | None = None
    last_activity: datetime | None = None
    active_days: int = 0
    inactivity_periods: list[InactivityPeriod] = Field(default_factory=list)
    bursts: list[ActivityBurst] = Field(default_factory=list)


class AssetPath(ObservationModel):
    asset_id: str
    asset_type: TonAssetType
    title: str | None = None
    current_owner: str = ""
    previous_owners: list[str] = Field(default_factory=list)
    tx_chain: list[str] = Field(default_factory=list)
    marketplace_links: list[str] = Field(default_factory=list)
    source: str


class CounterpartyRankingEntry(ObservationModel):
    address: str
    chain: Chain
    tx_count: int = 0
    total_in: float = 0.0
    total_out: float = 0.0
    last_seen: datetime | None = None
    labels: list[str] = Field(default_factory=list)


class CounterpartyRanking(ObservationModel):
    most_frequent: list[CounterpartyRankingEntry] = Field(default_factory=list)
    biggest_transfers: list[CounterpartyRankingEntry] = Field(default_factory=list)
    latest_interactions: list[CounterpartyRankingEntry] = Field(default_factory=list)


class ServiceDetection(ObservationModel):
    address: str
    chain: Chain | Literal["multi"]
    category: Literal["exchange", "marketplace", "service"]
    name: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source: str
    evidence: str | None = None


class AddressReport(ObservationModel):
    # Preserve the user's NFT identifier when the analysis target is its owner.
    input_resolution: dict = Field(default_factory=dict)
    nft_intelligence: dict[str, Any] | None = None
    ton_service_intelligence: dict[str, Any] = Field(default_factory=dict)
    attribution_intelligence: dict[str, Any] = Field(default_factory=dict)
    contract_observations: list[dict[str, Any]] = Field(default_factory=list)
    collection_audit: dict[str, Any] = Field(default_factory=dict)
    schema_version: str = "0.3"
    financial_summary: dict[str, dict[str, Decimal]] = Field(default_factory=dict)
    coverage: dict[str, Any] = Field(default_factory=dict)
    target_address: str
    detected_chains: list[Chain] = Field(default_factory=list)
    balances: list[Balance] = Field(default_factory=list)
    transactions: list[Transaction] = Field(default_factory=list)
    tokens: list[TokenHolding] = Field(default_factory=list)
    ton_assets: list[TonAsset] = Field(default_factory=list)
    ton_activity_intelligence: list[TonActivitySignal] = Field(default_factory=list)
    tron_activity_intelligence: list[TronActivitySignal] = Field(default_factory=list)
    dogecoin_activity_intelligence: list[DogecoinActivitySignal] = Field(default_factory=list)
    wallet_migration: WalletMigrationSignal | None = None
    behavioral_fingerprint: BehavioralFingerprint | None = None
    telegram_identities: list[TelegramIdentity] = Field(default_factory=list)
    labels: list[Label] = Field(default_factory=list)
    counterparties: list[Counterparty] = Field(default_factory=list)
    activity_chains: list[ActivityChain] = Field(default_factory=list)
    wallet_timeline: WalletTimeline = Field(default_factory=WalletTimeline)
    asset_paths: list[AssetPath] = Field(default_factory=list)
    counterparty_ranking: CounterpartyRanking = Field(default_factory=CounterpartyRanking)
    service_detections: list[ServiceDetection] = Field(default_factory=list)
    bitcoin: dict = Field(default_factory=dict)
    dogecoin: dict = Field(default_factory=dict)
    bsc: dict = Field(default_factory=dict)
    tron: dict = Field(default_factory=dict)
    solana: dict = Field(default_factory=dict)
    ens_name: str | None = None
    reverse_ens: str | None = None
    resolver: str | None = None
    ens_reverse_resolver: str | None = None
    ens_owner: str | None = None
    ens_resolved_address: str | None = None
    ens_reverse_valid: bool | None = None
    avatar: str | None = None
    text_records: dict[str, str] = Field(default_factory=dict)
    ens_profile: dict[str, Any] = Field(default_factory=dict)
    # Source-scoped public claims; these never add financial rows or a risk score.
    public_address_context: dict[str, Any] = Field(default_factory=dict)
    ens_warnings: list[str] = Field(default_factory=list)
    source_health: list[SourceHealth] = Field(default_factory=list)
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_flags: list[RiskFlag] = Field(default_factory=list)
    sources_used: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

