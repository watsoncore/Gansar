"""Typed, conservative attribution records; contract identity is not client identity."""
from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import Field

from app.models.report import ObservationModel


class AttributionStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    UNKNOWN = "UNKNOWN"


class ContractDescriptor(ObservationModel):
    kind: str = "unknown"
    code_hash: str | None = None
    code_hashes: dict[str, str] = Field(default_factory=dict)
    wallet_version: str | None = None
    interfaces: list[str] = Field(default_factory=list)
    status: AttributionStatus = AttributionStatus.UNKNOWN
    evidence_ids: list[str] = Field(default_factory=list)


class ServiceAttribution(ObservationModel):
    attribution_id: str
    service_id: str
    name: str
    category: str = "public_address_label"
    status: AttributionStatus = AttributionStatus.UNKNOWN
    method: str
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)
    source_url: str | None = None
    observed_at: str | None = None
    conflicts: list[str] = Field(default_factory=list)


class AddressAttribution(ObservationModel):
    address: str
    account_status: str = "unknown"
    account_type: str = "unknown"
    contract: ContractDescriptor = Field(default_factory=ContractDescriptor)
    attributions: list[ServiceAttribution] = Field(default_factory=list)
    client_attribution: dict[str, Any] = Field(default_factory=lambda: {
        "status": "UNKNOWN", "reason": "Public contract state does not identify the user's wallet application."})
    evidence_ids: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    observed_at: str | None = None


class AttributionEvidence(ObservationModel):
    evidence_id: str
    source: str
    upstream: str
    url: str
    observed_at: str
    relation: str
    address: str | None = None
    transaction_hash: str | None = None
    observation_id: str | None = None
    facts: dict[str, Any] = Field(default_factory=dict)
