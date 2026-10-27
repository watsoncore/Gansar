"""Typed assertions describe one relation; a transfer is never ownership proof."""
from typing import Any,Literal
from pydantic import Field
from app.models.report import ObservationModel

Status=Literal['CONFIRMED','PROBABLE','POSSIBLE','UNKNOWN']

class AttributionClaim(ObservationModel):
    attribution_id:str
    blockchain:str
    address:str
    entity_name:str
    entity_type:str
    relationship:str
    status:Status='UNKNOWN'
    confidence_rationale:str
    method:str
    evidence_ids:list[str]=Field(default_factory=list)
    source_urls:list[str]=Field(default_factory=list)
    observation_timestamps:list[str]=Field(default_factory=list)
    conflicting_evidence:list[str]=Field(default_factory=list)
    alternative_explanations:list[str]=Field(default_factory=list)
    coverage_limitations:list[str]=Field(default_factory=list)
    icon_reference:str|None=None

class Evidence(ObservationModel):
    evidence_id:str
    source:str
    upstream:str
    url:str
    observed_at:str
    relation:str
    blockchain:str
    address:str|None=None
    transaction_hash:str|None=None
    facts:dict[str,Any]=Field(default_factory=dict)
    source_independence:str='unestablished'
