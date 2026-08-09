"""
backend/app/models/api_models.py — Request/response schemas for the API.

These wrap the agent-layer's schema.py types into API-friendly
request/response models. Kept separate from agents/orchestrator/schema.py
because API contracts (what the frontend sees) and internal pipeline
contracts (what agents pass to each other) can evolve independently.
"""

from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel, Field

from agents.orchestrator.schema import (
    StaticAnalysisOutput,
    DynamicAnalysisOutput,
    MitreTechnique,
    CapabilityTag,
)


class YaraMatchDetail(BaseModel):
    """A single rule-engine match, as returned by the static-analysis engine."""
    rule_name: str
    category: str
    severity: str
    description: str


class PackingInfo(BaseModel):
    """Packing detection + best-effort unpacking result (see static-analysis's packing/ package)."""
    is_packed: bool
    packer_name: Optional[str] = None
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    unpack_attempted: bool = False
    unpack_succeeded: bool = False
    unpack_method: Optional[str] = None
    unpack_error: Optional[str] = None
    unpacked_sha256: Optional[str] = None


class ExplainedStringDetail(BaseModel):
    """A single extracted string with its plain-language explanation (see strings/explain.py)."""
    value: str
    type: str
    category: str
    explanation: str
    severity: str


class GeoIocDetail(BaseModel):
    """A single IP indicator resolved to a detailed geographic + ASN attribution.

    Only `ip` is guaranteed; every other field is optional and comes back as
    None when the MaxMind databases aren't configured, the address is private/
    non-routable, or the DB doesn't cover it. The PDF report renderer treats
    None as "not available" rather than an error.
    """
    ip: str
    country: Optional[str] = None
    country_iso: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    postal_code: Optional[str] = None
    timezone: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_radius: Optional[int] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    isp: Optional[str] = None
    is_hosting: Optional[bool] = None
    is_proxy: Optional[bool] = None
    threat_level: Optional[str] = None


class SubmitSampleRequest(BaseModel):
    """
    Body for POST /api/cases/submit.
    In Week 2/3, static/dynamic data is supplied directly (since
    Member 1/2's real services aren't wired to the DB yet). In
    Week 4+, this becomes just {"sample_id": "..."} once static and
    dynamic results are already persisted by their respective modules
    and this endpoint just triggers the agent pipeline against them.
    """
    static_analysis: StaticAnalysisOutput
    dynamic_analysis: Optional[DynamicAnalysisOutput] = None


class CaseSummary(BaseModel):
    """Lightweight summary for list views (case table on the dashboard)."""
    sample_id: str
    platform: str
    file_type: str
    risk_score: int
    status: str  # "malicious" | "suspicious" | "clean" — derived from risk_score
    submitted_at: str


class CaseDetail(BaseModel):
    """Full case detail — matches the agent-layer output contract, extended
    with the richer static-analysis findings (hashes, YARA matches, packing,
    explained strings) needed for a real evidentiary report rather than a
    generic summary."""
    sample_id: str
    platform: str
    file_type: str
    risk_score: int
    status: str
    mitre_techniques: list[MitreTechnique]
    capability_tags: list[CapabilityTag]
    narrative_summary: str
    submitted_at: str
    file_size_bytes: Optional[int] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    yara_matches: list[YaraMatchDetail] = Field(default_factory=list)
    packing: Optional[PackingInfo] = None
    explained_strings: list[ExplainedStringDetail] = Field(default_factory=list)
    geo_iocs: list[GeoIocDetail] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str
    sandbox_online: bool
    version: str
    # False means the API is running on the in-memory fallback store and every
    # write is being discarded on restart (see backend/app/db.py init_db()).
    # Surfaced here because that failure is otherwise invisible from outside.
    database_online: bool = False


def risk_score_to_status(score: int) -> str:
    """Shared logic for turning a numeric score into a dashboard status badge."""
    if score >= 60:
        return "malicious"
    elif score >= 25:
        return "suspicious"
    return "clean"