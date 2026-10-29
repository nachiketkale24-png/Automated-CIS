from datetime import datetime
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field


# ── Finding status validation ──────────────────────────────────────────
class FindingStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL = "MANUAL"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# ── Finding schemas ────────────────────────────────────────────────────
class FindingInput(BaseModel):
    """Finding submitted as part of an audit creation request."""
    rule_id: str = Field(min_length=1)
    status: FindingStatus
    severity: str = "Medium"
    expected: str | None = Field(default=None, alias="expected_value")
    actual: str | None = Field(default=None, alias="actual_value")
    evidence_source: str | None = None
    evidence: dict = Field(default_factory=dict)
    remediation: str | None = None

    model_config = ConfigDict(populate_by_name=True)


class FindingRead(BaseModel):
    """Finding returned from the API."""
    id: int
    rule_id: str
    status: str
    severity: str
    expected: str | None
    actual: str | None
    evidence_source: str | None
    evidence: dict
    remediation: str | None
    model_config = ConfigDict(from_attributes=True)


# ── Snapshot schema (re-exported from Chinmay's work) ──────────────────
class SnapshotInput(BaseModel):
    evidence: dict = Field(default_factory=dict)
    is_simulated: bool = True


# ── Audit schemas ──────────────────────────────────────────────────────
class AuditCreate(BaseModel):
    """Request body for POST /api/audits."""
    asset_id: int
    benchmark_version: str | None = Field(
        default=None,
        description="CIS benchmark version string, e.g. 'CIS_Cisco_IOS_17_v2.1.0'",
    )
    is_simulated: bool = True
    # The following fields allow the caller to include findings / snapshot
    # at creation time (Chinmay's existing pattern).  When omitted the audit
    # starts as 'pending'.
    status: str = "pending"
    score: float | None = Field(default=None, ge=0, le=100)
    findings: list[FindingInput] = Field(default_factory=list)
    snapshot: SnapshotInput | None = None


class AuditSummary(BaseModel):
    """Lightweight audit representation for list endpoints."""
    id: int
    asset_id: int
    status: str
    score: float | None
    is_simulated: bool
    benchmark_version: str | None
    started_at: datetime
    completed_at: datetime | None
    model_config = ConfigDict(from_attributes=True)


class AuditRead(BaseModel):
    """Full audit with findings for detail endpoints."""
    id: int
    asset_id: int
    status: str
    score: float | None
    is_simulated: bool
    benchmark_version: str | None
    started_at: datetime
    completed_at: datetime | None
    findings: list[FindingRead] = []
    model_config = ConfigDict(from_attributes=True)
