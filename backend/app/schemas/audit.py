from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


ALLOWED_STATUSES = {"PASS", "FAIL", "MANUAL", "ERROR", "NOT APPLICABLE"}


class FindingInput(BaseModel):
    rule_id: str
    status: str
    severity: str = "Medium"
    expected: str | None = None
    actual: str | None = None
    evidence_source: str | None = None
    evidence: dict = Field(default_factory=dict)
    remediation: str | None = None


class SnapshotInput(BaseModel):
    evidence: dict = Field(default_factory=dict)
    is_simulated: bool = True


class AuditCreate(BaseModel):
    asset_id: int
    status: str = "COMPLETED"
    score: float | None = Field(default=None, ge=0, le=100)
    is_simulated: bool = True
    findings: list[FindingInput] = Field(default_factory=list)
    snapshot: SnapshotInput | None = None


class FindingRead(BaseModel):
    id: int
    rule_id: str
    status: str
    severity: str
    expected: str | None
    actual: str | None
    evidence_source: str | None
    evidence: dict
    remediation: str | None


class AuditRead(BaseModel):
    id: int
    asset_id: int
    status: str
    score: float | None
    is_simulated: bool
    started_at: datetime
    completed_at: datetime | None
    findings: list[FindingRead] = []
    model_config = ConfigDict(from_attributes=True)
