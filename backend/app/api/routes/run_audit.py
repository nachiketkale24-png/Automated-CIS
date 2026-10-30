"""
POST /api/run-audit — trigger a deterministic fixture or live audit.

This is a backward-compatible addition. Existing endpoints are unchanged.
Findings are persisted and retrievable via existing GET /api/audits/{id}/findings.
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.audit_runner import run_audit, SUPPORTED_FIXTURES

router = APIRouter(prefix="/run-audit", tags=["run-audit"])


class RunAuditRequest(BaseModel):
    asset_id: int = Field(description="ID of the asset to audit")
    fixture_name: str | None = Field(
        default=None,
        description=(
            "Name of a pre-defined fixture for simulated audits. "
            f"Supported values: {sorted(SUPPORTED_FIXTURES.keys())}. "
            "If None, attempts live collection (Linux or Windows)."
        ),
    )
    benchmark_version: str | None = Field(
        default=None,
        description="Optional benchmark version string, e.g. 'CIS_Cisco_IOS_17_v2.1.0' or 'CIS_Windows_Server_2022_v1.0_ILLUSTRATIVE'",
    )


class RunAuditResponse(BaseModel):
    audit_id: int
    asset_id: int
    status: str
    score: float | None
    coverage_pct: float
    is_simulated: bool
    fixture_name: str | None
    benchmark_version: str | None
    finding_counts: dict


@router.post("", response_model=RunAuditResponse, status_code=201)
def trigger_audit(payload: RunAuditRequest, db: Session = Depends(get_db)):
    """
    Trigger a full CIS compliance audit for an asset.

    - **fixture_name**: use 'cisco_baseline', 'cisco_modified', 'windows_baseline', or 'windows_hardened'.
    - Findings are persisted and retrievable at GET /api/audits/{audit_id}/findings.
    - All fixture audits are marked is_simulated=true.
    - Score = PASS/(PASS+FAIL)*100. None if no assessable findings.
    """
    result = run_audit(
        db=db,
        asset_id=payload.asset_id,
        fixture_name=payload.fixture_name,
        benchmark_version=payload.benchmark_version,
    )
    return result
