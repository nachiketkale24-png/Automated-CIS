"""
GET /api/audits/{audit_id}/correlations

Returns a JSON array of computed exposure correlations for the given audit.
Correlations are read-only and deterministic — they do not mutate stored data.
Returns [] if no correlation rules match.
Returns 404 if the audit does not exist.

This endpoint is backward-compatible; it is added alongside existing
/audits/{audit_id}, /audits/{audit_id}/findings, and /audits/{audit_id}/drift
endpoints without modifying them.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.persistence import get_audit, get_audit_findings
from app.services.correlation_engine import compute_correlations

router = APIRouter(prefix="/audits", tags=["correlations"])


@router.get("/{audit_id}/correlations")
def get_correlations(audit_id: int, db: Session = Depends(get_db)):
    """
    Compute and return exposure correlations for a stored audit.

    - **audit_id**: ID of a previously completed audit.
    - Returns a JSON array; empty array when no rules match.
    - 404 when the audit does not exist.
    - Never modifies the audit or its findings.
    - Results are deterministic: same audit → same output.
    """
    # get_audit raises HTTPException(404) if not found
    audit = get_audit(db, audit_id)
    findings = get_audit_findings(db, audit_id)

    correlations = compute_correlations(
        audit_id=audit.id,
        asset_id=audit.asset_id,
        is_simulated=audit.is_simulated,
        findings=findings,
    )
    return correlations
