from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.schemas.audit import AuditCreate, AuditRead, AuditSummary, FindingRead
from app.services.persistence import create_audit, get_audit, get_audit_findings, list_audits
from app.models import Finding

router = APIRouter(prefix="/audits", tags=["audits"])


def _finding_read(item: Finding) -> dict:
    return {"id": item.id, "rule_id": item.rule_id, "status": item.status,
            "severity": item.severity, "expected": item.expected, "actual": item.actual,
            "evidence_source": item.evidence_source, "evidence": item.evidence_json or {},
            "remediation": item.remediation}


@router.get("", response_model=dict)
def get_audits(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    audits, total = list_audits(db, skip=skip, limit=limit)
    return {
        "items": [AuditSummary.model_validate(a).model_dump() for a in audits],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.post("", response_model=AuditRead, status_code=201)
def post_audit(payload: AuditCreate, db: Session = Depends(get_db)):
    audit = create_audit(db, payload)
    return {"id": audit.id, "asset_id": audit.asset_id, "status": audit.status,
            "score": audit.score, "is_simulated": audit.is_simulated,
            "benchmark_version": audit.benchmark_version,
            "started_at": audit.started_at, "completed_at": audit.completed_at,
            "findings": [_finding_read(f) for f in audit.findings]}


@router.get("/{audit_id}", response_model=AuditRead)
def get_audit_by_id(audit_id: int, db: Session = Depends(get_db)):
    audit = get_audit(db, audit_id)
    return {"id": audit.id, "asset_id": audit.asset_id, "status": audit.status,
            "score": audit.score, "is_simulated": audit.is_simulated,
            "benchmark_version": audit.benchmark_version,
            "started_at": audit.started_at, "completed_at": audit.completed_at,
            "findings": [_finding_read(f) for f in audit.findings]}


@router.get("/{audit_id}/findings", response_model=list[FindingRead])
def get_findings(audit_id: int, db: Session = Depends(get_db)):
    return [_finding_read(f) for f in get_audit_findings(db, audit_id)]
