from datetime import datetime, timezone
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import select, func
from fastapi import HTTPException

from app.models import Asset, Audit, Finding, Snapshot
from app.schemas.asset import AssetCreate
from app.schemas.audit import AuditCreate


# ── Asset persistence ──────────────────────────────────────────────────

def list_assets(db: Session) -> list[Asset]:
    return list(db.scalars(select(Asset).order_by(Asset.id.desc())).all())


def get_asset(db: Session, asset_id: int) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


def create_asset(db: Session, data: AssetCreate) -> Asset:
    # mode="json" serialises Enum to its .value string — works with both MySQL and SQLite
    asset = Asset(**data.model_dump(mode="json"))
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


# ── Audit persistence ─────────────────────────────────────────────────

def create_audit(db: Session, data: AuditCreate) -> Audit:
    asset = db.get(Asset, data.asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Determine status and completed_at based on whether findings are
    # provided at creation time.
    status = data.status
    completed_at = None
    if data.findings and status == "pending":
        # Caller submitted findings inline → mark as completed
        status = "COMPLETED"
        completed_at = datetime.now(timezone.utc)
    elif status not in ("pending",):
        # Explicit status supplied (e.g. "COMPLETED") – trust it
        completed_at = datetime.now(timezone.utc)

    audit = Audit(
        asset_id=data.asset_id,
        status=status,
        score=data.score,
        is_simulated=data.is_simulated,
        benchmark_version=data.benchmark_version,
        completed_at=completed_at,
    )
    for item in data.findings:
        audit.findings.append(Finding(
            rule_id=item.rule_id,
            status=item.status,
            severity=item.severity,
            expected=item.expected,
            actual=item.actual,
            evidence_source=item.evidence_source,
            evidence_json=item.evidence,
            remediation=item.remediation,
        ))
    if data.snapshot is not None:
        audit.snapshots.append(Snapshot(
            evidence_json=data.snapshot.evidence,
            is_simulated=data.snapshot.is_simulated,
        ))
    db.add(audit)
    db.commit()
    return get_audit(db, audit.id)


def list_audits(db: Session, skip: int = 0, limit: int = 50) -> tuple[list[Audit], int]:
    """Return paginated audits and total count."""
    total = db.scalar(select(func.count(Audit.id))) or 0
    audits = list(
        db.scalars(
            select(Audit)
            .order_by(Audit.started_at.desc())
            .offset(skip)
            .limit(limit)
        ).all()
    )
    return audits, total


def get_audit(db: Session, audit_id: int) -> Audit:
    stmt = select(Audit).options(selectinload(Audit.findings)).where(Audit.id == audit_id)
    audit = db.scalars(stmt).first()
    if audit is None:
        raise HTTPException(status_code=404, detail="Audit not found")
    return audit


def get_audit_findings(db: Session, audit_id: int) -> list[Finding]:
    audit = db.get(Audit, audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="Audit not found")
    return list(db.scalars(select(Finding).where(Finding.audit_id == audit_id).order_by(Finding.id)).all())
