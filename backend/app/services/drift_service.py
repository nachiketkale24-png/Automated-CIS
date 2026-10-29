from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models import Audit, Snapshot


def _flatten(value: object, prefix: str = "") -> dict[str, object]:
    result: dict[str, object] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            result.update(_flatten(child, path))
    else:
        result[prefix] = value
    return result


def compare_latest_snapshots(db: Session, audit_id: int) -> dict:
    current_audit = db.get(Audit, audit_id)
    if current_audit is None:
        raise HTTPException(status_code=404, detail="Audit not found")

    snapshots = list(db.scalars(
        select(Snapshot)
        .join(Audit, Snapshot.audit_id == Audit.id)
        .where(Audit.asset_id == current_audit.asset_id, Audit.id != audit_id)
        .order_by(Audit.started_at.desc(), Snapshot.id.desc())
    ).all())
    current_snapshot = db.scalars(
        select(Snapshot).where(Snapshot.audit_id == audit_id).order_by(Snapshot.id.desc())
    ).first()
    if current_snapshot is None:
        raise HTTPException(status_code=404, detail="Current audit has no snapshot")
    if not snapshots:
        return {"asset_id": current_audit.asset_id, "baseline_audit_id": None,
                "current_audit_id": audit_id, "changes": [],
                "message": "No previous snapshot exists for this asset; current snapshot is the baseline."}

    baseline_snapshot = snapshots[0]
    before = _flatten(baseline_snapshot.evidence_json or {})
    after = _flatten(current_snapshot.evidence_json or {})
    changes = []
    for key in sorted(set(before) | set(after)):
        if key not in before:
            changes.append({"setting": key, "change_type": "added", "before": None, "after": after[key]})
        elif key not in after:
            changes.append({"setting": key, "change_type": "removed", "before": before[key], "after": None})
        elif before[key] != after[key]:
            changes.append({"setting": key, "change_type": "modified", "before": before[key], "after": after[key]})
    return {"asset_id": current_audit.asset_id, "baseline_audit_id": baseline_snapshot.audit_id,
            "current_audit_id": audit_id, "changes": changes}
