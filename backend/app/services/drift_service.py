
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Audit, Finding, Snapshot


def _flatten(value: object, prefix: str = "") -> dict[str, object]:
    result: dict[str, object] = {}

    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            result.update(_flatten(child, path))
    elif prefix:
        result[prefix] = value

    return result


def _same_value(before: object, after: object) -> bool:
    return type(before) is type(after) and before == after


def compare_latest_snapshots(db: Session, audit_id: int) -> dict:
    current_audit = db.get(Audit, audit_id)

    if current_audit is None:
        raise HTTPException(status_code=404, detail="Audit not found")

    current_snapshot = db.scalars(
        select(Snapshot)
        .where(Snapshot.audit_id == audit_id)
        .order_by(Snapshot.id.desc())
    ).first()

    if current_snapshot is None:
        raise HTTPException(
            status_code=404,
            detail="Current audit has no snapshot",
        )

    baseline_snapshot = db.scalars(
        select(Snapshot)
        .join(Audit, Snapshot.audit_id == Audit.id)
        .where(
            Audit.asset_id == current_audit.asset_id,
            Audit.id != audit_id,
            Audit.status == "COMPLETED",
            Audit.is_simulated == current_snapshot.is_simulated,
            Snapshot.is_simulated == current_snapshot.is_simulated,
        )
        .order_by(
            Audit.started_at.desc(),
            Audit.id.desc(),
            Snapshot.id.desc(),
        )
    ).first()

    current_evidence = _flatten(current_snapshot.evidence_json or {})

    if baseline_snapshot is None:
        return {
            "asset_id": current_audit.asset_id,
            "baseline_audit_id": None,
            "current_audit_id": audit_id,
            "is_simulated": current_snapshot.is_simulated,
            "changes": [],
            "newly_failing_controls": [],
            "resolved_controls": [],
            "message": (
                "No previous completed snapshot of the same type exists "
                "for this asset. Current snapshot is the baseline."
            ),
        }

    baseline_evidence = _flatten(baseline_snapshot.evidence_json or {})
    changes = []

    for key in sorted(set(baseline_evidence) | set(current_evidence)):
        if key not in baseline_evidence:
            changes.append({
                "setting": key,
                "change_type": "added",
                "before": None,
                "after": current_evidence[key],
            })
        elif key not in current_evidence:
            changes.append({
                "setting": key,
                "change_type": "removed",
                "before": baseline_evidence[key],
                "after": None,
            })
        elif not _same_value(baseline_evidence[key], current_evidence[key]):
            changes.append({
                "setting": key,
                "change_type": "modified",
                "before": baseline_evidence[key],
                "after": current_evidence[key],
            })

    baseline_findings = list(db.scalars(
        select(Finding).where(
            Finding.audit_id == baseline_snapshot.audit_id
        )
    ).all())

    current_findings = list(db.scalars(
        select(Finding).where(
            Finding.audit_id == audit_id
        )
    ).all())

    baseline_by_rule = {f.rule_id: f for f in baseline_findings}
    current_by_rule = {f.rule_id: f for f in current_findings}

    newly_failing_controls = []
    resolved_controls = []

    for rule_id in sorted(set(baseline_by_rule) | set(current_by_rule)):
        before = baseline_by_rule.get(rule_id)
        after = current_by_rule.get(rule_id)

        before_status = before.status.upper() if before else None
        after_status = after.status.upper() if after else None

        if after_status == "FAIL" and before_status != "FAIL":
            newly_failing_controls.append({
                "rule_id": rule_id,
                "previous_status": before_status,
                "current_status": after_status,
                "severity": after.severity,
            })

        elif before_status == "FAIL" and after_status == "PASS":
            resolved_controls.append({
                "rule_id": rule_id,
                "previous_status": before_status,
                "current_status": after_status,
                "severity": before.severity,
            })

    return {
        "asset_id": current_audit.asset_id,
        "baseline_audit_id": baseline_snapshot.audit_id,
        "current_audit_id": audit_id,
        "is_simulated": current_snapshot.is_simulated,
        "changes": changes,
        "newly_failing_controls": newly_failing_controls,
        "resolved_controls": resolved_controls,
    }
