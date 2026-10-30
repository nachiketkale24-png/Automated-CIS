"""
Audit runner service — ties together loader, collector, evaluator,
scorer, and the existing persistence layer.

Uses ONLY existing SQLAlchemy models and persistence helpers from
app.services.persistence. Does not duplicate database logic.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.collectors import cisco as cisco_collector
from app.collectors import linux as linux_collector
from app.collectors import windows as windows_collector
from app.engine.evaluator import evaluate_rules
from app.engine.loader import RuleValidationError, load_rules_for_asset_type
from app.engine.scorer import compute_score
from app.models import Asset, Audit, Finding, Snapshot
from app.services.persistence import get_asset

logger = logging.getLogger(__name__)

# Path to the rules directory (relative to backend/)
_RULES_DIR = Path(__file__).parent.parent.parent / "rules"

# Path to fixtures directory (relative to backend/)
_FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"

SUPPORTED_FIXTURES = {
    "cisco_baseline": _FIXTURES_DIR / "baseline" / "cisco_running_config.txt",
    "cisco_modified": _FIXTURES_DIR / "modified" / "cisco_running_config.txt",
    "windows_baseline": _FIXTURES_DIR / "baseline" / "windows_config.json",
    "windows_hardened": _FIXTURES_DIR / "hardened" / "windows_config.json",
}


def _collect_evidence(
    asset: Asset,
    fixture_name: str | None,
) -> dict[str, Any]:
    """
    Collect evidence for the given asset.

    If fixture_name is provided, loads from that fixture file (is_simulated=True).
    Otherwise attempts live collection based on asset_type (Linux or Windows).

    Raises HTTPException(400) for unknown fixture names.
    Returns an evidence dict (may contain '_error' key on failure).
    """
    if fixture_name is not None:
        if fixture_name not in SUPPORTED_FIXTURES:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown fixture '{fixture_name}'. "
                       f"Supported: {sorted(SUPPORTED_FIXTURES.keys())}",
            )
        path = SUPPORTED_FIXTURES[fixture_name]
        if fixture_name.startswith("cisco"):
            return cisco_collector.collect_from_file(
                path,
                source_label=f"cisco_fixture:{fixture_name}",
            )
        if fixture_name.startswith("windows"):
            return windows_collector.collect_from_file(
                path,
                source_label=f"windows_fixture:{fixture_name}",
            )

    # No fixture → live collection based on asset_type
    asset_type = asset.asset_type.lower()
    if asset_type == "linux":
        return linux_collector.collect()
    if asset_type == "windows":
        return windows_collector.collect()

    raise HTTPException(
        status_code=400,
        detail=f"Live collection not supported for asset_type '{asset_type}'. "
               "Provide a fixture_name for simulated audits.",
    )


def run_audit(
    db: Session,
    asset_id: int,
    fixture_name: str | None = None,
    benchmark_version: str | None = None,
) -> dict[str, Any]:
    """
    Full end-to-end audit pipeline:
      1. Validate asset exists
      2. Load rules for the asset type (or fixture's implied type)
      3. Collect / load evidence
      4. Evaluate rules → findings
      5. Compute score
      6. Persist audit + findings + snapshot using existing models
      7. Return summary

    An audit is only marked COMPLETED when steps 4-6 all succeed.
    On any collection error, the audit is saved as 'ERROR' status.
    """
    # 1. Validate asset
    asset = get_asset(db, asset_id)  # raises 404 if not found

    # Determine effective asset_type for rule loading
    effective_type = asset.asset_type.lower()
    is_simulated = fixture_name is not None

    # For Cisco fixtures, force the rule set to 'router'
    if fixture_name and fixture_name.startswith("cisco"):
        effective_type = "router"
    elif fixture_name and fixture_name.startswith("windows"):
        effective_type = "windows"

    # Set default benchmark_version if not provided
    if not benchmark_version:
        if effective_type == "windows":
            benchmark_version = "CIS_Windows_Server_2022_v1.0_ILLUSTRATIVE"
        elif effective_type in ("router", "firewall", "switch", "network_device"):
            benchmark_version = "CIS_Cisco_IOS_17_v2.1.0"
        elif effective_type == "linux":
            benchmark_version = "CIS_Ubuntu_Linux_22.04_v1.0"

    # 2. Load rules
    try:
        rules = load_rules_for_asset_type(_RULES_DIR, effective_type)
    except (RuleValidationError, FileNotFoundError) as exc:
        raise HTTPException(status_code=500, detail=f"Rule loading failed: {exc}") from exc

    if not rules:
        raise HTTPException(
            status_code=400,
            detail=f"No rules available for asset type '{effective_type}'. "
                   "Cannot produce a meaningful audit.",
        )

    # 3. Collect evidence
    evidence = _collect_evidence(asset, fixture_name)

    # Check for collection-level error
    collection_failed = "_error" in evidence

    # 4. Evaluate rules (still run even on collection error — all will be ERROR/MANUAL)
    findings_data = evaluate_rules(rules, evidence)

    # 5. Score
    score_result = compute_score(findings_data)
    score = score_result["score"]

    # Determine audit status
    audit_status = "ERROR" if collection_failed else "COMPLETED"

    # 6. Persist
    audit = Audit(
        asset_id=asset_id,
        status="running",          # set running first, update on success
        score=None,
        is_simulated=is_simulated,
        benchmark_version=benchmark_version,
        completed_at=None,
    )
    db.add(audit)
    db.flush()  # get audit.id without committing yet

    # Persist findings
    for fd in findings_data:
        finding = Finding(
            audit_id=audit.id,
            rule_id=fd["rule_id"],
            status=fd["status"],
            severity=fd["severity"],
            expected=fd.get("expected"),
            actual=fd.get("actual"),
            evidence_source=fd.get("evidence_source"),
            evidence_json=fd.get("evidence") or {},
            remediation=fd.get("remediation"),
        )
        db.add(finding)

    # Persist snapshot (normalised evidence, excluding internal _source and _error keys)
    snapshot_evidence = {k: v for k, v in evidence.items() if not k.startswith("_")}
    snapshot = Snapshot(
        audit_id=audit.id,
        evidence_json=snapshot_evidence,
        is_simulated=is_simulated,
    )
    db.add(snapshot)

    # Update audit to final status
    audit.status = audit_status
    audit.score = score
    audit.completed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(audit)

    logger.info(
        "Audit %d completed: status=%s score=%s findings=%d",
        audit.id, audit_status, score, len(findings_data),
    )

    return {
        "audit_id": audit.id,
        "asset_id": asset_id,
        "status": audit_status,
        "score": score,
        "coverage_pct": score_result["coverage_pct"],
        "is_simulated": is_simulated,
        "fixture_name": fixture_name,
        "benchmark_version": benchmark_version,
        "finding_counts": {
            "pass": score_result["pass_count"],
            "fail": score_result["fail_count"],
            "manual": score_result["manual_count"],
            "error": score_result["error_count"],
            "not_applicable": score_result["na_count"],
            "total": score_result["total"],
        },
    }
