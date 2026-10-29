"""
Task 5 — Exposure Correlation Engine (read-only, deterministic).

Design principles:
- Correlations are COMPUTED, not stored. No new database tables.
- Every correlation is derived from persisted Finding records only.
- No evidence is fabricated or assumed.
- Attack paths are NEVER confirmed without explicit reachability evidence.
- Repeated calls with the same data always return the same result.
- Fixture-derived results (is_simulated=True on the audit) are labelled accordingly.

Two implemented rules
---------------------
CORR-001  Insecure Management Access (same-audit, same-asset)
  Triggers when BOTH:
    - NET-SSH-001  status == "FAIL"   (SSH not enabled)
    - NET-TELNET-002  status == "FAIL"  (Telnet enabled)
  are present in the same audit's findings.

CORR-002  Cross-Asset Related Exposure
  Conservative by design: no confirmed cross-asset correlation is returned
  unless explicit network-relationship evidence is stored in the findings.
  The current data model does not carry verified reachability; therefore
  CORR-002 always returns no results — the rule exists to document the
  contract and can be extended once relationship data is added.
"""
from __future__ import annotations

from typing import Any

# ── Rule trigger definitions ────────────────────────────────────────────────

_CORR_001_TRIGGERS: set[str] = {"NET-SSH-001", "NET-TELNET-002"}

_CORR_001_META: dict[str, Any] = {
    "rule_id": "CORR-001",
    "title": "Insecure management access",
    "severity": "High",
    "recommendation": (
        "Enable SSHv2 ('ip ssh version 2'), disable Telnet on all VTY lines "
        "('transport input ssh'), and restrict management access to approved "
        "source addresses via an access-class ACL."
    ),
}


# ── Public API ───────────────────────────────────────────────────────────────

def compute_correlations(
    audit_id: int,
    asset_id: int,
    is_simulated: bool,
    findings: list[Any],           # list of Finding ORM objects
) -> list[dict[str, Any]]:
    """
    Compute all applicable correlations for a single audit.

    Args:
        audit_id:     The audit being analysed.
        asset_id:     Asset the audit belongs to.
        is_simulated: Whether the audit was fixture-based.
        findings:     List of Finding ORM objects with .rule_id, .status,
                      .id, .evidence_json, .evidence_source attributes.

    Returns:
        List of correlation dicts (may be empty). Never raises; errors are
        returned as an ERROR-status correlation.
    """
    results: list[dict[str, Any]] = []

    try:
        results.extend(_apply_corr_001(audit_id, asset_id, is_simulated, findings))
        results.extend(_apply_corr_002())          # always empty — see docstring
    except Exception as exc:                       # noqa: BLE001
        # Surface evaluation errors without crashing the endpoint
        results.append({
            "correlation_id": f"CORR-ERROR:{audit_id}",
            "rule_id": "CORR-ERROR",
            "title": "Correlation evaluation error",
            "severity": "Error",
            "status": "ERROR",
            "asset_ids": [asset_id],
            "finding_ids": [],
            "explanation": f"Correlation engine encountered an unexpected error: {exc}",
            "evidence": [],
            "recommendation": "Review backend logs for details.",
            "is_simulated": is_simulated,
            "attack_path_confirmed": False,
        })

    return results


# ── CORR-001 ─────────────────────────────────────────────────────────────────

def _apply_corr_001(
    audit_id: int,
    asset_id: int,
    is_simulated: bool,
    findings: list[Any],
) -> list[dict[str, Any]]:
    """
    CORR-001 — Insecure Management Access.

    Fires when BOTH NET-SSH-001 and NET-TELNET-002 are FAIL
    in the same audit.  A single failed finding is not sufficient.
    PASS findings never trigger this rule.
    """
    # Index FAIL findings by rule_id
    fail_map: dict[str, Any] = {}
    for f in findings:
        if f.rule_id in _CORR_001_TRIGGERS and f.status == "FAIL":
            fail_map[f.rule_id] = f

    # Both triggers must be present as FAIL
    if _CORR_001_TRIGGERS != set(fail_map.keys()):
        return []

    ssh_finding = fail_map["NET-SSH-001"]
    telnet_finding = fail_map["NET-TELNET-002"]

    finding_ids = sorted([ssh_finding.id, telnet_finding.id])
    correlation_id = f"CORR-001:{audit_id}"

    # Collect evidence from both findings (evidence_json may be None or {})
    evidence: list[dict] = []
    for f in [ssh_finding, telnet_finding]:
        ev = f.evidence_json or {}
        if ev:
            evidence.append({
                "finding_id": f.id,
                "rule_id": f.rule_id,
                "source": f.evidence_source or "unknown",
                "data": ev,
            })

    explanation = (
        f"SSH is disabled (NET-SSH-001 = FAIL, finding #{ssh_finding.id}) and "
        f"Telnet is enabled (NET-TELNET-002 = FAIL, finding #{telnet_finding.id}) "
        "in the same audit. Together these findings indicate that management "
        "access to this device uses an unencrypted protocol while the encrypted "
        "alternative is unavailable. Network reachability from untrusted segments "
        "has not been verified and is not assumed."
    )

    return [{
        "correlation_id": correlation_id,
        "rule_id": "CORR-001",
        "title": _CORR_001_META["title"],
        "severity": _CORR_001_META["severity"],
        "status": "CORRELATED_EXPOSURE",
        "asset_ids": [asset_id],
        "finding_ids": finding_ids,
        "explanation": explanation,
        "evidence": evidence,
        "recommendation": _CORR_001_META["recommendation"],
        "is_simulated": is_simulated,
        "attack_path_confirmed": False,   # never true without reachability proof
    }]


# ── CORR-002 ─────────────────────────────────────────────────────────────────

def _apply_corr_002() -> list[dict]:
    """
    CORR-002 — Cross-Asset Related Exposure (conservative / placeholder).

    No confirmed cross-asset correlation is returned until explicit
    network-relationship or shared-segment evidence is available in the
    data model. Returning an empty list is the correct, safe behaviour.

    Extension point: when verified asset-relationship records are added
    (e.g. a NetworkLink table), implement the matching logic here and
    pass the relevant evidence through compute_correlations().
    """
    return []
