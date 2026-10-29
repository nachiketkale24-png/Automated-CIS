"""
Task 5 — Correlation Engine Tests

Tests cover:
1. CORR-001 fires when SSH=FAIL and Telnet=FAIL on the same asset.
2. Correlation has correct finding IDs, explanation, recommendation, is_simulated.
3. A single FAIL finding (SSH only) does NOT trigger CORR-001.
4. PASS findings do NOT trigger CORR-001.
5. Determinism — same audit → identical correlations on repeated calls.
6. Missing audit returns 404.
7. Audit with no matching findings returns [].
8. CORR-002 is conservative — returns no cross-asset correlation without evidence.
9. End-to-end: run-audit (modified Cisco fixture) → correlations endpoint.

All tests use the same isolated in-memory SQLite + StaticPool pattern
as test_engine.py. No live devices. No external services.
"""
from __future__ import annotations

import app.models  # noqa: F401
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app

# ── In-memory isolated DB ─────────────────────────────────────────────────────
_corr_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_CorrSession = sessionmaker(bind=_corr_engine, autoflush=False, autocommit=False)


def _override_get_db():
    db = _CorrSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db


@pytest.fixture(autouse=True)
def db_setup():
    """Per-test: register override, create tables, drop after."""
    app.dependency_overrides[get_db] = _override_get_db
    Base.metadata.create_all(bind=_corr_engine)
    yield
    Base.metadata.drop_all(bind=_corr_engine)
    app.dependency_overrides[get_db] = _override_get_db


client = TestClient(app)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_asset(asset_type: str = "router") -> int:
    r = client.post("/api/assets", json={
        "name": "CORR-TEST-ASSET",
        "asset_type": asset_type,
        "hostname": "corr-test.local",
    })
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _make_audit(asset_id: int, findings: list[dict], is_simulated: bool = True) -> int:
    """Create an audit with the given finding list via the existing audit API."""
    r = client.post("/api/audits", json={
        "asset_id": asset_id,
        "is_simulated": is_simulated,
        "status": "COMPLETED",
        "score": None,
        "findings": findings,
    })
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _ssh_fail_finding() -> dict:
    return {
        "rule_id": "NET-SSH-001",
        "status": "FAIL",
        "severity": "High",
        "expected_value": "True",
        "actual_value": "False",
        "evidence_source": "cisco_fixture:cisco_modified",
        "evidence": {"services.ssh_enabled": False},
        "remediation": "Configure ip ssh version 2.",
    }


def _telnet_fail_finding() -> dict:
    return {
        "rule_id": "NET-TELNET-002",
        "status": "FAIL",
        "severity": "High",
        "expected_value": "False",
        "actual_value": "True",
        "evidence_source": "cisco_fixture:cisco_modified",
        "evidence": {"services.telnet_enabled": True},
        "remediation": "Remove transport input telnet from VTY lines.",
    }


def _ssh_pass_finding() -> dict:
    return {
        "rule_id": "NET-SSH-001",
        "status": "PASS",
        "severity": "High",
        "expected_value": "True",
        "actual_value": "True",
        "evidence_source": "cisco_fixture:cisco_baseline",
        "evidence": {"services.ssh_enabled": True},
        "remediation": "Configure ip ssh version 2.",
    }


def _telnet_pass_finding() -> dict:
    return {
        "rule_id": "NET-TELNET-002",
        "status": "PASS",
        "severity": "High",
        "expected_value": "False",
        "actual_value": "False",
        "evidence_source": "cisco_fixture:cisco_baseline",
        "evidence": {"services.telnet_enabled": False},
        "remediation": "Remove transport input telnet from VTY lines.",
    }


# ═════════════════════════════════════════════════════════════════════════════
# Test 1 — CORR-001 fires when SSH=FAIL + Telnet=FAIL
# ═════════════════════════════════════════════════════════════════════════════
class TestCorr001Triggers:
    def test_corr001_fires_with_ssh_and_telnet_fail(self):
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [_ssh_fail_finding(), _telnet_fail_finding()])

        r = client.get(f"/api/audits/{audit_id}/correlations")
        assert r.status_code == 200, r.text
        data = r.json()
        assert isinstance(data, list)
        assert len(data) == 1

        c = data[0]
        assert c["rule_id"] == "CORR-001"
        assert c["status"] == "CORRELATED_EXPOSURE"
        assert c["severity"] == "High"
        assert c["title"] == "Insecure management access"

    def test_corr001_finding_ids_are_correct(self):
        """Correlation must reference the actual stored Finding IDs."""
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [_ssh_fail_finding(), _telnet_fail_finding()])

        # Get the actual stored finding IDs
        findings_r = client.get(f"/api/audits/{audit_id}/findings")
        stored = {f["rule_id"]: f["id"] for f in findings_r.json()}

        r = client.get(f"/api/audits/{audit_id}/correlations")
        c = r.json()[0]
        assert sorted(c["finding_ids"]) == sorted([
            stored["NET-SSH-001"], stored["NET-TELNET-002"]
        ])

    def test_corr001_has_explanation(self):
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [_ssh_fail_finding(), _telnet_fail_finding()])
        c = client.get(f"/api/audits/{audit_id}/correlations").json()[0]
        assert "SSH" in c["explanation"] or "ssh" in c["explanation"].lower()
        assert "Telnet" in c["explanation"] or "telnet" in c["explanation"].lower()
        assert "network reachability" in c["explanation"].lower()

    def test_corr001_has_recommendation(self):
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [_ssh_fail_finding(), _telnet_fail_finding()])
        c = client.get(f"/api/audits/{audit_id}/correlations").json()[0]
        assert c["recommendation"] != ""
        assert len(c["recommendation"]) > 10

    def test_corr001_is_simulated_matches_audit(self):
        """is_simulated on correlation must reflect the audit flag, not be hardcoded."""
        asset_id = _make_asset()
        # Simulated audit
        audit_id_sim = _make_audit(asset_id, [_ssh_fail_finding(), _telnet_fail_finding()], is_simulated=True)
        c_sim = client.get(f"/api/audits/{audit_id_sim}/correlations").json()[0]
        assert c_sim["is_simulated"] is True

        # Non-simulated audit
        audit_id_live = _make_audit(asset_id, [_ssh_fail_finding(), _telnet_fail_finding()], is_simulated=False)
        c_live = client.get(f"/api/audits/{audit_id_live}/correlations").json()[0]
        assert c_live["is_simulated"] is False

    def test_corr001_attack_path_never_confirmed(self):
        """attack_path_confirmed must always be False — no reachability proof exists."""
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [_ssh_fail_finding(), _telnet_fail_finding()])
        c = client.get(f"/api/audits/{audit_id}/correlations").json()[0]
        assert c["attack_path_confirmed"] is False

    def test_corr001_includes_asset_id(self):
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [_ssh_fail_finding(), _telnet_fail_finding()])
        c = client.get(f"/api/audits/{audit_id}/correlations").json()[0]
        assert asset_id in c["asset_ids"]

    def test_corr001_correlation_id_contains_audit_id(self):
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [_ssh_fail_finding(), _telnet_fail_finding()])
        c = client.get(f"/api/audits/{audit_id}/correlations").json()[0]
        assert str(audit_id) in c["correlation_id"]


# ═════════════════════════════════════════════════════════════════════════════
# Test 3+4 — Single or PASS findings must NOT trigger CORR-001
# ═════════════════════════════════════════════════════════════════════════════
class TestCorr001NotTriggered:
    def test_single_ssh_fail_does_not_trigger(self):
        """One FAIL is not enough. Both triggers must be present."""
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [_ssh_fail_finding()])
        r = client.get(f"/api/audits/{audit_id}/correlations")
        assert r.status_code == 200
        assert r.json() == []

    def test_single_telnet_fail_does_not_trigger(self):
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [_telnet_fail_finding()])
        r = client.get(f"/api/audits/{audit_id}/correlations")
        assert r.status_code == 200
        assert r.json() == []

    def test_pass_findings_do_not_trigger(self):
        """PASS findings must never cause a CORR-001 correlation."""
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [_ssh_pass_finding(), _telnet_pass_finding()])
        r = client.get(f"/api/audits/{audit_id}/correlations")
        assert r.status_code == 200
        assert r.json() == []

    def test_mixed_one_pass_one_fail_does_not_trigger(self):
        """SSH=PASS + Telnet=FAIL must not trigger CORR-001."""
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [_ssh_pass_finding(), _telnet_fail_finding()])
        r = client.get(f"/api/audits/{audit_id}/correlations")
        assert r.status_code == 200
        assert r.json() == []

    def test_empty_findings_returns_empty(self):
        """Audit with no findings → empty correlation list."""
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [])
        r = client.get(f"/api/audits/{audit_id}/correlations")
        assert r.status_code == 200
        assert r.json() == []

    def test_unrelated_fail_findings_do_not_trigger(self):
        """Unrelated failing rules (not NET-SSH-001/NET-TELNET-002) must not trigger."""
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [
            {"rule_id": "NET-LOG-003", "status": "FAIL", "severity": "Medium",
             "expected_value": "exists", "actual_value": "None",
             "evidence_source": "test", "evidence": {}, "remediation": "Add logging host."},
            {"rule_id": "NET-ACL-004", "status": "FAIL", "severity": "High",
             "expected_value": "True", "actual_value": "False",
             "evidence_source": "test", "evidence": {}, "remediation": "Add ACL."},
        ])
        r = client.get(f"/api/audits/{audit_id}/correlations")
        assert r.status_code == 200
        assert r.json() == []


# ═════════════════════════════════════════════════════════════════════════════
# Test 5 — CORR-002: No cross-asset correlation without explicit evidence
# ═════════════════════════════════════════════════════════════════════════════
class TestCorr002Conservative:
    def test_two_separate_assets_each_with_both_fail_do_not_cross_correlate(self):
        """
        Even if two different assets both have SSH+Telnet FAIL, CORR-002
        must not return a cross-asset correlation without verified relationship
        evidence. Each asset's audit returns only CORR-001 for its own findings.
        """
        asset_a = _make_asset()
        asset_b = _make_asset()
        audit_a = _make_audit(asset_a, [_ssh_fail_finding(), _telnet_fail_finding()])
        audit_b = _make_audit(asset_b, [_ssh_fail_finding(), _telnet_fail_finding()])

        corr_a = client.get(f"/api/audits/{audit_a}/correlations").json()
        corr_b = client.get(f"/api/audits/{audit_b}/correlations").json()

        # Each audit gets its own CORR-001 (not cross-correlated to the other)
        assert len(corr_a) == 1
        assert corr_a[0]["rule_id"] == "CORR-001"
        assert asset_b not in corr_a[0]["asset_ids"]

        assert len(corr_b) == 1
        assert corr_b[0]["rule_id"] == "CORR-001"
        assert asset_a not in corr_b[0]["asset_ids"]

    def test_no_corr002_without_relationship_evidence(self):
        """CORR-002 must return no results for any audit in current data model."""
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [_ssh_fail_finding(), _telnet_fail_finding()])
        corrs = client.get(f"/api/audits/{audit_id}/correlations").json()
        # No CORR-002 in results
        corr_ids = [c["rule_id"] for c in corrs]
        assert "CORR-002" not in corr_ids


# ═════════════════════════════════════════════════════════════════════════════
# Test 6 — 404 for missing audit
# ═════════════════════════════════════════════════════════════════════════════
class TestMissingAudit:
    def test_missing_audit_returns_404(self):
        r = client.get("/api/audits/99999/correlations")
        assert r.status_code == 404

    def test_missing_audit_error_message(self):
        r = client.get("/api/audits/99999/correlations")
        assert "not found" in r.json()["detail"].lower()


# ═════════════════════════════════════════════════════════════════════════════
# Test 8 — Determinism
# ═════════════════════════════════════════════════════════════════════════════
class TestDeterminism:
    def test_repeated_requests_return_identical_results(self):
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [_ssh_fail_finding(), _telnet_fail_finding()])

        r1 = client.get(f"/api/audits/{audit_id}/correlations").json()
        r2 = client.get(f"/api/audits/{audit_id}/correlations").json()
        r3 = client.get(f"/api/audits/{audit_id}/correlations").json()

        assert r1 == r2 == r3, "Correlations must be deterministic"

    def test_baseline_fixture_audit_returns_empty_correlations(self):
        """Baseline audit (all PASS) must produce no correlations."""
        asset_id = _make_asset()
        audit_id = _make_audit(asset_id, [
            _ssh_pass_finding(), _telnet_pass_finding(),
        ])
        r = client.get(f"/api/audits/{audit_id}/correlations")
        assert r.json() == []


# ═════════════════════════════════════════════════════════════════════════════
# End-to-end — run-audit → correlations via run_audit endpoint
# ═════════════════════════════════════════════════════════════════════════════
class TestEndToEnd:
    def test_modified_cisco_fixture_produces_corr001(self):
        """
        Full pipeline: create asset → POST /api/run-audit (cisco_modified)
        → GET /api/audits/{id}/correlations → CORR-001 present.
        """
        # Create a router asset
        r = client.post("/api/assets", json={
            "name": "E2E-CORR-ROUTER",
            "asset_type": "router",
            "hostname": "e2e-corr.local",
        })
        assert r.status_code == 201
        asset_id = r.json()["id"]

        # Run modified fixture audit (SSH disabled + Telnet enabled)
        run_r = client.post("/api/run-audit", json={
            "asset_id": asset_id,
            "fixture_name": "cisco_modified",
        })
        assert run_r.status_code == 201, run_r.text
        audit_id = run_r.json()["audit_id"]

        # Get correlations
        corr_r = client.get(f"/api/audits/{audit_id}/correlations")
        assert corr_r.status_code == 200, corr_r.text
        corrs = corr_r.json()

        # CORR-001 must be in results
        corr_ids = [c["rule_id"] for c in corrs]
        assert "CORR-001" in corr_ids, f"Expected CORR-001, got: {corr_ids}"

        # Validate structure
        c001 = next(c for c in corrs if c["rule_id"] == "CORR-001")
        assert c001["is_simulated"] is True
        assert c001["attack_path_confirmed"] is False
        assert len(c001["finding_ids"]) == 2
        assert asset_id in c001["asset_ids"]

    def test_baseline_cisco_fixture_returns_no_correlations(self):
        """Baseline fixture (all PASS) → empty correlations list."""
        r = client.post("/api/assets", json={
            "name": "E2E-BASE-ROUTER",
            "asset_type": "router",
            "hostname": "e2e-base.local",
        })
        asset_id = r.json()["id"]

        run_r = client.post("/api/run-audit", json={
            "asset_id": asset_id,
            "fixture_name": "cisco_baseline",
        })
        audit_id = run_r.json()["audit_id"]

        corr_r = client.get(f"/api/audits/{audit_id}/correlations")
        assert corr_r.status_code == 200
        assert corr_r.json() == []
