"""
Test suite for:
  - Windows collector (live and fixture-based)
  - Improved boolean evaluation (is_true / is_false safe string handling)
  - Linux firewall and SSH evidence improvements
  - LNX-SSH-001 updated rule (permit_empty_passwords)
  - Windows rules against baseline/hardened fixtures
  - Windows drift detection and regression tracking
  - Windows end-to-end audit pipeline via /api/run-audit

All tests use isolated in-memory SQLite via StaticPool.
No live external network connections.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import app.models  # noqa: F401
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app

# ── In-memory isolated DB ────────────────────────────────────────────────────
_win_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_WinSession = sessionmaker(bind=_win_engine, autoflush=False, autocommit=False)


def _override_get_db():
    db = _WinSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db


@pytest.fixture(autouse=True)
def db_setup():
    """Per-test: register override, create tables, drop after."""
    app.dependency_overrides[get_db] = _override_get_db
    Base.metadata.create_all(bind=_win_engine)
    yield
    Base.metadata.drop_all(bind=_win_engine)
    app.dependency_overrides[get_db] = _override_get_db


client = TestClient(app)

RULES_DIR = Path(__file__).parent.parent / "rules"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_asset(asset_type="windows"):
    r = client.post("/api/assets", json={
        "name": f"TEST-{asset_type.upper()}",
        "asset_type": asset_type,
        "hostname": f"{asset_type}.test.local",
    })
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _make_rule(operator, expected_value, evidence_path="target.key"):
    return {
        "rule_id": "TEST-BOOL-001",
        "title": "Test boolean rule",
        "description": "desc",
        "severity": "High",
        "benchmark_reference": "TEST-REF",
        "evidence_path": evidence_path,
        "operator": operator,
        "expected_value": expected_value,
        "remediation": "fix it",
        "version": "1.0",
    }


def _ev(rule, value, source="test_fixture"):
    from app.engine.evaluator import evaluate_rule
    evidence = {"_source": source, "target": {"key": value}}
    return evaluate_rule(rule, evidence)


# ════════════════════════════════════════════════════════════════════════════
# 1. Boolean evaluator — safe string handling
# ════════════════════════════════════════════════════════════════════════════
class TestBooleanEvaluatorSafety:
    """Test that is_true and is_false handle string booleans correctly."""

    def test_is_true_python_true_passes(self):
        f = _ev(_make_rule("is_true", True), True)
        assert f["status"] == "PASS"

    def test_is_true_python_false_fails(self):
        f = _ev(_make_rule("is_true", True), False)
        assert f["status"] == "FAIL"

    def test_is_false_python_false_passes(self):
        f = _ev(_make_rule("is_false", False), False)
        assert f["status"] == "PASS"

    def test_is_false_python_true_fails(self):
        f = _ev(_make_rule("is_false", False), True)
        assert f["status"] == "FAIL"

    # String "true" / "false"
    def test_is_true_string_true_passes(self):
        f = _ev(_make_rule("is_true", True), "true")
        assert f["status"] == "PASS"

    def test_is_true_string_false_fails(self):
        f = _ev(_make_rule("is_true", True), "false")
        assert f["status"] == "FAIL"

    def test_is_false_string_false_passes(self):
        f = _ev(_make_rule("is_false", False), "false")
        assert f["status"] == "PASS"

    def test_is_false_string_true_fails(self):
        f = _ev(_make_rule("is_false", False), "true")
        assert f["status"] == "FAIL"

    # String "yes" / "no"
    def test_is_true_string_yes_passes(self):
        f = _ev(_make_rule("is_true", True), "yes")
        assert f["status"] == "PASS"

    def test_is_true_string_no_fails(self):
        f = _ev(_make_rule("is_true", True), "no")
        assert f["status"] == "FAIL"

    def test_is_false_string_no_passes(self):
        f = _ev(_make_rule("is_false", False), "no")
        assert f["status"] == "PASS"

    def test_is_false_string_yes_fails(self):
        f = _ev(_make_rule("is_false", False), "yes")
        assert f["status"] == "FAIL"

    # Numeric 1 / 0
    def test_is_true_string_1_passes(self):
        f = _ev(_make_rule("is_true", True), "1")
        assert f["status"] == "PASS"

    def test_is_true_string_0_fails(self):
        f = _ev(_make_rule("is_true", True), "0")
        assert f["status"] == "FAIL"

    def test_is_true_int_1_passes(self):
        f = _ev(_make_rule("is_true", True), 1)
        assert f["status"] == "PASS"

    def test_is_true_int_0_fails(self):
        f = _ev(_make_rule("is_true", True), 0)
        assert f["status"] == "FAIL"

    # Case-insensitive
    def test_is_true_uppercase_TRUE(self):
        f = _ev(_make_rule("is_true", True), "TRUE")
        assert f["status"] == "PASS"

    def test_is_true_mixed_case_False(self):
        f = _ev(_make_rule("is_true", True), "False")
        assert f["status"] == "FAIL"

    # None or ambiguous values must produce MANUAL (never PASS)
    def test_is_true_none_produces_manual(self):
        from app.engine.evaluator import evaluate_rule
        rule = _make_rule("is_true", True)
        evidence = {"_source": "test", "target": {"key": None}}
        f = evaluate_rule(rule, evidence)
        assert f["status"] == "MANUAL"

    def test_is_false_none_produces_manual(self):
        from app.engine.evaluator import evaluate_rule
        rule = _make_rule("is_false", False)
        evidence = {"_source": "test", "target": {"key": None}}
        f = evaluate_rule(rule, evidence)
        assert f["status"] == "MANUAL"

    def test_is_true_ambiguous_string_produces_manual(self):
        f = _ev(_make_rule("is_true", True), "maybe")
        assert f["status"] == "MANUAL"

    def test_is_false_ambiguous_string_produces_manual(self):
        f = _ev(_make_rule("is_false", False), "maybe")
        assert f["status"] == "MANUAL"


# ════════════════════════════════════════════════════════════════════════════
# 2. Linux collector and rule improvements
# ════════════════════════════════════════════════════════════════════════════
class TestLinuxImprovements:
    def test_firewall_evidence_structure(self):
        from app.collectors import linux
        with mock.patch.object(linux, "_run", return_value=None):
            with mock.patch("shutil.which", return_value=None):
                fw = linux._collect_firewall()
        assert "active" in fw
        assert "installed" in fw
        assert "ufw_installed" in fw
        assert "ufw_active" in fw
        assert "iptables_installed" in fw
        assert "iptables_has_rules" in fw
        assert fw["active"] is False

    def test_firewall_ufw_active_detected(self):
        from app.collectors import linux
        with mock.patch("shutil.which", side_effect=lambda name: "/usr/sbin/ufw" if name == "ufw" else None):
            with mock.patch.object(linux, "_run", return_value="Status: active\nTo Action From\n-- ------ ----"):
                fw = linux._collect_firewall()
        assert fw["ufw_active"] is True
        assert fw["active"] is True

    def test_firewall_ufw_inactive_not_active(self):
        from app.collectors import linux
        with mock.patch("shutil.which", side_effect=lambda name: "/usr/sbin/ufw" if name == "ufw" else None):
            with mock.patch.object(linux, "_run", return_value="Status: inactive"):
                fw = linux._collect_firewall()
        assert fw["ufw_active"] is False
        assert fw["active"] is False

    def test_lnx_ssh_001_checks_permit_empty_passwords(self):
        from app.engine.loader import load_rules
        rules = load_rules(RULES_DIR / "linux.json")
        r = next((rule for rule in rules if rule["rule_id"] == "LNX-SSH-001"), None)
        assert r is not None
        assert r["evidence_path"] == "sshd.permit_empty_passwords"
        assert r["expected_value"] == "no"

    def test_lnx_ssh_001_evaluates_pass(self):
        from app.engine.evaluator import evaluate_rule
        from app.engine.loader import load_rules
        rules = load_rules(RULES_DIR / "linux.json")
        r = next(rule for rule in rules if rule["rule_id"] == "LNX-SSH-001")
        ev = {"_source": "test", "sshd": {"permit_empty_passwords": "no"}}
        finding = evaluate_rule(r, ev)
        assert finding["status"] == "PASS"

    def test_lnx_ssh_001_evaluates_fail(self):
        from app.engine.evaluator import evaluate_rule
        from app.engine.loader import load_rules
        rules = load_rules(RULES_DIR / "linux.json")
        r = next(rule for rule in rules if rule["rule_id"] == "LNX-SSH-001")
        ev = {"_source": "test", "sshd": {"permit_empty_passwords": "yes"}}
        finding = evaluate_rule(r, ev)
        assert finding["status"] == "FAIL"


# ════════════════════════════════════════════════════════════════════════════
# 3. Windows collector & rules
# ════════════════════════════════════════════════════════════════════════════
class TestWindowsRulesAndCollector:
    def test_windows_rules_load(self):
        from app.engine.loader import load_rules_for_asset_type
        rules = load_rules_for_asset_type(RULES_DIR, "windows")
        assert len(rules) >= 12
        ids = [r["rule_id"] for r in rules]
        assert len(ids) == len(set(ids)), "Rule IDs must be unique"
        for r in rules:
            assert r["rule_id"].startswith("WIN-")

    def test_windows_baseline_fixture_all_pass(self):
        from app.collectors.windows import collect_from_file
        from app.engine.evaluator import evaluate_rules
        from app.engine.loader import load_rules_for_asset_type
        rules = load_rules_for_asset_type(RULES_DIR, "windows")
        ev = collect_from_file(FIXTURES_DIR / "baseline" / "windows_config.json")
        findings = evaluate_rules(rules, ev)
        fails = [f for f in findings if f["status"] == "FAIL"]
        assert len(fails) == 0, f"Expected 0 FAILs on baseline, got {fails}"
        passes = [f for f in findings if f["status"] == "PASS"]
        assert len(passes) == len(rules)

    def test_windows_hardened_fixture_has_failures(self):
        from app.collectors.windows import collect_from_file
        from app.engine.evaluator import evaluate_rules
        from app.engine.loader import load_rules_for_asset_type
        rules = load_rules_for_asset_type(RULES_DIR, "windows")
        ev = collect_from_file(FIXTURES_DIR / "hardened" / "windows_config.json")
        findings = evaluate_rules(rules, ev)
        fails = [f for f in findings if f["status"] == "FAIL"]
        assert len(fails) >= 5, f"Expected >= 5 failures, got {len(fails)}"

    def test_missing_windows_evidence_is_manual(self):
        from app.engine.evaluator import evaluate_rules
        from app.engine.loader import load_rules_for_asset_type
        rules = load_rules_for_asset_type(RULES_DIR, "windows")
        findings = evaluate_rules(rules, {"_source": "empty"})
        for f in findings:
            assert f["status"] == "MANUAL", f"{f['rule_id']} should be MANUAL on missing evidence"


# ════════════════════════════════════════════════════════════════════════════
# 4. Windows end-to-end API & Drift
# ════════════════════════════════════════════════════════════════════════════
class TestWindowsAPIAndDrift:
    def test_run_audit_windows_baseline(self):
        asset_id = _make_asset("windows")
        r = client.post("/api/run-audit", json={
            "asset_id": asset_id,
            "fixture_name": "windows_baseline",
        })
        assert r.status_code == 201
        data = r.json()
        assert data["status"] == "COMPLETED"
        assert data["is_simulated"] is True
        assert data["score"] == 100.0
        assert data["finding_counts"]["fail"] == 0

    def test_run_audit_windows_hardened(self):
        asset_id = _make_asset("windows")
        r = client.post("/api/run-audit", json={
            "asset_id": asset_id,
            "fixture_name": "windows_hardened",
        })
        assert r.status_code == 201
        data = r.json()
        assert data["status"] == "COMPLETED"
        assert data["is_simulated"] is True
        assert data["score"] < 100.0
        assert data["finding_counts"]["fail"] >= 5

    def test_windows_drift_detection(self):
        asset_id = _make_asset("windows")
        # Run baseline audit
        r1 = client.post("/api/run-audit", json={
            "asset_id": asset_id,
            "fixture_name": "windows_baseline",
        })
        audit1_id = r1.json()["audit_id"]

        # Run drift on first audit: baseline created, no changes
        d1 = client.get(f"/api/audits/{audit1_id}/drift").json()
        assert d1["baseline_audit_id"] is None
        assert d1["changes"] == []

        # Run modified audit on same asset
        r2 = client.post("/api/run-audit", json={
            "asset_id": asset_id,
            "fixture_name": "windows_hardened",
        })
        audit2_id = r2.json()["audit_id"]

        # Run drift on second audit
        d2 = client.get(f"/api/audits/{audit2_id}/drift").json()
        assert d2["baseline_audit_id"] == audit1_id
        assert len(d2["changes"]) > 0
        assert len(d2["newly_failing_controls"]) > 0

    def test_identical_audit_no_false_drift(self):
        asset_id = _make_asset("windows")
        r1 = client.post("/api/run-audit", json={
            "asset_id": asset_id,
            "fixture_name": "windows_baseline",
        })
        r2 = client.post("/api/run-audit", json={
            "asset_id": asset_id,
            "fixture_name": "windows_baseline",
        })
        audit2_id = r2.json()["audit_id"]

        d = client.get(f"/api/audits/{audit2_id}/drift").json()
        assert d["baseline_audit_id"] == r1.json()["audit_id"]
        assert len(d["changes"]) == 0
        assert len(d["newly_failing_controls"]) == 0
        assert len(d["resolved_controls"]) == 0

    def test_different_assets_never_compared(self):
        asset1 = _make_asset("windows")
        asset2 = _make_asset("windows")

        client.post("/api/run-audit", json={"asset_id": asset1, "fixture_name": "windows_baseline"})
        r2 = client.post("/api/run-audit", json={"asset_id": asset2, "fixture_name": "windows_hardened"})
        audit2_id = r2.json()["audit_id"]

        # Asset 2's first audit should have no baseline, never compare against Asset 1
        d = client.get(f"/api/audits/{audit2_id}/drift").json()
        assert d["baseline_audit_id"] is None
        assert d["asset_id"] == asset2
