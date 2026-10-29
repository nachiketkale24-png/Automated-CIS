"""
Test suite for Task 2+3: Rule engine, collectors, and end-to-end audit pipeline.

Tests are fully isolated — they use SQLite in-memory via dependency override.
They do NOT touch MySQL production data.
They do NOT make live network connections.
"""
from __future__ import annotations

import copy
from pathlib import Path

import app.models  # noqa: F401 – register models with Base.metadata before tests
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app

# ── In-memory SQLite with StaticPool ─────────────────────────────────────────
# StaticPool keeps a single connection so all threads/sessions share the same
# in-memory database. No files on disk → no Windows file-locking issues.
engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def override_get_db():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def db_setup():
    """Per-test: re-register our override, create tables, drop tables after."""
    # Re-register every test so test_api.py teardown cannot overwrite our override
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    # In-memory DB: nothing to delete from disk.
    # Re-register after teardown so the next test in this module is also covered.
    app.dependency_overrides[get_db] = override_get_db


client = TestClient(app)

# ── Helpers ───────────────────────────────────────────────────────────────────
RULES_DIR = Path(__file__).parent.parent / "rules"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def _make_asset(asset_type="router"):
    r = client.post("/api/assets", json={
        "name": f"TEST-{asset_type.upper()}",
        "asset_type": asset_type,
        "hostname": f"{asset_type}.test.local",
    })
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ════════════════════════════════════════════════════════════════════════════════
# 1. Rule Loader Tests
# ════════════════════════════════════════════════════════════════════════════════
class TestRuleLoader:
    def test_load_network_rules(self):
        from app.engine.loader import load_rules
        rules = load_rules(RULES_DIR / "network.json")
        assert len(rules) >= 1
        for r in rules:
            assert "rule_id" in r
            assert "operator" in r
            assert "evidence_path" in r

    def test_load_linux_rules(self):
        from app.engine.loader import load_rules
        rules = load_rules(RULES_DIR / "linux.json")
        assert len(rules) >= 1

    def test_missing_file_raises(self):
        from app.engine.loader import load_rules
        with pytest.raises(FileNotFoundError):
            load_rules(RULES_DIR / "nonexistent.json")

    def test_invalid_operator_raises(self, tmp_path):
        from app.engine.loader import load_rules, RuleValidationError
        bad = tmp_path / "bad.json"
        bad.write_text('[{"rule_id":"X","title":"t","description":"d","severity":"High",'
                       '"benchmark_reference":"ref","evidence_path":"a.b","operator":"magic",'
                       '"expected_value":null,"remediation":"fix","version":"1.0"}]')
        with pytest.raises(RuleValidationError, match="unknown operator"):
            load_rules(bad)

    def test_missing_required_field_raises(self, tmp_path):
        from app.engine.loader import load_rules, RuleValidationError
        bad = tmp_path / "bad.json"
        # Missing 'remediation' field
        bad.write_text('[{"rule_id":"X","title":"t","description":"d","severity":"High",'
                       '"benchmark_reference":"ref","evidence_path":"a.b","operator":"equals",'
                       '"expected_value":"yes","version":"1.0"}]')
        with pytest.raises(RuleValidationError, match="missing required fields"):
            load_rules(bad)

    def test_top_level_must_be_array(self, tmp_path):
        from app.engine.loader import load_rules, RuleValidationError
        bad = tmp_path / "bad.json"
        bad.write_text('{"rule_id": "X"}')
        with pytest.raises(RuleValidationError, match="JSON array"):
            load_rules(bad)

    def test_empty_rule_id_raises(self, tmp_path):
        from app.engine.loader import load_rules, RuleValidationError
        bad = tmp_path / "bad.json"
        bad.write_text('[{"rule_id":"","title":"t","description":"d","severity":"High",'
                       '"benchmark_reference":"ref","evidence_path":"a.b","operator":"equals",'
                       '"expected_value":"x","remediation":"fix","version":"1.0"}]')
        with pytest.raises(RuleValidationError):
            load_rules(bad)

    def test_load_rules_for_asset_type_router(self):
        from app.engine.loader import load_rules_for_asset_type
        rules = load_rules_for_asset_type(RULES_DIR, "router")
        assert len(rules) > 0

    def test_load_rules_for_asset_type_unknown(self):
        from app.engine.loader import load_rules_for_asset_type
        rules = load_rules_for_asset_type(RULES_DIR, "toaster")
        assert rules == []


# ════════════════════════════════════════════════════════════════════════════════
# 2. Evaluator — operator-by-operator
# ════════════════════════════════════════════════════════════════════════════════
def _make_rule(operator, expected_value, evidence_path="target.key"):
    return {
        "rule_id": "TEST-001",
        "title": "Test rule",
        "description": "desc",
        "severity": "High",
        "benchmark_reference": "TEST-REF",
        "evidence_path": evidence_path,
        "operator": operator,
        "expected_value": expected_value,
        "remediation": "fix it",
        "version": "1.0",
    }


class TestEvaluatorOperators:
    def _ev(self, rule, value, source="test_fixture"):
        from app.engine.evaluator import evaluate_rule
        evidence = {"_source": source, "target": {"key": value}}
        return evaluate_rule(rule, evidence)

    def test_is_true_pass(self):
        f = self._ev(_make_rule("is_true", True), True)
        assert f["status"] == "PASS"

    def test_is_true_fail(self):
        f = self._ev(_make_rule("is_true", True), False)
        assert f["status"] == "FAIL"

    def test_is_false_pass(self):
        f = self._ev(_make_rule("is_false", False), False)
        assert f["status"] == "PASS"

    def test_is_false_fail(self):
        f = self._ev(_make_rule("is_false", False), True)
        assert f["status"] == "FAIL"

    def test_equals_pass(self):
        f = self._ev(_make_rule("equals", "no"), "no")
        assert f["status"] == "PASS"

    def test_equals_fail(self):
        f = self._ev(_make_rule("equals", "no"), "yes")
        assert f["status"] == "FAIL"

    def test_equals_case_insensitive(self):
        f = self._ev(_make_rule("equals", "NO"), "no")
        assert f["status"] == "PASS"

    def test_not_equals_pass(self):
        f = self._ev(_make_rule("not_equals", "1"), "2")
        assert f["status"] == "PASS"

    def test_not_equals_fail(self):
        f = self._ev(_make_rule("not_equals", "1"), "1")
        assert f["status"] == "FAIL"

    def test_contains_pass(self):
        f = self._ev(_make_rule("contains", "sha512"), "obscure sha512 rounds=5000")
        assert f["status"] == "PASS"

    def test_contains_fail(self):
        f = self._ev(_make_rule("contains", "sha512"), "md5")
        assert f["status"] == "FAIL"

    def test_contains_none_value_fails(self):
        f = self._ev(_make_rule("contains", "sha512"), None)
        assert f["status"] == "FAIL"

    def test_exists_pass(self):
        f = self._ev(_make_rule("exists", None), "10.10.10.50")
        assert f["status"] == "PASS"

    def test_exists_none_value_fails(self):
        f = self._ev(_make_rule("exists", None), None)
        assert f["status"] == "FAIL"

    def test_exists_empty_string_fails(self):
        f = self._ev(_make_rule("exists", None), "")
        assert f["status"] == "FAIL"


# ════════════════════════════════════════════════════════════════════════════════
# 3. Missing / incomplete evidence — must never produce PASS
# ════════════════════════════════════════════════════════════════════════════════
class TestMissingEvidence:
    def test_missing_top_level_key_gives_manual(self):
        from app.engine.evaluator import evaluate_rule
        rule = _make_rule("is_true", True, "services.ssh_enabled")
        # Evidence has NO 'services' key
        evidence = {"_source": "empty", "logging": {"host": "10.0.0.1"}}
        f = evaluate_rule(rule, evidence)
        assert f["status"] == "MANUAL", f"Expected MANUAL, got {f['status']}"

    def test_missing_nested_key_gives_manual(self):
        from app.engine.evaluator import evaluate_rule
        rule = _make_rule("is_true", True, "services.ssh_enabled")
        evidence = {"_source": "partial", "services": {}}  # ssh_enabled missing
        f = evaluate_rule(rule, evidence)
        assert f["status"] == "MANUAL"

    def test_empty_evidence_gives_manual_for_all(self):
        from app.engine.evaluator import evaluate_rules
        from app.engine.loader import load_rules
        rules = load_rules(RULES_DIR / "network.json")
        findings = evaluate_rules(rules, {"_source": "empty_test"})
        for f in findings:
            assert f["status"] != "PASS", (
                f"Rule {f['rule_id']} returned PASS with empty evidence"
            )
            assert f["status"] == "MANUAL"

    def test_partial_evidence_no_false_pass(self):
        from app.engine.evaluator import evaluate_rules
        from app.engine.loader import load_rules
        rules = load_rules(RULES_DIR / "network.json")
        # Only provide one piece of evidence
        partial = {
            "_source": "partial_test",
            "services": {"ssh_enabled": True},
        }
        findings = evaluate_rules(rules, partial)
        # ssh rule should PASS, others should MANUAL (never PASS)
        statuses = {f["rule_id"]: f["status"] for f in findings}
        assert statuses.get("NET-SSH-001") == "PASS"
        for rule_id, status in statuses.items():
            if rule_id != "NET-SSH-001":
                assert status != "PASS", f"{rule_id} returned PASS with partial evidence"


# ════════════════════════════════════════════════════════════════════════════════
# 4. Invalid operators and malformed rules
# ════════════════════════════════════════════════════════════════════════════════
class TestInvalidRules:
    def test_unknown_operator_produces_error_finding(self):
        from app.engine.evaluator import evaluate_rule
        rule = {
            "rule_id": "BAD-001",
            "title": "bad", "description": "d", "severity": "High",
            "benchmark_reference": "ref", "evidence_path": "a.b",
            "operator": "magic_unknown",  # invalid
            "expected_value": True,
            "remediation": "fix", "version": "1.0",
        }
        evidence = {"_source": "test", "a": {"b": True}}
        f = evaluate_rule(rule, evidence)
        assert f["status"] == "ERROR"
        assert "magic_unknown" in f["actual"].lower() or "unknown operator" in f["actual"].lower()


# ════════════════════════════════════════════════════════════════════════════════
# 5. Determinism — same input → same output
# ════════════════════════════════════════════════════════════════════════════════
class TestDeterminism:
    def test_same_evidence_same_result(self):
        from app.engine.evaluator import evaluate_rules
        from app.engine.loader import load_rules

        rules = load_rules(RULES_DIR / "network.json")
        evidence = {
            "_source": "determinism_test",
            "services": {"ssh_enabled": True, "telnet_enabled": False},
            "logging": {"remote_host": "10.10.10.50"},
            "acls": {"mgmt_acl_present": True},
            "banner": {"login_banner": "Authorised use only"},
            "snmp": {"default_community": False},
        }

        results_1 = evaluate_rules(rules, copy.deepcopy(evidence))
        results_2 = evaluate_rules(rules, copy.deepcopy(evidence))

        for r1, r2 in zip(results_1, results_2):
            assert r1["status"] == r2["status"], f"Non-deterministic: {r1['rule_id']}"
            assert r1["actual"] == r2["actual"]


# ════════════════════════════════════════════════════════════════════════════════
# 6. Cisco collector / fixture parsing
# ════════════════════════════════════════════════════════════════════════════════
class TestCiscoCollector:
    def test_baseline_fixture_loads(self):
        from app.collectors.cisco import collect_from_file
        ev = collect_from_file(FIXTURES_DIR / "baseline" / "cisco_running_config.txt")
        assert ev["services"]["ssh_enabled"] is True
        assert ev["services"]["telnet_enabled"] is False
        assert ev["logging"]["remote_host"] is not None
        assert ev["acls"]["mgmt_acl_present"] is True
        assert ev["banner"]["login_banner"] is not None
        assert ev["snmp"]["default_community"] is False

    def test_modified_fixture_loads(self):
        from app.collectors.cisco import collect_from_file
        ev = collect_from_file(FIXTURES_DIR / "modified" / "cisco_running_config.txt")
        assert ev["services"]["ssh_enabled"] is False
        assert ev["services"]["telnet_enabled"] is True
        assert ev["logging"]["remote_host"] is None
        assert ev["acls"]["mgmt_acl_present"] is False
        assert ev["banner"]["login_banner"] is None
        assert ev["snmp"]["default_community"] is True

    def test_missing_fixture_raises(self):
        from app.collectors.cisco import collect_from_file
        with pytest.raises(FileNotFoundError):
            collect_from_file(FIXTURES_DIR / "nonexistent" / "config.txt")

    def test_collect_from_text(self):
        from app.collectors.cisco import collect_from_text
        config = "ip ssh version 2\nline vty 0 4\n transport input ssh\n"
        ev = collect_from_text(config, source_label="inline_test")
        assert ev["_source"] == "inline_test"
        assert ev["services"]["ssh_enabled"] is True
        assert ev["services"]["telnet_enabled"] is False

    def test_baseline_all_pass_with_network_rules(self):
        from app.collectors.cisco import collect_from_file
        from app.engine.evaluator import evaluate_rules
        from app.engine.loader import load_rules

        rules = load_rules(RULES_DIR / "network.json")
        ev = collect_from_file(FIXTURES_DIR / "baseline" / "cisco_running_config.txt")
        findings = evaluate_rules(rules, ev)

        fail_findings = [f for f in findings if f["status"] == "FAIL"]
        pass_findings = [f for f in findings if f["status"] == "PASS"]
        assert len(fail_findings) == 0, f"Baseline should have 0 FAILs, got: {[f['rule_id'] for f in fail_findings]}"
        assert len(pass_findings) == len(rules), "All rules should PASS for baseline"

    def test_modified_produces_failures(self):
        from app.collectors.cisco import collect_from_file
        from app.engine.evaluator import evaluate_rules
        from app.engine.loader import load_rules

        rules = load_rules(RULES_DIR / "network.json")
        ev = collect_from_file(FIXTURES_DIR / "modified" / "cisco_running_config.txt")
        findings = evaluate_rules(rules, ev)

        fail_findings = [f for f in findings if f["status"] == "FAIL"]
        assert len(fail_findings) >= 4, (
            f"Modified config should fail multiple rules, got only {len(fail_findings)} FAILs"
        )

    def test_baseline_vs_modified_different_findings(self):
        from app.collectors.cisco import collect_from_file
        from app.engine.evaluator import evaluate_rules
        from app.engine.loader import load_rules

        rules = load_rules(RULES_DIR / "network.json")
        ev_b = collect_from_file(FIXTURES_DIR / "baseline" / "cisco_running_config.txt")
        ev_m = collect_from_file(FIXTURES_DIR / "modified" / "cisco_running_config.txt")

        findings_b = {f["rule_id"]: f["status"] for f in evaluate_rules(rules, ev_b)}
        findings_m = {f["rule_id"]: f["status"] for f in evaluate_rules(rules, ev_m)}

        # They must differ
        assert findings_b != findings_m, "Baseline and modified configs must produce different findings"

    def test_simulated_source_label(self):
        from app.collectors.cisco import collect_from_file
        ev = collect_from_file(
            FIXTURES_DIR / "baseline" / "cisco_running_config.txt",
            source_label="cisco_fixture:cisco_baseline",
        )
        assert "cisco_fixture" in ev["_source"]


# ════════════════════════════════════════════════════════════════════════════════
# 7. Linux collector on Windows
# ════════════════════════════════════════════════════════════════════════════════
class TestLinuxCollector:
    def test_linux_collector_on_windows_returns_error_not_pass(self):
        from app.collectors.linux import collect
        import platform
        if platform.system() != "Linux":
            ev = collect()
            # Must contain _error, not silently return empty evidence
            assert "_error" in ev, "Expected _error key in non-Linux evidence"
            # No PASS should result from this evidence
            from app.engine.evaluator import evaluate_rules
            from app.engine.loader import load_rules
            rules = load_rules(RULES_DIR / "linux.json")
            findings = evaluate_rules(rules, ev)
            for f in findings:
                assert f["status"] != "PASS", (
                    f"{f['rule_id']} returned PASS from error evidence"
                )


# ════════════════════════════════════════════════════════════════════════════════
# 8. Compliance scoring
# ════════════════════════════════════════════════════════════════════════════════
class TestScorer:
    def test_all_pass(self):
        from app.engine.scorer import compute_score
        findings = [{"status": "PASS"}] * 5
        r = compute_score(findings)
        assert r["score"] == 100.0
        assert r["pass_count"] == 5
        assert r["coverage_pct"] == 100.0

    def test_all_fail(self):
        from app.engine.scorer import compute_score
        findings = [{"status": "FAIL"}] * 3
        r = compute_score(findings)
        assert r["score"] == 0.0
        assert r["fail_count"] == 3

    def test_mixed(self):
        from app.engine.scorer import compute_score
        findings = [
            {"status": "PASS"},
            {"status": "PASS"},
            {"status": "FAIL"},
            {"status": "MANUAL"},
            {"status": "ERROR"},
        ]
        r = compute_score(findings)
        assert r["score"] == pytest.approx(66.67)
        assert r["pass_count"] == 2
        assert r["fail_count"] == 1
        assert r["manual_count"] == 1
        assert r["error_count"] == 1
        assert r["total"] == 5
        # Coverage = 3 assessable / 5 total
        assert r["coverage_pct"] == pytest.approx(60.0)

    def test_no_pass_or_fail_returns_none_score(self):
        from app.engine.scorer import compute_score
        findings = [{"status": "MANUAL"}, {"status": "ERROR"}]
        r = compute_score(findings)
        assert r["score"] is None, "Score must be None when no assessable findings"

    def test_manual_not_counted_as_pass(self):
        from app.engine.scorer import compute_score
        findings = [{"status": "MANUAL"}] * 10
        r = compute_score(findings)
        assert r["score"] is None
        assert r["pass_count"] == 0

    def test_not_applicable_not_counted_as_pass(self):
        from app.engine.scorer import compute_score
        findings = [{"status": "NOT_APPLICABLE"}] * 5
        r = compute_score(findings)
        assert r["score"] is None
        assert r["pass_count"] == 0

    def test_empty_findings(self):
        from app.engine.scorer import compute_score
        r = compute_score([])
        assert r["score"] is None
        assert r["total"] == 0
        assert r["coverage_pct"] == 0.0


# ════════════════════════════════════════════════════════════════════════════════
# 9. End-to-end API — /api/run-audit + findings retrieval
# ════════════════════════════════════════════════════════════════════════════════
class TestRunAuditAPI:
    def test_run_audit_cisco_baseline(self):
        asset_id = _make_asset("router")
        r = client.post("/api/run-audit", json={
            "asset_id": asset_id,
            "fixture_name": "cisco_baseline",
            "benchmark_version": "CIS_Cisco_IOS_17_v2.1.0_ILLUSTRATIVE",
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["status"] == "COMPLETED"
        assert data["is_simulated"] is True
        assert data["score"] == 100.0
        assert data["finding_counts"]["fail"] == 0
        assert data["finding_counts"]["total"] > 0

    def test_run_audit_cisco_modified(self):
        asset_id = _make_asset("router")
        r = client.post("/api/run-audit", json={
            "asset_id": asset_id,
            "fixture_name": "cisco_modified",
        })
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["status"] == "COMPLETED"
        assert data["is_simulated"] is True
        assert data["score"] is not None
        assert data["score"] < 100.0
        assert data["finding_counts"]["fail"] >= 4

    def test_findings_retrievable_via_existing_api(self):
        asset_id = _make_asset("firewall")
        run_r = client.post("/api/run-audit", json={
            "asset_id": asset_id,
            "fixture_name": "cisco_baseline",
        })
        assert run_r.status_code == 201
        audit_id = run_r.json()["audit_id"]

        # Retrieve via existing findings endpoint
        findings_r = client.get(f"/api/audits/{audit_id}/findings")
        assert findings_r.status_code == 200
        findings = findings_r.json()
        assert len(findings) > 0

        # Verify full schema
        for f in findings:
            assert "rule_id" in f
            assert "status" in f
            assert "severity" in f
            assert "expected" in f
            assert "actual" in f
            assert "evidence" in f
            assert "evidence_source" in f
            assert "remediation" in f

    def test_baseline_findings_retrievable_are_all_pass(self):
        asset_id = _make_asset("router")
        run_r = client.post("/api/run-audit", json={
            "asset_id": asset_id,
            "fixture_name": "cisco_baseline",
        })
        audit_id = run_r.json()["audit_id"]
        findings = client.get(f"/api/audits/{audit_id}/findings").json()
        for f in findings:
            assert f["status"] == "PASS", f"Expected PASS for baseline, got {f['status']} on {f['rule_id']}"

    def test_audit_retrievable_via_existing_audit_endpoint(self):
        asset_id = _make_asset("router")
        run_r = client.post("/api/run-audit", json={
            "asset_id": asset_id,
            "fixture_name": "cisco_modified",
        })
        audit_id = run_r.json()["audit_id"]

        audit_r = client.get(f"/api/audits/{audit_id}")
        assert audit_r.status_code == 200
        audit = audit_r.json()
        assert audit["id"] == audit_id
        assert audit["status"] == "COMPLETED"
        assert audit["is_simulated"] is True
        assert audit["score"] is not None

    def test_invalid_asset_returns_404(self):
        r = client.post("/api/run-audit", json={
            "asset_id": 99999,
            "fixture_name": "cisco_baseline",
        })
        assert r.status_code == 404

    def test_unknown_fixture_returns_400(self):
        asset_id = _make_asset("router")
        r = client.post("/api/run-audit", json={
            "asset_id": asset_id,
            "fixture_name": "nonexistent_fixture",
        })
        assert r.status_code == 400
        assert "nonexistent_fixture" in r.json()["detail"]

    def test_simulated_is_labeled(self):
        asset_id = _make_asset("router")
        r = client.post("/api/run-audit", json={
            "asset_id": asset_id,
            "fixture_name": "cisco_baseline",
        })
        assert r.json()["is_simulated"] is True

    def test_baseline_vs_modified_different_scores(self):
        asset_id = _make_asset("router")

        r_b = client.post("/api/run-audit", json={
            "asset_id": asset_id, "fixture_name": "cisco_baseline"})
        r_m = client.post("/api/run-audit", json={
            "asset_id": asset_id, "fixture_name": "cisco_modified"})

        score_b = r_b.json()["score"]
        score_m = r_m.json()["score"]
        assert score_b > score_m, (
            f"Baseline score ({score_b}) should exceed modified ({score_m})"
        )

    def test_coverage_pct_returned(self):
        asset_id = _make_asset("router")
        r = client.post("/api/run-audit", json={
            "asset_id": asset_id, "fixture_name": "cisco_baseline"})
        assert "coverage_pct" in r.json()
        assert r.json()["coverage_pct"] > 0
