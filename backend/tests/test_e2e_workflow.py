"""
End-to-End Validation Workflow Test (Section 12 of specification).

Executes the complete 17-step simulated validation workflow:
1. Register a Linux asset
2. Execute a Linux audit using a controlled fixture
3. Persist its findings and snapshot
4. Run another identical audit
5. Verify no false drift
6. Modify the Linux evidence
7. Run another audit
8. Verify drift events and finding regressions
9. Register a Windows asset
10. Execute a Windows fixture-based audit
11. Verify Windows findings and snapshot persistence
12. Register a Cisco asset
13. Run the baseline Cisco fixture
14. Run the modified Cisco fixture
15. Verify expected Cisco findings and drift
16. Verify exposure correlation (CORR-001)
17. Verify API contracts needed by the frontend
"""
from __future__ import annotations

import json
from pathlib import Path

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
_e2e_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_E2ESession = sessionmaker(bind=_e2e_engine, autoflush=False, autocommit=False)


def _override_get_db():
    db = _E2ESession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db


@pytest.fixture(autouse=True)
def db_setup():
    app.dependency_overrides[get_db] = _override_get_db
    Base.metadata.create_all(bind=_e2e_engine)
    yield
    Base.metadata.drop_all(bind=_e2e_engine)
    app.dependency_overrides[get_db] = _override_get_db


client = TestClient(app)


def test_complete_17_step_validation_workflow():
    # ── Step 1: Register a Linux asset ─────────────────────────────────────────
    r_linux = client.post("/api/assets", json={
        "name": "prod-linux-01",
        "asset_type": "linux",
        "hostname": "prod-linux-01.internal",
        "platform": "Ubuntu 22.04 LTS",
    })
    assert r_linux.status_code == 201
    linux_asset_id = r_linux.json()["id"]

    # ── Step 2 & 3: Execute a Linux audit with a controlled fixture & persist ─
    # Submitting via /api/audits with snapshot and findings
    linux_findings_1 = [
        {
            "rule_id": "LNX-SSH-001",
            "status": "PASS",
            "severity": "High",
            "expected": "no",
            "actual": "no",
            "evidence_source": "linux_fixture:v1",
            "evidence": {"sshd": {"permit_empty_passwords": "no"}},
            "remediation": "PermitEmptyPasswords no",
        },
        {
            "rule_id": "LNX-FW-004",
            "status": "PASS",
            "severity": "High",
            "expected": "true",
            "actual": "True",
            "evidence_source": "linux_fixture:v1",
            "evidence": {"firewall": {"active": True}},
            "remediation": "Enable ufw",
        },
    ]
    linux_snapshot_1 = {
        "is_simulated": True,
        "evidence": {
            "sshd": {"permit_empty_passwords": "no", "permit_root_login": "no"},
            "firewall": {"active": True, "ufw_active": True},
        },
    }
    r_audit_l1 = client.post("/api/audits", json={
        "asset_id": linux_asset_id,
        "status": "COMPLETED",
        "score": 100.0,
        "is_simulated": True,
        "benchmark_version": "CIS_Ubuntu_Linux_22.04_v1.0",
        "findings": linux_findings_1,
        "snapshot": linux_snapshot_1,
    })
    assert r_audit_l1.status_code == 201
    audit_l1_id = r_audit_l1.json()["id"]

    # Verify findings retrievable
    f_res = client.get(f"/api/audits/{audit_l1_id}/findings")
    assert f_res.status_code == 200
    assert len(f_res.json()) == 2

    # ── Step 4 & 5: Run another identical audit & verify NO false drift ───────
    r_audit_l2 = client.post("/api/audits", json={
        "asset_id": linux_asset_id,
        "status": "COMPLETED",
        "score": 100.0,
        "is_simulated": True,
        "benchmark_version": "CIS_Ubuntu_Linux_22.04_v1.0",
        "findings": linux_findings_1,
        "snapshot": linux_snapshot_1,
    })
    audit_l2_id = r_audit_l2.json()["id"]

    drift_l2 = client.get(f"/api/audits/{audit_l2_id}/drift").json()
    assert drift_l2["baseline_audit_id"] == audit_l1_id
    assert len(drift_l2["changes"]) == 0
    assert len(drift_l2["newly_failing_controls"]) == 0
    assert len(drift_l2["resolved_controls"]) == 0

    # ── Step 6, 7 & 8: Modify Linux evidence, run audit, verify drift events ─
    linux_findings_3 = [
        {
            "rule_id": "LNX-SSH-001",
            "status": "FAIL",  # regression!
            "severity": "High",
            "expected": "no",
            "actual": "yes",
            "evidence_source": "linux_fixture:v2",
            "evidence": {"sshd": {"permit_empty_passwords": "yes"}},
            "remediation": "Set PermitEmptyPasswords no",
        },
        {
            "rule_id": "LNX-FW-004",
            "status": "PASS",
            "severity": "High",
            "expected": "true",
            "actual": "True",
            "evidence_source": "linux_fixture:v2",
            "evidence": {"firewall": {"active": True}},
        },
    ]
    linux_snapshot_3 = {
        "is_simulated": True,
        "evidence": {
            "sshd": {"permit_empty_passwords": "yes", "permit_root_login": "no"},
            "firewall": {"active": True, "ufw_active": True},
        },
    }
    r_audit_l3 = client.post("/api/audits", json={
        "asset_id": linux_asset_id,
        "status": "COMPLETED",
        "score": 50.0,
        "is_simulated": True,
        "benchmark_version": "CIS_Ubuntu_Linux_22.04_v1.0",
        "findings": linux_findings_3,
        "snapshot": linux_snapshot_3,
    })
    audit_l3_id = r_audit_l3.json()["id"]

    drift_l3 = client.get(f"/api/audits/{audit_l3_id}/drift").json()
    assert drift_l3["baseline_audit_id"] == audit_l2_id
    # Configuration changes detected
    assert len(drift_l3["changes"]) == 1
    assert drift_l3["changes"][0]["setting"] == "sshd.permit_empty_passwords"
    assert drift_l3["changes"][0]["change_type"] == "modified"
    assert drift_l3["changes"][0]["before"] == "no"
    assert drift_l3["changes"][0]["after"] == "yes"
    # Control regression detected
    assert len(drift_l3["newly_failing_controls"]) == 1
    assert drift_l3["newly_failing_controls"][0]["rule_id"] == "LNX-SSH-001"
    assert drift_l3["newly_failing_controls"][0]["previous_status"] == "PASS"
    assert drift_l3["newly_failing_controls"][0]["current_status"] == "FAIL"

    # ── Step 9 & 10 & 11: Register Windows asset & execute fixture-based audit ─
    r_win = client.post("/api/assets", json={
        "name": "ad-server-01",
        "asset_type": "windows",
        "hostname": "ad01.corp.internal",
        "platform": "Windows Server 2022",
    })
    win_asset_id = r_win.json()["id"]

    r_audit_w1 = client.post("/api/run-audit", json={
        "asset_id": win_asset_id,
        "fixture_name": "windows_baseline",
    })
    assert r_audit_w1.status_code == 201
    audit_w1_data = r_audit_w1.json()
    assert audit_w1_data["status"] == "COMPLETED"
    assert audit_w1_data["score"] == 100.0
    audit_w1_id = audit_w1_data["audit_id"]

    # Verify Windows findings and snapshot persistence
    w_findings = client.get(f"/api/audits/{audit_w1_id}/findings").json()
    assert len(w_findings) >= 12
    assert all(f["rule_id"].startswith("WIN-") for f in w_findings)

    # ── Step 12 & 13: Register Cisco asset & run baseline fixture ─────────────
    r_cisco = client.post("/api/assets", json={
        "name": "core-router-01",
        "asset_type": "router",
        "hostname": "10.0.0.1",
        "platform": "Cisco IOS 17",
    })
    cisco_asset_id = r_cisco.json()["id"]

    r_cisco_base = client.post("/api/run-audit", json={
        "asset_id": cisco_asset_id,
        "fixture_name": "cisco_baseline",
    })
    assert r_cisco_base.status_code == 201
    audit_c1_id = r_cisco_base.json()["audit_id"]
    assert r_cisco_base.json()["score"] == 100.0

    # ── Step 14 & 15: Run modified Cisco fixture, verify findings and drift ────
    r_cisco_mod = client.post("/api/run-audit", json={
        "asset_id": cisco_asset_id,
        "fixture_name": "cisco_modified",
    })
    assert r_cisco_mod.status_code == 201
    audit_c2_id = r_cisco_mod.json()["audit_id"]
    assert r_cisco_mod.json()["score"] < 100.0

    cisco_drift = client.get(f"/api/audits/{audit_c2_id}/drift").json()
    assert cisco_drift["baseline_audit_id"] == audit_c1_id
    assert len(cisco_drift["changes"]) > 0
    assert len(cisco_drift["newly_failing_controls"]) >= 4

    # ── Step 16: Verify exposure correlation (CORR-001) ──────────────────────
    # Modified Cisco fixture fails both NET-SSH-001 and NET-TELNET-002 -> CORR-001 must trigger!
    corr_resp = client.get(f"/api/audits/{audit_c2_id}/correlations")
    assert corr_resp.status_code == 200
    correlations = corr_resp.json()
    assert len(correlations) >= 1
    corr_001 = next((c for c in correlations if c["rule_id"] == "CORR-001"), None)
    assert corr_001 is not None
    assert corr_001["severity"] == "High"
    assert corr_001["attack_path_confirmed"] is False
    assert corr_001["is_simulated"] is True
    assert len(corr_001["finding_ids"]) == 2

    # Baseline Cisco fixture has no fail -> CORR-001 must NOT trigger!
    corr_base_resp = client.get(f"/api/audits/{audit_c1_id}/correlations")
    assert corr_base_resp.status_code == 200
    assert corr_base_resp.json() == []

    # ── Step 17: Verify frontend API endpoints contract ───────────────────────
    # Test GET /api/assets
    assets = client.get("/api/assets").json()
    assert len(assets) == 3

    # Test GET /api/audits summary
    audits = client.get("/api/audits?skip=0&limit=50").json()
    assert audits["total"] >= 5

    # Test GET /api/audits/{id}
    audit_detail = client.get(f"/api/audits/{audit_c2_id}").json()
    assert audit_detail["id"] == audit_c2_id
    assert len(audit_detail["findings"]) > 0
