"""
Test suite for CIS Compliance Auditor API.

Uses an isolated SQLite in-memory database via FastAPI dependency overrides
so tests run without MySQL.
"""
import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401 – register models before any test
from app.db.base import Base
from app.db.session import get_db
from app.main import app as fastapi_app


# ── Isolated test DB (file-based so SQLAlchemy JSON type works across threads) ──
# The fixture drops all tables and deletes the file on teardown.
TEST_DATABASE_URL = "sqlite:///./test_cis_auditor.db"
_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


fastapi_app.dependency_overrides[get_db] = override_get_db  # module-level


@pytest.fixture(autouse=True)
def setup_teardown():
    """Create all tables before each test; drop and delete file after."""
    fastapi_app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=_engine)
    yield
    Base.metadata.drop_all(bind=_engine)
    _engine.dispose()
    if os.path.exists("test_cis_auditor.db"):
        os.remove("test_cis_auditor.db")
    fastapi_app.dependency_overrides[get_db] = override_get_db


client = TestClient(fastapi_app)


# ═══════════════════════════════════════════════════════════════════════
# 1. Health / DB connectivity
# ═══════════════════════════════════════════════════════════════════════
class TestHealth:
    def test_health_returns_ok(self):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("healthy", "degraded")
        assert "database" in data

    def test_root_returns_app_info(self):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "docs" in resp.json()


# ═══════════════════════════════════════════════════════════════════════
# 2. Asset CRUD
# ═══════════════════════════════════════════════════════════════════════
class TestAssets:
    def _create_asset(self, **overrides):
        payload = {
            "name": "Core Router",
            "asset_type": "router",
            "hostname": "192.168.1.1",
            "platform": "Cisco IOS",
        }
        payload.update(overrides)
        return client.post("/api/assets", json=payload)

    def test_list_empty(self):
        resp = client.get("/api/assets")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_asset(self):
        resp = self._create_asset()
        assert resp.status_code == 201
        data = resp.json()
        assert data["id"] >= 1
        assert data["name"] == "Core Router"
        assert data["asset_type"] == "router"
        assert data["hostname"] == "192.168.1.1"
        assert "created_at" in data

    def test_list_after_create(self):
        self._create_asset()
        resp = client.get("/api/assets")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    def test_get_by_id(self):
        create_resp = self._create_asset()
        asset_id = create_resp.json()["id"]
        resp = client.get(f"/api/assets/{asset_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == asset_id

    def test_get_nonexistent(self):
        resp = client.get("/api/assets/99999")
        assert resp.status_code == 404

    def test_create_validates_name(self):
        resp = self._create_asset(name="")
        assert resp.status_code == 422

    def test_create_validates_hostname(self):
        resp = self._create_asset(hostname="")
        assert resp.status_code == 422

    def test_create_validates_asset_type(self):
        resp = self._create_asset(asset_type="toaster")
        assert resp.status_code == 422

    def test_all_valid_asset_types(self):
        for t in ("windows", "linux", "firewall", "router", "switch", "network_device"):
            resp = self._create_asset(asset_type=t, name=f"dev-{t}", hostname=f"{t}.local")
            assert resp.status_code == 201, f"Failed for asset_type={t}"


# ═══════════════════════════════════════════════════════════════════════
# 3. Audit CRUD
# ═══════════════════════════════════════════════════════════════════════
class TestAudits:
    def _create_asset(self):
        resp = client.post("/api/assets", json={
            "name": "Test FW", "asset_type": "firewall",
            "hostname": "10.0.0.1",
        })
        return resp.json()["id"]

    def _create_audit(self, asset_id, **overrides):
        payload = {
            "asset_id": asset_id,
            "is_simulated": True,
            "benchmark_version": "CIS_Cisco_IOS_17_v2.1.0",
        }
        payload.update(overrides)
        return client.post("/api/audits", json=payload)

    def test_create_pending_audit(self):
        aid = self._create_asset()
        resp = self._create_audit(aid)
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "pending"
        assert data["asset_id"] == aid
        assert data["benchmark_version"] == "CIS_Cisco_IOS_17_v2.1.0"
        assert data["score"] is None
        assert data["completed_at"] is None

    def test_create_audit_with_findings(self):
        aid = self._create_asset()
        resp = self._create_audit(aid, findings=[
            {
                "rule_id": "NET-SSH-001",
                "status": "FAIL",
                "severity": "High",
                "expected": "Telnet disabled",
                "actual": "Telnet enabled",
                "evidence_source": "sample configuration fixture",
                "evidence": {"services": {"telnet": True}},
                "remediation": "Disable Telnet and use SSH for management",
            }
        ])
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "COMPLETED"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == "NET-SSH-001"
        assert data["findings"][0]["status"] == "FAIL"
        assert data["completed_at"] is not None

    def test_create_audit_invalid_asset(self):
        resp = self._create_audit(99999)
        assert resp.status_code == 404

    def test_create_audit_validates_finding_status(self):
        aid = self._create_asset()
        resp = self._create_audit(aid, findings=[
            {"rule_id": "X", "status": "BOGUS", "severity": "Low"}
        ])
        assert resp.status_code == 422

    def test_get_audit_by_id(self):
        aid = self._create_asset()
        create_resp = self._create_audit(aid)
        audit_id = create_resp.json()["id"]
        resp = client.get(f"/api/audits/{audit_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == audit_id

    def test_get_audit_nonexistent(self):
        resp = client.get("/api/audits/99999")
        assert resp.status_code == 404

    def test_list_audits(self):
        aid = self._create_asset()
        self._create_audit(aid)
        self._create_audit(aid, benchmark_version="v2")
        resp = client.get("/api/audits")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    def test_list_audits_pagination(self):
        aid = self._create_asset()
        for _ in range(5):
            self._create_audit(aid)
        resp = client.get("/api/audits?skip=2&limit=2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 5
        assert len(data["items"]) == 2
        assert data["skip"] == 2
        assert data["limit"] == 2


# ═══════════════════════════════════════════════════════════════════════
# 4. Findings
# ═══════════════════════════════════════════════════════════════════════
class TestFindings:
    def _seed(self, with_findings=True):
        asset = client.post("/api/assets", json={
            "name": "Switch-1", "asset_type": "switch",
            "hostname": "switch1.lab",
        }).json()
        findings = []
        if with_findings:
            findings = [
                {"rule_id": "NET-SSH-001", "status": "FAIL", "severity": "High",
                 "expected": "SSH only", "actual": "Telnet and SSH",
                 "evidence_source": "fixture", "evidence": {},
                 "remediation": "Disable Telnet"},
                {"rule_id": "NET-LOG-002", "status": "PASS", "severity": "Medium",
                 "evidence": {}, "evidence_source": "fixture"},
            ]
        audit = client.post("/api/audits", json={
            "asset_id": asset["id"], "is_simulated": True, "findings": findings,
        }).json()
        return audit["id"]

    def test_get_findings(self):
        audit_id = self._seed(with_findings=True)
        resp = client.get(f"/api/audits/{audit_id}/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        assert data[0]["rule_id"] == "NET-SSH-001"

    def test_get_findings_empty(self):
        audit_id = self._seed(with_findings=False)
        resp = client.get(f"/api/audits/{audit_id}/findings")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_findings_nonexistent_audit(self):
        resp = client.get("/api/audits/99999/findings")
        assert resp.status_code == 404

    def test_finding_status_values(self):
        """All allowed status values should be accepted."""
        asset = client.post("/api/assets", json={
            "name": "Test", "asset_type": "linux", "hostname": "localhost",
        }).json()
        for status in ("PASS", "FAIL", "MANUAL", "ERROR", "NOT_APPLICABLE"):
            resp = client.post("/api/audits", json={
                "asset_id": asset["id"],
                "findings": [{"rule_id": f"R-{status}", "status": status, "severity": "Low"}],
            })
            assert resp.status_code == 201, f"Failed for finding status={status}"
