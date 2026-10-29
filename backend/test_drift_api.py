
import os
import uuid
import requests

BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000/api")
TIMEOUT = 15

session = requests.Session()
session.headers.update({"Content-Type": "application/json"})

run_id = uuid.uuid4().hex[:8]
passed = 0
failed = 0


def check(name, condition, details=""):
    global passed, failed

    if condition:
        passed += 1
        print(f"PASS: {name}")
    else:
        failed += 1
        print(f"FAIL: {name}")
        if details:
            print(f"      {details}")


def request(method, path, payload=None, expected_status=None):
    response = session.request(
        method,
        f"{BASE_URL}{path}",
        json=payload,
        timeout=TIMEOUT,
    )

    if expected_status is not None and response.status_code != expected_status:
        raise RuntimeError(
            f"{method} {path}: expected HTTP {expected_status}, "
            f"received HTTP {response.status_code}: {response.text}"
        )

    return response


def create_asset(label):
    payload = {
        "name": f"Drift Test {label} {run_id}",
        "asset_type": "network_device",
        "hostname": f"{label.lower()}-{run_id}",
        "platform": "Linux",
    }

    response = request("POST", "/assets", payload, 201)
    data = response.json()

    asset_id = data.get("id", data.get("asset_id"))
    if asset_id is None:
        raise RuntimeError(f"Asset ID missing from response: {data}")

    return asset_id


def create_audit(asset_id, evidence, rule_status):
    telnet_enabled = evidence.get("services", {}).get("telnet", False)

    payload = {
        "asset_id": asset_id,
        "benchmark_version": "CIS_TEST_1.0",
        "is_simulated": True,
        "status": "COMPLETED",
        "score": 100 if rule_status == "PASS" else 80,
        "findings": [
            {
                "rule_id": "NET-SSH-001",
                "status": rule_status,
                "severity": "High",
                "expected_value": "Telnet disabled",
                "actual_value": (
                    "Telnet disabled"
                    if not telnet_enabled
                    else "Telnet enabled"
                ),
                "evidence_source": "automated test fixture",
                "evidence": {
                    "services": {
                        "ssh": True,
                        "telnet": telnet_enabled,
                    }
                },
                "remediation": "Disable Telnet",
            }
        ],
        "snapshot": {
            "is_simulated": True,
            "evidence": evidence,
        },
    }

    response = request("POST", "/audits", payload, 201)
    data = response.json()

    audit_id = data.get("id", data.get("audit_id"))
    if audit_id is None:
        raise RuntimeError(f"Audit ID missing from response: {data}")

    return audit_id


def get_drift(audit_id):
    response = request("GET", f"/audits/{audit_id}/drift", expected_status=200)
    return response.json()


def run_tests():
    print(f"\nAPI: {BASE_URL}")
    print("Starting snapshot persistence and drift tests...\n")

    asset_id = create_asset("Primary")
    print(f"Created test asset: {asset_id}")

    baseline_evidence = {
        "hostname": f"primary-{run_id}",
        "services": {"ssh": True, "telnet": False},
        "firewall": {"enabled": True},
    }

    baseline_id = create_audit(asset_id, baseline_evidence, "PASS")
    print(f"Created baseline audit: {baseline_id}")

    # Test 1: First snapshot becomes the baseline.
    first_drift = get_drift(baseline_id)

    check(
        "First snapshot has no previous baseline",
        first_drift.get("baseline_audit_id") is None,
        str(first_drift),
    )

    check(
        "First snapshot is marked simulated",
        first_drift.get("is_simulated") is True,
        str(first_drift),
    )

    # Test 2: Snapshot changes and PASS -> FAIL regression.
    changed_evidence = {
        "hostname": f"primary-{run_id}",
        "services": {"ssh": True, "telnet": True},
        "firewall": {"enabled": False},
        "ntp": {"enabled": True},
    }

    changed_id = create_audit(asset_id, changed_evidence, "FAIL")
    print(f"Created changed audit: {changed_id}")

    drift = get_drift(changed_id)

    check(
        "Correct baseline audit is selected",
        drift.get("baseline_audit_id") == baseline_id,
        str(drift),
    )

    changes = {
        item["setting"]: item
        for item in drift.get("changes", [])
    }

    check(
        "Modified firewall setting detected",
        changes.get("firewall.enabled", {}).get("change_type") == "modified"
        and changes["firewall.enabled"].get("before") is True
        and changes["firewall.enabled"].get("after") is False,
        str(changes.get("firewall.enabled")),
    )

    check(
        "Modified Telnet setting detected",
        changes.get("services.telnet", {}).get("change_type") == "modified"
        and changes["services.telnet"].get("before") is False
        and changes["services.telnet"].get("after") is True,
        str(changes.get("services.telnet")),
    )

    check(
        "Added NTP setting detected",
        changes.get("ntp.enabled", {}).get("change_type") == "added"
        and changes["ntp.enabled"].get("after") is True,
        str(changes.get("ntp.enabled")),
    )

    newly_failing = {
        item["rule_id"]: item
        for item in drift.get("newly_failing_controls", [])
    }

    check(
        "PASS -> FAIL regression detected",
        newly_failing.get("NET-SSH-001", {}).get("previous_status") == "PASS"
        and newly_failing["NET-SSH-001"].get("current_status") == "FAIL",
        str(newly_failing),
    )

    # Test 3: FAIL -> PASS resolution.
    resolved_evidence = {
        "hostname": f"primary-{run_id}",
        "services": {"ssh": True, "telnet": False},
        "firewall": {"enabled": True},
        "ntp": {"enabled": True},
    }

    resolved_id = create_audit(asset_id, resolved_evidence, "PASS")
    print(f"Created resolved audit: {resolved_id}")

    resolved_drift = get_drift(resolved_id)

    resolved_controls = {
        item["rule_id"]: item
        for item in resolved_drift.get("resolved_controls", [])
    }

    check(
        "FAIL -> PASS resolution detected",
        resolved_controls.get("NET-SSH-001", {}).get("previous_status") == "FAIL"
        and resolved_controls["NET-SSH-001"].get("current_status") == "PASS",
        str(resolved_controls),
    )

    # Test 4: A different asset must not use the first asset's baseline.
    other_asset_id = create_asset("Isolated")
    other_evidence = {
        "hostname": f"isolated-{run_id}",
        "services": {"ssh": True, "telnet": False},
        "firewall": {"enabled": True},
    }

    other_audit_id = create_audit(
        other_asset_id,
        other_evidence,
        "PASS",
    )

    other_drift = get_drift(other_audit_id)

    check(
        "Different asset has no unrelated baseline",
        other_drift.get("baseline_audit_id") is None
        and other_drift.get("asset_id") == other_asset_id,
        str(other_drift),
    )

    # Test 5: Nonexistent audit should return HTTP 404.
    missing_id = 999999999
    missing_response = request(
        "GET",
        f"/audits/{missing_id}/drift",
    )

    check(
        "Missing audit returns HTTP 404",
        missing_response.status_code == 404,
        f"HTTP {missing_response.status_code}: {missing_response.text}",
    )


if __name__ == "__main__":
    try:
        run_tests()
    except Exception as exc:
        failed += 1
        print(f"\nTEST RUN ERROR: {exc}")
    finally:
        print("\n" + "=" * 45)
        print(f"PASSED: {passed}")
        print(f"FAILED: {failed}")
        print("=" * 45)

        if failed:
            print("Review the failures above before considering the tests complete.")
        else:
            print("All automated drift tests passed.")
