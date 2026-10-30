"""
Deterministic rule evaluator.

Principles:
- Missing / None evidence  → MANUAL  (never PASS)
- Collection errors        → ERROR
- Unknown operators        → ERROR   (never silently ignored)
- NOT_APPLICABLE           → only when rule explicitly flags it
- Identical evidence + rule version → identical result (deterministic)
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Status constants – match FindingStatus enum in schemas/audit.py
STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_MANUAL = "MANUAL"
STATUS_ERROR = "ERROR"
STATUS_NA = "NOT_APPLICABLE"


def _get_nested(data: dict, path: str) -> tuple[bool, Any]:
    """
    Traverse a dot-separated evidence_path and return (found, value).

    Returns (False, None) if any key is absent.
    """
    parts = path.split(".")
    current: Any = data
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _to_bool(value: Any) -> bool | None:
    """
    Safely convert a value to bool.

    Returns:
        True   -- for Python True, 1, or strings 'true'/'yes'/'1' (case-insensitive)
        False  -- for Python False, 0, or strings 'false'/'no'/'0' (case-insensitive)
        None   -- for None, ambiguous strings, or unparseable types (produces MANUAL)
    """
    if value is None:
        return None
    if type(value) is bool:
        return value
    if isinstance(value, (int, float)):
        if value == 1:
            return True
        if value == 0:
            return False
        return None
    if isinstance(value, str):
        lower = value.strip().lower()
        if lower in ("true", "yes", "1"):
            return True
        if lower in ("false", "no", "0"):
            return False
        return None
    return None


def _evaluate_operator(operator: str, actual: Any, expected: Any) -> tuple[str, str]:
    """
    Apply the operator.  Returns (status, explanation_of_actual).

    The explanation is stored as the 'actual' field in the finding.
    Raises ValueError for unknown operators (caller converts to ERROR).
    """
    # Normalise strings for comparison operators
    actual_str = str(actual).strip().lower() if actual is not None else None
    expected_str = str(expected).strip().lower() if expected is not None else None

    if operator == "is_true":
        bool_val = _to_bool(actual)
        if bool_val is None:
            return STATUS_MANUAL, str(actual)
        return (STATUS_PASS if bool_val is True else STATUS_FAIL), str(actual)

    if operator == "is_false":
        bool_val = _to_bool(actual)
        if bool_val is None:
            return STATUS_MANUAL, str(actual)
        return (STATUS_PASS if bool_val is False else STATUS_FAIL), str(actual)

    if operator == "exists":
        # The caller already confirmed the path exists before reaching here,
        # so actual is the value found (may be None/empty — we treat that as FAIL)
        passed = actual is not None and actual != "" and actual != []
        return (STATUS_PASS if passed else STATUS_FAIL), repr(actual)

    if operator == "equals":
        passed = actual_str == expected_str
        return (STATUS_PASS if passed else STATUS_FAIL), str(actual)

    if operator == "not_equals":
        passed = actual_str != expected_str
        return (STATUS_PASS if passed else STATUS_FAIL), str(actual)

    if operator == "contains":
        if actual_str is None:
            return STATUS_FAIL, "None"
        passed = expected_str in actual_str
        return (STATUS_PASS if passed else STATUS_FAIL), str(actual)

    raise ValueError(f"Unknown operator: '{operator}'")


def evaluate_rule(rule: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """
    Evaluate a single rule against normalised evidence.

    Args:
        rule:     A validated rule dict from the loader.
        evidence: Normalised nested dictionary from a collector.

    Returns:
        A finding dict with keys:
          rule_id, status, severity, expected, actual,
          evidence, evidence_source, remediation
    """
    rule_id = rule["rule_id"]
    severity = rule["severity"]
    expected_value = rule["expected_value"]
    operator = rule["operator"]
    evidence_path = rule["evidence_path"]
    remediation = rule["remediation"]
    evidence_source = evidence.get("_source", "unknown")

    base: dict[str, Any] = {
        "rule_id": rule_id,
        "severity": severity,
        "expected": str(expected_value) if expected_value is not None else "exists",
        "actual": None,
        "evidence": {},
        "evidence_source": evidence_source,
        "remediation": remediation,
    }

    try:
        found, value = _get_nested(evidence, evidence_path)

        if not found:
            # Missing evidence — requires human verification, never PASS
            base["status"] = STATUS_MANUAL
            base["actual"] = f"Evidence path '{evidence_path}' not found in collected data"
            base["evidence"] = {"path_checked": evidence_path, "data_keys": list(evidence.keys())}
            return base

        # Evidence present — evaluate deterministically
        status, actual_repr = _evaluate_operator(operator, value, expected_value)

        base["status"] = status
        base["actual"] = actual_repr
        base["evidence"] = {evidence_path: value}
        return base

    except ValueError as exc:
        # Unknown operator — this is a rule definition bug
        logger.error("Rule '%s' operator error: %s", rule_id, exc)
        base["status"] = STATUS_ERROR
        base["actual"] = f"Evaluation error: {exc}"
        base["evidence"] = {"error": str(exc)}
        return base

    except Exception as exc:  # noqa: BLE001
        # Unexpected error — do not mask as PASS
        logger.exception("Unexpected error evaluating rule '%s': %s", rule_id, exc)
        base["status"] = STATUS_ERROR
        base["actual"] = f"Unexpected evaluation error: {exc}"
        base["evidence"] = {"error": str(exc)}
        return base


def evaluate_rules(
    rules: list[dict[str, Any]],
    evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Evaluate all rules against the given evidence.  Deterministic.

    Args:
        rules:    List of validated rule dicts.
        evidence: Normalised evidence dict (may include '_source' key).

    Returns:
        List of finding dicts, one per rule, in the same order.
    """
    return [evaluate_rule(r, evidence) for r in rules]
