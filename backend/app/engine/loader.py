"""
Rule loader — reads and validates JSON rule catalog files.

Each rule must contain:
  rule_id, title, description, severity, benchmark_reference,
  evidence_path, operator, expected_value, remediation, version
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = {
    "rule_id", "title", "description", "severity",
    "benchmark_reference", "evidence_path", "operator",
    "expected_value", "remediation", "version",
}

SUPPORTED_OPERATORS = {
    "equals", "not_equals", "exists",
    "contains", "is_true", "is_false",
}

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}


class RuleValidationError(Exception):
    """Raised when a rule definition is malformed."""


def _validate_rule(rule: dict[str, Any], source_file: str) -> None:
    """Raise RuleValidationError if any required field is missing or invalid."""
    missing = REQUIRED_FIELDS - set(rule.keys())
    if missing:
        raise RuleValidationError(
            f"Rule '{rule.get('rule_id', '<unknown>')}' in {source_file} "
            f"is missing required fields: {sorted(missing)}"
        )

    op = rule["operator"]
    if op not in SUPPORTED_OPERATORS:
        raise RuleValidationError(
            f"Rule '{rule['rule_id']}' in {source_file} uses unknown operator "
            f"'{op}'. Supported: {sorted(SUPPORTED_OPERATORS)}"
        )

    if not rule["rule_id"].strip():
        raise RuleValidationError(f"rule_id must be a non-empty string in {source_file}")

    if not rule["evidence_path"].strip():
        raise RuleValidationError(
            f"Rule '{rule['rule_id']}' has an empty evidence_path in {source_file}"
        )


def load_rules(path: str | Path) -> list[dict[str, Any]]:
    """
    Load and validate all rules from a JSON file.

    Args:
        path: Path to a JSON rule catalog file.

    Returns:
        List of validated rule dictionaries.

    Raises:
        FileNotFoundError: if the file does not exist.
        RuleValidationError: if any rule is malformed.
        json.JSONDecodeError: if the file is not valid JSON.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Rule file not found: {path}")

    with path.open(encoding="utf-8-sig") as fh:
        rules = json.load(fh)

    if not isinstance(rules, list):
        raise RuleValidationError(f"{path}: top-level element must be a JSON array")

    validated: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            raise RuleValidationError(f"{path}: each rule must be a JSON object")
        _validate_rule(rule, str(path))
        validated.append(rule)

    logger.info("Loaded %d rules from %s", len(validated), path)
    return validated


def load_rules_for_asset_type(rules_dir: str | Path, asset_type: str) -> list[dict[str, Any]]:
    """
    Load rules appropriate for the given asset_type.

    Mapping:
      - firewall / router / switch / network_device -> network.json
      - linux                                       -> linux.json
      - windows                                     -> windows.json

    Returns an empty list (not an error) if no rule file covers this asset type.
    """
    rules_dir = Path(rules_dir)
    mapping: dict[str, str] = {
        "firewall": "network.json",
        "router": "network.json",
        "switch": "network.json",
        "network_device": "network.json",
        "linux": "linux.json",
        "windows": "windows.json",
    }

    filename = mapping.get(asset_type.lower())
    if filename is None:
        logger.warning("No rule file mapped for asset_type '%s'", asset_type)
        return []

    return load_rules(rules_dir / filename)
