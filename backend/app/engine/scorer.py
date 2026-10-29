"""
Compliance scoring — deterministic, no AI/ML.

Formula:  score = PASS / (PASS + FAIL) * 100
  - MANUAL, ERROR, NOT_APPLICABLE are excluded from the score denominator.
  - If there are no PASS or FAIL findings, score is None (not 0 or 100).
  - Coverage = (PASS + FAIL) / total_findings * 100
"""
from __future__ import annotations

from typing import Any


def compute_score(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Compute compliance score and coverage from a list of finding dicts.

    Args:
        findings: List of finding dicts, each must have a 'status' key.

    Returns:
        dict with:
          score        (float 0-100, or None if no PASS/FAIL results)
          pass_count   (int)
          fail_count   (int)
          manual_count (int)
          error_count  (int)
          na_count     (int)
          total        (int)
          coverage_pct (float 0-100 — proportion of assessable findings)
    """
    counts: dict[str, int] = {
        "PASS": 0,
        "FAIL": 0,
        "MANUAL": 0,
        "ERROR": 0,
        "NOT_APPLICABLE": 0,
    }

    for f in findings:
        status = f.get("status", "ERROR")
        if status in counts:
            counts[status] += 1
        else:
            counts["ERROR"] += 1  # unexpected status treated as ERROR

    total = len(findings)
    assessable = counts["PASS"] + counts["FAIL"]

    score: float | None = None
    if assessable > 0:
        score = round(counts["PASS"] / assessable * 100, 2)

    coverage_pct = round(assessable / total * 100, 2) if total > 0 else 0.0

    return {
        "score": score,
        "pass_count": counts["PASS"],
        "fail_count": counts["FAIL"],
        "manual_count": counts["MANUAL"],
        "error_count": counts["ERROR"],
        "na_count": counts["NOT_APPLICABLE"],
        "total": total,
        "coverage_pct": coverage_pct,
    }
