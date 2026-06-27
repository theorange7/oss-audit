"""
rubric.py — turns a list of ScanResults into per-category verdicts and an
overall PASS / WARN / FAIL under the selected profile.
"""

from .models import Finding, ScanResult, CategoryVerdict
from .severity import SEVERITY_LEVELS


RUBRIC_THRESHOLDS = {
    "standard": {
        "vuln":      {"fail_critical": 1, "fail_high": 5,  "warn_high": 1},
        "secret":    {"fail_critical": 1, "fail_high": 1,  "warn_high": 1},
        "license":   {"fail_high": 1,     "warn_medium": 1},
        "health":    {"fail_high": 3,     "warn_high": 1},
        # Telemetry is advisory: grep patterns are heuristic, so we surface them
        # for review rather than failing the audit outright.
        "telemetry": {"warn_high": 1,     "warn_medium": 1},
        "static":    {"fail_critical": 1, "fail_high": 10, "warn_high": 3},
    },
    "privacy": {
        # Tighter thresholds for privacy-sensitive / confidential contexts
        "vuln":      {"fail_critical": 1, "fail_high": 1,  "warn_high": 1},
        "secret":    {"fail_critical": 1, "fail_high": 1,  "warn_high": 1},
        "license":   {"fail_high": 1,     "warn_medium": 1},
        "health":    {"fail_high": 2,     "warn_high": 1},
        # Advisory even under privacy — flag for review, don't hard-fail on a heuristic.
        "telemetry": {"warn_high": 1,     "warn_medium": 1},
        "static":    {"fail_critical": 1, "fail_high": 5,  "warn_high": 1},
    },
}


def apply_rubric(tool_results: list[ScanResult], profile: str) -> tuple[list[CategoryVerdict], str, str]:
    thresholds = RUBRIC_THRESHOLDS.get(profile, RUBRIC_THRESHOLDS["standard"])

    # Aggregate findings by category
    by_category: dict[str, list[Finding]] = {}
    for tr in tool_results:
        for f in tr.findings:
            by_category.setdefault(f.category, []).append(f)

    scores = []
    for cat, thresh in thresholds.items():
        findings = by_category.get(cat, [])
        counts = {s: sum(1 for f in findings if f.severity == s)
                  for s in SEVERITY_LEVELS}

        verdict = "PASS"
        reason = "No significant issues detected."

        if cat == "telemetry" and not findings:
            reason = "No telemetry/analytics SDK calls or PII patterns found."
        elif cat == "license" and not findings:
            verdict = "WARN"
            reason = "No license file detected — manual review required."

        # Apply fail conditions
        if counts["critical"] >= thresh.get("fail_critical", 999):
            verdict = "FAIL"
            reason = f"{counts['critical']} critical issue(s) found."
        elif counts["high"] >= thresh.get("fail_high", 999):
            verdict = "FAIL"
            reason = f"{counts['high']} high-severity issue(s) exceed threshold ({thresh.get('fail_high')})."
        elif counts["high"] >= thresh.get("warn_high", 999) or counts["medium"] >= thresh.get("warn_medium", 999):
            if verdict != "FAIL":
                verdict = "WARN"
                if cat == "telemetry":
                    reason = (f"{counts['high']} high / {counts['medium']} medium telemetry/PII "
                              f"signal(s) — heuristic matches; review before use.")
                else:
                    reason = f"{counts['high']} high / {counts['medium']} medium issue(s) — review recommended."

        scores.append(CategoryVerdict(
            category=cat,
            verdict=verdict,
            reason=reason,
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
        ))

    # Overall verdict: FAIL if any FAIL, WARN if any WARN, else PASS
    verdicts = [s.verdict for s in scores]
    if "FAIL" in verdicts:
        overall = "FAIL"
        overall_reason = "One or more categories failed the rubric. Review findings before deployment."
    elif "WARN" in verdicts:
        overall = "WARN"
        overall_reason = "Issues warrant manual review before use in sensitive environments."
    else:
        overall = "PASS"
        overall_reason = "No blocking issues detected under the selected profile."

    return scores, overall, overall_reason
