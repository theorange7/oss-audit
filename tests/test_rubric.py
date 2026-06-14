"""Tests for the rubric engine: apply_rubric thresholds, profiles, and overall verdict."""

from oss_audit.runner import apply_rubric
from tests.conftest import make_finding, make_tool_result


def _scores_by_cat(scores):
    return {s.category: s for s in scores}


def test_empty_results_warns_on_missing_license():
    # No findings at all: every category passes except license, which warns
    # because no license file was detected → overall WARN.
    scores, overall, reason = apply_rubric([make_tool_result(findings=[])], "privacy")
    by_cat = _scores_by_cat(scores)
    assert by_cat["vuln"].verdict == "PASS"
    assert by_cat["telemetry"].verdict == "PASS"
    assert by_cat["license"].verdict == "WARN"
    assert overall == "WARN"


def test_critical_vuln_fails():
    findings = [make_finding(category="vuln", severity="critical")]
    scores, overall, _ = apply_rubric([make_tool_result(findings=findings)], "privacy")
    assert _scores_by_cat(scores)["vuln"].verdict == "FAIL"
    assert overall == "FAIL"


def test_single_high_vuln_diverges_by_profile():
    findings = [make_finding(category="vuln", severity="high")]

    privacy = _scores_by_cat(apply_rubric([make_tool_result(findings=findings)], "privacy")[0])
    standard = _scores_by_cat(apply_rubric([make_tool_result(findings=findings)], "standard")[0])

    # privacy fails on the first high CVE; standard only warns (fail threshold is 5).
    assert privacy["vuln"].verdict == "FAIL"
    assert standard["vuln"].verdict == "WARN"


def test_counts_are_populated_per_category():
    findings = [
        make_finding(category="vuln", severity="high"),
        make_finding(category="vuln", severity="high"),
        make_finding(category="vuln", severity="medium"),
        make_finding(category="vuln", severity="low"),
    ]
    scores, _, _ = apply_rubric([make_tool_result(findings=findings)], "standard")
    vuln = _scores_by_cat(scores)["vuln"]
    assert (vuln.high_count, vuln.medium_count, vuln.low_count) == (2, 1, 1)
    assert vuln.critical_count == 0


def test_permissive_license_passes():
    findings = [make_finding(category="license", severity="info", title="License: MIT")]
    scores, _, _ = apply_rubric([make_tool_result(findings=findings)], "privacy")
    assert _scores_by_cat(scores)["license"].verdict == "PASS"


def test_copyleft_license_fails():
    findings = [make_finding(category="license", severity="high", title="License: GPL")]
    scores, _, _ = apply_rubric([make_tool_result(findings=findings)], "privacy")
    assert _scores_by_cat(scores)["license"].verdict == "FAIL"


def test_overall_is_worst_category():
    # A FAIL anywhere beats WARN/PASS elsewhere.
    findings = [
        make_finding(category="vuln", severity="critical"),     # FAIL
        make_finding(category="static", severity="high"),       # at most WARN under standard
    ]
    _, overall, _ = apply_rubric([make_tool_result(findings=findings)], "standard")
    assert overall == "FAIL"


def test_findings_aggregate_across_tool_results():
    # Two separate tool results contributing to the same category should sum.
    tr1 = make_tool_result(tool="grype", findings=[make_finding(category="vuln", severity="high")])
    tr2 = make_tool_result(tool="trivy", findings=[make_finding(category="vuln", severity="high")])
    scores, _, _ = apply_rubric([tr1, tr2], "standard")
    assert _scores_by_cat(scores)["vuln"].high_count == 2
