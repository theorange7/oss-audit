"""Shared test fixtures and builders.

Tests import from the package's public facade (oss_audit.runner / oss_audit.report
/ oss_audit.cli) so they stay valid across the internal module restructure.
"""

import pytest

from oss_audit.runner import AuditResult, ToolResult, Finding, apply_rubric


def make_finding(category="vuln", severity="high", tool="grype",
                 title="CVE-0001 in pkg 1.0", detail="a vulnerability", location="pkg.json"):
    return Finding(tool=tool, severity=severity, category=category,
                   title=title, detail=detail, location=location)


def make_tool_result(tool="grype", findings=None, available=True, ran=True,
                     error="", duration_s=0.5):
    return ToolResult(tool=tool, available=available, ran=ran,
                      findings=list(findings or []), error=error, duration_s=duration_s)


@pytest.fixture
def build_result():
    """Return a factory that builds a fully-scored AuditResult from a list of Findings."""
    def _build(findings=None, profile="privacy", repo_name="myrepo", skipped_tools=None):
        tr = make_tool_result(findings=findings or [])
        res = AuditResult(
            repo_url=f"https://github.com/org/{repo_name}",
            repo_name=repo_name,
            profile=profile,
            timestamp="2026-06-14T14:32:01+00:00",
            tool_results=[tr],
            skipped_tools=list(skipped_tools or []),
        )
        rubric, overall, reason = apply_rubric(res.tool_results, profile)
        res.rubric = rubric
        res.overall_verdict = overall
        res.overall_reason = reason
        return res
    return _build
