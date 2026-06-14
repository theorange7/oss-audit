"""Tests for the JSON / Markdown / HTML renderers."""

import json

from oss_audit.report import to_json, to_markdown, to_html
from tests.conftest import make_finding


def test_to_json_structure(build_result):
    res = build_result(findings=[
        make_finding(category="vuln", severity="critical", title="CVE-1"),
        make_finding(category="vuln", severity="low", title="CVE-2"),
    ], skipped_tools=["scorecard"])
    data = json.loads(to_json(res))

    assert data["meta"]["repo_name"] == "myrepo"
    assert data["meta"]["overall_verdict"] == res.overall_verdict
    assert data["skipped_tools"] == ["scorecard"]
    assert len(data["findings"]) == 2
    assert {f["title"] for f in data["findings"]} == {"CVE-1", "CVE-2"}
    assert any(t["tool"] == "grype" for t in data["tool_summary"])


def test_to_markdown_contains_key_fields(build_result):
    res = build_result(findings=[make_finding(title="CVE-MD", severity="high")])
    md = to_markdown(res)
    assert "myrepo" in md
    assert "CVE-MD" in md
    assert res.overall_verdict in md
    assert "## Executive Summary" in md


def test_to_html_renders_and_escapes_detail(build_result):
    # A finding detail containing markup must be escaped in the HTML output.
    res = build_result(findings=[
        make_finding(title="XSS test", detail="<script>alert(1)</script>", severity="high"),
    ])
    html = to_html(res)
    assert "<!DOCTYPE html>" in html
    assert "XSS test" in html
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_to_html_orders_findings_by_severity(build_result):
    res = build_result(findings=[
        make_finding(category="vuln", severity="low", title="LOW_ONE"),
        make_finding(category="vuln", severity="critical", title="CRIT_ONE"),
    ])
    html = to_html(res)
    # Within the rendered output the critical finding must appear before the low one.
    assert html.index("CRIT_ONE") < html.index("LOW_ONE")


def test_renderers_handle_no_findings(build_result):
    res = build_result(findings=[])
    # None of these should raise on an empty finding set.
    assert json.loads(to_json(res))["findings"] == []
    assert "## Executive Summary" in to_markdown(res)
    assert "<!DOCTYPE html>" in to_html(res)
