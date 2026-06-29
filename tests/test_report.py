"""Tests for the JSON / Markdown / HTML renderers."""

import json

from oss_audit.report import to_json, to_markdown, to_html
from tests.conftest import make_finding


def test_to_json_structure(build_result):
    res = build_result(findings=[
        make_finding(category="vuln", severity="critical", title="CVE-1"),
        make_finding(category="vuln", severity="low", title="CVE-2"),
    ], skipped_scanners=["scorecard"])
    data = json.loads(to_json(res))

    assert data["meta"]["repo_name"] == "myrepo"
    assert data["meta"]["overall_verdict"] == res.overall_verdict
    assert data["skipped_scanners"] == ["scorecard"]
    assert len(data["findings"]) == 2
    assert {f["title"] for f in data["findings"]} == {"CVE-1", "CVE-2"}
    assert any(t["scanner"] == "grype" for t in data["scanner_summary"])


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


# ── Issue 5: HTML escaping regression tests ───────────────────────────────────

def test_html_escapes_finding_title(build_result):
    res = build_result(findings=[
        make_finding(title='<img src=x onerror=alert(1)>', severity="high"),
    ])
    html = to_html(res)
    assert '<img src=x onerror=alert(1)>' not in html
    assert '&lt;img src=x onerror=alert(1)&gt;' in html


def test_html_escapes_finding_location(build_result):
    res = build_result(findings=[
        make_finding(location='</code><script>alert(1)</script>', severity="high"),
    ])
    html = to_html(res)
    assert '<script>' not in html


def test_html_escapes_verdict_reason(build_result):
    res = build_result(findings=[
        make_finding(category="vuln", severity="high", title="x"),
    ])
    res.overall_reason = '<b>injected</b>'
    html = to_html(res)
    assert '<b>injected</b>' not in html
    assert '&lt;b&gt;injected&lt;/b&gt;' in html


def test_html_sanitises_javascript_repo_url(build_result):
    res = build_result(findings=[])
    res.repo_url = 'javascript:alert(1)'
    html = to_html(res)
    assert 'href="javascript:' not in html


def test_html_detail_escapes_ampersand_and_quotes(build_result):
    res = build_result(findings=[
        make_finding(detail='a & b "quoted"', severity="low"),
    ])
    html = to_html(res)
    assert 'a & b "quoted"' not in html
    assert '&amp;' in html
    assert '&quot;' in html


# ── Issue 6: Markdown escaping regression tests ───────────────────────────────

def test_markdown_escapes_pipe_in_title(build_result):
    res = build_result(findings=[
        make_finding(title="foo | bar", severity="high"),
    ])
    md = to_markdown(res)
    assert "foo | bar" not in md
    assert "foo \\| bar" in md


def test_markdown_escapes_pipe_in_location(build_result):
    res = build_result(findings=[
        make_finding(location="path/to/file|injected", severity="high"),
    ])
    md = to_markdown(res)
    assert "path/to/file|injected" not in md


def test_markdown_neutralises_backtick_in_title(build_result):
    res = build_result(findings=[
        make_finding(title="title `with` backticks", severity="medium"),
    ])
    md = to_markdown(res)
    assert "`with`" not in md


def test_markdown_neutralises_newline_in_title(build_result):
    res = build_result(findings=[
        make_finding(title="line1\nline2", severity="low"),
    ])
    md = to_markdown(res)
    assert "line1 line2" in md


# ── Issue 7: Unknown category regression tests ────────────────────────────────

def test_html_renders_finding_with_unknown_category(build_result):
    res = build_result(findings=[
        make_finding(category="custom_scanner_xyz", severity="high", title="Unknown-cat finding"),
    ])
    html = to_html(res)
    assert "Unknown-cat finding" in html


def test_markdown_renders_finding_with_unknown_category(build_result):
    res = build_result(findings=[
        make_finding(category="custom_scanner_xyz", severity="high", title="Unknown-cat finding"),
    ])
    md = to_markdown(res)
    assert "Unknown-cat finding" in md


def test_unknown_category_findings_grouped_in_other_section(build_result):
    res = build_result(findings=[
        make_finding(category="custom_scanner_xyz", severity="critical", title="UnknownA"),
        make_finding(category="another_custom", severity="low", title="UnknownB"),
    ])
    html = to_html(res)
    md = to_markdown(res)
    assert "Other" in html
    assert "UnknownA" in html
    assert "UnknownB" in html
    assert "Other" in md
    assert "UnknownA" in md
    assert "UnknownB" in md
