"""Tests for per-section scanner attribution.

Covers the SCANNER_CATEGORIES capability map (and its drift against what scanners
actually emit), the scanned_by() helper, honest license-grep attribution, and the
renderer output that surfaces it.
"""

from oss_audit.report._common import (
    SCANNER_CATEGORIES, HEURISTIC_SCANNERS, display_scanner, scanned_by,
)
from oss_audit.report import to_markdown, to_html
from oss_audit.scanners import (
    parse_grype, parse_trivy, parse_semgrep, parse_osv, parse_scorecard,
    parse_gitleaks, run_license_scan, run_telemetry_scan,
)
from oss_audit.models import AuditResult
from oss_audit.rubric import apply_rubric
from tests.conftest import make_finding, make_scan_result


def _full_result(findings):
    """An AuditResult whose scan_results cover every category's scanner, so the
    'Scanned by' lines have something real to report."""
    by_scanner: dict[str, list] = {}
    for f in findings:
        by_scanner.setdefault(f.scanner, []).append(f)
    slots = ["grype", "trivy", "osv-scanner", "gitleaks", "semgrep",
             "scorecard", "telemetry-grep"]
    scan_results = [make_scan_result(scanner=s, findings=by_scanner.get(s, []))
                    for s in slots]
    res = AuditResult(repo_url="https://github.com/org/myrepo", repo_name="myrepo",
                      profile="privacy", timestamp="2026-06-14T14:32:01+00:00",
                      scan_results=scan_results)
    res.rubric, res.overall_verdict, res.overall_reason = apply_rubric(
        res.scan_results, "privacy")
    return res


# ── capability-map drift ─────────────────────────────────────────────────────
# The map is the source of truth for "Scanned by". If a scanner starts emitting a
# new category, the map must learn about it — otherwise the section line lies.

def _emitted_categories():
    """Categories each scanner actually emits, derived from real scanner output."""
    emitted: dict[str, set[str]] = {}

    def record(findings):
        for f in findings:
            emitted.setdefault(f.scanner, set()).add(f.category)

    record(parse_grype({"matches": [
        {"vulnerability": {"id": "CVE-1", "severity": "High"},
         "artifact": {"name": "p", "version": "1"}},
    ]}))
    record(parse_trivy({"Results": [
        {"Target": "x",
         "Vulnerabilities": [{"VulnerabilityID": "CVE-2", "PkgName": "p",
                              "InstalledVersion": "1", "Severity": "HIGH"}],
         "Secrets": [{"Title": "key", "Match": "AKIA"}]},
    ]}))
    record(parse_osv({"results": [{"packages": [
        {"package": {"name": "p"}, "vulnerabilities": [{"id": "OSV-1"}]},
    ]}]}))
    record(parse_gitleaks([{"Description": "k", "Commit": "abcdef12",
                            "File": "f", "StartLine": 1}]))
    record(parse_semgrep({"results": [
        {"check_id": "a.b.c", "path": "f", "start": {"line": 1},
         "extra": {"severity": "ERROR", "message": "m"}},
    ]}))
    record(parse_scorecard({"score": 5.0, "checks": [
        {"name": "Maintained", "score": 8},
    ]}))
    return emitted


def test_capability_map_covers_emitted_categories():
    """Every category a parser emits must be declared for that scanner in the map."""
    for scanner, cats in _emitted_categories().items():
        assert scanner in SCANNER_CATEGORIES, \
            f"{scanner} emits findings but is not in SCANNER_CATEGORIES"
        missing = cats - SCANNER_CATEGORIES[scanner]
        assert not missing, f"{scanner} emits {missing} not declared in SCANNER_CATEGORIES"


def test_grep_scanners_emit_declared_categories(tmp_path):
    # license-grep fallback (licensee not installed) → license category.
    (tmp_path / "LICENSE").write_text("MIT License\n\nPermission is hereby granted...")
    lic = run_license_scan(str(tmp_path), available={"licensee": False})
    assert lic.scanner == "license-grep"
    assert lic.findings and all(f.scanner == "license-grep" for f in lic.findings)
    assert {f.category for f in lic.findings} <= SCANNER_CATEGORIES["license-grep"]

    # telemetry-grep → telemetry category.
    (tmp_path / "app.py").write_text("import mixpanel\nmixpanel.track('x')\n")
    tel = run_telemetry_scan(str(tmp_path))
    assert tel.scanner == "telemetry-grep"
    assert tel.findings and all(f.scanner == "telemetry-grep" for f in tel.findings)
    assert {f.category for f in tel.findings} <= SCANNER_CATEGORIES["telemetry-grep"]


def test_syft_not_credited_as_vuln_scanner():
    # syft builds an SBOM; it must not appear as a vulnerability detector.
    assert "syft" not in SCANNER_CATEGORIES


# ── scanned_by helper ────────────────────────────────────────────────────────

def _result_with(scan_results):
    return AuditResult(repo_url="u", repo_name="r", profile="privacy",
                       timestamp="t", scan_results=scan_results)


def test_scanned_by_lists_ran_scanners_even_with_zero_findings():
    res = _result_with([
        make_scan_result(scanner="grype", findings=[], available=True, ran=True),
        make_scan_result(scanner="osv-scanner", findings=[], available=True, ran=True),
        make_scan_result(scanner="trivy", findings=[], available=True, ran=True),
    ])
    ran, not_installed = scanned_by(res, "vuln")
    assert ran == ["grype", "osv-scanner", "trivy"]
    assert not_installed == []


def test_scanned_by_reports_missing_thirdparty_as_not_installed():
    res = _result_with([
        make_scan_result(scanner="osv-scanner", findings=[], available=True, ran=True),
        make_scan_result(scanner="grype", findings=[], available=False, ran=False),
        make_scan_result(scanner="trivy", findings=[], available=False, ran=False),
    ])
    ran, not_installed = scanned_by(res, "vuln")
    assert ran == ["osv-scanner"]
    assert not_installed == ["grype", "trivy"]


def test_scanned_by_never_lists_heuristics_as_not_installed():
    # telemetry-grep is built in; its absence is impossible and must never show
    # up as "not installed".
    res = _result_with([])
    ran, not_installed = scanned_by(res, "telemetry")
    assert ran == []
    assert not_installed == []


def test_display_scanner_tags_heuristics_only():
    assert display_scanner("grype") == "grype"
    assert display_scanner("license-grep") == "license-grep (heuristic)"
    assert all(display_scanner(s).endswith("(heuristic)") for s in HEURISTIC_SCANNERS)


# ── renderer integration ─────────────────────────────────────────────────────

def test_markdown_shows_scanned_by_and_scanner_column():
    res = _full_result([make_finding(category="vuln", scanner="grype",
                                      title="CVE-MD", severity="high")])
    md = to_markdown(res)
    assert "**Scanned by:**" in md
    assert "| Severity | Title | Scanner | Location |" in md
    # the finding's scanner appears in its row
    assert "| `grype` |" in md
    # the vuln section credits the scanners that ran, not the missing ones
    assert "grype, osv-scanner, trivy" in md


def test_html_renders_clean_section_with_attribution():
    # No findings at all → every category is clean and must still name its scanner.
    res = _full_result([])
    html = to_html(res)
    assert "Scanned by:" in html
    assert "No issues detected" in html
    # telemetry's built-in heuristic is tagged
    assert "telemetry-grep (heuristic)" in html
