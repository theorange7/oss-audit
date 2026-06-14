"""Tests for the pure scanner output parsers.

These feed decoded tool output (the shape each scanner emits) to parse_* and
assert on the normalised Findings — no scanner binary required.
"""

import json
from pathlib import Path

from oss_audit.scanners import (
    parse_grype, parse_trivy, parse_semgrep, parse_osv, parse_scorecard, parse_gitleaks,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# ── grype ────────────────────────────────────────────────────────────────────

def test_parse_grype_fixture():
    findings = parse_grype(_load("grype.json"))
    assert len(findings) == 2

    first = findings[0]
    assert first.severity == "critical"
    assert first.category == "vuln"
    assert first.title == "CVE-2021-1234 in libfoo 1.2.3"
    assert first.location == "/app/requirements.txt"

    second = findings[1]
    assert second.severity == "medium"          # "Moderate" → medium
    assert second.location == ""                 # no locations key


def test_parse_grype_empty():
    assert parse_grype({}) == []
    assert parse_grype({"matches": []}) == []


# ── trivy ────────────────────────────────────────────────────────────────────

def test_parse_trivy_vulns_and_secrets():
    data = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "PkgName": "lodash",
                     "InstalledVersion": "4.0.0", "Severity": "HIGH", "Description": "proto pollution"},
                ],
                "Secrets": [
                    {"Title": "AWS Access Key", "Match": "AKIA..."},
                ],
            },
        ]
    }
    findings = parse_trivy(data)
    assert len(findings) == 2
    vuln = next(f for f in findings if f.category == "vuln")
    secret = next(f for f in findings if f.category == "secret")
    assert vuln.severity == "high"
    assert vuln.title == "CVE-1 in lodash 4.0.0"
    assert secret.severity == "high"
    assert secret.title == "Secret: AWS Access Key"
    assert secret.location == "package-lock.json"


def test_parse_trivy_handles_null_lists():
    # Trivy emits null (not []) for absent Vulnerabilities/Secrets.
    data = {"Results": [{"Target": "x", "Vulnerabilities": None, "Secrets": None}]}
    assert parse_trivy(data) == []
    assert parse_trivy({}) == []


# ── semgrep ──────────────────────────────────────────────────────────────────

def test_parse_semgrep_title_is_last_rule_segment():
    data = {
        "results": [
            {
                "check_id": "python.lang.security.audit.dangerous-eval",
                "path": "src/app.py",
                "start": {"line": 42},
                "extra": {"severity": "ERROR", "message": "Avoid eval"},
            }
        ]
    }
    findings = parse_semgrep(data)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "static"
    assert f.title == "dangerous-eval"          # last dotted segment
    assert f.location == "src/app.py:42"
    assert f.severity == "info"                  # "ERROR" is unmapped → info


def test_parse_semgrep_empty():
    assert parse_semgrep({}) == []


# ── osv ──────────────────────────────────────────────────────────────────────

def test_parse_osv_cvss_mapping():
    data = {
        "results": [
            {"packages": [
                {"package": {"name": "requests"},
                 "vulnerabilities": [
                     {"id": "OSV-1", "summary": "bad", "severity": [{"score": "9.5"}]},
                     {"id": "OSV-2", "summary": "meh", "severity": [{"score": "5.0"}]},
                     {"id": "OSV-3", "summary": "no score"},   # defaults to medium
                 ]},
            ]},
        ]
    }
    findings = parse_osv(data)
    sev_by_id = {f.title.split()[0]: f.severity for f in findings}
    assert sev_by_id["OSV-1"] == "critical"
    assert sev_by_id["OSV-2"] == "medium"
    assert sev_by_id["OSV-3"] == "medium"        # no severity entries → default


def test_parse_osv_non_numeric_score_keeps_default():
    data = {"results": [{"packages": [
        {"package": {"name": "p"}, "vulnerabilities": [
            {"id": "OSV-X", "severity": [{"score": "CVSS:3.1/AV:N"}]},
        ]},
    ]}]}
    assert parse_osv(data)[0].severity == "medium"


# ── scorecard ────────────────────────────────────────────────────────────────

def test_parse_scorecard_fixture():
    findings = parse_scorecard(_load("scorecard.json"))
    # 1 aggregate + 3 per-check
    assert len(findings) == 4

    agg = findings[0]
    assert agg.title == "OpenSSF Scorecard aggregate: 7.3/10"
    assert agg.severity == "low"                 # 7.3 → low
    assert "at commit abcdef12" in agg.detail

    by_name = {f.title.split(":")[0]: f for f in findings[1:]}
    assert by_name["Maintained"].severity == "info"          # 10 → passing
    assert by_name["Branch-Protection"].severity == "high"   # 2 → high
    # details capped at 3
    assert "d1; d2; d3" in by_name["Branch-Protection"].detail
    assert "d4" not in by_name["Branch-Protection"].detail
    assert by_name["CII-Best-Practices"].title.endswith("N/A")  # score -1


def test_parse_scorecard_no_aggregate_when_negative():
    # A negative aggregate (couldn't compute) yields no aggregate finding.
    findings = parse_scorecard({"score": -1, "checks": []})
    assert findings == []


# ── gitleaks ─────────────────────────────────────────────────────────────────

def test_parse_gitleaks():
    leaks = [
        {"Description": "AWS Key", "RuleID": "aws", "Commit": "deadbeefcafef00d",
         "Author": "alice", "File": "config.py", "StartLine": 10},
    ]
    findings = parse_gitleaks(leaks)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert f.category == "secret"
    assert f.title == "Secret detected: AWS Key"
    assert f.location == "config.py:10"
    assert "deadbeef" in f.detail            # commit truncated to 8 chars


def test_parse_gitleaks_empty_and_none():
    assert parse_gitleaks([]) == []
    assert parse_gitleaks(None) == []
