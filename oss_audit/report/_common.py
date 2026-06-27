"""
Shared rendering constants and finding-collection helpers used by all three
report renderers.
"""

from ..models import AuditResult, Finding

VERDICT_EMOJI = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "ERROR": "🔴", "UNKNOWN": "❓"}
VERDICT_COLOR = {"PASS": "#22c55e", "WARN": "#f59e0b", "FAIL": "#ef4444", "ERROR": "#dc2626", "UNKNOWN": "#94a3b8"}
SEV_COLOR = {"critical": "#7f1d1d", "high": "#ef4444", "medium": "#f59e0b", "low": "#6366f1", "info": "#64748b"}
SEV_BG    = {"critical": "#fef2f2", "high": "#fff7ed", "medium": "#fffbeb", "low": "#eef2ff", "info": "#f8fafc"}

CAT_LABELS = {
    "vuln": "Vulnerabilities",
    "secret": "Secrets / Credentials",
    "license": "License",
    "health": "Project Health",
    "telemetry": "Telemetry / Privacy",
    "static": "Static Analysis",
}

# ── scanner attribution ──────────────────────────────────────────────────────
# Which finding categories each scanner is capable of producing. This is the
# source of truth for the per-section "Scanned by" line — it lets an empty section
# still name the scanner(s) that looked (and found nothing), which is a trust
# signal. Keep in sync with the categories the scanners actually emit (a test
# guards this). Note: syft is intentionally absent — it builds an SBOM that feeds
# grype, it does not detect vulnerabilities, so it is not credited as a vuln scanner.
SCANNER_CATEGORIES: dict[str, set[str]] = {
    "grype":          {"vuln"},
    "trivy":          {"vuln", "secret"},
    "osv-scanner":    {"vuln"},
    "gitleaks":       {"secret"},
    "semgrep":        {"static"},
    "scorecard":      {"health"},
    "licensee":       {"license"},
    "license-grep":   {"license"},
    "telemetry-grep": {"telemetry"},
}

# Built-in heuristics: always available, so never reported as "not installed",
# and tagged "(heuristic)" so a reader doesn't mistake them for industry scanners.
HEURISTIC_SCANNERS: frozenset[str] = frozenset({"license-grep", "telemetry-grep"})


def display_scanner(scanner: str) -> str:
    """Scanner id for display — built-in greps get a '(heuristic)' qualifier."""
    return f"{scanner} (heuristic)" if scanner in HEURISTIC_SCANNERS else scanner


def scanned_by(result: AuditResult, category: str) -> tuple[list[str], list[str]]:
    """
    For one finding category, return (ran, not_installed):
      ran           — capable scanners that actually executed (even if 0 findings)
      not_installed — capable third-party scanners that were unavailable
    Both lists are sorted for deterministic output. Built-in heuristics are never
    listed as not_installed.
    """
    capable = {s for s, cats in SCANNER_CATEGORIES.items() if category in cats}
    by_name = {sr.scanner: sr for sr in result.scan_results}

    ran = sorted(s for s in capable if s in by_name and by_name[s].ran)
    not_installed = sorted(
        s for s in capable
        if s not in ran
        and s not in HEURISTIC_SCANNERS
        and (s not in by_name or not by_name[s].available)
    )
    return ran, not_installed


def scanner_findings(result: AuditResult, category: str | None = None) -> list[Finding]:
    findings = []
    for tr in result.scan_results:
        for f in tr.findings:
            if category is None or f.category == category:
                findings.append(f)
    return findings


def all_findings(result: AuditResult) -> list[Finding]:
    return scanner_findings(result)
