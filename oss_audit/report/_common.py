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


def scanner_findings(result: AuditResult, category: str | None = None) -> list[Finding]:
    findings = []
    for tr in result.scan_results:
        for f in tr.findings:
            if category is None or f.category == category:
                findings.append(f)
    return findings


def all_findings(result: AuditResult) -> list[Finding]:
    return scanner_findings(result)


def html_escape(s: str) -> str:
    """Quote-aware HTML escape for untrusted content."""
    return (s
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;"))


def safe_href(url: str) -> str:
    """Return url (HTML-escaped) if scheme is http/https, else '#'."""
    from urllib.parse import urlparse
    scheme = urlparse(url).scheme.lower()
    if scheme in ("http", "https"):
        return html_escape(url)
    return "#"
