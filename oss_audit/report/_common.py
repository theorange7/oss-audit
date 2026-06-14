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


def tool_findings(result: AuditResult, category: str | None = None) -> list[Finding]:
    findings = []
    for tr in result.tool_results:
        for f in tr.findings:
            if category is None or f.category == category:
                findings.append(f)
    return findings


def all_findings(result: AuditResult) -> list[Finding]:
    return tool_findings(result)
