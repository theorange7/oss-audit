"""
models.py — the unified data model shared across scanners, rubric, and reports.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    tool: str
    severity: str          # critical / high / medium / low / info
    category: str          # vuln / secret / license / health / telemetry / static
    title: str
    detail: str
    location: Optional[str] = None


@dataclass
class ToolResult:
    tool: str
    available: bool
    ran: bool
    findings: list[Finding] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""
    duration_s: float = 0.0


@dataclass
class RubricScore:
    category: str
    verdict: str      # PASS / WARN / FAIL
    reason: str
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


@dataclass
class AuditResult:
    repo_url: str
    repo_name: str
    profile: str
    timestamp: str
    tool_results: list[ToolResult] = field(default_factory=list)
    rubric: list[RubricScore] = field(default_factory=list)
    overall_verdict: str = "UNKNOWN"
    overall_reason: str = ""
    skipped_tools: list[str] = field(default_factory=list)
