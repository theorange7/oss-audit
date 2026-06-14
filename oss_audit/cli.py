#!/usr/bin/env python3
"""
oss-audit — CLI entry point
Usage: oss-audit <github-url> [options]
"""

import sys
import time
import threading
from pathlib import Path

import click
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich import box

from .runner import audit, check_tools
from .report import to_json, to_markdown, to_html

console = Console()

# ── tool display metadata ──────────────────────────────────────────────────────

TOOL_LABEL = {
    "git":         "git clone",
    "syft":        "syft  (SBOM)",
    "grype":       "grype  (vulns)",
    "trivy":       "trivy  (vulns + secrets)",
    "gitleaks":    "gitleaks  (secrets)",
    "semgrep":     "semgrep  (static)",
    "osv-scanner": "osv-scanner  (deps)",
    "licensee":    "licensee  (license)",
    "telemetry":   "telemetry  (PII grep)",
    "scorecard":   "scorecard  (health)",
}

TOOL_ORDER = list(TOOL_LABEL.keys())

STATUS_STYLE = {
    "waiting":  ("dim", "·  waiting"),
    "started":  ("yellow", "⟳  running"),
    "done":     ("green",  "✓  done"),
    "skipped":  ("dim",    "⬜ skipped"),
    "error":    ("red",    "✗  error"),
}

VERDICT_STYLE = {
    "PASS":    "bold green",
    "WARN":    "bold yellow",
    "FAIL":    "bold red",
    "ERROR":   "bold red",
    "UNKNOWN": "dim",
}

CAT_LABELS = {
    "vuln":      "Vulnerabilities",
    "secret":    "Secrets / Credentials",
    "license":   "License",
    "health":    "Project Health",
    "telemetry": "Telemetry / Privacy",
    "static":    "Static Analysis",
}


# ── live progress ──────────────────────────────────────────────────────────────

class ProgressTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self._status: dict[str, str] = {t: "waiting" for t in TOOL_ORDER}
        self._started_at: dict[str, float] = {}
        self._elapsed: dict[str, float] = {}
        self._findings: dict[str, int] = {}
        self._wall_start = time.monotonic()

    def update(self, tool: str, status: str):
        now = time.monotonic()
        with self._lock:
            self._status[tool] = status
            if status == "started":
                self._started_at[tool] = now
            elif status in ("done", "skipped", "error"):
                t0 = self._started_at.get(tool)
                self._elapsed[tool] = (now - t0) if t0 else 0.0

    def set_findings(self, tool: str, count: int):
        with self._lock:
            self._findings[tool] = count

    def elapsed(self, tool: str) -> float:
        now = time.monotonic()
        with self._lock:
            if self._status[tool] == "started":
                t0 = self._started_at.get(tool)
                return (now - t0) if t0 else 0.0
            return self._elapsed.get(tool, 0.0)

    def wall_elapsed(self) -> float:
        return time.monotonic() - self._wall_start

    def render(self) -> Table:
        t = Table(box=box.SIMPLE, show_header=True, header_style="dim", expand=False,
                  padding=(0, 1))
        t.add_column("Tool",     style="bold", min_width=28)
        t.add_column("Status",   min_width=14)
        t.add_column("Time",     justify="right", min_width=6)
        t.add_column("Findings", justify="right", min_width=8)

        with self._lock:
            for tool in TOOL_ORDER:
                st = self._status.get(tool, "waiting")
                sty, label = STATUS_STYLE.get(st, ("dim", st))
                elapsed = self._elapsed.get(tool) if st != "started" else None

                if st == "started":
                    t0 = self._started_at.get(tool)
                    elapsed_live = (time.monotonic() - t0) if t0 else 0.0
                    time_str = f"{elapsed_live:.1f}s"
                else:
                    time_str = f"{elapsed:.1f}s" if elapsed else "—"

                findings = self._findings.get(tool)
                findings_str = str(findings) if findings is not None else "—"

                t.add_row(
                    TOOL_LABEL.get(tool, tool),
                    Text(label, style=sty),
                    time_str,
                    findings_str,
                )
        return t


# ── CLI ────────────────────────────────────────────────────────────────────────

@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.argument("repo_url", required=False, default=None)
@click.option(
    "--profile", "-p",
    type=click.Choice(["privacy", "standard"], case_sensitive=False),
    default="privacy",
    show_default=True,
    help="Rubric profile. 'privacy' applies tighter thresholds for sensitive environments.",
)
@click.option(
    "--output", "-o",
    default=None,
    help=(
        "Output base path (without extension). "
        "Defaults to ~/.oss-audit/reports/{repo}/{timestamp}. "
        "When set explicitly, no timestamp or --latest symlink is created."
    ),
)
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["all", "md", "html", "json"], case_sensitive=False),
    default="all",
    show_default=True,
    help="Output format(s). 'all' writes MD + HTML + JSON.",
)
@click.option(
    "--check-tools", "do_check_tools",
    is_flag=True,
    default=False,
    help="Print tool availability and exit.",
)
@click.option(
    "--include-tests",
    is_flag=True,
    default=False,
    help="Include test files in semgrep, trivy, and telemetry scans. Excluded by default to reduce false positives.",
)
@click.version_option("0.1.0", prog_name="oss-audit")
def cli(repo_url, profile, output, fmt, do_check_tools, include_tests):
    """
    Audit an open-source GitHub repository for security, privacy,
    and licensing issues before use in a sensitive environment.

    \b
    Examples:
      oss-audit https://github.com/org/repo
      oss-audit https://github.com/org/repo --profile standard
      oss-audit https://github.com/org/repo --output ./reports/myrepo --format html
      open ~/.oss-audit/reports/myrepo/latest.html
    """

    if do_check_tools:
        _print_tool_check()
        return

    if not repo_url:
        raise click.UsageError("REPO_URL is required unless --check-tools is passed.")

    # First-run notice: warn before creating ~/.oss-audit/ for the first time.
    if output is None and _default_reports_dir_is_new():
        console.print()
        console.print(
            f"[bold yellow]Notice:[/] Reports will be saved to "
            f"[cyan]{DEFAULT_REPORTS_DIR}[/] by default."
        )
        console.print(
            "  Use [bold]--output <path>[/] to write reports anywhere you like instead."
        )
        console.print()
        if not click.confirm("  Continue?", default=True):
            console.print("\n  Aborted. Re-run with [bold]--output ./my-report[/] to set a custom path.\n")
            sys.exit(0)

    console.print()
    console.print(f"[bold]oss-audit[/]  profile: [cyan]{profile}[/]  {repo_url}")
    if not include_tests:
        console.print("  [dim]Test files excluded from semgrep, trivy, and telemetry scans (--include-tests to override).[/]")
    console.print()

    tracker = ProgressTracker()

    def on_event(tool: str, status: str):
        tracker.update(tool, status)

    with Live(tracker.render(), console=console, refresh_per_second=8,
              vertical_overflow="visible") as live:

        def refresh_loop():
            while not done_event.is_set():
                live.update(tracker.render())
                time.sleep(0.125)

        done_event = threading.Event()
        refresh_thread = threading.Thread(target=refresh_loop, daemon=True)
        refresh_thread.start()

        result = audit(repo_url=repo_url, profile=profile, on_event=on_event,
                       skip_tests=not include_tests)

        # Populate finding counts from finished result.
        # "telemetry-grep" is the internal ToolResult name; map it to the tracker key.
        _tool_key = {"telemetry-grep": "telemetry"}
        for tr in result.tool_results:
            key = _tool_key.get(tr.tool, tr.tool)
            tracker.set_findings(key, len(tr.findings))

        done_event.set()
        refresh_thread.join()
        live.update(tracker.render())

    console.print()
    _print_summary(result, tracker.wall_elapsed())
    console.print()

    # Resolve output path and whether to create --latest symlinks.
    out_base, use_latest = _resolve_output(output, result.repo_name, result.timestamp)
    out_base.parent.mkdir(parents=True, exist_ok=True)
    written = []

    formats = {
        "json": (fmt in ("all", "json"), to_json),
        "md":   (fmt in ("all", "md"),   to_markdown),
        "html": (fmt in ("all", "html"), to_html),
    }
    for ext, (enabled, renderer) in formats.items():
        if not enabled:
            continue
        p = out_base.with_suffix(f".{ext}")
        p.write_text(renderer(result), encoding="utf-8")
        written.append(p)
        if use_latest:
            _update_symlink(p, ext)

    console.print("[dim]Reports written:[/]")
    for p in written:
        console.print(f"  [cyan]{p}[/]")
    if use_latest:
        repo_dir = out_base.parent
        console.print(f"\n  [dim]Latest:[/] [cyan]{repo_dir}/latest.html[/]")
    console.print()

    sys.exit(0 if result.overall_verdict in ("PASS", "WARN") else 1)


# ── output helpers ────────────────────────────────────────────────────────────

DEFAULT_REPORTS_DIR = Path.home() / ".oss-audit" / "reports"


def _resolve_output(
    explicit: Optional[str], repo_name: str, iso_timestamp: str
) -> tuple[Path, bool]:
    """Return (out_base, use_latest). use_latest is True only for the default location."""
    if explicit:
        return Path(explicit), False

    try:
        from datetime import datetime
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        ts = dt.strftime("%Y%m%d-%H%M%S")
    except Exception:
        ts = iso_timestamp[:19].replace(":", "").replace("T", "-")

    repo_dir = DEFAULT_REPORTS_DIR / repo_name
    return repo_dir / ts, True


def _update_symlink(target: Path, ext: str):
    """Point latest.<ext> in the same directory to target (by relative name)."""
    link = target.parent / f"latest.{ext}"
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(target.name)


def _default_reports_dir_is_new() -> bool:
    return not DEFAULT_REPORTS_DIR.exists()


# ── summary ────────────────────────────────────────────────────────────────────

def _print_summary(result, wall_s: float = 0.0):
    v = result.overall_verdict
    vstyle = VERDICT_STYLE.get(v, "dim")

    console.rule(style="dim")
    console.print(
        f"  Overall: [{vstyle}]{v}[/]  [dim]{result.overall_reason}[/]"
    )
    console.rule(style="dim")
    console.print()

    t = Table(box=box.SIMPLE, show_header=True, header_style="dim", expand=False,
              padding=(0, 1))
    t.add_column("Category",  style="bold", min_width=26)
    t.add_column("Verdict",   min_width=8)
    t.add_column("Crit",  justify="right")
    t.add_column("High",  justify="right")
    t.add_column("Med",   justify="right")
    t.add_column("Low",   justify="right")

    for r in result.rubric:
        rstyle = VERDICT_STYLE.get(r.verdict, "dim")
        t.add_row(
            CAT_LABELS.get(r.category, r.category),
            Text(r.verdict, style=rstyle),
            _sev_cell(r.critical_count, "red"),
            _sev_cell(r.high_count,     "orange3"),
            _sev_cell(r.medium_count,   "yellow"),
            str(r.low_count) if r.low_count else "[dim]0[/]",
        )

    console.print(t)

    if result.skipped_tools:
        console.print(
            f"  [dim]Skipped (not installed): {', '.join(result.skipped_tools)}[/]"
        )
        console.print()

    if wall_s:
        console.print(f"  [dim]Completed in {wall_s:.1f}s[/]")


def _sev_cell(n: int, color: str) -> str:
    return f"[bold {color}]{n}[/]" if n else "[dim]0[/]"


# ── tool check ─────────────────────────────────────────────────────────────────

def _print_tool_check():
    available = check_tools()
    console.print()
    console.print("[bold]Tool availability:[/]")
    console.print()
    for name, present in available.items():
        icon = "[green]✅[/]" if present else "[dim]❌[/]"
        console.print(f"  {icon}  {name}")
    console.print()
    missing = [n for n, p in available.items() if not p]
    if missing:
        console.print("  [dim]Missing tools will be skipped during audits.[/]")
        console.print(f"  [dim]Install via:[/] [cyan]brew install {' '.join(missing)}[/]")
        console.print("  [dim]Or use the Docker image for full coverage.[/]")
    else:
        console.print("  [green]All tools available. Full coverage enabled.[/]")
    console.print()


if __name__ == "__main__":
    cli()
