#!/usr/bin/env python3
"""
oss-audit — CLI entry point
"""

import sys
import time
import threading
import json
import webbrowser
from pathlib import Path
from datetime import datetime

import click
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich import box

from .runner import audit, check_tools
from .report import to_json, to_markdown, to_html

console = Console()

# ── constants ──────────────────────────────────────────────────────────────────

DEFAULT_REPORTS_DIR = Path.home() / ".oss-audit" / "reports"

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
    "waiting":  ("dim",    "·  waiting"),
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


# ── live progress tracker ──────────────────────────────────────────────────────

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

                if st == "started":
                    t0 = self._started_at.get(tool)
                    time_str = f"{(time.monotonic() - t0):.1f}s" if t0 else "—"
                else:
                    elapsed = self._elapsed.get(tool)
                    time_str = f"{elapsed:.1f}s" if elapsed else "—"

                findings = self._findings.get(tool)
                t.add_row(
                    TOOL_LABEL.get(tool, tool),
                    Text(label, style=sty),
                    time_str,
                    str(findings) if findings is not None else "—",
                )
        return t


# ── CLI group ──────────────────────────────────────────────────────────────────

CONTEXT = dict(help_option_names=["-h", "--help"])

@click.group(context_settings=CONTEXT)
@click.version_option("0.1.0", prog_name="oss-audit")
def cli():
    """Audit open-source repositories for security, privacy, and licensing issues."""


# ── scan subcommand ────────────────────────────────────────────────────────────

@cli.command("scan", context_settings=CONTEXT)
@click.argument("repo_url")
@click.option(
    "--profile", "-p",
    type=click.Choice(["privacy", "standard"], case_sensitive=False),
    default="privacy", show_default=True,
    help="Rubric profile. 'privacy' applies tighter thresholds.",
)
@click.option(
    "--output", "-o",
    default=None,
    help=(
        "Output base path (no extension). "
        "Defaults to ~/.oss-audit/reports/{repo}/{timestamp}. "
        "When set explicitly, no timestamp or latest symlink is created."
    ),
)
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["all", "md", "html", "json"], case_sensitive=False),
    default="html", show_default=True,
    help="Output format(s). 'all' writes HTML + MD + JSON.",
)
@click.option(
    "--check-tools", "do_check_tools",
    is_flag=True, default=False,
    help="Print tool availability and exit.",
)
@click.option(
    "--include-tests",
    is_flag=True, default=False,
    help="Include test files in semgrep, trivy, and telemetry scans.",
)
def scan(repo_url, profile, output, fmt, do_check_tools, include_tests):
    """
    Audit a GitHub repository.

    \b
    Examples:
      oss-audit scan https://github.com/org/repo
      oss-audit scan https://github.com/org/repo --profile standard
      oss-audit scan https://github.com/org/repo --format all
    """
    if do_check_tools:
        _print_tool_check()
        return

    # First-run notice before creating ~/.oss-audit/.
    if output is None and _default_reports_dir_is_new():
        console.print()
        console.print(
            f"[bold yellow]Notice:[/] Reports will be saved to [cyan]{DEFAULT_REPORTS_DIR}[/] by default."
        )
        console.print("  Use [bold]--output <path>[/] to write reports elsewhere.")
        console.print()
        if not click.confirm("  Continue?", default=True):
            console.print("\n  Aborted. Re-run with [bold]--output ./my-report[/] to set a custom path.\n")
            sys.exit(0)

    console.print()
    console.print(f"[bold]oss-audit[/]  profile: [cyan]{profile}[/]  {repo_url}")
    if not include_tests:
        console.print("  [dim]Test files excluded (--include-tests to override).[/]")
    console.print()

    tracker = ProgressTracker()

    with Live(tracker.render(), console=console, refresh_per_second=8,
              vertical_overflow="visible") as live:

        done_event = threading.Event()

        def refresh_loop():
            while not done_event.is_set():
                live.update(tracker.render())
                time.sleep(0.125)

        refresh_thread = threading.Thread(target=refresh_loop, daemon=True)
        refresh_thread.start()

        result = audit(
            repo_url=repo_url, profile=profile,
            on_event=tracker.update,
            skip_tests=not include_tests,
        )

        _tool_key = {"telemetry-grep": "telemetry"}
        for tr in result.tool_results:
            tracker.set_findings(_tool_key.get(tr.tool, tr.tool), len(tr.findings))

        done_event.set()
        refresh_thread.join()
        live.update(tracker.render())

    console.print()
    _print_summary(result, tracker.wall_elapsed())
    console.print()

    out_base, use_latest = _resolve_output(output, result.repo_name, result.timestamp)
    out_base.parent.mkdir(parents=True, exist_ok=True)
    written = []

    for ext, (enabled, renderer) in {
        "html": (fmt in ("all", "html"), to_html),
        "md":   (fmt in ("all", "md"),   to_markdown),
        "json": (fmt in ("all", "json"), to_json),
    }.items():
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
        console.print(f"\n  [dim]Latest:[/] [cyan]{out_base.parent}/latest.html[/]")
    console.print()

    sys.exit(0 if result.overall_verdict in ("PASS", "WARN") else 1)


# ── reports subcommand ─────────────────────────────────────────────────────────

@cli.command("reports", context_settings=CONTEXT)
def reports():
    """
    Browse, open, or delete generated HTML reports.

    \b
    Examples:
      oss-audit reports
    """
    if not DEFAULT_REPORTS_DIR.exists():
        console.print(f"\n[dim]No reports found. Run [bold]oss-audit scan <url>[/] first.[/]\n")
        return

    # Collect all timestamped HTML files (exclude latest.* symlinks).
    entries: list[tuple[str, Path]] = []
    for repo_dir in sorted(DEFAULT_REPORTS_DIR.iterdir()):
        if not repo_dir.is_dir():
            continue
        for html in sorted(repo_dir.glob("*.html"), reverse=True):
            if html.is_symlink():
                continue
            entries.append((repo_dir.name, html))

    if not entries:
        console.print(f"\n[dim]No reports found in {DEFAULT_REPORTS_DIR}[/]\n")
        return

    # Display report list.
    console.print()
    t = Table(box=box.SIMPLE, show_header=True, header_style="dim", expand=False,
              padding=(0, 1))
    t.add_column("#",         justify="right", style="dim", min_width=3)
    t.add_column("Repo",      style="bold",    min_width=20)
    t.add_column("Timestamp",                  min_width=18)
    t.add_column("Verdict",                    min_width=8)

    for i, (repo, html) in enumerate(entries, 1):
        verdict, vstyle = _read_verdict(html)
        t.add_row(str(i), repo, _format_ts(html.stem), Text(verdict, style=vstyle))

    console.print(t)

    # Select a report.
    try:
        idx = click.prompt(
            "Select report",
            type=click.IntRange(1, len(entries)),
            prompt_suffix=" [1-{}]: ".format(len(entries)),
        )
    except click.Abort:
        console.print()
        return

    repo, html = entries[idx - 1]
    console.print(
        f"\n  [bold]{repo}[/]  [dim]{_format_ts(html.stem)}[/]\n"
        f"  [o] Open in browser\n"
        f"  [d] Delete\n"
        f"  [q] Cancel\n"
    )

    try:
        action = click.prompt("Action", type=click.Choice(["o", "d", "q"]),
                              default="o", show_choices=False)
    except click.Abort:
        console.print()
        return

    if action == "o":
        webbrowser.open(html.as_uri())
        console.print(f"\n  [green]Opened[/] [cyan]{html}[/]\n")

    elif action == "d":
        _delete_report(html)

    # q: fall through silently


# ── output helpers ─────────────────────────────────────────────────────────────

def _resolve_output(explicit: str | None, repo_name: str, iso_timestamp: str) -> tuple[Path, bool]:
    if explicit:
        return Path(explicit), False
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        ts = dt.strftime("%Y%m%d-%H%M%S")
    except Exception:
        ts = iso_timestamp[:19].replace(":", "").replace("T", "-")
    return DEFAULT_REPORTS_DIR / repo_name / ts, True


def _update_symlink(target: Path, ext: str):
    link = target.parent / f"latest.{ext}"
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(target.name)


def _default_reports_dir_is_new() -> bool:
    return not DEFAULT_REPORTS_DIR.exists()


def _format_ts(stem: str) -> str:
    """Convert '20260614-143201' → '2026-06-14  14:32:01'."""
    try:
        dt = datetime.strptime(stem, "%Y%m%d-%H%M%S")
        return dt.strftime("%Y-%m-%d  %H:%M:%S")
    except ValueError:
        return stem


def _read_verdict(html: Path) -> tuple[str, str]:
    """Read overall verdict from JSON sidecar; fall back to '?' if absent."""
    sidecar = html.with_suffix(".json")
    try:
        data = json.loads(sidecar.read_text(encoding="utf-8"))
        v = data.get("meta", {}).get("overall_verdict", "?")
        return v, VERDICT_STYLE.get(v, "dim")
    except Exception:
        return "?", "dim"


def _delete_report(html: Path):
    repo_dir = html.parent
    stem = html.stem
    deleted = []

    for ext in ("html", "md", "json"):
        f = html.with_suffix(f".{ext}")
        if f.exists():
            f.unlink()
            deleted.append(f.name)

        # Remove latest symlink if it pointed at this file.
        link = repo_dir / f"latest.{ext}"
        if link.is_symlink() and link.resolve().stem == stem:
            link.unlink()
            # Point latest at the next most recent file if one exists.
            remaining = sorted(
                [p for p in repo_dir.glob(f"*.{ext}") if not p.is_symlink()],
                reverse=True,
            )
            if remaining:
                _update_symlink(remaining[0], ext)

    console.print(f"\n  [red]Deleted:[/] {', '.join(deleted)}\n")

    # Remove the repo directory if now empty (ignoring latest.* symlinks).
    real_files = [p for p in repo_dir.iterdir() if not p.is_symlink()]
    if not real_files:
        for link in repo_dir.iterdir():
            link.unlink()
        repo_dir.rmdir()
        console.print(f"  [dim]Removed empty directory {repo_dir}[/]\n")


# ── scan summary ───────────────────────────────────────────────────────────────

def _print_summary(result, wall_s: float = 0.0):
    v = result.overall_verdict
    vstyle = VERDICT_STYLE.get(v, "dim")

    console.rule(style="dim")
    console.print(f"  Overall: [{vstyle}]{v}[/]  [dim]{result.overall_reason}[/]")
    console.rule(style="dim")
    console.print()

    t = Table(box=box.SIMPLE, show_header=True, header_style="dim", expand=False,
              padding=(0, 1))
    t.add_column("Category", style="bold", min_width=26)
    t.add_column("Verdict",  min_width=8)
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
        console.print(f"  [dim]Skipped (not installed): {', '.join(result.skipped_tools)}[/]")
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
