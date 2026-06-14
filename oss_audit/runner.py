"""
runner.py — orchestrates all scanning tools, normalises output,
applies rubric, returns a unified AuditResult.
"""

import subprocess
import shutil
import json
import re
import tempfile
import os
import time
import fnmatch
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from dataclasses import dataclass, field
from typing import Optional, Callable


# ── test-file exclusion patterns ──────────────────────────────────────────────

TEST_DIR_NAMES: frozenset[str] = frozenset({
    "test", "tests", "spec", "specs", "__tests__",
    "e2e", "fixtures", "mocks", "testdata",
})

TEST_FILE_GLOBS: tuple[str, ...] = (
    "test_*",       # Python: test_auth.py
    "*_test.*",     # Go:     auth_test.go
    "*.test.*",     # JS/TS:  auth.test.js
    "*.spec.*",     # JS/TS:  auth.spec.ts
    "conftest.py",
)
from pathlib import Path


# ── data model ────────────────────────────────────────────────────────────────

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


# ── tool availability ──────────────────────────────────────────────────────────

TOOLS = {
    "git":        "git",
    "syft":       "syft",
    "grype":      "grype",
    "gitleaks":   "gitleaks",
    "semgrep":    "semgrep",
    "osv-scanner":"osv-scanner",
    "scorecard":  "scorecard",
    "licensee":   "licensee",
    "trivy":      "trivy",
}

def check_tools() -> dict[str, bool]:
    return {name: shutil.which(cmd) is not None for name, cmd in TOOLS.items()}


# ── helpers ────────────────────────────────────────────────────────────────────

def run_cmd(cmd: list[str], cwd: str = None, timeout: int = 300, extra_env: dict = None) -> tuple[int, str, str]:
    """Run a command; return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
            env=extra_env,
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timed out"
    except Exception as e:
        return -1, "", str(e)


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def normalise_sev(s: str) -> str:
    s = s.lower().strip()
    mapping = {
        "critical": "critical", "crit": "critical",
        "high": "high",
        "medium": "medium", "moderate": "medium", "med": "medium",
        "low": "low",
        "info": "info", "informational": "info", "note": "info",
        "warning": "medium", "warn": "medium",
        "negligible": "low", "unknown": "info",
    }
    return mapping.get(s, "info")


# ── individual scanners ────────────────────────────────────────────────────────

def run_syft(repo_path: str, available: dict) -> tuple[ToolResult, Optional[str]]:
    """Generate SBOM with syft. Returns (ToolResult, sbom_path|None)."""
    tr = ToolResult(tool="syft", available=available.get("syft", False), ran=False)
    sbom_path = None
    if not tr.available:
        return tr, sbom_path
    sbom_path = os.path.join(repo_path, "_sbom.json")
    t0 = time.time()
    rc, out, err = run_cmd(
        ["syft", "dir:.", "-o", f"json={sbom_path}"],
        cwd=repo_path,
    )
    tr.duration_s = time.time() - t0
    tr.ran = True
    tr.raw_output = out[:4000]
    if rc != 0:
        tr.error = err[:500]
        sbom_path = None
    else:
        # Count packages as info finding
        try:
            with open(sbom_path) as f:
                sbom = json.load(f)
            pkg_count = len(sbom.get("artifacts", []))
            tr.findings.append(Finding(
                tool="syft", severity="info", category="vuln",
                title=f"SBOM generated: {pkg_count} packages",
                detail=f"Software Bill of Materials created at {sbom_path}"
            ))
        except Exception:
            pass
    return tr, sbom_path if (sbom_path and os.path.exists(sbom_path)) else None


def run_grype(repo_path: str, available: dict, sbom_path: Optional[str]) -> ToolResult:
    tr = ToolResult(tool="grype", available=available.get("grype", False), ran=False)
    if not tr.available:
        return tr

    # prefer SBOM if available, fall back to directory
    target = f"sbom:{sbom_path}" if sbom_path else f"dir:{repo_path}"
    t0 = time.time()
    rc, out, err = run_cmd(["grype", target, "-o", "json"], cwd=repo_path)
    tr.duration_s = time.time() - t0
    tr.ran = True
    tr.raw_output = out[:8000]

    try:
        data = json.loads(out)
        for m in data.get("matches", []):
            vuln = m.get("vulnerability", {})
            pkg = m.get("artifact", {})
            sev = normalise_sev(vuln.get("severity", "info"))
            tr.findings.append(Finding(
                tool="grype",
                severity=sev,
                category="vuln",
                title=f"{vuln.get('id','?')} in {pkg.get('name','?')} {pkg.get('version','?')}",
                detail=vuln.get("description", "")[:300],
                location=pkg.get("locations", [{}])[0].get("realPath", "") if pkg.get("locations") else "",
            ))
    except json.JSONDecodeError:
        tr.error = "Could not parse grype JSON output"
    return tr


def run_trivy(repo_path: str, available: dict, skip_tests: bool = True) -> ToolResult:
    """Trivy as fallback / complement to grype+syft."""
    tr = ToolResult(tool="trivy", available=available.get("trivy", False), ran=False)
    if not tr.available:
        return tr
    t0 = time.time()
    cmd = ["trivy", "fs", "--format", "json", "--quiet"]
    if skip_tests:
        for d in sorted(TEST_DIR_NAMES):
            cmd += ["--skip-dirs", d]
        for g in TEST_FILE_GLOBS:
            cmd += ["--skip-files", g]
    cmd.append(".")
    rc, out, err = run_cmd(cmd, cwd=repo_path)
    tr.duration_s = time.time() - t0
    tr.ran = True
    tr.raw_output = out[:8000]

    try:
        data = json.loads(out)
        for result in data.get("Results", []):
            for v in result.get("Vulnerabilities", []) or []:
                sev = normalise_sev(v.get("Severity", "info"))
                tr.findings.append(Finding(
                    tool="trivy",
                    severity=sev,
                    category="vuln",
                    title=f"{v.get('VulnerabilityID','?')} in {v.get('PkgName','?')} {v.get('InstalledVersion','?')}",
                    detail=v.get("Description", "")[:300],
                    location=result.get("Target", ""),
                ))
            for s in result.get("Secrets", []) or []:
                tr.findings.append(Finding(
                    tool="trivy",
                    severity="high",
                    category="secret",
                    title=f"Secret: {s.get('Title','?')}",
                    detail=s.get("Match", "")[:200],
                    location=result.get("Target", ""),
                ))
    except json.JSONDecodeError:
        tr.error = "Could not parse trivy JSON output"
    return tr


def run_gitleaks(repo_path: str, available: dict) -> ToolResult:
    tr = ToolResult(tool="gitleaks", available=available.get("gitleaks", False), ran=False)
    if not tr.available:
        return tr
    report_path = os.path.join(repo_path, "_gitleaks.json")
    t0 = time.time()
    rc, out, err = run_cmd(
        ["gitleaks", "detect", "--source", ".", "--report-format", "json",
         "--report-path", report_path, "--no-banner", "--redact"],
        cwd=repo_path,
    )
    tr.duration_s = time.time() - t0
    tr.ran = True

    try:
        if os.path.exists(report_path):
            with open(report_path) as f:
                leaks = json.load(f) or []
            for leak in leaks:
                tr.findings.append(Finding(
                    tool="gitleaks",
                    severity="high",
                    category="secret",
                    title=f"Secret detected: {leak.get('Description', leak.get('RuleID','?'))}",
                    detail=f"Commit: {leak.get('Commit','?')[:8]} | Author: {leak.get('Author','?')}",
                    location=f"{leak.get('File','?')}:{leak.get('StartLine','?')}",
                ))
    except Exception as e:
        tr.error = str(e)[:300]
    return tr


def run_semgrep(repo_path: str, available: dict, skip_tests: bool = True) -> ToolResult:
    tr = ToolResult(tool="semgrep", available=available.get("semgrep", False), ran=False)
    if not tr.available:
        return tr
    t0 = time.time()
    cmd = ["semgrep", "--config", "p/security-audit", "--json", "--no-rewrite-rule-ids", "--quiet"]
    if skip_tests:
        for d in sorted(TEST_DIR_NAMES):
            cmd += ["--exclude", d]
        for g in TEST_FILE_GLOBS:
            cmd += ["--exclude", g]
    cmd.append(".")
    rc, out, err = run_cmd(cmd, cwd=repo_path, timeout=600)
    tr.duration_s = time.time() - t0
    tr.ran = True
    tr.raw_output = out[:8000]

    try:
        data = json.loads(out)
        for r in data.get("results", []):
            meta = r.get("extra", {}).get("metadata", {})
            sev = normalise_sev(r.get("extra", {}).get("severity", "info"))
            tr.findings.append(Finding(
                tool="semgrep",
                severity=sev,
                category="static",
                title=r.get("check_id", "?").split(".")[-1],
                detail=r.get("extra", {}).get("message", "")[:300],
                location=f"{r.get('path','?')}:{r.get('start',{}).get('line','?')}",
            ))
    except json.JSONDecodeError:
        tr.error = "Could not parse semgrep JSON output"
    return tr


def run_osv(repo_path: str, available: dict) -> ToolResult:
    tr = ToolResult(tool="osv-scanner", available=available.get("osv-scanner", False), ran=False)
    if not tr.available:
        return tr
    t0 = time.time()
    rc, out, err = run_cmd(
        ["osv-scanner", "--format", "json", "--recursive", "."],
        cwd=repo_path,
    )
    tr.duration_s = time.time() - t0
    tr.ran = True
    tr.raw_output = out[:8000]

    try:
        data = json.loads(out)
        for result in data.get("results", []):
            for pkg in result.get("packages", []):
                for vuln in pkg.get("vulnerabilities", []):
                    sev = "medium"
                    for sev_entry in vuln.get("severity", []):
                        # rough CVSS mapping
                        score_str = sev_entry.get("score", "")
                        try:
                            score = float(score_str)
                            if score >= 9.0: sev = "critical"
                            elif score >= 7.0: sev = "high"
                            elif score >= 4.0: sev = "medium"
                            else: sev = "low"
                        except ValueError:
                            pass
                    tr.findings.append(Finding(
                        tool="osv-scanner",
                        severity=sev,
                        category="vuln",
                        title=f"{vuln.get('id','?')} in {pkg.get('package',{}).get('name','?')}",
                        detail=vuln.get("summary", "")[:300],
                    ))
    except json.JSONDecodeError:
        tr.error = "Could not parse osv-scanner JSON output"
    return tr


def run_scorecard(repo_url: str, available: dict) -> ToolResult:
    tr = ToolResult(tool="scorecard", available=available.get("scorecard", False), ran=False)
    if not tr.available:
        return tr

    # Scorecard requires a GitHub token for API calls.
    # Resolution order: GITHUB_AUTH_TOKEN → GITHUB_TOKEN → `gh auth token`
    token = os.environ.get("GITHUB_AUTH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        _, gh_out, _ = run_cmd(["gh", "auth", "token"])
        token = gh_out.strip() or None

    if not token:
        tr.ran = False
        tr.error = (
            "No GitHub token found. Set GITHUB_AUTH_TOKEN, GITHUB_TOKEN, "
            "or authenticate via `gh auth login` to enable OpenSSF Scorecard."
        )
        return tr

    scorecard_env = {**os.environ, "GITHUB_AUTH_TOKEN": token}

    t0 = time.time()
    rc, out, err = run_cmd(
        ["scorecard", "--repo", repo_url, "--format", "json", "--show-details"],
        timeout=180,
        extra_env=scorecard_env,
    )
    tr.duration_s = time.time() - t0
    tr.ran = True
    tr.raw_output = out[:8000]

    # scorecard exits 1 when findings exist — that is normal, not an error.
    # A non-zero exit with no parseable JSON means something went wrong.
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        tr.error = (err or out)[:500] or "Could not parse scorecard JSON output"
        return tr

    # ── aggregate score ────────────────────────────────────────────────────────
    aggregate = data.get("score", -1)
    commit = data.get("repo", {}).get("commit", "")[:8]
    checks = data.get("checks", [])

    if aggregate >= 0:
        if aggregate < 4:
            agg_sev = "high"
        elif aggregate < 7:
            agg_sev = "medium"
        elif aggregate < 9:
            agg_sev = "low"
        else:
            agg_sev = "info"
        tr.findings.append(Finding(
            tool="scorecard",
            severity=agg_sev,
            category="health",
            title=f"OpenSSF Scorecard aggregate: {aggregate:.1f}/10",
            detail=(
                f"{len(checks)} checks evaluated"
                + (f" at commit {commit}" if commit else "")
            ),
        ))

    # ── per-check findings ────────────────────────────────────────────────────
    for check in checks:
        score = check.get("score", -1)
        name  = check.get("name", "?")

        if score < 0:
            sev = "info"       # N/A — check could not run
        elif score < 4:
            sev = "high"
        elif score < 7:
            sev = "medium"
        elif score < 9:
            sev = "low"
        else:
            sev = "info"       # passing

        reason  = check.get("reason", "")
        details = [d for d in (check.get("details") or []) if d][:3]
        doc_url = check.get("documentation", {}).get("url", "")

        detail_parts = [reason] if reason else []
        if details:
            detail_parts.append("; ".join(details))
        if doc_url:
            detail_parts.append(doc_url)
        detail = " — ".join(detail_parts)

        score_str = f"{score}/10" if score >= 0 else "N/A"
        tr.findings.append(Finding(
            tool="scorecard",
            severity=sev,
            category="health",
            title=f"{name}: {score_str}",
            detail=detail[:400],
        ))

    return tr


def run_license_scan(repo_path: str, available: dict) -> ToolResult:
    """Use licensee if available, otherwise grep for LICENSE files."""
    tr = ToolResult(tool="licensee", available=available.get("licensee", False), ran=False)
    tr.ran = True  # we always do something here

    if available.get("licensee", False):
        t0 = time.time()
        rc, out, err = run_cmd(
            ["licensee", "detect", "--json", "."],
            cwd=repo_path,
        )
        tr.duration_s = time.time() - t0
        try:
            data = json.loads(out)
            for lic in data.get("licenses", []):
                spdx = lic.get("spdx_id", "UNKNOWN")
                copyleft = any(x in spdx for x in ["GPL", "AGPL", "LGPL", "EUPL", "CDDL"])
                sev = "high" if copyleft else "info"
                tr.findings.append(Finding(
                    tool="licensee",
                    severity=sev,
                    category="license",
                    title=f"License: {spdx}",
                    detail="Copyleft license — may restrict use in proprietary/SaaS products." if copyleft
                           else "Permissive license.",
                ))
        except Exception:
            tr.error = "Could not parse licensee JSON"
    else:
        # Fallback: scan LICENSE files manually
        for fname in ["LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"]:
            fpath = os.path.join(repo_path, fname)
            if os.path.exists(fpath):
                with open(fpath, errors="ignore") as f:
                    content = f.read(2000)
                # Simple heuristic detection
                if re.search(r"GNU AFFERO|AGPL", content, re.I):
                    sev, label = "high", "AGPL (strong copyleft)"
                elif re.search(r"GNU GENERAL PUBLIC|GPL", content, re.I):
                    sev, label = "high", "GPL (copyleft)"
                elif re.search(r"GNU LESSER|LGPL", content, re.I):
                    sev, label = "medium", "LGPL (weak copyleft)"
                elif re.search(r"MIT License", content, re.I):
                    sev, label = "info", "MIT (permissive)"
                elif re.search(r"Apache License", content, re.I):
                    sev, label = "info", "Apache 2.0 (permissive)"
                elif re.search(r"BSD", content, re.I):
                    sev, label = "info", "BSD (permissive)"
                else:
                    sev, label = "medium", "License detected but type unclear — review manually"
                tr.findings.append(Finding(
                    tool="licensee",
                    severity=sev,
                    category="license",
                    title=f"License: {label}",
                    detail=f"Found in {fname}",
                ))
                break
        else:
            tr.findings.append(Finding(
                tool="licensee",
                severity="medium",
                category="license",
                title="No LICENSE file found",
                detail="Could not determine license. Manual review required.",
            ))
    return tr


def run_telemetry_scan(repo_path: str, skip_tests: bool = True) -> ToolResult:
    """Grep-based scan for telemetry/analytics calls and PII patterns."""
    tr = ToolResult(tool="telemetry-grep", available=True, ran=True)

    telemetry_patterns = [
        (r"(mixpanel|amplitude|segment\.com|heap\.io|fullstory|hotjar|"
         r"datadog|sentry\.io|rollbar|newrelic|elastic\.co|"
         r"analytics\.track|analytics\.identify|gtag\(|ga\(|"
         r"firebase\.analytics|posthog\.capture)", "Telemetry/analytics SDK call"),
        (r"(phone home|callhome|call_home|beacon\.send|"
         r"urllib.*telemetry|requests\.post.*telemetry)", "Possible phone-home pattern"),
        (r"(password|secret|api_key|apikey|token|credential|private_key)\s*=\s*['\"][^'\"]{6,}", "Possible hardcoded credential"),
        (r"(ssn|social.security|passport.number|credit.card|"
         r"date.of.birth|health.record|medical)", "PII field reference"),
    ]

    extensions = {".py", ".js", ".ts", ".go", ".java", ".rb", ".php",
                  ".cs", ".swift", ".kt", ".rs", ".env", ".yaml", ".yml", ".json"}

    skip_dirs = {"node_modules", "vendor", "__pycache__", "dist", "build", ".git"}
    if skip_tests:
        skip_dirs = skip_dirs | TEST_DIR_NAMES

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in skip_dirs]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in extensions:
                continue
            if skip_tests and any(fnmatch.fnmatch(fname, pat) for pat in TEST_FILE_GLOBS):
                continue
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, repo_path)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    for lineno, line in enumerate(f, 1):
                        for pattern, label in telemetry_patterns:
                            if re.search(pattern, line, re.I):
                                sev = "high" if "credential" in label.lower() else "medium"
                                tr.findings.append(Finding(
                                    tool="telemetry-grep",
                                    severity=sev,
                                    category="telemetry",
                                    title=label,
                                    detail=line.strip()[:200],
                                    location=f"{rel_path}:{lineno}",
                                ))
            except Exception:
                pass
    return tr


# ── rubric engine ──────────────────────────────────────────────────────────────

RUBRIC_THRESHOLDS = {
    "standard": {
        "vuln":      {"fail_critical": 1, "fail_high": 5,  "warn_high": 1},
        "secret":    {"fail_critical": 1, "fail_high": 1,  "warn_high": 1},
        "license":   {"fail_high": 1,     "warn_medium": 1},
        "health":    {"fail_high": 3,     "warn_high": 1},
        "telemetry": {"fail_high": 3,     "warn_medium": 1},
        "static":    {"fail_critical": 1, "fail_high": 10, "warn_high": 3},
    },
    "privacy": {
        # Tighter thresholds for privacy-sensitive / confidential contexts
        "vuln":      {"fail_critical": 1, "fail_high": 1,  "warn_high": 1},
        "secret":    {"fail_critical": 1, "fail_high": 1,  "warn_high": 1},
        "license":   {"fail_high": 1,     "warn_medium": 1},
        "health":    {"fail_high": 2,     "warn_high": 1},
        "telemetry": {"fail_high": 1,     "warn_medium": 1},
        "static":    {"fail_critical": 1, "fail_high": 5,  "warn_high": 1},
    },
}


def apply_rubric(tool_results: list[ToolResult], profile: str) -> tuple[list[RubricScore], str, str]:
    thresholds = RUBRIC_THRESHOLDS.get(profile, RUBRIC_THRESHOLDS["standard"])

    # Aggregate findings by category
    by_category: dict[str, list[Finding]] = {}
    for tr in tool_results:
        for f in tr.findings:
            by_category.setdefault(f.category, []).append(f)

    scores = []
    for cat, thresh in thresholds.items():
        findings = by_category.get(cat, [])
        counts = {s: sum(1 for f in findings if f.severity == s)
                  for s in ["critical", "high", "medium", "low", "info"]}

        verdict = "PASS"
        reason = "No significant issues detected."

        if cat == "telemetry" and not findings:
            reason = "No telemetry/analytics SDK calls or PII patterns found."
        elif cat == "license" and not findings:
            verdict = "WARN"
            reason = "No license file detected — manual review required."

        # Apply fail conditions
        if counts["critical"] >= thresh.get("fail_critical", 999):
            verdict = "FAIL"
            reason = f"{counts['critical']} critical issue(s) found."
        elif counts["high"] >= thresh.get("fail_high", 999):
            verdict = "FAIL"
            reason = f"{counts['high']} high-severity issue(s) exceed threshold ({thresh.get('fail_high')})."
        elif counts["high"] >= thresh.get("warn_high", 999) or counts["medium"] >= thresh.get("warn_medium", 999):
            if verdict != "FAIL":
                verdict = "WARN"
                reason = f"{counts['high']} high / {counts['medium']} medium issue(s) — review recommended."

        scores.append(RubricScore(
            category=cat,
            verdict=verdict,
            reason=reason,
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
        ))

    # Overall verdict: FAIL if any FAIL, WARN if any WARN, else PASS
    verdicts = [s.verdict for s in scores]
    if "FAIL" in verdicts:
        overall = "FAIL"
        overall_reason = "One or more categories failed the rubric. Review findings before deployment."
    elif "WARN" in verdicts:
        overall = "WARN"
        overall_reason = "Issues warrant manual review before use in sensitive environments."
    else:
        overall = "PASS"
        overall_reason = "No blocking issues detected under the selected profile."

    return scores, overall, overall_reason


# ── main entry point ───────────────────────────────────────────────────────────

def audit(
    repo_url: str,
    profile: str = "privacy",
    on_event: Optional[Callable[[str, str], None]] = None,
    skip_tests: bool = True,
) -> AuditResult:
    """
    Run a full audit of repo_url under the given profile.

    on_event(tool, status) is called as each tool transitions state:
      status is one of: "started", "done", "skipped", "error"
    """
    from datetime import datetime, timezone

    def notify(tool: str, status: str):
        if on_event:
            on_event(tool, status)

    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    result = AuditResult(
        repo_url=repo_url,
        repo_name=repo_name,
        profile=profile,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    available = check_tools()

    with tempfile.TemporaryDirectory(prefix="oss-audit-") as tmpdir:
        repo_path = os.path.join(tmpdir, repo_name)

        with ThreadPoolExecutor(max_workers=10) as pool:
            # Scorecard only needs the URL — start it immediately alongside the clone.
            sc_future: Optional[Future] = None
            if available.get("scorecard", False):
                notify("scorecard", "started")
                sc_future = pool.submit(run_scorecard, repo_url, available)
            else:
                result.skipped_tools.append("scorecard")
                notify("scorecard", "skipped")

            # Clone the repo.
            notify("git", "started")
            rc, out, err = run_cmd(["git", "clone", "--depth", "50", repo_url, repo_path])
            if rc != 0:
                notify("git", "error")
                result.overall_verdict = "ERROR"
                result.overall_reason = f"Failed to clone repository: {err[:300]}"
                if sc_future:
                    sc_future.cancel()
                return result
            notify("git", "done")

            # Wrap each scanner so it calls notify on entry and exit.
            def _run(name: str, fn, *args):
                notify(name, "started")
                tr = fn(*args)
                notify(name, "done")
                return tr

            def _run_syft(name: str):
                notify(name, "started")
                tr, sbom = run_syft(repo_path, available)
                notify(name, "done")
                return tr, sbom

            # Submit all clone-independent tools in parallel.
            syft_future   = pool.submit(_run_syft, "syft")
            trivy_fut     = pool.submit(_run, "trivy",      run_trivy,          repo_path, available, skip_tests)
            gitleaks_fut  = pool.submit(_run, "gitleaks",   run_gitleaks,       repo_path, available)
            semgrep_fut   = pool.submit(_run, "semgrep",    run_semgrep,        repo_path, available, skip_tests)
            osv_fut       = pool.submit(_run, "osv-scanner",run_osv,            repo_path, available)
            license_fut   = pool.submit(_run, "licensee",   run_license_scan,   repo_path, available)
            telemetry_fut = pool.submit(_run, "telemetry",  run_telemetry_scan, repo_path, skip_tests)

            # Grype can start as soon as syft finishes (uses the SBOM).
            syft_tr, sbom_path = syft_future.result()
            if not syft_tr.available:
                result.skipped_tools.append("syft")
                notify("syft", "skipped")

            notify("grype", "started")
            grype_tr = run_grype(repo_path, available, sbom_path)
            notify("grype", "done")

            # Collect the remaining parallel results.
            trivy_tr     = trivy_fut.result()
            gitleaks_tr  = gitleaks_fut.result()
            semgrep_tr   = semgrep_fut.result()
            osv_tr       = osv_fut.result()
            lic_tr       = license_fut.result()
            tel_tr       = telemetry_fut.result()

        # Collect scorecard result (may still be running during ^^ collection).
        sc_tr = sc_future.result() if sc_future else None

    # Preserve a deterministic ordering in the report.
    for tr, skip_name in [
        (syft_tr,    "syft"),
        (grype_tr,   "grype"),
        (trivy_tr,   "trivy"),
        (gitleaks_tr,"gitleaks"),
        (semgrep_tr, "semgrep"),
        (osv_tr,     "osv-scanner"),
        (lic_tr,     None),
        (tel_tr,     None),
    ]:
        result.tool_results.append(tr)
        if skip_name and not tr.available:
            result.skipped_tools.append(skip_name)

    if sc_tr:
        result.tool_results.append(sc_tr)

    rubric, overall, reason = apply_rubric(result.tool_results, profile)
    result.rubric = rubric
    result.overall_verdict = overall
    result.overall_reason = reason

    return result
