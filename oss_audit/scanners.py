"""
scanners.py — tool availability, the subprocess helper, and one run_<tool>
function per scanner. Each returns a ScanResult with normalised Findings.
"""

import subprocess
import shutil
import json
import re
import os
import time
import fnmatch
from typing import Optional

from .models import Finding, ScanResult
from .severity import normalise_sev, score_to_severity


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


# ── tool availability ──────────────────────────────────────────────────────────

SCANNERS = {
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

def check_scanners() -> dict[str, bool]:
    return {name: shutil.which(cmd) is not None for name, cmd in SCANNERS.items()}


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


# ── individual scanners ────────────────────────────────────────────────────────

def run_syft(repo_path: str, available: dict) -> tuple[ScanResult, Optional[str]]:
    """Generate SBOM with syft. Returns (ScanResult, sbom_path|None)."""
    tr = ScanResult(scanner="syft", available=available.get("syft", False), ran=False)
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
                scanner="syft", severity="info", category="vuln",
                title=f"SBOM generated: {pkg_count} packages",
                detail=f"Software Bill of Materials created at {sbom_path}"
            ))
        except Exception:
            pass
    return tr, sbom_path if (sbom_path and os.path.exists(sbom_path)) else None


def parse_grype(data: dict) -> list[Finding]:
    findings = []
    for m in data.get("matches", []):
        vuln = m.get("vulnerability", {})
        pkg = m.get("artifact", {})
        sev = normalise_sev(vuln.get("severity", "info"))
        findings.append(Finding(
            scanner="grype",
            severity=sev,
            category="vuln",
            title=f"{vuln.get('id','?')} in {pkg.get('name','?')} {pkg.get('version','?')}",
            detail=vuln.get("description", "")[:300],
            location=pkg.get("locations", [{}])[0].get("realPath", "") if pkg.get("locations") else "",
        ))
    return findings


def run_grype(repo_path: str, available: dict, sbom_path: Optional[str]) -> ScanResult:
    tr = ScanResult(scanner="grype", available=available.get("grype", False), ran=False)
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
    except json.JSONDecodeError:
        tr.error = "Could not parse grype JSON output"
        return tr
    tr.findings.extend(parse_grype(data))
    return tr


def parse_trivy(data: dict) -> list[Finding]:
    findings = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []) or []:
            sev = normalise_sev(v.get("Severity", "info"))
            findings.append(Finding(
                scanner="trivy",
                severity=sev,
                category="vuln",
                title=f"{v.get('VulnerabilityID','?')} in {v.get('PkgName','?')} {v.get('InstalledVersion','?')}",
                detail=v.get("Description", "")[:300],
                location=result.get("Target", ""),
            ))
        for s in result.get("Secrets", []) or []:
            findings.append(Finding(
                scanner="trivy",
                severity="high",
                category="secret",
                title=f"Secret: {s.get('Title','?')}",
                detail=s.get("Match", "")[:200],
                location=result.get("Target", ""),
            ))
    return findings


def run_trivy(repo_path: str, available: dict, skip_tests: bool = True) -> ScanResult:
    """Trivy as fallback / complement to grype+syft."""
    tr = ScanResult(scanner="trivy", available=available.get("trivy", False), ran=False)
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
    except json.JSONDecodeError:
        tr.error = "Could not parse trivy JSON output"
        return tr
    tr.findings.extend(parse_trivy(data))
    return tr


def parse_gitleaks(leaks: list) -> list[Finding]:
    findings = []
    for leak in leaks or []:
        findings.append(Finding(
            scanner="gitleaks",
            severity="high",
            category="secret",
            title=f"Secret detected: {leak.get('Description', leak.get('RuleID','?'))}",
            detail=f"Commit: {leak.get('Commit','?')[:8]} | Author: {leak.get('Author','?')}",
            location=f"{leak.get('File','?')}:{leak.get('StartLine','?')}",
        ))
    return findings


def run_gitleaks(repo_path: str, available: dict) -> ScanResult:
    tr = ScanResult(scanner="gitleaks", available=available.get("gitleaks", False), ran=False)
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
            tr.findings.extend(parse_gitleaks(leaks))
    except Exception as e:
        tr.error = str(e)[:300]
    return tr


def parse_semgrep(data: dict) -> list[Finding]:
    findings = []
    for r in data.get("results", []):
        sev = normalise_sev(r.get("extra", {}).get("severity", "info"))
        findings.append(Finding(
            scanner="semgrep",
            severity=sev,
            category="static",
            title=r.get("check_id", "?").split(".")[-1],
            detail=r.get("extra", {}).get("message", "")[:300],
            location=f"{r.get('path','?')}:{r.get('start',{}).get('line','?')}",
        ))
    return findings


def run_semgrep(repo_path: str, available: dict, skip_tests: bool = True) -> ScanResult:
    tr = ScanResult(scanner="semgrep", available=available.get("semgrep", False), ran=False)
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
    except json.JSONDecodeError:
        tr.error = "Could not parse semgrep JSON output"
        return tr
    tr.findings.extend(parse_semgrep(data))
    return tr


def parse_osv(data: dict) -> list[Finding]:
    findings = []
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
                findings.append(Finding(
                    scanner="osv-scanner",
                    severity=sev,
                    category="vuln",
                    title=f"{vuln.get('id','?')} in {pkg.get('package',{}).get('name','?')}",
                    detail=vuln.get("summary", "")[:300],
                ))
    return findings


def run_osv(repo_path: str, available: dict) -> ScanResult:
    tr = ScanResult(scanner="osv-scanner", available=available.get("osv-scanner", False), ran=False)
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
    except json.JSONDecodeError:
        tr.error = "Could not parse osv-scanner JSON output"
        return tr
    tr.findings.extend(parse_osv(data))
    return tr


def parse_scorecard(data: dict) -> list[Finding]:
    findings = []

    # ── aggregate score ────────────────────────────────────────────────────────
    aggregate = data.get("score", -1)
    commit = data.get("repo", {}).get("commit", "")[:8]
    checks = data.get("checks", [])

    if aggregate >= 0:
        findings.append(Finding(
            scanner="scorecard",
            severity=score_to_severity(aggregate),
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
        sev   = score_to_severity(score)

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
        findings.append(Finding(
            scanner="scorecard",
            severity=sev,
            category="health",
            title=f"{name}: {score_str}",
            detail=detail[:400],
        ))

    return findings


def run_scorecard(repo_url: str, available: dict) -> ScanResult:
    tr = ScanResult(scanner="scorecard", available=available.get("scorecard", False), ran=False)
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
    tr.findings.extend(parse_scorecard(data))
    return tr


def run_license_scan(repo_path: str, available: dict) -> ScanResult:
    """Use licensee if available, otherwise grep for LICENSE files."""
    tr = ScanResult(scanner="licensee", available=available.get("licensee", False), ran=False)
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
                    scanner="licensee",
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
                    scanner="licensee",
                    severity=sev,
                    category="license",
                    title=f"License: {label}",
                    detail=f"Found in {fname}",
                ))
                break
        else:
            tr.findings.append(Finding(
                scanner="licensee",
                severity="medium",
                category="license",
                title="No LICENSE file found",
                detail="Could not determine license. Manual review required.",
            ))
    return tr


def run_telemetry_scan(repo_path: str, skip_tests: bool = True) -> ScanResult:
    """Grep-based scan for telemetry/analytics calls and PII patterns."""
    tr = ScanResult(scanner="telemetry-grep", available=True, ran=True)

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
                                    scanner="telemetry-grep",
                                    severity=sev,
                                    category="telemetry",
                                    title=label,
                                    detail=line.strip()[:200],
                                    location=f"{rel_path}:{lineno}",
                                ))
            except Exception:
                pass
    return tr
