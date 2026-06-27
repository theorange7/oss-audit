"""
runner.py — orchestrates all scanners and returns a unified AuditResult.

The data model, severity helpers, individual scanners, and rubric engine live in
their own modules (models / severity / scanners / rubric). They are re-exported
here so `from oss_audit.runner import ...` keeps working as the package facade.
"""

import os
import tempfile
from concurrent.futures import ThreadPoolExecutor, Future
from datetime import datetime, timezone
from typing import Optional, Callable

from .models import Finding, ScanResult, CategoryVerdict, AuditResult
from .severity import (
    SEVERITY_LEVELS, severity_rank, normalise_sev, score_to_severity,
)
from .rubric import RUBRIC_THRESHOLDS, apply_rubric
from .scanners import (
    SCANNERS, TEST_DIR_NAMES, TEST_FILE_GLOBS,
    check_scanners, run_cmd,
    run_syft, run_grype, run_trivy, run_gitleaks, run_semgrep,
    run_osv, run_scorecard, run_license_scan, run_telemetry_scan,
    parse_grype, parse_trivy, parse_semgrep, parse_osv, parse_scorecard, parse_gitleaks,
)

__all__ = [
    "Finding", "ScanResult", "CategoryVerdict", "AuditResult",
    "SEVERITY_LEVELS", "severity_rank", "normalise_sev", "score_to_severity",
    "RUBRIC_THRESHOLDS", "apply_rubric",
    "SCANNERS", "TEST_DIR_NAMES", "TEST_FILE_GLOBS", "check_scanners", "run_cmd",
    "run_syft", "run_grype", "run_trivy", "run_gitleaks", "run_semgrep",
    "run_osv", "run_scorecard", "run_license_scan", "run_telemetry_scan",
    "parse_grype", "parse_trivy", "parse_semgrep", "parse_osv", "parse_scorecard", "parse_gitleaks",
    "audit",
]


# ── main entry point ───────────────────────────────────────────────────────────

def audit(
    repo_url: str,
    profile: str = "privacy",
    on_event: Optional[Callable[[str, str], None]] = None,
    skip_tests: bool = True,
) -> AuditResult:
    """
    Run a full audit of repo_url under the given profile.

    on_event(scanner, status) is called as each scanner transitions state:
      status is one of: "started", "done", "skipped", "error"
    """
    def notify(scanner: str, status: str):
        if on_event:
            on_event(scanner, status)

    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    result = AuditResult(
        repo_url=repo_url,
        repo_name=repo_name,
        profile=profile,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    available = check_scanners()

    with tempfile.TemporaryDirectory(prefix="oss-audit-") as tmpdir:
        repo_path = os.path.join(tmpdir, repo_name)

        with ThreadPoolExecutor(max_workers=10) as pool:
            # Scorecard only needs the URL — start it immediately alongside the clone.
            sc_future: Optional[Future] = None
            if available.get("scorecard", False):
                notify("scorecard", "started")
                sc_future = pool.submit(run_scorecard, repo_url, available)
            else:
                result.skipped_scanners.append("scorecard")
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

            # Submit all clone-independent scanners in parallel.
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
                result.skipped_scanners.append("syft")
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
        result.scan_results.append(tr)
        if skip_name and not tr.available:
            result.skipped_scanners.append(skip_name)

    if sc_tr:
        result.scan_results.append(sc_tr)

    rubric, overall, reason = apply_rubric(result.scan_results, profile)
    result.rubric = rubric
    result.overall_verdict = overall
    result.overall_reason = reason

    return result
