"""End-to-end test that runs a real audit against a small public repository
using whatever scanner tools are actually installed.

Marked `e2e` so it is excluded from the default run. Execute it explicitly with:

    uv run pytest -m e2e

It skips gracefully when git is missing or GitHub is unreachable, so it is safe
to leave in CI behind a network/tooling guard.
"""

import json
import socket

import pytest

from oss_audit.runner import audit, check_scanners
from oss_audit.report import to_json, to_markdown, to_html

# Tiny, stable, dependency-free repository — fast to clone.
E2E_REPO = "https://github.com/octocat/Hello-World"
E2E_REPO_NAME = "Hello-World"


def _network_available(host: str = "github.com", port: int = 443, timeout: float = 3.0) -> bool:
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


@pytest.mark.e2e
def test_e2e_real_audit_is_well_formed():
    if not check_scanners().get("git"):
        pytest.skip("git is not installed")
    if not _network_available():
        pytest.skip("no network access to github.com")

    result = audit(E2E_REPO, profile="standard")

    # A clone failure (transient network / rate limit) is an environment issue,
    # not a logic failure — skip rather than fail the suite.
    if result.overall_verdict == "ERROR":
        pytest.skip(f"clone failed: {result.overall_reason}")

    # ── structural assertions on a genuine run ──
    assert result.repo_name == E2E_REPO_NAME
    assert result.overall_verdict in {"PASS", "WARN", "FAIL"}
    assert result.scan_results, "expected at least one scan result"
    assert result.rubric, "expected rubric verdicts"
    assert result.timestamp

    # The telemetry grep needs no external binary, so it always runs.
    ran_scanners = {tr.scanner for tr in result.scan_results if tr.ran}
    assert "telemetry-grep" in ran_scanners

    # Any scanner reported as available must have actually run.
    available = check_scanners()
    for tr in result.scan_results:
        if tr.available:
            assert tr.ran, f"{tr.scanner} was available but did not run"

    # The real result must render in all three formats without error.
    data = json.loads(to_json(result))
    assert data["meta"]["repo_name"] == E2E_REPO_NAME
    assert "<!DOCTYPE html>" in to_html(result)
    assert "# OSS Audit Report" in to_markdown(result)
