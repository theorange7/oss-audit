"""Tests for the CLI's pure helpers: output path resolution, timestamp formatting,
verdict lookup."""

import json
from pathlib import Path

from oss_audit import cli
from oss_audit.cli import _resolve_output, _format_ts, _read_verdict, DEFAULT_REPORTS_DIR


def test_resolve_output_explicit_path_no_latest():
    out_base, use_latest = _resolve_output("/tmp/custom/report", "myrepo", "2026-06-14T14:32:01+00:00")
    assert out_base == Path("/tmp/custom/report")
    assert use_latest is False


def test_resolve_output_default_is_timestamped_under_home():
    out_base, use_latest = _resolve_output(None, "myrepo", "2026-06-14T14:32:01+00:00")
    assert out_base == DEFAULT_REPORTS_DIR / "myrepo" / "20260614-143201"
    assert use_latest is True


def test_resolve_output_bad_timestamp_falls_back():
    out_base, use_latest = _resolve_output(None, "myrepo", "not-a-timestamp")
    # Falls back to a sanitised stem rather than raising.
    assert out_base.parent == DEFAULT_REPORTS_DIR / "myrepo"
    assert use_latest is True


def test_format_ts_valid():
    assert _format_ts("20260614-143201") == "2026-06-14  14:32:01"


def test_format_ts_passthrough_on_invalid():
    assert _format_ts("latest") == "latest"


def test_read_verdict_from_sidecar(tmp_path):
    html = tmp_path / "report.html"
    html.write_text("<html></html>", encoding="utf-8")
    (tmp_path / "report.json").write_text(
        json.dumps({"meta": {"overall_verdict": "FAIL"}}), encoding="utf-8"
    )
    verdict, style = _read_verdict(html)
    assert verdict == "FAIL"
    assert style == cli.VERDICT_STYLE["FAIL"]


def test_read_verdict_missing_sidecar(tmp_path):
    html = tmp_path / "orphan.html"
    html.write_text("<html></html>", encoding="utf-8")
    verdict, style = _read_verdict(html)
    assert verdict == "?"
    assert style == "dim"
