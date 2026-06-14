"""Tests for the severity helpers: normalise_sev, severity_rank, score_to_severity."""

import pytest

from oss_audit.runner import normalise_sev, severity_rank, SEVERITY_LEVELS


@pytest.mark.parametrize("raw, expected", [
    ("CRITICAL", "critical"),
    ("crit", "critical"),
    ("High", "high"),
    ("moderate", "medium"),
    ("med", "medium"),
    ("warning", "medium"),
    ("warn", "medium"),
    ("low", "low"),
    ("negligible", "low"),
    ("informational", "info"),
    ("note", "info"),
    ("unknown", "info"),
    ("  HIGH  ", "high"),          # whitespace + case
    ("something-else", "info"),    # unmapped → info
])
def test_normalise_sev(raw, expected):
    assert normalise_sev(raw) == expected


def test_severity_levels_order():
    assert SEVERITY_LEVELS == ("critical", "high", "medium", "low", "info")


@pytest.mark.parametrize("sev, rank", [
    ("critical", 0),
    ("high", 1),
    ("medium", 2),
    ("low", 3),
    ("info", 4),
])
def test_severity_rank_known(sev, rank):
    assert severity_rank(sev) == rank


def test_severity_rank_unknown_sorts_last():
    assert severity_rank("bogus") == len(SEVERITY_LEVELS)
    assert severity_rank("bogus") > severity_rank("info")


def test_severity_rank_sorts_findings():
    sevs = ["low", "critical", "info", "high", "medium"]
    assert sorted(sevs, key=severity_rank) == ["critical", "high", "medium", "low", "info"]


from oss_audit.severity import score_to_severity  # noqa: E402


@pytest.mark.parametrize("score, expected", [
    (-1, "info"),    # N/A — check could not run
    (0, "high"),
    (3.9, "high"),
    (4, "medium"),
    (6.9, "medium"),
    (7, "low"),
    (8.9, "low"),
    (9, "info"),
    (10, "info"),
])
def test_score_to_severity_boundaries(score, expected):
    assert score_to_severity(score) == expected
