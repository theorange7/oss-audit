"""
severity.py — canonical severity ordering and the mappings every other module
uses to sort, bucket, and normalise severities.
"""

# Canonical severity ordering, most → least severe. Shared across the codebase so
# everything sorts and buckets severities the same way.
SEVERITY_LEVELS: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


def severity_rank(sev: str) -> int:
    """Sort key for a severity: 0 = most severe. Unknown values sort last."""
    try:
        return SEVERITY_LEVELS.index(sev)
    except ValueError:
        return len(SEVERITY_LEVELS)


def score_to_severity(score: float) -> str:
    """Map a 0–10 OpenSSF Scorecard score to a severity bucket.

    A negative score means the check could not run (N/A) and maps to info.
    """
    if score < 0:
        return "info"    # N/A — check could not run
    if score < 4:
        return "high"
    if score < 7:
        return "medium"
    if score < 9:
        return "low"
    return "info"        # passing


def normalise_sev(s: str) -> str:
    """Map a vendor severity string onto one of SEVERITY_LEVELS."""
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
