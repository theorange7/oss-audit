"""JSON renderer — machine-readable structured output."""

import json

from ..models import AuditResult, Finding, CategoryVerdict
from ._common import all_findings


def to_json(result: AuditResult) -> str:
    def finding_dict(f: Finding):
        return {"scanner": f.scanner, "severity": f.severity, "category": f.category,
                "title": f.title, "detail": f.detail, "location": f.location}

    def rubric_dict(r: CategoryVerdict):
        return {"category": r.category, "verdict": r.verdict, "reason": r.reason,
                "counts": {"critical": r.critical_count, "high": r.high_count,
                           "medium": r.medium_count, "low": r.low_count}}

    data = {
        "meta": {
            "repo_url": result.repo_url,
            "repo_name": result.repo_name,
            "profile": result.profile,
            "timestamp": result.timestamp,
            "overall_verdict": result.overall_verdict,
            "overall_reason": result.overall_reason,
        },
        "skipped_scanners": result.skipped_scanners,
        "rubric": [rubric_dict(r) for r in result.rubric],
        "findings": [finding_dict(f) for f in all_findings(result)],
        "scanner_summary": [
            {"scanner": tr.scanner, "available": tr.available, "ran": tr.ran,
             "duration_s": round(tr.duration_s, 2), "finding_count": len(tr.findings),
             "error": tr.error}
            for tr in result.scan_results
        ],
    }
    return json.dumps(data, indent=2)
