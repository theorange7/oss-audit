# oss-audit

The domain of auditing an open-source GitHub repository for security, secret, license, privacy/telemetry, and project-health risks before adopting it. oss-audit orchestrates external scanners, normalises their output, and applies a rubric to reach a verdict.

## Language

### The audit

**Audit**:
One end-to-end run against a single repository: clone it, run every available scanner, apply the rubric, and emit a report.

**Profile**:
A named strictness preset that selects which rubric thresholds apply (`standard`, `privacy`). `privacy` is the tighter preset for confidential or sensitive environments.

**Report**:
The artifact an audit produces, rendered as HTML, Markdown, and JSON from the same result.

### Findings

**Scanner**:
An external program oss-audit invokes during an audit (syft, grype, trivy, gitleaks, semgrep, osv-scanner, licensee, scorecard, and the git clone step). Most emit Findings; the clone step is the exception.
_Avoid_: Tool, scanner-tool, plugin

**Finding**:
A single issue surfaced by one scanner, carrying a Severity, a Category, and an optional location.
_Avoid_: Issue, result, hit, alert

**Category**:
The kind of risk a Finding represents: `vuln`, `secret`, `license`, `health`, `telemetry`, or `static`. The rubric judges each Category independently.
_Avoid_: Type, kind, class

**Severity**:
The seriousness of a Finding, ranked most-to-least severe: `critical`, `high`, `medium`, `low`, `info`. Vendor severities are normalised onto this scale.
_Avoid_: Priority, level, rank

### Rubric and outcome

**Rubric**:
The rules that turn a Profile's per-Category thresholds plus the collected Findings into Verdicts.
_Avoid_: Policy, ruleset, scoring

**Verdict**:
The judgment the rubric assigns. Per Category it is `PASS`, `WARN`, or `FAIL`. The overall Verdict is a superset that also includes `UNKNOWN` (not yet computed) and `ERROR` (the audit could not run, e.g. clone failed).
_Avoid_: Score, grade, rating, status

**Score**:
Reserved for the numeric 0–10 OpenSSF Scorecard value of a project-health check. A Score is not a Verdict; it is mapped onto a Severity before the rubric sees it.
_Avoid_: using "score" for a Verdict or rubric outcome
