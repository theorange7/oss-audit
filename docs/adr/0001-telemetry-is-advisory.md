# Telemetry findings are advisory — they never FAIL an audit

Telemetry detection is a heuristic grep for analytics SDKs, phone-home patterns, and PII field references, so it produces a meaningful rate of false positives. We therefore let the `telemetry` Category reach a `WARN` Verdict but never `FAIL` — in **both** the `standard` and `privacy` profiles — so a heuristic match surfaces for human review without blocking adoption. Every other Category can hard-fail; telemetry deliberately cannot.

## Consequences

The `privacy` profile is *not* uniformly the strictest: it tightens vuln/static/health thresholds but leaves telemetry warn-only, the same as `standard`. A repo with heavy telemetry signals will `WARN`, not `FAIL`, so a CI gate keyed on the FAIL exit code (`1`) will not block on telemetry alone.
