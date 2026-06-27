# oss-audit

A CLI tool that audits open-source GitHub repositories for **security vulnerabilities, exposed secrets, license issues, privacy/telemetry risks, and project health** — before you bring them into a sensitive or confidential environment.

It orchestrates best-in-class open source scanners, runs them in parallel, normalises their output, applies a configurable rubric, and produces a unified **HTML + Markdown + JSON** report.

The CLI is available as both `oss-audit` and the short alias `ossa`.

---

## Quickstart (Docker — recommended)

```bash
# Build
docker build -t oss-audit .

# Audit a repo (reports land in ./reports/)
docker run --rm -v $(pwd)/reports:/reports \
  oss-audit scan https://github.com/org/repo \
  --output /reports/myrepo \
  --profile privacy
```

Open `./reports/myrepo.html` in your browser for the visual report.

---

## Local install

```bash
# With uv (recommended) — installs the CLI into the project venv
uv sync
uv run ossa scan https://github.com/org/repo

# Or with pip
pip install -e .
ossa scan https://github.com/org/repo
```

Missing tools are skipped and noted in the report. Install more for better coverage:

```bash
# macOS (Homebrew)
brew install syft grype gitleaks trivy osv-scanner semgrep

# Ruby tool
gem install licensee
```

Check what's installed:

```bash
ossa scan --check-tools
```

---

## Usage

`oss-audit` is a command group with two subcommands: `scan` and `reports`.

### `scan` — audit a repository

```
ossa scan [OPTIONS] REPO_URL

Arguments:
  REPO_URL    Full GitHub (or any git) repository URL

Options:
  -p, --profile [privacy|standard]  Rubric profile (default: privacy)
  -o, --output PATH                 Report base path, without extension.
                                    Defaults to ~/.oss-audit/reports/{repo}/{timestamp}.
                                    When set explicitly, no timestamp or
                                    latest symlink is created.
  -f, --format [all|md|html|json]   Output format(s) (default: html)
  --include-tests                   Scan test files too (excluded by default
                                    to reduce false positives)
  --check-tools                     Print tool availability and exit
  -h, --help                        Show this message and exit
```

### `reports` — browse generated reports

```
ossa reports
```

Lists every saved HTML report grouped by repo, shows the overall verdict for each,
and lets you **open one in your default browser** or **delete** it (deleting also
removes the matching `.md`/`.json` files and updates the `latest.*` symlinks).

### Examples

```bash
# Full audit with privacy profile (default), HTML report
ossa scan https://github.com/org/repo

# Standard profile, all three formats, custom output path
ossa scan https://github.com/org/repo \
  --profile standard \
  --format all \
  --output ./reports/myrepo

# JSON only, piped into jq
ossa scan https://github.com/org/repo --format json --output ./myrepo
jq '.meta' ./myrepo.json

# Browse and open past reports
ossa reports
```

---

## Where reports go

By default, reports are written to a per-repo, timestamped path under your home directory:

```
~/.oss-audit/reports/
  myrepo/
    20260614-143201.html
    latest.html  ->  20260614-143201.html   # symlink, updated each run
    20260614-155042.html                     # later run, nothing overwritten
```

Re-running never overwrites a previous report. The `latest.*` symlinks always point
at the most recent run for that repo. The first time `~/.oss-audit/` would be created,
the CLI asks for confirmation; pass `--output <path>` to write somewhere explicit
instead (an explicit path skips the timestamp and symlinks).

---

## What it checks

| Category | Tools | What it looks for |
|---|---|---|
| **Vulnerabilities** | grype, trivy, osv-scanner | CVEs in dependencies (direct & transitive) |
| **Secrets / Credentials** | gitleaks, trivy | Leaked API keys, tokens, passwords in code & git history |
| **License** | licensee (or fallback grep) | Copyleft licenses (GPL, AGPL) that may restrict use |
| **Project Health** | OpenSSF Scorecard | Maintainer activity, branch protection, MFA, update cadence |
| **Telemetry / Privacy** | Custom grep scanner | Analytics SDKs, phone-home patterns, PII field references |
| **Static Analysis** | semgrep (`p/security-audit`) | Security antipatterns in source code |

### Test files

Test files are **excluded by default** from the file-aware scanners (semgrep, trivy,
and the telemetry grep) to reduce false positives — code under `test/`, `tests/`,
`spec/`, `__tests__/`, `fixtures/`, etc., and files like `*_test.go`, `*.spec.ts`,
`test_*.py`, `conftest.py` does not run in production. Pass `--include-tests` to scan
them anyway. (gitleaks still scans the full git history regardless, since secrets
committed in test files are real leaks.)

### OpenSSF Scorecard authentication

Scorecard calls the GitHub API and needs a token. oss-audit looks for one in this order:

1. `GITHUB_AUTH_TOKEN`
2. `GITHUB_TOKEN`
3. `gh auth token` (your local GitHub CLI session, if you're signed in)

If none is found, the Scorecard check is reported as skipped with an explanation.

---

## Profiles

| Setting | `standard` | `privacy` |
|---|---|---|
| Fail on critical CVE | 1+ | 1+ |
| Fail on high CVEs | 5+ | **1+** |
| Fail on high static findings | 10+ | **5+** |
| Fail on high health findings | 3+ | **2+** |
| Telemetry findings | Warn only — never fails | Warn only — never fails |

**Telemetry is advisory.** It can raise a `WARN` but never a `FAIL`, in either profile, because the telemetry scanner is a heuristic grep prone to false positives. The `privacy` profile tightens vulnerability, static-analysis, and health thresholds but leaves telemetry warn-only — see [ADR-0001](docs/adr/0001-telemetry-is-advisory.md). A CI gate keyed on the FAIL exit code will not block on telemetry alone.

Use `--profile privacy` (the default) for anything involving personal data, confidential information, or mixed tech-literacy environments where risks need to be surfaced aggressively.

---

## Output formats

**HTML** (default) — visual dark-theme report with verdict banner, per-category tables, and full findings list. Best for sharing with non-technical stakeholders.

**Markdown** — suitable for pasting into Confluence, Notion, GitHub Issues, or a PR description.

**JSON** — machine-readable, structured output for piping into dashboards, CI gates, or your own tooling.

Pass `--format all` to write all three. The process exit code is `0` for PASS/WARN, `1` for FAIL.

---

## CI/CD integration

```yaml
# GitHub Actions example
- name: OSS Audit
  run: |
    docker run --rm -v ${{ github.workspace }}/reports:/reports \
      oss-audit scan ${{ env.TARGET_REPO }} \
      --output /reports/audit \
      --format json
  continue-on-error: false   # non-zero exit on FAIL blocks the pipeline
```

---

## Architecture

After cloning the repo once, all scanners run **concurrently** in a thread pool
(grype waits only for syft's SBOM; Scorecard runs against the URL alongside the clone).
Wall-clock time is roughly the single slowest tool rather than the sum of all of them.

```
ossa scan <url>
    │
    ├── Clone repo (git, depth=50)
    │
    ├── syft          → SBOM (.json)
    ├── grype         → CVE scan (uses SBOM)
    ├── trivy         → CVE + secret scan
    ├── gitleaks      → Secret scan (full git history)
    ├── semgrep       → Static analysis (p/security-audit)
    ├── osv-scanner   → Dep vuln scan (OSV database)
    ├── scorecard     → OpenSSF project health (API call)
    ├── licensee      → License detection
    └── telemetry-grep → Privacy/telemetry pattern scan
           │
    Normalise → unified Finding[] with severity + category
           │
    Rubric engine → PASS / WARN / FAIL per category
           │
    Render → .html (+ .md + .json with --format all)
```

### Module layout

- `oss_audit/runner.py` — scanner orchestration, normalisation, rubric engine, data model
- `oss_audit/report.py` — renders an `AuditResult` to HTML / Markdown / JSON
- `oss_audit/cli.py` — the `scan` and `reports` commands, live progress UI

---

## Extending

**Add a new scanner:** implement a `run_<tool>(repo_path, available) -> ToolResult` function in `oss_audit/scanners.py` (split the output parsing into a pure `parse_<tool>(data) -> list[Finding]` so it can be unit-tested), submit it in `audit()` in `runner.py`, and append its `ToolResult` to `result.tool_results`. Ensure its findings use the standard `category` values (`vuln`, `secret`, `license`, `health`, `telemetry`, `static`) and a severity from `SEVERITY_LEVELS` (`oss_audit/severity.py`).

**Customise the rubric:** edit the `RUBRIC_THRESHOLDS` dict in `oss_audit/rubric.py`, or add a new profile key.

---

## Development & testing

```bash
uv sync                       # installs the package + dev dependencies (pytest)

uv run pytest                 # fast unit tests (scanners not required)
uv run pytest -m e2e          # end-to-end: clones a real repo and runs installed tools
uv run pytest -m "not e2e"    # explicitly exclude the e2e test
```

The unit tests cover the pure logic — rubric, severity mapping, the scanner
output parsers (`parse_*`, fed fixture JSON), the renderers, and the CLI
helpers — and need no scanner binaries. The `e2e` test audits a small public
repository with whatever tools are installed and skips automatically when git
or network access is unavailable.

---

## Planned enhancements

- [ ] YAML-configurable rubric (override thresholds without editing source)
- [ ] `--since <date>` flag to limit git history scan depth for gitleaks
- [ ] Dependency diff mode: compare two versions of the same repo
- [ ] SARIF output format for GitHub Advanced Security integration
- [ ] Slack/Teams webhook for CI report delivery

---

## License

MIT
