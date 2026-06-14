# oss-audit

A CLI tool that audits open-source GitHub repositories for **security vulnerabilities, exposed secrets, license issues, privacy/telemetry risks, and project health** — before you bring them into a sensitive or confidential environment.

Orchestrates best-in-class open source scanners, normalises their output, applies a configurable rubric, and produces a unified **Markdown + HTML + JSON** report.

---

## Quickstart (Docker — recommended)

```bash
# Build
docker build -t oss-audit .

# Audit a repo (reports land in ./reports/)
docker run --rm -v $(pwd)/reports:/reports \
  oss-audit https://github.com/org/repo \
  --output /reports/myrepo \
  --profile privacy
```

Open `./reports/myrepo.html` in your browser for the visual report.

---

## Local install (if you have some tools already)

```bash
pip install -e .
oss-audit https://github.com/org/repo
```

Missing tools are skipped silently and noted in the report. Install more for better coverage:

```bash
# macOS (Homebrew)
brew install syft grype gitleaks trivy osv-scanner semgrep

# Ruby tool
gem install licensee
```

---

## Usage

```
oss-audit [OPTIONS] REPO_URL

Arguments:
  REPO_URL    Full GitHub (or any git) repository URL

Options:
  -p, --profile [privacy|standard]  Rubric profile (default: privacy)
  -o, --output PATH                 Report output path, without extension
                                    (default: ./oss-audit-report)
  -f, --format [all|md|html|json]   Output format(s) (default: all)
  --check-tools                     Print tool availability and exit
  -h, --help                        Show this message and exit
  --version                         Show version and exit
```

### Examples

```bash
# Full audit with privacy profile (default)
oss-audit https://github.com/org/repo

# Standard profile, HTML only, custom output path
oss-audit https://github.com/org/repo \
  --profile standard \
  --format html \
  --output ./reports/myrepo

# Check which tools are installed
oss-audit --check-tools

# JSON only (for piping into other tools / dashboards)
oss-audit https://github.com/org/repo --format json | jq '.meta'
```

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

---

## Profiles

| Setting | `standard` | `privacy` |
|---|---|---|
| Fail on critical CVE | 1+ | 1+ |
| Fail on high CVEs | 5+ | **1+** |
| Fail on telemetry high findings | 3+ | **1+** |
| Fail on static high findings | 10+ | **5+** |

Use `--profile privacy` (the default) for anything involving personal data, confidential information, or mixed tech-literacy environments where telemetry risks need to be surfaced aggressively.

---

## Output formats

**HTML** — visual dark-theme report with verdict banner, per-category tables, and full findings list. Best for sharing with non-technical stakeholders.

**Markdown** — suitable for pasting into Confluence, Notion, GitHub Issues, or a PR description.

**JSON** — machine-readable, structured output for piping into dashboards, CI gates, or your own tooling. Exit code is `0` for PASS/WARN, `1` for FAIL.

---

## CI/CD integration

```yaml
# GitHub Actions example
- name: OSS Audit
  run: |
    docker run --rm -v ${{ github.workspace }}/reports:/reports \
      oss-audit ${{ env.TARGET_REPO }} \
      --output /reports/audit \
      --format json
  continue-on-error: false   # non-zero exit on FAIL blocks the pipeline
```

---

## Architecture

```
oss-audit <url>
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
    Render → .md + .html + .json
```

---

## Extending

**Add a new scanner:** implement a `run_<tool>(repo_path, available) -> ToolResult` function in `oss_audit/runner.py`, append its output to `result.tool_results`, and ensure its findings use the standard `category` values (`vuln`, `secret`, `license`, `health`, `telemetry`, `static`).

**Customise the rubric:** edit the `RUBRIC_THRESHOLDS` dict in `runner.py`, or add a new profile key.

---

## Planned enhancements

- [ ] YAML-configurable rubric (override thresholds without editing source)
- [ ] `--since <date>` flag to limit git history scan depth for gitleaks
- [ ] Dependency diff mode: compare two versions of the same repo
- [ ] SARIF output format for GitHub Advanced Security integration
- [ ] Slack/Teams webhook for CI report delivery
- [ ] OpenSSF Scorecard via API (no local install required)

---

## License

MIT
