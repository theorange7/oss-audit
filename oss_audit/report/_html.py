"""HTML renderer — visual dark-theme report for sharing with stakeholders."""

from datetime import datetime

from ..models import AuditResult
from ..severity import severity_rank
from ._common import VERDICT_EMOJI, VERDICT_COLOR, SEV_COLOR, SEV_BG, CAT_LABELS, all_findings


def to_html(result: AuditResult) -> str:
    v = result.overall_verdict
    vc = VERDICT_COLOR.get(v, "#94a3b8")
    findings = all_findings(result)
    total_critical = sum(1 for f in findings if f.severity == "critical")
    total_high     = sum(1 for f in findings if f.severity == "high")
    total_medium   = sum(1 for f in findings if f.severity == "medium")
    total_low      = sum(1 for f in findings if f.severity == "low")
    total_findings = len(findings)

    # Build rubric rows
    rubric_rows = ""
    for r in result.rubric:
        rc = VERDICT_COLOR.get(r.verdict, "#94a3b8")
        rubric_rows += f"""
        <tr>
          <td class="cat-label">{CAT_LABELS.get(r.category, r.category)}</td>
          <td><span class="verdict-pill" style="background:{rc}20;color:{rc};border:1px solid {rc}40">{r.verdict}</span></td>
          <td class="num {'sev-critical' if r.critical_count else ''}">{r.critical_count}</td>
          <td class="num {'sev-high' if r.high_count else ''}">{r.high_count}</td>
          <td class="num {'sev-medium' if r.medium_count else ''}">{r.medium_count}</td>
          <td class="num">{r.low_count}</td>
          <td class="reason-text">{r.reason}</td>
        </tr>"""

    # Build findings sections
    finding_sections = ""
    for r in result.rubric:
        cat_findings = sorted(
            [f for f in findings if f.category == r.category],
            key=lambda f: severity_rank(f.severity)
        )
        if not cat_findings:
            continue
        rc = VERDICT_COLOR.get(r.verdict, "#94a3b8")
        rows = ""
        for f in cat_findings[:25]:
            sc = SEV_COLOR.get(f.severity, "#64748b")
            sb = SEV_BG.get(f.severity, "#f8fafc")
            loc = f.location or "—"
            detail_escaped = f.detail.replace("<", "&lt;").replace(">", "&gt;")
            rows += f"""
            <tr>
              <td><span class="sev-badge" style="background:{sb};color:{sc};border:1px solid {sc}40">{f.severity}</span></td>
              <td class="finding-title">{f.title}</td>
              <td class="finding-detail">{detail_escaped}</td>
              <td class="finding-loc"><code>{loc}</code></td>
            </tr>"""
        overflow = f'<p class="overflow-note">…and {len(cat_findings)-25} more findings. See JSON output for complete list.</p>' if len(cat_findings) > 25 else ""

        finding_sections += f"""
        <section class="cat-section">
          <h3 class="cat-title" style="border-left:3px solid {rc}">
            <span class="verdict-dot" style="background:{rc}"></span>
            {CAT_LABELS.get(r.category, r.category)}
          </h3>
          <div class="table-wrap">
            <table class="findings-table">
              <thead><tr><th>Severity</th><th>Finding</th><th>Detail</th><th>Location</th></tr></thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
          {overflow}
        </section>"""

    # Scanner coverage rows
    tool_rows = ""
    for tr in result.scan_results:
        avail_html = '<span class="pill-ok">available</span>' if tr.available else '<span class="pill-skip">skipped</span>'
        ran_html   = '<span class="pill-ok">ran</span>' if tr.ran else '—'
        dur        = f"{tr.duration_s:.1f}s" if tr.ran else "—"
        err_html   = f'<span class="scanner-error">{tr.error[:80]}</span>' if tr.error else ""
        tool_rows += f"""
        <tr>
          <td><code class="scanner-name">{tr.scanner}</code></td>
          <td>{avail_html}</td>
          <td>{ran_html}</td>
          <td class="num">{len(tr.findings)}</td>
          <td>{dur}</td>
          <td>{err_html}</td>
        </tr>"""

    skipped_note = ""
    if result.skipped_scanners:
        skipped_list = ", ".join(f"<code>{t}</code>" for t in result.skipped_scanners)
        skipped_note = f'<p class="skipped-note">⬜ Skipped (not installed): {skipped_list}</p>'

    # Timestamp formatting
    try:
        ts = datetime.fromisoformat(result.timestamp.replace("Z","")).strftime("%d %b %Y %H:%M UTC")
    except Exception:
        ts = result.timestamp

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSS Audit — {result.repo_name}</title>
<style>
  :root {{
    --bg: #0f1117;
    --surface: #1a1d27;
    --surface2: #22263a;
    --border: #2d3148;
    --text: #e2e8f0;
    --text-muted: #6b7280;
    --text-dim: #94a3b8;
    --mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
    --sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --verdict: {vc};
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.6;
  }}

  /* ── header ── */
  .header {{
    background: linear-gradient(135deg, #0f1117 0%, #1a1d27 100%);
    border-bottom: 1px solid var(--border);
    padding: 2.5rem 3rem 2rem;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute;
    top: -60px; right: -60px;
    width: 300px; height: 300px;
    background: radial-gradient(circle, {vc}18 0%, transparent 70%);
    pointer-events: none;
  }}
  .header-eyebrow {{
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 0.6rem;
  }}
  .header-title {{
    font-size: 1.8rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: #f1f5f9;
  }}
  .header-title code {{
    font-family: var(--mono);
    font-size: 1.5rem;
    color: var(--verdict);
  }}
  .header-meta {{
    margin-top: 0.75rem;
    font-size: 12px;
    color: var(--text-muted);
    display: flex;
    gap: 1.5rem;
    flex-wrap: wrap;
  }}
  .header-meta span {{ display: flex; align-items: center; gap: 0.35rem; }}

  /* ── verdict banner ── */
  .verdict-banner {{
    margin: 2rem 3rem;
    padding: 1.25rem 1.75rem;
    background: {vc}12;
    border: 1px solid {vc}40;
    border-radius: 10px;
    display: flex;
    align-items: flex-start;
    gap: 1rem;
  }}
  .verdict-icon {{
    font-size: 2.2rem;
    line-height: 1;
    flex-shrink: 0;
  }}
  .verdict-label {{
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: {vc};
    margin-bottom: 0.2rem;
  }}
  .verdict-text {{
    font-size: 0.95rem;
    color: var(--text-dim);
  }}
  .verdict-score-row {{
    margin-left: auto;
    display: flex;
    gap: 1rem;
    align-items: center;
    flex-shrink: 0;
  }}
  .stat-chip {{
    text-align: center;
    min-width: 52px;
  }}
  .stat-chip .stat-n {{
    font-family: var(--mono);
    font-size: 1.4rem;
    font-weight: 700;
    line-height: 1;
  }}
  .stat-chip .stat-l {{
    font-size: 9px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-top: 2px;
  }}

  /* ── main layout ── */
  .main {{ padding: 0 3rem 3rem; }}

  /* ── section titles ── */
  .section-title {{
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin: 2.5rem 0 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
  }}

  /* ── summary table ── */
  .summary-table {{ width: 100%; border-collapse: collapse; }}
  .summary-table th {{
    font-size: 10px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text-muted);
    padding: 0.5rem 0.75rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }}
  .summary-table td {{ padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--border)18; }}
  .summary-table tr:last-child td {{ border-bottom: none; }}
  .summary-table tr:hover td {{ background: var(--surface2); }}
  .cat-label {{ font-weight: 500; color: #cbd5e1; }}
  .num {{ font-family: var(--mono); text-align: center; }}
  .sev-critical {{ color: #ef4444; font-weight: 700; }}
  .sev-high     {{ color: #f97316; font-weight: 600; }}
  .sev-medium   {{ color: #f59e0b; }}
  .reason-text  {{ color: var(--text-muted); font-size: 12px; max-width: 350px; }}

  /* ── pills ── */
  .verdict-pill {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 99px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }}
  .sev-badge {{
    display: inline-block;
    padding: 1px 7px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    font-family: var(--mono);
  }}
  .pill-ok   {{ background: #16a34a20; color: #4ade80; border-radius: 99px; padding: 1px 7px; font-size: 11px; }}
  .pill-skip {{ background: #37415120; color: #6b7280; border-radius: 99px; padding: 1px 7px; font-size: 11px; }}

  /* ── findings sections ── */
  .cat-section {{ margin: 1.5rem 0; }}
  .cat-title {{
    font-size: 0.95rem;
    font-weight: 600;
    color: #cbd5e1;
    padding: 0.6rem 0.75rem;
    background: var(--surface);
    border-radius: 6px 6px 0 0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }}
  .verdict-dot {{
    width: 8px; height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }}
  .table-wrap {{ overflow-x: auto; }}
  .findings-table {{
    width: 100%; border-collapse: collapse;
    background: var(--surface);
    border-radius: 0 0 6px 6px;
    overflow: hidden;
  }}
  .findings-table th {{
    font-size: 10px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--text-muted);
    padding: 0.45rem 0.75rem;
    text-align: left;
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
  }}
  .findings-table td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border)30; vertical-align: top; }}
  .findings-table tr:last-child td {{ border-bottom: none; }}
  .findings-table tr:hover td {{ background: var(--surface2); }}
  .finding-title {{ font-weight: 500; max-width: 260px; color: #e2e8f0; }}
  .finding-detail {{ color: var(--text-muted); font-size: 12px; max-width: 320px; }}
  .finding-loc code {{ font-family: var(--mono); font-size: 11px; color: #7c86a2; word-break: break-all; }}
  .overflow-note {{ font-size: 12px; color: var(--text-muted); padding: 0.5rem 0.75rem; font-style: italic; }}

  /* ── tool coverage ── */
  .scanner-name {{ color: #a5b4fc; }}
  .scanner-error {{ color: #f87171; font-size: 11px; }}

  /* ── misc ── */
  .skipped-note {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 1rem;
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 1rem;
  }}
  .footer {{
    margin: 3rem 3rem 2rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
    font-size: 11px;
    color: var(--text-muted);
    display: flex;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.5rem;
  }}

  @media (max-width: 768px) {{
    .header, .main, .verdict-banner, .footer {{ padding-left: 1.25rem; padding-right: 1.25rem; }}
    .verdict-banner {{ flex-direction: column; }}
    .verdict-score-row {{ margin-left: 0; }}
  }}
</style>
</head>
<body>

<header class="header">
  <div class="header-eyebrow">OSS Security &amp; Privacy Audit</div>
  <h1 class="header-title">Audit report — <code>{result.repo_name}</code></h1>
  <div class="header-meta">
    <span>🔗 <a href="{result.repo_url}" style="color:#7c86a2;text-decoration:none">{result.repo_url}</a></span>
    <span>🛡️ Profile: <strong style="color:#cbd5e1">{result.profile}</strong></span>
    <span>🕒 {ts}</span>
  </div>
</header>

<div class="verdict-banner">
  <div class="verdict-icon">{VERDICT_EMOJI.get(v,'?')}</div>
  <div>
    <div class="verdict-label">Overall Verdict</div>
    <div class="verdict-text">{result.overall_reason}</div>
  </div>
  <div class="verdict-score-row">
    <div class="stat-chip"><div class="stat-n" style="color:#ef4444">{total_critical}</div><div class="stat-l">Critical</div></div>
    <div class="stat-chip"><div class="stat-n" style="color:#f97316">{total_high}</div><div class="stat-l">High</div></div>
    <div class="stat-chip"><div class="stat-n" style="color:#f59e0b">{total_medium}</div><div class="stat-l">Medium</div></div>
    <div class="stat-chip"><div class="stat-n" style="color:#6366f1">{total_low}</div><div class="stat-l">Low</div></div>
    <div class="stat-chip"><div class="stat-n" style="color:#94a3b8">{total_findings}</div><div class="stat-l">Total</div></div>
  </div>
</div>

<main class="main">

  <div class="section-title">Executive Summary</div>
  <table class="summary-table">
    <thead>
      <tr>
        <th>Category</th><th>Verdict</th>
        <th>Critical</th><th>High</th><th>Medium</th><th>Low</th>
        <th>Notes</th>
      </tr>
    </thead>
    <tbody>{rubric_rows}</tbody>
  </table>

  <div class="section-title">Findings by Category</div>
  {finding_sections}

  <div class="section-title">Scanner Coverage</div>
  <table class="summary-table">
    <thead>
      <tr><th>Scanner</th><th>Available</th><th>Ran</th><th>Findings</th><th>Duration</th><th>Error</th></tr>
    </thead>
    <tbody>{tool_rows}</tbody>
  </table>
  {skipped_note}

</main>

<footer class="footer">
  <span>Generated by <strong>oss-audit</strong></span>
  <span>Profile: {result.profile} · {ts}</span>
</footer>

</body>
</html>"""

    return html
