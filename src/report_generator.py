#!/usr/bin/env python3
"""
MFF v2 — Module: Report Generator
- Interactive HTML report (filterable, sortable, dark forensics theme)
- Professional PDF report with all charts, tables, and executive summary
"""

import os
import base64
import json
import pandas as pd
from datetime import datetime, UTC

try:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable, Image as RLImage, KeepTogether,
        ListFlowable, ListItem,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate
    from reportlab.lib.colors import HexColor
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


def now_utc():
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


# ─────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────

def _img_b64(path: str) -> str:
    if not os.path.exists(path):
        return ""
    with open(path, "rb") as f:
        data = base64.b64encode(f.read()).decode()
    return f"data:image/png;base64,{data}"


def _df_html(df: pd.DataFrame, table_id: str = "") -> str:
    if df is None or df.empty:
        return "<p class='empty'>No data found.</p>"
    drop = [c for c in df.columns if c.endswith("_dt")]
    clean = df.drop(columns=drop, errors="ignore").fillna("").head(500)
    tid   = f' id="{table_id}"' if table_id else ""
    html  = clean.to_html(index=False, border=0, escape=True)
    html  = html.replace("<table", f"<table{tid} class=\"dt-table\"")
    return html


def _sev_badge(sev: str) -> str:
    c = {"CRITICAL":"#f78166","HIGH":"#d29922","MEDIUM":"#58a6ff","LOW":"#3fb950"}.get(sev,"#8b949e")
    return f'<span class="sev-badge" style="background:{c}">{sev}</span>'


def _risk_cell(val: str) -> str:
    c = {"CRITICAL":"#f78166","HIGH":"#d29922","MEDIUM":"#58a6ff","LOW":"#3fb950"}.get(str(val).upper(),"#8b949e")
    return f'<span style="color:{c};font-weight:bold">{val}</span>'


# ─────────────────────────────────────────────────────────────
# Interactive HTML Report
# ─────────────────────────────────────────────────────────────

def generate_html_report(
    out_dir, case_id,
    new_df, gone_df, scores_df,
    cmd_df, malfind_df, tagged_df,
    ioc_df, net_new_df, net_flagged_df,
    summary: dict,
):
    html_path = os.path.join(out_dir, "report_interactive.html")

    charts = {k: _img_b64(os.path.join(out_dir, v)) for k, v in {
        "dashboard":      "dashboard.png",
        "proc_counts":    "chart_process_counts.png",
        "risk_scores":    "chart_risk_scores.png",
        "timeline":       "chart_timeline.png",
        "cmdline":        "chart_cmdline_patterns.png",
        "malfind":        "chart_malfind_protection.png",
        "proc_tree":      "chart_process_tree.png",
        "atk_heatmap":    "chart_attack_heatmap.png",
    }.items()}

    def cblock(key, title, cls=""):
        src = charts.get(key, "")
        if not src: return ""
        return f'<div class="chart-card {cls}"><p class="chart-lbl">{title}</p><img src="{src}" alt="{title}" loading="lazy"></div>'

    def tblock(df, tid, label):
        return f"""
        <div class="tbl-controls">
          <input class="tbl-search" data-target="{tid}" placeholder="Search {label}…" type="search">
          <span class="tbl-count" id="{tid}-count"></span>
        </div>
        <div class="tbl-wrap">{_df_html(df, tid)}</div>"""

    sev            = summary.get("severity", {}).get("overall", "?")
    stats          = summary.get("statistics", {})
    critical_count = summary.get("severity", {}).get("critical_processes", 0)
    sev_hex        = {"CRITICAL":"#f78166","HIGH":"#d29922","MEDIUM":"#58a6ff","LOW":"#3fb950"}.get(sev,"#8b949e")
    gen_at         = summary.get("generated_at", now_utc())
    base_path      = summary.get("baseline_path", "—")
    atk_path       = summary.get("attack_path", "—")

    stat_cards = [
        ("new_processes",      "New Processes",          "#f78166"),
        ("gone_processes",     "Gone Processes",         "#58a6ff"),
        ("attack_techniques",  "ATT&CK Techniques",      "#d29922"),
        ("attack_tactics",     "ATT&CK Tactics",         "#d29922"),
        ("iocs_extracted",     "IOCs Extracted",         "#3fb950"),
        ("flagged_network_conns","Flagged Connections",  "#f78166"),
        ("new_network_conns",  "New Connections",        "#58a6ff"),
    ]

    cards_html = ""
    for key, label, color in stat_cards:
        val = stats.get(key, 0)
        cards_html += f"""
        <div class="stat-card">
          <div class="stat-num" style="color:{color}">{val}</div>
          <div class="stat-lbl">{label}</div>
        </div>"""
    cards_html += f"""
        <div class="stat-card">
          <div class="stat-num" style="color:{sev_hex}">{critical_count}</div>
          <div class="stat-lbl">Critical Risk Procs</div>
        </div>"""

    # ATT&CK tactic pills
    tactics = summary.get("mitre_attack", {}).get("tactics_observed", [])
    tactic_pills = " ".join(f'<span class="pill pill-blue">{t}</span>' for t in tactics) or "<em>None detected</em>"

    # IOC quick summary
    ioc_summary = summary.get("iocs", {})
    ioc_rows = ""
    for label, key in [("IPv4 Addresses","ipv4"),("Domains","domains"),
                       ("URLs","urls"),("SHA256","sha256"),("MD5","md5"),("File Paths","filepaths")]:
        items = ioc_summary.get(key, [])
        if items:
            ioc_rows += f'<tr><td class="ioc-type">{label}</td><td>{"  ·  ".join(str(i) for i in items[:8])}{"  …" if len(items)>8 else ""}</td></tr>'

    # Risk score table with coloured risk level
    scores_html = ""
    if not scores_df.empty:
        for _, row in scores_df.head(20).iterrows():
            rl   = str(row.get("RiskLevel","LOW"))
            rc   = {"CRITICAL":"#f78166","HIGH":"#d29922","MEDIUM":"#58a6ff","LOW":"#3fb950"}.get(rl,"#8b949e")
            scores_html += f"""<tr>
              <td>{row.get("Process","")}</td>
              <td>{row.get("PID","")}</td>
              <td><span style="color:{rc};font-weight:bold">{row.get("RiskScore",0)}</span></td>
              <td><span class="pill" style="background:{rc};color:#000">{rl}</span></td>
              <td style="color:#8b949e;font-size:0.75rem">{str(row.get("Indicators",""))[:80]}</td>
            </tr>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MFF v2 · {case_id}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
:root{{
  --bg:#0d1117; --panel:#161b22; --panel2:#1c2128; --border:#30363d;
  --accent:#f78166; --safe:#3fb950; --warn:#d29922; --info:#58a6ff;
  --text:#e6edf3; --sub:#8b949e; --grid:#21262d; --nav-w:210px;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth}}
body{{background:var(--bg);color:var(--text);font-family:'Share Tech Mono',monospace;font-size:13px;line-height:1.6}}

/* ── Nav ── */
nav#sidenav{{position:fixed;top:0;left:0;width:var(--nav-w);height:100vh;
  background:var(--panel);border-right:1px solid var(--border);
  overflow-y:auto;z-index:200;padding:18px 0 32px}}
nav#sidenav .nav-logo{{padding:12px 20px 18px;font-family:'Rajdhani',sans-serif;
  font-size:1rem;color:var(--accent);letter-spacing:2px;border-bottom:1px solid var(--border);margin-bottom:10px}}
nav#sidenav a{{display:flex;align-items:center;gap:8px;padding:7px 20px;color:var(--sub);
  text-decoration:none;font-size:0.78rem;border-left:3px solid transparent;transition:all .15s}}
nav#sidenav a:hover,nav#sidenav a.active{{color:var(--text);border-left-color:var(--accent);background:rgba(247,129,102,.07)}}
nav#sidenav .nav-section{{padding:14px 20px 4px;color:var(--sub);font-size:0.65rem;
  letter-spacing:2px;text-transform:uppercase}}

/* ── Main ── */
main{{margin-left:var(--nav-w);padding:28px 38px;max-width:1500px}}
section{{margin-bottom:56px;scroll-margin-top:24px}}
h2{{font-family:'Rajdhani',sans-serif;font-size:1.05rem;letter-spacing:2px;
  text-transform:uppercase;color:var(--info);
  border-left:3px solid var(--info);padding-left:12px;margin-bottom:20px}}

/* ── Header banner ── */
.page-header{{background:var(--panel);border-bottom:2px solid var(--accent);
  padding:20px 38px;margin-left:var(--nav-w);position:sticky;top:0;z-index:150;
  display:flex;align-items:center;justify-content:space-between}}
.page-header h1{{font-family:'Rajdhani',sans-serif;font-size:1.5rem;
  color:var(--accent);letter-spacing:3px;text-transform:uppercase}}
.page-header .meta{{color:var(--sub);font-size:0.75rem;line-height:1.7}}
.sev-badge{{display:inline-block;padding:4px 14px;border-radius:4px;
  font-weight:bold;font-size:0.85rem;color:#000;margin-left:12px}}

/* ── Stat cards ── */
.stat-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(148px,1fr));gap:14px;margin-bottom:30px}}
.stat-card{{background:var(--panel);border:1px solid var(--border);border-radius:8px;
  padding:16px 18px;transition:all .2s}}
.stat-card:hover{{border-color:var(--accent);transform:translateY(-2px)}}
.stat-num{{font-family:'Rajdhani',sans-serif;font-size:2.2rem;font-weight:700}}
.stat-lbl{{color:var(--sub);font-size:0.7rem;margin-top:2px;text-transform:uppercase;letter-spacing:1px}}

/* ── Chart grid ── */
.chart-grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:8px}}
.chart-card{{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px}}
.chart-card img{{width:100%;border-radius:4px;display:block}}
.chart-card.full{{grid-column:1/-1}}
.chart-lbl{{font-size:0.72rem;color:var(--sub);text-transform:uppercase;letter-spacing:1px;margin-bottom:10px}}

/* ── Tables ── */
.tbl-wrap{{overflow-x:auto;border-radius:6px;border:1px solid var(--border)}}
table.dt-table{{width:100%;border-collapse:collapse;font-size:0.77rem}}
table.dt-table thead tr{{background:var(--grid)}}
table.dt-table th{{color:var(--info);padding:9px 13px;text-align:left;
  cursor:pointer;user-select:none;white-space:nowrap;position:sticky;top:0;background:var(--grid)}}
table.dt-table th:hover{{color:var(--text)}}
table.dt-table td{{padding:7px 13px;border-bottom:1px solid var(--grid);vertical-align:top;word-break:break-word;max-width:340px}}
table.dt-table tr:hover td{{background:rgba(88,166,255,.04)}}
table.dt-table th::after{{content:' ⇅';opacity:.35;font-size:0.65rem}}
table.dt-table th.asc::after{{content:' ▲';opacity:1}}
table.dt-table th.desc::after{{content:' ▼';opacity:1}}
.tbl-controls{{display:flex;gap:10px;margin-bottom:10px;flex-wrap:wrap;align-items:center}}
.tbl-search{{background:var(--panel);border:1px solid var(--border);color:var(--text);
  padding:6px 12px;border-radius:4px;font-family:inherit;font-size:0.78rem;
  outline:none;width:280px;transition:border-color .15s}}
.tbl-search:focus{{border-color:var(--info)}}
.tbl-count{{color:var(--sub);font-size:0.73rem}}
.empty{{color:var(--sub);font-style:italic;padding:12px 0}}

/* ── Pills / badges ── */
.pill{{display:inline-block;padding:2px 9px;border-radius:3px;font-size:0.7rem;font-weight:bold;margin:1px}}
.pill-blue{{background:rgba(88,166,255,.18);color:var(--info)}}
.ioc-type{{color:var(--warn);font-weight:bold;white-space:nowrap;padding-right:16px}}

/* ── Info box ── */
.info-box{{background:var(--panel2);border:1px solid var(--border);border-radius:6px;
  padding:16px 20px;margin-bottom:16px;font-size:0.8rem;color:var(--sub)}}
.info-box b{{color:var(--text)}}

/* ── Print ── */
@media print{{nav#sidenav,.page-header,.tbl-controls{{display:none!important}}
  main{{margin-left:0;padding:0}} body{{background:#fff;color:#000}}}}
</style>
</head>
<body>

<!-- ── Sidebar ── -->
<nav id="sidenav">
  <div class="nav-logo">&#9654; MFF v2</div>
  <div class="nav-section">Overview</div>
  <a href="#summary">&#9650; Summary</a>
  <a href="#dashboard">&#9632; Dashboard</a>
  <div class="nav-section">Analysis</div>
  <a href="#risk">&#9888; Risk Scores</a>
  <a href="#process-diff">&#8635; Process Diff</a>
  <a href="#proc-tree">&#9001; Process Tree</a>
  <a href="#timeline">&#8986; Timeline</a>
  <div class="nav-section">Artefacts</div>
  <a href="#attack">&#128250; ATT&amp;CK</a>
  <a href="#cmdline">&#62; Cmdline</a>
  <a href="#malfind">&#9888; Malfind</a>
  <a href="#network">&#127760; Network</a>
  <a href="#iocs">&#128269; IOCs</a>
</nav>

<!-- ── Sticky header ── -->
<div class="page-header">
  <div>
    <h1>Memory Forensics Report {_sev_badge(sev)}</h1>
    <div class="meta">Case: <b style="color:var(--text)">{case_id}</b>
      &nbsp;·&nbsp; Generated: {gen_at}
      &nbsp;·&nbsp; Baseline: <code>{os.path.basename(base_path)}</code>
      &nbsp;→&nbsp; Attack: <code>{os.path.basename(atk_path)}</code>
    </div>
  </div>
</div>

<main>

<!-- ── Summary ── -->
<section id="summary">
  <h2>&#9650; Executive Summary</h2>
  <div class="stat-grid">{cards_html}</div>
  <div class="info-box">
    <b>Baseline:</b> {base_path}<br>
    <b>Attack capture:</b> {atk_path}<br>
    <b>ATT&CK Tactics observed:</b> {tactic_pills}
  </div>
  {f'<div class="info-box"><b>IOC Quick View</b><br><table style="margin-top:8px;font-size:0.78rem">{ioc_rows}</table></div>' if ioc_rows else ""}
</section>

<!-- ── Dashboard ── -->
<section id="dashboard">
  <h2>&#9632; Full Dashboard</h2>
  {cblock("dashboard","Full Comparison Dashboard","full")}
</section>

<!-- ── Risk Scores ── -->
<section id="risk">
  <h2>&#9888; Risk Scores</h2>
  <div class="chart-grid">
    {cblock("risk_scores","Risk Scoring Overview","full")}
  </div>
  <div class="info-box" style="margin-top:16px">
    <b>Scoring method:</b> Rule-based transparent scoring — no ML.
    RWX memory region = +60 · Suspicious cmdline = +40 · Known-malicious name = +50 · Anomaly name bonus = +15 (stacks only).<br>
    Thresholds: <span style="color:#f78166">CRITICAL ≥ 80</span> &nbsp;
    <span style="color:#d29922">HIGH ≥ 50</span> &nbsp;
    <span style="color:#58a6ff">MEDIUM ≥ 20</span> &nbsp;
    <span style="color:#3fb950">LOW &lt; 20</span>
  </div>
  <table class="dt-table" id="tbl-risk" style="margin-top:14px">
    <thead><tr>
      <th>Process</th><th>PID</th><th>Score</th><th>Risk Level</th><th>Indicators</th>
    </tr></thead>
    <tbody>{scores_html}</tbody>
  </table>
</section>

<!-- ── Process Diff ── -->
<section id="process-diff">
  <h2>&#8635; Process Differential</h2>
  <div class="chart-grid">
    {cblock("proc_counts","Process Count Analysis")}
  </div>
  <div style="margin-top:20px">
    <h3 style="color:var(--warn);margin-bottom:10px;font-size:0.9rem">&#9650; NEW Processes (Attack Only)</h3>
    {tblock(new_df,"tbl-new","new processes")}
  </div>
  <div style="margin-top:20px">
    <h3 style="color:var(--info);margin-bottom:10px;font-size:0.9rem">&#9660; GONE Processes (Baseline Only)</h3>
    {tblock(gone_df,"tbl-gone","gone processes")}
  </div>
</section>

<!-- ── Process Tree ── -->
<section id="proc-tree">
  <h2>&#9001; Parent-Child Process Tree</h2>
  {cblock("proc_tree","Process Tree — New processes highlighted in red","full")}
</section>

<!-- ── Timeline ── -->
<section id="timeline">
  <h2>&#8986; Process Timeline</h2>
  {cblock("timeline","Process Creation / Disappearance Events","full")}
</section>

<!-- ── ATT&CK ── -->
<section id="attack">
  <h2>&#128250; MITRE ATT&amp;CK Mapping</h2>
  <div class="chart-grid">
    {cblock("atk_heatmap","ATT&CK Coverage Heatmap","full")}
  </div>
  {tblock(tagged_df,"tbl-attack","ATT&CK tags")}
</section>

<!-- ── Cmdline ── -->
<section id="cmdline">
  <h2>&#62; Suspicious Command Lines</h2>
  {cblock("cmdline","Cmdline Pattern Hits")}
  {tblock(cmd_df,"tbl-cmdline","cmdline findings")}
</section>

<!-- ── Malfind ── -->
<section id="malfind">
  <h2>&#9888; Malfind — Memory Injection Artefacts</h2>
  {cblock("malfind","RWX Memory Protection Types")}
  <div style="margin-top:16px">
  {tblock(malfind_df,"tbl-malfind","malfind regions")}
  </div>
</section>

<!-- ── Network ── -->
<section id="network">
  <h2>&#127760; Network Artefacts</h2>
  <div style="margin-bottom:14px">
    <h3 style="color:var(--accent);margin-bottom:8px;font-size:0.9rem">Flagged Connections (suspicious ports)</h3>
    {tblock(net_flagged_df,"tbl-net-flag","flagged connections")}
  </div>
  <div>
    <h3 style="color:var(--info);margin-bottom:8px;font-size:0.9rem">New Connections (not in baseline)</h3>
    {tblock(net_new_df,"tbl-net-new","new connections")}
  </div>
</section>

<!-- ── IOCs ── -->
<section id="iocs">
  <h2>&#128269; Extracted IOCs</h2>
  {tblock(ioc_df,"tbl-iocs","IOCs")}
</section>

</main>

<script>
// ── Table sort
document.querySelectorAll('table.dt-table thead th').forEach((th, idx) => {{
  th.addEventListener('click', () => {{
    const tbl   = th.closest('table');
    const tbody = tbl.querySelector('tbody');
    const rows  = Array.from(tbody.querySelectorAll('tr'));
    const asc   = th.classList.contains('asc');
    tbl.querySelectorAll('th').forEach(t => t.classList.remove('asc','desc'));
    th.classList.add(asc ? 'desc' : 'asc');
    rows.sort((a,b) => {{
      const av = a.cells[idx]?.textContent.trim() || '';
      const bv = b.cells[idx]?.textContent.trim() || '';
      const an = parseFloat(av), bn = parseFloat(bv);
      if (!isNaN(an) && !isNaN(bn)) return asc ? bn-an : an-bn;
      return asc ? bv.localeCompare(av) : av.localeCompare(bv);
    }});
    rows.forEach(r => tbody.appendChild(r));
    updateCount(tbl);
  }});
}});

// ── Table search / filter
function updateCount(tbl) {{
  const id  = tbl.id;
  const cnt = document.getElementById(id+'-count');
  if (!cnt) return;
  const vis = tbl.querySelectorAll('tbody tr:not([hidden])').length;
  const tot = tbl.querySelectorAll('tbody tr').length;
  cnt.textContent = vis + ' / ' + tot + ' rows';
}}
document.querySelectorAll('.tbl-search').forEach(inp => {{
  inp.addEventListener('input', () => {{
    const q   = inp.value.toLowerCase();
    const tbl = document.getElementById(inp.dataset.target);
    if (!tbl) return;
    tbl.querySelectorAll('tbody tr').forEach(row => {{
      row.hidden = !row.textContent.toLowerCase().includes(q);
    }});
    updateCount(tbl);
  }});
}});

// ── Sidebar active on scroll
const sections = document.querySelectorAll('section[id]');
const navLinks  = document.querySelectorAll('nav a');
window.addEventListener('scroll', () => {{
  let cur = '';
  sections.forEach(s => {{ if (window.scrollY >= s.offsetTop - 140) cur = s.id; }});
  navLinks.forEach(a => {{
    a.classList.toggle('active', a.getAttribute('href') === '#'+cur);
  }});
}}, {{passive:true}});

// ── Init row counts
document.querySelectorAll('table.dt-table').forEach(tbl => updateCount(tbl));
</script>
</body></html>
""")
    print(f"  [+] Interactive HTML report: {html_path}")
    return html_path


# ─────────────────────────────────────────────────────────────
# PDF Report — Professional Forensics Document
# ─────────────────────────────────────────────────────────────

def generate_pdf_report(out_dir: str, case_id: str, summary: dict,
                        scores_df=None, new_df=None, gone_df=None,
                        cmd_df=None, malfind_df=None, tagged_df=None,
                        ioc_df=None, net_flagged_df=None):
    if not HAS_REPORTLAB:
        print("  [!] reportlab not installed — run: pip install reportlab")
        return None

    pdf_path = os.path.join(out_dir, "report_forensics.pdf")

    # ── Colours
    BG     = HexColor("#0d1117")
    PANEL  = HexColor("#161b22")
    BORDER = HexColor("#30363d")
    GRID   = HexColor("#21262d")
    ACCENT = HexColor("#f78166")
    SAFE   = HexColor("#3fb950")
    WARN   = HexColor("#d29922")
    INFO   = HexColor("#58a6ff")
    WHITE  = HexColor("#e6edf3")
    SUB    = HexColor("#8b949e")
    BLACK  = colors.black

    SEV_COLOR = {"CRITICAL": ACCENT, "HIGH": WARN, "MEDIUM": INFO, "LOW": SAFE}
    RISK_TXT  = {"CRITICAL": ACCENT, "HIGH": WARN, "MEDIUM": INFO, "LOW": SAFE}

    # ── Styles
    def S(name, **kw):
        base = {
            "fontName": "Courier", "fontSize": 8,
            "textColor": WHITE, "leading": 12, "spaceAfter": 4,
        }
        base.update(kw)
        return ParagraphStyle(name, **base)

    sTitle  = S("Title",  fontName="Helvetica-Bold", fontSize=22,
                textColor=ACCENT, alignment=TA_CENTER, spaceAfter=6, leading=28)
    sSub    = S("Sub",    fontName="Helvetica",      fontSize=9,
                textColor=SUB,   alignment=TA_CENTER, spaceAfter=4)
    sH1     = S("H1",     fontName="Helvetica-Bold", fontSize=13,
                textColor=INFO,  spaceBefore=18, spaceAfter=8, leading=18)
    sH2     = S("H2",     fontName="Helvetica-Bold", fontSize=10,
                textColor=WARN,  spaceBefore=10, spaceAfter=5, leading=14)
    sBody   = S("Body")
    sMono   = S("Mono",   fontName="Courier",        fontSize=7.5, leading=11)
    sCaption= S("Cap",    fontName="Helvetica",      fontSize=7,
                textColor=SUB,   alignment=TA_CENTER, spaceAfter=3)

    def hline(color=ACCENT, thick=1.2):
        return HRFlowable(width="100%", thickness=thick, color=color, spaceAfter=10, spaceBefore=4)

    def spacer(h=0.3):
        return Spacer(1, h*cm)

    def tbl_style(header_color=INFO, alt=True):
        base = [
            ("BACKGROUND",    (0,0),  (-1,0),  PANEL),
            ("TEXTCOLOR",     (0,0),  (-1,0),  header_color),
            ("FONTNAME",      (0,0),  (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),  (-1,-1), 7.5),
            ("FONTNAME",      (0,1),  (-1,-1), "Courier"),
            ("TEXTCOLOR",     (0,1),  (-1,-1), WHITE),
            ("BACKGROUND",    (0,1),  (-1,-1), BG),
            ("GRID",          (0,0),  (-1,-1), 0.3, BORDER),
            ("TOPPADDING",    (0,0),  (-1,-1), 4),
            ("BOTTOMPADDING", (0,0),  (-1,-1), 4),
            ("LEFTPADDING",   (0,0),  (-1,-1), 6),
            ("RIGHTPADDING",  (0,0),  (-1,-1), 6),
            ("VALIGN",        (0,0),  (-1,-1), "TOP"),
            ("WORDWRAP",      (0,0),  (-1,-1), True),
        ]
        if alt:
            base.append(("ROWBACKGROUNDS", (0,1), (-1,-1), [BG, GRID]))
        return TableStyle(base)

    def df_to_table(df, cols=None, col_widths=None, max_rows=30):
        if df is None or df.empty:
            return Paragraph("No data.", sMono)
        drop = [c for c in df.columns if c.endswith("_dt")]
        df2  = df.drop(columns=drop, errors="ignore").fillna("").head(max_rows)
        use  = cols if cols else list(df2.columns)
        use  = [c for c in use if c in df2.columns]
        rows = [[Paragraph(str(c), S("th", fontName="Helvetica-Bold",
                                     fontSize=7, textColor=INFO, leading=10))
                 for c in use]]
        for _, row in df2.iterrows():
            rows.append([Paragraph(str(row.get(c,""))[:120],
                                   sMono) for c in use])
        w = col_widths or [17*cm / len(use)] * len(use)
        t = Table(rows, colWidths=w, repeatRows=1)
        t.setStyle(tbl_style())
        return t

    def add_chart(story, fname, title, w=17*cm, h=None):
        path = os.path.join(out_dir, fname)
        if not os.path.exists(path):
            return
        story.append(Paragraph(title, sH2))
        try:
            from PIL import Image as PILImage
            with PILImage.open(path) as im:
                iw, ih = im.size
            ratio = ih / iw if iw else 0.5
            actual_h = h if h else w * ratio
            story.append(RLImage(path, width=w, height=actual_h))
        except ImportError:
            # PIL not available — fall back to fixed height
            actual_h = h if h else w * 0.5625
            story.append(RLImage(path, width=w, height=actual_h))
        except Exception as e:
            story.append(Paragraph(f"[Chart error: {e}]", sMono))
        story.append(spacer(0.25))

    # ── Page template with header/footer
    sev      = summary.get("severity", {}).get("overall", "UNKNOWN")
    sev_c    = SEV_COLOR.get(sev, SUB)
    stats    = summary.get("statistics", {})
    gen_at   = summary.get("generated_at", now_utc())
    base_path= summary.get("baseline_path", "—")
    atk_path = summary.get("attack_path",   "—")
    tactics  = summary.get("mitre_attack",  {}).get("tactics_observed", [])
    ioc_data = summary.get("iocs", {})
    crit_cnt = summary.get("severity", {}).get("critical_processes", 0)

    doc = SimpleDocTemplate(
        pdf_path, pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm,
        topMargin=1.8*cm, bottomMargin=2.2*cm,
        title=f"MFF v2 — {case_id}",
        author="MFF v2 Memory Forensics Framework",
    )

    story = []

    # ══════════════════════════════════
    # COVER PAGE
    # ══════════════════════════════════
    story += [spacer(1.5)]
    story.append(Paragraph("MEMORY FORENSICS REPORT", sTitle))
    story.append(Paragraph("MFF v2  ·  Post-Volatility Analysis Framework", sSub))
    story += [spacer(0.5), hline()]

    # Severity banner
    sev_tbl = Table([[f"OVERALL SEVERITY: {sev}"]], colWidths=[17*cm])
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), sev_c),
        ("TEXTCOLOR",     (0,0), (-1,-1), BLACK),
        ("FONTNAME",      (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 16),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("TOPPADDING",    (0,0), (-1,-1), 12),
        ("BOTTOMPADDING", (0,0), (-1,-1), 12),
    ]))
    story += [sev_tbl, spacer(0.5)]

    # Case metadata table
    meta_rows = [
        ["Case ID",          case_id],
        ["Generated",        gen_at],
        ["Baseline capture", os.path.basename(base_path)],
        ["Attack capture",   os.path.basename(atk_path)],
        ["Baseline path",    base_path],
        ["Attack path",      atk_path],
    ]
    meta_tbl = Table(meta_rows, colWidths=[5*cm, 12*cm])
    meta_tbl.setStyle(TableStyle([
        ("FONTNAME",     (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 8),
        ("FONTNAME",     (1,0), (1,-1), "Courier"),
        ("TEXTCOLOR",    (0,0), (0,-1), INFO),
        ("TEXTCOLOR",    (1,0), (1,-1), WHITE),
        ("BACKGROUND",   (0,0), (-1,-1), BG),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[BG, GRID]),
        ("GRID",         (0,0), (-1,-1), 0.3, BORDER),
        ("TOPPADDING",   (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
    ]))
    story += [meta_tbl, PageBreak()]

    # ══════════════════════════════════
    # PAGE 2 — EXECUTIVE SUMMARY
    # ══════════════════════════════════
    story.append(Paragraph("1.  EXECUTIVE SUMMARY", sH1))
    story.append(hline(INFO, 0.6))

    # Stats table
    stat_data = [
        ["Metric", "Value", "Metric", "Value"],
        ["New Processes (Attack Only)",    str(stats.get("new_processes",0)),
         "Critical Risk Processes",        str(crit_cnt)],
        ["Gone Processes (Baseline Only)", str(stats.get("gone_processes",0)),
         "ATT&CK Techniques Observed",     str(stats.get("attack_techniques",0))],
        ["New Network Connections",        str(stats.get("new_network_conns",0)),
         "ATT&CK Tactics Observed",        str(stats.get("attack_tactics",0))],
        ["Flagged Connections",            str(stats.get("flagged_network_conns",0)),
         "IOCs Extracted",                 str(stats.get("iocs_extracted",0))],
    ]
    stat_tbl = Table(stat_data, colWidths=[6*cm, 2.5*cm, 6*cm, 2.5*cm])
    stat_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),  (-1,0),  PANEL),
        ("TEXTCOLOR",     (0,0),  (-1,0),  INFO),
        ("FONTNAME",      (0,0),  (-1,0),  "Helvetica-Bold"),
        ("FONTNAME",      (0,1),  (-1,-1), "Courier"),
        ("FONTSIZE",      (0,0),  (-1,-1), 8),
        ("TEXTCOLOR",     (0,1),  (-1,-1), WHITE),
        ("TEXTCOLOR",     (1,1),  (1,-1),  ACCENT),
        ("TEXTCOLOR",     (3,1),  (3,-1),  ACCENT),
        ("FONTNAME",      (1,1),  (1,-1),  "Helvetica-Bold"),
        ("FONTNAME",      (3,1),  (3,-1),  "Helvetica-Bold"),
        ("FONTSIZE",      (1,1),  (1,-1),  10),
        ("FONTSIZE",      (3,1),  (3,-1),  10),
        ("BACKGROUND",    (0,1),  (-1,-1), BG),
        ("ROWBACKGROUNDS",(0,1),  (-1,-1), [BG, GRID]),
        ("GRID",          (0,0),  (-1,-1), 0.3, BORDER),
        ("TOPPADDING",    (0,0),  (-1,-1), 5),
        ("BOTTOMPADDING", (0,0),  (-1,-1), 5),
        ("LEFTPADDING",   (0,0),  (-1,-1), 8),
        ("ALIGN",         (1,0),  (1,-1),  "CENTER"),
        ("ALIGN",         (3,0),  (3,-1),  "CENTER"),
    ]))
    story += [stat_tbl, spacer()]

    # ATT&CK tactics
    if tactics:
        story.append(Paragraph("ATT&CK Tactics Observed:", sH2))
        tac_text = "  ·  ".join(tactics)
        story.append(Paragraph(tac_text, sMono))
        story += [spacer(0.3)]

    # IOC quick summary
    story.append(Paragraph("IOC Summary:", sH2))
    ioc_rows_pdf = [["Type", "Indicators (top 8)"]]
    for label, key in [("IPv4","ipv4"),("Domains","domains"),
                       ("URLs","urls"),("SHA256","sha256"),("MD5","md5")]:
        items = ioc_data.get(key, [])
        if items:
            ioc_rows_pdf.append([label, "  ·  ".join(str(i) for i in items[:8])])
    if len(ioc_rows_pdf) > 1:
        ioc_tbl = Table(ioc_rows_pdf, colWidths=[3.5*cm, 13.5*cm])
        ioc_tbl.setStyle(tbl_style(header_color=WARN))
        story.append(ioc_tbl)
    else:
        story.append(Paragraph("No IOCs extracted.", sMono))

    story += [spacer(), PageBreak()]

    # ══════════════════════════════════
    # PAGE 3+ — VISUALIZATIONS
    # ══════════════════════════════════
    story.append(Paragraph("2.  VISUALIZATIONS", sH1))
    story.append(hline(INFO, 0.6))

    add_chart(story, "dashboard.png",               "2.1  Full Forensics Dashboard",  w=17*cm)
    story.append(PageBreak())
    add_chart(story, "chart_risk_scores.png",        "2.2  Risk Scoring Overview",      w=17*cm)
    story.append(PageBreak())
    add_chart(story, "chart_process_counts.png",     "2.3  Process Delta Analysis",     w=17*cm)
    add_chart(story, "chart_timeline.png",           "2.4  Process Timeline",           w=17*cm)
    story.append(PageBreak())
    add_chart(story, "chart_process_tree.png",       "2.5  Parent-Child Process Tree",  w=17*cm)
    story.append(PageBreak())
    add_chart(story, "chart_attack_heatmap.png",     "2.6  MITRE ATT&CK Heatmap",       w=17*cm)
    add_chart(story, "chart_cmdline_patterns.png",   "2.7  Suspicious Cmdline Patterns",w=17*cm)
    add_chart(story, "chart_malfind_protection.png", "2.8  Malfind Memory Protections", w=17*cm)
    story.append(PageBreak())

    # ══════════════════════════════════
    # PAGE — RISK SCORE TABLE
    # ══════════════════════════════════
    story.append(Paragraph("3.  RISK SCORE TABLE", sH1))
    story.append(hline(INFO, 0.6))
    if scores_df is not None and not scores_df.empty:
        top_scores = scores_df[scores_df["RiskScore"] > 0].head(30)
        if top_scores.empty: top_scores = scores_df.head(20)
        rs_rows = [["Process", "PID", "Score", "Level", "Indicators"]]
        for _, row in top_scores.iterrows():
            rl    = str(row.get("RiskLevel","LOW"))
            rc    = RISK_TXT.get(rl, SUB)
            score = int(row.get("RiskScore", 0))
            rs_rows.append([
                Paragraph(str(row.get("Process",""))[:30], sMono),
                Paragraph(str(row.get("PID","")), sMono),
                Paragraph(f"<font color='{rc.hexval()}' fontName='Helvetica-Bold'>{score}</font>", sMono),
                Paragraph(f"<font color='{rc.hexval()}' fontName='Helvetica-Bold'>{rl}</font>", sMono),
                Paragraph(str(row.get("Indicators",""))[:80], sMono),
            ])
        rs_tbl = Table(rs_rows, colWidths=[4.5*cm,1.5*cm,1.5*cm,2*cm,7.5*cm], repeatRows=1)
        rs_tbl.setStyle(tbl_style())
        story += [rs_tbl, spacer(), PageBreak()]
    else:
        story += [Paragraph("No scored processes.", sMono), PageBreak()]

    # ══════════════════════════════════
    # PAGE — NEW PROCESSES
    # ══════════════════════════════════
    story.append(Paragraph("4.  NEW PROCESSES  (Attack Only)", sH1))
    story.append(hline(INFO, 0.6))
    if new_df is not None and not new_df.empty:
        cols = ["ImageFileName","PID","PPID","CreateTime"]
        story.append(df_to_table(new_df, cols=cols,
                                 col_widths=[5*cm,2*cm,2*cm,8*cm]))
    else:
        story.append(Paragraph("No new processes detected.", sMono))
    story += [spacer(), PageBreak()]

    # ══════════════════════════════════
    # PAGE — ATT&CK TAGS
    # ══════════════════════════════════
    story.append(Paragraph("5.  MITRE ATT&CK TECHNIQUE MATCHES", sH1))
    story.append(hline(INFO, 0.6))
    if tagged_df is not None and not tagged_df.empty:
        cols = ["Technique","TechniqueName","Tactic","MatchedKeyword","PID","Process"]
        story.append(df_to_table(tagged_df, cols=cols,
                                 col_widths=[2.2*cm,3.5*cm,3*cm,3*cm,1.5*cm,3.8*cm]))
    else:
        story.append(Paragraph("No ATT&CK techniques matched.", sMono))
    story += [spacer(), PageBreak()]

    # ══════════════════════════════════
    # PAGE — CMDLINE + MALFIND
    # ══════════════════════════════════
    story.append(Paragraph("6.  SUSPICIOUS CMDLINE FINDINGS", sH1))
    story.append(hline(INFO, 0.6))
    if cmd_df is not None and not cmd_df.empty:
        cols = ["ImageFileName","PID","MatchedPattern","Args"]
        story.append(df_to_table(cmd_df, cols=cols,
                                 col_widths=[3.5*cm,1.5*cm,3*cm,9*cm]))
    else:
        story.append(Paragraph("No suspicious command lines found.", sMono))
    story += [spacer()]

    story.append(Paragraph("7.  MALFIND — MEMORY INJECTION ARTEFACTS", sH1))
    story.append(hline(INFO, 0.6))
    if malfind_df is not None and not malfind_df.empty:
        cols = ["Process","PID","Protection","VadTag","Address"]
        cols = [c for c in cols if c in malfind_df.columns]
        story.append(df_to_table(malfind_df, cols=cols))
    else:
        story.append(Paragraph("No suspicious malfind artefacts found.", sMono))
    story += [spacer(), PageBreak()]

    # ══════════════════════════════════
    # PAGE — NETWORK + IOC DETAIL
    # ══════════════════════════════════
    story.append(Paragraph("8.  NETWORK ARTEFACTS", sH1))
    story.append(hline(INFO, 0.6))
    story.append(Paragraph("8a.  Flagged Connections (suspicious ports)", sH2))
    if net_flagged_df is not None and not net_flagged_df.empty:
        story.append(df_to_table(net_flagged_df))
    else:
        story.append(Paragraph("No flagged connections.", sMono))
    story += [spacer()]

    story.append(Paragraph("9.  IOC DETAIL TABLE", sH1))
    story.append(hline(INFO, 0.6))
    if ioc_df is not None and not ioc_df.empty:
        story.append(df_to_table(ioc_df, col_widths=[3*cm,8*cm,3*cm,3*cm]))
    else:
        story.append(Paragraph("No IOCs extracted.", sMono))
    story += [spacer(), PageBreak()]

    # ══════════════════════════════════
    # FINAL PAGE — methodology note
    # ══════════════════════════════════
    story.append(Paragraph("10.  METHODOLOGY", sH1))
    story.append(hline(INFO, 0.6))
    method_text = [
        ("Dataset",       "Memory images captured using VMware hypervisor snapshot of Windows 10 VM. "
                          "Attack simulations performed with Atomic Red Team (ART) scripts."),
        ("Volatility 3",  "Memory parsed using Volatility 3 plugins: pslist, cmdline, malfind, netscan, "
                          "pstree. Output exported as CSV."),
        ("Process diff",  "Baseline vs attack comparison by process name (ImageFileName). "
                          "PID-based diff rejected — PIDs reassigned on every reboot."),
        ("Risk scoring",  "Transparent rule-based scoring (no ML). "
                          "RWX memory region +60 · Suspicious cmdline +40 · Known-malicious name +50 · Anomaly bonus +15."),
        ("Malfind filter","Known-clean JIT processes excluded (browsers, Defender, .NET). "
                          "Only genuinely suspicious RWX regions retained."),
        ("ATT&CK mapping","25+ rule-based signatures across 8 tactics. Keyword matching on "
                          "cmdline args, process names, and network artefacts."),
        ("IOC extraction","Regex-based extraction: IPv4 (excluding RFC1918), domains, URLs, "
                          "MD5/SHA1/SHA256, Windows file paths."),
        ("Framework",     "MFF v2 — Python Post-Volatility Memory Forensics Framework. "
                          "FYP project. Tool chain: Volatility 3 → MFF v2 → HTML/PDF reports."),
    ]
    for label, text in method_text:
        story.append(Paragraph(f"<b>{label}:</b>  {text}", sBody))
        story.append(spacer(0.1))

    story += [spacer(0.5), hline(SUB, 0.4)]
    story.append(Paragraph(
        f"Report generated by MFF v2 Memory Forensics Framework  ·  {gen_at}  ·  Case: {case_id}",
        S("footer", fontName="Helvetica", fontSize=7, textColor=SUB, alignment=TA_CENTER)
    ))

    doc.build(story)
    print(f"  [+] PDF report: {pdf_path}")
    return pdf_path
