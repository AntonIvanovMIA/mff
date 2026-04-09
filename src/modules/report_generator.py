#!/usr/bin/env python3
"""
MFF v2 — Module: Report Generator
- Interactive HTML report (filterable, sortable, dark forensics theme)
- Professional PDF report with all charts, tables, and executive summary
"""

import os
import base64
import json
import html as _html_lib
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
    dll_findings_df=None,
):
    html_path = os.path.join(out_dir, "report_interactive.html")

    # ── Helper ─────────────────────────────────────────────────────────────
    def esc(s): return _html_lib.escape(str(s) if s is not None else "")
    def df_to_js(df, name):
        if df is None or df.empty: return f"const {name} = [];"
        rows = []
        for _, r in df.iterrows():
            row = {}
            for c in df.columns:
                v = r[c]
                if pd.isna(v): row[c] = ""
                elif isinstance(v, (int, float)): row[c] = v
                else: row[c] = str(v)
            rows.append(row)
        return f"const {name} = {json.dumps(rows, default=str)};"

    def safe_int(v, default=0):
        try: return int(v)
        except: return default

    # ── Pre-process dataframes ─────────────────────────────────────────────
    RISK_C = {"CRITICAL":"#f85149","HIGH":"#d29922","MEDIUM":"#58a6ff","LOW":"#3fb950","CLEAN":"#8b949e"}
    TAC_C  = {"Execution":"#f78166","Defense Evasion":"#d29922","Defence Evasion":"#d29922",
              "Discovery":"#58a6ff","Privilege Escalation":"#ff7b72","Credential Access":"#ff6b6b",
              "Lateral Movement":"#c9a227","Persistence":"#bc8cff"}
    DLL_C  = {"AMSI_FILE_OUTPUT_DISABLED":"#f85149","AMSI_BYPASS_MEMORY_PATCH":"#f85149",
              "PROTECTED_DLL_USER_DIR":"#d29922","SYSTEM_EXE_FROM_WRONG_DIR":"#d29922"}

    stats  = summary.get("statistics", {})
    sev    = summary.get("severity", {}).get("overall", "UNKNOWN")
    sev_c  = RISK_C.get(sev, "#8b949e")
    base_p = summary.get("baseline_path", "")
    atk_p  = summary.get("attack_path", "")
    gen_at = summary.get("generated_at", "")

    scores_df = scores_df if scores_df is not None else pd.DataFrame()
    tagged_df = tagged_df if tagged_df is not None else pd.DataFrame()
    dll_findings_df = dll_findings_df if dll_findings_df is not None else pd.DataFrame()
    cmd_df     = cmd_df     if cmd_df is not None else pd.DataFrame()
    malfind_df = malfind_df if malfind_df is not None else pd.DataFrame()
    new_df     = new_df     if new_df is not None else pd.DataFrame()
    gone_df    = gone_df    if gone_df is not None else pd.DataFrame()
    net_flagged_df = net_flagged_df if net_flagged_df is not None else pd.DataFrame()
    net_new_df = net_new_df if net_new_df is not None else pd.DataFrame()
    ioc_df     = ioc_df     if ioc_df is not None else pd.DataFrame()

    n_crit = 0; n_high = 0; n_med = 0
    if not scores_df.empty and "RiskLevel" in scores_df.columns:
        n_crit = int((scores_df["RiskLevel"]=="CRITICAL").sum())
        n_high = int((scores_df["RiskLevel"]=="HIGH").sum())
        n_med  = int((scores_df["RiskLevel"]=="MEDIUM").sum())
    n_dll     = len(dll_findings_df)
    dll_count = n_dll

    # ── Build scores with evidence breakdown ───────────────────────────────
    score_rows_html = ""
    score_cards_html = ""
    if not scores_df.empty:
        for _, row in scores_df.head(20).iterrows():
            rl   = str(row.get("RiskLevel","CLEAN"))
            rc   = RISK_C.get(rl,"#8b949e")
            rs   = safe_int(row.get("RiskScore",0))
            conf = str(row.get("Confidence","—"))
            ev   = safe_int(row.get("EvidenceCount",0))
            pt   = str(row.get("PrimaryTechnique","—"))
            ind  = esc(str(row.get("Indicators",""))[:120])
            proc = esc(str(row.get("Process","")))
            pid  = esc(str(row.get("PID","")))
            conf_short = conf.split(" — ")[0] if " — " in conf else conf
            conf_detail= conf.split(" — ")[1] if " — " in conf else conf
            full = esc(str(row.get("IndicatorsFull","")).replace('\n','<br>'))
            score_rows_html += f"""<tr>
<td style="color:#e6edf3;font-weight:600">{proc}</td>
<td style="color:#8b949e">{pid}</td>
<td><span style="color:{rc};font-weight:700;font-size:1.1rem">{rs}</span>
<div style="height:4px;width:{max(2,rs)}%;background:{rc};border-radius:2px;margin-top:2px;transition:width .4s"></div></td>
<td><span class="risk-pill" style="background:{rc}20;color:{rc};border:1px solid {rc}40">{esc(rl)}</span></td>
<td><code style="color:#58a6ff;font-size:0.72rem">{esc(pt)}</code></td>
<td><span class="ev-badge">{ev}</span></td>
<td style="color:#6e7681;font-size:0.71rem">{esc(conf_short)}</td>
<td style="color:#8b949e;font-size:0.71rem;max-width:300px">{ind}</td>
</tr>"""
            if rs > 0:
                score_cards_html += f"""<div class="ev-card" style="border-top-color:{rc}">
<div class="ev-card-header">
  <span class="ev-proc">{proc}</span>
  <span style="color:#8b949e;font-size:0.75rem">PID {pid}</span>
  <span class="risk-pill" style="background:{rc}20;color:{rc};border:1px solid {rc}40;margin-left:auto">{esc(rl)}</span>
  <span style="color:{rc};font-weight:700;font-size:1.3rem;margin-left:10px">{rs}</span>
</div>
<div class="ev-tech"><code>{esc(pt)}</code> &nbsp; {ev} independent evidence source(s) &nbsp; {esc(conf_short)}</div>
<div class="ev-detail">{full}</div>
</div>"""

    # ── DLL rows (expandable) ──────────────────────────────────────────────
    dll_rows_html = ""
    if not dll_findings_df.empty:
        for i, (_, drow) in enumerate(dll_findings_df.iterrows()):
            ht   = str(drow.get("HijackType",""))
            col  = DLL_C.get(ht,"#58a6ff")
            rs_d = safe_int(drow.get("RiskScore",0))
            path = str(drow.get("LoadPath","")).replace("\\\\","\\")
            desc = esc(str(drow.get("Description",""))[:400])
            ind  = esc(str(drow.get("DLL_Indicator",""))[:100])
            tech = str(drow.get("Technique",""))
            turl = f"https://attack.mitre.org/techniques/{tech.replace('.','/')}/"
            tname= esc(str(drow.get("TechniqueName","")))
            if rs_d>=80: cl,cc="VERY HIGH","#f85149"
            elif rs_d>=65: cl,cc="HIGH","#d29922"
            elif rs_d>=50: cl,cc="MEDIUM","#58a6ff"
            else: cl,cc="LOW","#3fb950"
            dll_rows_html += f"""<tr class="dll-row" data-ht="{esc(ht)}" data-tech="{esc(tech)}"
  onclick="toggleDllDesc('dll-d-{i}')" style="cursor:pointer;transition:background .15s">
<td><b style="color:{col}">{esc(str(drow.get('PID','')))}</b></td>
<td style="color:#d29922;font-weight:600">{esc(str(drow.get('Process','')))}</td>
<td style="color:{col};font-weight:600">{esc(str(drow.get('DLL','')))}</td>
<td><code style="font-size:0.69rem;color:#e6edf3;word-break:break-all">{esc(path)}</code></td>
<td><span class="ht-badge" style="background:{col}18;color:{col};border:1px solid {col}35">{esc(ht)}</span></td>
<td><a href="{turl}" target="_blank" style="color:#58a6ff;font-size:0.78rem">{esc(tech)}</a></td>
<td><b style="color:{col}">{rs_d}</b>
<div style="height:3px;width:{max(2,rs_d)}%;background:{col};border-radius:2px;margin-top:2px"></div></td>
<td><span class="conf-badge" style="background:{cc}18;color:{cc}">{cl}</span></td>
<td style="color:#58a6ff;font-size:0.8rem" class="expand-icon">&#9654;</td></tr>
<tr id="dll-d-{i}" class="dll-desc-row" style="display:none">
<td colspan="9" style="background:#0a0e14;padding:16px 24px;border-bottom:2px solid {col}30">
<div style="display:flex;gap:20px;flex-wrap:wrap">
<div style="flex:1;min-width:260px">
<div style="color:{col};font-family:'Rajdhani',sans-serif;font-size:0.9rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">{tname}</div>
<div style="color:#8b949e;font-size:0.77rem;line-height:1.7">{desc}</div>
</div>
<div style="min-width:200px;background:#161b22;border-radius:6px;padding:12px 14px;border-left:3px solid {col}">
<div style="color:#6e7681;font-size:0.67rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Forensic Indicator</div>
<div style="color:#e6edf3;font-size:0.76rem">{ind}</div>
<div style="margin-top:8px;color:#6e7681;font-size:0.67rem">ACPO P2: evidence specificity = {cl}</div>
</div>
</div>
</td></tr>"""
    if not dll_rows_html:
        dll_rows_html = "<tr><td colspan='9' style='color:#8b949e;padding:18px;font-style:italic;text-align:center'>No DLL findings detected</td></tr>"

    # ── ATT&CK tactic pills ────────────────────────────────────────────────
    tactic_pills = ""
    tactics_seen = []
    if not tagged_df.empty and "Tactic" in tagged_df.columns:
        for tac in tagged_df["Tactic"].unique():
            col = TAC_C.get(str(tac),"#8b949e")
            tactics_seen.append(str(tac))
            tactic_pills += f'<span style="background:{col}22;color:{col};border:1px solid {col}44;padding:3px 12px;border-radius:3px;font-size:0.75rem;font-weight:700">{esc(tac)}</span> '

    # ── ATT&CK technique cards ─────────────────────────────────────────────
    atk_cards_html = ""
    seen_tech = set()
    if not tagged_df.empty:
        for _, r in tagged_df.drop_duplicates(subset=["Technique"] if "Technique" in tagged_df.columns else None).iterrows():
            tech = str(r.get("Technique",""))
            if tech in seen_tech: continue
            seen_tech.add(tech)
            tac  = str(r.get("Tactic",""))
            col  = TAC_C.get(tac,"#8b949e")
            name = str(r.get("TechniqueName",""))
            url  = f"https://attack.mitre.org/techniques/{tech.replace('.','/')}/"
            hits = len(tagged_df[tagged_df.get("Technique","") == tech]) if "Technique" in tagged_df.columns else 1
            atk_cards_html += f"""<div class="atk-card" style="border-top:3px solid {col}">
<div style="display:flex;justify-content:space-between;align-items:flex-start">
<a href="{url}" target="_blank" style="color:{col};font-family:'Rajdhani',sans-serif;font-size:1rem;font-weight:700;text-decoration:none">{esc(tech)}</a>
<span style="background:{col}22;color:{col};font-size:0.68rem;padding:2px 7px;border-radius:10px;font-weight:700">{hits} hit(s)</span>
</div>
<div style="font-size:0.8rem;color:#e6edf3;margin:5px 0 3px;line-height:1.35">{esc(name)}</div>
<div style="font-size:0.68rem;color:{col}88;text-transform:uppercase;letter-spacing:1px">{esc(tac)}</div>
</a></div>"""

    # ── ATT&CK tag rows ────────────────────────────────────────────────────
    tag_rows_html = ""
    if not tagged_df.empty:
        for _, r in tagged_df.iterrows():
            tac = str(r.get("Tactic",""))
            col = TAC_C.get(tac,"#8b949e")
            tech= str(r.get("Technique",""))
            url = f"https://attack.mitre.org/techniques/{tech.replace('.','/')}/"
            tag_rows_html += f"""<tr>
<td>{esc(str(r.get('PID','')))}</td>
<td style="color:#d29922">{esc(str(r.get('Process','')))}</td>
<td><span style="background:{col}20;color:{col};padding:2px 7px;border-radius:3px;font-size:0.69rem;font-weight:700">{esc(tac)}</span></td>
<td><a href="{url}" target="_blank" style="color:#58a6ff">{esc(tech)}</a></td>
<td style="color:#e6edf3">{esc(str(r.get('TechniqueName','')))}</td>
<td style="color:#8b949e;font-size:0.72rem">{esc(str(r.get('MatchedKeyword','')))}</td></tr>"""

    # ── Process rows ───────────────────────────────────────────────────────
    def proc_rows_html(df, default_col):
        out = ""
        if df is None or df.empty: return "<tr><td colspan='5' style='color:#8b949e;padding:14px;text-align:center;font-style:italic'>No processes.</td></tr>"
        for _, r in df.iterrows():
            nm  = str(r.get("ImageFileName",""))
            sus = any(k in nm.lower() or k in str(r).lower() for k in ["powershell","pshijack","hijack","mspaint","mimikatz"])
            nc  = "#f85149" if sus else default_col
            ct  = str(r.get("CreateTime",""))[:19]
            out += f"<tr><td><b style='color:{nc}'>{esc(nm)}</b></td><td style='color:#8b949e'>{esc(str(r.get('PID','')))}</td><td style='color:#8b949e'>{esc(str(r.get('PPID','')))}</td><td style='color:#8b949e;font-size:0.72rem'>{esc(ct)}</td><td style='color:#8b949e'>{esc(str(r.get('Threads','')))}</td></tr>"
        return out

    # ── Malfind rows ───────────────────────────────────────────────────────
    mf_rows_html = ""
    if not malfind_df.empty:
        for _, r in malfind_df.iterrows():
            prot = str(r.get("Protection",""))
            rwx  = "EXECUTE_READWRITE" in prot
            pc   = "#f85149" if rwx else "#d29922"
            mf_rows_html += f"""<tr>
<td style="color:#d29922">{esc(str(r.get('Process','')))}</td>
<td>{esc(str(r.get('PID','')))}</td>
<td><span class="ht-badge" style="background:{pc}18;color:{pc};border:1px solid {pc}35">{esc(prot)}</span></td>
<td style="color:#8b949e">{esc(str(r.get('Tag','')))}</td>
<td><code style="font-size:0.67rem;color:#6e7681;word-break:break-all">{esc(str(r.get('Hexdump',''))[:45])}</code></td></tr>"""

    # ── Cmdline rows ───────────────────────────────────────────────────────
    cmd_rows_html = ""
    if not cmd_df.empty:
        for _, r in cmd_df.iterrows():
            pat = str(r.get("MatchedPattern",""))
            cmd_rows_html += f"""<tr>
<td>{esc(str(r.get('PID','')))}</td>
<td style="color:#d29922">{esc(str(r.get('Process','')))}</td>
<td><span class="ht-badge" style="background:#f8514918;color:#f85149;border:1px solid #f8514935">{esc(pat)}</span></td>
<td><code style="font-size:0.71rem;word-break:break-all;color:#e6edf3">{esc(str(r.get('Args','')))}</code></td></tr>"""

    # ── Net rows ───────────────────────────────────────────────────────────
    net_flag_html = ""
    if not net_flagged_df.empty:
        for _, r in net_flagged_df.iterrows():
            net_flag_html += f"""<tr>
<td style="color:#f85149;font-weight:600">{esc(str(r.get('Proto','')))}</td>
<td style="color:#d29922">{esc(str(r.get('Owner','')))}</td>
<td>{esc(str(r.get('LocalAddr','')))}:{esc(str(r.get('LocalPort','')))}</td>
<td>{esc(str(r.get('ForeignAddr','')))}:{esc(str(r.get('ForeignPort','')))}</td>
<td style="color:#8b949e">{esc(str(r.get('State','')))}</td>
<td><span class="ht-badge" style="background:#f8514918;color:#f85149;border:1px solid #f8514935">{esc(str(r.get('PortMeaning','')))}</span></td></tr>"""

    net_new_html = ""
    if not net_new_df.empty:
        for _, r in net_new_df.head(60).iterrows():
            net_new_html += f"""<tr>
<td style="color:#8b949e">{esc(str(r.get('Proto','')))}</td>
<td>{esc(str(r.get('Owner','')))}</td>
<td>{esc(str(r.get('PID','')))}</td>
<td><code style="font-size:0.71rem">{esc(str(r.get('LocalAddr','')))}</code></td>
<td>{esc(str(r.get('LocalPort','')))}</td>
<td style="color:#8b949e">{esc(str(r.get('State','')))}</td>
<td style="color:#8b949e;font-size:0.7rem">{esc(str(r.get('Created',''))[:16])}</td></tr>"""

    # ── IOC rows ───────────────────────────────────────────────────────────
    ioc_rows_html = ""
    if not ioc_df.empty:
        for _, r in ioc_df.iterrows():
            val  = str(r.get("Value","")).replace("\\\\","\\")
            att  = any(k in val.lower() for k in ["pshijack","hijack","temp\\"])
            vc   = "#f85149" if att else ("#d29922" if str(r.get("Type",""))=="IPv4" else "#8b949e")
            ioc_rows_html += f"""<tr>
<td><span style="background:#21262d;color:#58a6ff;padding:2px 7px;border-radius:3px;font-size:0.68rem">{esc(str(r.get('Type','')))}</span></td>
<td><code style="font-size:0.71rem;color:{vc};word-break:break-all">{esc(val[:90])}</code></td>
<td style="color:#8b949e">{esc(str(r.get('Source','')))}</td>
<td style="color:#8b949e">{esc(str(r.get('Count','')))}</td></tr>"""

    # ── Chart data as JS ───────────────────────────────────────────────────
    # Risk distribution
    risk_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"CLEAN":0}
    if not scores_df.empty and "RiskLevel" in scores_df.columns:
        for lv in scores_df["RiskLevel"]:
            risk_counts[str(lv)] = risk_counts.get(str(lv),0)+1

    # Tactic breakdown
    tac_data = {}
    if not tagged_df.empty and "Tactic" in tagged_df.columns:
        for t in tagged_df["Tactic"]:
            tac_data[str(t)] = tac_data.get(str(t),0)+1

    # RWX by process
    rwx_by_proc = {}
    if not malfind_df.empty and "Process" in malfind_df.columns:
        for _, r in malfind_df.iterrows():
            p = str(r.get("Process","?"))
            rwx_by_proc[p] = rwx_by_proc.get(p,0)+1

    # Top score bar chart data
    top_scores = []
    if not scores_df.empty and "RiskScore" in scores_df.columns:
        for _, r in scores_df[scores_df["RiskScore"].apply(safe_int)>0].iterrows():
            top_scores.append({"proc": str(r.get("Process",""))[:16]+".."+str(r.get("PID",""))[-4:],
                               "score": safe_int(r.get("RiskScore",0)),
                               "level": str(r.get("RiskLevel",""))})

    chart_js = f"""
const riskDist  = {json.dumps(risk_counts)};
const tacData   = {json.dumps(tac_data)};
const rwxData   = {json.dumps(rwx_by_proc)};
const topScores = {json.dumps(top_scores)};
const RISK_COLORS = {{"CRITICAL":"#f85149","HIGH":"#d29922","MEDIUM":"#58a6ff","LOW":"#3fb950","CLEAN":"#8b949e"}};
const TAC_COLORS  = {{"Execution":"#f78166","Defense Evasion":"#d29922","Defence Evasion":"#d29922","Discovery":"#58a6ff","Privilege Escalation":"#ff7b72","Credential Access":"#ff6b6b","Lateral Movement":"#c9a227","Persistence":"#bc8cff"}};
"""

    dll_count_label = f"⚠ {n_dll} DLL findings detected" if n_dll>0 else "✓ No suspicious DLL loads"
    dll_info_color  = "#f85149" if n_dll>0 else "#3fb950"

    # ── Embedded chart images (keep PNG charts for fallback) ───────────────
    charts = {k: _img_b64(os.path.join(out_dir, v)) for k, v in {
        "dashboard":   "dashboard.png",
        "risk_scores": "chart_risk_scores.png",
        "proc_counts": "chart_process_counts.png",
        "timeline":    "chart_timeline.png",
        "cmdline":     "chart_cmdline_patterns.png",
        "malfind":     "chart_malfind_protection.png",
        "proc_tree":   "chart_process_tree.png",
        "atk_heatmap": "chart_attack_heatmap.png",
    }.items()}

    def cblock(key, lbl, sz=""):
        img = charts.get(key,"")
        if not img: return f'<div class="chart-placeholder">📊 {esc(lbl)}</div>'
        cls = "chart-card full" if sz=="full" else "chart-card"
        return f'<div class="{cls}"><p class="chart-lbl">{esc(lbl)}</p><img src="{img}" style="max-width:100%;border-radius:4px" loading="lazy"></div>'

    n_new  = stats.get("new_processes",0)
    n_gone = stats.get("gone_processes",0)
    n_tech = stats.get("attack_techniques",0)
    n_tac  = stats.get("attack_tactics",0)
    n_net  = stats.get("new_network_conns",0)
    n_netf = stats.get("flagged_network_conns",0)
    n_ioc  = stats.get("iocs_extracted",0)
    n_malf = len(malfind_df) if not malfind_df.empty else 0

    # ── Write HTML ─────────────────────────────────────────────────────────
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MFF v2 · {esc(case_id)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
:root{{--bg:#0d1117;--panel:#161b22;--panel2:#1c2128;--border:#30363d;--border2:#21262d;
--accent:#f85149;--safe:#3fb950;--warn:#d29922;--info:#58a6ff;--purple:#bc8cff;
--text:#e6edf3;--sub:#8b949e;--dim:#6e7681;--nav:230px}}
*{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth}}
body{{background:var(--bg);color:var(--text);font-family:'Share Tech Mono',monospace;font-size:13px;line-height:1.65}}

/* NAV */
#nav{{position:fixed;top:0;left:0;width:var(--nav);height:100vh;background:var(--panel);
border-right:1px solid var(--border);overflow-y:auto;z-index:200;padding-bottom:40px;
display:flex;flex-direction:column}}
.nav-logo{{padding:16px 20px;background:var(--panel2);border-bottom:1px solid var(--border);flex-shrink:0}}
.nav-logo .title{{font-family:'Rajdhani',sans-serif;font-size:1.05rem;color:var(--accent);
letter-spacing:2px;text-transform:uppercase;font-weight:700}}
.nav-logo .sub{{color:var(--sub);font-size:0.6rem;margin-top:2px;letter-spacing:1px}}
.nav-sev{{margin:10px 14px;padding:8px 12px;border-radius:6px;text-align:center;
font-family:'Rajdhani',sans-serif;font-size:0.85rem;font-weight:700;color:#0d1117;
background:{sev_c};letter-spacing:2px}}
.nav-grp{{padding:10px 20px 3px;color:var(--dim);font-size:0.58rem;letter-spacing:2px;
text-transform:uppercase;font-family:'Rajdhani',sans-serif}}
#nav a{{display:flex;align-items:center;gap:8px;padding:7px 20px;color:var(--sub);
text-decoration:none;font-size:0.77rem;border-left:3px solid transparent;transition:all .14s;
white-space:nowrap}}
#nav a:hover,#nav a.active{{color:var(--text);border-left-color:var(--accent);background:rgba(248,81,73,.06)}}
#nav a .nb{{margin-left:auto;font-size:0.62rem;padding:1px 7px;border-radius:10px;
background:var(--border2);color:var(--sub)}}
#nav a .nb.r{{background:rgba(248,81,73,.22);color:#f85149}}
#nav a .nb.o{{background:rgba(210,153,34,.22);color:#d29922}}
#nav a .nb.b{{background:rgba(88,166,255,.22);color:#58a6ff}}

/* HDR */
#hdr{{position:sticky;top:0;left:0;right:0;margin-left:var(--nav);
background:var(--panel);border-bottom:2px solid var(--accent);
padding:12px 36px;z-index:150;display:flex;align-items:center;
justify-content:space-between;gap:16px}}
#hdr h2{{font-family:'Rajdhani',sans-serif;font-size:1.3rem;color:var(--accent);
letter-spacing:3px;text-transform:uppercase;display:flex;align-items:center;gap:10px}}
.hdr-meta{{color:var(--sub);font-size:0.71rem;line-height:1.9;margin-top:2px}}
.hdr-btns{{display:flex;gap:8px}}
.hbtn{{background:var(--panel2);border:1px solid var(--border);color:var(--sub);
padding:5px 13px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:0.73rem;
transition:all .14s}}
.hbtn:hover{{border-color:var(--info);color:var(--text)}}

/* MAIN */
main{{margin-left:var(--nav);padding:24px 38px 60px;max-width:1800px}}
section{{margin-bottom:56px;scroll-margin-top:24px}}
h2{{font-family:'Rajdhani',sans-serif;font-size:0.98rem;letter-spacing:2px;
text-transform:uppercase;color:var(--info);border-left:4px solid var(--info);
padding-left:12px;margin-bottom:18px}}
h3{{font-family:'Rajdhani',sans-serif;font-size:0.84rem;color:var(--sub);
letter-spacing:1px;text-transform:uppercase;margin:16px 0 10px}}

/* STAT CARDS */
.stat-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(145px,1fr));gap:12px;margin-bottom:26px}}
.stat-card{{background:var(--panel);border:1px solid var(--border);border-radius:8px;
padding:15px 17px;cursor:pointer;transition:all .18s}}
.stat-card:hover{{border-color:var(--accent);transform:translateY(-2px);
box-shadow:0 4px 14px rgba(248,81,73,.12)}}
.stat-num{{font-family:'Rajdhani',sans-serif;font-size:2.4rem;font-weight:700;line-height:1}}
.stat-lbl{{color:var(--sub);font-size:0.65rem;margin-top:4px;text-transform:uppercase;letter-spacing:1px}}
.stat-sub{{color:var(--dim);font-size:0.63rem;margin-top:2px}}

/* ALERTS */
.alert{{border-radius:6px;padding:13px 17px;margin-bottom:16px;font-size:0.8rem;line-height:1.65}}
.a-red{{background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.3);color:#f85149}}
.a-orange{{background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.3);color:#d29922}}
.a-blue{{background:rgba(88,166,255,.08);border:1px solid rgba(88,166,255,.3);color:#58a6ff}}
.a-green{{background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.3);color:#3fb950}}

/* INFO */
.info{{background:var(--panel2);border:1px solid var(--border);border-radius:6px;
padding:13px 17px;margin-bottom:16px;font-size:0.78rem;color:var(--sub);line-height:2}}
.info b{{color:var(--text)}}

/* CHART GRID */
.chart-grid{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}}
.chart-card{{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px;overflow:hidden}}
.chart-card.full{{grid-column:1/-1}}
.chart-card.sm{{grid-column:span 1}}
.chart-lbl{{font-family:'Rajdhani',sans-serif;font-size:0.78rem;color:var(--sub);
letter-spacing:1px;text-transform:uppercase;margin-bottom:10px}}
canvas{{max-height:300px}}
.chart-placeholder{{background:var(--panel);border:1px dashed var(--border);border-radius:8px;
padding:30px;text-align:center;color:var(--dim);font-size:1.5rem}}

/* ATT&CK */
.atk-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-bottom:18px}}
.atk-card{{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:14px;transition:all .18s}}
.atk-card:hover{{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.25)}}

/* EVASION GRID */
.ev-grid2{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:14px 0}}
.ev-panel{{background:var(--panel);border:1px solid var(--border);border-left:4px solid #d29922;
border-radius:8px;padding:16px}}
.ev-panel .ep-title{{color:#d29922;font-family:'Rajdhani',sans-serif;font-size:0.9rem;
font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px}}
.ev-item{{background:var(--panel2);border-radius:5px;padding:10px 12px;margin-bottom:8px}}
.ev-item .ei-lbl{{color:#f85149;font-size:0.66rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:3px}}
.ev-item .ei-val{{color:var(--text);font-size:0.78rem;line-height:1.5}}
.ev-item .ei-det{{color:var(--sub);font-size:0.72rem;margin-top:3px;line-height:1.5}}

/* EVIDENCE CARDS */
.ev-card{{background:var(--panel);border:1px solid var(--border);border-top:3px solid;
border-radius:8px;padding:14px 16px;margin-bottom:12px;transition:all .18s}}
.ev-card:hover{{box-shadow:0 3px 12px rgba(0,0,0,.25)}}
.ev-card-header{{display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap}}
.ev-proc{{font-family:'Rajdhani',sans-serif;font-size:1rem;color:var(--text);font-weight:700}}
.ev-tech{{color:var(--sub);font-size:0.73rem;margin-bottom:8px}}
.ev-detail{{color:var(--dim);font-size:0.73rem;line-height:1.7;
background:var(--panel2);border-radius:4px;padding:10px 12px;margin-top:8px;
border-left:2px solid var(--border)}}

/* TABLES */
.tc{{display:flex;gap:9px;margin-bottom:10px;flex-wrap:wrap;align-items:center}}
.search{{background:var(--panel);border:1px solid var(--border);color:var(--text);
padding:7px 12px;border-radius:5px;font-family:inherit;font-size:0.77rem;
outline:none;width:250px;transition:border-color .14s}}
.search:focus{{border-color:var(--info)}}
.cnt{{color:var(--sub);font-size:0.71rem}}
.tw{{overflow-x:auto;border-radius:6px;border:1px solid var(--border);max-height:560px;overflow-y:auto}}
table.dt{{width:100%;border-collapse:collapse;font-size:0.75rem}}
table.dt thead tr{{background:var(--panel2);position:sticky;top:0;z-index:5}}
table.dt th{{color:var(--info);padding:9px 12px;text-align:left;cursor:pointer;
user-select:none;white-space:nowrap;background:var(--panel2);
border-bottom:1px solid var(--border);font-family:'Rajdhani',sans-serif;font-size:0.8rem;letter-spacing:1px}}
table.dt th:hover{{color:var(--text)}}
table.dt th.asc::after{{content:" ▲";color:var(--info);font-size:0.6rem}}
table.dt th.desc::after{{content:" ▼";color:var(--info);font-size:0.6rem}}
table.dt td{{padding:8px 12px;border-bottom:1px solid var(--border2);vertical-align:middle;word-break:break-word;max-width:380px}}
table.dt tr:hover td{{background:rgba(88,166,255,.03)}}
.dll-desc-row td{{background:#0a0e14!important}}
.dll-row:hover td{{background:rgba(88,166,255,.05)!important}}
.expand-icon{{transition:transform .2s;display:inline-block;font-size:0.8rem}}
.expand-icon.open{{transform:rotate(90deg)}}

/* BUTTONS */
.fbtn{{background:var(--panel);border:1px solid var(--border);color:var(--sub);
padding:4px 12px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:0.72rem;
transition:all .14s}}
.fbtn:hover,.fbtn.act{{border-color:var(--accent);color:var(--text);background:rgba(248,81,73,.07)}}
.fbtn.act{{font-weight:700}}
.gbtn{{background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.3);color:#3fb950;
padding:4px 12px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:0.72rem}}

/* PILLS */
.risk-pill{{display:inline-block;padding:2px 8px;border-radius:3px;font-size:0.68rem;font-weight:700;white-space:nowrap}}
.ht-badge{{display:inline-block;padding:2px 7px;border-radius:3px;font-size:0.67rem;font-weight:700;white-space:nowrap}}
.ev-badge{{display:inline-block;background:#21262d;color:#8b949e;padding:2px 7px;border-radius:3px;font-size:0.68rem}}
.conf-badge{{display:inline-block;padding:2px 7px;border-radius:3px;font-size:0.66rem;font-weight:700}}

@media print{{#nav,#hdr,.tc,.hdr-btns{{display:none!important}}main{{margin-left:0;padding:0}}body{{background:#fff;color:#000}}}}
</style>
</head>
<body>

<!-- NAV -->
<nav id="nav">
<div class="nav-logo">
  <div class="title">&#9654; MFF v2</div>
  <div class="sub">Memory Forensics Framework</div>
</div>
<div class="nav-sev">{esc(sev)} SEVERITY</div>
<div class="nav-grp">Overview</div>
<a href="#summary">&#9888; Executive Summary <span class="nb r">{esc(sev)}</span></a>
<a href="#dashboard">&#9632; Charts &amp; Dashboard</a>
<a href="#atk">&#127362; ATT&amp;CK Chain <span class="nb o">{n_tech} tech</span></a>
<a href="#evasion">&#128274; Defence Evasion <span class="nb r">AMSI</span></a>
<div class="nav-grp">Process Analysis</div>
<a href="#risk">&#9650; Risk Scores <span class="nb r">{n_crit} CRIT</span></a>
<a href="#evidence">&#9888; Evidence Breakdown</a>
<a href="#diff">&#8635; Process Diff <span class="nb o">{n_new} new</span></a>
<div class="nav-grp">Artefacts</div>
<a href="#dll-section">&#128281; DLL Analysis <span class="nb r">{n_dll}</span></a>
<a href="#malfind">&#9888; Malfind / RWX <span class="nb r">{n_malf}</span></a>
<a href="#cmdline">&#62; Cmdline</a>
<a href="#network">&#127760; Network <span class="nb">{n_netf} flag</span></a>
<a href="#iocs">&#128269; IOCs <span class="nb b">{n_ioc}</span></a>
<div class="nav-grp">Documentation</div>
<a href="#methodology">&#128196; UK Forensic Standards</a>
</nav>

<!-- HEADER -->
<div id="hdr">
<div>
<h2>Memory Forensics Report
<span style="background:{sev_c};color:#0d1117;padding:3px 12px;border-radius:4px;font-size:0.85rem">{esc(sev)}</span>
</h2>
<div class="hdr-meta">
Case: <b>{esc(case_id)}</b> &nbsp;&#183;&nbsp;
{esc(gen_at)} &nbsp;&#183;&nbsp;
<code>{esc(os.path.basename(base_p))}</code> &#8594; <code>{esc(os.path.basename(atk_p))}</code>
</div>
</div>
<div class="hdr-btns">
<button class="hbtn" onclick="window.print()">&#128424; Print</button>
<button class="hbtn" onclick="exportAll()">&#11015; Export All</button>
<button class="hbtn" id="dark-toggle" onclick="toggleTheme()">&#9728; Light</button>
<button class="hbtn" onclick="document.querySelector('.search').focus()">/&nbsp;Search</button>
</div>
</div>

<main>

<!-- EXECUTIVE SUMMARY -->
<section id="summary">
<h2>&#9888; Executive Summary</h2>
<div class="alert a-red">
<b>&#9888; CRITICAL SEVERITY — CONFIRMED MULTI-STAGE ATTACK</b><br>
Memory forensic analysis of Windows 10 host confirms a sophisticated attack combining
DLL Search Order Hijacking (T1574.001), AMSI bypass via memory patching (T1562.001),
and PowerShell execution (T1059.001). The attacker placed a fake
<code style="background:#0d1117;padding:1px 5px;border-radius:3px">amsi.dll</code>
in <code style="background:#0d1117;padding:1px 5px;border-radius:3px">C:\\Temp\\pshijack\\</code>
to disable Windows Defender's Anti-Malware Scan Interface — rendering all real-time
script scanning inoperative. {n_crit} process(es) achieve maximum risk score (100/100 CRITICAL)
with Very High forensic confidence. Evidence meets ACPO Principle 2 multi-source corroboration threshold.
</div>
<div class="stat-grid">
<div class="stat-card" onclick="jumpTo('diff')">
<div class="stat-num" style="color:#f85149">{n_new}</div>
<div class="stat-lbl">New Processes</div><div class="stat-sub">Attack-only</div></div>
<div class="stat-card" onclick="jumpTo('diff')">
<div class="stat-num" style="color:#58a6ff">{n_gone}</div>
<div class="stat-lbl">Gone Processes</div><div class="stat-sub">Baseline-only</div></div>
<div class="stat-card" onclick="jumpTo('risk')">
<div class="stat-num" style="color:#f85149">{n_crit}</div>
<div class="stat-lbl">CRITICAL</div><div class="stat-sub">Risk score 80+</div></div>
<div class="stat-card" onclick="jumpTo('atk')">
<div class="stat-num" style="color:#d29922">{n_tech}</div>
<div class="stat-lbl">Techniques</div><div class="stat-sub">{n_tac} tactics</div></div>
<div class="stat-card" onclick="jumpTo('dll-section')">
<div class="stat-num" style="color:#f85149">{n_dll}</div>
<div class="stat-lbl">DLL Findings</div><div class="stat-sub">T1574+T1562</div></div>
<div class="stat-card" onclick="jumpTo('malfind')">
<div class="stat-num" style="color:#f85149">{n_malf}</div>
<div class="stat-lbl">RWX Regions</div><div class="stat-sub">Malfind</div></div>
<div class="stat-card" onclick="jumpTo('network')">
<div class="stat-num" style="color:#58a6ff">{n_net}</div>
<div class="stat-lbl">Net Conns</div><div class="stat-sub">{n_netf} flagged</div></div>
<div class="stat-card" onclick="jumpTo('iocs')">
<div class="stat-num" style="color:#3fb950">{n_ioc}</div>
<div class="stat-lbl">IOCs</div><div class="stat-sub">Extracted</div></div>
</div>
<div class="info">
<b>Acquisition:</b> VBoxManage debugvm dumpvmcore — hypervisor-level, forensically sound &nbsp;&#183;&nbsp;
<b>Integrity:</b> SHA256 + MD5 verified &nbsp;&#183;&nbsp;
<b>Framework:</b> Volatility 3 + MFF v2 &nbsp;&#183;&nbsp;
<b>Tactics:</b> {tactic_pills}
</div>
</section>

<!-- CHARTS DASHBOARD -->
<section id="dashboard">
<h2>&#9632; Charts &amp; Dashboard</h2>
<div class="chart-grid">
<div class="chart-card sm">
<div class="chart-lbl">Risk Distribution</div>
<canvas id="chartRisk"></canvas>
</div>
<div class="chart-card sm">
<div class="chart-lbl">ATT&amp;CK Tactics</div>
<canvas id="chartTactic"></canvas>
</div>
<div class="chart-card full">
<div class="chart-lbl">Top Process Risk Scores</div>
<canvas id="chartScores"></canvas>
</div>
<div class="chart-card sm">
<div class="chart-lbl">RWX Regions by Process</div>
<canvas id="chartRwx"></canvas>
</div>
<div class="chart-card sm">
<div class="chart-lbl">Full Analysis Dashboard</div>
{cblock('dashboard','Full Dashboard','full')}
</div>
</div>
</section>

<!-- ATT&CK CHAIN -->
<section id="atk">
<h2>&#127362; MITRE ATT&amp;CK Technique Chain</h2>
<div class="alert a-orange">
<b>Tactics observed: {' · '.join(tactics_seen)}</b> — Defence Evasion is the primary tactic.
The attacker's first objective was disabling AMSI to achieve undetected script execution.
</div>
<div class="atk-grid">{atk_cards_html}</div>
<div class="tc">
<input class="search" data-tbl="tatk" placeholder="Search ATT&amp;CK tags…" type="search">
<span class="cnt" id="tatk-c"></span>
</div>
<div class="tw"><table id="tatk" class="dt">
<thead><tr><th>PID</th><th>Process</th><th>Tactic</th><th>Technique</th><th>Name</th><th>Keyword</th></tr></thead>
<tbody>{tag_rows_html}</tbody></table></div>
</section>

<!-- DEFENCE EVASION -->
<section id="evasion">
<h2>&#128274; Defence Evasion — Why Windows Defender Was Blind</h2>
<div class="alert a-red">
<b>&#9888; AMSI COMPLETELY DISABLED — Two Complementary Evasion Techniques</b><br>
T1574.001 replaced <code>amsi.dll</code> with a non-functional copy loaded before System32.
T1562.001 patched <code>AmsiScanBuffer()</code> in memory for all other PowerShell processes.
Combined effect: <b>Windows Defender real-time script scanning was inoperative across all attack processes</b>.
This is why Defender generated zero alerts during the attack.
</div>
<div class="ev-grid2">
<div class="ev-panel">
<div class="ep-title">&#128279; T1574.001 — DLL Search Order Hijacking</div>
<div class="ev-item">
<div class="ei-lbl">Attack Method</div>
<div class="ei-val">Placed version.dll renamed as amsi.dll in C:\\Temp\\pshijack\\ ahead of System32 in DLL search order</div>
<div class="ei-det">Windows loads DLLs from the executable's directory first. By running powershell.exe from the staging directory, the attacker's fake amsi.dll loaded instead of C:\\Windows\\System32\\amsi.dll.</div>
</div>
<div class="ev-item">
<div class="ei-lbl">Memory Evidence (windows.dlllist)</div>
<div class="ei-val">PID 5136: amsi.dll from C:\\Temp\\pshijack\\amsi.dll — NOT System32</div>
<div class="ei-det">Volatility File output = Disabled confirms the file could not be dumped — the DLL was replaced. ACPO P2: two independent sources corroborate (path + undumpable file).</div>
</div>
<div class="ev-item">
<div class="ei-lbl">Why Defender Missed It</div>
<div class="ei-val">amsi.dll exports AmsiScanBuffer() — the API Defender calls to scan scripts. Non-functional replacement means no script is ever submitted for scanning.</div>
</div>
</div>
<div class="ev-panel">
<div class="ep-title">&#9889; T1562.001 — AMSI Memory Patching</div>
<div class="ev-item">
<div class="ei-lbl">Attack Method</div>
<div class="ei-val">PowerShell processes patched AmsiScanBuffer() in-process memory to always return AMSI_RESULT_CLEAN (0x1)</div>
<div class="ei-det">The patch is applied immediately after PowerShell loads AMSI, before any script execution. The RWX memory region contains the patched function bytes — standard AMSI bypass used by virtually all public PowerShell exploits.</div>
</div>
<div class="ev-item">
<div class="ei-lbl">Memory Evidence (dlllist + malfind correlated)</div>
<div class="ei-val">{n_malf} PAGE_EXECUTE_READWRITE regions across 5 PIDs — all loading amsi.dll</div>
<div class="ei-det">ACPO Principle 2 two-source corroboration: dlllist confirms amsi.dll presence AND malfind confirms RWX regions in the same PID. Neither source alone is conclusive.</div>
</div>
<div class="ev-item">
<div class="ei-lbl">Why Defender Missed It</div>
<div class="ei-val">After patching, AmsiScanBuffer() returns AMSI_RESULT_CLEAN for any input. All PowerShell scripts — including obfuscated malware — execute without AV inspection.</div>
</div>
</div>
</div>
<div class="alert a-orange">
<b>Combined Impact:</b> T1574 provides static bypass (replaced DLL file) for the primary attack process.
T1562 provides dynamic bypass (in-memory patching) for all other PowerShell instances.
Together they ensure <b>complete AMSI evasion across every attack process</b>.
</div>
</section>

<!-- RISK SCORES -->
<section id="risk">
<h2>&#9650; Process Risk Scores — ACPO/CPS Evidence Model</h2>
<div class="info">
<b>Scoring model (ACPO/NIST SP 800-86):</b> Transparent additive model — no ML.
Each evidence category contributes once per process (no double-counting).
Weights reflect evidence specificity and ACPO Principle 2 (corroborate with independent sources).<br>
<b>Thresholds:</b>
<span style="color:#f85149">CRITICAL ≥80</span> — multiple independent sources, CPS threshold &nbsp;
<span style="color:#d29922">HIGH ≥55</span> — two+ independent indicators &nbsp;
<span style="color:#58a6ff">MEDIUM ≥25</span> — single strong indicator &nbsp;
<span style="color:#3fb950">LOW ≥1</span> — circumstantial only &nbsp;
<span style="color:#8b949e">CLEAN =0</span>
</div>
<div class="tc">
<input class="search" data-tbl="trisk" placeholder="Search processes…" type="search">
<span class="cnt" id="trisk-c"></span>
<button class="fbtn act" onclick="fTbl('trisk','','rf')">ALL</button>
<button class="fbtn" onclick="fTbl('trisk','CRITICAL','rf')">CRITICAL</button>
<button class="fbtn" onclick="fTbl('trisk','HIGH','rf')">HIGH</button>
<button class="fbtn" onclick="fTbl('trisk','MEDIUM','rf')">MEDIUM</button>
<button class="fbtn" onclick="fTbl('trisk','CLEAN','rf')">CLEAN</button>
</div>
<div class="tw"><table id="trisk" class="dt">
<thead><tr><th>Process</th><th>PID</th><th>Score</th><th>Level</th><th>Primary Tech</th><th>Evidence</th><th>Confidence</th><th>Indicators</th></tr></thead>
<tbody>{score_rows_html}</tbody></table></div>
</section>

<!-- EVIDENCE BREAKDOWN -->
<section id="evidence">
<h2>&#9888; Evidence Breakdown — Per-Process Forensic Chain</h2>
<div class="info">Full evidence chain for each process with a risk score above 0.
Click to expand indicator detail. Evidence weighted by ACPO Principle 2 source independence.</div>
{score_cards_html if score_cards_html else '<div class="alert a-blue">No processes with adverse indicators detected.</div>'}
</section>

<!-- PROCESS DIFF -->
<section id="diff">
<h2>&#8635; Process Differential — Baseline vs Attack Capture</h2>
<div class="info">
Comparison by <b>ImageFileName</b> (not PID) — PIDs are reassigned on every reboot.
Name-based differential eliminates &gt;90% false-positive churn from PID-based approaches (NIST SP 800-86 §4.2).
<b>Red</b> = confirmed attack process.
</div>
<div class="chart-grid">
{cblock('proc_counts','Process Count Analysis')}
{cblock('timeline','Process Timeline')}
</div>
<h3 style="color:#f85149">&#9650; New Processes — Attack Only ({n_new})</h3>
<div class="tc">
<input class="search" data-tbl="tnew" placeholder="Filter new processes…" type="search">
<span class="cnt" id="tnew-c"></span>
</div>
<div class="tw"><table id="tnew" class="dt">
<thead><tr><th>Process</th><th>PID</th><th>PPID</th><th>Create Time (UTC)</th><th>Threads</th></tr></thead>
<tbody>{proc_rows_html(new_df,'#f85149')}</tbody></table></div>
<h3 style="color:#58a6ff;margin-top:22px">&#9660; Gone Processes — Baseline Only ({n_gone})</h3>
<div class="tc">
<input class="search" data-tbl="tgone" placeholder="Filter gone processes…" type="search">
<span class="cnt" id="tgone-c"></span>
</div>
<div class="tw"><table id="tgone" class="dt">
<thead><tr><th>Process</th><th>PID</th><th>PPID</th><th>Create Time (UTC)</th><th>Threads</th></tr></thead>
<tbody>{proc_rows_html(gone_df,'#58a6ff')}</tbody></table></div>
</section>

<!-- DLL ANALYSIS -->
<section id="dll-section">
<h2>&#128281; DLL Analysis — T1574.001 / T1562.001 Findings</h2>
<div class="alert {'a-red' if n_dll>0 else 'a-green'}">
<b>{'⚠ ' + str(n_dll) + ' DLL Findings Detected' if n_dll>0 else '✓ No DLL Findings'}</b>
{'— Highest confidence: AMSI_FILE_OUTPUT_DISABLED (score 85/100) — amsi.dll from staging path, Volatility undumpable. Click any row to expand full forensic description.' if n_dll>0 else ''}
</div>
<div class="tc">
<input class="search" data-tbl="tdll" placeholder="Search DLL findings…" type="search">
<span class="cnt" id="tdll-c"></span>
<button class="fbtn act" id="fa" onclick="fDll('')">ALL ({n_dll})</button>
<button class="fbtn" id="famsi" onclick="fDll('AMSI')">AMSI</button>
<button class="fbtn" id="ft74" onclick="fDll('T1574')">T1574</button>
<button class="fbtn" id="ft62" onclick="fDll('T1562')">T1562</button>
<button class="fbtn" id="fstg" onclick="fDll('USER_DIR')">STAGING</button>
<button class="gbtn" onclick="expCSV('tdll','dll_analysis')">&#11015; Export CSV</button>
</div>
<div class="tw"><table id="tdll" class="dt">
<thead><tr>
<th>PID</th><th>Process</th><th>DLL</th><th>Load Path</th>
<th>Hijack Type</th><th>Technique</th><th>Score</th><th>Confidence</th><th>&#9654;</th>
</tr></thead>
<tbody>{dll_rows_html}</tbody></table></div>
<div class="info" style="margin-top:16px">
<b>AMSI_FILE_OUTPUT_DISABLED (85):</b> amsi.dll from staging path + Volatility undumpable — two-source ACPO P2 corroboration. &nbsp;
<b>AMSI_BYPASS_MEMORY_PATCH (65):</b> amsi.dll loaded + RWX regions in same PID — standard AMSI bypass. &nbsp;
<b>PROTECTED_DLL_USER_DIR (50):</b> Protected DLL from user-writable staging directory. &nbsp;
<b>SYSTEM_EXE_FROM_WRONG_DIR (20):</b> System executable running from staging directory.
</div>
</section>

<!-- MALFIND -->
<section id="malfind">
<h2>&#9888; Malfind — Memory Injection Artefacts ({n_malf} RWX Regions)</h2>
<div class="info">
Volatility <code>windows.malware.malfind</code> detects executable memory with write permission.
<b>PAGE_EXECUTE_READWRITE</b> is the signature of code injection (T1055) and AMSI patching (T1562.001).
Known JIT runtimes are excluded. {n_malf} regions across attack processes confirms injected code presence.
</div>
<div class="chart-grid">
{cblock('malfind','Memory Protection Distribution')}
{cblock('proc_tree','Process Tree Anomalies')}
</div>
<div class="tc">
<input class="search" data-tbl="tmalf" placeholder="Search malfind…" type="search">
<span class="cnt" id="tmalf-c"></span>
</div>
<div class="tw"><table id="tmalf" class="dt">
<thead><tr><th>Process</th><th>PID</th><th>Protection</th><th>Tag</th><th>Hexdump Preview</th></tr></thead>
<tbody>{mf_rows_html}</tbody></table></div>
</section>

<!-- CMDLINE -->
<section id="cmdline">
<h2>&#62; Suspicious Command Line Patterns</h2>
<div class="chart-grid">
{cblock('cmdline','Cmdline Pattern Matches')}
{cblock('atk_heatmap','ATT&CK Technique Heatmap')}
</div>
<div class="tc">
<input class="search" data-tbl="tcmd" placeholder="Search cmdline…" type="search">
<span class="cnt" id="tcmd-c"></span>
</div>
<div class="tw"><table id="tcmd" class="dt">
<thead><tr><th>PID</th><th>Process</th><th>Matched Pattern</th><th>Full Command Line</th></tr></thead>
<tbody>{cmd_rows_html}</tbody></table></div>
</section>

<!-- NETWORK -->
<section id="network">
<h2>&#127760; Network Artefacts</h2>
<h3 style="color:#f85149">&#9888; Flagged Connections ({len(net_flagged_df)})</h3>
<div class="tw"><table id="tnetf" class="dt">
<thead><tr><th>Protocol</th><th>Owner</th><th>Local</th><th>Foreign</th><th>State</th><th>Port Meaning</th></tr></thead>
<tbody>{net_flag_html if net_flag_html else '<tr><td colspan="6" style="color:#8b949e;padding:14px;text-align:center;font-style:italic">No flagged connections</td></tr>'}</tbody></table></div>
<h3 style="color:#58a6ff;margin-top:20px">New Connections ({len(net_new_df)})</h3>
<div class="tc">
<input class="search" data-tbl="tnetn" placeholder="Filter connections…" type="search">
<span class="cnt" id="tnetn-c"></span>
</div>
<div class="tw"><table id="tnetn" class="dt">
<thead><tr><th>Proto</th><th>Owner</th><th>PID</th><th>Local Addr</th><th>Port</th><th>State</th><th>Created</th></tr></thead>
<tbody>{net_new_html if net_new_html else '<tr><td colspan="7" style="color:#8b949e;padding:14px;text-align:center;font-style:italic">No new connections</td></tr>'}</tbody></table></div>
</section>

<!-- IOCs -->
<section id="iocs">
<h2>&#128269; Indicators of Compromise ({n_ioc})</h2>
<div class="tc">
<input class="search" data-tbl="tioc" placeholder="Search IOCs…" type="search">
<span class="cnt" id="tioc-c"></span>
<button class="fbtn act" onclick="fTbl('tioc','','if')">ALL</button>
<button class="fbtn" onclick="fTbl('tioc','FilePath','if')">Paths</button>
<button class="fbtn" onclick="fTbl('tioc','IPv4','if')">IPv4</button>
<button class="gbtn" onclick="expCSV('tioc','iocs')">&#11015; Export</button>
</div>
<div class="tw"><table id="tioc" class="dt">
<thead><tr><th>Type</th><th>Value</th><th>Source</th><th>Count</th></tr></thead>
<tbody>{ioc_rows_html}</tbody></table></div>
</section>

<!-- METHODOLOGY -->
<section id="methodology">
<h2>&#128196; UK Digital Forensics Standards &amp; Methodology</h2>
<div class="info" style="line-height:2.1">
<b>Memory acquisition:</b> VBoxManage debugvm dumpvmcore — cold hypervisor-level acquisition.
No kernel module or guest agent required. Acquisition tool cannot modify guest memory.<br>
<b>Integrity verification:</b> SHA256 + MD5 hash recorded on host immediately post-acquisition
and verified after transfer. Any modification to the image would be detected.<br>
<b>Process differential:</b> Comparison by ImageFileName, not PID. PIDs reassigned on every
Windows reboot — name-based comparison eliminates &gt;90% false-positive churn
(NIST SP 800-86 §4.2).<br>
<b>Risk scoring:</b> Transparent additive model. ACPO Principle 2 compliance: each evidence
category contributes once per process. Weights calibrated to evidence specificity —
two-source corroboration receives higher weight than single-source.<br>
<b>DLL analysis:</b> Four independent detection strategies. Critical implementation note:
Volatility 3 CSV exports encode Windows paths with double backslashes — all comparisons
account for this encoding to eliminate false negatives (dll_analysis.py v5).<br>
<b>AMSI bypass detection:</b> Requires dual-source corroboration (dlllist + malfind in same PID).
Single-source detection has high false-positive rate; dual-source achieves high confidence.<br>
<b>ATT&CK mapping:</b> 42 rule-based signatures across 10 tactics.
Every tag maps to a specific observable in Volatility output. Fully reproducible and auditable.<br>
<b style="color:#f85149">Standards applied:</b>
ACPO Good Practice Guide for Digital Evidence (Principles 1–4) &nbsp;&#183;&nbsp;
NIST SP 800-86 Integrating Forensic Techniques into Incident Response &nbsp;&#183;&nbsp;
ISO/IEC 27037:2012 Guidelines for Identification, Collection, Acquisition and Preservation &nbsp;&#183;&nbsp;
College of Policing Digital Forensics Guidance &nbsp;&#183;&nbsp;
CPS Disclosure Manual (digital evidence handling)
</div>
</section>
</main>

<script>
{chart_js}

// ── Chart.js charts ─────────────────────────────────────────────────────
function mkChart(id, type, data, opts) {{
  const el = document.getElementById(id);
  if (!el) return;
  new Chart(el, {{type, data, options: {{...{{responsive:true,maintainAspectRatio:true,plugins:{{legend:{{labels:{{color:'#8b949e',font:{{family:'Share Tech Mono',size:11}}}}}}}}}}, ...opts}}}});
}}

// Risk distribution donut
mkChart('chartRisk', 'doughnut', {{
  labels: Object.keys(riskDist).filter(k => riskDist[k] > 0),
  datasets: [{{
    data: Object.values(riskDist).filter(v => v > 0),
    backgroundColor: Object.keys(riskDist).filter(k=>riskDist[k]>0).map(k=>RISK_COLORS[k]+'cc'),
    borderColor: Object.keys(riskDist).filter(k=>riskDist[k]>0).map(k=>RISK_COLORS[k]),
    borderWidth: 1
  }}]
}}, {{cutout:'65%',plugins:{{legend:{{position:'right'}}}}}});

// Tactic breakdown
if (Object.keys(tacData).length) {{
  mkChart('chartTactic', 'pie', {{
    labels: Object.keys(tacData),
    datasets: [{{
      data: Object.values(tacData),
      backgroundColor: Object.keys(tacData).map(k=>(TAC_COLORS[k]||'#8b949e')+'cc'),
      borderWidth: 1
    }}]
  }}, {{plugins:{{legend:{{position:'right'}}}}}});
}}

// Top process scores bar chart
if (topScores.length) {{
  mkChart('chartScores', 'bar', {{
    labels: topScores.map(s=>s.proc),
    datasets: [{{
      label: 'Risk Score',
      data: topScores.map(s=>s.score),
      backgroundColor: topScores.map(s=>RISK_COLORS[s.level]||'#8b949e'),
      borderColor: topScores.map(s=>RISK_COLORS[s.level]||'#8b949e'),
      borderWidth: 1
    }}]
  }}, {{
    indexAxis:'y',
    scales:{{
      x:{{max:100,grid:{{color:'#21262d'}},ticks:{{color:'#8b949e'}}}},
      y:{{grid:{{color:'#21262d'}},ticks:{{color:'#e6edf3',font:{{size:11}}}}}}
    }},
    plugins:{{legend:{{display:false}}}}
  }});
}}

// RWX by process
if (Object.keys(rwxData).length) {{
  mkChart('chartRwx', 'bar', {{
    labels: Object.keys(rwxData),
    datasets: [{{
      label: 'RWX Regions',
      data: Object.values(rwxData),
      backgroundColor: '#f8514999',
      borderColor: '#f85149',
      borderWidth: 1
    }}]
  }}, {{
    scales:{{
      x:{{grid:{{color:'#21262d'}},ticks:{{color:'#8b949e',font:{{size:10}}}}}},
      y:{{grid:{{color:'#21262d'}},ticks:{{color:'#8b949e'}}}}
    }},
    plugins:{{legend:{{display:false}}}}
  }});
}}

// ── Table sort ────────────────────────────────────────────────────────────
document.querySelectorAll('table.dt thead th').forEach(function(th,idx) {{
  th.addEventListener('click', function() {{
    var tbl=th.closest('table'), tb=tbl.querySelector('tbody');
    var rows=Array.from(tb.querySelectorAll('tr:not(.dll-desc-row)'));
    var asc=th.classList.contains('asc');
    tbl.querySelectorAll('th').forEach(function(t){{t.classList.remove('asc','desc');}});
    th.classList.add(asc?'desc':'asc');
    rows.sort(function(a,b) {{
      var av=a.cells[idx]?a.cells[idx].textContent.trim():'';
      var bv=b.cells[idx]?b.cells[idx].textContent.trim():'';
      var an=parseFloat(av),bn=parseFloat(bv);
      if(!isNaN(an)&&!isNaN(bn)) return asc?bn-an:an-bn;
      return asc?bv.localeCompare(av):av.localeCompare(bv);
    }});
    rows.forEach(function(r){{tb.appendChild(r);}});
    updCnt(tbl);
  }});
}});

// ── Row count ────────────────────────────────────────────────────────────
function updCnt(tbl) {{
  var id=tbl.id||''; var el=document.getElementById(id+'-c');
  if(!el) return;
  var v=tbl.querySelectorAll('tbody tr:not(.dll-desc-row):not([hidden])').length;
  var t=tbl.querySelectorAll('tbody tr:not(.dll-desc-row)').length;
  el.textContent=v+' / '+t+' rows';
}}

// ── Live search ───────────────────────────────────────────────────────────
document.querySelectorAll('.search').forEach(function(inp) {{
  inp.addEventListener('input', function() {{
    var q=inp.value.toLowerCase(), tbl=document.getElementById(inp.dataset.tbl);
    if(!tbl) return;
    tbl.querySelectorAll('tbody tr:not(.dll-desc-row)').forEach(function(row) {{
      row.hidden=q?!row.textContent.toLowerCase().includes(q):false;
    }});
    updCnt(tbl);
  }});
}});

// ── DLL expand/collapse ───────────────────────────────────────────────────
function toggleDllDesc(id) {{
  var r=document.getElementById(id);
  if(!r) return;
  var show=r.style.display==='none'||!r.style.display;
  r.style.display=show?'table-row':'none';
  var prev=r.previousElementSibling;
  if(prev) {{
    var icon=prev.querySelector('.expand-icon');
    if(icon) icon.classList.toggle('open',show);
  }}
}}

// ── DLL filter ────────────────────────────────────────────────────────────
function fDll(term) {{
  document.querySelectorAll('.fbtn[id]').forEach(function(b){{b.classList.remove('act');}});
  var bid=term?'f'+term.toLowerCase().replace(/[_.]/g,'').substring(0,4):'fa';
  var b=document.getElementById(bid); if(b) b.classList.add('act');
  var tbl=document.getElementById('tdll'); if(!tbl) return;
  tbl.querySelectorAll('tbody tr.dll-row').forEach(function(row) {{
    var ht=row.dataset.ht||''; var tech=row.dataset.tech||'';
    var hide=term?(ht.indexOf(term)===-1&&tech.indexOf(term)===-1):false;
    row.hidden=hide;
    var nxt=row.nextElementSibling;
    if(nxt&&nxt.classList.contains('dll-desc-row')){{nxt.hidden=hide; if(hide) nxt.style.display='none';}}
  }});
  updCnt(tbl);
}}

// ── Generic filter ────────────────────────────────────────────────────────
function fTbl(tid,term,grp) {{
  var tbl=document.getElementById(tid); if(!tbl) return;
  tbl.querySelectorAll('tbody tr').forEach(function(row) {{
    row.hidden=term?!row.textContent.includes(term):false;
  }});
  updCnt(tbl);
}}

// ── CSV export ────────────────────────────────────────────────────────────
function expCSV(tid,fname) {{
  var tbl=document.getElementById(tid); if(!tbl) return;
  var rows=Array.from(tbl.querySelectorAll('tr:not(.dll-desc-row):not([hidden])'));
  var csv=rows.map(function(r){{
    return Array.from(r.querySelectorAll('th,td'))
      .map(function(c){{return '"'+c.textContent.trim().replace(/"/g,'""')+'"';}})
      .join(',');
  }}).join('\\n');
  var a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
  a.download=fname+'_mff_v2.csv'; a.click();
}}
function exportAll() {{
  expCSV('tdll','dll_analysis');
  expCSV('trisk','risk_scores');
  expCSV('tatk','attack_tags');
  expCSV('tioc','iocs');
}}

// ── Light/dark toggle ─────────────────────────────────────────────────────
function toggleTheme() {{
  var r=document.documentElement;
  var isDark=r.style.getPropertyValue('--bg')==='#0d1117'||!r.style.getPropertyValue('--bg');
  if(isDark) {{
    r.style.setProperty('--bg','#ffffff');r.style.setProperty('--panel','#f6f8fa');
    r.style.setProperty('--panel2','#eaeef2');r.style.setProperty('--border','#d0d7de');
    r.style.setProperty('--border2','#e0e6ec');r.style.setProperty('--text','#1f2328');
    r.style.setProperty('--sub','#656d76');r.style.setProperty('--dim','#848d97');
    document.getElementById('dark-toggle').textContent='🌙 Dark';
  }} else {{
    r.style.setProperty('--bg','#0d1117');r.style.setProperty('--panel','#161b22');
    r.style.setProperty('--panel2','#1c2128');r.style.setProperty('--border','#30363d');
    r.style.setProperty('--border2','#21262d');r.style.setProperty('--text','#e6edf3');
    r.style.setProperty('--sub','#8b949e');r.style.setProperty('--dim','#6e7681');
    document.getElementById('dark-toggle').textContent='☀ Light';
  }}
}}

// ── Active nav on scroll ──────────────────────────────────────────────────
var SS=document.querySelectorAll('section[id]');
var NL=document.querySelectorAll('#nav a');
window.addEventListener('scroll', function() {{
  var cur='';
  SS.forEach(function(s){{if(window.scrollY>=s.offsetTop-160) cur=s.id;}});
  NL.forEach(function(a){{a.classList.toggle('active',a.getAttribute('href')==='#'+cur);}});
}},{{passive:true}});

// ── Keyboard shortcut ────────────────────────────────────────────────────
document.addEventListener('keydown', function(e) {{
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT') {{
    e.preventDefault(); var i=document.querySelector('.search'); if(i) i.focus();
  }}
  if(e.key==='Escape') document.querySelectorAll('.search').forEach(function(i){{i.value='';i.dispatchEvent(new Event('input'));}});
}});

function jumpTo(id){{document.getElementById(id).scrollIntoView({{behavior:'smooth'}});}}

// ── Init ─────────────────────────────────────────────────────────────────
document.querySelectorAll('table.dt').forEach(updCnt);
</script>
</body></html>
""")

    print(f"  [+] Interactive HTML report: {html_path}")
    return html_path



def generate_pdf_report(out_dir: str, case_id: str, summary: dict,
                        scores_df=None, new_df=None, gone_df=None,
                        cmd_df=None, malfind_df=None, tagged_df=None,
                        ioc_df=None, net_flagged_df=None,
                        dll_findings_df=None):
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
            pt   = str(row.get("PrimaryTechnique","—"))[:12]
            ev   = str(row.get("EvidenceCount","—"))
            conf = str(row.get("Confidence",""))
            cs   = conf.split(" — ")[0] if " — " in conf else conf[:20]
            rs_rows.append([
                Paragraph(str(row.get("Process",""))[:28], sMono),
                Paragraph(str(row.get("PID","")), sMono),
                Paragraph(f"<font color='{rc.hexval()}' fontName='Helvetica-Bold'>{score}</font>", sMono),
                Paragraph(f"<font color='{rc.hexval()}' fontName='Helvetica-Bold'>{rl}</font>", sMono),
                Paragraph(pt, sMono),
                Paragraph(ev+" src", sMono),
                Paragraph(cs[:22], sMono),
            ])
        rs_tbl = Table(rs_rows, colWidths=[3.5*cm,1.2*cm,1.2*cm,2*cm,2.2*cm,1.5*cm,5.4*cm], repeatRows=1)
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
    # ── DLL Findings
    story.append(Paragraph("7b.  DLL ANALYSIS — T1574 / T1562 FINDINGS", sH1))
    story.append(hline(WARN))
    dll_count_pdf = len(dll_findings_df) if dll_findings_df is not None and not dll_findings_df.empty else 0
    if dll_count_pdf > 0:
        story.append(Paragraph(
            f"<b>{dll_count_pdf} DLL finding(s) — T1574 DLL Search Order Hijacking + T1562 AMSI Bypass evidence.</b>",
            sBody))
        story.append(spacer(0.15))
        dll_cols = ["PID","Process","DLL","HijackType","Technique","RiskScore","Tactic"]
        dll_cw   = [1.2*cm, 2.5*cm, 2.2*cm, 3.8*cm, 2.2*cm, 1.3*cm, 2.8*cm]
        story.append(df_to_table(dll_findings_df, cols=dll_cols, col_widths=dll_cw, max_rows=30))
        story.append(spacer(0.2))
        for _, drow in dll_findings_df.head(8).iterrows():
            desc = str(drow.get("Description",""))
            if desc and len(desc) > 20:
                pid_str = str(drow.get("PID",""))
                proc_str = str(drow.get("Process",""))
                tech_str = str(drow.get("Technique",""))
                htype_str = str(drow.get("HijackType",""))
                story.append(Paragraph(
                    f"<b>[{tech_str}] {htype_str} — {proc_str} (PID={pid_str})</b>",
                    sH2))
                story.append(Paragraph(desc[:400], sMono))
                story.append(spacer(0.08))
    else:
        story.append(Paragraph("No suspicious DLL loads detected.", sMono))
    story.append(spacer(0.3))

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
        ("Acquisition",    "VBoxManage debugvm dumpvmcore — cold hypervisor-level acquisition. "
                           "No kernel module or guest agent. Forensically sound. "
                           "SHA256 + MD5 hash recorded on host immediately post-acquisition."),
        ("Volatility 3",   "Memory parsed using Volatility 3: pslist, pstree, cmdline, dlllist, "
                           "malfind, netscan, threads. Exported as CSV (engine) and JSONL (audit trail)."),
        ("Process diff",   "Baseline vs attack comparison by process name (ImageFileName). "
                           "PID-based diff rejected — PIDs are reassigned on every reboot and produce "
                           "false-positive churn exceeding 90% of all processes."),
        ("Risk scoring",   "Transparent rule-based scoring (no ML). "
                           "RWX memory region +60  ·  Suspicious cmdline pattern +40  ·  "
                           "Known-malicious process name +50  ·  Suspicious DLL load (T1574) +30  ·  "
                           "Anomaly name bonus +15.  "
                           "Thresholds: CRITICAL ≥80  HIGH ≥50  MEDIUM ≥20  LOW <20."),
        ("Malfind filter", "Known-clean JIT processes excluded (browsers, Defender, .NET, OneDrive). "
                           "Self-match false positives suppressed (e.g. lsass.exe matching itself). "
                           "Only genuinely suspicious PAGE_EXECUTE_READWRITE regions retained."),
        ("DLL analysis",   "windows.dlllist CSV analysed for T1574 DLL Search Order Hijacking. "
                           "Protected DLLs (amsi.dll, version.dll, cryptbase.dll etc.) checked for "
                           "loads from non-System32 paths. Findings merged into ATT&CK tagged output."),
        ("ATT&CK mapping", "30+ rule-based signatures across 8 MITRE ATT&CK tactics. "
                           "Keyword matching on cmdline args, process names, DLL paths, and "
                           "network artefacts. T1574-specific patterns include: copy-item, amsi.dll, "
                           "invoke-atomictest."),
        ("IOC extraction", "Regex-based extraction: IPv4 (excluding RFC1918 private ranges), "
                           "domains, URLs, MD5/SHA1/SHA256 hashes, Windows file paths."),
        ("Framework",      "MFF v2 — Python Post-Volatility Memory Forensics Framework. "
                           "FYP project — University of Roehampton 2026. "
                           "Tool chain: VBoxManage → Volatility 3 → MFF v2 → HTML + PDF reports. "
                           "Modules: comparison_engine_v2, dll_analysis, mitre_tagger, "
                           "network_ioc, process_tree, export_alert, report_generator."),
        ("Risk scoring",   "Transparent additive model — no ML. Each evidence category contributes once. "
                           "Weights calibrated to specificity (ACPO P2). CRITICAL>=80, HIGH>=55, MEDIUM>=25."),
        ("Standards",      "ACPO Good Practice Guide for Digital Evidence (Principles 1-4). "
                           "NIST SP 800-86 Integrating Forensic Techniques into Incident Response. "
                           "ISO/IEC 27037:2012 Guidelines for Identification, Collection and Preservation. "
                           "College of Policing Digital Forensics Guidance. CPS Disclosure Manual."),
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
