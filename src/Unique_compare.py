#!/usr/bin/env python3
"""
MFF Memory Forensics Framework - Comparison Engine
Baseline vs Attack Memory Comparison with Automatic Visualization
"""

import os
import argparse
import pandas as pd
import numpy as np
from datetime import datetime, UTC

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend — safe for server/headless use
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
import matplotlib.ticker as ticker

# ============================================================
# STYLE CONFIG — dark forensics theme
# ============================================================
THEME = {
    "bg":        "#0d1117",
    "panel":     "#161b22",
    "border":    "#30363d",
    "accent":    "#f78166",      # red  — attack / high risk
    "safe":      "#3fb950",      # green — baseline / safe
    "warn":      "#d29922",      # yellow — medium risk
    "info":      "#58a6ff",      # blue  — neutral info
    "text":      "#e6edf3",
    "subtext":   "#8b949e",
    "grid":      "#21262d",
}

plt.rcParams.update({
    "figure.facecolor":  THEME["bg"],
    "axes.facecolor":    THEME["panel"],
    "axes.edgecolor":    THEME["border"],
    "axes.labelcolor":   THEME["text"],
    "xtick.color":       THEME["subtext"],
    "ytick.color":       THEME["subtext"],
    "text.color":        THEME["text"],
    "grid.color":        THEME["grid"],
    "grid.linestyle":    "--",
    "grid.linewidth":    0.5,
    "font.family":       "monospace",
    "font.size":         9,
})


# ============================================================
# Utility
# ============================================================

def now_utc():
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

def safe_read_csv(path):
    if not os.path.exists(path):
        print(f"[!] Missing file: {path}")
        return pd.DataFrame()
    return pd.read_csv(path)

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


# ============================================================
# Load Case Data
# ============================================================

def load_case(case_path):
    exports = os.path.join(case_path, "exports", "csv")
    data = {
        "pslist":  safe_read_csv(os.path.join(exports, "windows.pslist.csv")),
        "cmdline": safe_read_csv(os.path.join(exports, "windows.cmdline.csv")),
        "malfind": safe_read_csv(os.path.join(exports, "windows.malfind.csv")),
        "netscan": safe_read_csv(os.path.join(exports, "windows.netscan.csv")),
    }
    return data


# ============================================================
# Process Diff  — NEW vs BASELINE
# ============================================================

def process_diff(base_df, attack_df):
    if base_df.empty or attack_df.empty:
        return pd.DataFrame(), pd.DataFrame()

    new_processes  = attack_df[~attack_df["PID"].isin(base_df["PID"])].copy()
    gone_processes = base_df[~base_df["PID"].isin(attack_df["PID"])].copy()

    new_processes["DiffStatus"]  = "NEW (Attack Only)"
    gone_processes["DiffStatus"] = "GONE (Baseline Only)"

    return new_processes, gone_processes


# ============================================================
# Command Line Suspicious Detection
# ============================================================

SUSPICIOUS_PATTERNS = [
    "AtomicRedTeam",
    "RWXinjection",
    "CreateRemoteThread",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "net user",
    "net localgroup",
    "whoami",
    "mimikatz",
    "procdump",
    "lsass",
]

def cmdline_findings(df):
    if df.empty:
        return pd.DataFrame()

    findings = []
    for pat in SUSPICIOUS_PATTERNS:
        mask = df["Args"].astype(str).str.contains(pat, case=False, na=False)
        matches = df[mask].copy()
        if not matches.empty:
            matches["MatchedPattern"] = pat
            findings.append(matches)

    if findings:
        result = pd.concat(findings).drop_duplicates(subset=["PID", "Args"] if "Args" in df.columns else None)
        return result
    return pd.DataFrame()


# ============================================================
# Malfind Analysis
# ============================================================

def malfind_analysis(df):
    if df.empty:
        return pd.DataFrame()
    suspicious = df[df["Protection"].astype(str).str.contains("EXECUTE", na=False)].copy()
    return suspicious


# ============================================================
# Timeline Correlation
# ============================================================

def timeline_correlation(ps_df):
    if ps_df.empty:
        return pd.DataFrame()

    df = ps_df.copy()

    for col in ("CreateTime", "ExitTime"):
        dt_col = f"{col}_dt"
        if col in df.columns:
            df[dt_col] = pd.to_datetime(df[col], errors="coerce", utc=True)
            df[col] = df[dt_col].apply(
                lambda x: x.strftime("%Y-%m-%d %H:%M:%S UTC") if pd.notna(x) else ""
            )

    sort_col = "CreateTime_dt" if "CreateTime_dt" in df.columns else df.columns[0]
    df = df.sort_values(by=sort_col, na_position="last")
    return df


# ============================================================
# Risk Scoring Engine
# ============================================================

def scoring_engine(process_df, cmd_df, mal_df):
    scores = []

    for _, row in process_df.iterrows():
        pid  = row.get("PID")
        name = row.get("ImageFileName", "Unknown")
        score   = 0
        reasons = []

        if not cmd_df.empty and pid in cmd_df["PID"].values:
            score += 40
            reasons.append("Suspicious cmdline")

        if not mal_df.empty and pid in mal_df["PID"].values:
            score += 60
            reasons.append("RWX memory region")

        if any(kw in name.lower() for kw in ("rwx", "inject", "hook", "shell", "mimikatz")):
            score += 50
            reasons.append("Injection-related name")

        scores.append({
            "PID":       pid,
            "Process":   name,
            "RiskScore": score,
            "RiskLevel": risk_label(score),
            "Indicators": "; ".join(reasons) if reasons else "None",
        })

    return pd.DataFrame(scores).sort_values(by="RiskScore", ascending=False)


def risk_label(score):
    if score >= 80:  return "CRITICAL"
    if score >= 50:  return "HIGH"
    if score >= 20:  return "MEDIUM"
    return "LOW"


# ============================================================
# VISUALIZATIONS
# ============================================================

def _save(fig, path):
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=THEME["bg"])
    plt.close(fig)
    print(f"  [+] Chart saved: {path}")


# ── 1. Process Count Comparison (Baseline vs Attack) ─────────
def chart_process_counts(base_df, attack_df, new_df, gone_df, out_dir):
    fig, ax = plt.subplots(figsize=(8, 4.5))

    labels   = ["Baseline\nProcesses", "Attack\nProcesses", "New in\nAttack", "Gone from\nBaseline"]
    values   = [len(base_df), len(attack_df), len(new_df), len(gone_df)]
    colors   = [THEME["safe"], THEME["accent"], THEME["warn"], THEME["info"]]

    bars = ax.bar(labels, values, color=colors, width=0.5, zorder=3)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.4,
                str(val), ha="center", va="bottom",
                color=THEME["text"], fontweight="bold", fontsize=11)

    ax.set_title("Process Count: Baseline vs Attack Snapshot", color=THEME["text"],
                 fontsize=13, fontweight="bold", pad=14)
    ax.set_ylabel("Process Count", color=THEME["subtext"])
    ax.grid(axis="y", zorder=0)
    ax.set_ylim(0, max(values) * 1.2 + 1)
    ax.spines[["top", "right"]].set_visible(False)

    _save(fig, os.path.join(out_dir, "chart_process_counts.png"))


# ── 2. Risk Score Distribution ────────────────────────────────
def chart_risk_scores(scores_df, out_dir):
    if scores_df.empty:
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Left — bar chart of top processes by score
    top = scores_df.head(15)
    colors = [
        THEME["accent"]  if s >= 80 else
        THEME["warn"]    if s >= 50 else
        THEME["info"]    if s >= 20 else THEME["safe"]
        for s in top["RiskScore"]
    ]
    bars = ax1.barh(top["Process"].astype(str) + " [" + top["PID"].astype(str) + "]",
                    top["RiskScore"], color=colors, zorder=3)
    ax1.set_title("Top Processes by Risk Score", color=THEME["text"],
                  fontsize=11, fontweight="bold")
    ax1.set_xlabel("Risk Score", color=THEME["subtext"])
    ax1.axvline(80, color=THEME["accent"], linestyle="--", linewidth=1, alpha=0.6, label="Critical ≥80")
    ax1.axvline(50, color=THEME["warn"],   linestyle="--", linewidth=1, alpha=0.6, label="High ≥50")
    ax1.legend(fontsize=7, loc="lower right")
    ax1.invert_yaxis()
    ax1.grid(axis="x", zorder=0)
    ax1.spines[["top", "right"]].set_visible(False)

    # Right — pie of risk levels
    level_counts = scores_df["RiskLevel"].value_counts()
    level_colors = {
        "CRITICAL": THEME["accent"],
        "HIGH":     THEME["warn"],
        "MEDIUM":   THEME["info"],
        "LOW":      THEME["safe"],
    }
    pie_colors = [level_colors.get(lbl, THEME["subtext"]) for lbl in level_counts.index]

    wedges, texts, autotexts = ax2.pie(
        level_counts.values,
        labels=level_counts.index,
        colors=pie_colors,
        autopct="%1.0f%%",
        startangle=140,
        wedgeprops={"linewidth": 1.5, "edgecolor": THEME["bg"]},
    )
    for t in texts:     t.set_color(THEME["text"])
    for t in autotexts: t.set_color(THEME["bg"]); t.set_fontweight("bold")
    ax2.set_title("Risk Level Distribution", color=THEME["text"],
                  fontsize=11, fontweight="bold")

    fig.suptitle("Risk Scoring Overview", color=THEME["text"],
                 fontsize=14, fontweight="bold", y=1.01)
    _save(fig, os.path.join(out_dir, "chart_risk_scores.png"))


# ── 3. New vs Gone Process Timeline ──────────────────────────
def chart_timeline(new_df, gone_df, out_dir):
    combined_frames = []

    for df, label, color in [(new_df, "NEW", THEME["accent"]),
                              (gone_df, "GONE", THEME["info"])]:
        if df.empty:
            continue
        tmp = df.copy()
        tmp["_Label"] = label
        tmp["_Color"] = color
        combined_frames.append(tmp)

    if not combined_frames:
        return

    combined = pd.concat(combined_frames, ignore_index=True)

    if "CreateTime" not in combined.columns:
        return

    combined["_Time"] = pd.to_datetime(combined["CreateTime"], errors="coerce", utc=True)
    combined = combined.dropna(subset=["_Time"]).sort_values("_Time")

    if combined.empty:
        return

    fig, ax = plt.subplots(figsize=(13, 5))

    for _, row in combined.iterrows():
        ax.scatter(row["_Time"], row.get("ImageFileName", "?"),
                   color=row["_Color"], s=80, zorder=4,
                   marker="^" if row["_Label"] == "NEW" else "v")

    new_patch  = mpatches.Patch(color=THEME["accent"], label="NEW process (attack)")
    gone_patch = mpatches.Patch(color=THEME["info"],   label="GONE process (baseline only)")
    ax.legend(handles=[new_patch, gone_patch], fontsize=8)
    ax.set_title("Process Timeline — New & Gone Entries", color=THEME["text"],
                 fontsize=12, fontweight="bold")
    ax.set_xlabel("Create Time (UTC)", color=THEME["subtext"])
    ax.set_ylabel("Process Name",      color=THEME["subtext"])
    ax.grid(True, zorder=0)
    ax.spines[["top", "right"]].set_visible(False)
    fig.autofmt_xdate()

    _save(fig, os.path.join(out_dir, "chart_timeline.png"))


# ── 4. Suspicious Command Pattern Frequency ───────────────────
def chart_cmdline_patterns(cmd_df, out_dir):
    if cmd_df.empty or "MatchedPattern" not in cmd_df.columns:
        return

    counts = cmd_df["MatchedPattern"].value_counts()

    fig, ax = plt.subplots(figsize=(9, max(3, len(counts) * 0.45 + 1)))

    bars = ax.barh(counts.index, counts.values,
                   color=THEME["warn"], edgecolor=THEME["border"], zorder=3)

    for bar, val in zip(bars, counts.values):
        ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", color=THEME["text"], fontsize=9)

    ax.set_title("Suspicious Cmdline Pattern Hits", color=THEME["text"],
                 fontsize=12, fontweight="bold")
    ax.set_xlabel("Hit Count", color=THEME["subtext"])
    ax.invert_yaxis()
    ax.grid(axis="x", zorder=0)
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_xlim(0, counts.max() * 1.2)

    _save(fig, os.path.join(out_dir, "chart_cmdline_patterns.png"))


# ── 5. Malfind Protection Breakdown ──────────────────────────
def chart_malfind(mal_df, out_dir):
    if mal_df.empty or "Protection" not in mal_df.columns:
        return

    counts = mal_df["Protection"].value_counts().head(10)

    fig, ax = plt.subplots(figsize=(8, 4))
    colors = [THEME["accent"] if "EXECUTE" in str(p) else THEME["warn"] for p in counts.index]
    ax.bar(counts.index, counts.values, color=colors, zorder=3,
           edgecolor=THEME["border"])
    ax.set_title("Malfind — Memory Protection Types", color=THEME["text"],
                 fontsize=12, fontweight="bold")
    ax.set_ylabel("Count", color=THEME["subtext"])
    ax.grid(axis="y", zorder=0)
    ax.spines[["top", "right"]].set_visible(False)
    plt.xticks(rotation=30, ha="right")

    exec_patch = mpatches.Patch(color=THEME["accent"], label="EXECUTE (suspicious)")
    other_patch = mpatches.Patch(color=THEME["warn"],  label="Other")
    ax.legend(handles=[exec_patch, other_patch], fontsize=8)

    _save(fig, os.path.join(out_dir, "chart_malfind_protection.png"))


# ── 6. Master Dashboard ───────────────────────────────────────
def chart_dashboard(base_df, attack_df, new_df, gone_df, scores_df, cmd_df, mal_df, out_dir):
    """Single-page summary dashboard."""
    fig = plt.figure(figsize=(16, 10))
    fig.suptitle("MFF — Memory Forensics Comparison Dashboard",
                 color=THEME["text"], fontsize=16, fontweight="bold", y=0.98)

    gs = GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.35)

    # ── Panel A: process counts ──────────────────────────────
    ax_a = fig.add_subplot(gs[0, 0])
    labels = ["Baseline", "Attack", "New", "Gone"]
    values = [len(base_df), len(attack_df), len(new_df), len(gone_df)]
    colors = [THEME["safe"], THEME["accent"], THEME["warn"], THEME["info"]]
    bars = ax_a.bar(labels, values, color=colors, zorder=3, width=0.6)
    for bar, v in zip(bars, values):
        ax_a.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2,
                  str(v), ha="center", fontsize=9, fontweight="bold", color=THEME["text"])
    ax_a.set_title("Process Counts", fontsize=10, fontweight="bold")
    ax_a.set_ylim(0, max(values) * 1.3 + 1)
    ax_a.grid(axis="y", zorder=0)
    ax_a.spines[["top", "right"]].set_visible(False)

    # ── Panel B: risk level pie ───────────────────────────────
    ax_b = fig.add_subplot(gs[0, 1])
    if not scores_df.empty:
        level_counts = scores_df["RiskLevel"].value_counts()
        lc = {"CRITICAL": THEME["accent"], "HIGH": THEME["warn"],
              "MEDIUM": THEME["info"], "LOW": THEME["safe"]}
        pc = [lc.get(l, THEME["subtext"]) for l in level_counts.index]
        wedges, texts, autos = ax_b.pie(
            level_counts.values, labels=level_counts.index, colors=pc,
            autopct="%1.0f%%", startangle=140,
            wedgeprops={"linewidth": 1.2, "edgecolor": THEME["bg"]},
            textprops={"fontsize": 8})
        for t in texts:  t.set_color(THEME["text"])
        for t in autos:  t.set_color(THEME["bg"]); t.set_fontweight("bold")
    ax_b.set_title("Risk Distribution", fontsize=10, fontweight="bold")

    # ── Panel C: cmdline hits ─────────────────────────────────
    ax_c = fig.add_subplot(gs[0, 2])
    if not cmd_df.empty and "MatchedPattern" in cmd_df.columns:
        top_pats = cmd_df["MatchedPattern"].value_counts().head(8)
        ax_c.barh(top_pats.index, top_pats.values, color=THEME["warn"], zorder=3)
        ax_c.invert_yaxis()
        ax_c.grid(axis="x", zorder=0)
    ax_c.set_title("Cmdline Pattern Hits", fontsize=10, fontweight="bold")
    ax_c.spines[["top", "right"]].set_visible(False)

    # ── Panel D: top risk scores ──────────────────────────────
    ax_d = fig.add_subplot(gs[1, 0:2])
    if not scores_df.empty:
        top = scores_df.head(10)
        colors_d = [
            THEME["accent"] if s >= 80 else
            THEME["warn"]   if s >= 50 else
            THEME["info"]   if s >= 20 else THEME["safe"]
            for s in top["RiskScore"]
        ]
        labels_d = top["Process"].astype(str) + "  (PID " + top["PID"].astype(str) + ")"
        ax_d.barh(labels_d, top["RiskScore"], color=colors_d, zorder=3)
        ax_d.invert_yaxis()
        ax_d.axvline(80, color=THEME["accent"], ls="--", lw=1, alpha=0.5, label="Critical")
        ax_d.axvline(50, color=THEME["warn"],   ls="--", lw=1, alpha=0.5, label="High")
        ax_d.legend(fontsize=7)
        ax_d.grid(axis="x", zorder=0)
    ax_d.set_title("Top Processes by Risk Score", fontsize=10, fontweight="bold")
    ax_d.spines[["top", "right"]].set_visible(False)

    # ── Panel E: malfind protection ───────────────────────────
    ax_e = fig.add_subplot(gs[1, 2])
    if not mal_df.empty and "Protection" in mal_df.columns:
        mprot = mal_df["Protection"].value_counts().head(6)
        ecols = [THEME["accent"] if "EXECUTE" in str(p) else THEME["warn"] for p in mprot.index]
        ax_e.bar(range(len(mprot)), mprot.values, color=ecols, zorder=3)
        ax_e.set_xticks(range(len(mprot)))
        ax_e.set_xticklabels(mprot.index, rotation=25, ha="right", fontsize=7)
        ax_e.grid(axis="y", zorder=0)
    ax_e.set_title("Malfind Protections", fontsize=10, fontweight="bold")
    ax_e.spines[["top", "right"]].set_visible(False)

    _save(fig, os.path.join(out_dir, "dashboard.png"))


# ============================================================
# HTML Report  (embeds charts)
# ============================================================

def generate_html(out_path, new_df, gone_df, cmd_findings, malfind, scores):

    html_path = os.path.join(out_path, "comparison_report.html")

    def tbl(df):
        if df.empty:
            return "<p style='color:#8b949e;font-style:italic'>No data.</p>"
        return df.to_html(index=False, border=0,
                          classes="tbl", escape=True)

    def img(name, title):
        path = os.path.join(out_path, name)
        if not os.path.exists(path):
            return ""
        return f"""
        <div class="chart-block">
          <h3>{title}</h3>
          <img src="{name}" alt="{title}">
        </div>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MFF — Memory Comparison Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@400;700&display=swap');
  :root {{
    --bg:     #0d1117;
    --panel:  #161b22;
    --border: #30363d;
    --accent: #f78166;
    --safe:   #3fb950;
    --warn:   #d29922;
    --info:   #58a6ff;
    --text:   #e6edf3;
    --sub:    #8b949e;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text);
          font-family: 'Share Tech Mono', monospace; }}
  header {{ padding: 32px 40px 20px;
            border-bottom: 1px solid var(--border); }}
  header h1 {{ font-family: 'Exo 2', sans-serif; font-size: 1.9rem;
               color: var(--accent); letter-spacing: 2px; }}
  header p  {{ color: var(--sub); font-size: 0.85rem; margin-top: 6px; }}
  .badge {{ display:inline-block; padding:2px 10px; border-radius:4px;
            font-size:0.75rem; font-weight:bold; margin-left:12px; }}
  .badge-red   {{ background:var(--accent); color:#000; }}
  .badge-green {{ background:var(--safe);   color:#000; }}
  main {{ max-width: 1400px; margin: 0 auto; padding: 30px 40px; }}
  section {{ margin-bottom: 44px; }}
  h2 {{ font-family: 'Exo 2', sans-serif; font-size: 1.15rem;
        color: var(--info); border-left: 3px solid var(--info);
        padding-left: 12px; margin-bottom: 14px; letter-spacing: 1px; }}
  h3 {{ color: var(--sub); font-size: 0.9rem; margin-bottom: 8px; }}
  .chart-block {{ background: var(--panel); border: 1px solid var(--border);
                  border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
  .chart-block img {{ max-width:100%; border-radius:4px; }}
  table.tbl {{ width:100%; border-collapse:collapse;
               font-size:0.8rem; }}
  table.tbl thead tr {{ background: var(--panel); }}
  table.tbl th {{ color: var(--info); padding: 8px 12px;
                  text-align:left; border-bottom:1px solid var(--border); }}
  table.tbl td {{ padding: 7px 12px; border-bottom:1px solid var(--grid, #21262d); }}
  table.tbl tr:hover td {{ background: rgba(255,255,255,0.03); }}
  .stat-row {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:24px; }}
  .stat {{ background: var(--panel); border:1px solid var(--border);
           border-radius:8px; padding:16px 24px; flex:1; min-width:140px; }}
  .stat .num {{ font-family:'Exo 2',sans-serif; font-size:2rem;
                font-weight:700; color: var(--accent); }}
  .stat .lbl {{ color: var(--sub); font-size:0.78rem; margin-top:4px; }}
  footer {{ border-top:1px solid var(--border); padding:20px 40px;
            color: var(--sub); font-size:0.78rem; }}
</style>
</head>
<body>
<header>
  <h1>&#9654; MFF Memory Forensics Report
    <span class="badge badge-red">ATTACK</span>
    <span class="badge badge-green">BASELINE</span>
  </h1>
  <p>Generated: {now_utc()}</p>
</header>
<main>

<section>
  <h2>&#9650; Summary Statistics</h2>
  <div class="stat-row">
    <div class="stat"><div class="num">{len(new_df)}</div>
      <div class="lbl">New Processes (Attack Only)</div></div>
    <div class="stat"><div class="num">{len(gone_df)}</div>
      <div class="lbl">Gone Processes (Baseline Only)</div></div>
    <div class="stat"><div class="num">{len(cmd_findings)}</div>
      <div class="lbl">Suspicious Cmdline Hits</div></div>
    <div class="stat"><div class="num">{len(malfind)}</div>
      <div class="lbl">RWX Malfind Regions</div></div>
    <div class="stat"><div class="num">{len(scores[scores['RiskLevel']=='CRITICAL']) if not scores.empty else 0}</div>
      <div class="lbl">Critical Risk Processes</div></div>
  </div>
</section>

<section>
  <h2>&#9650; Dashboard</h2>
  {img("dashboard.png", "Full Comparison Dashboard")}
</section>

<section>
  <h2>&#9650; Process Diff Charts</h2>
  {img("chart_process_counts.png", "Process Count Comparison")}
  {img("chart_timeline.png", "Process Timeline")}
</section>

<section>
  <h2>&#9650; New Processes (Attack Only)</h2>
  {tbl(new_df.drop(columns=["CreateTime_dt","ExitTime_dt"], errors="ignore"))}
</section>

<section>
  <h2>&#9650; Gone Processes (Baseline Only)</h2>
  {tbl(gone_df.drop(columns=["CreateTime_dt","ExitTime_dt"], errors="ignore"))}
</section>

<section>
  <h2>&#9650; Suspicious Command Lines</h2>
  {img("chart_cmdline_patterns.png", "Cmdline Pattern Frequency")}
  {tbl(cmd_findings)}
</section>

<section>
  <h2>&#9650; RWX Memory (Malfind)</h2>
  {img("chart_malfind_protection.png", "Memory Protection Breakdown")}
  {tbl(malfind)}
</section>

<section>
  <h2>&#9650; Risk Scores</h2>
  {img("chart_risk_scores.png", "Risk Score Overview")}
  {tbl(scores)}
</section>

</main>
<footer>MFF Comparison Engine &mdash; {now_utc()}</footer>
</body></html>
""")

    print(f"[+] HTML report: {html_path}")


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="MFF Memory Forensics Comparison Engine")
    parser.add_argument("--baseline",   required=True, help="Path to baseline case folder")
    parser.add_argument("--attack",     required=True, help="Path to attack case folder")
    parser.add_argument("--out",        required=True, help="Output directory")
    parser.add_argument("--make-html",  action="store_true", help="Generate HTML report")
    parser.add_argument("--charts-only",action="store_true", help="Skip CSV output, charts only")
    args = parser.parse_args()

    ensure_dir(args.out)

    print(f"[*] Loading baseline: {args.baseline}")
    base = load_case(args.baseline)

    print(f"[*] Loading attack:   {args.attack}")
    attack = load_case(args.attack)

    # — Analysis —
    new_df, gone_df = process_diff(base["pslist"], attack["pslist"])
    cmd_findings_df = cmdline_findings(attack["cmdline"])
    malfind_df      = malfind_analysis(attack["malfind"])
    timeline_df     = timeline_correlation(attack["pslist"])
    scores_df       = scoring_engine(new_df, cmd_findings_df, malfind_df)

    # — CSV export —
    if not args.charts_only:
        new_df.to_csv(os.path.join(args.out, "process_new.csv"),    index=False)
        gone_df.to_csv(os.path.join(args.out, "process_gone.csv"),  index=False)
        cmd_findings_df.to_csv(os.path.join(args.out, "cmdline_findings.csv"), index=False)
        malfind_df.to_csv(os.path.join(args.out, "malfind.csv"),    index=False)
        timeline_df.to_csv(os.path.join(args.out, "timeline.csv"),  index=False)
        scores_df.to_csv(os.path.join(args.out, "scores.csv"),      index=False)
        print("[+] CSV files written.")

    # — Charts —
    print("[*] Generating charts...")
    chart_process_counts(base["pslist"], attack["pslist"], new_df, gone_df, args.out)
    chart_risk_scores(scores_df, args.out)
    chart_timeline(new_df, gone_df, args.out)
    chart_cmdline_patterns(cmd_findings_df, args.out)
    chart_malfind(malfind_df, args.out)
    chart_dashboard(base["pslist"], attack["pslist"], new_df, gone_df,
                    scores_df, cmd_findings_df, malfind_df, args.out)

    # — HTML —
    if args.make_html:
        generate_html(args.out, new_df, gone_df, cmd_findings_df, malfind_df, scores_df)

    print("\n[+] Done. Results in:", args.out)


if __name__ == "__main__":
    main()
