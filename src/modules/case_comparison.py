#!/usr/bin/env python3
"""
MFF v2 — Module: Case Comparison Report
=========================================
Cross-case analysis: compare multiple attack case results side-by-side.

Reads the CSV/JSON outputs from comparison_engine_v2.py runs and produces:
  • comparison_chart_risk.png       — risk scores per case
  • comparison_chart_attacks.png    — MITRE ATT&CK matrix (cases × techniques)
  • comparison_chart_processes.png  — process delta per case
  • comparison_chart_malfind.png    — RWX memory hits per case
  • comparison_chart_iocs.png       — IOC count per case
  • comparison_matrix.csv           — machine-readable summary table
  • comparison_report.html          — interactive HTML report
  • comparison_report.pdf           — professional PDF report

Usage:
    import case_comparison

    cases = [
        ("Case 02 — T1055", "/MFF/analysis/comparison/case01_vs_case02"),
        ("Case 03 — T1059", "/MFF/analysis/comparison/case01_vs_case03"),
        ("Case 04 — T1574", "/MFF/analysis/comparison/case01_vs_case04"),
        ("Case 05 — Multi", "/MFF/analysis/comparison/case01_vs_case05"),
    ]
    case_comparison.run(cases, out_dir="/MFF/analysis/comparison_report")

CLI:
    python case_comparison.py \\
        --dirs  "Case02:/MFF/analysis/comparison/case01_vs_case02" \\
                "Case03:/MFF/analysis/comparison/case01_vs_case03" \\
        --out   /MFF/analysis/comparison_report \\
        --make-html --make-pdf
"""

import os
import sys
import json
import base64
import argparse
from datetime import datetime, UTC

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec


# ─── colour palette (matches comparison engine dark theme) ─────────────────

THEME = {
    "bg":      "#0d1117",
    "panel":   "#161b22",
    "border":  "#30363d",
    "accent":  "#f78166",
    "safe":    "#3fb950",
    "warn":    "#d29922",
    "info":    "#58a6ff",
    "text":    "#e6edf3",
    "subtext": "#8b949e",
    "grid":    "#21262d",
}

CASE_PALETTE = [
    "#58a6ff", "#f78166", "#3fb950", "#d29922",
    "#bc8cff", "#e06c75", "#56d364", "#79c0ff",
]

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
# Utilities
# ============================================================

def _now():
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

def _save(fig, path):
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=THEME["bg"])
    plt.close(fig)
    print(f"  [+] Chart: {path}")

def _wm(ax, text="MFF v2 · Case Comparison"):
    ax.text(0.99, 0.01, text, transform=ax.transAxes,
            fontsize=6, color=THEME["subtext"], alpha=0.4,
            ha="right", va="bottom", style="italic")

def _spines(ax):
    ax.spines[["top","right"]].set_visible(False)
    ax.spines["left"].set_color(THEME["border"])
    ax.spines["bottom"].set_color(THEME["border"])

def _safe_read(path):
    if not os.path.exists(path):
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception:
        return pd.DataFrame()

def _safe_json(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}

def _img_b64(path):
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception:
        return ""


# ============================================================
# Load case results
# ============================================================

def load_case_results(label: str, out_dir: str) -> dict:
    """
    Load all CSV/JSON artefacts produced by comparison_engine_v2.py
    from a single case output directory.

    Returns a dict with keys:
        label, out_dir,
        scores, attack_tags, tactic_summary, process_new, process_gone,
        malfind, cmdline, net_new, net_flagged, iocs, dll_hijack,
        summary (JSON threat_summary)
    """
    def rd(name):
        return _safe_read(os.path.join(out_dir, name))

    summary = _safe_json(os.path.join(out_dir, "threat_summary.json"))

    # Pull top-level stats from JSON summary when CSVs are missing
    stats = summary.get("statistics", {})
    sev   = summary.get("severity", {})

    return {
        "label":          label,
        "out_dir":        out_dir,
        "scores":         rd("scores.csv"),
        "attack_tags":    rd("attack_tags.csv"),
        "tactic_summary": rd("tactic_summary.csv"),
        "process_new":    rd("process_new.csv"),
        "process_gone":   rd("process_gone.csv"),
        "malfind":        rd("malfind.csv"),
        "cmdline":        rd("cmdline_findings.csv"),
        "net_new":        rd("net_new.csv"),
        "net_flagged":    rd("net_flagged.csv"),
        "iocs":           rd("iocs.csv"),
        "dll_hijack":     rd("dll_hijack.csv"),
        "summary":        summary,
        # convenience scalars
        "severity":       sev.get("overall", "UNKNOWN"),
        "new_procs":      stats.get("new_processes",   len(rd("process_new.csv"))),
        "gone_procs":     stats.get("gone_processes",  len(rd("process_gone.csv"))),
        "techniques":     stats.get("attack_techniques", 0),
        "ioc_count":      stats.get("ioc_count",       len(rd("iocs.csv"))),
        "net_new_count":  stats.get("net_new_connections", len(rd("net_new.csv"))),
    }


# ============================================================
# Build summary matrix
# ============================================================

def build_matrix(cases: list) -> pd.DataFrame:
    """
    Build a machine-readable comparison matrix.
    One row per case, columns = key metrics.
    """
    rows = []
    for c in cases:
        scores    = c["scores"]
        tags      = c["attack_tags"]
        malfind   = c["malfind"]
        dll       = c["dll_hijack"]

        # Risk score stats
        max_score  = int(scores["RiskScore"].max())  if not scores.empty and "RiskScore" in scores.columns else 0
        crit_count = int((scores["RiskLevel"]=="CRITICAL").sum()) if not scores.empty and "RiskLevel" in scores.columns else 0
        high_count = int((scores["RiskLevel"]=="HIGH").sum())     if not scores.empty and "RiskLevel" in scores.columns else 0
        med_count  = int((scores["RiskLevel"]=="MEDIUM").sum())   if not scores.empty and "RiskLevel" in scores.columns else 0

        # Techniques
        techs = list(tags["Technique"].unique()) if not tags.empty and "Technique" in tags.columns else []
        tactics = list(tags["Tactic"].unique())  if not tags.empty and "Tactic"    in tags.columns else []

        # Malfind
        rwx_count = len(malfind) if not malfind.empty else 0

        # DLL hijack
        dll_count = len(dll) if not dll.empty else 0

        rows.append({
            "Case":                  c["label"],
            "Severity":              c["severity"],
            "MaxRiskScore":          max_score,
            "CriticalProcesses":     crit_count,
            "HighProcesses":         high_count,
            "MediumProcesses":       med_count,
            "NewProcesses":          c["new_procs"],
            "GoneProcesses":         c["gone_procs"],
            "RWX_Regions":           rwx_count,
            "DLL_Hijack_Findings":   dll_count,
            "Techniques_Detected":   len(techs),
            "Tactics_Detected":      len(tactics),
            "Techniques_List":       ", ".join(sorted(techs)),
            "Tactics_List":          ", ".join(sorted(tactics)),
            "IOCs":                  c["ioc_count"],
            "Net_New_Connections":   c["net_new_count"],
        })

    return pd.DataFrame(rows)


# ============================================================
# Charts
# ============================================================

def chart_risk_comparison(cases: list, out_dir: str):
    """Grouped bar — max risk score per case, coloured by severity."""
    labels = [c["label"] for c in cases]
    n      = len(labels)

    scores_list = []
    colors_list = []
    sev_colors  = {
        "CRITICAL": THEME["accent"],
        "HIGH":     THEME["warn"],
        "MEDIUM":   THEME["info"],
        "LOW":      THEME["safe"],
        "UNKNOWN":  THEME["subtext"],
    }

    for c in cases:
        sc = c["scores"]
        if not sc.empty and "RiskScore" in sc.columns:
            mx = int(sc["RiskScore"].max())
        else:
            mx = 0
        scores_list.append(mx)
        colors_list.append(sev_colors.get(c["severity"], THEME["subtext"]))

    fig, ax = plt.subplots(figsize=(max(10, n * 2.2 + 2), 6))
    fig.patch.set_facecolor(THEME["bg"])
    ax.set_facecolor(THEME["panel"])
    fig.suptitle("MAX RISK SCORE PER CASE", color=THEME["accent"],
                 fontsize=12, fontweight="bold", fontfamily="monospace")

    bars = ax.bar(range(n), scores_list, color=colors_list, width=0.6, zorder=3,
                  edgecolor=THEME["bg"], linewidth=1.5)
    for bar, v, c in zip(bars, scores_list, cases):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1.5,
                f"{v}", ha="center", fontweight="bold",
                color=THEME["text"], fontsize=11)
        ax.text(bar.get_x() + bar.get_width()/2, -8,
                c["severity"], ha="center", fontsize=8,
                color=sev_colors.get(c["severity"], THEME["subtext"]),
                fontweight="bold")

    ax.axhline(80, color=THEME["accent"], ls="--", lw=1.2, alpha=0.7, label="Critical (80)")
    ax.axhline(50, color=THEME["warn"],   ls="--", lw=1.2, alpha=0.7, label="High (50)")
    ax.axhline(20, color=THEME["info"],   ls="--", lw=1.2, alpha=0.4, label="Medium (20)")
    ax.legend(fontsize=8, facecolor=THEME["grid"], edgecolor=THEME["border"],
              labelcolor=THEME["text"])

    ax.set_xticks(range(n))
    ax.set_xticklabels([c["label"] for c in cases], rotation=15, ha="right", fontsize=9)
    ax.set_ylim(-15, 120)
    ax.set_ylabel("Max Risk Score", color=THEME["subtext"])
    ax.grid(axis="y", zorder=0, alpha=0.4)
    _spines(ax); _wm(ax)
    plt.tight_layout()
    _save(fig, os.path.join(out_dir, "comparison_chart_risk.png"))


def chart_attack_matrix(cases: list, out_dir: str):
    """
    MITRE ATT&CK detection matrix.
    Rows = techniques, columns = cases.
    Cell = number of process hits.
    """
    # Collect all unique techniques across all cases
    all_techs = {}   # technique_id → name
    for c in cases:
        tags = c["attack_tags"]
        if tags.empty or "Technique" not in tags.columns:
            continue
        for _, row in tags.iterrows():
            tid  = str(row.get("Technique", ""))
            name = str(row.get("TechniqueName", tid))
            if tid:
                all_techs[tid] = name

    if not all_techs:
        return

    techniques  = sorted(all_techs.keys())
    tech_labels = [f"{tid}\n{all_techs[tid][:18]}" for tid in techniques]
    case_labels = [c["label"] for c in cases]
    n_tech = len(techniques)
    n_case = len(cases)

    # Build matrix (technique × case) = hit count
    matrix = np.zeros((n_tech, n_case), dtype=int)
    for ci, c in enumerate(cases):
        tags = c["attack_tags"]
        if tags.empty or "Technique" not in tags.columns:
            continue
        for ti, tid in enumerate(techniques):
            count = (tags["Technique"].astype(str) == tid).sum()
            matrix[ti, ci] = count

    h = max(5, n_tech * 0.65 + 2)
    w = max(8, n_case * 1.8 + 3)
    fig, ax = plt.subplots(figsize=(w, h))
    fig.patch.set_facecolor(THEME["bg"])
    ax.set_facecolor(THEME["panel"])
    fig.suptitle("MITRE ATT&CK — DETECTION MATRIX (CASES × TECHNIQUES)",
                 color=THEME["accent"], fontsize=11, fontweight="bold",
                 fontfamily="monospace")

    import matplotlib.colors as mcolors
    cmap = mcolors.LinearSegmentedColormap.from_list(
        "mff", ["#161b22", "#1a3a5c", THEME["info"], THEME["accent"]])

    im = ax.imshow(matrix, cmap=cmap, aspect="auto",
                   vmin=0, vmax=max(matrix.max(), 1))

    ax.set_xticks(range(n_case))
    ax.set_xticklabels(case_labels, rotation=20, ha="right", fontsize=8.5,
                       color=THEME["text"])
    ax.set_yticks(range(n_tech))
    ax.set_yticklabels(tech_labels, fontsize=8, color=THEME["text"])

    # Annotate cells
    for ti in range(n_tech):
        for ci in range(n_case):
            v = matrix[ti, ci]
            color = THEME["text"] if v > 0 else THEME["subtext"]
            ax.text(ci, ti, str(v) if v > 0 else "·",
                    ha="center", va="center", fontsize=9,
                    fontweight="bold", color=color)

    # Grid lines
    for x in np.arange(-0.5, n_case, 1):
        ax.axvline(x, color=THEME["border"], lw=0.5)
    for y in np.arange(-0.5, n_tech, 1):
        ax.axhline(y, color=THEME["border"], lw=0.5)

    plt.colorbar(im, ax=ax, label="Hit Count", fraction=0.04, pad=0.02)
    plt.tight_layout()
    _save(fig, os.path.join(out_dir, "comparison_chart_attacks.png"))


def chart_process_delta(cases: list, out_dir: str):
    """Grouped bars — new / gone processes per case."""
    labels = [c["label"] for c in cases]
    n      = len(labels)
    new_vals  = [c["new_procs"]  for c in cases]
    gone_vals = [c["gone_procs"] for c in cases]

    x     = np.arange(n)
    width = 0.38

    fig, ax = plt.subplots(figsize=(max(10, n * 2.5), 6))
    fig.patch.set_facecolor(THEME["bg"])
    ax.set_facecolor(THEME["panel"])
    fig.suptitle("PROCESS DELTA — NEW vs GONE (PER CASE)", color=THEME["accent"],
                 fontsize=12, fontweight="bold", fontfamily="monospace")

    bars_new  = ax.bar(x - width/2, new_vals,  width, color=THEME["warn"],
                       label="New (Attack Only)", zorder=3, edgecolor=THEME["bg"])
    bars_gone = ax.bar(x + width/2, gone_vals, width, color=THEME["info"],
                       label="Gone (Baseline Only)", zorder=3, edgecolor=THEME["bg"])

    for bar, v in zip(bars_new,  new_vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                str(v), ha="center", fontsize=9, fontweight="bold", color=THEME["text"])
    for bar, v in zip(bars_gone, gone_vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                str(v), ha="center", fontsize=9, fontweight="bold", color=THEME["text"])

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right", fontsize=9)
    ax.set_ylabel("Process Count", color=THEME["subtext"])
    ax.legend(fontsize=9, facecolor=THEME["grid"], edgecolor=THEME["border"],
              labelcolor=THEME["text"])
    ax.set_ylim(0, max(max(new_vals + gone_vals) * 1.3 + 1, 5))
    ax.grid(axis="y", zorder=0, alpha=0.4)
    _spines(ax); _wm(ax)
    plt.tight_layout()
    _save(fig, os.path.join(out_dir, "comparison_chart_processes.png"))


def chart_malfind_ioc(cases: list, out_dir: str):
    """Side-by-side: RWX regions and IOC count per case."""
    labels    = [c["label"] for c in cases]
    n         = len(labels)
    rwx_vals  = [len(c["malfind"]) if not c["malfind"].empty else 0 for c in cases]
    ioc_vals  = [c["ioc_count"] for c in cases]
    dll_vals  = [len(c["dll_hijack"]) if not c["dll_hijack"].empty else 0 for c in cases]

    x     = np.arange(n)
    width = 0.26

    fig, ax = plt.subplots(figsize=(max(10, n * 2.8), 6))
    fig.patch.set_facecolor(THEME["bg"])
    ax.set_facecolor(THEME["panel"])
    fig.suptitle("ARTEFACT COUNTS PER CASE — RWX · IOC · DLL HIJACK",
                 color=THEME["accent"], fontsize=12, fontweight="bold",
                 fontfamily="monospace")

    bars1 = ax.bar(x - width, rwx_vals, width, color=THEME["accent"],
                   label="RWX Regions (malfind)", zorder=3, edgecolor=THEME["bg"])
    bars2 = ax.bar(x,         ioc_vals, width, color=THEME["info"],
                   label="IOCs Extracted", zorder=3, edgecolor=THEME["bg"])
    bars3 = ax.bar(x + width, dll_vals, width, color=THEME["warn"],
                   label="DLL Hijack Findings", zorder=3, edgecolor=THEME["bg"])

    for bar, v in zip(bars1, rwx_vals):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                    str(v), ha="center", fontsize=8.5, color=THEME["text"])
    for bar, v in zip(bars2, ioc_vals):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                    str(v), ha="center", fontsize=8.5, color=THEME["text"])
    for bar, v in zip(bars3, dll_vals):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                    str(v), ha="center", fontsize=8.5, color=THEME["text"])

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right", fontsize=9)
    ax.set_ylabel("Count", color=THEME["subtext"])
    ax.legend(fontsize=8.5, facecolor=THEME["grid"], edgecolor=THEME["border"],
              labelcolor=THEME["text"])
    ax.grid(axis="y", zorder=0, alpha=0.4)
    _spines(ax); _wm(ax)
    plt.tight_layout()
    _save(fig, os.path.join(out_dir, "comparison_chart_artefacts.png"))


def chart_technique_coverage(cases: list, out_dir: str):
    """Horizontal stacked bar — technique count per tactic per case."""
    all_tactics = set()
    for c in cases:
        tags = c["attack_tags"]
        if not tags.empty and "Tactic" in tags.columns:
            all_tactics.update(tags["Tactic"].dropna().unique())
    all_tactics = sorted(all_tactics)

    if not all_tactics:
        return

    tactic_colors = {
        "Execution":           "#f78166",
        "Defense Evasion":     "#d29922",
        "Credential Access":   "#ff6b6b",
        "Discovery":           "#58a6ff",
        "Lateral Movement":    "#c9a227",
        "Persistence":         "#bc8cff",
        "Command and Control": "#e06c75",
        "Exfiltration":        "#e5534b",
    }

    n      = len(cases)
    labels = [c["label"] for c in cases]
    x      = np.arange(n)

    fig, ax = plt.subplots(figsize=(max(10, n * 2.5 + 2), 6))
    fig.patch.set_facecolor(THEME["bg"])
    ax.set_facecolor(THEME["panel"])
    fig.suptitle("ATT&CK TACTIC COVERAGE PER CASE",
                 color=THEME["accent"], fontsize=12, fontweight="bold",
                 fontfamily="monospace")

    bottoms = np.zeros(n)
    for tactic in all_tactics:
        counts = []
        for c in cases:
            tags = c["attack_tags"]
            if tags.empty or "Tactic" not in tags.columns:
                counts.append(0)
            else:
                tc = (tags["Tactic"].astype(str) == tactic)
                uniq = tags[tc]["Technique"].nunique() if "Technique" in tags.columns else tc.sum()
                counts.append(int(uniq))
        color = tactic_colors.get(tactic, THEME["info"])
        bars = ax.bar(x, counts, bottom=bottoms, color=color, label=tactic,
                      width=0.55, zorder=3, edgecolor=THEME["bg"], linewidth=0.8)
        for bar, v, b in zip(bars, counts, bottoms):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width()/2,
                        b + v/2,
                        str(v), ha="center", va="center",
                        fontsize=8, fontweight="bold", color="#000000")
        bottoms = bottoms + np.array(counts, dtype=float)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right", fontsize=9)
    ax.set_ylabel("Unique Technique Hits", color=THEME["subtext"])
    ax.legend(fontsize=7.5, facecolor=THEME["grid"], edgecolor=THEME["border"],
              labelcolor=THEME["text"], loc="upper left", ncol=2)
    ax.grid(axis="y", zorder=0, alpha=0.4)
    _spines(ax); _wm(ax)
    plt.tight_layout()
    _save(fig, os.path.join(out_dir, "comparison_chart_tactics.png"))


def chart_dashboard(cases: list, matrix_df: pd.DataFrame, out_dir: str):
    """Master comparison dashboard — 6-panel overview."""
    n = len(cases)
    if n == 0:
        return

    fig = plt.figure(figsize=(22, 13))
    fig.patch.set_facecolor(THEME["bg"])
    fig.suptitle("MFF v2 — CROSS-CASE COMPARISON DASHBOARD",
                 color=THEME["accent"], fontsize=15, fontweight="bold",
                 fontfamily="monospace", y=0.99)
    gs = GridSpec(3, 3, figure=fig, hspace=0.52, wspace=0.38,
                  top=0.95, bottom=0.07, left=0.06, right=0.97)

    case_labels = [c["label"] for c in cases]
    x = np.arange(n)

    sev_colors = {
        "CRITICAL": THEME["accent"], "HIGH": THEME["warn"],
        "MEDIUM": THEME["info"], "LOW": THEME["safe"], "UNKNOWN": THEME["subtext"],
    }

    # Panel 1 — Max risk scores
    ax1 = fig.add_subplot(gs[0, 0])
    ax1.set_facecolor(THEME["panel"])
    scores = matrix_df["MaxRiskScore"].tolist() if "MaxRiskScore" in matrix_df.columns else [0]*n
    sevs   = matrix_df["Severity"].tolist()     if "Severity"     in matrix_df.columns else ["UNKNOWN"]*n
    cols   = [sev_colors.get(s, THEME["subtext"]) for s in sevs]
    bars   = ax1.bar(x, scores, color=cols, zorder=3, edgecolor=THEME["bg"])
    for bar, v in zip(bars, scores):
        ax1.text(bar.get_x()+bar.get_width()/2, bar.get_height()+1.5,
                 str(v), ha="center", fontsize=8, fontweight="bold", color=THEME["text"])
    ax1.set_xticks(x); ax1.set_xticklabels(case_labels, rotation=20, ha="right", fontsize=7)
    ax1.axhline(80, color=THEME["accent"], ls="--", lw=1, alpha=0.7)
    ax1.set_ylim(0, 120); ax1.set_title("Max Risk Score", fontsize=9, color=THEME["text"])
    ax1.grid(axis="y", zorder=0, alpha=0.4); _spines(ax1)

    # Panel 2 — Techniques detected
    ax2 = fig.add_subplot(gs[0, 1])
    ax2.set_facecolor(THEME["panel"])
    techs = matrix_df["Techniques_Detected"].tolist() if "Techniques_Detected" in matrix_df.columns else [0]*n
    bars2 = ax2.bar(x, techs, color=CASE_PALETTE[:n], zorder=3, edgecolor=THEME["bg"])
    for bar, v in zip(bars2, techs):
        ax2.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.1,
                 str(v), ha="center", fontsize=8, fontweight="bold", color=THEME["text"])
    ax2.set_xticks(x); ax2.set_xticklabels(case_labels, rotation=20, ha="right", fontsize=7)
    ax2.set_title("ATT&CK Techniques", fontsize=9, color=THEME["text"])
    ax2.grid(axis="y", zorder=0, alpha=0.4); _spines(ax2)

    # Panel 3 — RWX regions
    ax3 = fig.add_subplot(gs[0, 2])
    ax3.set_facecolor(THEME["panel"])
    rwx = matrix_df["RWX_Regions"].tolist() if "RWX_Regions" in matrix_df.columns else [0]*n
    bars3 = ax3.bar(x, rwx, color=THEME["accent"], zorder=3, edgecolor=THEME["bg"])
    for bar, v in zip(bars3, rwx):
        if v > 0:
            ax3.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.1,
                     str(v), ha="center", fontsize=8, fontweight="bold", color=THEME["text"])
    ax3.set_xticks(x); ax3.set_xticklabels(case_labels, rotation=20, ha="right", fontsize=7)
    ax3.set_title("RWX Memory Regions", fontsize=9, color=THEME["text"])
    ax3.grid(axis="y", zorder=0, alpha=0.4); _spines(ax3)

    # Panel 4 — New processes
    ax4 = fig.add_subplot(gs[1, 0])
    ax4.set_facecolor(THEME["panel"])
    new_p = matrix_df["NewProcesses"].tolist() if "NewProcesses" in matrix_df.columns else [0]*n
    bars4 = ax4.bar(x, new_p, color=THEME["warn"], zorder=3, edgecolor=THEME["bg"])
    for bar, v in zip(bars4, new_p):
        ax4.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.1,
                 str(v), ha="center", fontsize=8, fontweight="bold", color=THEME["text"])
    ax4.set_xticks(x); ax4.set_xticklabels(case_labels, rotation=20, ha="right", fontsize=7)
    ax4.set_title("New Processes", fontsize=9, color=THEME["text"])
    ax4.grid(axis="y", zorder=0, alpha=0.4); _spines(ax4)

    # Panel 5 — IOC count
    ax5 = fig.add_subplot(gs[1, 1])
    ax5.set_facecolor(THEME["panel"])
    iocs = matrix_df["IOCs"].tolist() if "IOCs" in matrix_df.columns else [0]*n
    bars5 = ax5.bar(x, iocs, color=THEME["info"], zorder=3, edgecolor=THEME["bg"])
    for bar, v in zip(bars5, iocs):
        ax5.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.1,
                 str(v), ha="center", fontsize=8, fontweight="bold", color=THEME["text"])
    ax5.set_xticks(x); ax5.set_xticklabels(case_labels, rotation=20, ha="right", fontsize=7)
    ax5.set_title("IOCs Extracted", fontsize=9, color=THEME["text"])
    ax5.grid(axis="y", zorder=0, alpha=0.4); _spines(ax5)

    # Panel 6 — DLL hijack findings
    ax6 = fig.add_subplot(gs[1, 2])
    ax6.set_facecolor(THEME["panel"])
    dll = matrix_df["DLL_Hijack_Findings"].tolist() if "DLL_Hijack_Findings" in matrix_df.columns else [0]*n
    cols6 = [THEME["accent"] if v > 0 else THEME["safe"] for v in dll]
    bars6 = ax6.bar(x, dll, color=cols6, zorder=3, edgecolor=THEME["bg"])
    for bar, v in zip(bars6, dll):
        ax6.text(bar.get_x()+bar.get_width()/2, max(bar.get_height(), 0)+0.05,
                 str(v), ha="center", fontsize=8, fontweight="bold", color=THEME["text"])
    ax6.set_xticks(x); ax6.set_xticklabels(case_labels, rotation=20, ha="right", fontsize=7)
    ax6.set_title("DLL Hijack Findings", fontsize=9, color=THEME["text"])
    ax6.set_ylim(0, max(max(dll), 1)*1.4+0.5)
    ax6.grid(axis="y", zorder=0, alpha=0.4); _spines(ax6)

    # Panel 7 spanning — Severity summary table (text)
    ax7 = fig.add_subplot(gs[2, :])
    ax7.set_facecolor(THEME["panel"])
    ax7.axis("off")

    col_heads = ["Case", "Severity", "Max Score", "Critical", "Techniques", "RWX", "DLL Hijack", "IOCs", "New Procs"]
    col_keys  = ["Case","Severity","MaxRiskScore","CriticalProcesses",
                 "Techniques_Detected","RWX_Regions","DLL_Hijack_Findings","IOCs","NewProcesses"]

    table_data = [[str(matrix_df.iloc[i].get(k, "")) for k in col_keys] for i in range(len(matrix_df))]
    tbl = ax7.table(
        cellText   = table_data,
        colLabels  = col_heads,
        loc        = "center",
        cellLoc    = "center",
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(8.5)
    tbl.scale(1, 1.6)

    # Header style
    for j in range(len(col_heads)):
        tbl[0, j].set_facecolor(THEME["info"])
        tbl[0, j].set_text_props(color="white", fontweight="bold")

    # Row colours
    sev_bg = {"CRITICAL":"#3a1010","HIGH":"#3a2800","MEDIUM":"#0f1e3a","LOW":"#0f2a17","UNKNOWN":"#1a1a1a"}
    for i in range(len(table_data)):
        sev = matrix_df.iloc[i].get("Severity","UNKNOWN")
        bg  = sev_bg.get(sev, "#161b22")
        for j in range(len(col_heads)):
            tbl[i+1, j].set_facecolor(bg)
            tbl[i+1, j].set_text_props(color=THEME["text"])

    ax7.set_title("SUMMARY TABLE — ALL CASES",
                  fontsize=10, fontweight="bold", color=THEME["text"], pad=12)

    _save(fig, os.path.join(out_dir, "comparison_dashboard.png"))


# ============================================================
# HTML Comparison Report
# ============================================================

def generate_comparison_html(cases: list, matrix_df: pd.DataFrame,
                              out_dir: str, generated_at: str):
    """Full interactive HTML comparison report."""

    def img_tag(fname):
        b64 = _img_b64(os.path.join(out_dir, fname))
        if not b64:
            return f"<p style='color:#8b949e'>[Chart not available: {fname}]</p>"
        return f'<img src="data:image/png;base64,{b64}" style="max-width:100%;border-radius:6px;margin:10px 0">'

    # Build techniques table
    all_techs = {}
    for c in cases:
        tags = c["attack_tags"]
        if not tags.empty and "Technique" in tags.columns:
            for _, row in tags.iterrows():
                tid = str(row.get("Technique",""))
                all_techs[tid] = {
                    "name":  str(row.get("TechniqueName", tid)),
                    "tactic":str(row.get("Tactic","?")),
                    "url":   str(row.get("ATT&CK_URL","")),
                }

    tech_rows = ""
    for tid, info in sorted(all_techs.items()):
        detected = []
        not_det  = []
        for c in cases:
            tags = c["attack_tags"]
            found = (not tags.empty and "Technique" in tags.columns
                     and tid in tags["Technique"].astype(str).values)
            if found:
                detected.append(c["label"])
            else:
                not_det.append(c["label"])
        cells = ""
        for c in cases:
            found = c["label"] in detected
            cells += (f'<td style="text-align:center;background:#0f2a17">✅</td>'
                      if found else
                      f'<td style="text-align:center;background:#1a1010">❌</td>')
        url = info.get("url","")
        tid_link = f'<a href="{url}" target="_blank" style="color:#58a6ff">{tid}</a>' if url else tid
        tech_rows += (f'<tr><td>{tid_link}</td>'
                      f'<td>{info["tactic"]}</td>'
                      f'<td>{info["name"]}</td>'
                      f'{cells}</tr>\n')

    case_headers = "".join(f'<th>{c["label"]}</th>' for c in cases)

    # Build summary rows
    summary_rows = ""
    sev_colors = {"CRITICAL":"#c00000","HIGH":"#c55a11","MEDIUM":"#d29922","LOW":"#375623"}
    for _, row in matrix_df.iterrows():
        sev   = str(row.get("Severity","UNKNOWN"))
        color = sev_colors.get(sev, "#aaaaaa")
        cells = "".join(
            f'<td style="text-align:center">{row.get(k,"")}</td>'
            for k in ["Severity","MaxRiskScore","CriticalProcesses",
                      "Techniques_Detected","RWX_Regions",
                      "DLL_Hijack_Findings","IOCs","NewProcesses"]
        )
        summary_rows += (f'<tr><td><b>{row.get("Case","")}</b></td>'
                         f'{cells}</tr>\n')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MFF v2 — Cross-Case Comparison Report</title>
<style>
  :root {{
    --bg:#0d1117; --panel:#161b22; --border:#30363d;
    --accent:#f78166; --safe:#3fb950; --warn:#d29922;
    --info:#58a6ff; --text:#e6edf3; --sub:#8b949e;
    --crit:#c00000; --high:#c55a11;
  }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:"Segoe UI",system-ui,monospace; background:var(--bg); color:var(--text); padding:24px; }}
  h1 {{ color:var(--accent); font-size:1.9rem; margin-bottom:4px; }}
  h2 {{ color:var(--info); font-size:1.2rem; border-bottom:2px solid var(--info); padding-bottom:6px; margin:28px 0 14px; }}
  h3 {{ color:var(--warn); font-size:1rem; margin:18px 0 8px; }}
  .meta {{ color:var(--sub); font-size:.85rem; margin-bottom:20px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:14px; margin:14px 0; }}
  .card {{ background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:16px; }}
  .card .val {{ font-size:1.6rem; font-weight:700; color:var(--accent); }}
  .card .lbl {{ font-size:.8rem; color:var(--sub); margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; font-size:.85rem; }}
  th {{ background:#1f3864; color:#fff; padding:8px 10px; text-align:left; }}
  td {{ padding:7px 10px; border-bottom:1px solid var(--border); }}
  tr:hover td {{ background:#1c2128; }}
  .sev-CRITICAL {{ color:#ff6b6b; font-weight:700; }}
  .sev-HIGH     {{ color:#d29922; font-weight:700; }}
  .sev-MEDIUM   {{ color:#58a6ff; font-weight:700; }}
  .sev-LOW      {{ color:#3fb950; }}
  .img-wrap {{ background:var(--panel); border-radius:8px; padding:14px; margin:10px 0; }}
  footer {{ margin-top:40px; color:var(--sub); font-size:.78rem; text-align:center; border-top:1px solid var(--border); padding-top:12px; }}
  .tag {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:.78rem; font-weight:600; margin:2px; }}
  .tag-crit {{ background:#3a1010; color:#ff6b6b; }}
  .tag-high {{ background:#3a2800; color:#d29922; }}
  .tag-med  {{ background:#0f1e3a; color:#58a6ff; }}
  .tag-low  {{ background:#0f2a17; color:#3fb950; }}
</style>
</head>
<body>
<h1>🔬 MFF v2 — Cross-Case Comparison Report</h1>
<p class="meta">Generated: {generated_at} &nbsp;|&nbsp; Cases compared: {len(cases)}</p>

<h2>1. Overview — All Cases</h2>
<div class="grid">
{''.join(f"""<div class="card">
  <div class="lbl">{c["label"]}</div>
  <div class="val {f'sev-{c["severity"]}'}">{c["severity"]}</div>
  <div class="lbl">Max Risk: {(int(c["scores"]["RiskScore"].max()) if not c["scores"].empty and "RiskScore" in c["scores"].columns else 0)}</div>
  <div class="lbl">Techniques: {c["techniques"]} &nbsp;|&nbsp; IOCs: {c["ioc_count"]}</div>
</div>""" for c in cases)}
</div>

<h2>2. Comparison Dashboard</h2>
<div class="img-wrap">{img_tag("comparison_dashboard.png")}</div>

<h2>3. Risk Score Comparison</h2>
<div class="img-wrap">{img_tag("comparison_chart_risk.png")}</div>

<h2>4. Process Delta</h2>
<div class="img-wrap">{img_tag("comparison_chart_processes.png")}</div>

<h2>5. ATT&CK Tactic Coverage</h2>
<div class="img-wrap">{img_tag("comparison_chart_tactics.png")}</div>

<h2>6. MITRE ATT&CK Detection Matrix</h2>
<div class="img-wrap">{img_tag("comparison_chart_attacks.png")}</div>

<h2>7. Artefact Counts</h2>
<div class="img-wrap">{img_tag("comparison_chart_artefacts.png")}</div>

<h2>8. Summary Table</h2>
<table>
<tr>
  <th>Case</th><th>Severity</th><th>Max Score</th><th>Critical</th>
  <th>Techniques</th><th>RWX Regions</th><th>DLL Hijack</th>
  <th>IOCs</th><th>New Processes</th>
</tr>
{summary_rows}
</table>

<h2>9. Technique Detection Matrix</h2>
<table>
<tr><th>Technique</th><th>Tactic</th><th>Name</th>{case_headers}</tr>
{tech_rows}
</table>

<footer>
MFF v2 — Memory Forensics Framework &nbsp;·&nbsp; Cross-Case Comparison &nbsp;·&nbsp; {generated_at}
</footer>
</body>
</html>"""

    path = os.path.join(out_dir, "comparison_report.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  [+] HTML comparison report: {path}")
    return path


# ============================================================
# PDF Comparison Report
# ============================================================

def generate_comparison_pdf(cases: list, matrix_df: pd.DataFrame,
                             out_dir: str, generated_at: str):
    """Professional PDF comparison report using ReportLab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch, cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            Image, HRFlowable, PageBreak,
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        def S(name, **kw):
            from reportlab.lib.styles import ParagraphStyle
            return ParagraphStyle(name, **kw)

        NAVY  = colors.HexColor("#1F3864")
        BLUE  = colors.HexColor("#2E75B6")
        TEAL  = colors.HexColor("#17375E")
        ACC   = colors.HexColor("#f78166")
        INFO  = colors.HexColor("#58a6ff")
        WARN  = colors.HexColor("#d29922")
        SAFE  = colors.HexColor("#3fb950")
        GREY  = colors.HexColor("#404040")
        LGREY = colors.HexColor("#D9E2F3")
        WHITE = colors.white
        BLACK = colors.black
        CRIT  = colors.HexColor("#C00000")
        HIGH  = colors.HexColor("#C55A11")

        sev_color = {"CRITICAL":CRIT,"HIGH":HIGH,"MEDIUM":BLUE,"LOW":SAFE}

        sH1   = S("H1",   fontName="Helvetica-Bold",  fontSize=16, textColor=NAVY,  spaceAfter=8)
        sH2   = S("H2",   fontName="Helvetica-Bold",  fontSize=12, textColor=BLUE,  spaceAfter=6)
        sBody = S("Body", fontName="Helvetica",        fontSize=9,  textColor=GREY,  spaceAfter=4)
        sSub  = S("Sub",  fontName="Helvetica-Oblique",fontSize=8,  textColor=colors.HexColor("#8b949e"))
        sMono = S("Mono", fontName="Courier",           fontSize=8,  textColor=GREY)

        def spacer(n=0.15):
            return Spacer(1, n*inch)

        def hline(c=BLUE, w=0.6):
            return HRFlowable(width="100%", thickness=w, color=c, spaceAfter=6, spaceBefore=2)

        pdf_path = os.path.join(out_dir, "comparison_report.pdf")
        doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                                topMargin=0.7*inch, bottomMargin=0.7*inch,
                                leftMargin=0.8*inch, rightMargin=0.8*inch)
        W = A4[0] - 1.6*inch
        story = []

        # Cover
        story.append(spacer(1.5))
        story.append(Paragraph("MFF v2", S("cov1", fontName="Helvetica-Bold",
                                            fontSize=36, textColor=BLUE, alignment=TA_CENTER)))
        story.append(Paragraph("Memory Forensics Framework",
                                S("cov2", fontName="Helvetica-Bold", fontSize=18,
                                  textColor=NAVY, alignment=TA_CENTER)))
        story.append(Paragraph("Cross-Case Comparison Report",
                                S("cov3", fontName="Helvetica", fontSize=14,
                                  textColor=GREY, alignment=TA_CENTER, spaceAfter=20)))
        story.append(hline(BLUE, 1))
        story.append(spacer(0.3))

        # Cover metadata table
        meta_data = [
            ["Generated", generated_at],
            ["Cases compared", str(len(cases))],
            ["Case labels", " · ".join(c["label"] for c in cases)],
        ]
        meta_tbl = Table(meta_data, colWidths=[W*0.28, W*0.72])
        meta_tbl.setStyle(TableStyle([
            ("FONTNAME",    (0,0),(-1,-1), "Helvetica"),
            ("FONTSIZE",    (0,0),(-1,-1), 9),
            ("FONTNAME",    (0,0),(0,-1),  "Helvetica-Bold"),
            ("TEXTCOLOR",   (0,0),(0,-1),  BLUE),
            ("TEXTCOLOR",   (1,0),(1,-1),  GREY),
            ("GRID",        (0,0),(-1,-1), 0.4, colors.HexColor("#CCCCCC")),
            ("BACKGROUND",  (0,0),(0,-1),  LGREY),
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[WHITE, colors.HexColor("#F2F7FF")]),
            ("PADDING",     (0,0),(-1,-1), 5),
        ]))
        story.append(meta_tbl)
        story.append(PageBreak())

        # 1. Executive Summary table
        story.append(Paragraph("1.  EXECUTIVE SUMMARY", sH1))
        story.append(hline(BLUE))

        col_heads  = ["Case","Severity","Max Score","Critical","Techniques","RWX","DLL Hijack","IOCs","New Procs"]
        col_keys   = ["Case","Severity","MaxRiskScore","CriticalProcesses",
                      "Techniques_Detected","RWX_Regions","DLL_Hijack_Findings","IOCs","NewProcesses"]
        col_widths = [W*0.22, W*0.10, W*0.09, W*0.09,
                      W*0.12, W*0.09, W*0.11, W*0.09, W*0.09]

        tbl_data = [col_heads]
        for _, row in matrix_df.iterrows():
            tbl_data.append([str(row.get(k,"")) for k in col_keys])

        tbl = Table(tbl_data, colWidths=col_widths, repeatRows=1)
        style = [
            ("FONTNAME",    (0,0),(-1,0),  "Helvetica-Bold"),
            ("FONTNAME",    (0,1),(-1,-1), "Helvetica"),
            ("FONTSIZE",    (0,0),(-1,-1), 8),
            ("BACKGROUND",  (0,0),(-1,0),  BLUE),
            ("TEXTCOLOR",   (0,0),(-1,0),  WHITE),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, colors.HexColor("#F0F5FF")]),
            ("GRID",        (0,0),(-1,-1), 0.4, colors.HexColor("#CCCCCC")),
            ("PADDING",     (0,0),(-1,-1), 5),
            ("ALIGN",       (2,0),(-1,-1), "CENTER"),
        ]
        # colour severity cells
        for ri, (_, row) in enumerate(matrix_df.iterrows(), start=1):
            sev = str(row.get("Severity","UNKNOWN"))
            c2  = sev_color.get(sev, GREY)
            style.append(("TEXTCOLOR", (1, ri), (1, ri), c2))
            style.append(("FONTNAME",  (1, ri), (1, ri), "Helvetica-Bold"))
        tbl.setStyle(TableStyle(style))
        story.append(tbl)
        story.append(spacer(0.3))

        # 2. Dashboard image
        story.append(Paragraph("2.  COMPARISON DASHBOARD", sH1))
        story.append(hline(BLUE))
        dash_img = os.path.join(out_dir, "comparison_dashboard.png")
        if os.path.exists(dash_img):
            story.append(Image(dash_img, width=W, height=W*0.6))
        story.append(PageBreak())

        # 3. Individual charts
        chart_pairs = [
            ("3.  RISK SCORE COMPARISON",  "comparison_chart_risk.png"),
            ("4.  PROCESS DELTA",          "comparison_chart_processes.png"),
            ("5.  ATT&CK TACTIC COVERAGE", "comparison_chart_tactics.png"),
            ("6.  MITRE ATT&CK MATRIX",    "comparison_chart_attacks.png"),
            ("7.  ARTEFACT COUNTS",        "comparison_chart_artefacts.png"),
        ]
        for section_title, chart_file in chart_pairs:
            story.append(Paragraph(section_title, sH1))
            story.append(hline(BLUE))
            cpath = os.path.join(out_dir, chart_file)
            if os.path.exists(cpath):
                story.append(Image(cpath, width=W, height=W*0.48))
            else:
                story.append(Paragraph(f"[Chart not generated: {chart_file}]", sSub))
            story.append(spacer(0.2))

        story.append(PageBreak())

        # 8. Technique detection matrix table
        story.append(Paragraph("8.  TECHNIQUE DETECTION MATRIX", sH1))
        story.append(hline(BLUE))

        all_techs = {}
        for c in cases:
            tags = c["attack_tags"]
            if not tags.empty and "Technique" in tags.columns:
                for _, row in tags.iterrows():
                    tid = str(row.get("Technique",""))
                    all_techs[tid] = {
                        "name":  str(row.get("TechniqueName", tid)),
                        "tactic":str(row.get("Tactic","?")),
                    }

        if all_techs:
            case_short = [c["label"][:14] for c in cases]
            tmatrix_head = ["Technique", "Tactic", "Name"] + case_short
            tmatrix_cw   = ([W*0.12, W*0.15, W*0.25] +
                             [W*0.48/max(len(cases),1)]*len(cases))
            tmatrix_data = [tmatrix_head]
            for tid in sorted(all_techs.keys()):
                info  = all_techs[tid]
                cells = []
                for c in cases:
                    tags = c["attack_tags"]
                    found = (not tags.empty and "Technique" in tags.columns
                             and tid in tags["Technique"].astype(str).values)
                    cells.append("✓" if found else "·")
                tmatrix_data.append([tid, info["tactic"], info["name"]] + cells)

            tm = Table(tmatrix_data, colWidths=tmatrix_cw, repeatRows=1)
            tm_style = [
                ("FONTNAME",   (0,0),(-1,0),  "Helvetica-Bold"),
                ("FONTNAME",   (0,1),(-1,-1), "Helvetica"),
                ("FONTSIZE",   (0,0),(-1,-1), 7.5),
                ("BACKGROUND", (0,0),(-1,0),  TEAL),
                ("TEXTCOLOR",  (0,0),(-1,0),  WHITE),
                ("GRID",       (0,0),(-1,-1), 0.4, colors.HexColor("#CCCCCC")),
                ("PADDING",    (0,0),(-1,-1), 4),
                ("ALIGN",      (3,0),(-1,-1), "CENTER"),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, colors.HexColor("#F0F5FF")]),
            ]
            # colour ✓ cells green
            for ri, row_d in enumerate(tmatrix_data[1:], start=1):
                for ci, val in enumerate(row_d[3:], start=3):
                    if val == "✓":
                        tm_style.append(("TEXTCOLOR", (ci, ri), (ci, ri), SAFE))
                        tm_style.append(("FONTNAME",  (ci, ri), (ci, ri), "Helvetica-Bold"))
            tm.setStyle(TableStyle(tm_style))
            story.append(tm)

        story.append(spacer(0.4))

        # 9. Case detail summaries
        story.append(PageBreak())
        story.append(Paragraph("9.  INDIVIDUAL CASE SUMMARIES", sH1))
        story.append(hline(BLUE))

        for c in cases:
            story.append(Paragraph(c["label"], sH2))
            scores = c["scores"]
            tags   = c["attack_tags"]
            top_proc = "—"
            if not scores.empty and "Process" in scores.columns:
                top_proc = str(scores.iloc[0].get("Process","—"))

            top_score = 0
            if not scores.empty and "RiskScore" in scores.columns:
                top_score = int(scores["RiskScore"].max())

            tech_list = "None detected"
            if not tags.empty and "Technique" in tags.columns:
                tech_list = ", ".join(sorted(tags["Technique"].unique()))

            detail = [
                ["Severity",              c["severity"]],
                ["Highest risk process",  f"{top_proc}  (score: {top_score})"],
                ["Techniques detected",   tech_list],
                ["New processes",         str(c["new_procs"])],
                ["RWX memory regions",    str(len(c["malfind"]) if not c["malfind"].empty else 0)],
                ["DLL hijack findings",   str(len(c["dll_hijack"]) if not c["dll_hijack"].empty else 0)],
                ["IOCs extracted",        str(c["ioc_count"])],
                ["Net new connections",   str(c["net_new_count"])],
            ]
            dtbl = Table(detail, colWidths=[W*0.35, W*0.65])
            dtbl.setStyle(TableStyle([
                ("FONTNAME",  (0,0),(0,-1), "Helvetica-Bold"),
                ("FONTNAME",  (1,0),(1,-1), "Helvetica"),
                ("FONTSIZE",  (0,0),(-1,-1),8.5),
                ("TEXTCOLOR", (0,0),(0,-1), BLUE),
                ("TEXTCOLOR", (1,0),(1,-1), GREY),
                ("GRID",      (0,0),(-1,-1),0.4, colors.HexColor("#CCCCCC")),
                ("ROWBACKGROUNDS",(0,0),(-1,-1),[WHITE, colors.HexColor("#F0F5FF")]),
                ("PADDING",   (0,0),(-1,-1),5),
            ]))
            story.append(dtbl)
            story.append(spacer(0.25))

        # 10. Methodology
        story.append(PageBreak())
        story.append(Paragraph("10.  METHODOLOGY", sH1))
        story.append(hline(BLUE))
        method = [
            ("Comparison method", "Each attack case analysed independently against the same baseline using "
                                  "comparison_engine_v2.py. Results (CSV + JSON) loaded by this comparison "
                                  "module and aggregated into cross-case charts and tables."),
            ("Risk scoring",      "Rule-based transparent scoring (no ML). RWX +60 · Suspicious cmdline +40 · "
                                  "Malicious name +50 · DLL hijack +30 · Anomaly bonus +15."),
            ("DLL analysis",      "dll_analysis.py checks windows.dlllist CSV for protected DLLs "
                                  "(amsi.dll, version.dll, etc.) loaded from non-System32 paths."),
            ("ATT&CK mapping",    "mitre_tagger.py — 30+ rule-based signatures across 8 tactics. "
                                  "Includes T1574.001 DLL hijacking, T1562 defense evasion, T1059 execution."),
            ("Framework",         "MFF v2 — Python Post-Volatility Memory Forensics Framework. "
                                  "FYP — University of Roehampton 2026. "
                                  "Modules: comparison_engine_v2, dll_analysis, mitre_tagger, "
                                  "network_ioc, process_tree, case_comparison, report_generator."),
        ]
        for label, text in method:
            story.append(Paragraph(f"<b>{label}:</b>  {text}", sBody))
            story.append(spacer(0.1))

        story += [spacer(0.5), hline(colors.HexColor("#8b949e"), 0.4)]
        story.append(Paragraph(
            f"MFF v2 Cross-Case Comparison  ·  {generated_at}",
            S("footer", fontName="Helvetica", fontSize=7,
              textColor=colors.HexColor("#8b949e"), alignment=TA_CENTER)
        ))

        doc.build(story)
        print(f"  [+] PDF comparison report: {pdf_path}")
        return pdf_path

    except ImportError:
        print("  [!] reportlab not installed — PDF skipped. Install: pip install reportlab")
        return None


# ============================================================
# Master runner
# ============================================================

def run(cases_input, out_dir: str, make_html: bool = True,
        make_pdf: bool = True) -> dict:
    """
    Run the full cross-case comparison.

    cases_input: list of (label, out_dir) tuples
                 e.g. [("Case02 T1055", "/MFF/analysis/comparison/case01_vs_case02"), ...]

    Returns dict with paths to all generated files.
    """
    os.makedirs(out_dir, exist_ok=True)
    gen_at = _now()

    print(f"\n{'='*65}")
    print(f"  MFF v2 — Cross-Case Comparison")
    print(f"  Cases : {len(cases_input)}")
    print(f"  Output: {out_dir}")
    print(f"  Time  : {gen_at}")
    print(f"{'='*65}\n")

    # Load all case results
    print("[1/5] Loading case results...")
    cases = []
    for label, case_out_dir in cases_input:
        if not os.path.isdir(case_out_dir):
            print(f"  [!] Directory not found: {case_out_dir} — skipping {label}")
            continue
        data = load_case_results(label, case_out_dir)
        cases.append(data)
        print(f"  [+] Loaded: {label}  severity={data['severity']}  "
              f"techniques={data['techniques']}  iocs={data['ioc_count']}")

    if not cases:
        print("[!] No valid cases found — aborting.")
        return {}

    # Build matrix
    print("[2/5] Building comparison matrix...")
    matrix_df = build_matrix(cases)
    matrix_df.to_csv(os.path.join(out_dir, "comparison_matrix.csv"), index=False)
    print(f"  [+] Matrix: {os.path.join(out_dir, 'comparison_matrix.csv')}")

    # Generate charts
    print("[3/5] Generating comparison charts...")
    chart_risk_comparison(cases, out_dir)
    chart_process_delta(cases, out_dir)
    chart_attack_matrix(cases, out_dir)
    chart_malfind_ioc(cases, out_dir)
    chart_technique_coverage(cases, out_dir)
    chart_dashboard(cases, matrix_df, out_dir)

    outputs = {}

    # HTML report
    if make_html:
        print("[4/5] Generating HTML comparison report...")
        outputs["html"] = generate_comparison_html(cases, matrix_df, out_dir, gen_at)

    # PDF report
    if make_pdf:
        print("[5/5] Generating PDF comparison report...")
        outputs["pdf"] = generate_comparison_pdf(cases, matrix_df, out_dir, gen_at)

    print(f"\n{'='*65}")
    print(f"  ✓  Comparison complete")
    print(f"  Cases analysed : {len(cases)}")
    print(f"  Output dir     : {out_dir}")
    print(f"{'='*65}\n")

    return outputs


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MFF v2 — Cross-Case Comparison Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python case_comparison.py \\
    --dirs "Case02 T1055:/MFF/analysis/comparison/case01_vs_case02" \\
           "Case03 T1059:/MFF/analysis/comparison/case01_vs_case03" \\
           "Case04 T1574:/MFF/analysis/comparison/case01_vs_case04" \\
           "Case05 Multi:/MFF/analysis/comparison/case01_vs_case05" \\
    --out /MFF/analysis/comparison_report \\
    --make-html --make-pdf
        """
    )
    parser.add_argument("--dirs", nargs="+", required=True,
                        help="'Label:out_dir' pairs e.g. 'Case02:/MFF/analysis/case01_vs_case02'")
    parser.add_argument("--out", required=True, help="Output directory for comparison report")
    parser.add_argument("--make-html", action="store_true", help="Generate HTML report")
    parser.add_argument("--make-pdf",  action="store_true", help="Generate PDF report")
    args = parser.parse_args()

    cases_input = []
    for item in args.dirs:
        if ":" not in item:
            print(f"[!] Skipping invalid --dirs entry (no colon): {item}")
            continue
        # split on FIRST colon only (Windows paths have colons)
        idx   = item.index(":")
        label = item[:idx].strip()
        path  = item[idx+1:].strip()
        cases_input.append((label, path))

    if not cases_input:
        print("[!] No valid cases specified.")
        sys.exit(1)

    run(
        cases_input = cases_input,
        out_dir     = args.out,
        make_html   = args.make_html,
        make_pdf    = args.make_pdf,
    )
