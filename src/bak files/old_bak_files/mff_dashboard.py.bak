#!/usr/bin/env python3
"""
MFF v2 — CLI Dashboard
Live terminal dashboard showing analysis results.
Uses only stdlib — no rich/textual required.
Reads output CSVs and JSON from a completed analysis run.

Usage:
  python mff_dashboard.py --out /MFF/analysis/comparison/case01_vs_case03
  python mff_dashboard.py --out /MFF/analysis/comparison/case01_vs_case03 --watch
"""

import os
import sys
import time
import json
import argparse
import csv
from datetime import datetime


# ── ANSI codes (work on Linux/Mac, Windows 10+ with VT enabled)
R  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[38;5;203m"
GREEN  = "\033[38;5;71m"
YELLOW = "\033[38;5;178m"
BLUE   = "\033[38;5;75m"
CYAN   = "\033[38;5;80m"
WHITE  = "\033[38;5;253m"
GREY   = "\033[38;5;240m"
BG_PNL = "\033[48;5;235m"
CLEAR  = "\033[2J\033[H"


def sev_color(s):
    return {
        "CRITICAL": RED+BOLD,
        "HIGH":     YELLOW+BOLD,
        "MEDIUM":   BLUE,
        "LOW":      GREEN,
    }.get(str(s).upper(), WHITE)


def bar(value, max_val, width=20, fill="█", empty="░"):
    if max_val == 0:
        filled = 0
    else:
        filled = int((value / max_val) * width)
    return GREEN + fill * filled + GREY + empty * (width - filled) + R


def box(title, lines, width=70):
    top    = f"┌─ {CYAN}{BOLD}{title}{R} " + "─" * max(0, width - len(title) - 4) + "┐"
    bottom = "└" + "─" * (width - 2) + "┘"
    body   = []
    for line in lines:
        # strip ANSI for length calc
        import re
        clean = re.sub(r'\033\[[0-9;]*m', '', line)
        pad   = max(0, width - 2 - len(clean))
        body.append(f"│ {line}{' '*pad} │")
    return "\n".join([top] + body + [bottom])


def read_csv_rows(path, max_rows=12):
    if not os.path.exists(path):
        return [], []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows   = list(reader)[:max_rows]
        return reader.fieldnames or [], rows


def read_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def format_table(headers, rows, col_widths=None, max_col=18):
    if not headers or not rows:
        return [f"  {GREY}(no data){R}"]
    lines = []
    cols  = headers[:6]  # show first 6 columns max
    if not col_widths:
        col_widths = [min(max_col, max(len(str(c)), max(
            (len(str(r.get(c,""))) for r in rows), default=4
        ))) for c in cols]

    header_line = "  " + "  ".join(
        f"{CYAN}{str(c)[:col_widths[i]]:<{col_widths[i]}}{R}"
        for i, c in enumerate(cols))
    lines.append(header_line)
    lines.append("  " + GREY + "─" * (sum(col_widths) + 2*len(cols)) + R)

    for row in rows:
        row_vals = []
        for i, c in enumerate(cols):
            val = str(row.get(c, ""))[:col_widths[i]]
            w   = col_widths[i]
            if c in ("RiskScore","Score"):
                try:
                    s = int(val)
                    color = RED if s>=80 else YELLOW if s>=50 else BLUE if s>=20 else GREEN
                    row_vals.append(f"{color}{val:<{w}}{R}")
                except ValueError:
                    row_vals.append(f"{val:<{w}}")
            elif c == "RiskLevel":
                row_vals.append(f"{sev_color(val)}{val:<{w}}{R}")
            elif c == "Tactic":
                row_vals.append(f"{YELLOW}{val:<{w}}{R}")
            elif c == "Technique":
                row_vals.append(f"{BLUE}{val:<{w}}{R}")
            else:
                row_vals.append(f"{WHITE}{val:<{w}}{R}")
        lines.append("  " + "  ".join(row_vals))

    return lines


def render(out_dir):
    summary   = read_json(os.path.join(out_dir, "threat_summary.json"))
    sev            = summary.get("severity", {}).get("overall", "UNKNOWN")
    stats          = summary.get("statistics", {})
    critical_count = summary.get("severity", {}).get("critical_processes", 0)
    case_id   = summary.get("case_id", os.path.basename(out_dir))
    gen_at    = summary.get("generated_at", "?")
    tactics   = summary.get("mitre_attack", {}).get("tactics_observed", [])

    _, score_rows = read_csv_rows(os.path.join(out_dir, "scores.csv"), 10)
    _, atk_rows   = read_csv_rows(os.path.join(out_dir, "attack_tags.csv"), 10)
    _, ioc_rows   = read_csv_rows(os.path.join(out_dir, "iocs.csv"), 12)
    _, net_rows   = read_csv_rows(os.path.join(out_dir, "net_flagged.csv"), 8)
    _, new_rows   = read_csv_rows(os.path.join(out_dir, "process_new.csv"), 10)

    sev_c = sev_color(sev)
    w     = 72

    output = [CLEAR]
    output.append(f"{BOLD}{CYAN}{'━'*w}{R}")
    output.append(f"{BOLD}  MFF v2 — Memory Forensics CLI Dashboard{R}")
    output.append(f"  {DIM}Case: {WHITE}{case_id}{R}  {DIM}│{R}  {DIM}Analysed: {WHITE}{gen_at}{R}")
    output.append(f"  {DIM}Output: {GREY}{out_dir}{R}")
    output.append(f"{BOLD}{CYAN}{'━'*w}{R}")

    # ── Severity banner
    sc = {"CRITICAL":"\033[41m","HIGH":"\033[43m","MEDIUM":"\033[44m","LOW":"\033[42m"}.get(sev,"\033[47m")
    output.append(f"\n  {sc}{BOLD}  SEVERITY: {sev}  {R}\n")

    # ── Stats row
    stats_lines = [
        f"  {CYAN}{'New Processes':<28}{R}{RED}{BOLD}{stats.get('new_processes',0):<6}{R}  "
        f"{CYAN}{'ATT&CK Techniques':<28}{R}{YELLOW}{BOLD}{stats.get('attack_techniques',0)}{R}",

        f"  {CYAN}{'Gone Processes':<28}{R}{BLUE}{BOLD}{stats.get('gone_processes',0):<6}{R}  "
        f"{CYAN}{'ATT&CK Tactics':<28}{R}{YELLOW}{BOLD}{stats.get('attack_tactics',0)}{R}",

        f"  {CYAN}{'Critical Risk Processes':<28}{R}{RED}{BOLD}"
        f"{critical_count:<6}{R}  "
        f"{CYAN}{'IOCs Extracted':<28}{R}{GREEN}{BOLD}{stats.get('iocs_extracted',0)}{R}",

        f"  {CYAN}{'New Network Connections':<28}{R}{YELLOW}{BOLD}{stats.get('new_network_conns',0):<6}{R}  "
        f"{CYAN}{'Flagged Connections':<28}{R}{RED}{BOLD}{stats.get('flagged_network_conns',0)}{R}",
    ]
    output.append(box("Statistics", stats_lines, w))

    # ── ATT&CK Tactics
    if tactics:
        tac_per_row = 3
        tac_lines   = []
        for i in range(0, len(tactics), tac_per_row):
            chunk = tactics[i:i+tac_per_row]
            tac_lines.append("  " + "  │  ".join(f"{YELLOW}{t}{R}" for t in chunk))
        output.append("")
        output.append(box("MITRE ATT&CK Tactics Observed", tac_lines, w))

    # ── Top Risk Scores
    if score_rows:
        max_score = max((int(r.get("RiskScore",0)) for r in score_rows), default=100)
        sc_lines  = []
        for row in score_rows[:8]:
            name  = str(row.get("Process","?"))[:20]
            pid   = str(row.get("PID",""))
            score = int(row.get("RiskScore", 0))
            level = str(row.get("RiskLevel",""))
            b     = bar(score, max_score, 14)
            sc_lines.append(
                f"  {sev_color(level)}{name:<20}{R} {GREY}[{pid:>6}]{R}  "
                f"{b}  {sev_color(level)}{score:>3}{R}  {DIM}{level}{R}")
        output.append("")
        output.append(box("Top Risk Scores", sc_lines, w))

    # ── New Processes
    if new_rows:
        new_lines = format_table(
            ["ImageFileName","PID","PPID","CreateTime","DiffStatus"],
            new_rows, max_col=20)
        output.append("")
        output.append(box(f"New Processes (Attack Only) — {len(new_rows)} shown", new_lines, w))

    # ── ATT&CK Technique hits
    if atk_rows:
        atk_lines = format_table(
            ["Tactic","Technique","TechniqueName","MatchedKeyword","PID"],
            atk_rows, max_col=22)
        output.append("")
        output.append(box(f"ATT&CK Technique Hits — {len(atk_rows)} shown", atk_lines, w))

    # ── IOCs
    if ioc_rows:
        ioc_lines = format_table(
            ["Type","Value","Source","Count"],
            ioc_rows, max_col=40)
        output.append("")
        output.append(box(f"Top IOCs — {len(ioc_rows)} shown", ioc_lines, w))

    # ── Flagged Network
    if net_rows:
        net_lines = format_table(
            ["PID","ForeignAddr","ForeignPort","State","SuspiciousPort","PortMeaning"],
            net_rows, max_col=20)
        output.append("")
        output.append(box(f"Flagged Network Connections — {len(net_rows)} shown", net_lines, w))

    # ── Footer
    output.append(f"\n{CYAN}{'━'*w}{R}")
    output.append(f"  {GREY}Output files: {', '.join(f for f in os.listdir(out_dir) if f.endswith(('.html','.pdf','.json')))}{R}")
    output.append(f"  {GREY}Refreshed: {datetime.utcnow().strftime('%H:%M:%S UTC')}{R}")
    output.append(f"{CYAN}{'━'*w}{R}\n")

    return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(description="MFF v2 CLI Dashboard")
    parser.add_argument("--out",     required=True, help="Analysis output directory")
    parser.add_argument("--watch",   action="store_true",
                        help="Live refresh mode (refreshes every 10s)")
    parser.add_argument("--interval",type=int, default=10,
                        help="Refresh interval in seconds (default: 10)")
    args = parser.parse_args()

    if not os.path.isdir(args.out):
        print(f"[!] Output directory not found: {args.out}")
        sys.exit(1)

    if args.watch:
        print(f"[*] Live dashboard — Ctrl+C to exit")
        try:
            while True:
                print(render(args.out))
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[*] Dashboard stopped.")
    else:
        print(render(args.out))


if __name__ == "__main__":
    main()
