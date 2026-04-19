#!/usr/bin/env python3

import os
import argparse
import pandas as pd
from datetime import datetime, UTC
import hashlib
import json

# ------------------------------------------------------------
# Utility
# ------------------------------------------------------------

def now():
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def safe_read_csv(path):
    if not os.path.exists(path):
        print(f"[!] Missing file: {path}")
        return pd.DataFrame()
    return pd.read_csv(path)


# ------------------------------------------------------------
# Dataset Manifest
# ------------------------------------------------------------

def create_manifest(case_path):

    manifest = {}

    exports = os.path.join(case_path, "exports", "csv")

    manifest["case_path"] = case_path
    manifest["generated"] = now()
    manifest["files"] = []

    if not os.path.exists(exports):
        return manifest

    for f in os.listdir(exports):

        fp = os.path.join(exports, f)

        size = os.path.getsize(fp)

        manifest["files"].append({
            "file": f,
            "size": size
        })

    return manifest


# ------------------------------------------------------------
# Load Case Data
# ------------------------------------------------------------

def load_case(case_path):

    exports = os.path.join(case_path, "exports", "csv")

    data = {
        "pslist": safe_read_csv(os.path.join(exports, "windows.pslist.csv")),
        "cmdline": safe_read_csv(os.path.join(exports, "windows.cmdline.csv")),
        "malfind": safe_read_csv(os.path.join(exports, "windows.malfind.csv")),
        "netscan": safe_read_csv(os.path.join(exports, "windows.netscan.csv"))
    }

    return data


# ------------------------------------------------------------
# Process Difference Detection
# ------------------------------------------------------------

def process_diff(base_df, attack_df):

    if base_df.empty or attack_df.empty:
        return pd.DataFrame()

    new_proc = attack_df[
        ~attack_df["ImageFileName"].isin(base_df["ImageFileName"])
    ]

    return new_proc


# ------------------------------------------------------------
# Suspicious Command Line Detection
# ------------------------------------------------------------

def cmdline_findings(df):

    if df.empty:
        return pd.DataFrame()

    patterns = [
        "powershell",
        "EncodedCommand",
        "ExecutionPolicy",
        "AtomicRedTeam",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "RWXinjection",
        "mshta"
    ]

    findings = []

    for p in patterns:

        mask = df["Args"].astype(str).str.contains(p, case=False, na=False)

        m = df[mask]

        if not m.empty:
            findings.append(m)

    if findings:
        return pd.concat(findings).drop_duplicates()
    else:
        return pd.DataFrame()


# ------------------------------------------------------------
# RWX Memory Detection
# ------------------------------------------------------------

def malfind_analysis(df):

    if df.empty:
        return pd.DataFrame()

    suspicious = df[
        df["Protection"].astype(str).str.contains("EXECUTE", na=False)
    ]

    return suspicious


# ------------------------------------------------------------
# Timeline Correlation
# ------------------------------------------------------------

def timeline(ps_df):

    if ps_df.empty:
        return pd.DataFrame()

    df = ps_df.copy()

    if "CreateTime" in df.columns:

        df["CreateTime_dt"] = pd.to_datetime(
            df["CreateTime"],
            errors="coerce",
            utc=True
        )

    df = df.sort_values(by="CreateTime_dt", na_position="last")

    return df


# ------------------------------------------------------------
# Risk Scoring Engine
# ------------------------------------------------------------

def scoring(process_df, cmd_df, mal_df):

    scores = []

    for _, row in process_df.iterrows():

        pid = row.get("PID")
        name = row.get("ImageFileName", "Unknown")

        score = 0
        reasons = []

        if not cmd_df.empty and pid in cmd_df["PID"].values:

            score += 40
            reasons.append("Suspicious command line")

        if not mal_df.empty and pid in mal_df["PID"].values:

            score += 60
            reasons.append("RWX memory region")

        if "powershell" in name.lower():

            score += 30
            reasons.append("Command interpreter")

        scores.append({
            "PID": pid,
            "Process": name,
            "RiskScore": score,
            "Indicators": "; ".join(reasons)
        })

    df = pd.DataFrame(scores)

    if not df.empty:
        df = df.sort_values(by="RiskScore", ascending=False)

    return df


# ------------------------------------------------------------
# HTML Report
# ------------------------------------------------------------

def generate_html(out, proc, cmd, mal, score, baseline, attack):

    path = os.path.join(out, "comparison_report.html")

    with open(path, "w") as f:

        f.write("<html><head><title>Memory Comparison</title></head><body>")

        f.write("<h1>Memory Forensics Comparison Report</h1>")

        f.write(f"<p>Generated: {now()}</p>")

        f.write("<h2>Dataset</h2>")
        f.write(f"<p>Baseline: {baseline}</p>")
        f.write(f"<p>Attack: {attack}</p>")

        f.write("<h2>New Processes</h2>")
        f.write(proc.to_html(index=False))

        f.write("<h2>Suspicious Command Lines</h2>")
        f.write(cmd.to_html(index=False))

        f.write("<h2>RWX Memory Findings</h2>")
        f.write(mal.to_html(index=False))

        f.write("<h2>Risk Scores</h2>")
        f.write(score.to_html(index=False))

        f.write("</body></html>")

    print(f"[+] HTML report generated: {path}")


# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("--baseline", required=True)
    parser.add_argument("--attack", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--make-html", action="store_true")

    args = parser.parse_args()

    print("\n=== Comparison Configuration ===")
    print(f"Baseline case : {args.baseline}")
    print(f"Attack case   : {args.attack}")
    print(f"Output folder : {args.out}")
    print("================================\n")

    ensure_dir(args.out)

    base = load_case(args.baseline)
    attack = load_case(args.attack)

    proc_df = process_diff(base["pslist"], attack["pslist"])
    cmd_df = cmdline_findings(attack["cmdline"])
    mal_df = malfind_analysis(attack["malfind"])
    timeline_df = timeline(attack["pslist"])
    score_df = scoring(proc_df, cmd_df, mal_df)

    proc_df.to_csv(os.path.join(args.out, "process_diff.csv"), index=False)
    cmd_df.to_csv(os.path.join(args.out, "cmdline_diff.csv"), index=False)
    mal_df.to_csv(os.path.join(args.out, "malfind_diff.csv"), index=False)
    timeline_df.to_csv(os.path.join(args.out, "timeline.csv"), index=False)
    score_df.to_csv(os.path.join(args.out, "scores.csv"), index=False)

    manifest = {
        "baseline": create_manifest(args.baseline),
        "attack": create_manifest(args.attack),
        "generated": now()
    }

    with open(os.path.join(args.out, "dataset_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=4)

    if args.make_html:
        generate_html(args.out, proc_df, cmd_df, mal_df, score_df,
                      args.baseline, args.attack)

    print("[+] Comparison completed successfully")


if __name__ == "__main__":
    main()
