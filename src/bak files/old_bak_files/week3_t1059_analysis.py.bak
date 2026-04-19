import json
import os
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


CASE_DIR = Path("/MFF/cases/case03_t1059_attack")
EXPORT_JSONL = CASE_DIR / "exports" / "jsonl"

OUT_DIR = Path("/MFF/analysis/t1059/case03_t1059_attack")
TABLES_DIR = OUT_DIR / "tables"
FIGURES_DIR = OUT_DIR / "figures"

TABLES_DIR.mkdir(parents=True, exist_ok=True)
FIGURES_DIR.mkdir(parents=True, exist_ok=True)


def load_jsonl(path: Path) -> pd.DataFrame:
    if not path.exists():
        print(f"[!] Missing file: {path}")
        return pd.DataFrame()
    try:
        return pd.read_json(path, lines=True)
    except ValueError:
        print(f"[!] Could not parse JSONL: {path}")
        return pd.DataFrame()


def normalise_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [str(c).strip() for c in df.columns]
    return df


def safe_text(value) -> str:
    if pd.isna(value):
        return ""
    return str(value)


def find_process_artifacts(pslist_df: pd.DataFrame) -> pd.DataFrame:
    if pslist_df.empty:
        return pd.DataFrame()

    pslist_df = normalise_columns(pslist_df)

    process_col = None
    pid_col = None
    ppid_col = None

    for col in pslist_df.columns:
        lc = col.lower()
        if lc in ["imagefilename", "process", "name"]:
            process_col = col
        elif lc == "pid":
            pid_col = col
        elif lc == "ppid":
            ppid_col = col

    if not process_col or not pid_col:
        return pd.DataFrame()

    target_names = ["powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe"]

    findings = pslist_df[
        pslist_df[process_col].astype(str).str.lower().isin(target_names)
    ].copy()

    findings["ArtifactType"] = "Process Creation"
    findings["WhySuspicious"] = findings[process_col].astype(str).apply(
        lambda x: f"{x} is associated with command/script execution (T1059)"
    )

    keep_cols = [c for c in [pid_col, ppid_col, process_col, "ArtifactType", "WhySuspicious"] if c in findings.columns]
    return findings[keep_cols].sort_values(by=pid_col)


def find_parent_child_artifacts(pstree_df: pd.DataFrame) -> pd.DataFrame:
    if pstree_df.empty:
        return pd.DataFrame()

    pstree_df = normalise_columns(pstree_df)

    pid_col = None
    ppid_col = None
    proc_col = None

    for col in pstree_df.columns:
        lc = col.lower()
        if lc == "pid":
            pid_col = col
        elif lc == "ppid":
            ppid_col = col
        elif lc in ["imagefilename", "process", "name"]:
            proc_col = col

    if not pid_col or not ppid_col or not proc_col:
        return pd.DataFrame()

    df = pstree_df[[pid_col, ppid_col, proc_col]].copy()
    df["proc_lc"] = df[proc_col].astype(str).str.lower()

    pid_to_name = dict(zip(df[pid_col], df["proc_lc"]))

    suspicious_rows = []

    for _, row in df.iterrows():
        pid = row[pid_col]
        ppid = row[ppid_col]
        proc_name = row["proc_lc"]
        parent_name = pid_to_name.get(ppid, "unknown")

        suspicious = False
        reason = ""

        if proc_name == "powershell.exe" and parent_name == "explorer.exe":
            suspicious = True
            reason = "Interactive PowerShell launched from Explorer"
        elif proc_name == "powershell.exe" and parent_name == "powershell.exe":
            suspicious = True
            reason = "Nested PowerShell spawning detected"
        elif proc_name in ["notepad.exe", "mshta.exe", "cmd.exe"] and parent_name == "powershell.exe":
            suspicious = True
            reason = f"{proc_name} spawned by PowerShell"

        if suspicious:
            suspicious_rows.append({
                "PID": pid,
                "PPID": ppid,
                "Process": row[proc_col],
                "ParentProcess": parent_name,
                "ArtifactType": "Parent-Child Behaviour",
                "WhySuspicious": reason
            })

    return pd.DataFrame(suspicious_rows)


def find_commandline_artifacts(cmdline_df: pd.DataFrame) -> pd.DataFrame:
    if cmdline_df.empty:
        return pd.DataFrame()

    cmdline_df = normalise_columns(cmdline_df)

    pid_col = None
    proc_col = None
    cmd_col = None

    for col in cmdline_df.columns:
        lc = col.lower()
        if lc == "pid":
            pid_col = col
        elif lc in ["process", "imagefilename", "name"]:
            proc_col = col
        elif lc in ["args", "commandline", "cmdline"]:
            cmd_col = col

    if not pid_col or not proc_col:
        return pd.DataFrame()

    if not cmd_col:
        cmdline_df["ArgsDerived"] = ""
        cmd_col = "ArgsDerived"

    patterns = [
        "powershell",
        "-executionpolicy bypass",
        "-enc",
        "encodedcommand",
        "iex",
        "downloadstring",
        "mshta",
    ]

    findings = []

    for _, row in cmdline_df.iterrows():
        pid = row[pid_col]
        proc = safe_text(row[proc_col])
        cmd = safe_text(row[cmd_col])
        text = f"{proc} {cmd}".lower()

        matched = [p for p in patterns if p in text]
        if matched:
            findings.append({
                "PID": pid,
                "Process": proc,
                "CommandLine": cmd,
                "MatchedPatterns": "; ".join(matched),
                "ArtifactType": "Command Line Evidence",
                "WhySuspicious": "Suspicious PowerShell/command execution pattern detected"
            })

    return pd.DataFrame(findings)


def find_memory_artifacts(malfind_df: pd.DataFrame) -> pd.DataFrame:
    if malfind_df.empty:
        return pd.DataFrame()

    malfind_df = normalise_columns(malfind_df)

    pid_col = None
    proc_col = None
    prot_col = None
    priv_col = None
    tag_col = None

    for col in malfind_df.columns:
        lc = col.lower()
        if lc == "pid":
            pid_col = col
        elif lc in ["process", "imagefilename", "name"]:
            proc_col = col
        elif lc == "protection":
            prot_col = col
        elif lc == "privatememory":
            priv_col = col
        elif lc == "tag":
            tag_col = col

    if not pid_col or not proc_col or not prot_col:
        return pd.DataFrame()

    findings = []

    for _, row in malfind_df.iterrows():
        proc = safe_text(row[proc_col]).lower()
        protection = safe_text(row[prot_col]).upper()
        private_mem = safe_text(row[priv_col]) if priv_col else ""
        tag = safe_text(row[tag_col]) if tag_col else ""

        if proc == "powershell.exe" and "EXECUTE_READWRITE" in protection:
            findings.append({
                "PID": row[pid_col],
                "Process": row[proc_col],
                "Protection": protection,
                "PrivateMemory": private_mem,
                "Tag": tag,
                "ArtifactType": "In-Memory Execution",
                "WhySuspicious": "PowerShell has RWX executable memory region"
            })

    return pd.DataFrame(findings)


def score_artifacts(process_df, parent_df, cmd_df, mem_df) -> pd.DataFrame:
    scores = {}

    def ensure_pid(pid, process_name="unknown"):
        if pid not in scores:
            scores[pid] = {
                "PID": pid,
                "Process": process_name,
                "RiskScore": 0,
                "Indicators": []
            }

    for df, score_value, indicator_name in [
        (process_df, 20, "T1059-linked process"),
        (parent_df, 30, "Suspicious parent-child behaviour"),
        (cmd_df, 40, "Suspicious command line"),
        (mem_df, 60, "RWX memory region detected"),
    ]:
        if df.empty:
            continue
        for _, row in df.iterrows():
            pid = row.get("PID")
            process_name = row.get("Process", "unknown")
            ensure_pid(pid, process_name)
            scores[pid]["RiskScore"] += score_value
            scores[pid]["Indicators"].append(indicator_name)

    out = pd.DataFrame(scores.values())
    if out.empty:
        return out

    out["Indicators"] = out["Indicators"].apply(lambda x: "; ".join(sorted(set(x))))
    return out.sort_values(by="RiskScore", ascending=False)


def create_summary(process_df, parent_df, cmd_df, mem_df, score_df):
    summary_path = OUT_DIR / "summary.md"

    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("# Week 3 – T1059 Analysis Summary\n\n")
        f.write("## Dataset\n")
        f.write("- Case: case03_t1059_attack\n")
        f.write("- Dump: T1059.raw\n\n")

        f.write("## Artefact Counts\n")
        f.write(f"- Process creation findings: {len(process_df)}\n")
        f.write(f"- Parent-child findings: {len(parent_df)}\n")
        f.write(f"- Command-line findings: {len(cmd_df)}\n")
        f.write(f"- In-memory execution findings: {len(mem_df)}\n\n")

        if not score_df.empty:
            f.write("## Highest-Risk Processes\n")
            for _, row in score_df.head(10).iterrows():
                f.write(
                    f"- PID {row['PID']} | {row['Process']} | "
                    f"Score {row['RiskScore']} | {row['Indicators']}\n"
                )

        f.write("\n## Analyst Conclusion\n")
        f.write(
            "The Week 3 dataset contains T1059-related artefacts including PowerShell "
            "process creation, suspicious parent-child chains, suspicious command-line "
            "patterns, and RWX memory regions associated with PowerShell.\n"
        )


def create_chart(score_df: pd.DataFrame):
    if score_df.empty:
        return

    top_df = score_df.head(10).copy()
    labels = top_df["Process"].astype(str) + " (" + top_df["PID"].astype(str) + ")"

    plt.figure(figsize=(12, 6))
    plt.bar(labels, top_df["RiskScore"])
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Risk Score")
    plt.title("Top T1059 Suspicious Processes")
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "t1059_top_scores.png")
    plt.close()


def main():
    pslist_df = load_jsonl(EXPORT_JSONL / "windows.pslist.jsonl")
    pstree_df = load_jsonl(EXPORT_JSONL / "windows.pstree.jsonl")
    cmdline_df = load_jsonl(EXPORT_JSONL / "windows.cmdline.jsonl")
    malfind_df = load_jsonl(EXPORT_JSONL / "windows.malfind.jsonl")
    netscan_df = load_jsonl(EXPORT_JSONL / "windows.netscan.jsonl")  # loaded for completeness

    process_df = find_process_artifacts(pslist_df)
    parent_df = find_parent_child_artifacts(pstree_df)
    cmd_df = find_commandline_artifacts(cmdline_df)
    mem_df = find_memory_artifacts(malfind_df)

    score_df = score_artifacts(process_df, parent_df, cmd_df, mem_df)

    process_df.to_csv(TABLES_DIR / "process_findings.csv", index=False)
    parent_df.to_csv(TABLES_DIR / "parent_child_findings.csv", index=False)
    cmd_df.to_csv(TABLES_DIR / "command_findings.csv", index=False)
    mem_df.to_csv(TABLES_DIR / "memory_findings.csv", index=False)
    score_df.to_csv(TABLES_DIR / "scores.csv", index=False)

    create_summary(process_df, parent_df, cmd_df, mem_df, score_df)
    create_chart(score_df)

    print("[+] Week 3 T1059 analysis complete")
    print(f"[+] Output directory: {OUT_DIR}")


if __name__ == "__main__":
    main()
