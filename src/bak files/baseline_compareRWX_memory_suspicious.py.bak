import pandas as pd
from pathlib import Path

BASELINE_DIR = Path("/MFF/cases/case01_baseline/exports/jsonl")
ATTACK_DIR = Path("/MFF/cases/case03_t1059_attack/exports/jsonl")

OUT_DIR = Path("/MFF/analysis/comparison/case01_vs_case03")
OUT_DIR.mkdir(parents=True, exist_ok=True)

def load_jsonl(path):
    if not path.exists():
        return pd.DataFrame()
    return pd.read_json(path, lines=True)

print("[+] Loading baseline data")

baseline_ps = load_jsonl(BASELINE_DIR / "windows.pslist.jsonl")
baseline_cmd = load_jsonl(BASELINE_DIR / "windows.cmdline.jsonl")

print("[+] Loading attack data")

attack_ps = load_jsonl(ATTACK_DIR / "windows.pslist.jsonl")
attack_cmd = load_jsonl(ATTACK_DIR / "windows.cmdline.jsonl")

print("[+] Normalizing columns")

baseline_ps.columns = [c.lower() for c in baseline_ps.columns]
attack_ps.columns = [c.lower() for c in attack_ps.columns]

baseline_cmd.columns = [c.lower() for c in baseline_cmd.columns]
attack_cmd.columns = [c.lower() for c in attack_cmd.columns]

print("[+] Detecting new processes")

baseline_processes = set(baseline_ps["imagefilename"].str.lower())
attack_processes = set(attack_ps["imagefilename"].str.lower())

new_processes = attack_processes - baseline_processes

new_proc_df = attack_ps[
    attack_ps["imagefilename"].str.lower().isin(new_processes)
]

new_proc_df.to_csv(
    OUT_DIR / "new_processes.csv",
    index=False
)

print("[+] Detecting new command lines")

baseline_cmds = set(baseline_cmd["args"].astype(str))
attack_cmds = set(attack_cmd["args"].astype(str))

new_cmds = attack_cmds - baseline_cmds

new_cmd_df = attack_cmd[
    attack_cmd["args"].astype(str).isin(new_cmds)
]

new_cmd_df.to_csv(
    OUT_DIR / "new_commands.csv",
    index=False
)

print("[+] Baseline comparison completed")

print("New processes:", len(new_proc_df))
print("New commands:", len(new_cmd_df))
