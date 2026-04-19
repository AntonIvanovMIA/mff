#!/usr/bin/env python3
"""
MFF v2 — Module: Automation
Three automation modes:
  1. watchdog  — auto-run analysis when new case folders appear
  2. batch     — compare multiple attack captures vs one baseline
  3. vol3      — auto-run Volatility 3 plugins and export CSVs
"""

import os
import sys
import time
import json
import subprocess
import threading
import hashlib
from datetime import datetime, UTC
from pathlib import Path


def now_utc():
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


# ============================================================
# Batch Mode
# ============================================================

def run_batch(baseline_path: str, attack_dirs: list, out_root: str,
              make_html: bool = True, make_pdf: bool = False,
              webhook_url: str = None, baseline_label: str = "baseline"):
    """
    Compare one baseline against multiple attack cases.
    Results written to out_root/<attack_case_name>/
    Returns list of result dicts for summary table.
    """
    # Import main engine here to avoid circular import
    import importlib.util, sys as _sys
    engine_path = os.path.join(os.path.dirname(__file__), "..", "comparison_engine_v2.py")

    results = []
    for atk_path in attack_dirs:
        atk_name = os.path.basename(atk_path.rstrip("/\\"))
        out_dir  = os.path.join(out_root, f"{baseline_label}_vs_{atk_name}")
        os.makedirs(out_dir, exist_ok=True)

        print(f"\n{'='*60}")
        print(f"[BATCH] {baseline_label} ← → {atk_name}")
        print(f"{'='*60}")

        cmd = [sys.executable, engine_path,
               "--baseline", baseline_path,
               "--attack",   atk_path,
               "--out",      out_dir]
        if make_html: cmd.append("--make-html")
        if make_pdf:  cmd.append("--make-pdf")
        if webhook_url: cmd += ["--webhook", webhook_url]

        start = time.time()
        result = subprocess.run(cmd, capture_output=False, text=True)
        elapsed = round(time.time() - start, 1)

        rc = result.returncode
        if rc == 0:
            status = "OK"
            label  = "OK"
        elif rc == 2:
            status = "SKIPPED (no exports found)"
            label  = "SKIP"
        else:
            status = f"FAILED (rc={rc})"
            label  = "FAIL"

        results.append({
            "baseline":    baseline_label,
            "attack_case": atk_name,
            "out_dir":     out_dir,
            "success":     rc == 0,
            "elapsed_sec": elapsed,
            "status":      status,
        })

        print(f"[{label}] {atk_name} — {elapsed}s")

    # Write batch summary
    summary_path = os.path.join(out_root, "batch_summary.json")
    with open(summary_path, "w") as f:
        json.dump({
            "generated_at": now_utc(),
            "baseline":     baseline_path,
            "results":      results
        }, f, indent=2)

    print(f"\n[+] Batch complete. {len(results)} cases processed.")
    print(f"[+] Summary: {summary_path}")
    print(f"\n[HINT] Generate comparison report:")
    print(f"  python modules/automation.py compare \\")
    print(f"    --batch-root {out_root} \\")
    print(f"    --out        {out_root}/comparison_report \\")
    print(f"    --make-html --make-pdf")
    return results


# ============================================================
# Volatility 3 Auto-Runner
# ============================================================

VOL3_PLUGINS = [
    ("windows.pslist",   "windows.pslist.PsList"),
    ("windows.cmdline",  "windows.cmdline.CmdLine"),
    ("windows.malfind",  "windows.malfind.Malfind"),
    ("windows.netscan",  "windows.netscan.NetScan"),
    ("windows.pstree",   "windows.pstree.PsTree"),
    ("windows.dlllist",  "windows.dlllist.DllList"),
    ("windows.handles",  "windows.handles.Handles"),
    ("windows.modules",  "windows.modules.Modules"),
    ("windows.registry.hivelist", "windows.registry.hivelist.HiveList"),
]


def find_vol3(vol3_path: str = None) -> str:
    """Locate vol.py or vol3 executable."""
    candidates = [vol3_path] if vol3_path else []
    candidates += [
        "vol3", "vol.py", "volatility3",
        "/usr/local/bin/vol3",
        "/opt/volatility3/vol.py",
        os.path.expanduser("~/volatility3/vol.py"),
    ]
    for c in candidates:
        if c and shutil_which(c):
            return c
    return None


def shutil_which(name):
    """Simple which() fallback."""
    import shutil
    return shutil.which(name)


def run_vol3_on_image(image_path: str, out_dir: str,
                      plugins: list = None, vol3_bin: str = None,
                      timeout: int = 300) -> dict:
    """
    Run Volatility 3 plugins on a memory image and export CSV files.
    Returns dict: { plugin_name: csv_path | error_message }
    """
    vol3 = find_vol3(vol3_bin)
    if not vol3:
        print("[!] Volatility 3 not found. Set --vol3-bin or add vol3 to PATH.")
        return {}

    exports_dir = os.path.join(out_dir, "exports", "csv")
    os.makedirs(exports_dir, exist_ok=True)

    plugin_list = plugins or VOL3_PLUGINS
    results     = {}

    for short_name, plugin_class in plugin_list:
        out_csv = os.path.join(exports_dir, f"{short_name}.csv")

        print(f"  [*] Running: {plugin_class} → {os.path.basename(out_csv)}")

        cmd = [vol3, "-f", image_path,
               "-r", "csv",
               plugin_class]

        try:
            with open(out_csv, "w") as csv_out:
                proc = subprocess.run(
                    cmd,
                    stdout=csv_out,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    text=True,
                )

            if proc.returncode == 0:
                size = os.path.getsize(out_csv)
                print(f"  [+] {short_name} → {size} bytes")
                results[short_name] = out_csv
            else:
                err = proc.stderr[:300] if proc.stderr else "unknown error"
                print(f"  [!] {short_name} failed: {err}")
                results[short_name] = f"ERROR: {err}"

        except subprocess.TimeoutExpired:
            print(f"  [!] {short_name} timed out after {timeout}s")
            results[short_name] = "ERROR: timeout"
        except FileNotFoundError:
            print(f"  [!] {vol3} not found")
            break
        except Exception as e:
            print(f"  [!] {short_name} exception: {e}")
            results[short_name] = f"ERROR: {e}"

    manifest = {
        "image":        image_path,
        "generated_at": now_utc(),
        "vol3_bin":     vol3,
        "plugins":      results,
    }
    manifest_path = os.path.join(out_dir, "vol3_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n  [+] Vol3 manifest: {manifest_path}")
    return results


# ============================================================
# Watchdog — Filesystem Monitor
# ============================================================

class CaseWatcher:
    """
    Watches a directory for new case folders.
    When a new folder appears that contains exports/csv/*.csv files,
    it auto-triggers analysis against a configured baseline.

    Usage (no watchdog library needed — uses polling):
      watcher = CaseWatcher(
          watch_dir   = "/MFF/cases",
          baseline    = "/MFF/cases/case01_baseline",
          out_root    = "/MFF/analysis",
          engine_path = "/MFF/src/comparison_engine_v2.py",
      )
      watcher.start()   # blocks (use thread for background)
    """

    def __init__(self, watch_dir: str, baseline: str, out_root: str,
                 engine_path: str, poll_interval: int = 15,
                 make_html: bool = True, make_pdf: bool = False,
                 webhook_url: str = None):

        self.watch_dir     = watch_dir
        self.baseline      = baseline
        self.out_root      = out_root
        self.engine_path   = engine_path
        self.poll_interval = poll_interval
        self.make_html     = make_html
        self.make_pdf      = make_pdf
        self.webhook_url   = webhook_url
        self._seen         = set()
        self._running      = False

    def _is_valid_case(self, path: str) -> bool:
        """Check if folder looks like a complete MFF case."""
        csv_dir = os.path.join(path, "exports", "csv")
        if not os.path.isdir(csv_dir):
            return False
        csvs = [f for f in os.listdir(csv_dir) if f.endswith(".csv")]
        return len(csvs) >= 1

    def _process_case(self, case_path: str):
        case_name = os.path.basename(case_path.rstrip("/\\"))
        out_dir   = os.path.join(self.out_root, f"auto_{case_name}")
        os.makedirs(out_dir, exist_ok=True)

        print(f"\n[WATCHDOG] New case detected: {case_name}")
        print(f"[WATCHDOG] Output: {out_dir}")

        cmd = [sys.executable, self.engine_path,
               "--baseline", self.baseline,
               "--attack",   case_path,
               "--out",      out_dir]
        if self.make_html: cmd.append("--make-html")
        if self.make_pdf:  cmd.append("--make-pdf")
        if self.webhook_url: cmd += ["--webhook", self.webhook_url]

        try:
            result = subprocess.run(cmd, timeout=600, text=True)
            if result.returncode == 0:
                print(f"[WATCHDOG] ✓ Analysis complete: {out_dir}")
            else:
                print(f"[WATCHDOG] ✗ Analysis failed (rc={result.returncode})")
        except subprocess.TimeoutExpired:
            print(f"[WATCHDOG] ✗ Analysis timed out for {case_name}")
        except Exception as e:
            print(f"[WATCHDOG] ✗ Error: {e}")

    def _scan(self):
        """One scan pass — find new valid case folders."""
        try:
            entries = os.listdir(self.watch_dir)
        except PermissionError:
            return

        for entry in entries:
            full_path = os.path.join(self.watch_dir, entry)
            if not os.path.isdir(full_path):
                continue
            if full_path == self.baseline:
                continue
            if full_path in self._seen:
                continue

            self._seen.add(full_path)

            if self._is_valid_case(full_path):
                t = threading.Thread(
                    target=self._process_case,
                    args=(full_path,),
                    daemon=True,
                )
                t.start()

    def start(self, background: bool = False):
        """
        Start watching.
        background=True: returns immediately, runs in daemon thread.
        background=False: blocks (useful for standalone watchdog script).
        """
        print(f"[WATCHDOG] Watching: {self.watch_dir}")
        print(f"[WATCHDOG] Baseline: {self.baseline}")
        print(f"[WATCHDOG] Poll interval: {self.poll_interval}s")
        print(f"[WATCHDOG] Press Ctrl+C to stop.\n")

        self._running = True

        # Initial seed — mark existing folders as seen (don't process them)
        try:
            for entry in os.listdir(self.watch_dir):
                full = os.path.join(self.watch_dir, entry)
                if os.path.isdir(full):
                    self._seen.add(full)
        except Exception:
            pass

        def _loop():
            while self._running:
                self._scan()
                time.sleep(self.poll_interval)

        if background:
            t = threading.Thread(target=_loop, daemon=True, name="mff-watchdog")
            t.start()
            return t
        else:
            try:
                _loop()
            except KeyboardInterrupt:
                print("\n[WATCHDOG] Stopped.")

    def stop(self):
        self._running = False




# ============================================================
# Analyse Mode  —  standalone single-case analysis
# ============================================================

# Plugins run in analyse mode (both CSV and JSONL formats)
ANALYSE_PLUGINS = [
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline",
    "windows.malfind",
    "windows.netscan",
    "windows.dlllist",
    "windows.threads",
]

# JSONL-only plugins (richer data, used alongside CSV)
ANALYSE_PLUGINS_JSONL = ANALYSE_PLUGINS  # same set, both formats tried


def _detect_exports(case_path: str) -> dict:
    """
    Detect what data is already available in a case folder.
    Returns dict with keys: csv_dir, jsonl_dir, csv_files, jsonl_files, raw_files
    """
    csv_dir   = os.path.join(case_path, "exports", "csv")
    jsonl_dir = os.path.join(case_path, "exports", "jsonl")

    csv_files   = []
    jsonl_files = []
    raw_files   = []

    if os.path.isdir(csv_dir):
        csv_files = [f for f in os.listdir(csv_dir) if f.endswith(".csv")]

    if os.path.isdir(jsonl_dir):
        jsonl_files = [f for f in os.listdir(jsonl_dir) if f.endswith(".jsonl")]

    # Look for raw memory images in case root
    for ext in (".raw", ".vmem", ".mem", ".dmp", ".lime"):
        raw_files += [
            f for f in os.listdir(case_path)
            if f.endswith(ext) and os.path.isfile(os.path.join(case_path, f))
        ]

    return {
        "csv_dir":    csv_dir,
        "jsonl_dir":  jsonl_dir,
        "csv_files":  csv_files,
        "jsonl_files": jsonl_files,
        "raw_files":  raw_files,
        "has_csv":    len(csv_files) >= 1,
        "has_jsonl":  len(jsonl_files) >= 1,
        "has_raw":    len(raw_files) >= 1,
    }


def run_vol3_both_formats(image_path: str, case_path: str,
                           vol3_bin: str = None, timeout: int = 600) -> bool:
    """
    Run Volatility 3 on a raw image and export BOTH CSV and JSONL formats.
    Exports go into:
        case_path/exports/csv/windows.<plugin>.csv
        case_path/exports/jsonl/windows.<plugin>.jsonl
    Returns True if at least one plugin succeeded.
    """
    vol3 = find_vol3(vol3_bin)
    if not vol3:
        print("  [!] Volatility 3 not found.")
        print("  [!] Set --vol3-bin or ensure vol.py is in ~/volatility3/")
        return False

    csv_dir   = os.path.join(case_path, "exports", "csv")
    jsonl_dir = os.path.join(case_path, "exports", "jsonl")
    os.makedirs(csv_dir,   exist_ok=True)
    os.makedirs(jsonl_dir, exist_ok=True)

    # Map short name → Volatility 3 plugin class
    PLUGIN_MAP = {
        "windows.pslist":   "windows.pslist.PsList",
        "windows.pstree":   "windows.pstree.PsTree",
        "windows.cmdline":  "windows.cmdline.CmdLine",
        "windows.malfind":  "windows.malware.malfind.Malfind",
        "windows.netscan":  "windows.netscan.NetScan",
        "windows.dlllist":  "windows.dlllist.DllList",
        "windows.threads":  "windows.threads.Threads",
    }

    succeeded = 0

    for short, plugin_class in PLUGIN_MAP.items():
        csv_out   = os.path.join(csv_dir,   f"{short}.csv")
        jsonl_out = os.path.join(jsonl_dir, f"{short}.jsonl")

        print(f"  [*] {short}")

        # Run CSV export
        try:
            with open(csv_out, "w") as fout:
                r = subprocess.run(
                    [vol3, "-q", "-f", image_path, "-r", "csv", plugin_class],
                    stdout=fout, stderr=subprocess.PIPE,
                    timeout=timeout, text=True)
            if r.returncode == 0 and os.path.getsize(csv_out) > 10:
                print(f"      CSV  → {os.path.getsize(csv_out):>8,} bytes  OK")
                succeeded += 1
            else:
                err = (r.stderr or "")[:120].strip()
                print(f"      CSV  → FAILED  ({err})")
        except subprocess.TimeoutExpired:
            print(f"      CSV  → TIMEOUT ({timeout}s)")
        except Exception as e:
            print(f"      CSV  → ERROR: {e}")

        # Run JSONL export
        try:
            with open(jsonl_out, "w") as fout:
                r = subprocess.run(
                    [vol3, "-q", "-f", image_path, "-r", "jsonl", plugin_class],
                    stdout=fout, stderr=subprocess.PIPE,
                    timeout=timeout, text=True)
            if r.returncode == 0 and os.path.getsize(jsonl_out) > 10:
                print(f"      JSONL→ {os.path.getsize(jsonl_out):>8,} bytes  OK")
            else:
                err = (r.stderr or "")[:120].strip()
                print(f"      JSONL→ FAILED  ({err})")
        except subprocess.TimeoutExpired:
            print(f"      JSONL→ TIMEOUT ({timeout}s)")
        except Exception as e:
            print(f"      JSONL→ ERROR: {e}")

    return succeeded > 0


def run_case_analyse(
    case_path:   str,
    out_dir:     str,
    image_path:  str  = None,
    vol3_bin:    str  = None,
    vol3_timeout:int  = 600,
    make_html:   bool = True,
    make_pdf:    bool = False,
    no_csv:      bool = False,
    webhook_url: str  = None,
) -> bool:
    """
    Standalone single-case analysis mode.

    What it does:
      1. Detects available data (CSV, JSONL, raw .raw/.vmem)
      2. If --image given (or raw found + no exports): runs Volatility 3
         and exports BOTH CSV and JSONL automatically
      3. Loads all Volatility 3 plugin exports using the engine's
         CSV-first / JSONL-fallback loader (same as comparison mode)
      4. Runs full analysis pipeline:
           - Risk scoring (malfind RWX + cmdline patterns + DLL hijacking)
           - MITRE ATT&CK auto-tagging (42 rules)
           - DLL analysis (T1574.001 / T1562.001)
           - IOC extraction (IPs, domains, hashes, paths)
           - Network suspicious port flagging
           - Process tree rendering
           - ATT&CK heatmap
      5. Generates HTML report, PDF report, all CSV exports,
         JSON threat summary, and terminal colour summary

    Does NOT require a baseline — analyses the case on its own.
    Uses comparison_engine_v2.py's load_case() and all analysis modules.

    Parameters
    ----------
    case_path   : Path to case folder  (e.g. /MFF/cases/case04_t1574_attack)
    out_dir     : Where to write all output files
    image_path  : Optional path to .raw/.vmem file — runs vol3 if given
    vol3_bin    : Optional path to vol.py / vol3 executable
    vol3_timeout: Seconds per Volatility plugin (default 600)
    make_html   : Generate interactive HTML report
    make_pdf    : Generate PDF report
    no_csv      : Skip CSV output files
    webhook_url : Slack / generic webhook URL for alerts
    """

    case_name = os.path.basename(case_path.rstrip("/\\"))
    os.makedirs(out_dir, exist_ok=True)

    print(f"\n{'='*65}")
    print(f"  MFF v2 — CASE ANALYSIS (standalone)")
    print(f"  Case   : {case_name}")
    print(f"  Path   : {case_path}")
    print(f"  Output : {out_dir}")
    print(f"  Time   : {now_utc()}")
    print(f"{'='*65}\n")

    # ── Step 1: Detect what data exists ───────────────────────
    exports = _detect_exports(case_path)
    print(f"[1/6] Checking available data in {case_path}")
    print(f"      CSV   files : {len(exports['csv_files'])}  "
          f"({', '.join(exports['csv_files'][:3])}{'...' if len(exports['csv_files'])>3 else ''})")
    print(f"      JSONL files : {len(exports['jsonl_files'])}")
    print(f"      Raw images  : {exports['raw_files'] or 'none'}")

    # ── Step 2: Run Volatility 3 if needed / requested ────────
    if image_path:
        # User explicitly provided a raw image path
        abs_image = os.path.abspath(image_path)
        if not os.path.exists(abs_image):
            print(f"\n[!] Image not found: {abs_image}")
            return False
        print(f"\n[2/6] Running Volatility 3 on: {abs_image}")
        ok = run_vol3_both_formats(abs_image, case_path, vol3_bin, vol3_timeout)
        if not ok:
            print("[!] Volatility 3 produced no output — aborting.")
            return False
    elif exports["has_raw"] and not exports["has_csv"] and not exports["has_jsonl"]:
        # Raw image found in case folder, no exports yet — auto-run vol3
        raw_path = os.path.join(case_path, exports["raw_files"][0])
        print(f"\n[2/6] Raw image found, no exports yet.")
        print(f"      Auto-running Volatility 3 on: {raw_path}")
        ok = run_vol3_both_formats(raw_path, case_path, vol3_bin, vol3_timeout)
        if not ok:
            print("[!] Volatility 3 produced no output — aborting.")
            return False
    else:
        print(f"\n[2/6] Using existing exports (CSV/JSONL) — skipping Volatility 3")
        if not exports["has_csv"] and not exports["has_jsonl"]:
            print("  [!] No CSV or JSONL exports found and no raw image.")
            print(f"  [!] Expected: {exports['csv_dir']}/windows.*.csv")
            print(f"  [!] Or     : {exports['jsonl_dir']}/windows.*.jsonl")
            print("  [!] Or provide --image /path/to/dump.raw")
            return False

    # ── Step 3: Load all plugin data ──────────────────────────
    print(f"\n[3/6] Loading Volatility 3 exports...")

    # Use the engine's load_case() which does CSV-first / JSONL-fallback
    engine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    sys.path.insert(0, engine_dir)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    try:
        import comparison_engine_v2 as eng
    except ImportError as e:
        print(f"  [!] Cannot import comparison_engine_v2: {e}")
        print(f"  [!] Make sure comparison_engine_v2.py is in {engine_dir}")
        return False

    try:
        import mitre_tagger
        import network_ioc
        import dll_analysis
        import export_alert
        import process_tree
        import report_generator
    except ImportError as e:
        print(f"  [!] Cannot import module: {e}")
        return False

    data = eng.load_case(case_path)

    loaded = {k: len(v) for k, v in data.items() if not v.empty}
    print(f"      Loaded: { {k: f'{v} rows' for k,v in loaded.items()} }")

    if not loaded:
        print("  [!] All plugins returned empty — nothing to analyse.")
        return False

    # ── Step 4: Run full analysis pipeline ────────────────────
    print(f"\n[4/6] Running analysis pipeline...")

    # Cmdline suspicious patterns
    cmd_df      = eng.cmdline_findings(data["cmdline"])
    print(f"      Cmdline findings  : {len(cmd_df)}")

    # Malfind RWX filtering
    malfind_df  = eng.malfind_analysis(data["malfind"])
    print(f"      Malfind RWX       : {len(malfind_df)} suspicious regions")

    # Thread anomalies
    thread_df   = eng.threads_analysis(data["threads"])
    print(f"      Thread anomalies  : {len(thread_df)}")

    # Pstree anomalies
    pstree_df   = eng.pstree_anomaly(data["pstree"])
    print(f"      Process tree anom : {len(pstree_df)}")

    # Process exe path anomalies
    exe_path_df = eng.process_exe_path_anomaly(data["pslist"])
    print(f"      Exe path anomalies: {len(exe_path_df)}")

    # DLL analysis (T1574 / T1562)
    dllhijack_df = dll_analysis.full_dll_analysis(data["dlllist"], malfind_df)
    print(f"      DLL findings      : {len(dllhijack_df)}")
    if not dllhijack_df.empty:
        techs = sorted(dllhijack_df["Technique"].unique().tolist()) if "Technique" in dllhijack_df.columns else []
        print(f"      DLL techniques    : {techs}")

    # Risk scoring — score ALL processes in the case (no baseline diff needed)
    scores_df = eng.scoring_engine(
        process_df = data["pslist"],   # all processes
        cmd_df     = cmd_df,
        mal_df     = malfind_df,
        dll_df     = dllhijack_df,
        proc_df    = data["pslist"],
    )
    n_crit = int((scores_df["RiskLevel"] == "CRITICAL").sum()) if not scores_df.empty else 0
    n_high = int((scores_df["RiskLevel"] == "HIGH").sum())     if not scores_df.empty else 0
    print(f"      Scored processes  : {len(scores_df)}  "
          f"(CRITICAL={n_crit}  HIGH={n_high})")

    # MITRE ATT&CK tagging
    tagged_df  = mitre_tagger.tag_all(
        data["pslist"], data["cmdline"],
        malfind_df,     data["netscan"])

    # Merge DLL ATT&CK tags into main tags
    if not dllhijack_df.empty and "Technique" in dllhijack_df.columns:
        dll_tags = dll_analysis.dll_attack_tags(dllhijack_df)
        if not dll_tags.empty:
            tagged_df = eng.pd.concat([tagged_df, dll_tags],
                                      ignore_index=True).drop_duplicates(
                subset=["PID", "Technique", "MatchedKeyword"],
                keep="first") if not tagged_df.empty else dll_tags

    tactic_sum = mitre_tagger.summary_by_tactic(tagged_df)
    techniques = sorted(tagged_df["Technique"].unique().tolist()) if not tagged_df.empty else []
    print(f"      ATT&CK techniques : {len(techniques)}  {techniques}")

    # Network suspicious ports + IOC extraction
    import pandas as pd
    net_flagged_df = pd.DataFrame()
    net_new_df     = pd.DataFrame()
    if not data["netscan"].empty:
        # In single-case mode, flag suspicious ports directly (no baseline to diff)
        flagged_rows = []
        from network_ioc import SUSPICIOUS_PORTS, parse_port
        for _, row in data["netscan"].iterrows():
            for port_col in ("ForeignPort", "LocalPort"):
                if port_col not in row.index: continue
                port = parse_port(str(row[port_col]))
                if port in SUSPICIOUS_PORTS:
                    r = row.to_dict()
                    r["SuspiciousPort"] = port
                    r["PortMeaning"]    = SUSPICIOUS_PORTS[port]
                    flagged_rows.append(r)
                    break
        net_flagged_df = pd.DataFrame(flagged_rows) if flagged_rows else pd.DataFrame()
        print(f"      Flagged net conns : {len(net_flagged_df)}")

    ioc_df = network_ioc.extract_iocs(
        data["pslist"], data["cmdline"],
        malfind_df,     data["netscan"])
    print(f"      IOCs extracted    : {len(ioc_df)}")

    # Charts
    print(f"\n[5/6] Generating charts and reports...")
    # Standalone: show total processes + CRITICAL/HIGH scored as "notable"
    _notable_procs = eng.pd.DataFrame()
    if not scores_df.empty and "RiskLevel" in scores_df.columns:
        _crit_high = scores_df[scores_df["RiskLevel"].isin(["CRITICAL","HIGH"])]
        if not _crit_high.empty and not data["pslist"].empty:
            _notable_procs = data["pslist"][
                data["pslist"]["PID"].isin(_crit_high["PID"])].copy()
    eng.chart_process_counts(
        data["pslist"], data["pslist"],
        _notable_procs, eng.pd.DataFrame(), out_dir)
    eng.chart_risk_scores(scores_df, out_dir)
    timeline_df = eng.timeline_correlation(data["pslist"])
    # Standalone timeline: show all processes by CreateTime (no baseline diff)
    # Mark scored CRITICAL/HIGH processes as "notable" in the timeline
    _timeline_notable = eng.pd.DataFrame()
    if not scores_df.empty and "RiskLevel" in scores_df.columns:
        _high_pids = set(
            scores_df[scores_df["RiskLevel"].isin(["CRITICAL","HIGH"])]["PID"].tolist()
        )
        if not data["pslist"].empty and "PID" in data["pslist"].columns:
            _timeline_notable = data["pslist"][
                data["pslist"]["PID"].isin(_high_pids)
            ].copy()
            if not _timeline_notable.empty:
                _timeline_notable["DiffStatus"] = "NEW (Attack Only)"
    eng.chart_timeline(_timeline_notable, eng.pd.DataFrame(), out_dir)
    eng.chart_cmdline_patterns(cmd_df, out_dir)
    eng.chart_malfind(malfind_df, out_dir)
    eng.chart_dashboard(data["pslist"], data["pslist"],
                        eng.pd.DataFrame(), eng.pd.DataFrame(),
                        scores_df, cmd_df, malfind_df, out_dir)
    process_tree.render_process_tree(data["pslist"], eng.pd.DataFrame(), out_dir)
    process_tree.render_attack_heatmap(tagged_df, out_dir)

    # Build JSON summary
    case_id = case_name
    json_summary = export_alert.build_json_summary(
        case_id        = case_id,
        baseline_path  = "N/A (standalone analysis)",
        attack_path    = case_path,
        new_df         = eng.pd.DataFrame(),
        gone_df        = eng.pd.DataFrame(),
        scores_df      = scores_df,
        tagged_df      = tagged_df,
        ioc_df         = ioc_df,
        net_new_df     = net_new_df,
        net_flagged_df = net_flagged_df,
    )

    # CSV exports
    if not no_csv:
        cmd_df.to_csv(os.path.join(out_dir, "cmdline_findings.csv"),  index=False)
        malfind_df.to_csv(os.path.join(out_dir, "malfind.csv"),       index=False)
        scores_df.to_csv(os.path.join(out_dir, "scores.csv"),         index=False)
        tagged_df.to_csv(os.path.join(out_dir, "attack_tags.csv"),    index=False)
        tactic_sum.to_csv(os.path.join(out_dir, "tactic_summary.csv"),index=False)
        ioc_df.to_csv(os.path.join(out_dir, "iocs.csv"),              index=False)
        timeline_df.to_csv(os.path.join(out_dir, "timeline.csv"),     index=False)
        if not net_flagged_df.empty:
            net_flagged_df.to_csv(os.path.join(out_dir, "net_flagged.csv"), index=False)
        if not dllhijack_df.empty:
            dllhijack_df.to_csv(os.path.join(out_dir, "dll_hijack.csv"), index=False)
        if not thread_df.empty:
            thread_df.to_csv(os.path.join(out_dir, "thread_findings.csv"), index=False)
        if not pstree_df.empty:
            pstree_df.to_csv(os.path.join(out_dir, "pstree_anomaly.csv"), index=False)
        export_alert.write_json_summary(json_summary, out_dir)

    # HTML report
    if make_html:
        report_generator.generate_html_report(
            out_dir        = out_dir,
            case_id        = case_id,
            new_df         = eng.pd.DataFrame(),
            gone_df        = eng.pd.DataFrame(),
            scores_df      = scores_df,
            cmd_df         = cmd_df,
            malfind_df     = malfind_df,
            tagged_df      = tagged_df,
            ioc_df         = ioc_df,
            net_new_df     = net_new_df,
            net_flagged_df = net_flagged_df,
            summary        = json_summary,
            dll_findings_df= dllhijack_df,
        )

    # PDF report
    if make_pdf:
        report_generator.generate_pdf_report(
            out_dir        = out_dir,
            case_id        = case_id,
            summary        = json_summary,
            scores_df      = scores_df,
            new_df         = eng.pd.DataFrame(),
            gone_df        = eng.pd.DataFrame(),
            cmd_df         = cmd_df,
            malfind_df     = malfind_df,
            tagged_df      = tagged_df,
            ioc_df         = ioc_df,
            net_flagged_df = net_flagged_df,
            dll_findings_df= dllhijack_df,
        )

    # Webhook alert
    if webhook_url:
        export_alert.send_webhook(webhook_url, json_summary)

    # ── Step 6: Terminal colour summary ───────────────────────
    sev = json_summary["severity"]["overall"]
    print(f"\n[6/6] Analysis complete")
    print(f"{'='*65}")
    print(f"  Case     : {case_name}")
    print(f"  Severity : {sev}")
    print(f"  Processes: {len(data['pslist'])}  scored={len(scores_df)}"
          f"  CRITICAL={n_crit}  HIGH={n_high}")
    print(f"  RWX      : {len(malfind_df)} suspicious memory regions")
    print(f"  ATT&CK   : {len(techniques)} techniques  {techniques}")
    print(f"  IOCs     : {len(ioc_df)}")
    print(f"  DLL      : {len(dllhijack_df)} findings")
    print(f"  Output   : {out_dir}")
    print(f"{'='*65}\n")
    return True

# ============================================================
# CLI  (standalone usage)
# ============================================================

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="MFF v2 Automation")
    sub = p.add_subparsers(dest="mode", required=True)

    # watchdog
    wp = sub.add_parser("watchdog", help="Monitor directory for new cases")
    wp.add_argument("--watch-dir",   required=True)
    wp.add_argument("--baseline",    required=True)
    wp.add_argument("--out-root",    required=True)
    wp.add_argument("--engine",      required=True, help="Path to comparison_engine_v2.py")
    wp.add_argument("--interval",    type=int, default=15)
    wp.add_argument("--make-html",   action="store_true")
    wp.add_argument("--make-pdf",    action="store_true")
    wp.add_argument("--webhook",     default=None)

    # batch
    bp = sub.add_parser("batch", help="Compare baseline vs multiple attack cases")
    bp.add_argument("--baseline",    required=True)
    bp.add_argument("--attacks",     nargs="+", required=True)
    bp.add_argument("--out-root",    required=True)
    bp.add_argument("--make-html",   action="store_true")
    bp.add_argument("--make-pdf",    action="store_true")
    bp.add_argument("--webhook",     default=None)

    # compare
    cp = sub.add_parser("compare", help="Cross-case comparison report from batch results")
    cp.add_argument("--batch-root",  required=True,
                    help="Root dir produced by batch mode (contains one subdir per case)")
    cp.add_argument("--out",         required=True,
                    help="Output dir for comparison report")
    cp.add_argument("--make-html",   action="store_true")
    cp.add_argument("--make-pdf",    action="store_true")

    # vol3
    vp = sub.add_parser("vol3", help="Auto-run Volatility 3 on a memory image")
    vp.add_argument("--image",       required=True)
    vp.add_argument("--out",         required=True)
    vp.add_argument("--vol3-bin",    default=None)
    vp.add_argument("--timeout",     type=int, default=300)

    # analyse — NEW: standalone single-case analysis
    ap = sub.add_parser("analyse",
        help="Standalone analysis of a single case (no baseline needed). "
             "Reads existing CSV/JSONL exports, or runs Volatility 3 on a "
             "raw image if --image is given or a .raw file is found in case folder.")
    ap.add_argument("--case",      required=True,
                    help="Path to case folder  e.g. /MFF/cases/case04_t1574_attack")
    ap.add_argument("--out",       required=True,
                    help="Output directory for all results")
    ap.add_argument("--image",     default=None,
                    help="Path to raw memory image (.raw/.vmem). "
                         "If given, Volatility 3 runs automatically and exports "
                         "both CSV and JSONL before analysis. "
                         "If not given, existing exports in --case are used.")
    ap.add_argument("--vol3-bin",  default=None,
                    help="Path to vol.py / vol3 executable "
                         "(default: auto-detect from PATH and ~/volatility3/)")
    ap.add_argument("--vol3-timeout", type=int, default=600,
                    help="Seconds per Volatility plugin (default: 600)")
    ap.add_argument("--make-html", action="store_true",
                    help="Generate interactive HTML forensics report")
    ap.add_argument("--make-pdf",  action="store_true",
                    help="Generate PDF forensics report")
    ap.add_argument("--no-csv",    action="store_true",
                    help="Skip CSV output files")
    ap.add_argument("--webhook",   default=None,
                    help="Slack or generic webhook URL for critical alerts")

    args = p.parse_args()

    if args.mode == "watchdog":
        engine_path = os.path.abspath(args.engine)
        watcher = CaseWatcher(
            watch_dir    = args.watch_dir,
            baseline     = args.baseline,
            out_root     = args.out_root,
            engine_path  = engine_path,
            poll_interval= args.interval,
            make_html    = args.make_html,
            make_pdf     = args.make_pdf,
            webhook_url  = args.webhook,
        )
        watcher.start(background=False)

    elif args.mode == "batch":
        engine = os.path.join(os.path.dirname(__file__), "..", "comparison_engine_v2.py")
        run_batch(
            baseline_path = args.baseline,
            attack_dirs   = args.attacks,
            out_root      = args.out_root,
            make_html     = args.make_html,
            make_pdf      = args.make_pdf,
            webhook_url   = args.webhook,
        )

    elif args.mode == "compare":
        # Discover all subdirectories in batch-root that look like case outputs
        import glob as _glob
        batch_root  = os.path.abspath(args.batch_root)
        out_dir     = os.path.abspath(args.out)
        # Skip the comparison_report output dir itself — it has CSVs
        # (comparison_matrix.csv) but is not a case directory
        SKIP_DIR_NAMES = {"comparison_report", "comparison", "cross_case", "reports"}
        subdirs     = sorted([
            d for d in os.listdir(batch_root)
            if os.path.isdir(os.path.join(batch_root, d))
            and d.lower() not in SKIP_DIR_NAMES
        ])
        if not subdirs:
            print(f"[!] No subdirectories found in {batch_root}")
            sys.exit(1)

        # Build (label, path) pairs
        cases_input = []
        for sd in subdirs:
            full = os.path.join(batch_root, sd)
            # Only include dirs that have at least one output CSV
            csvs = [f for f in os.listdir(full) if f.endswith(".csv")]
            if csvs:
                label = sd.replace("_vs_", " vs ").replace("_", " ").title()
                cases_input.append((label, full))
                print(f"  [+] Found case: {label}")
            else:
                print(f"  [i] Skipping (no CSVs): {sd}")

        if not cases_input:
            print("[!] No valid case output directories found.")
            sys.exit(1)

        # Import and run
        sys.path.insert(0, os.path.dirname(__file__))
        import case_comparison
        case_comparison.run(
            cases_input = cases_input,
            out_dir     = out_dir,
            make_html   = args.make_html,
            make_pdf    = args.make_pdf,
        )

    elif args.mode == "vol3":
        run_vol3_on_image(
            image_path = args.image,
            out_dir    = args.out,
            vol3_bin   = args.vol3_bin,
            timeout    = args.timeout,
        )

    elif args.mode == "analyse":
        ok = run_case_analyse(
            case_path    = os.path.abspath(args.case),
            out_dir      = os.path.abspath(args.out),
            image_path   = args.image,
            vol3_bin     = args.vol3_bin,
            vol3_timeout = args.vol3_timeout,
            make_html    = args.make_html,
            make_pdf     = args.make_pdf,
            no_csv       = args.no_csv,
            webhook_url  = args.webhook,
        )
        sys.exit(0 if ok else 1)
