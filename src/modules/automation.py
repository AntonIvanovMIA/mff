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

    # vol3
    vp = sub.add_parser("vol3", help="Auto-run Volatility 3 on a memory image")
    vp.add_argument("--image",       required=True)
    vp.add_argument("--out",         required=True)
    vp.add_argument("--vol3-bin",    default=None)
    vp.add_argument("--timeout",     type=int, default=300)

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

    elif args.mode == "vol3":
        run_vol3_on_image(
            image_path = args.image,
            out_dir    = args.out,
            vol3_bin   = args.vol3_bin,
            timeout    = args.timeout,
        )
