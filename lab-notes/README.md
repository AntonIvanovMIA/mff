# MFF v2 — Memory Forensics Framework
### Python Post-Volatility Memory Forensics Framework for Analysis and Visualization

---

## Project Overview

This framework sits **after Volatility 3** in the forensics pipeline. Volatility extracts
raw data from memory images. This framework takes those CSV exports and turns them into
structured analysis, risk scoring, MITRE ATT&CK mapping, IOC extraction, visual reports,
and automated alerting — all from the command line.

```
Memory Image (.vmem)
      │
      ▼
 Volatility 3  ──►  CSV exports  (pslist, cmdline, malfind, netscan)
                          │
                          ▼
              MFF v2 Comparison Engine
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
   HTML Report       Risk Scores      MITRE ATT&CK
   PDF Report        IOC Watchlist    Process Tree
   JSON/SIEM         Network Diff     CLI Dashboard
```

---

## File Structure — All 9 Files

```
MFF/src/
│
├── comparison_engine_v2.py      ← MASTER SCRIPT — orchestrates all modules
├── mff_dashboard.py             ← CLI terminal dashboard (live or one-shot)
│
└── modules/
    ├── __init__.py              ← package marker (do not edit)
    ├── mitre_tagger.py          ← MITRE ATT&CK auto-tagger (25+ technique rules)
    ├── network_ioc.py           ← Network diff + IOC extractor (IPs, hashes, paths)
    ├── process_tree.py          ← Parent-child process tree + ATT&CK heatmap charts
    ├── export_alert.py          ← JSON SIEM export + Slack/webhook alerting
    ├── report_generator.py      ← Interactive HTML report + PDF report
    └── automation.py            ← Watchdog / Batch mode / Volatility 3 runner
```

> All modules are imported and orchestrated by `comparison_engine_v2.py`.
> You never need to run the modules directly except for the automation tasks in File 8.

---

## Expected Case Folder Structure

```
/MFF/
├── src/
│   ├── comparison_engine_v2.py
│   ├── mff_dashboard.py
│   └── modules/
│       ├── __init__.py
│       ├── mitre_tagger.py
│       ├── network_ioc.py
│       ├── process_tree.py
│       ├── export_alert.py
│       ├── report_generator.py
│       └── automation.py
│
├── cases/
│   ├── case01_baseline/
│   │   └── exports/csv/
│   │       ├── windows.pslist.csv
│   │       ├── windows.cmdline.csv
│   │       ├── windows.malfind.csv
│   │       └── windows.netscan.csv
│   │
│   └── case03_t1059_attack/
│       └── exports/csv/
│           ├── windows.pslist.csv
│           ├── windows.cmdline.csv
│           ├── windows.malfind.csv
│           └── windows.netscan.csv
│
├── images/
│   └── case03.vmem                ← raw memory image (for vol3 runner)
│
└── analysis/
    └── comparison/
        └── case01_vs_case03/      ← all output files written here
```

---

## FILE 1 — comparison_engine_v2.py  (MASTER)

This is the only script you need for a full end-to-end analysis.
It loads both cases, runs every module, generates all 8 charts, and writes all outputs.

### Minimum command
```bash
python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case03_t1059_attack \
  --out      /MFF/analysis/comparison/case01_vs_case03 \
  --make-html
```

### With PDF report
```bash
python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case03_t1059_attack \
  --out      /MFF/analysis/comparison/case01_vs_case03 \
  --make-html \
  --make-pdf
```

### With Slack alert
```bash
python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case03_t1059_attack \
  --out      /MFF/analysis/comparison/case01_vs_case03 \
  --make-html \
  --webhook  https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### With generic webhook (Teams, PagerDuty, custom SOAR)
```bash
python /MFF/src/comparison_engine_v2.py \
  --baseline     /MFF/cases/case01_baseline \
  --attack       /MFF/cases/case03_t1059_attack \
  --out          /MFF/analysis/comparison/case01_vs_case03 \
  --make-html \
  --webhook      https://your-soar-endpoint.example.com/alert \
  --webhook-mode generic
```

### Full command — every flag enabled
```bash
python /MFF/src/comparison_engine_v2.py \
  --baseline     /MFF/cases/case01_baseline \
  --attack       /MFF/cases/case03_t1059_attack \
  --out          /MFF/analysis/comparison/case01_vs_case03 \
  --make-html \
  --make-pdf \
  --webhook      https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  --webhook-mode slack \
  --case-id      CASE-003
```

### Charts only — skip CSV output
```bash
python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case03_t1059_attack \
  --out      /MFF/analysis/comparison/case01_vs_case03 \
  --make-html \
  --no-csv
```

### All flags reference
| Flag | Required | Description |
|---|---|---|
| `--baseline` | ✅ | Path to baseline case folder |
| `--attack` | ✅ | Path to attack case folder |
| `--out` | ✅ | Output directory (auto-created if missing) |
| `--make-html` | optional | Generate interactive HTML report |
| `--make-pdf` | optional | Generate PDF report (requires reportlab) |
| `--webhook` | optional | Slack or generic webhook URL |
| `--webhook-mode` | optional | `slack` (default) or `generic` |
| `--case-id` | optional | Custom case identifier label |
| `--no-csv` | optional | Skip CSV output, produce charts/reports only |

---

## FILE 2 — mff_dashboard.py  (CLI Terminal Dashboard)

Reads the output directory of a completed analysis run and renders a coloured terminal
dashboard showing severity, stats, top risk scores, ATT&CK hits, IOCs, and network flags.
Uses ANSI colour only — no extra libraries required.

### One-shot view
```bash
python /MFF/src/mff_dashboard.py \
  --out /MFF/analysis/comparison/case01_vs_case03
```

### Live refresh — auto-updates every 10 seconds
```bash
python /MFF/src/mff_dashboard.py \
  --out      /MFF/analysis/comparison/case01_vs_case03 \
  --watch
```

### Live refresh with custom interval
```bash
python /MFF/src/mff_dashboard.py \
  --out      /MFF/analysis/comparison/case01_vs_case03 \
  --watch \
  --interval 5
```

### All flags reference
| Flag | Required | Description |
|---|---|---|
| `--out` | ✅ | Analysis output directory to read from |
| `--watch` | optional | Enable live auto-refresh loop |
| `--interval` | optional | Refresh interval in seconds (default: 10) |

> Must be run after `comparison_engine_v2.py` has completed.
> Press `Ctrl+C` to exit watch mode.

---

## FILE 3 — modules/mitre_tagger.py  (MITRE ATT&CK Auto-Tagger)

**Not run directly.** Imported and called by `comparison_engine_v2.py`.

Scans pslist, cmdline, malfind, and netscan data against 25+ built-in ATT&CK rules
covering: Execution, Defense Evasion, Credential Access, Discovery, Lateral Movement,
Command and Control, and Exfiltration. Every hit is tagged with Tactic, Technique ID,
TechniqueName, and a direct link to attack.mitre.org.

Output files it produces (via master engine):
- `attack_tags.csv` — every tagged finding
- `tactic_summary.csv` — hit counts by tactic and technique
- `chart_attack_heatmap.png` — visual heatmap

To use this module in your own script:
```python
import sys
sys.path.insert(0, "/MFF/src")
from modules.mitre_tagger import tag_all, summary_by_tactic

tagged_df  = tag_all(pslist_df, cmdline_df, malfind_df, netscan_df)
tactic_sum = summary_by_tactic(tagged_df)
```

---

## FILE 4 — modules/network_ioc.py  (Network Diff + IOC Extractor)

**Not run directly.** Imported and called by `comparison_engine_v2.py`.

Does two jobs:

**Network diff** — compares baseline vs attack netscan. Identifies new connections,
gone connections, and flags any new connection touching a known-bad port (Metasploit 4444,
Tor 9050, RDP 3389, SMB 445, Meterpreter, IRC C2, etc.)

**IOC extraction** — regex-scans all data columns for IPv4 addresses (private ranges
excluded), domains, URLs, MD5/SHA1/SHA256 hashes, and Windows/Linux file paths.
Results are deduplicated and counted by source.

Output files it produces (via master engine):
- `net_new.csv` — new connections in attack not present in baseline
- `net_flagged.csv` — connections to suspicious/known-bad ports
- `iocs.csv` — all extracted IOCs with type, value, source, and hit count

To use this module in your own script:
```python
from modules.network_ioc import network_diff, extract_iocs

new_conns, gone_conns, flagged = network_diff(base_netscan_df, attack_netscan_df)
ioc_df = extract_iocs(pslist_df, cmdline_df, malfind_df, netscan_df)
```

---

## FILE 5 — modules/process_tree.py  (Process Tree + ATT&CK Heatmap)

**Not run directly.** Imported and called by `comparison_engine_v2.py`.

Builds a parent-child process relationship graph from PPID/PID columns. Renders the
tree as a chart with attack-only (new) processes coloured red and baseline processes
coloured green. Also renders the ATT&CK heatmap (tactic columns × technique rows,
cells coloured and numbered by hit count).

Output files it produces (via master engine):
- `chart_process_tree.png` — parent-child process tree
- `chart_attack_heatmap.png` — ATT&CK coverage heatmap

To use this module in your own script:
```python
from modules.process_tree import render_process_tree, render_attack_heatmap

render_process_tree(attack_pslist_df, new_processes_df, "/MFF/analysis/out")
render_attack_heatmap(tagged_df, "/MFF/analysis/out")
```

---

## FILE 6 — modules/export_alert.py  (JSON Export + Alerting)

**Not run directly.** Imported and called by `comparison_engine_v2.py`.

Builds a structured JSON threat summary from all analysis results. The schema is
Elastic ECS compatible for direct SIEM ingestion. Sends Slack Block Kit alerts or
generic JSON webhooks. Uses only Python stdlib (urllib) — no requests library needed.

Output files it produces (via master engine):
- `threat_summary.json` — full structured threat summary

To use this module in your own script:
```python
from modules.export_alert import build_json_summary, write_json_summary, send_webhook

summary = build_json_summary(
    case_id, baseline_path, attack_path,
    new_df, gone_df, scores_df, tagged_df,
    ioc_df, net_new_df, net_flagged_df
)
write_json_summary(summary, "/MFF/analysis/out")
send_webhook("https://hooks.slack.com/services/XXX", summary, mode="slack")
```

---

## FILE 7 — modules/report_generator.py  (HTML + PDF Reports)

**Not run directly.** Imported and called by `comparison_engine_v2.py`
when `--make-html` or `--make-pdf` flags are passed.

**HTML report** — sticky sidebar navigation, filterable and sortable tables for every
section, all charts embedded as base64 (fully self-contained single .html file, no CDN
or internet needed), dark forensics theme, summary stat cards, tab-switched sections
for process diff/network/IOCs.

**PDF report** — professional multi-page layout via reportlab: cover page, severity
banner, executive summary table, ATT&CK tactic list, IOC summary, and all charts
embedded as images.

Output files it produces:
- `report_interactive.html` — triggered by `--make-html`
- `report_forensics.pdf` — triggered by `--make-pdf` (requires reportlab)

Install reportlab for PDF support:
```bash
pip install reportlab
```

---

## FILE 8 — modules/automation.py  (Watchdog / Batch / Vol3 Runner)

**Can be run directly** as a standalone script for three automation workflows.

---

### Batch mode — compare one baseline vs multiple attack cases

Runs the full engine on each attack case in sequence. Each gets its own output
subfolder. A `batch_summary.json` is written listing all results and timings.

```bash
python /MFF/src/modules/automation.py batch \
  --baseline /MFF/cases/case01_baseline \
  --attacks  /MFF/cases/case03_t1059_attack \
             /MFF/cases/case04_t1055_attack \
             /MFF/cases/case05_lateral \
  --out-root /MFF/analysis/batch_run_01 \
  --make-html
```

With PDF and Slack alert per case:
```bash
python /MFF/src/modules/automation.py batch \
  --baseline /MFF/cases/case01_baseline \
  --attacks  /MFF/cases/case03_t1059_attack \
             /MFF/cases/case04_t1055_attack \
  --out-root /MFF/analysis/batch_run_01 \
  --make-html \
  --make-pdf \
  --webhook  https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

---

### Watchdog mode — auto-analyse new case folders as they appear

Polls a directory every N seconds. When a new subfolder appears that contains
`exports/csv/*.csv` it automatically triggers the full engine against it.
Existing folders at startup are skipped — only new arrivals trigger analysis.

```bash
python /MFF/src/modules/automation.py watchdog \
  --watch-dir /MFF/cases \
  --baseline  /MFF/cases/case01_baseline \
  --out-root  /MFF/analysis/auto \
  --engine    /MFF/src/comparison_engine_v2.py \
  --make-html \
  --interval  15
```

Press `Ctrl+C` to stop.

---

### Vol3 runner — auto-run Volatility 3 on a raw memory image

Runs all standard plugins (pslist, cmdline, malfind, netscan, pstree, dlllist,
handles, modules, registry.hivelist) and exports each as a CSV into
`--out/exports/csv/`. After this completes the folder is ready to pass directly
to `comparison_engine_v2.py` as `--baseline` or `--attack`.

```bash
python /MFF/src/modules/automation.py vol3 \
  --image /MFF/images/case03.vmem \
  --out   /MFF/cases/case03_t1059_attack
```

With custom vol3 path and timeout:
```bash
python /MFF/src/modules/automation.py vol3 \
  --image    /MFF/images/case03.vmem \
  --out      /MFF/cases/case03_t1059_attack \
  --vol3-bin /opt/volatility3/vol.py \
  --timeout  600
```

Full pipeline from raw image to report:
```bash
# Step 1 — run vol3 on baseline image
python /MFF/src/modules/automation.py vol3 \
  --image /MFF/images/baseline.vmem \
  --out   /MFF/cases/case01_baseline

# Step 2 — run vol3 on attack image
python /MFF/src/modules/automation.py vol3 \
  --image /MFF/images/case03.vmem \
  --out   /MFF/cases/case03_t1059_attack

# Step 3 — run full comparison
python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case03_t1059_attack \
  --out      /MFF/analysis/comparison/case01_vs_case03 \
  --make-html
```

### All flags — automation.py
| Mode | Flag | Required | Description |
|---|---|---|---|
| batch | `--baseline` | ✅ | Baseline case path |
| batch | `--attacks` | ✅ | One or more attack case paths (space separated) |
| batch | `--out-root` | ✅ | Root output directory |
| batch | `--make-html` | optional | Generate HTML for each case |
| batch | `--make-pdf` | optional | Generate PDF for each case |
| batch | `--webhook` | optional | Webhook URL for each alert |
| watchdog | `--watch-dir` | ✅ | Directory to monitor |
| watchdog | `--baseline` | ✅ | Baseline case path |
| watchdog | `--out-root` | ✅ | Root output directory |
| watchdog | `--engine` | ✅ | Full path to comparison_engine_v2.py |
| watchdog | `--interval` | optional | Poll interval in seconds (default: 15) |
| watchdog | `--make-html` | optional | Generate HTML per case |
| watchdog | `--make-pdf` | optional | Generate PDF per case |
| watchdog | `--webhook` | optional | Webhook URL per alert |
| vol3 | `--image` | ✅ | Path to raw memory image (.vmem) |
| vol3 | `--out` | ✅ | Case output directory |
| vol3 | `--vol3-bin` | optional | Path to vol.py if not on PATH |
| vol3 | `--timeout` | optional | Per-plugin timeout seconds (default: 300) |

---

## FILE 9 — modules/__init__.py  (Package Marker)

Empty file. Required so Python treats the modules folder as a package and allows
`from modules.mitre_tagger import ...` style imports to work.
Do not edit or delete.

---

## All Output Files Reference

| File | Triggered by | Description |
|---|---|---|
| `report_interactive.html` | `--make-html` | Filterable/sortable HTML report, all charts embedded |
| `report_forensics.pdf` | `--make-pdf` | Exportable multi-page PDF |
| `threat_summary.json` | always | SIEM/SOAR structured JSON (Elastic ECS compatible) |
| `dashboard.png` | always | Master 5-panel summary chart |
| `chart_process_counts.png` | always | Baseline vs attack process count bar chart |
| `chart_process_tree.png` | always | Parent-child process tree (new=red, baseline=green) |
| `chart_attack_heatmap.png` | always | MITRE ATT&CK tactic × technique heatmap |
| `chart_risk_scores.png` | always | Top risk scores bar + risk level pie |
| `chart_timeline.png` | always | Process creation timeline (new and gone) |
| `chart_cmdline_patterns.png` | always | Suspicious cmdline pattern hit frequency |
| `chart_malfind_protection.png` | always | Malfind memory protection type breakdown |
| `process_new.csv` | always | Processes new in attack (not in baseline) |
| `process_gone.csv` | always | Processes gone from baseline (not in attack) |
| `cmdline_findings.csv` | always | Suspicious cmdline hits with matched pattern column |
| `malfind.csv` | always | RWX/EXECUTE memory regions from malfind |
| `timeline.csv` | always | Full attack pslist sorted by CreateTime |
| `scores.csv` | always | Per-process risk scores with level and indicators |
| `attack_tags.csv` | always | All MITRE ATT&CK tagged findings with technique URL |
| `tactic_summary.csv` | always | Tactic/technique hit counts sorted by frequency |
| `iocs.csv` | always | All extracted IOCs — type, value, source, count |
| `net_new.csv` | always | New network connections present in attack only |
| `net_flagged.csv` | always | New connections to suspicious/known-bad ports |

---

## Risk Scoring Logic

Scoring is evidence-only. A process never gets a high score from its name alone.

| Evidence | Points | How it triggers |
|---|---|---|
| Suspicious cmdline | +40 | PID found in cmdline scan results |
| RWX memory region | +60 | PID found in malfind EXECUTE results |
| Known-malicious name | +50 | Exact match: mimikatz.exe, rubeus.exe, meterpreter, etc. |
| Anomalous name bonus | +15 | Name contains shellcode/hollowing/reflective AND score already > 0 |

| Score | Risk Level |
|---|---|
| 80 + | CRITICAL |
| 50 – 79 | HIGH |
| 20 – 49 | MEDIUM |
| 0 – 19 | LOW |

Legitimate Windows processes (ShellExperienceHost.exe, svchost.exe, lsass.exe)
will always score LOW unless they have real forensic evidence against them.

---

## Dependencies

| Library | Required | Install | Used for |
|---|---|---|---|
| `pandas` | ✅ | usually pre-installed | all data processing |
| `numpy` | ✅ | usually pre-installed | chart calculations |
| `matplotlib` | ✅ | usually pre-installed | all 8 charts |
| `reportlab` | optional | `pip install reportlab` | PDF report only |
| Python stdlib | ✅ | built-in | JSON, webhooks, watchdog polling, CSV |

```bash
pip install pandas numpy matplotlib reportlab
```

No internet connection is required at analysis time.
All ATT&CK rules, suspicious port lists, and IOC patterns are fully built in.
