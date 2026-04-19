# MFF v2 — Memory Forensics Framework

> **Post-Volatility 3 Analysis & Visualization Framework**  
> FYP — University of Roehampton 2026  
> Student: Anton Ivanov  
> Submission: 1 May 2026  
> GitHub: [github.com/AntonIvanovMIA/MFF](https://github.com/AntonIvanovMIA/MFF)

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Framework Architecture](#2-framework-architecture)
3. [Dataset — 5 Cases](#3-dataset--5-cases)
4. [Attack Simulation Methodology](#4-attack-simulation-methodology)
5. [Memory Acquisition](#5-memory-acquisition)
6. [Volatility 3 Export Commands](#6-volatility-3-export-commands)
7. [MFF Analysis Commands](#7-mff-analysis-commands)
8. [Analysis Results — All Cases](#8-analysis-results--all-cases)
9. [Risk Scoring Methodology](#9-risk-scoring-methodology)
10. [MITRE ATT&CK Detection Rules](#10-mitre-attck-detection-rules)
11. [DLL Analysis Logic](#11-dll-analysis-logic)
12. [UK Forensic Standards Compliance](#12-uk-forensic-standards-compliance)
13. [Project Directory Structure](#13-project-directory-structure)
14. [Output Files Per Run](#14-output-files-per-run)
15. [Dependencies & Installation](#15-dependencies--installation)
16. [Known Bugs Fixed](#16-known-bugs-fixed)
17. [Git Repository](#17-git-repository)
18. [Final Verification Checklist](#18-final-verification-checklist)

---

## 1. Project Overview

MFF v2 is a Python-based post-Volatility 3 memory forensics analysis framework. It automates the pipeline from raw memory dump through to professional forensic reports — without requiring machine learning.

### What the framework does

- Loads Volatility 3 plugin exports (CSV and JSONL) from any case folder
- Compares an attack memory dump against a clean baseline (process diff by name)
- Scores every process using a transparent rule-based risk model
- Maps detected artefacts to MITRE ATT&CK techniques (42 rules, 8 tactics)
- Detects T1574 DLL hijacking and T1562 AMSI bypass via multi-source correlation
- Extracts IOCs: IPv4 addresses, domains, file paths, hashes
- Generates interactive HTML reports and professional PDF forensics reports
- Supports standalone analysis (no baseline needed), batch runs, and cross-case comparison

### Comparison vs existing tools

| Feature | Volatility 3 alone | volGPT | MFF v2 |
|---|---|---|---|
| Baseline vs attack diff | ❌ | ❌ | ✅ Name-based process diff |
| Risk scoring (transparent) | ❌ | ❌ | ✅ Rule-based, no ML |
| DLL hijacking detection | ❌ | ❌ | ✅ T1574.001 + T1562.001 |
| MITRE ATT&CK auto-tagging | ❌ | Partial | ✅ 42 rules, 8 tactics |
| Interactive HTML report | ❌ | ❌ | ✅ Filterable, clickable |
| PDF forensics report | ❌ | ❌ | ✅ ACPO/NIST/ISO 27037 |
| Batch multi-case analysis | ❌ | ❌ | ✅ automation.py |
| Cross-case comparison | ❌ | ❌ | ✅ case_comparison.py |
| JSONL + CSV dual format | ❌ | ❌ | ✅ Auto-detect both |
| IOC extraction | ❌ | ❌ | ✅ IP/domain/hash/path |
| Dynamic attack narrative | ❌ | ❌ | ✅ Auto-generated per case |

---

## 2. Framework Architecture

### Module map

```
/MFF/src/
├── comparison_engine_v2.py          ← Master engine — loads data, runs full pipeline
└── modules/
    ├── dll_analysis.py              ← T1574.001 DLL hijacking + T1562.001 AMSI bypass
    ├── mitre_tagger.py              ← 42 ATT&CK rules across 8 tactics
    ├── network_ioc.py               ← Network diff + IOC extraction
    ├── process_tree.py              ← Process tree chart + ATT&CK heatmap
    ├── export_alert.py              ← JSON threat summary + webhook alerts
    ├── report_generator.py          ← Interactive HTML + PDF reports
    ├── automation.py                ← 4 modes: batch, analyse, compare, vol3
    ├── case_comparison.py           ← Cross-case comparison charts and report
    └── mff_dashboard.py             ← Live terminal dashboard
```

### Data flow pipeline

```
VBoxManage dumpvmcore
        ↓
Volatility 3 (7 plugins × CSV + JSONL)
        ↓
load_case()  ←  CSV-first, JSONL fallback
        ↓
┌───────────────────────────────────────────────┐
│  Analysis Pipeline                            │
│  1. Process diff  (name-based, not PID)       │
│  2. Cmdline analysis  (suspicious flags)      │
│  3. Malfind analysis  (RWX regions)           │
│  4. DLL analysis  (T1574 + T1562)             │
│  5. Risk scoring  (additive, no ML)           │
│  6. ATT&CK tagging  (42 rules)               │
│  7. Network diff + IOC extraction             │
│  8. Process tree + heatmap charts             │
│  9. Dynamic attack narrative                  │
└───────────────────────────────────────────────┘
        ↓
report_generator.py
        ↓
report_interactive.html  +  report_forensics.pdf
```

### Data loading — CSV-first, JSONL fallback

`load_case()` in `comparison_engine_v2.py` automatically tries `exports/csv/` first, then falls back to `exports/jsonl/` if the CSV is missing or empty. No configuration needed.

| Plugin | CSV file | JSONL file |
|---|---|---|
| windows.pslist | windows.pslist.csv | windows.pslist.jsonl |
| windows.pstree | windows.pstree.csv | windows.pstree.jsonl |
| windows.cmdline | windows.cmdline.csv | windows.cmdline.jsonl |
| windows.dlllist | windows.dlllist.csv | windows.dlllist.jsonl |
| windows.malfind | windows.malfind.csv | windows.malfind.jsonl |
| windows.netscan | windows.netscan.csv | windows.netscan.jsonl |
| windows.threads | windows.threads.csv | windows.threads.jsonl |

> **Important:** The Volatility 3 plugin class is `windows.malware.malfind` but the output file **must** be named `windows.malfind.csv` / `windows.malfind.jsonl` for `load_case()` to find it.

### Process diff methodology

Process comparison uses `ImageFileName` (process name) not PID. PID-based diff was rejected because PIDs are reassigned on every reboot, producing false-positive churn exceeding 90% of all processes. Name-based diff correctly identifies genuinely new attack processes.

---

## 3. Dataset — 5 Cases

### Target environment

- **VM:** Windows 10 Home — DESKTOP-GQOVOJU
- **Platform:** VirtualBox on Windows 11 host
- **RAM:** 4 GB (dump size ~4 GB per case)
- **Network:** 10.0.2.15 (VM) / 10.0.2.2 (gateway)
- **User:** lucif / desktop-gqovoju\lucif

### Case table

| Case | Folder | Technique | Raw file | SHA256 |
|---|---|---|---|---|
| Baseline | case01_baseline | Clean — no attack | baseline.raw | recorded in hash_values.txt |
| Case 02 | case02_t1055_5_attack | T1055.5 — Thread Local Storage Injection | T1055.raw | recorded in hash_values.txt |
| Case 03 | case03_t1059_attack | T1059.001 — PowerShell | T1059.raw | recorded in hash_values.txt |
| Case 04 | case04_t1574_attack | T1574.001 — DLL Search Order Hijacking | T1574.raw | recorded in hash_values.txt |
| Case 05 | case05_multi_attack | Multi: T1055+T1059+T1574+T1082+T1016+T1033+T1057+T1562 | T_multi.raw | a0983f4df938595db7ffdb377b743defdd02428f6b1d97b9f653821690a8f1d0 |

### Evidence folder structure per case

```
/MFF/cases/<case>/
├── <image>.raw                  ← Raw memory dump (read-only chmod 444)
└── exports/
    ├── csv/
    │   ├── windows.pslist.csv
    │   ├── windows.pstree.csv
    │   ├── windows.cmdline.csv
    │   ├── windows.dlllist.csv
    │   ├── windows.malfind.csv
    │   ├── windows.netscan.csv
    │   └── windows.threads.csv
    └── jsonl/
        ├── windows.pslist.jsonl
        ├── windows.pstree.jsonl
        ├── windows.cmdline.jsonl
        ├── windows.dlllist.jsonl
        ├── windows.malfind.jsonl
        ├── windows.netscan.jsonl
        └── windows.threads.jsonl
```

---

## 4. Attack Simulation Methodology

All attacks executed inside the Windows 10 VM with PowerShell as Administrator, then VM memory dumped from the Windows 11 host immediately without closing the VM.

### Case 02 — T1055.5 Process Injection

**Tool:** Atomic Red Team — Invoke-AtomicTest T1055  
**Evidence produced:** PAGE_EXECUTE_READWRITE regions in powershell.exe — VirtualAlloc with flProtect=0x40

```powershell
# Inside Windows 10 VM — PowerShell as Administrator
$env:PathToAtomicsFolder = "C:\AtomicRedTeam\atomics"
Invoke-AtomicTest T1055 -TestNumbers 1

# Keep process alive
Start-Sleep -Seconds 600
```

---

### Case 03 — T1059.001 PowerShell

**Evidence produced:** Multiple PowerShell processes with `-enc`, `-ExecutionPolicy Bypass`, `-NoProfile`, `-WindowStyle Hidden`

```powershell
# Inside Windows 10 VM — PowerShell as Administrator

# Encoded payload (T1059.001)
$cmd = "Get-Process | Select-Object Name,Id | ConvertTo-Json"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$enc = [Convert]::ToBase64String($bytes)
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList `
  '-ExecutionPolicy','Bypass','-NoProfile','-WindowStyle','Hidden','-enc',$enc

# Keep processes alive
Start-Sleep -Seconds 600
```

---

### Case 04 — T1574.001 DLL Search Order Hijacking

**Evidence produced:** `amsi.dll` from `C:\Temp\pshijack\` (not System32). `powershell.exe` from `C:\Temp\multiattack\` (non-standard path)

```powershell
# Inside Windows 10 VM — PowerShell as Administrator

# Create staging directory and plant hijacked DLL
New-Item -ItemType Directory -Force C:\Temp\pshijack | Out-Null
Copy-Item C:\Windows\System32\amsi.dll C:\Temp\pshijack\amsi.dll -Force
Get-Item C:\Temp\pshijack\amsi.dll   # verify

# Non-standard PowerShell execution path
mkdir C:\Temp\multiattack -Force
Copy-Item C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe `
  C:\Temp\multiattack\powershell.exe -Force
cd C:\Temp\multiattack
.\powershell.exe

# Inside that PowerShell window — run discovery then sleep
whoami; hostname; systeminfo; ipconfig /all
Start-Sleep -Seconds 600
```

---

### Case 05 — Multi-technique (strongest case)

**Evidence produced:** 8 ATT&CK techniques across 3 tactics. 42 RWX regions. 12 DLL findings. Full recon chain.

```powershell
# Inside Windows 10 VM — PowerShell as Administrator

# ── Phase 1: Setup staging directory and DLL plant
New-Item -ItemType Directory -Force C:\Temp\mff_multi | Out-Null
Copy-Item C:\Windows\System32\amsi.dll C:\Temp\mff_multi\amsi.dll -Force
Get-Item C:\Temp\mff_multi\amsi.dll   # verify: 103936 bytes

# ── Phase 2: Discovery chain (T1082 + T1016 + T1033 + T1057)
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList `
  '-ExecutionPolicy','Bypass',
  '-NoProfile',
  '-WindowStyle','Hidden',
  '-Command',
  'systeminfo; Get-ComputerInfo | Out-Null; ipconfig /all; Get-NetIPAddress | Out-Null; whoami; Get-LocalUser | Out-Null; Get-Process | Out-Null; tasklist; Start-Sleep -Seconds 600'

# ── Phase 3: Encoded PowerShell sleeper (T1059.001 with -enc)
$encCmd = 'Start-Sleep -Seconds 600'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($encCmd))
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList `
  '-ExecutionPolicy','Bypass',
  '-NoProfile',
  '-WindowStyle','Hidden',
  '-enc',
  $enc

# ── Phase 4: DLL hijack + RWX memory allocation script (T1574.001 + T1055 + T1562.001)
# Create the attack script
@'
$ErrorActionPreference = "SilentlyContinue"

Copy-Item C:\Windows\System32\amsi.dll C:\Temp\mff_multi\amsi.dll -Force

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class MFFNative {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
}
"@

$h1 = [MFFNative]::LoadLibrary("C:\Temp\mff_multi\amsi.dll")

$buf = [MFFNative]::VirtualAlloc([IntPtr]::Zero, 4096, 0x3000, 0x40)

if ($buf -ne [IntPtr]::Zero) {
    [System.Runtime.InteropServices.Marshal]::Copy([byte[]](0x90,0x90,0xC3), 0, $buf, 3)
}

Start-Sleep -Seconds 600
'@ | Set-Content -Path C:\Temp\mff_multi\case05_rwx_amsi.ps1 -Encoding ASCII

# Run the script
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList `
  '-ExecutionPolicy','Bypass',
  '-NoProfile',
  '-WindowStyle','Hidden',
  '-File',
  'C:\Temp\mff_multi\case05_rwx_amsi.ps1'

# ── Verify attack processes are alive before dumping
Get-CimInstance Win32_Process |
  Where-Object { $_.Name -match 'powershell' } |
  Select-Object ProcessId, Name, CommandLine |
  Format-List
```

---

## 5. Memory Acquisition

Performed from **Windows 11 host machine** immediately after attack, while VM is still running with all attack processes alive.

### Step 1 — Dump from host (Windows CMD)

```cmd
cd "C:\Program Files\Oracle\VirtualBox"

VBoxManage debugvm "Windows 10" dumpvmcore --filename "D:\2.ROEHAMPTON\Final year\FYPROJECT\Memory forensics framework tools for analyse and visualisation\shared\......raw"
```

### Step 2 — Hash on host immediately

```cmd
certutil -hashfile "D:\2.ROEHAMPTON\Final year\FYPROJECT\Memory forensics framework tools for analyse and visualisation\shared\......raw" SHA256
```

Write down the SHA256. This is the chain of custody hash.

### Step 3 — Transfer to Kali

```bash
cp /media/sf_shared/T_multi.raw /MFF/cases/case05_multi_attack/T_multi.raw
ls -lh /MFF/cases/case05_multi_attack/......raw   # verify ~4 GB
```

### Step 4 — Hash on Kali and verify

```bash
sha256sum /MFF/cases/case05_multi_attack/.....raw
md5sum    /MFF/cases/case05_multi_attack/...raw
```

SHA256 must match the host value. If it does not match, the dump is corrupted — repeat acquisition.

### Step 5 — Lock evidence and record hashes

```bash
chmod 444 /MFF/cases/case05_multi_attack/.....raw
example:

echo "Case: case05_multi_attack"        >> /MFF/docs/hash_values.txt
echo "File: T_multi.raw"                >> /MFF/docs/hash_values.txt
sha256sum /MFF/cases/case05_multi_attack/T_multi.raw | awk '{print "SHA256: "$1}' >> /MFF/docs/hash_values.txt
md5sum    /MFF/cases/case05_multi_attack/T_multi.raw | awk '{print "MD5:    "$1}' >> /MFF/docs/hash_values.txt
sha1sum   /MFF/cases/case05_multi_attack/T_multi.raw | awk '{print "SHA1:   "$1}' >> /MFF/docs/hash_values.txt
echo "--------------------------------------" >> /MFF/docs/hash_values.txt

tail -n 8 /MFF/docs/hash_values.txt   # verify
```

---

## 6. Volatility 3 Export Commands

Run these from Kali. Replace the raw filename for each case.

```bash
source /MFF/venv/bin/activate
cd ~/volatility3
```

### Template — replace CASE and RAWFILE per case

| Case | CASE variable | RAWFILE |
|---|---|---|
| case01_baseline | case01_baseline | baseline.raw |
| case02_t1055_5_attack | case02_t1055_5_attack | T1055.raw |
| case03_t1059_attack | case03_t1059_attack | T1059.raw |
| case04_t1574_attack | case04_t1574_attack | T1574.raw |
| case05_multi_attack | case05_multi_attack | T_multi.raw |

### CSV exports (7 plugins)

```bash
CASE=case05_multi_attack
RAW=/MFF/cases/$CASE/T_multi.raw
OUT=/MFF/cases/$CASE/exports/csv

mkdir -p $OUT

python vol.py -q -f $RAW -r csv windows.pslist   > $OUT/windows.pslist.csv
python vol.py -q -f $RAW -r csv windows.pstree   > $OUT/windows.pstree.csv
python vol.py -q -f $RAW -r csv windows.cmdline  > $OUT/windows.cmdline.csv
python vol.py -q -f $RAW -r csv windows.dlllist  > $OUT/windows.dlllist.csv
python vol.py -q -f $RAW -r csv windows.netscan  > $OUT/windows.netscan.csv
python vol.py -q -f $RAW -r csv windows.threads  > $OUT/windows.threads.csv

# malfind — note: class is windows.malware.malfind but output file must be windows.malfind.csv
python vol.py -q -f $RAW -r csv windows.malware.malfind > $OUT/windows.malfind.csv
# If above fails try:
python vol.py -q -f $RAW -r csv windows.malfind > $OUT/windows.malfind.csv
```

### JSONL exports (7 plugins — fallback for engine)

```bash
OUT=/MFF/cases/$CASE/exports/jsonl
mkdir -p $OUT

python vol.py -q -f $RAW -r jsonl windows.pslist   > $OUT/windows.pslist.jsonl
python vol.py -q -f $RAW -r jsonl windows.pstree   > $OUT/windows.pstree.jsonl
python vol.py -q -f $RAW -r jsonl windows.cmdline  > $OUT/windows.cmdline.jsonl
python vol.py -q -f $RAW -r jsonl windows.dlllist  > $OUT/windows.dlllist.jsonl
python vol.py -q -f $RAW -r jsonl windows.netscan  > $OUT/windows.netscan.jsonl
python vol.py -q -f $RAW -r jsonl windows.threads  > $OUT/windows.threads.jsonl
python vol.py -q -f $RAW -r jsonl windows.malware.malfind > $OUT/windows.malfind.jsonl
```

### Verify all exports

```bash
ls -lh /MFF/cases/case05_multi_attack/exports/csv/
ls -lh /MFF/cases/case05_multi_attack/exports/jsonl/

# All 7 files must exist and be non-empty
# Verify key artefacts present
grep -i "multiattack\|mff_multi\|enc\|bypass\|systeminfo\|whoami" \
  /MFF/cases/case05_multi_attack/exports/csv/windows.cmdline.csv | head -10

grep -i "amsi\|mff_multi\|multiattack" \
  /MFF/cases/case05_multi_attack/exports/csv/windows.dlllist.csv | head -10
```

---

## 7. MFF Analysis Commands

### Always first — activate environment

```bash
source /MFF/venv/bin/activate
```

---

### 7.1 Comparison — Baseline vs Attack (all 4 cases)

```bash
# Case 02 — T1055.5 Process Injection
python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case02_t1055_5_attack \
  --out      /MFF/analysis/comparison/case01_vs_case02 \
  --make-html --make-pdf

# Case 03 — T1059 PowerShell
python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case03_t1059_attack \
  --out      /MFF/analysis/comparison/case01_vs_case03 \
  --make-html --make-pdf

# Case 04 — T1574 DLL Hijacking
python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case04_t1574_attack \
  --out      /MFF/analysis/comparison/case01_vs_case04 \
  --make-html --make-pdf

# Case 05 — Multi-technique
python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case05_multi_attack \
  --out      /MFF/analysis/comparison/case01_vs_case05 \
  --make-html --make-pdf
```

---

### 7.2 Standalone Analysis — Single Case (no baseline needed)

Reads existing exports and runs full analysis pipeline on the attack case alone.

```bash
# Case 02
python /MFF/src/modules/automation.py analyse \
  --case /MFF/cases/case02_t1055_5_attack \
  --out  /MFF/analysis/single/case02 \
  --make-html --make-pdf

# Case 03
python /MFF/src/modules/automation.py analyse \
  --case /MFF/cases/case03_t1059_attack \
  --out  /MFF/analysis/single/case03 \
  --make-html --make-pdf

# Case 04
python /MFF/src/modules/automation.py analyse \
  --case /MFF/cases/case04_t1574_attack \
  --out  /MFF/analysis/single/case04 \
  --make-html --make-pdf

# Case 05
python /MFF/src/modules/automation.py analyse \
  --case /MFF/cases/case05_multi_attack \
  --out  /MFF/analysis/single/case05 \
  --make-html --make-pdf
```

---

### 7.3 Batch — All 4 Attack Cases at Once

```bash
python /MFF/src/modules/automation.py batch \
  --baseline /MFF/cases/case01_baseline \
  --attacks  /MFF/cases/case02_t1055_5_attack \
             /MFF/cases/case03_t1059_attack \
             /MFF/cases/case04_t1574_attack \
             /MFF/cases/case05_multi_attack \
  --out-root /MFF/analysis/batch_run_final \
  --make-html --make-pdf
```

---

### 7.4 Cross-Case Comparison Report

Run after batch. Generates cross-case comparison charts and a combined report.

```bash
python /MFF/src/modules/automation.py compare \
  --batch-root /MFF/analysis/batch_run_final \
  --out        /MFF/analysis/batch_run_final/comparison_report \
  --make-html --make-pdf
```

---

### 7.5 Open All Reports

```bash
# Individual comparisons
firefox /MFF/analysis/comparison/case01_vs_case02/report_interactive.html
firefox /MFF/analysis/comparison/case01_vs_case03/report_interactive.html
firefox /MFF/analysis/comparison/case01_vs_case04/report_interactive.html
firefox /MFF/analysis/comparison/case01_vs_case05/report_interactive.html

# Standalone analyses
firefox /MFF/analysis/single/case02/report_interactive.html
firefox /MFF/analysis/single/case03/report_interactive.html
firefox /MFF/analysis/single/case04/report_interactive.html
firefox /MFF/analysis/single/case05/report_interactive.html

# Cross-case comparison
firefox /MFF/analysis/batch_run_final/comparison_report/comparison_report.html
```

---

## 8. Analysis Results — All Cases

All results generated by `comparison_engine_v2.py` against `case01_baseline`.

### 8.1 Cross-case summary

| Case | Severity | Max Score | Critical | Techniques | RWX | DLL Hijack | IOCs | New Procs |
|---|---|---|---|---|---|---|---|---|
| case02 — T1055.5 | CRITICAL | 100 | 2 | 2 | 7 | 2 | 40 | 13 |
| case03 — T1059 | CRITICAL | 100 | 3 | 2 | 5 | 1 | 52 | 16 |
| case04 — T1574 | CRITICAL | 100 | 6 | 3 | 22 | 9 | 49 | 15 |
| case05 — Multi | CRITICAL | 100 | 8 | 8 | 42 | 12 | 59 | 16 |

### 8.2 Technique detection matrix

| Technique | Name | Tactic | Case02 | Case03 | Case04 | Case05 |
|---|---|---|---|---|---|---|
| T1055 | Process Injection | Defense Evasion | ✅ | ✅ | ✅ | ✅ |
| T1562.001 | AMSI Bypass | Defense Evasion | ✅ | ✅ | ✅ | ✅ |
| T1574.001 | DLL Search Order Hijacking | Defense Evasion | — | — | ✅ | ✅ |
| T1059.001 | PowerShell | Execution | — | — | — | ✅ |
| T1082 | System Information Discovery | Discovery | — | — | — | ✅ |
| T1016 | Network Config Discovery | Discovery | — | — | — | ✅ |
| T1033 | System Owner/User Discovery | Discovery | — | — | — | ✅ |
| T1057 | Process Discovery | Discovery | — | — | — | ✅ |

### 8.3 Key forensic findings per case

#### Case 02 — T1055.5 Process Injection

- 7 `PAGE_EXECUTE_READWRITE` regions in `powershell.exe` (PIDs 992, 7764)
- VirtualAlloc with `flProtect=0x40` — standard shellcode allocation pattern
- AMSI bypass via memory patching: `amsi.dll` loaded AND RWX regions in same PID (T1562.001)
- 2 CRITICAL-scored processes, risk score 100/100
- 13 new processes vs baseline

#### Case 03 — T1059.001 PowerShell

- PowerShell with `-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc` flags
- Encoded payload detected in args: `-enc UwB0AGEAcg...`
- 5 RWX regions — AMSI bypass attempt alongside execution
- 3 CRITICAL-scored processes (powershell.exe)
- 16 new processes vs baseline, 52 IOCs

#### Case 04 — T1574.001 DLL Search Order Hijacking

- `amsi.dll` loaded from `C:\Temp\pshijack\amsi.dll` — NOT System32
- `AMSI_FILE_OUTPUT_DISABLED` — highest confidence finding (score 90)
- `powershell.exe` running from `C:\Temp\multiattack\powershell.exe` — non-standard path
- 22 RWX regions across 6 CRITICAL processes
- 9 DLL findings — `version.dll`, `amsi.dll` from staging paths
- 3 ATT&CK techniques: T1055, T1562.001, T1574.001

#### Case 05 — Multi-technique (strongest case)

**New processes introduced (attack-only):**

| Process | PID | CreateTime (UTC) | Significance |
|---|---|---|---|
| powershell.exe | 4512 | 17:17:58 | First attack PS — parent of chain |
| powershell.exe | 2824 | 17:19:32 | From C:\Temp\multiattack\ — T1574 |
| powershell.exe | 10128 | 17:35:17 | Discovery chain launcher |
| powershell.exe | 3448 | 17:36:02 | Encoded payload (-enc) |
| powershell.exe | 3092 | 17:37:34 | RWX/AMSI script |
| powershell.exe | 260 | 17:40:06 | Discovery: systeminfo+ipconfig+whoami |
| powershell.exe | 9508 | 17:40:14 | Encoded payload duplicate |
| powershell.exe | 1676 | 17:40:50 | RWX/AMSI script duplicate |

**DLL findings (highest confidence):**

| PID | Process | DLL | HijackType | Technique | Score |
|---|---|---|---|---|---|
| 3092 | powershell.exe | amsi.dll | AMSI_FILE_OUTPUT_DISABLED | T1562.001 | 90 |
| 1676 | powershell.exe | amsi.dll | AMSI_FILE_OUTPUT_DISABLED | T1562.001 | 90 |
| 2824 | powershell.exe | amsi.dll | AMSI_BYPASS_MEMORY_PATCH | T1562.001 | 80 |
| 4512 | powershell.exe | amsi.dll | AMSI_BYPASS_MEMORY_PATCH | T1562.001 | 80 |
| 3092 | powershell.exe | amsi.dll | PROTECTED_DLL_USER_DIR | T1574.001 | 70 |
| 1676 | powershell.exe | amsi.dll | PROTECTED_DLL_USER_DIR | T1574.001 | 70 |

**Cmdline artefacts (key entries):**

```
PID 2824   C:\Temp\multiattack\powershell.exe
           ← Non-standard execution path — T1574

PID 3448   powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden
           -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAANgAwADAA
           ← Encoded command — T1059.001

PID 3092   powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden
           -File C:\Temp\mff_multi\case05_rwx_amsi.ps1
           ← RWX + AMSI script — T1055 + T1574 + T1562

PID 260    powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden
           -Command systeminfo; Get-ComputerInfo; ipconfig /all; Get-NetIPAddress;
           whoami; Get-LocalUser; Get-Process; tasklist; Start-Sleep -Seconds 600
           ← Full discovery chain — T1082 + T1016 + T1033 + T1057
```

---

## 9. Risk Scoring Methodology

MFF v2 uses a **transparent, rule-based additive scoring model — no machine learning.** Each evidence category contributes exactly once per process. Score is clamped to 100. Aligned with ACPO Principle 2 (multi-source corroboration).

| Category | Score | Source | Rationale |
|---|---|---|---|
| AMSI DLL from staging (T1562.001) | +90 | dlllist: amsi.dll NOT from System32, File=disabled | Highest specificity — non-functional AMSI confirmed |
| AMSI memory patch (T1562.001) | +80 | dlllist: amsi.dll + malfind: RWX same PID | Two-source corroboration |
| Staging directory execution | +70 | dlllist: protected DLL from Temp/AppData | Direct T1574 artefact |
| 5+ RWX memory regions (T1055) | +55 | malfind: PAGE_EXECUTE_READWRITE × 5+ | Substantial injection evidence |
| Protected DLL from user dir | +50 | dlllist: amsi.dll from non-System32 path | T1574 specific evidence |
| Staging cmdline path | +40 | cmdline: \\Temp\\ or non-standard path | Execution anomaly |
| Suspicious cmdline flags | +40 | cmdline: -enc, bypass, iex, downloadstring | Behavioral evidence |
| High-risk parent chain | +25 | pstree: suspicious parent-child | Corroborative |
| 1-4 RWX regions | +20 | malfind: small region count | Weak — supporting only |
| Anomalous name keyword | +15 | Only stacks on top of other evidence | Never triggers alone |

### Risk level thresholds

| Level | Score | Meaning | Standard |
|---|---|---|---|
| CRITICAL | ≥ 80 | Multiple independent sources | Meets CPS digital evidence threshold |
| HIGH | ≥ 55 | Two or more independent indicators | Strong forensic confidence |
| MEDIUM | ≥ 25 | Single strong or multiple weak | Moderate confidence |
| LOW | ≥ 1 | Circumstantial only | Supporting evidence |
| CLEAN | 0 | No adverse findings | No evidence |

---

## 10. MITRE ATT&CK Detection Rules

`mitre_tagger.py` contains 42 rule-based signatures across 8 tactics. Detection logic:

### Key design decisions

**T1059.001 (PowerShell)** — Requires suspicious flags, not just process presence:
```
Keywords: -enc , -encoded, -nop , -noprofile, -w hidden, -windowstyle hidden,
          bypass, iex , iex(, invoke-expression, downloadstring, downloadfile,
          invoke-webrequest, reflection.assembly, frombase64string
Source:   cmdline only (NOT pslist — process presence ≠ malicious execution)
```

**T1059.003 (CMD Shell)** — Requires payload flag, not just cmd.exe present:
```
Keywords: cmd /c , cmd /k , cmd.exe /c, cmd.exe /k
Source:   cmdline only
```

**T1055 (Process Injection)** — Detected from malfind Protection column:
```
Keywords: PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ_WRITE, EXECUTE_READWRITE
Source:   malfind (scans Protection column AND ImageFileName)
```

**T1005 (Data from Local System)** — Specific cmdlets only (no "type " false positive):
```
Keywords: get-content , copy-item c:\\, robocopy , compress-archive ,
          [io.file]::readalltext, out-file , export-csv
Source:   cmdline
```

### Confidence levels

Every ATT&CK hit carries a Confidence field:
- `HIGH` — from cmdline or malfind (actual attack evidence)
- `LOW` — from pslist (process just exists — not attack evidence alone)

`summary_by_tactic()` filters to HIGH confidence only for the technique count shown in reports and terminal output.

---

## 11. DLL Analysis Logic

`dll_analysis.py` uses four detection strategies:

### Strategy 1 — Staging path detection (T1574.001)

Scans every DLL path in `windows.dlllist` for suspicious path keywords:

```python
SUSPICIOUS_PATH_KEYWORDS = (
    "\\temp\\", "\\tmp\\", "\\appdata\\",
    "\\users\\", "\\downloads\\", "\\desktop\\",
    "\\public\\", "\\recycle", "\\pshijack\\", "\\hijack\\",
)
```

Protected DLLs (amsi.dll, version.dll, cryptbase.dll, etc.) loaded from staging paths = T1574.001.

### Strategy 2 — AMSI file output disabled (T1562.001 — highest confidence)

If `amsi.dll` is loaded from a non-System32 path AND the dlllist `FileOutput` column shows `Disabled` — the real AMSI has been replaced. Score 90.

### Strategy 3 — AMSI memory patch correlation (T1562.001)

Cross-correlates `dlllist` and `malfind` by PID. If `powershell.exe` loads `amsi.dll` AND has `PAGE_EXECUTE_READWRITE` regions in the same PID — AmsiScanBuffer() has been patched in memory. Score 80.

### Strategy 4 — SYSTEM_EXE_FROM_WRONG_DIR

Checks if known system executables (powershell.exe, cmd.exe, notepad.exe) are running from paths outside System32/SysWOW64.

### Legitimate AppData exclusions

```python
LEGITIMATE_APPDATA_SUBSTRINGS = (
    "microsoft\\onedrive\\",
    "microsoft\\edge\\",
    "google\\chrome\\",
    "mozilla firefox\\",
    "microsoft\\teams\\",
)
```

OneDrive, Edge, Chrome, Teams load DLLs from AppData legitimately — excluded from staging detection.

---

## 12. UK Forensic Standards Compliance

| Standard | Principle | How MFF v2 Complies |
|---|---|---|
| ACPO Good Practice Guide | Principle 1 — No alteration | VBoxManage dumpvmcore does not alter original VM state. Hypervisor-level, no kernel module. |
| ACPO Good Practice Guide | Principle 2 — Competence | Risk scoring requires multi-source corroboration. DLL path + RWX = two independent sources. Single-source findings scored lower and labelled clearly. |
| ACPO Good Practice Guide | Principle 3 — Audit trail | SHA256 + MD5 + SHA1 recorded on host immediately post-acquisition. Kali hash verified against host hash before analysis begins. |
| ACPO Good Practice Guide | Principle 4 — Responsibility | All analysis steps documented. Commands deterministic — same input = same output. No ML randomness. Reproducible by any examiner. |
| NIST SP 800-86 | Integrating Forensic Techniques into IR | Volatility 3 used for memory parsing per NIST guidance on volatile data collection and analysis. |
| ISO/IEC 27037:2012 | Digital Evidence Guidelines | Evidence identification, collection, acquisition and preservation followed. Chain of custody in hash_values.txt. |
| College of Policing | Digital Forensics Guidance | Examination methodology aligned with CoP guidance on digital device examination. |
| CPS Disclosure Manual | Digital Evidence Threshold | CRITICAL threshold (≥80) requires multiple independent sources — calibrated to CPS standard for digital evidence disclosure. |

---

## 13. Project Directory Structure

```
mff/
├── analysis/
│   ├── comparison/
│   │   ├── case01_vs_case02/
│   │   ├── case01_vs_case03/
│   │   ├── case01_vs_case04/
│   │   └── case01_vs_case05/
│   ├── single/
│   │   ├── case02/
│   │   ├── case03/
│   │   ├── case04/
│   │   └── case05/
│   └── batch_run_final/
│       ├── case02_t1055_5_attack/
│       ├── case03_t1059_attack/
│       ├── case04_t1574_attack/
│       ├── case05_multi_attack/
│       └── comparison_report/
├── cases/
│   ├── case01_baseline/
│   │   └── exports/
│   │       ├── csv/
│   │       │   ├── windows.pslist.csv
│   │       │   ├── windows.pstree.csv
│   │       │   ├── windows.cmdline.csv
│   │       │   ├── windows.dlllist.csv
│   │       │   ├── windows.malfind.csv
│   │       │   ├── windows.netscan.csv
│   │       │   └── windows.threads.csv
│   │       └── jsonl/
│   │           ├── windows.pslist.jsonl
│   │           ├── windows.pstree.jsonl
│   │           ├── windows.cmdline.jsonl
│   │           ├── windows.dlllist.jsonl
│   │           ├── windows.malfind.jsonl
│   │           ├── windows.netscan.jsonl
│   │           └── windows.threads.jsonl
│   ├── case02_t1055_5_attack/
│   │   ├── T1055.raw
│   │   └── exports/
│   │       ├── csv/    [same 7 plugin outputs]
│   │       └── jsonl/  [same 7 plugin outputs]
│   ├── case03_t1059_attack/
│   │   ├── T1059.raw
│   │   └── exports/
│   │       ├── csv/    [same 7 plugin outputs]
│   │       └── jsonl/  [same 7 plugin outputs]
│   ├── case04_t1574_attack/
│   │   ├── T1574.raw
│   │   └── exports/
│   │       ├── csv/    [same 7 plugin outputs]
│   │       └── jsonl/  [same 7 plugin outputs]
│   └── case05_multi_attack/
│       ├── T_multi.raw
│       └── exports/
│           ├── csv/    [same 7 plugin outputs]
│           └── jsonl/  [same 7 plugin outputs]
├── docs/
│   ├── Case 04 — Artefact Analysis.md
│   ├── MFF_COMMANDS.md
│   ├── artefact_schema.md
│   ├── case01_baseline_artefact_analysis.md
│   ├── case03_t1059_artefact_analysis.md
│   ├── case04_t1574_artefact_analysis.md
│   ├── case04_t1574_artefact_schema.md
│   ├── case05_commands_log.md
│   ├── case05_dissertation_section.md
│   ├── case05_evidence_index.md
│   ├── case05_final_checklist.md
│   ├── case05_memory_acquisition_and_integrity.md
│   ├── case05_multi_attack_report_notes.md
│   ├── case05_report_mapping.md
│   ├── commands.md
│   ├── final_project_checklist.md
│   └── hash_values.txt
├── lab-notes/
│   ├── docs/
│   │   └── acquisition_log.md
│   ├── MFF_COMMANDS2.md
│   ├── README.md
│   └── TEST 1Document.txt
├── screenshots/
│   ├── week1/
│   ├── week2/
│   ├── week3/
│   ├── week4/
│   └── week5/
│       └── case 5 screenshots/
├── src/
│   ├── bak files/
│   │   └── comparison_engine_v2.py.bak
│   ├── modules/
│   │   ├── dll_analysis.py
│   │   ├── mitre_tagger.py
│   │   ├── network_ioc.py
│   │   ├── process_tree.py
│   │   ├── export_alert.py
│   │   ├── report_generator.py
│   │   ├── automation.py
│   │   ├── case_comparison.py
│   │   ├── mff_dashboard.py
│   │   └── Unique_compare.py
│   └── comparison_engine_v2.py
├── .gitignore
└── README.md
```

---

## 14. Output Files Per Run

Every analysis run produces these files in the `--out` directory:

| File | Description |
|---|---|
| `report_interactive.html` | Self-contained interactive HTML — all charts embedded as base64 |
| `report_forensics.pdf` | Professional PDF forensics report (ACPO/NIST/ISO 27037 aligned) |
| `dashboard.png` | Full analysis dashboard (5 panels: process counts, risk dist, cmdline hits, risk scores, RWX, timeline) |
| `chart_process_counts.png` | Process count bar + capture composition donut |
| `chart_risk_scores.png` | Top processes by risk score + distribution donut |
| `chart_timeline.png` | Process creation/disappearance timeline (NEW=red, GONE=blue) |
| `chart_cmdline_patterns.png` | Suspicious cmdline pattern hits horizontal bar |
| `chart_malfind_protection.png` | RWX memory protection distribution + per-process count |
| `chart_process_tree.png` | Parent-child process tree (attack nodes in red/orange) |
| `chart_attack_heatmap.png` | MITRE ATT&CK technique coverage heatmap |
| `scores.csv` | Risk scores for all processes with evidence breakdown |
| `attack_tags.csv` | MITRE ATT&CK technique matches with Confidence + Source |
| `cmdline_findings.csv` | Suspicious command line matches with matched pattern |
| `malfind.csv` | Filtered RWX memory regions (JIT processes excluded) |
| `dll_hijack.csv` | DLL hijacking findings with HijackType and RiskScore |
| `process_new.csv` | New processes — attack-only (vs baseline) |
| `process_gone.csv` | Gone processes — baseline-only (absent in attack) |
| `iocs.csv` | Extracted IOCs: IPv4, domains, file paths, hashes |
| `net_flagged.csv` | Flagged network connections on suspicious ports |
| `net_new.csv` | New network connections vs baseline |
| `threat_summary.json` | JSON threat summary — SIEM/webhook compatible |
| `timeline.csv` | Process timeline data (CreateTime per process) |
| `tactic_summary.csv` | ATT&CK tactic summary (HIGH confidence only) |

**Cross-case comparison run additionally produces:**

| File | Description |
|---|---|
| `comparison_report.html` | Cross-case interactive HTML |
| `comparison_report.pdf` | Cross-case PDF |
| `comparison_matrix.csv` | All cases summary matrix |

---

## 15. Dependencies & Installation

### Python packages

```bash
# Activate virtual environment first
source /MFF/venv/bin/activate

# Install all required packages
pip install pandas numpy matplotlib reportlab pillow --break-system-packages

# Verify
python -c "import pandas, numpy, matplotlib, reportlab, PIL; print('All dependencies OK')"
```

| Package | Version | Purpose |
|---|---|---|
| pandas | ≥ 2.0 | All DataFrame operations — core data processing |
| numpy | ≥ 1.24 | Numerical operations |
| matplotlib | ≥ 3.7 | All chart generation (dark theme) |
| reportlab | ≥ 4.0 | PDF report generation |
| pillow | ≥ 10.0 | Image handling for PDF chart embedding |

### Volatility 3

```bash
# Location
~/volatility3/vol.py

# Test
cd ~/volatility3
python vol.py --help
```

### Environment setup from scratch

```bash
# Create virtual environment
python3 -m venv /MFF/venv
source /MFF/venv/bin/activate

# Install packages
pip install pandas numpy matplotlib reportlab pillow --break-system-packages

# Clone framework (if setting up fresh)
git clone https://github.com/AntonIvanovMIA/MFF.git /MFF

# Create case directory structure
mkdir -p /MFF/cases/case01_baseline/exports/{csv,jsonl}
mkdir -p /MFF/cases/case02_t1055_5_attack/exports/{csv,jsonl}
mkdir -p /MFF/cases/case03_t1059_attack/exports/{csv,jsonl}
mkdir -p /MFF/cases/case04_t1574_attack/exports/{csv,jsonl}
mkdir -p /MFF/cases/case05_multi_attack/exports/{csv,jsonl}
mkdir -p /MFF/analysis/comparison /MFF/analysis/single /MFF/analysis/batch_run_final
mkdir -p /MFF/docs
```

---

## 16. Known Bugs Fixed

All bugs identified during development and resolved:

| Bug | Root Cause | Fix Applied |
|---|---|---|
| T1055 false positives on MsMpEng, SearchApp | `tag_all()` received raw `attack["malfind"]` not filtered `malfind_df` | Pass `malfind_df` (already filtered) not `attack["malfind"]` to `tag_all()` |
| T1059.001 firing on clean PowerShell path | Keyword `powershell` matched `C:\...\powershell.exe` in Args — just the EXE path | Require actual attack flags: `-enc`, `bypass`, `iex`, `downloadstring` etc. |
| T1059.003 noise — cmd.exe always present | `cmd.exe` in pslist fired — cmd.exe always running on Windows | Require `/c` or `/k` with payload in cmdline; removed pslist source |
| T1005 false positive on `type ` | `type ` (with space) matched substrings in normal paths | Removed `type ` keyword; kept specific PS data access cmdlets only |
| IOC garbage: `x.Fr`, `q....` | `Hexdump` and `Disasm` columns were scanned for IOCs | Removed `Hexdump` and `Disasm` from `source_map` in `network_ioc.py` |
| DLL false positives: OneDrive, Edge | `\\appdata\\` keyword flagged legitimate vendor DLLs | Added `LEGITIMATE_APPDATA_SUBSTRINGS` to `_is_legitimate()` in `dll_analysis.py` |
| Double base64 prefix — broken images | `_img_b64()` already returned full URI; template added prefix again | Changed `src="data:image/png;base64,{img}"` to `src="{img}"` |
| Hardcoded case04 narrative in report | Executive summary had hardcoded `pshijack`, `version.dll`, `PID 5136` | Added `_build_attack_narrative()` — fully dynamic from actual data |
| Timeline empty in standalone mode | No baseline diff → `new_df` empty → `chart_timeline()` returned immediately | Timeline now shows CRITICAL/HIGH scored processes by CreateTime |
| UnboundLocalError: `pd` | `import pandas as pd` inside `if` block; `net_flagged_df` referenced before | Moved `import pandas as pd` before variable assignment |
| Confidence field missing | `tag_all()` hits had no confidence metadata | Added `Confidence: HIGH/LOW` and `Source` field to every ATT&CK hit |
| malfind tag_dataframe scanning wrong column | `ImageFileName` found before `Protection` in column priority list | For `source="malfind"` now scans both `Protection` AND `ImageFileName` |

---

## 17. Git Repository

```bash
# Repository
https://github.com/AntonIvanovMIA/MFF.git

# Final commit — run from Kali
cd /MFF
git add .
git commit -m "MFF v2 final — all 5 cases complete, all reports generated, framework polished"
git push origin main

# Verify
git log --oneline | head -10
git status
`in conflict is used this :
cd /MFF

git fetch origin
git pull --rebase origin main
git push origin main``

### .gitignore — important entries

```gitignore
# Raw memory dumps — too large for GitHub (>100MB rejected)
*.raw
*.vmem
*.dmp
*.lime

# Virtual environment
venv/

# Python cache
__pycache__/
*.pyc
*.pyo

# Analysis outputs (optional — large)
analysis/
```

---

## 18. Final Verification Checklist

Run these before submission to confirm everything is in order:

```bash
source /MFF/venv/bin/activate

# 1. Python environment
which python   # must be /MFF/venv/bin/python

# 2. All modules importable
cd /MFF/src
python -c "import comparison_engine_v2; print('Engine OK')"
python -c "from modules import dll_analysis, mitre_tagger, network_ioc; print('Modules OK')"

# 3. All case exports present (7 CSV files each)
for case in case01_baseline case02_t1055_5_attack case03_t1059_attack case04_t1574_attack case05_multi_attack; do
  count=$(ls /MFF/cases/$case/exports/csv/*.csv 2>/dev/null | wc -l)
  echo "$case: $count CSV files"
done

# 4. All comparison reports present
for pair in case01_vs_case02 case01_vs_case03 case01_vs_case04 case01_vs_case05; do
  html=/MFF/analysis/comparison/$pair/report_interactive.html
  pdf=/MFF/analysis/comparison/$pair/report_forensics.pdf
  echo "$pair: HTML=$([ -f $html ] && echo OK || echo MISSING) PDF=$([ -f $pdf ] && echo OK || echo MISSING)"
done

# 5. Batch run complete
ls /MFF/analysis/batch_run_final/

# 6. Cross-case comparison report
ls /MFF/analysis/batch_run_final/comparison_report/

# 7. Hash values recorded
cat /MFF/docs/hash_values.txt

# 8. Git committed
git -C /MFF log --oneline | head -5
git -C /MFF status
```

### Expected output — everything working

```
/MFF/venv/bin/python
Engine OK
Modules OK
case01_baseline: 7 CSV files
case02_t1055_5_attack: 7 CSV files
case03_t1059_attack: 7 CSV files
case04_t1574_attack: 7 CSV files
case05_multi_attack: 7 CSV files
case01_vs_case02: HTML=OK PDF=OK
case01_vs_case03: HTML=OK PDF=OK
case01_vs_case04: HTML=OK PDF=OK
case01_vs_case05: HTML=OK PDF=OK
```

---

## Credentials & Infrastructure Reference

| Component | Value |
|---|---|
| Project root | /MFF |
| Python venv | /MFF/venv |
| Volatility 3 | ~/volatility3/vol.py |
| Shared folder (Windows→Kali) | /media/sf_shared/ |
| ElasticStack credentials | elastic → Anton@, kibana_system → Kibana2026@, Logstash → Logstash2026@ |
| VM hostname | DESKTOP-GQOVOJU |
| VM user | lucif (desktop-gqovoju\lucif) |
| VM IP | 10.0.2.15 |
| Gateway | 10.0.2.2 |
| GitHub | https://github.com/AntonIvanovMIA/MFF.git |

---

*MFF v2 — Memory Forensics Framework · FYP University of Roehampton 2026 · Anton Ivanov*
