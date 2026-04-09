# Case 04 — Artefact Analysis (T1574.001 DLL Hijacking + AMSI Bypass)

## Overview

This case analyses a controlled simulation of **DLL Search Order Hijacking (T1574.001)** combined with **AMSI memory bypass behaviour (T1562.001)**.

The attack was executed using manually staged binaries and controlled execution paths to ensure persistent memory artefacts suitable for forensic analysis.

Dataset:

case04_t1574_attack

The Memory Forensics Framework (MFF) processed the dataset and identified multiple correlated indicators across process execution, DLL loading, and memory behaviour.

---

# Dataset Processing Pipeline

Memory acquisition:

VBoxManage debugvm "Windows 10" dumpvmcore

Volatility plugins:

windows.pslist
windows.pstree
windows.cmdline
windows.dlllist
windows.malware.malfind
windows.threads

The framework performed:

* Baseline comparison
* Artefact correlation
* Risk scoring
* MITRE ATT&CK mapping

---

# Key Artefact Findings

## 1. Suspicious PowerShell Execution

Multiple PowerShell processes were identified:

* PID 5844
* PID 1316
* PID 6764
* PID 7804
* PID 5136

All processes correspond to:

T1059.001 — PowerShell Execution

---

## 2. AMSI Bypass via Memory Patching

The framework detected:

* `amsi.dll` loaded in PowerShell processes
* Presence of **PAGE_EXECUTE_READWRITE (RWX)** memory regions

Examples:

PID 6764 → 5 RWX regions
PID 7804 → 5 RWX regions
PID 5136 → 5 RWX regions

### Interpretation

This pattern indicates:

* In-memory modification of AMSI scanning logic
* Execution of code within writable + executable regions

This behaviour matches:

T1562.001 — Disable or Modify Tools (AMSI Memory Patch)

---

## 3. DLL Search Order Hijacking (Primary Attack)

### Critical Finding

Process:

powershell.exe (PID 5136)

Loaded DLL:

C:\Temp\pshijack\amsi.dll

Expected location:

C:\Windows\System32\amsi.dll

### Interpretation

This indicates:

* DLL loaded from attacker-controlled directory
* Violation of expected system DLL loading path

This confirms:

T1574.001 — DLL Search Order Hijacking

---

## 4. Additional Hijack Evidence (mspaint.exe)

Process:

mspaint.exe (PID 8060)

Loaded DLL:

C:\temp\hijack\VERSION.dll

Executable path:

C:\temp\hijack\mspaint.exe

### Interpretation

* System binary executed from non-standard directory
* DLL loaded from same directory
* Confirms classic DLL search order hijacking behaviour

---

## 5. Combined Behaviour Correlation

The framework identified overlapping behaviours:

| Behaviour            | Technique |
| -------------------- | --------- |
| PowerShell execution | T1059.001 |
| AMSI memory patching | T1562.001 |
| DLL hijacking        | T1574.001 |

### Key Insight

The attack demonstrates:

* Execution (PowerShell)
* Defense evasion (AMSI bypass)
* Persistence / hijacking (DLL search order)

---

# Risk Scoring Results

High-risk processes:

powershell.exe (PID 5136)
Risk Score: 80
Indicators:

* AMSI DLL loaded from staging directory
* RWX memory regions detected
* Suspicious execution chain

mspaint.exe (PID 8060)
Risk Score: 70
Indicators:

* System executable from user directory
* DLL loaded from staging path

---

# Baseline Comparison Findings

The following artefacts were absent in baseline:

* C:\Temp\pshijack\powershell.exe
* C:\Temp\pshijack\amsi.dll
* C:\temp\hijack\mspaint.exe
* C:\temp\hijack\VERSION.dll

These are classified as:

NEW (Attack Only)

---

# Indicators of Compromise

* C:\Temp\pshijack\amsi.dll
* C:\temp\hijack\VERSION.dll
* C:\temp\hijack\mspaint.exe

---

# MITRE ATT&CK Mapping

| Technique | Description                |
| --------- | -------------------------- |
| T1059.001 | PowerShell execution       |
| T1562.001 | AMSI memory patching       |
| T1574.001 | DLL search order hijacking |

---

# Conclusion

The analysis confirms a **multi-layered attack scenario** combining:

* DLL hijacking
* AMSI bypass via memory patching
* PowerShell execution

The presence of:

* Non-standard DLL paths
* RWX memory regions
* Attack-only processes

provides **high-confidence forensic evidence** of malicious behaviour.

The Memory Forensics Framework successfully correlated multiple artefact sources to produce a structured and explainable detection result.

---
