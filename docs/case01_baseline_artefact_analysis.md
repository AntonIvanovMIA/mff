# Case 01 — Artefact Analysis (Baseline System)

## Overview

This analysis documents the baseline memory state of a Windows 10 system prior to any attack simulation.

The purpose of this dataset is to establish a clean reference environment used by the Memory Forensics Framework (MFF) for comparison against attack scenarios.

Baseline dataset:

case01_baseline

This dataset represents:

* Normal operating system behaviour
* Legitimate process execution
* Expected command-line activity
* Absence of malicious artefacts

The baseline is critical for enabling accurate anomaly detection and reducing false positives during attack analysis.

---

# Dataset Processing Pipeline

Memory acquisition:

VBoxManage debugvm "Windows 10" dumpvmcore

Volatility extraction plugins:

windows.info
windows.pslist
windows.pstree
windows.cmdline
windows.dlllist
windows.malware.malfind
windows.netscan

The outputs were exported to structured datasets (CSV format) and processed using the Memory Forensics Framework.

The framework performs:

* Baseline profiling
* Artefact structuring
* Behavioural mapping
* Preparation for comparison analysis

---

# System Information

The windows.info plugin confirms a standard Windows 10 system configuration.

This provides:

* OS version validation
* Kernel-level metadata
* System context for analysis

This step ensures that the memory image is valid and compatible with forensic processing.

---

# Process Artefact Analysis

The windows.pslist output shows only legitimate system processes.

Observed processes include:

System
smss.exe
csrss.exe
wininit.exe
services.exe
lsass.exe
explorer.exe

Process behaviour is consistent with normal Windows operation.

Process hierarchy (validated with windows.pstree):

wininit.exe
├── services.exe
├── lsass.exe
└── lsaiso.exe

There are:

* No anomalous parent-child relationships
* No unexpected process creation
* No suspicious executables

---

# Command Execution Analysis

The windows.cmdline dataset shows only standard system command execution.

Examples include:

C:\Windows\System32\services.exe

There are:

* No encoded commands
* No scripting abuse (PowerShell, cmd injection)
* No attacker-controlled execution

This confirms the absence of command execution techniques such as:

T1059 — Command and Scripting Interpreter

---

# DLL Analysis

The windows.dlllist output confirms that:

* Only legitimate system DLLs are loaded
* No unsigned modules are present
* No injected libraries are observed

This indicates:

* No DLL injection
* No reflective loading
* No abnormal module behaviour

---

# Memory Injection Analysis

The windows.malware.malfind plugin shows:

* No suspicious memory regions
* No PAGE_EXECUTE_READWRITE segments
* No injected code

This confirms:

The system is free from in-memory execution techniques such as:

* Shellcode injection
* Reflective DLL loading
* Fileless malware

---

# Network Activity Analysis

The windows.netscan dataset shows only expected system-level network activity.

Observed behaviour includes:

* Local communication
* Standard Windows networking

There are:

* No suspicious remote connections
* No command-and-control indicators
* No anomalous ports

---

# Risk Scoring Results

The Memory Forensics Framework assigns risk scores based on detected artefacts.

In the baseline dataset:

All processes are classified as:

Risk Score: 0–10
Risk Level: LOW

No indicators of compromise were detected.

---

# Baseline Behaviour Summary

The system exhibits fully normal behaviour across all analysed artefacts.

| Category             | Status   |
| -------------------- | -------- |
| Process activity     | Normal   |
| Command execution    | Benign   |
| Memory regions       | Clean    |
| Network activity     | Expected |
| Injection indicators | None     |

---

# Role in Framework

This baseline dataset is essential for the operation of the Memory Forensics Framework.

It is used to:

* Identify new processes in attack cases
* Detect behavioural deviations
* Reduce false positives
* Establish trusted system behaviour

The baseline enables accurate comparison against attack scenarios such as:

* T1055 — Process Injection
* T1059 — Command Execution
* T1574 — Hijacking

---

# Comparison Context

During comparison, the framework identifies anomalies by contrasting baseline and attack datasets.

Example:

Baseline: no powershell.exe execution
Attack: powershell.exe detected → flagged as anomaly

This approach allows precise detection of malicious behaviour introduced during attack simulations.

---

# Conclusion

The baseline memory analysis confirms a clean and stable system state.

No evidence was found of:

* Command execution attacks
* Memory injection
* Suspicious processes
* Malicious network activity

This dataset serves as a trusted reference model for detecting anomalies in subsequent forensic investigations.

---
