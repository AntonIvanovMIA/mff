# Memory Artefact Schema (Case 01 — Baseline System)

## Overview

This section defines the structured artefact schema used by the Memory Forensics Framework (MFF) for analysing the baseline memory dataset.

The baseline schema represents a **clean system state**, where all observed artefacts correspond to legitimate operating system behaviour.

This schema serves as the reference model for comparison against attack scenarios.

---

# 1. Process Artefact Schema (windows.pslist)

Source Plugin:

windows.pslist

This dataset contains active processes observed in memory.

| Field         | Description                |
| ------------- | -------------------------- |
| PID           | Unique process identifier  |
| PPID          | Parent process identifier  |
| ImageFileName | Executable name            |
| CreateTime    | Process creation timestamp |
| ExitTime      | Process termination time   |

### Baseline Characteristics

* Processes correspond to standard Windows components
* Stable parent-child relationships
* No unexpected process creation

Example processes:

System
smss.exe
csrss.exe
wininit.exe
services.exe
lsass.exe
explorer.exe

Interpretation:

These processes represent normal system operation and form the trusted baseline for comparison.

---

# 2. Process Hierarchy Schema (windows.pstree)

Source Plugin:

windows.pstree

This dataset represents parent-child process relationships.

### Baseline Characteristics

* Logical process hierarchy
* No orphaned processes
* No anomalous spawning behaviour

Example structure:

wininit.exe
├── services.exe
├── lsass.exe
└── lsaiso.exe

Interpretation:

This structure confirms normal Windows boot and service initialization behaviour.

---

# 3. Command-Line Artefact Schema (windows.cmdline)

Source Plugin:

windows.cmdline

This dataset contains command-line arguments associated with processes.

| Field   | Description            |
| ------- | ---------------------- |
| PID     | Process identifier     |
| Process | Process name           |
| Args    | Command-line arguments |

### Baseline Characteristics

* Standard system execution paths
* No scripting engine abuse
* No encoded or obfuscated commands

Example:

C:\Windows\System32\services.exe

Interpretation:

No evidence of command execution techniques such as:

T1059 — Command and Scripting Interpreter

---

# 4. DLL Artefact Schema (windows.dlllist)

Source Plugin:

windows.dlllist

This dataset lists DLLs loaded by processes.

| Field   | Description           |
| ------- | --------------------- |
| PID     | Process identifier    |
| Process | Process name          |
| DLLPath | Path to loaded module |

### Baseline Characteristics

* Only trusted Windows DLLs loaded
* No unsigned modules
* No injected libraries

Interpretation:

This confirms the absence of DLL injection or reflective loading techniques.

---

# 5. Memory Region Artefact Schema (windows.malfind)

Source Plugin:

windows.malware.malfind

This dataset identifies suspicious memory regions.

| Field      | Description             |
| ---------- | ----------------------- |
| PID        | Process identifier      |
| Process    | Process name            |
| Protection | Memory protection flags |
| Tag        | Memory region type      |

### Baseline Characteristics

* No PAGE_EXECUTE_READWRITE regions
* No injected memory segments
* No anomalous VAD entries

Interpretation:

The system does not exhibit characteristics of in-memory attacks such as:

* Shellcode execution
* Reflective DLL injection
* Fileless malware

---

# 6. Network Artefact Schema (windows.netscan)

Source Plugin:

windows.netscan

This dataset contains network connections observed in memory.

| Field      | Description        |
| ---------- | ------------------ |
| LocalAddr  | Local IP address   |
| RemoteAddr | Remote IP address  |
| State      | Connection state   |
| Process    | Associated process |

### Baseline Characteristics

* Expected system-level communication
* No suspicious external endpoints
* No anomalous ports

Interpretation:

No evidence of command-and-control communication or external attacker interaction.

---

# 7. Risk Scoring Schema (Framework Generated)

The Memory Forensics Framework assigns risk scores based on artefact analysis.

| Field      | Description          |
| ---------- | -------------------- |
| PID        | Process identifier   |
| Process    | Process name         |
| RiskScore  | Numerical risk score |
| RiskLevel  | Classification level |
| Indicators | Detection indicators |

### Baseline Characteristics

* All processes classified as LOW risk
* No suspicious indicators detected

Example:

Process: explorer.exe
RiskScore: 5
RiskLevel: LOW

Interpretation:

The baseline establishes the expected "clean" scoring profile for comparison with attack datasets.

---

# 8. Baseline Comparison Schema

The framework uses the baseline dataset as a reference for detecting anomalies.

| Field         | Description           |
| ------------- | --------------------- |
| ImageFileName | Process name          |
| PID           | Process identifier    |
| CreateTime    | Process creation time |
| DiffStatus    | Comparison result     |

### Baseline Characteristics

All processes are marked as:

BASELINE (Reference)

Interpretation:

Any deviation from this dataset in attack cases is treated as a potential anomaly.

---

# Summary

The baseline artefact schema defines the expected behaviour of a clean system.

This schema enables the Memory Forensics Framework to:

* Establish trusted system behaviour
* Detect deviations in attack scenarios
* Reduce false positives
* Support accurate risk scoring

By defining normal system activity, the baseline schema forms the foundation for all comparative forensic analysis performed by the framework.

---------------------------------------------------------------------------
# Memory Artefact Schema (Case 02 — T1055-5 Process Injection)

## Overview

This section defines the structured artefact schema used by the Memory Forensics Framework (MFF) for analysing the T1055-5 process injection dataset.

The schema is derived from Volatility plugin outputs and enriched with framework-level interpretation to identify in-memory injection behaviour.

Unlike the baseline schema, this case focuses on **high-confidence injection indicators**, including process lineage anomalies and executable memory regions.

---

# 1. Process Artefact Schema (windows.pslist)

Source Plugin:

windows.pslist

| Field         | Description                   |
| ------------- | ----------------------------- |
| PID           | Unique process identifier     |
| PPID          | Parent process identifier     |
| ImageFileName | Executable name               |
| CreateTime    | Process creation timestamp    |
| ExitTime      | Process termination timestamp |

### Observed Artefacts

* RWXinjectionLocal.exe (PID 2184)
* powershell.exe (PID 7764, PPID 2184)
* conhost.exe (PID 4964, PPID 7764)

### Key Findings

* A short-lived injector process (`RWXinjectionLocal.exe`) is observed
* The injector spawns `powershell.exe`, indicating process chaining
* Process creation timestamps are tightly correlated (same second window)

### Interpretation

This behaviour is consistent with:

* Loader / injector execution
* Parent-child anomaly (non-standard parent spawning PowerShell)
* Attack staging behaviour

This aligns with:

MITRE ATT&CK T1055 — Process Injection

---

# 2. Process Hierarchy Schema (windows.pstree)

Source Plugin:

windows.pstree

### Observed Structure

RWXinjectionLocal.exe (2184)
└── powershell.exe (7764)
  └── conhost.exe (4964)

### Key Findings

* Non-standard process chain originating from Atomic Red Team binary
* PowerShell execution is directly linked to injector process
* Console host spawned as a result of PowerShell execution

### Interpretation

This hierarchy deviates from baseline behaviour:

* PowerShell is not launched from explorer.exe (typical)
* Instead, it is launched from an injector binary

This is a strong behavioural indicator of:

* Controlled execution flow manipulation
* Injection staging chain

---

# 3. Command-Line Artefact Schema (windows.cmdline)

Source Plugin:

windows.cmdline

| Field   | Description            |
| ------- | ---------------------- |
| PID     | Process identifier     |
| Process | Process name           |
| Args    | Command-line arguments |

### Observed Artefacts

powershell.exe executed from:

\Device\HarddiskVolume2\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

RWXinjectionLocal.exe executed from:

\Device\HarddiskVolume2\AtomicRedTeam\atomics\T1055\bin\x64\RWXinjectionLocal.exe

### Key Findings

* Execution of Atomic Red Team injector binary
* Direct invocation of PowerShell following injector execution

### Interpretation

The presence of a custom binary followed by PowerShell execution indicates:

* Scripted attack orchestration
* Use of legitimate tools (PowerShell) as post-injection execution context

---

# 4. Memory Injection Artefact Schema (windows.malfind)

Source Plugin:

windows.malware.malfind

| Field      | Description                  |
| ---------- | ---------------------------- |
| PID        | Process identifier           |
| Process    | Process name                 |
| Protection | Memory protection flags      |
| Tag        | Memory region classification |

### Observed Artefacts

* powershell.exe (PID 7764)
* Memory protection: PAGE_EXECUTE_READWRITE

### Key Findings

* RWX memory region detected inside PowerShell process
* Memory region allows simultaneous read, write, and execute permissions

### Interpretation

RWX memory regions are strong indicators of:

* Shellcode staging
* Reflective code loading
* In-memory payload execution

In this case:

* RWX memory appears in the exact process spawned by the injector
* Temporal correlation matches injection execution window

This provides **high-confidence evidence of in-memory code execution**

---

# 5. Thread Artefact Schema (windows.threads)

Source Plugin:

windows.threads

| Field        | Description                 |
| ------------ | --------------------------- |
| PID          | Process identifier          |
| TID          | Thread identifier           |
| StartAddress | Thread start memory address |

### Observed Behaviour

* Threads associated with powershell.exe process

### Key Findings

* Threads executing within suspicious memory regions (RWX areas likely targets)
* Potential redirection of execution flow into injected memory

### Interpretation

Thread analysis supports:

* Execution of code within injected memory regions
* Possible remote thread creation or execution redirection

This reinforces the injection hypothesis from malfind analysis.

---

# 6. DLL Artefact Schema (windows.dlllist)

Source Plugin:

windows.dlllist

| Field   | Description        |
| ------- | ------------------ |
| PID     | Process identifier |
| Process | Process name       |
| DLLPath | Loaded module path |

### Observed Behaviour

* Standard system DLLs loaded into PowerShell process

### Key Findings

* No abnormal or unsigned DLLs required for injection
* Injection achieved without disk-based DLL artifacts

### Interpretation

This supports:

* Fileless execution model
* Memory-only attack technique

---

# 7. Network Artefact Schema (windows.netscan)

Source Plugin:

windows.netscan

| Field      | Description        |
| ---------- | ------------------ |
| LocalAddr  | Local IP           |
| RemoteAddr | Remote IP          |
| State      | Connection state   |
| Process    | Associated process |

### Observed Behaviour

* No strong evidence of external C2 communication

### Interpretation

* Injection appears local and controlled (simulation environment)
* No network-based payload delivery detected

---

# 8. Risk Scoring Artefact Schema (Framework Generated)

| Field      | Description        |
| ---------- | ------------------ |
| PID        | Process identifier |
| Process    | Process name       |
| RiskScore  | Numerical score    |
| RiskLevel  | Classification     |
| Indicators | Detection reasons  |

### Observed High-Risk Process

Process: powershell.exe
PID: 7764

### Indicators

* Spawned by injector process
* RWX memory region detected
* Suspicious execution chain
* Injection-related behaviour

### Risk Assessment

Risk Score: HIGH / CRITICAL

### Interpretation

The combination of:

* process lineage anomaly
* RWX memory detection
* execution timing correlation

produces a high-confidence malicious classification.

---

# 9. Baseline Comparison Artefact Schema

| Field         | Description        |
| ------------- | ------------------ |
| ImageFileName | Process name       |
| PID           | Process identifier |
| CreateTime    | Creation time      |
| DiffStatus    | Comparison result  |

### Key Findings

* RWXinjectionLocal.exe → NEW (Attack Only)
* powershell.exe (PID 7764) → NEW (Attack Only)

### Interpretation

These processes do not exist in the baseline dataset and therefore represent:

* Attack-introduced behaviour
* High-value forensic artefacts

---

# Summary

The artefact schema for Case 02 captures multiple correlated indicators of process injection:

* Injector process execution
* Anomalous process lineage
* RWX memory regions in target process
* Thread execution within suspicious memory
* Absence of disk-based artifacts (fileless behaviour)

These combined artefacts provide strong forensic evidence of:

MITRE ATT&CK T1055 — Process Injection

The structured schema enables the Memory Forensics Framework to:

* Detect injection behaviour automatically
* Correlate multiple artefact sources
* Assign risk scores based on evidence
* Compare attack behaviour against baseline systems

---------------------------------------------------------------------------

# Memory Artefact Schema (Case03 — T1059 Command Execution)

This section documents the structured artefact fields used by the Memory Forensics Framework (MFF) Python analysis layer.

The fields originate from Volatility plugin outputs and are parsed by the framework to enable automated artefact detection, baseline comparison, and risk scoring.

---

# 1. Process Artefact Schema (windows.pslist)

Source Plugin:

windows.pslist

This dataset contains the active process list extracted from memory.

| Field | Example Value | Description |
|------|---------------|-------------|
| PID | 7888 | Unique process identifier |
| PPID | 6016 | Parent process identifier |
| ImageFileName | powershell.exe | Executable name |
| CreateTime | 2026-02-17 23:50:10 UTC | Process creation timestamp |
| ExitTime | — | Process termination timestamp (if applicable) |

Example Row:

PID: 7888  
PPID: 6016  
ImageFileName: powershell.exe  
CreateTime: 2026-02-17 23:50:10 UTC  

Interpretation:

This indicates that **PowerShell was spawned by explorer.exe (PID 6016)** during the attack simulation.

Process chain:
explorer.exe (6016)
└── powershell.exe (7888)

This behaviour is consistent with **MITRE ATT&CK T1059 — Command and Scripting Interpreter**.

---

# 2. Command Execution Artefact Schema (windows.cmdline)

Source Plugin:

windows.cmdline

This dataset contains command-line arguments associated with processes.

| Field | Example Value | Description |
|------|---------------|-------------|
| PID | 7888 | Process identifier |
| Process | powershell.exe | Process name |
| Args | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | Command arguments |
| MatchedPattern | powershell | Suspicious keyword detected by the framework |

Example Row:

PID: 7888  
Process: powershell.exe  
Args: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  

Framework Interpretation:

The command execution pattern matches **PowerShell invocation**, which is frequently used in attacker scripts and automation frameworks.

The framework automatically flags such command patterns during analysis.

---

# 3. Memory Injection Artefact Schema (windows.malfind)

Source Plugin:

windows.malware.malfind

This plugin detects suspicious memory regions that may contain injected or hidden code.

| Field | Example Value | Description |
|------|---------------|-------------|
| PID | 7888 | Process identifier |
| Process | powershell.exe | Process containing suspicious memory |
| Protection | PAGE_EXECUTE_READWRITE | Memory protection flags |
| Tag | VadS | Memory region classification |

Example Row:

PID: 7888  
Process: powershell.exe  
Protection: PAGE_EXECUTE_READWRITE  
Tag: VadS  

Interpretation:

RWX memory permissions indicate a region that is:

• Readable  
• Writable  
• Executable  

Such memory regions are often associated with:

• shellcode execution  
• reflective DLL loading  
• fileless malware  

The presence of RWX memory regions inside PowerShell suggests **in-memory code execution**.

---

# 4. Risk Scoring Artefact Schema (Framework Generated)

The Memory Forensics Framework generates additional fields through its scoring engine.

| Field | Example Value | Description |
|------|---------------|-------------|
| PID | 7888 | Process identifier |
| Process | powershell.exe | Process name |
| RiskScore | 150 | Numerical risk score |
| RiskLevel | CRITICAL | Risk classification |
| Indicators | Suspicious cmdline; RWX memory region; Injection-related name | Detection reasons |

Example Row:

PID: 7888  
Process: powershell.exe  
RiskScore: 150  
RiskLevel: CRITICAL  

Indicators:

Suspicious command line  
RWX memory region  
Injection-related behaviour  

Interpretation:

The scoring engine prioritises suspicious processes by combining multiple artefact indicators.

The PowerShell process received the highest score due to the combination of:

• command execution  
• executable memory  
• suspicious behaviour indicators

---

# 5. Baseline Comparison Artefact Schema

The framework compares baseline and attack snapshots to identify new processes.

| Field | Example Value | Description |
|------|---------------|-------------|
| ImageFileName | powershell.exe | Process name |
| PID | 7888 | Process identifier |
| PPID | 6016 | Parent process identifier |
| CreateTime | 2026-02-17 23:50:10 UTC | Process creation time |
| DiffStatus | NEW (Attack Only) | Process not present in baseline |

Example Row:

ImageFileName: powershell.exe  
PID: 7888  
PPID: 6016  
CreateTime: 2026-02-17 23:50:10 UTC  
DiffStatus: NEW (Attack Only)

Interpretation:

The process did not exist in the baseline memory image and therefore represents a behavioural anomaly introduced during the attack scenario.

---

# Summary

The Memory Forensics Framework processes structured artefacts derived from Volatility plugin outputs.

These artefacts enable the framework to:

• reconstruct process behaviour  
• identify suspicious command execution  
• detect injected memory regions  
• compare system states between baseline and attack snapshots  
• assign risk scores to suspicious processes

This structured artefact schema allows the framework to transform raw memory analysis data into actionable forensic intelligence.
---------------------------------------------------------------------------




# Memory Artefact Schema (Case 04 — DLL Hijacking + AMSI Bypass)

## Overview

This schema defines the structured artefacts used by the Memory Forensics Framework (MFF) to detect DLL hijacking and AMSI bypass behaviour.

The schema combines process execution, DLL loading, and memory analysis to produce high-confidence detection results.

---

# 1. Process Artefact Schema (windows.pslist)

| Field         | Description        |
| ------------- | ------------------ |
| PID           | Process identifier |
| PPID          | Parent process     |
| ImageFileName | Executable name    |
| CreateTime    | Creation time      |

### Observed Findings

* Multiple PowerShell instances
* Execution from non-standard directories

### Interpretation

Indicates:

* Script execution activity
* Potential attacker-controlled processes

---

# 2. Command-Line Artefact Schema (windows.cmdline)

| Field   | Description        |
| ------- | ------------------ |
| PID     | Process identifier |
| Process | Process name       |
| Args    | Execution path     |

### Observed Findings

* C:\Temp\pshijack\powershell.exe
* C:\temp\hijack\mspaint.exe

### Interpretation

* Execution from staging directories
* Deviation from baseline system behaviour

---

# 3. DLL Artefact Schema (windows.dlllist)

| Field   | Description        |
| ------- | ------------------ |
| PID     | Process identifier |
| Process | Process name       |
| DLLPath | Loaded DLL path    |

### Observed Findings

* C:\Temp\pshijack\amsi.dll
* C:\temp\hijack\VERSION.dll

### Interpretation

* DLL loaded from attacker-controlled directory
* Violation of expected System32 loading

---

# 4. Memory Injection Schema (windows.malware.malfind)

| Field      | Description        |
| ---------- | ------------------ |
| PID        | Process identifier |
| Protection | Memory permissions |

### Observed Findings

* PAGE_EXECUTE_READWRITE regions
* Multiple RWX segments in PowerShell

### Interpretation

* In-memory execution
* AMSI patching behaviour

---

# 5. Thread Artefact Schema (windows.threads)

| Field        | Description        |
| ------------ | ------------------ |
| PID          | Process identifier |
| TID          | Thread ID          |
| StartAddress | Execution address  |

### Interpretation

* Threads executing within modified memory regions
* Supports memory patching evidence

---

# 6. Risk Scoring Schema

| Field      | Description       |
| ---------- | ----------------- |
| RiskScore  | Numerical score   |
| RiskLevel  | Classification    |
| Indicators | Detection reasons |

### Observed Indicators

* DLL from user directory
* RWX memory regions
* Suspicious process lineage

---

# 7. Baseline Comparison Schema

| Field         | Description       |
| ------------- | ----------------- |
| ImageFileName | Process           |
| DiffStatus    | Comparison result |

### Observed Findings

* Attack-only processes identified
* New DLL paths detected

---

# Summary

The schema enables detection of:

* DLL search order hijacking
* AMSI bypass behaviour
* Execution anomalies

By correlating:

* process execution
* DLL loading
* memory permissions

the framework produces **high-confidence forensic intelligence**.

---------------------------------------------------------------------------


# Case 05 – Real Artifact Schema

## 1. Case Identity
- Case Name: case05_multi_attack
- Baseline Reference: case01_baseline
- Attack Image: /MFF/cases/case05_multi_attack/T_multi.raw
- Comparison Output Directory: /MFF/analysis/comparison/case01_vs_case05

## 2. Primary Acquisition Artifact
### T_multi.raw
- Type: Raw memory image
- Role: Primary forensic evidence source for Case 05
- Acquisition Method: Hypervisor-assisted VirtualBox memory dump
- Analytical Importance: All Volatility outputs and all MFF comparison outputs for Case 05 were derived from this image

## 3. Integrity Record
The following hash values were recorded for the Case 05 memory image:

- MD5: 8c4f8c763f78993b30b2ac4a230952a2
- SHA1: 3d1825d640cbf425b54c83464eea9076ba251463
- SHA256: a0983f4df938595db7ffdb377b743defdd02428f6b1d97b9f653821690a8f1d0

Interpretation:
These values form the integrity record for the acquired memory image and support chain-of-custody documentation for Case 05.

## 4. Case-Level Evidence Summary
The final processed outputs for Case 05 reported the following high-level findings:

- Overall Severity: CRITICAL
- Critical Processes: 8
- New Processes: 16
- Gone Processes: 16
- ATT&CK Techniques Detected: 8
- ATT&CK Tactics Detected: 3
- IOCs Extracted: 59
- New Network Connections: 139
- Flagged Network Connections: 4
- RWX Memory Regions (cross-case summary): 42
- DLL Hijack / DLL Anomaly Findings (cross-case summary): 12

Interpretation:
Case 05 produced the richest and widest behavioural coverage of all completed attack cases. It was the strongest case for demonstrating multi-artefact correlation within the framework.

## 5. Real Artifacts Found by Evidence Class

### 5.1 Process Delta Artifacts
**Source Files:**
- process_new.csv
- process_gone.csv
- windows.pslist.csv
- windows.pstree.csv
- timeline.csv

**Actual Artifacts Found:**
The attack-only process diff included several `powershell.exe` instances associated with the scenario, including the following suspicious PIDs:

- 4512
- 2824
- 10128
- 3448
- 3092
- 260
- 9508
- 1676

Other new processes were also observed, such as:
- OfficeClickToR
- PhoneExperienc
- m365copilot_au
- SystemSettings
- ApplicationFra
- CalculatorApp

**Analytical Interpretation:**
The presence of multiple new `powershell.exe` processes strongly supports attack execution in memory. However, some non-PowerShell new processes are likely environmental drift rather than malicious activity. For this reason, process delta alone is not sufficient and must be interpreted together with command-line, DLL, and malfind evidence.

### 5.2 Command-Line Artifacts
**Source Files:**
- windows.cmdline.csv
- cmdline_findings.csv

**Actual Artifacts Found:**
The command-line outputs captured the following real suspicious patterns:

1. Execution from a non-standard PowerShell path:
   - `C:\Temp\multiattack\powershell.exe`

2. Hidden PowerShell with bypass and encoded execution:
   - `powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc ...`

3. Hidden PowerShell executing the staged script:
   - `powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File C:\Temp\mff_multi\case05_rwx_amsi.ps1`

4. Discovery and enumeration activity visible in command-line evidence:
   - `whoami`
   - `systeminfo`
   - `Get-ComputerInfo`
   - `ipconfig /all`
   - `Get-NetIPAddress`
   - `Get-LocalUser`
   - `Get-Process`
   - `tasklist`
   - `Start-Sleep -Seconds 600`

**Analytical Interpretation:**
These command-line artefacts provide direct evidence of:
- suspicious PowerShell execution
- hidden and bypass-oriented PowerShell activity
- encoded command use
- staged execution from temporary directories
- system, user, process, and network discovery behaviour

This is one of the strongest evidence classes in Case 05.

### 5.3 DLL / AMSI Artifacts
**Source Files:**
- windows.dlllist.csv
- dll_hijack.csv

**Actual Artifacts Found:**
The strongest confirmed staged DLL findings were:

- PID 3092 – `powershell.exe` loaded `amsi.dll` from:
  - `C:\Temp\mff_multi\amsi.dll`

- PID 1676 – `powershell.exe` loaded `amsi.dll` from:
  - `C:\Temp\mff_multi\amsi.dll`

These findings were recorded with:
- Technique: `T1562.001`
- Technique Name: Disable or Modify Tools – AMSI Bypass
- Risk Score: 90

The output explicitly described these as:
- non-System32 DLL loads
- replaced DLL confirmed
- high-confidence AMSI-related defence evasion evidence

**Analytical Interpretation:**
This is the strongest DLL-related evidence in the case. It shows that `powershell.exe` loaded `amsi.dll` from a temporary staging directory rather than the expected System32 location. This strongly supports DLL abuse and AMSI-related evasion behaviour.

### 5.4 RWX / Malfind Artifacts
**Source Files:**
- windows.malfind.csv
- malfind.csv
- scores.csv

**Actual Artifacts Found:**
The Case 05 outputs showed repeated `PAGE_EXECUTE_READWRITE` memory regions associated with `powershell.exe`. The scored findings explicitly referenced:

- `5× PAGE_EXECUTE_READWRITE memory regions`

for multiple critical PowerShell processes.

The cross-case comparison summary reported:
- RWX Regions in Case 05: 42

The raw `windows.malfind.csv` also showed that not every RWX region in memory belonged to the attack process. For example, RWX entries also appeared in `MsMpEng.exe`.

**Analytical Interpretation:**
RWX evidence in `powershell.exe` is highly significant in this case because it is correlated with suspicious PowerShell command lines and staged AMSI DLL loading. However, the presence of RWX alone should not automatically be treated as malicious, because some legitimate Windows processes may also show RWX memory regions. The strongest interpretation therefore comes from correlation, not from isolated malfind output.

### 5.5 ATT&CK Technique Artifacts
**Source Files:**
- attack_tags.csv
- tactic_summary.csv
- threat_summary.json.txt

**Actual Artifacts Found:**
The following ATT&CK techniques were detected in Case 05:

- T1016 – System Network Configuration Discovery
- T1033 – System Owner/User Discovery
- T1055 – Process Injection
- T1057 – Process Discovery
- T1059.001 – PowerShell
- T1082 – System Information Discovery
- T1562.001 – Disable or Modify Tools / AMSI-related evasion
- T1574.001 – DLL Search Order Hijacking

**Observed Tactics:**
- Defense Evasion
- Discovery
- Execution

**Technique Hit Counts from tactic_summary.csv:**
- T1059.001 PowerShell: 17
- T1055 Process Injection: 16
- T1562.001 AMSI Memory Patch: 6
- T1574.001 DLL Search Order Hijacking: 2
- T1562.001 AMSI Bypass: 2
- T1016 System Network Configuration Discovery: 2
- T1033 System Owner/User Discovery: 2
- T1057 Process Discovery: 2
- T1082 System Information Discovery: 2

**Analytical Interpretation:**
Case 05 had the broadest ATT&CK coverage of all completed cases. This confirms that the scenario successfully generated multi-technique evidence rather than remaining limited to one behaviour type.

### 5.6 Scoring Artifacts
**Source Files:**
- scores.csv
- threat_summary.json.txt
- report_forensics.pdf

**Actual Artifacts Found:**
The final outputs classified the case as:
- Overall Severity: CRITICAL
- Critical Processes: 8
- Max Risk Score: 100

Critical high-risk `powershell.exe` processes included:
- PID 4512
- PID 1676
- PID 260
- PID 9508
- PID 3092
- PID 3448
- PID 10128
- PID 2824

The score explanations referenced evidence such as:
- AMSI bypass via memory patching
- 5× PAGE_EXECUTE_READWRITE memory regions
- suspicious command-line patterns
- multiple independent evidence sources

**Analytical Interpretation:**
The scoring output demonstrates the value of evidence correlation. Instead of flagging only one suspicious string or one plugin result, the framework combined multiple findings into a prioritised critical-risk assessment.

### 5.7 IOC Artifacts
**Source Files:**
- iocs.csv
- threat_summary.json.txt

**Actual Artifacts Found:**
Case 05 extracted 59 IOCs. Examples visible in the IOC output included:

- `C:\Temp\mff_multi\case05_rwx_amsi.ps1`
- `C:\Temp\multiattack\powershell.exe`
- `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

**Analytical Interpretation:**
The IOC output is useful for triage, documentation, and appendix material. It also demonstrates that the framework can transform raw forensic findings into a structured list of actionable indicators.

### 5.8 Network Artifacts
**Source Files:**
- windows.netscan.csv
- net_new.csv
- net_flagged.csv

**Actual Artifacts Found:**
The case reported:
- 139 new network connections
- 4 flagged network connections

Examples visible in the network outputs included common system-related entries such as:
- TCP 139 LISTENING
- TCP 135 LISTENING

**Analytical Interpretation:**
The network outputs provide supporting context, but they are not the strongest primary evidence in this case. Some entries likely reflect normal system or virtualised environment activity. For Case 05, the command-line, DLL, and malfind outputs are much stronger than netscan alone.

## 6. Real Correlated Evidence Chain
The strongest forensic interpretation in Case 05 comes from the following real evidence chain:

1. `powershell.exe` executed from a non-standard temporary path  
2. hidden PowerShell used `-ExecutionPolicy Bypass`, `-NoProfile`, and encoded execution  
3. discovery commands were captured in command-line output  
4. `powershell.exe` loaded `amsi.dll` from `C:\Temp\mff_multi\amsi.dll`  
5. `powershell.exe` showed repeated `PAGE_EXECUTE_READWRITE` memory regions  
6. ATT&CK mapping identified Discovery, Execution, and Defense Evasion techniques  
7. multiple `powershell.exe` processes were assigned CRITICAL risk scores

## 7. Analytical Cautions
- Process delta output contains some background noise due to baseline drift
- Network deltas contain benign system activity
- RWX regions should not be treated as malicious in isolation
- The strongest conclusions are the ones supported by multiple evidence classes at the same time

## 8. Case 05 Completion Criteria
Case 05 should be considered technically complete when the following evidence categories all exist and match the findings above:

- raw memory image
- hash integrity record
- raw Volatility outputs
- processed comparison outputs
- ATT&CK mapping outputs
- scoring outputs
- HTML and PDF final reports
- documentation notes for methodology and reporting

