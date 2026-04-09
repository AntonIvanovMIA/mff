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

---
