# Memory Artefact Schema (Case 04 — T1574.001 DLL Search Order Hijacking with AMSI Bypass)

## Overview

This section defines the structured artefact schema used by the Memory Forensics Framework (MFF) for analysing Case 04.

The case is centred on **DLL Search Order Hijacking (T1574.001)**, with correlated **PowerShell execution (T1059.001)** and **AMSI bypass / memory patching behaviour (T1562.001)**.

Unlike a pure injection-only case, this schema relies on the correlation of:

- process execution paths,
- staged command lines,
- DLL load paths,
- memory protection anomalies,
- risk scoring,
- and baseline comparison results.

---

# 1. Process Artefact Schema (windows.pslist)

Source Plugin:

windows.pslist

| Field | Description |
|------|-------------|
| PID | Unique process identifier |
| PPID | Parent process identifier |
| ImageFileName | Executable name |
| CreateTime | Process creation timestamp |
| ExitTime | Process termination timestamp |
| SessionId | User or service session |
| DiffStatus | Baseline comparison state |

### Case 04 Findings

Key attack-related processes include:

- `powershell.exe` (PIDs 5844, 1316, 7804, 6764, 5136)
- `mspaint.exe` (PID 8060)

### Interpretation

This schema is used to identify:

- attack-only processes not present in the baseline,
- suspicious recurrence of PowerShell,
- execution of system binaries in non-standard contexts,
- and parent-child relationships relevant to staged execution.

For this case, **PID 5136** and **PID 8060** are the highest-value process artefacts because they link directly to staging directories.

---

# 2. Process Tree Schema (windows.pstree)

Source Plugin:

windows.pstree

| Field | Description |
|------|-------------|
| PID | Child process identifier |
| PPID | Parent process identifier |
| TreeDepth | Process hierarchy depth |
| ImageFileName | Process image |

### Case 04 Findings

The PowerShell processes do not appear as isolated one-off events. Instead, several are linked through suspicious parent-child relationships.

Examples used by the framework include:

- `powershell.exe` PID 5844 spawning PID 7804
- `powershell.exe` PID 7804 spawning PID 6764
- a high-risk lineage linking to `powershell.exe` PID 5136

### Interpretation

This schema supports detection of:

- staged execution,
- chained PowerShell activity,
- and inheritance of risk from suspicious parent processes.

---

# 3. Command-Line Artefact Schema (windows.cmdline)

Source Plugin:

windows.cmdline

| Field | Description |
|------|-------------|
| PID | Process identifier |
| Process | Process name |
| Args | Command-line arguments |
| MatchedPattern | Suspicious keyword or path pattern |

### Case 04 Findings

Observed command-line paths include:

- `"C:\Temp\pshijack\powershell.exe"`
- `"C:\temp\hijack\mspaint.exe"`

Matched patterns include:

- `powershell`
- `\temp\`
- `\hijack\`
- `pshijack`

### Interpretation

This schema is used to detect:

- execution from staging directories,
- misuse of trusted system binaries from non-standard locations,
- and PowerShell invocation supporting ATT&CK execution mapping.

The command-line schema provides the earliest direct indication that the process is operating outside its normal baseline path.

---

# 4. DLL Load Artefact Schema (windows.dlllist)

Source Plugin:

windows.dlllist

| Field | Description |
|------|-------------|
| PID | Process identifier |
| Process | Process name |
| DLL | Loaded DLL name |
| LoadPath | Full loaded module path |
| HijackType | Framework classification |

### Case 04 Findings

Critical DLL anomalies:

- `powershell.exe` (PID 5136) loads `C:\Temp\pshijack\amsi.dll`
- `mspaint.exe` (PID 8060) loads `C:\temp\hijack\VERSION.dll`

Expected protected locations:

- `C:\Windows\System32\amsi.dll`
- `C:\Windows\System32\version.dll`

### Interpretation

This is the core schema for **T1574.001** detection.

The framework flags DLL loads where:

- a protected Windows DLL is loaded from a user-writable or staging path,
- a system executable loads a DLL from its executable directory instead of System32,
- or the DLL path is inconsistent with baseline system behaviour.

Framework labels observed in this case include:

- `PROTECTED_DLL_USER_DIR`
- `AMSI_FILE_OUTPUT_DISABLED`
- `SYSTEM_EXE_FROM_WRONG_DIR`

---

# 5. Memory Region Artefact Schema (windows.malware.malfind)

Source Plugin:

windows.malware.malfind

| Field | Description |
|------|-------------|
| PID | Process identifier |
| Process | Process name |
| Start VPN | Start address of suspicious region |
| End VPN | End address of suspicious region |
| Tag | VAD tag |
| Protection | Memory protection flags |
| PrivateMemory | Whether private memory is present |

### Case 04 Findings

PowerShell processes with RWX regions include:

- PID 1316 — 5 regions
- PID 5844 — 2 regions
- PID 6764 — 5 regions
- PID 7804 — 5 regions
- PID 5136 — 5 regions

Protection observed:

- `PAGE_EXECUTE_READWRITE`

### Interpretation

This schema supports detection of:

- in-memory code staging,
- AMSI patching behaviour,
- and suspicious writable + executable memory.

RWX memory alone is not treated as conclusive. The framework only elevates it strongly when it is correlated with DLL and command-line evidence in the same PID.

---

# 6. Thread Artefact Schema (windows.threads)

Source Plugin:

windows.threads

| Field | Description |
|------|-------------|
| PID | Process identifier |
| TID | Thread identifier |
| StartAddress | Thread start address |
| State | Thread state |

### Interpretation

In this case, thread data is used as supporting context rather than the primary detection source. It can strengthen conclusions when suspicious threads execute within or near modified memory regions, but the decisive evidence in Case 04 comes from command-line, DLL, and malfind correlation.

---

# 7. Network Artefact Schema (windows.netscan)

Source Plugin:

windows.netscan

| Field | Description |
|------|-------------|
| LocalAddr | Local address |
| LocalPort | Local port |
| ForeignAddr | Remote address |
| ForeignPort | Remote port |
| State | Socket state |
| PID | Owning process |
| Owner | Owning process name |

### Case 04 Findings

The framework recorded:

- 94 new network connections
- 3 flagged connections

Flagged items relate to `svchost.exe` listening on TCP port 135.

### Interpretation

This schema is retained for completeness, but the network evidence is not the primary basis for detection in this case. Case 04 is predominantly a local execution and DLL loading attack pattern rather than a network-centric intrusion pattern.

---

# 8. ATT&CK Tagging Schema (Framework Generated)

| Field | Description |
|------|-------------|
| PID | Process identifier |
| Process | Process name |
| MatchedText | Artifact text that triggered mapping |
| MatchedKeyword | Detection keyword |
| Tactic | ATT&CK tactic |
| Technique | ATT&CK technique ID |
| TechniqueName | ATT&CK technique name |

### Case 04 Findings

The framework mapped:

- `powershell.exe` → **T1059.001 PowerShell**
- `amsi.dll` + PowerShell evidence → **T1562.001 Disable or Modify Tools / AMSI Bypass**
- `C:\Temp\pshijack\amsi.dll` and `C:\temp\hijack\VERSION.dll` → **T1574.001 DLL Search Order Hijacking**

### Interpretation

This schema translates raw artefacts into analyst-readable adversary behaviour. It allows the framework to explain not just what was found, but what the behaviour means in ATT&CK terms.

---

# 9. Risk Scoring Artefact Schema (Framework Generated)

| Field | Description |
|------|-------------|
| PID | Process identifier |
| Process | Process name |
| RiskScore | Numerical score |
| RiskLevel | Severity class |
| Confidence | Analyst confidence statement |
| EvidenceCount | Number of corroborating evidence sources |
| PrimaryTechnique | Main ATT&CK technique |
| Indicators | Short evidence summary |
| IndicatorsFull | Expanded rule-based explanation |

### Case 04 Findings

Highest-priority processes include:

- `powershell.exe` (PID 5136) — Risk Score **100**
- `mspaint.exe` (PID 8060) — Risk Score **100**
- `powershell.exe` (PID 5844) — Risk Score **100**
- `powershell.exe` (PID 7804) — Risk Score **100**
- `powershell.exe` (PID 6764) — Risk Score **100**

### Interpretation

The scoring schema prioritises processes that exhibit **multiple independent evidence sources**. In Case 04, the most important combined indicators are:

- staging-path execution,
- protected DLL loads from staging directories,
- multiple RWX memory regions,
- suspicious command-line patterns,
- and suspicious parent-child inheritance.

This makes the risk model explainable and defensible in an academic forensic context.

---

# 10. Baseline Comparison Schema

| Field | Description |
|------|-------------|
| PID | Process identifier |
| ImageFileName | Process name |
| DiffStatus | Baseline comparison result |
| CreateTime | Process creation time |

### Case 04 Findings

Attack-only examples:

- `powershell.exe` (PID 5844)
- `powershell.exe` (PID 1316)
- `mspaint.exe` (PID 8060)
- `powershell.exe` (PID 7804)
- `powershell.exe` (PID 6764)

### Interpretation

This schema is critical because it distinguishes:

- normal Windows behaviour already present in the clean image,
- from new attack-introduced processes and anomalies.

For Case 04, the comparison confirms that the suspicious staged processes are not simply routine system activity.

---

# Summary

The Case 04 artefact schema captures a **correlated defense-evasion workflow** involving:

- execution of trusted binaries from staging directories,
- loading of protected DLLs from non-System32 locations,
- repeated PowerShell activity,
- AMSI-related DLL correlation,
- multiple PAGE_EXECUTE_READWRITE memory regions,
- and attack-only processes absent from the baseline.

By combining these artefacts, the Memory Forensics Framework can detect and explain:

- **T1059.001 — PowerShell**
- **T1562.001 — Disable or Modify Tools / AMSI Bypass**
- **T1574.001 — DLL Search Order Hijacking**

This schema is therefore not just a list of fields. It is the structured detection model that enables Case 04 to be interpreted as a high-confidence malicious scenario rather than an isolated collection of raw plugin outputs.
