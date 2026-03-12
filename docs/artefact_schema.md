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
