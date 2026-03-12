# Case 03 — Artefact Analysis (T1059 Command Execution)

## Overview

This analysis investigates memory artefacts generated during a simulated command execution attack using the Atomic Red Team framework.

The attack emulates MITRE ATT&CK technique:

T1059 – Command and Scripting Interpreter

A memory snapshot was captured after the attack and compared against a baseline system state using the Memory Forensics Framework (MFF).

Baseline dataset:

case01_baseline

Attack dataset:

case03_t1059_attack

The framework automatically compared both datasets and generated artefact findings using Volatility plugin outputs.

---

# Dataset Processing Pipeline

Memory acquisition:

VBoxManage debugvm "Windows 10" dumpvmcore

Volatility extraction plugins:

windows.pslist  
windows.cmdline  
windows.malware.malfind  
windows.netscan

These outputs were exported to structured datasets and processed using the MFF comparison engine.

The comparison engine performs:

Baseline comparison  
Artefact detection  
Risk scoring  
Visualization generation

---

# New Artefacts Identified

The framework detected **143 processes that were not present in the baseline memory snapshot**.

Examples include:

powershell.exe  
notepad.exe  

These processes were generated during the execution of the Atomic Red Team T1059 simulation.

PowerShell is a known attack tool frequently used for command execution and scripting-based attacks.

---

# Command Execution Evidence

Command-line analysis revealed suspicious command execution patterns.

Example process:

powershell.exe

The framework detected this process using the Volatility plugin:

windows.cmdline

These artefacts indicate the use of PowerShell as a command interpreter during the simulated attack.

This behaviour directly corresponds to:

MITRE ATT&CK T1059

---

# Memory Injection Indicators

The Volatility plugin `windows.malware.malfind` identified executable memory regions with the protection flag:

PAGE_EXECUTE_READWRITE

RWX memory permissions indicate memory regions that are:

Readable  
Writable  
Executable  

Such memory regions are often associated with:

Shellcode execution  
Reflective DLL injection  
Fileless malware

The presence of RWX memory regions within PowerShell processes suggests in-memory execution of malicious code.

---

# Risk Scoring Results

The framework applies rule-based scoring to identify high-risk processes.

Example:

Process: powershell.exe  
PID: 7888  

Risk Score: 150  
Risk Level: CRITICAL  

Indicators detected:

Suspicious command line  
RWX memory region  
Injection-related process behaviour

This combination strongly indicates malicious execution activity.

---

# Baseline Comparison Findings

The comparison engine identified several differences between the baseline and attack memory images.

Attack system state produced:

143 new processes  
131 processes missing compared to baseline

These differences demonstrate how system behaviour changes during attack execution.

Baseline comparison is critical because it reduces false positives and highlights anomalous artefacts introduced by the attack.

---

# MITRE ATT&CK Techniques Observed

The framework correlated artefacts with multiple ATT&CK techniques.

Execution:

T1059 — Command and Scripting Interpreter

Defense Evasion:

T1036 — Masquerading

Credential Access indicators were also detected through interactions with the LSASS process.

---

# Indicators of Compromise

The framework extracted several indicators of compromise from memory artefacts.

Examples include:

C:\Windows\System32\svchost.exe  
C:\Windows\System32\RuntimeBroker.exe  

These indicators were extracted from command-line and process artefacts.

---

# Framework Contribution

The Memory Forensics Framework introduces automated post-processing of Volatility plugin outputs.

Key capabilities include:

Baseline-aware artefact detection  
Risk scoring engine  
MITRE ATT&CK mapping  
Automated visualisation dashboards  
HTML forensic reporting

This approach transforms raw memory artefacts into structured forensic intelligence.

---

# Conclusion

The framework successfully identified artefacts associated with the simulated command execution attack.

The analysis revealed:

PowerShell process execution  
Executable RWX memory regions  
Command-line artefacts  
Anomalous processes not present in the baseline system

These findings confirm the effectiveness of the framework in detecting memory-based attack activity.
