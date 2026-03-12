# Case Report

## Case03 — PowerShell Execution Attack (MITRE ATT&CK T1059)

---

# Overview

This case analyses a **memory dump captured after executing an Atomic Red Team simulation of MITRE ATT&CK technique T1059**.

Technique T1059 represents the abuse of scripting interpreters such as:

• PowerShell
• CMD
• Python
• Bash

Attackers frequently use these interpreters to execute malicious commands directly in memory.

The objective of this case is to determine whether the execution artifacts can be recovered from RAM.

---

# Evidence Source

Memory Image

```
/MFF/cases/case03_t1059_attack/case03_t1059_attack.raw
```

---

# Volatility Analysis

The following Volatility plugins were executed.

---

# System Information

Command

```
python vol.py -q -f /MFF/cases/case03_t1059_attack/case03_t1059_attack.raw windows.info -r jsonl
```

Purpose

Identify OS version, kernel profile, and system configuration.

---

# Process Enumeration

Command

```
python vol.py -q -f /MFF/cases/case03_t1059_attack/case03_t1059_attack.raw windows.pslist -r jsonl
```

Key Observation

Multiple PowerShell processes were identified.

Example artifact

```
powershell.exe PID 7888
Parent PID 6016
```

---

# Process Tree Reconstruction

Command

```
python vol.py -q -f /MFF/cases/case03_t1059_attack/case03_t1059_attack.raw windows.pstree -r jsonl
```

Key hierarchy observed

```
winlogon.exe
 └ userinit.exe
     └ explorer.exe
         └ powershell.exe
```

This confirms the PowerShell session originated from a user environment.

---

# Command Line Artifacts

Command

```
python vol.py -q -f /MFF/cases/case03_t1059_attack/case03_t1059_attack.raw windows.cmdline -r jsonl
```

Recovered process arguments

```
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
```

This confirms the scripting interpreter execution.

---

# Malicious Memory Regions

Command

```
python vol.py -q -f /MFF/cases/case03_t1059_attack/case03_t1059_attack.raw windows.malware.malfind -r jsonl
```

Malfind detected **executable memory regions inside powershell.exe**.

Example finding

```
Process: powershell.exe
Protection: PAGE_EXECUTE_READWRITE
PrivateMemory: true
```

RWX memory is commonly associated with:

• shellcode execution
• in-memory payloads
• reflective injection

---

# Network Activity

Command

```
python vol.py -q -f /MFF/cases/case03_t1059_attack/case03_t1059_attack.raw windows.netscan -r jsonl
```

Network connections identified include:

```
TCP connections to external IP addresses
UDP system services
Windows background services
```

These connections indicate normal OS activity but demonstrate the ability to correlate process activity with network artifacts.

---

# Key Indicators

Recovered artifacts confirm:

• PowerShell interpreter execution
• Multiple child PowerShell processes
• RWX memory regions detected
• Process tree showing user execution context

These indicators are consistent with **MITRE ATT&CK technique T1059 behaviour**.

---

# Conclusion

Memory forensics analysis successfully recovered indicators of scripting interpreter abuse.

The case demonstrates that volatile memory analysis can reveal:

• interpreter activity
• execution hierarchy
• injected memory regions
• associated network connections

These artifacts provide strong evidence of PowerShell based execution within the investigated system.

## Most Important Evidence from Week-3

From your dataset we confirmed:

Evidence 1
Multiple PowerShell processes
Evidence 2
Explorer → PowerShell process chain
Evidence 3
PowerShell spawning additional processes
Evidence 4
Executable RWX memory regions in PowerShell