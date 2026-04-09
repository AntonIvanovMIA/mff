# Case 04 — Artefact Analysis (T1574.001 DLL Search Order Hijacking with AMSI Bypass Indicators)

## Overview

This case analyses a controlled memory-forensic capture of **DLL Search Order Hijacking (MITRE ATT&CK T1574.001)** with correlated **PowerShell execution (T1059.001)** and strong **AMSI bypass / memory patching indicators (T1562.001)**.

The attack dataset was compared against the trusted baseline dataset using the Memory Forensics Framework (MFF). The resulting analysis identified a critical multi-stage attack pattern involving:

- execution of PowerShell from a staging directory,
- loading of protected DLLs from non-System32 paths,
- multiple PAGE_EXECUTE_READWRITE memory regions in PowerShell processes,
- attack-only processes absent from the baseline capture,
- and a clear defense-evasion chain combining DLL hijacking and AMSI tampering.

Baseline dataset:

case01_baseline

Attack dataset:

case04_t1574_attack

According to the generated forensic report, the comparison produced:

- **15 new processes (attack only)**
- **16 processes missing compared to baseline**
- **94 new network connections**
- **3 flagged network connections**
- **49 extracted indicators of compromise**
- **3 ATT&CK techniques across 2 tactics**
- **6 critical-risk processes**

These results support a final case severity of:

**CRITICAL**

---

# Dataset Processing Pipeline

Memory acquisition:

VBoxManage debugvm "Windows 10" dumpvmcore

Primary Volatility plugins used:

windows.pslist  
windows.pstree  
windows.cmdline  
windows.dlllist  
windows.malware.malfind  
windows.threads  
windows.netscan  

Framework processing stages:

- baseline comparison
- suspicious command-line detection
- DLL path correlation
- RWX memory analysis
- IOC extraction
- MITRE ATT&CK tagging
- risk scoring
- HTML and PDF reporting

---

# Executive Findings

The strongest findings in this case centre on two staged execution paths:

- `C:\Temp\pshijack\powershell.exe`
- `C:\temp\hijack\mspaint.exe`

The framework identified the following high-confidence artifacts:

1. `powershell.exe` (**PID 5136**) executed from `C:\Temp\pshijack\powershell.exe`
2. The same process loaded `amsi.dll` from `C:\Temp\pshijack\amsi.dll` instead of `C:\Windows\System32\amsi.dll`
3. `powershell.exe` (**PID 5136**) also contained **5 PAGE_EXECUTE_READWRITE memory regions**
4. `mspaint.exe` (**PID 8060**) executed from `C:\temp\hijack\mspaint.exe`
5. `mspaint.exe` (**PID 8060**) loaded `version.dll` from `C:\temp\hijack\VERSION.dll`
6. Several additional PowerShell processes (**PIDs 1316, 5844, 6764, 7804**) loaded `amsi.dll` and exhibited multiple RWX memory regions, producing a repeated AMSI-bypass pattern

This produces a multi-layered case in which:

- **T1574.001** explains the DLL path hijacking,
- **T1562.001** explains the AMSI bypass / modification pattern,
- **T1059.001** explains the PowerShell execution behaviour.

---

# Process Delta Analysis

Baseline comparison identified **15 new processes** that were not present in the baseline snapshot.

Attack-only examples include:

- `powershell.exe` (**PID 5844**) — CreateTime: `2026-04-08 18:55:14 UTC`
- `powershell.exe` (**PID 1316**) — CreateTime: `2026-04-09 02:18:41 UTC`
- `mspaint.exe` (**PID 8060**) — CreateTime: `2026-04-09 02:34:48 UTC`
- `powershell.exe` (**PID 7804**) — CreateTime: `2026-04-09 02:39:16 UTC`
- `powershell.exe` (**PID 6764**) — CreateTime: `2026-04-09 02:39:42 UTC`
- `WmiPrvSE.exe` (**PID 9124**) — CreateTime: `2026-04-09 02:46:13 UTC`

### Interpretation

These attack-only processes are important because they do not exist in the clean system reference model. Their appearance after staging activity provides strong evidence that the abnormal behaviour was introduced during the attack sequence rather than being part of normal Windows operation.

The framework also recorded **16 baseline-only processes** as missing in the attack image. Many of these belong to normal workload differences such as Edge and update-related activity, which reinforces the value of baseline comparison for separating attack artifacts from ordinary environmental drift.

---

# Command-Line Analysis

The command-line findings identify two especially important staging paths:

- `"C:\Temp\pshijack\powershell.exe"`
- `"C:\temp\hijack\mspaint.exe"`

Matched patterns include:

- `powershell`
- `\temp\`
- `\hijack\`
- `pshijack`

### Key Findings

- `powershell.exe` (**PID 5136**) was executed from a non-standard staging folder rather than the normal System32 path
- `mspaint.exe` (**PID 8060**) was executed from a hijack staging directory
- Multiple other PowerShell processes were also observed, supporting a chain of repeated script-based execution events

### Interpretation

This behaviour is not consistent with the baseline system profile. Execution of trusted Windows binaries from attacker-controlled or staging directories is a classic indicator of search-order abuse and defense-evasion staging.

The command-line evidence also supports:

**T1059.001 — PowerShell**

because multiple PowerShell instances were invoked and persisted during the attack window.

---

# DLL Hijacking Analysis

DLL analysis is the strongest evidence source in this case.

## Primary DLL Hijack Finding

Process:

`powershell.exe` (**PID 5136**)

Loaded DLL:

`C:\Temp\pshijack\amsi.dll`

Expected location:

`C:\Windows\System32\amsi.dll`

### Interpretation

This is a high-confidence **DLL Search Order Hijacking** artifact. A protected system DLL was loaded from a staging directory instead of System32. This is precisely the behaviour expected in:

**T1574.001 — DLL Search Order Hijacking**

The framework classified this as:

- `PROTECTED_DLL_USER_DIR`
- `AMSI_FILE_OUTPUT_DISABLED`

The latter is especially important because it indicates that the loaded `amsi.dll` from the staging directory could not be normally dumped as a standard system-backed module, further strengthening the conclusion that replacement or hijack occurred.

## Secondary DLL Hijack Finding

Process:

`mspaint.exe` (**PID 8060**)

Loaded DLL:

`C:\temp\hijack\VERSION.dll`

Executable path:

`C:\temp\hijack\mspaint.exe`

### Interpretation

This is another clear DLL search-order hijack pattern:

- a Windows executable was launched from a staging directory,
- the executable loaded a protected DLL from the same attacker-controlled directory,
- and the loaded DLL path deviates from the expected protected system location.

This confirms that the case contains not just one isolated DLL anomaly, but a repeated pattern of hijack-oriented staging behaviour.

---

# AMSI Bypass and RWX Memory Analysis

The framework correlated `dlllist` and `malfind` results to identify **AMSI bypass via memory patching**.

## High-Confidence AMSI Memory Patch Pattern

The following PowerShell processes loaded `amsi.dll` and also contained RWX memory regions:

- `powershell.exe` (**PID 1316**) — **5 RWX regions**
- `powershell.exe` (**PID 5844**) — **2 RWX regions**
- `powershell.exe` (**PID 6764**) — **5 RWX regions**
- `powershell.exe` (**PID 7804**) — **5 RWX regions**
- `powershell.exe` (**PID 5136**) — **5 RWX regions**

### Interpretation

This repeated combination is highly significant:

- `amsi.dll` present in PowerShell
- PAGE_EXECUTE_READWRITE regions present in the same process
- suspicious PowerShell execution behaviour already established by cmdline analysis

This is consistent with:

**T1562.001 — Disable or Modify Tools (AMSI Memory Patch / AMSI Bypass)**

RWX memory alone is not definitive proof of malicious code. However, when combined with AMSI-related DLL evidence and suspicious execution paths, the pattern becomes highly persuasive from a forensic perspective.

For **PID 5136**, the evidence is particularly strong because it combines:

- local execution from `C:\Temp\pshijack\powershell.exe`
- local loading of `C:\Temp\pshijack\amsi.dll`
- **5 RWX memory regions**

This makes PID 5136 the most important process in the case.

---

# Process Chain and Staged Execution

Risk scoring indicates that the PowerShell processes are not isolated. Instead, they form a staged process chain:

- `powershell.exe` (**PID 5844**) spawned **PID 7804**
- `powershell.exe` (**PID 7804**) spawned **PID 6764**
- `powershell.exe` (**PID 1316**) is linked as the parent of **PID 5136** in framework scoring logic

### Interpretation

This parent-child pattern supports a multi-step attack sequence rather than a single benign PowerShell invocation. The framework therefore treats the later processes as higher-confidence malicious descendants because they inherit suspicious ancestry in addition to their own DLL and memory indicators.

---

# Risk Scoring Results

The case produced **6 CRITICAL** processes according to the generated report.

Most important scored processes include:

## `powershell.exe` (PID 5136)

Risk Score: **100**  
Risk Level: **CRITICAL**

Key indicators:

- AMSI DLL replaced from staging path
- Execution from staging / non-standard path
- 5 PAGE_EXECUTE_READWRITE memory regions
- Cmdline staging patterns: `powershell`, `\temp\`, `pshijack`
- Spawned by high-risk parent

## `mspaint.exe` (PID 8060)

Risk Score: **100**  
Risk Level: **CRITICAL**

Key indicators:

- Protected DLL from staging directory
- Execution from staging / non-standard path
- Cmdline staging path patterns: `\temp\`, `\hijack\`
- System executable executed from non-System32 path

## Additional Critical PowerShell Processes

- PID 5844 — Risk Score **100**
- PID 7804 — Risk Score **100**
- PID 6764 — Risk Score **100**
- PID 1316 — Critical by report-wide severity distribution and AMSI + RWX correlation

### Interpretation

The scoring engine correctly prioritised processes that had **multiple corroborating evidence sources** rather than relying on any single weak indicator.

---

# Network Findings

The comparison identified:

- **94 new network connections**
- **3 flagged connections**

The flagged items are all associated with `svchost.exe` listening on port **135** (`DCOM/RPC`).

### Interpretation

These network findings do not represent the primary attack mechanism in this case. They are useful contextual artifacts but are weaker than the process, DLL, and malfind evidence.

The strongest attack logic remains local execution, DLL hijacking, and AMSI modification.

---

# Indicators of Compromise

The most important case-specific indicators are:

- `C:\Temp\pshijack\powershell.exe`
- `C:\Temp\pshijack\amsi.dll`
- `C:\temp\hijack\mspaint.exe`
- `C:\temp\hijack\VERSION.dll`
- `powershell.exe` with repeated RWX memory regions

These artifacts are substantially more probative than generic high-frequency Windows paths in the broader IOC export.

---

# MITRE ATT&CK Mapping

The framework identified the following techniques:

## Execution

**T1059.001 — PowerShell**

Observed in multiple PowerShell processes:

- PID 5844
- PID 1316
- PID 7804
- PID 6764
- PID 5136

## Defense Evasion

**T1562.001 — Disable or Modify Tools / AMSI Bypass**

Observed where PowerShell processes load `amsi.dll` and exhibit RWX memory regions.

**T1574.001 — DLL Search Order Hijacking**

Observed where:

- `powershell.exe` (**PID 5136**) loads `C:\Temp\pshijack\amsi.dll`
- `mspaint.exe` (**PID 8060**) loads `C:\temp\hijack\VERSION.dll`

---

# Conclusion

This case represents a **valid, high-confidence defense-evasion scenario** with strong forensic support for both:

- **DLL Search Order Hijacking (T1574.001)**
- **AMSI bypass / modification behaviour (T1562.001)**

The most important forensic artifact is:

`powershell.exe` (**PID 5136**) executing from `C:\Temp\pshijack\powershell.exe` while loading `C:\Temp\pshijack\amsi.dll` and exhibiting **5 RWX memory regions**.

This process alone provides:

- path anomaly,
- protected DLL anomaly,
- in-memory execution anomaly,
- attack-only baseline deviation,
- and ATT&CK-aligned defense-evasion behaviour.

The additional `mspaint.exe` / `version.dll` hijack finding strengthens the case by showing repeated DLL search-order abuse using a second staging path.

Overall, the Memory Forensics Framework successfully transformed raw Volatility outputs into structured, explainable forensic intelligence and correctly elevated the case to:

**CRITICAL severity**
