# Case 02 — T1055-5 Process Injection (RWX Memory) — Forensic Case Report

## 1. Objective

Capture and validate a controlled, ethical simulation of **MITRE ATT&CK T1055 (Process Injection)** using Atomic Red Team, then identify **in-memory injection artifacts** using Volatility 3 for later automation and baseline comparison.

## 2. Evidence Summary

- **Evidence File:** `t1055_5_attack.raw`
- **Case Path:** `/cases/case02_t1055_5_attack/`
- **SHA256:** `85e4b855c6b625f79a18982bf5aa98df62801517e65c4887cc5e218675e47db8`
- **Acquisition:** VirtualBox hypervisor memory dump (`VBoxManage dumpvmcore`)
- **Volatility:** 3 Framework 2.28.0

## 3. What T1055-5 Means (Technical Explanation)

**Process Injection (T1055)** is a technique where an attacker executes code within the address space of another process to:

- evade detection,
- inherit permissions of the target process,
- blend into legitimate process activity.

A typical injection flow includes:

1. A helper process runs (injector / loader).
2. A target process is created or selected.
3. Memory is allocated in the target (often RWX or RW → RX transition).
4. Payload bytes are written into that memory.
5. Execution is redirected (commonly via remote thread creation or APC or similar).

In this case, the Atomic simulation produced the key hallmark:

- **RWX memory regions inside a target process** consistent with injected/staged code.

## 4. Timeline and Correlation (From Process Listings)

### Key event window

At **2026-02-18 00:55:10 UTC**, the following correlated chain is observed:

- `RWXinjectionLocal.exe` (**PID 2184**) executed from:
  `\Device\HarddiskVolume2\AtomicRedTeam\atomics\T1055\bin\x64\RWXinjectionLocal.exe`  
  - CreateTime: **2026-02-18 00:55:10 UTC**  
  - ExitTime: **2026-02-18 00:55:16 UTC**

- `powershell.exe` (**PID 7764**, **PPID 2184**) created immediately after:
  `\Device\HarddiskVolume2\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

- `conhost.exe` (**PID 4964**, **PPID 7764**) created as the console host:
  `\Device\HarddiskVolume2\Windows\System32\conhost.exe`

**Interpretation:**

- The injector/helper process is short-lived (typical loader behavior).
- The spawned PowerShell process is the correlated target process in the chain.
- The dump captured during this window preserves artifacts before cleanup.

## 5. Injection Artifacts (Malfind)

Volatility `windows.malware.malfind` identifies **PAGE_EXECUTE_READWRITE (RWX)** memory regions inside:

- `powershell.exe` (**PID 7764**)

RWX memory in a user process is a high-signal indicator for injection/staging because:

- Legitimate code pages are usually **RX** (execute-read) in normal operation.
- RWX pages are commonly created temporarily for payload staging/execution.
- The finding aligns with the exact time window of the Atomic injector execution.

**Forensic conclusion:**  
The correlation between:

- the **injector process** (`RWXinjectionLocal.exe`),
- the **target process** (`powershell.exe` PID 7764),
- and **RWX memory** detected in that target
is consistent with a successful T1055 process injection simulation.

## 6. Artefacts Generated (Exports for Automation)

CSV exports (prepared for automated parsing and comparison vs baseline):

- `windows.cmdline.csv`
- `windows.dlllist.csv`
- `windows.malfind.csv`
- `windows.netscan.csv`

## 7. Case Conclusion

This capture is a **valid, clean T1055 injection case**:

- The Atomic test executed successfully (injector observed, correct path, correct timing).
- The injection artifacts are present in memory (malfind detects RWX in PowerShell).
- Integrity is verified with matching SHA256 on host and Kali.
- Suitable for baseline-vs-attack differential analysis and automated detection pipeline development.
