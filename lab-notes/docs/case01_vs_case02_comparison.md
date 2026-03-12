# Case Comparison Report  

## Case 01 (Baseline) vs Case 02 (T1055-5 RWX Injection)

Author: Anton  
Date: 18 February 2026  
Project: Memory Forensics Framework  
Technique: MITRE ATT&CK T1055-5 — Process Injection (RWX Memory Allocation)

---

## 1. Evidence Overview

## Case 01 — Baseline

File: baseline.raw  
Purpose: Clean system reference  
SHA256: 4fbc8ddf2cdcdd187e5d74f66ab4c1c2d5fffe2753b34c870015d4ea055aa432  

No adversary activity executed.  
Used as behavioural reference dataset.

---

## Case 02 — T1055-5 Attack

File: t1055_5_attack.raw  
SHA256: 85e4b855c6b625f79a18982bf5aa98df62801517e65c4887cc5e218675e47db8  

Technique executed via Atomic Red Team.  
Memory captured immediately after injection execution.  
No cleanup performed prior to dump.

---

## 2. Process-Level Comparison

## 2.1 Baseline (Case 01)

Observed processes:

- System
- smss.exe
- csrss.exe
- services.exe
- lsass.exe
- explorer.exe
- Standard svchost.exe instances

No:

- RWXinjectionLocal.exe
- Suspicious PowerShell execution
- Abnormal parent-child relationships

Process tree consistent with standard Windows boot behaviour.

---

## 2.2 Attack Case (Case 02)

New processes identified:

| PID  | PPID | Process Name             | Notes |
|------|------|--------------------------|-------|
| 2184 | 9076 | RWXinjectionLocal.exe    | Injector binary |
| 7764 | 2184 | powershell.exe           | Injected target |
| 4964 | 7764 | conhost.exe              | Console host |

Key Observation:

RWXinjectionLocal.exe → spawned powershell.exe  
powershell.exe → spawned conhost.exe  

This parent-child chain does NOT exist in baseline.

---

## 3. Command-Line Evidence

From windows.cmdline:

powershell.exe executed with:

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  
-Command "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Atomic Red Team','Warning','OK','Warning'); Start-Process 'notepad.exe'"

This confirms:

- Atomic Red Team execution
- Script-based execution path
- Execution redirection behaviour

No similar PowerShell invocation exists in baseline.

---

## 4. Injection Artefact — Memory-Level Evidence

## Malfind Results — Case 02

Multiple RWX (PAGE_EXECUTE_READWRITE) regions detected in:

PID 7764 — powershell.exe

Protection:
PAGE_EXECUTE_READWRITE

Indicators:

- RWX memory allocation
- Shellcode-like assembly
- Jump redirection instructions
- Executable non-image memory region

Example:
Function prologue patterns  
Jump-to-address instructions  
Memory regions not mapped to legitimate modules

These artefacts were NOT present in baseline.

---

## 5. Correlation Analysis

Timeline:

2184 RWXinjectionLocal.exe created  
→ 7764 powershell.exe spawned  
→ RWX memory allocated  
→ Shellcode execution region identified  
→ Memory dump captured  
→ Injector exited (ExitTime observed)

Correlation confirms:

✔ Remote thread injection executed  
✔ RWX memory allocation succeeded  
✔ Execution redirection occurred  
✔ Dump captured during active injection window  
✔ Evidence preserved before cleanup  

---

# 6. Baseline vs Attack Differential

| Artefact Type | Case 01 | Case 02 |
|---------------|---------|---------|
| Injector Binary | ❌ | ✔ |
| Suspicious PowerShell | ❌ | ✔ |
| Abnormal PPID Chain | ❌ | ✔ |
| RWX Memory Regions | ❌ | ✔ |
| Shellcode Patterns | ❌ | ✔ |
| Injection Behaviour | ❌ | ✔ |

---

## 7. ATT&CK Mapping

Technique: T1055-5  
Name: Process Injection — RWX Memory  

Behaviour Observed:

- VirtualAllocEx-like allocation
- PAGE_EXECUTE_READWRITE memory
- Remote thread execution
- Execution inside legitimate process (PowerShell)

This is a textbook implementation of T1055-5.

---

## 8. Forensic Conclusion

Case 01 confirms clean baseline behaviour.

Case 02 demonstrates confirmed process injection via RWX memory allocation, with:

- Verified injector binary
- Confirmed child PowerShell process
- Confirmed RWX memory regions
- Confirmed execution artefacts
- No evidence of cleanup prior to capture

The acquisition timing was correct.

This constitutes a valid forensic capture of T1055-5 process injection.

---

## 9. Framework Impact

This comparison validates:

✔ Baseline behavioural modelling works  
✔ Injection detection logic is reproducible  
✔ Malfind-based RWX detection is reliable  
✔ Parent-child correlation improves confidence  
✔ Structured JSON export supports automation  

This case is suitable for automated detection rule development in Week 3.
