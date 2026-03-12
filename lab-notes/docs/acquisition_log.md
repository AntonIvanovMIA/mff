# Memory Acquisition Log

## Case 01 — Baseline (Clean)

- Date: 09 Feb 2026
- VM: "Windows 10" (VirtualBox)
- Acquisition method: VirtualBox hypervisor memory dump (dumpvmcore)
- Reason: Driver-based acquisition (WinPmem) failed due to host hypervisor/security stack constraints (kernel driver could not start).

## — Baseline Evidence Validation (Analysis  Kali VM)

Evidence was copied from the shared transfer directory into an isolated forensic workspace prior to analysis.

Commands executed:

cp /media/sf_shared/baseline.raw /cases/case01_baseline/
sha256sum /cases/case01_baseline/baseline.raw

SHA256 Result:
4fbc8ddf2cddd187e5d74f66ab4c1c2d5fffe2753b34c870015d4ea055aa432

The computed hash matched the acquisition hash generated on the host system, confirming evidence integrity and successful transfer.

No analysis was performed on the shared folder. All forensic analysis is conducted exclusively on isolated case copies.

### Command (Host)

VBoxManage debugvm "Windows 10" dumpvmcore --filename "...\shared\baseline.raw"

### Output

- File: baseline.raw
- Location: shared\baseline.raw
- Size: ~4.56 GB

### Acquire baseline memory (host)

VBoxManage debugvm "Windows 10" dumpvmcore --filename "D:\2.ROEHAMPTON\Final year\FYPROJECT\Memory forensics framework tools for analyse and visualisation\shared\baseline.raw"

### Volatility Validation — Baseline Memory

The baseline memory image was validated using Volatility 3 to confirm structural integrity and operating system identification.

Command executed:

python vol.py -f /cases/case01_baseline/baseline.raw windows.info

Results confirmed:

- Windows 10 kernel successfully identified
- Symbol resolution completed
- Memory layer translation constructed
- Image suitable for forensic analysis

This confirms that the acquisition, transfer, and validation pipeline is operational and reproducible.

### Volatility Baseline Artefact Extraction

Date: 09 Feb 2026

Following integrity validation of the baseline memory image, structured forensic artefact extraction was performed using Volatility 3.

Analysis Environment:

- Platform: Kali Linux VM
- Tool: Volatility 3 Framework
- Execution Mode: Python virtual environment

Evidence Location:
/cases/case01_baseline/baseline.raw

Export Formats:

- JSONL (machine-readable for Python framework processing)
- CSV (tabular format for manual inspection)

Plugins Executed:

- windows.info
- windows.pslist
- windows.pstree
- windows.cmdline
- windows.dlllist
- windows.malfind
- windows.netscan

Methodology:
Volatility 3 requires single-plugin execution per command. Each artefact was exported using structured renderers.

Example Command:
python vol.py -q -f /cases/case01_baseline/baseline.raw -r jsonl windows.pslist > /cases/case01_baseline/exports/jsonl/windows.pslist.jsonl

Integrity Assurance:
Analysis was performed on verified evidence copy stored inside isolated case workspace.

No modifications were made to original acquisition file.

### Additional Baseline Artefact Behaviour Profiling

Following successful Volatility export generation, baseline artefact profiling was conducted.

The purpose of this stage was to establish reference behavioural characteristics of a clean Windows 10 system in volatile memory.

Observed Baseline Indicators:

Process Behaviour:
Core Windows processes including System, smss.exe, csrss.exe, services.exe and explorer.exe were identified. Process parent-child relationships aligned with expected OS boot sequence.

Execution Behaviour:
Command-line analysis confirmed expected system service execution patterns with no anomalous command injection behaviour.

Network Behaviour:
Network socket analysis identified only standard local and service-based network communication with no suspicious external connections.

Memory Injection Indicators:
Memory scanning using malfind revealed no suspicious RWX memory regions, confirming clean baseline injection state.

These observations form the reference dataset for later comparative attack memory analysis.

### Rationale

Kernel-level acquisition tools (e.g. WinPmem) could not be used reliably
due to hypervisor and host security constraints.
Hypervisor-assisted acquisition was selected as a stable and forensically
sound alternative for a controlled lab environment

### Integrity (Host)

SHA256:
4fbc8ddf2cdcdd187e5d74f66ab4c1c2d5fffe2753b34c870015d4ea055aa432
Final Integrity Confirmation:
Host and analysis environment SHA256 hashes were re-verified and confirmed identical.
No evidence corruption occurred during transfer or analysis.

### Notes

- No adversary activity executed
- Baseline reference dataset
- Used for comparison in later attack simulations
- The guest OS was not modified during acquisition.
- Memory was captured externally via the hypervisor.

## Case 02 — T1055-5 (Process Injection: RWX / CreateRemoteThread-style behavior)

**Case ID:** case02_t1055_5_attack  
**Technique:** MITRE ATT&CK T1055 — Process Injection (Atomic Red Team simulation)  
**Atomic Test:** RWX process injection local helper (`RWXinjectionLocal.exe`)  
**Host/VM Platform:** VirtualBox (Windows 10 target VM)  
**Acquisition Type:** Hypervisor-assisted memory dump (VBoxManage `dumpvmcore`)  
**Evidence File:** `t1055_5_attack.raw`  
**Evidence Location (Kali):** `/cases/case02_t1055_5_attack/t1055_5_attack.raw`

### Integrity Verification (Hash Matching)

SHA256 (Kali):
`85e4b855c6b625f79a18982bf5aa98df62801517e65c4887cc5e218675e47db8`

SHA256 (Host Windows, CertUtil):
`85e4b855c6b625f79a18982bf5aa98df62801517e65c4887cc5e218675e47db8`

**Conclusion:** Host and Kali hashes match. Evidence integrity preserved during transfer.

---

## Analysis Workflow (Volatility 3)

**Volatility Version:** 2.28.0  
**Working Directory:** `/home/anton/volatility3/`  
**Command Pattern Used:**

- `python vol.py -q -f <image> <plugin>`
- Primary plugins: `windows.pslist`, `windows.pstree`, `windows.cmdline`, `windows.dlllist`, `windows.netscan`, `windows.malware.malfind`

### Commands Executed (Case02)

```bash
python vol.py -q -f /cases/case02_t1055_5_attack/t1055_5_attack.raw windows.pslist
python vol.py -q -f /cases/case02_t1055_5_attack/t1055_5_attack.raw windows.pstree
python vol.py -q -f /cases/case02_t1055_5_attack/t1055_5_attack.raw windows.cmdline
python vol.py -q -f /cases/case02_t1055_5_attack/t1055_5_attack.raw windows.dlllist
python vol.py -q -f /cases/case02_t1055_5_attack/t1055_5_attack.raw windows.netscan
python vol.py -q -f /cases/case02_t1055_5_attack/t1055_5_attack.raw windows.malware.malfind

### Structured Exports (Case02)

Primary Format: JSONL (for automated ingestion)
Secondary Format: CSV (manual inspection)

Example:

python vol.py -q -f ... -r jsonl windows.pslist > exports/jsonl/windows.pslist.jsonl

## Observed Execution Chain

### 1. Injection Executable

PID: 2184  
Process Name: RWXinjectionLocal.exe  
Path:
\Device\HarddiskVolume2\AtomicRedTeam\atomics\T1055\bin\x64\RWXinjectionLocal.exe  

Execution Time:
Start: 2026-02-18 00:55:10 UTC  
Exit: 2026-02-18 00:55:16 UTC  

This confirms the Atomic test executed successfully.

---

### 2. Target Process

PID: 7764  
Parent PID: 2184  
Process Name: powershell.exe  
Path:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  

Command Line:
powershell.exe -Command "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Atomic Red Team','Warning','OK','Warning'); Start-Process 'notepad.exe'"

This confirms:

- The injection targeted powershell.exe
- The test executed during live memory state
- The capture occurred before cleanup

---

### 3. Console Host

PID: 4964  
Parent PID: 7764  
Process Name: conhost.exe  

This aligns with expected Windows console behavior following PowerShell execution.

---

## Memory Injection Artefacts (Volatility Analysis)

Plugin Used:
windows.malware.malfind

Findings:

PID 7764 (powershell.exe)

Multiple VAD regions:
Protection: PAGE_EXECUTE_READWRITE  
Tag: VadS  

Hexdump contains:

- Non-zero byte sequences
- Jump instructions
- Assembly prologues
- Memory regions consistent with shellcode

This confirms:

✔ Remote thread injection succeeded  
✔ Executable memory was allocated  
✔ Shellcode was written into target process  
✔ Execution redirection present  

Baseline comparison confirms:

Case01 (clean baseline) contained no such RWX memory in powershell.exe.

This establishes clear behavioral delta between baseline and attack state.

---

## Forensic Correlation

Correlation Matrix:

Injection Binary → PID 2184  
Target Process → PID 7764  
Injected RWX Regions → PID 7764  
Console Child → PID 4964  

This structured relationship confirms a complete CreateRemoteThread injection lifecycle.

---

## Preservation Statement

- Dump captured immediately after injection.
- Cleanup was NOT executed prior to acquisition.
- Memory artefacts preserved in volatile state.
- Analysis performed exclusively on verified copy.
- Original dump remained unchanged.

---

## Conclusion

This capture represents a valid, controlled T1055-5 injection scenario.

The dataset is suitable for:

- Baseline vs Attack comparative analysis
- Rule-based RWX detection
- Automated PID correlation
- Visualization framework development
- Dissertation evaluation

Case02 is confirmed as a clean, reproducible, injection-positive forensic image.

## Key Findings (Evidence of Injection)

### 1) Execution Chain (Process Correlation)

At 2026-02-18 00:55:10 UTC, process creation shows a tight parent/child relationship consistent with the Atomic test:

RWXinjectionLocal.exe (PID 2184) executed from:
\Device\HarddiskVolume2\AtomicRedTeam\atomics\T1055\bin\x64\RWXinjectionLocal.exe

CreateTime: 2026-02-18 00:55:10 UTC

ExitTime: 2026-02-18 00:55:16 UTC (short-lived helper process)

powershell.exe (PID 7764, PPID 2184) spawned immediately:
\Device\HarddiskVolume2\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

conhost.exe (PID 4964, PPID 7764) spawned as the console host for PowerShell:
\Device\HarddiskVolume2\Windows\System32\conhost.exe

This correlation demonstrates:

The Atomic test executed successfully

The memory capture occurred during active execution (not post-cleanup)

The injection artifacts were preserved in the dump

### 2) Malfind (Injected / Suspicious Memory Regions)

Volatility windows.malware.malfind identified RWX (PAGE_EXECUTE_READWRITE) memory regions inside:

powershell.exe (PID 7764)

RWX memory is a high-confidence indicator for process injection / in-memory staging because:

Legitimate modules are typically RX (execute-read) rather than RWX

RWX is commonly used by injection techniques to place and execute shellcode

The RWX regions appear in the same time window as the Atomic helper process

### Conclusion:
The combined evidence (process chain + RWX memory in target process) confirms a successful T1055-5 process injection simulation.

Export Artifacts

Structured exports were produced for later automated comparison against the baseline case:

CSV exports (already collected):

windows.cmdline.csv

windows.dlllist.csv

windows.malfind.csv

windows.netscan.csv

### (Additional JSON/CSV exports can be generated using Volatility renderers for pipeline ingestion.)

### Final Assessment

This is a valid forensic case representing T1055-5 style RWX process injection behavior:

Attack execution is present in the process tree (RWXinjectionLocal → PowerShell → Conhost)

Injection behavior is present in memory (Malfind shows RWX regions inside PowerShell)

Hash integrity is confirmed and reproducible

##### Memory Acquisition Log CASE 3

## Case Information

Case ID: case03_t1059_attack
Attack Technique: MITRE ATT&CK T1059 – Command and Scripting Interpreter (PowerShell)
Acquisition Method: VirtualBox Live Memory Dump
Analyst: Anton Ivanov
Framework: Memory Forensics Framework Tools for Analyse and Visualisation (MFF)

---

# Acquisition Procedure

The Windows 10 virtual machine was used to execute an Atomic Red Team simulation of **MITRE ATT&CK technique T1059**.
Immediately after the attack execution, a **live memory dump** was captured from the host system using the VirtualBox debugging interface.

This ensures the dump contains:

• attack process artifacts
• process hierarchy
• PowerShell execution traces
• memory-resident code segments
• network artifacts

---

## Step 1 — Execute Attack Inside Windows VM

Inside the Windows VM, PowerShell was used to trigger the Atomic Red Team simulation.

```powershell
$env:PathToAtomicsFolder = "C:\AtomicRedTeam\atomics"
Invoke-AtomicTest T1059
```

This executes the **PowerShell interpreter attack simulation**.

## Step 2 — Capture Memory Dump From Host

On the **Windows host machine**, run the following command in **Administrator Command Prompt**.

Navigate to the VirtualBox installation directory.

```
cd "C:\Program Files\Oracle\VirtualBox"
```

Then execute the memory dump command.

VBoxManage debugvm "Windows 10" dumpvmcore --filename "D:\2.ROEHAMPTON\Final year\FYPROJECT\Memory forensics framework tools for analyse and visualisation\shared\case03_t1059_attack.raw"
```

This produces a **RAW memory dump** of the running VM.

The dump is stored in the **shared folder used by the analysis VM**.

---

## Step 3 — Transfer Dump to Kali Analysis Environment

Inside Kali the shared directory is mounted and the dump is copied into the forensic case directory.

Case directory structure:

/MFF/cases/case03_t1059_attack/

## Step 4 — Compute Integrity Hash

To maintain forensic integrity a SHA256 hash is generated.

Example host command:

certutil -hashfile "D:\2.ROEHAMPTON\Final year\FYPROJECT\Memory forensics framework tools for analyse and visualisation\shared\case03_t1059_attack.raw" SHA256
```

The hash value is stored inside:

/docs/hash_values.txt

---

## Evidence Location

Raw Memory Image

/MFF/cases/case03_t1059_attack/case03_t1059_attack.raw

Volatility Exports

/MFF/cases/case03_t1059_attack/exports/


## Acquisition Verification

The dump was successfully parsed by Volatility 3 indicating the image is valid.

Example verification command:

python vol.py -q -f /MFF/cases/case03_t1059_attack/case03_t1059_attack.raw windows.info

Successful output confirms:

• Windows kernel identified
• memory structure accessible
• plugins functional
