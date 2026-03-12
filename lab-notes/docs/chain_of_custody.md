# Digital Evidence Chain of Custody

## Memory Forensics Framework Project

---

## Case Identification

Case ID: CASE01_BASELINE  
Evidence Type: Volatile Memory Image  
Evidence Filename: baseline.raw  
Evidence Size: ~4.56 GB  
Evidence Format: RAW Memory Image  

---

## Evidence Acquisition

### Acquisition Method

Memory evidence was acquired using a hypervisor-assisted memory capture technique via Oracle VirtualBox. The acquisition utilised the VirtualBox `dumpvmcore` debugging interface to capture a full memory snapshot of the Windows 10 virtual machine.

### Acquisition Environment

Host System:

- Operating System: Windows (Host Machine)
- Hypervisor: Oracle VirtualBox
- Role: Evidence acquisition and storage

Victim System:

- Operating System: Windows 10 Virtual Machine
- Purpose: Controlled volatile memory artefact generation

### Acquisition Command

VBoxManage debugvm "Windows 10" dumpvmcore --filename "D:...\shared\baseline.raw"


### Acquisition Rationale

Kernel-driver acquisition tools such as WinPmem could not be reliably executed due to host hypervisor and endpoint security constraints. Hypervisor-assisted acquisition was therefore selected as a stable and forensically sound alternative suitable for controlled laboratory environments.

---

## Evidence Integrity Verification (Host)

Immediately following acquisition, cryptographic hashing was performed to establish baseline evidence integrity.

### Host Hash Command

certutil -hashfile "baseline.raw" SHA256


### Host Hash Value

4fbc8ddf2cdcdd187e5d74f66ab4c1c2d5fffe2753b34c870015d4ea055aa432


---

## Evidence Storage (Primary)

Primary Storage Location:
Host System Shared Evidence Repository


Purpose:

- Preserve original acquisition file
- Maintain unmodified master evidence copy

Access Control:

- Read-only usage during transfer
- Original evidence never analysed directly

---

## Evidence Transfer Procedure

Evidence was transferred from the acquisition host to the forensic analysis virtual machine using VirtualBox Shared Folder functionality.

### Transfer Path

Host:
D:...\shared\baseline.raw


Analysis VM:
/media/sf_shared/baseline.raw


Transfer Method:

- Hypervisor controlled shared folder
- No network transfer utilised
- Controlled lab isolation maintained

---

## Evidence Isolation and Preservation

In accordance with digital forensic best practice, analysis was not performed on the shared transfer location.

Evidence was duplicated into an isolated forensic case workspace before examination.

### Isolation Command

cp /media/sf_shared/baseline.raw /cases/case01_baseline/


---

## Evidence Integrity Verification (Analysis VM)

Following transfer, cryptographic hashing was repeated to confirm integrity preservation.

### Verification Command

sha256sum /cases/case01_baseline/baseline.raw


### Verification Result

4fbc8ddf2cdcdd187e5d74f66ab4c1c2d5fffe2753b34c870015d4ea055aa432


### Integrity Confirmation

The hash generated in the analysis environment matched the acquisition hash generated on the host system, confirming that:

- No evidence alteration occurred during transfer
- Chain of custody remained intact
- Evidence remains forensically reliable

---

## Evidence Handling Policy

The following handling principles were strictly enforced:

1. Original evidence remains preserved on host system.
2. All forensic analysis conducted only on verified working copy.
3. Shared folders utilised solely for controlled transfer.
4. No modification permitted to original acquisition artefact.
5. All analytical outputs stored separately from source evidence.

---

## Evidence Analysis Environment

Analysis Platform:

- Operating System: Kali Linux Virtual Machine
- Toolset:
  - Volatility 3 Framework
  - Python Virtual Environment

Evidence Location:
/cases/case01_baseline/baseline.raw


---

## Evidence Processing and Artefact Extraction

Structured forensic artefacts were extracted using Volatility 3 plugins including:

- windows.info
- windows.pslist
- windows.pstree
- windows.cmdline
- windows.dlllist
- windows.malfind
- windows.netscan

Export Formats:

- JSONL (Machine processing)
- CSV (Manual inspection)

---

## Evidence Preservation Assurance

Throughout acquisition, transfer, verification and analysis:

- Evidence authenticity maintained
- Evidence integrity verified
- Evidence reproducibility ensured
- Analytical traceability documented

---

## Custody Timeline

| Stage | Location | Responsible | Action |
|--------|------------|----------------|------------|
| Acquisition | Host System | Investigator | Memory dump created |
| Integrity Hash | Host System | Investigator | SHA256 generated |
| Transfer | VirtualBox Shared Folder | Investigator | Evidence transferred |
| Isolation | Kali VM | Investigator | Evidence copied to case workspace |
| Verification | Kali VM | Investigator | Hash verification repeated |
| Analysis | Kali VM | Investigator | Volatility artefact extraction |

---

## Chain of Custody Declaration

This document certifies that the memory evidence referenced in CASE01_BASELINE was acquired, transferred, stored, and analysed in accordance with recognised digital forensic handling principles. Evidence integrity has been verified through cryptographic hashing at multiple stages, and the original evidence artefact remains preserved without modification.

---

Investigator:
Anton Ivanov

Project:
Memory Forensics Framework for Volatile Artefact Analysis and Visualisation

Date:
10 February 2026

---

## Chain of Custody — Case 02 (T1055-5)

### Evidence Description

- Evidence Type: Volatile Memory Image
- Filename: t1055_5_attack.raw
- Case ID: Case 02 — T1055-5
- Acquisition Method: VirtualBox hypervisor dump (dumpvmcore)

### Acquisition Details

The memory image was acquired from the host system using
VirtualBox hypervisor-assisted memory capture during active
attack execution.

No cleanup or remediation actions were performed prior to capture.

### Integrity Verification

- Hash Algorithm: SHA256
- Hash Value:
  85e4b855c6b625f79a18982bf5aa98df62801517e65c4887cc5e218675e47db8
- Host and analysis environment hashes match exactly.

### Handling & Storage

- Original image retained on host system
- Verified copy transferred to Kali Linux analysis VM
- Analysis performed exclusively on verified copy

### Analysis Integrity

All forensic analysis was conducted using Volatility 3.
No modifications were made to the original or working copies.

### Custody Status

Evidence integrity preserved throughout acquisition,
transfer, analysis, and documentation phases.


## 2.  chain_of_custody.md

```md
## Evidence Handling — Case02 (T1055-5)

| Date (UTC) | Evidence | Action | SHA256 | Analyst |
|---|---|---|---|---|
| 2026-02-18 | `t1055_5_attack.raw` | Acquired VM memory via VirtualBox hypervisor (`VBoxManage dumpvmcore`) and transferred to Kali case folder | `85e4b855c6b625f79a18982bf5aa98df62801517e65c4887cc5e218675e47db8` | Anton |

### Handling Notes
- Evidence acquired in an isolated university lab VM environment.
- Original file integrity verified using SHA256 on both Host (CertUtil) and Kali (sha256sum).
- No modifications performed on the evidence file after hashing.
- Subsequent analysis performed on the copy stored under `/cases/case02_t1055_5_attack/`.


# Chain of Custody

Case ID: case03_t1059_attack

---

Evidence Description

Memory dump captured from Windows 10 virtual machine after execution of MITRE ATT&CK technique T1059 simulation.

Evidence File

```
case03_t1059_attack.raw
```

---

Acquisition Details

Acquired using:

VirtualBox Debug Interface

Command Used

```
VBoxManage debugvm "Windows 10" dumpvmcore --filename "case03_t1059_attack.raw"
```

---

Evidence Handling

1. Memory dump created immediately after attack execution
2. Dump stored in secure host directory
3. SHA256 hash generated to preserve integrity
4. Image transferred to Kali analysis environment
5. Volatility analysis executed without modifying original evidence

---

Storage Location

```
/MFF/cases/case03_t1059_attack/
```

---

Analyst

Anton Ivanov

---

Purpose

Used as forensic dataset for the **Memory Forensics Framework Tools for Analyse and Visualisation project**.
