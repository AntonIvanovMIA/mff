# VM Configuration (Lab)

## Host

- OS: Windows (host machine)
- Hypervisor: Oracle VirtualBox
- Role: Memory acquisition and storage

## Victim VM

- Name: Windows 10
- Purpose: Controlled Windows target for memory artefact generation
- RAM: 4 GB (baseline dump produced ~4.56 GB image)
- Notes: Host security/hypervisor constraints prevented kernel-driver acquisition tools; hypervisor-based acquisition was used instead.
- Notes:
- The guest OS was not modified during acquisition.
- Memory was captured externally via the hypervisor.

## Analysis VM

- Name: kali
- Purpose: Volatility 3 + Python post-processing (framework)

### Analysis Environment Validation

Analysis VM:

- OS: Kali Linux
- Role: Memory forensic analysis
- Tools: Volatility 3 (Python-based)

Evidence Handling:

- Shared folders used only for transfer
- Evidence copied into /cases directory
- Analysis performed on isolated copies only

Permissions:

- Evidence directories owned by analyst user
- Read/write access controlled within analysis VM

This configuration ensures separation of acquisition, transfer, and analysis stages.

### Baseline Memory Analysis Methodology

Baseline volatile memory was analysed using Volatility 3 plugins with structured JSONL export.

Analysis plugins included:

- windows.pslist
- windows.pstree
- windows.cmdline
- windows.dlllist
- windows.malfind
- windows.netscan

Output was stored in structured JSONL format for automated ingestion into the Python post-processing analysis framework.

This stage establishes behavioural reference indicators used for anomaly detection in subsequent experimental attack scenarios.

### Evidence Processing Workflow

Acquisition Source:
Host-level VirtualBox hypervisor memory dump

Evidence Transfer:
VirtualBox shared folder mechanism

Analysis Workflow:

1. Evidence copied to isolated case directory
2. Integrity verified via SHA256 hashing
3. Memory artefacts extracted using Volatility 3
4. Outputs exported to structured analysis formats

This workflow ensures reproducibility, evidential integrity, and structured data ingestion for automated analysis tooling.


### Case 02 Notes (T1055-5)

No snapshots used (resource optimization for student hardware [poster]).
Artefacts: RWX regions, anomalous PID chain for advanced Python detection [11].
Environment: Same as baseline; host-only network for isolation [22].




###  Virtual Machine Configuration

Analysis Environment for Memory Forensics Framework (MFF)

---

Host System

Operating System: Windows
Hypervisor: Oracle VirtualBox

---

Windows Target VM

Operating System: Windows 10
Purpose: Attack simulation target

Installed tools:

• Atomic Red Team
• PowerShell
• VirtualBox Guest Additions

---

Kali Analysis VM

Operating System: Kali Linux

Purpose:

• memory analysis
• Volatility execution
• artifact extraction
• dataset generation

Key tools:

Volatility 3
Python
jq
grep

---

Case Directory Structure

```
/MFF
 ├ cases
 │  ├ case01_baseline
 │  ├ case02_t1055_5_attack
 │  └ case03_t1059_attack
 │
 ├ docs
 ├ analysis
 ├ shared
```

---

Volatility Execution Environment

Volatility installed inside Python virtual environment.

Example command:

```
python vol.py -q -f MEMORY_DUMP windows.pslist
```

Outputs exported as structured JSONL datasets for later analysis and visualisation.
