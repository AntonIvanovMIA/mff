# Week 3 – T1059 Analysis Summary

## Dataset
- Case: case03_t1059_attack
- Dump: T1059.raw

## Artefact Counts
- Process creation findings: 4
- Parent-child findings: 0
- Command-line findings: 4
- In-memory execution findings: 5

## Highest-Risk Processes
- PID 7888 | unknown | Score 360 | RWX memory region detected; Suspicious command line; T1059-linked process
- PID 4200 | unknown | Score 60 | Suspicious command line; T1059-linked process
- PID 9608 | unknown | Score 60 | Suspicious command line; T1059-linked process
- PID 9864 | unknown | Score 60 | Suspicious command line; T1059-linked process

## Analyst Conclusion
The Week 3 dataset contains T1059-related artefacts including PowerShell process creation, suspicious parent-child chains, suspicious command-line patterns, and RWX memory regions associated with PowerShell.
