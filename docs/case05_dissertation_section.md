# Case 05 – Multi-Attack Scenario

## 1. Introduction to the Case
Case 05 was designed as the final and most comprehensive attack scenario in the Memory Forensics Framework. Unlike the earlier single-technique cases, this case intentionally combined several behaviours within a single execution chain in order to generate richer artefacts across process, command-line, DLL, memory, and network analysis. The main purpose of this case was to evaluate whether the framework could correlate multiple suspicious indicators at the same time and produce a high-confidence forensic interpretation.

## 2. Objective
The objective of Case 05 was to simulate a multi-stage attack that would leave evidence of command execution, system discovery, process discovery, defense evasion, and memory tampering in the acquired memory image. This case was intended to demonstrate the full analytical capability of the framework, including baseline comparison, suspicious command-line detection, DLL anomaly detection, executable writable memory detection, ATT&CK mapping, and automated scoring.

## 3. Scenario Design
The scenario combined both visible and hidden PowerShell execution. A non-standard copy of powershell.exe was staged in a temporary folder and launched from that location in order to create a suspicious execution path. Discovery commands were then executed to generate evidence of host, user, process, and network enumeration. Additional child processes were created through cmd.exe in order to produce suspicious parent-child relationships in the process tree.

To strengthen the case further, hidden PowerShell execution was also used with bypass-related arguments, no-profile execution, and encoded command syntax. A staged amsi.dll path was introduced from a temporary directory, and a PowerShell script associated with executable writable memory behaviour was executed. A sleep delay was used to keep the suspicious processes resident in memory long enough for the dump to capture them.

## 4. Attack Execution Procedure
The attack began by creating a temporary working directory and copying powershell.exe into a non-standard location. This copy was used to execute visible discovery commands such as user enumeration, hostname collection, system information gathering, network configuration inspection, process listing, and related reconnaissance actions. The purpose of this step was to create command-line artefacts that would later be visible through Volatility cmdline output and baseline comparison.

The next stage introduced a chained execution structure by launching cmd.exe from PowerShell and running child commands through cmd.exe /c. This was done to create a more realistic malicious execution chain and to generate suspicious parent-child relationships visible within pstree and process-delta outputs.

The final stage introduced hidden PowerShell execution using options such as ExecutionPolicy Bypass, NoProfile, WindowStyle Hidden, and encoded command invocation. In addition, a staged DLL path containing amsi.dll was used from a temporary directory, and a PowerShell script associated with executable writable memory allocation was executed. Together, these actions were intended to produce correlated artefacts across command-line, DLL, and malfind-based analysis.

## 5. Memory Acquisition
After the multi-attack sequence had been executed and the relevant processes were kept alive in memory, a hypervisor-assisted memory dump was acquired from the host using VirtualBox. This approach was used consistently across the project because it avoided in-guest driver limitations and provided a stable raw dump suitable for post-mortem analysis. The resulting memory image for this case was stored as T_multi.raw and transferred into the Case 05 directory for analysis.

## 6. Integrity Verification
To preserve forensic soundness, the Case 05 raw memory image was hashed after acquisition and transfer. MD5, SHA1, and SHA256 values were recorded as part of the evidence chain. This ensured that the memory image could be verified as unchanged throughout later stages of analysis and reporting.

## 7. Analysis Workflow
The acquired memory image was analysed using Volatility 3 plugin exports and then processed through the Python-based Memory Forensics Framework. The main plugin outputs used in this case were info, pslist, pstree, cmdline, dlllist, netscan, malfind, and threads. These raw outputs were then compared against the official baseline memory image from Case 01.

The framework processed the raw plugin outputs to produce structured findings such as new processes, missing baseline processes, suspicious command-line matches, DLL anomalies, executable writable memory findings, IOC extraction, ATT&CK technique tagging, risk scoring, and final report generation. This workflow allowed the case to move beyond simple plugin output review and into enriched, correlation-based interpretation.

## 8. Findings
Case 05 produced the richest set of findings across all completed attack scenarios. The comparison identified multiple new powershell.exe processes not present in the baseline, including processes launched from suspicious paths and processes using hidden or bypass-oriented arguments. Command-line analysis highlighted encoded PowerShell execution, temp-path execution, and multiple discovery-related commands.

DLL analysis identified amsi.dll being loaded from a non-standard path under C:\Temp\mff_multi\, which strongly suggested staged AMSI-related tampering or DLL abuse. Malfind analysis identified multiple PAGE_EXECUTE_READWRITE regions associated with powershell.exe processes, supporting the presence of suspicious in-memory activity. When these findings were correlated together, the framework assigned several PowerShell processes a CRITICAL risk level.

The final outputs also showed that Case 05 had the broadest ATT&CK coverage of all cases, with techniques mapped across Execution, Discovery, and Defense Evasion. This made it the most complete case for demonstrating the intended capabilities of the framework.

## 9. Interpretation
The significance of Case 05 lies not in any single artefact viewed in isolation, but in the combined weight of correlated evidence. Suspicious PowerShell command lines alone may indicate administrative or scripted behaviour, and executable writable memory regions alone may sometimes appear in benign contexts. However, when hidden PowerShell execution, encoded commands, staged DLL loading, and executable writable memory are observed together in the same case, the confidence of malicious interpretation becomes significantly stronger.

This case therefore demonstrates the value of correlation-based post-Volatility analysis. Rather than relying on a single plugin or a single suspicious string, the framework combines multiple weak and strong indicators into a higher-confidence forensic conclusion.

## 10. Limitations
The main limitation in this case was the lack of a newly acquired clean baseline snapshot captured immediately before the execution of the multi-attack scenario. Because of this, the comparison relied on the official baseline memory image from Case 01, which introduced some expected environmental differences. As a result, some benign process and network variation appeared in the delta outputs. Despite this limitation, the framework still successfully isolated the most relevant suspicious artefacts and prioritised them through enrichment and scoring.

## 11. Conclusion
Case 05 successfully demonstrated the final intended functionality of the Memory Forensics Framework. It showed that the framework could ingest Volatility plugin outputs, compare them with a known baseline, detect suspicious command-line and process behaviours, identify staged DLL loading, detect executable writable memory anomalies, map findings to ATT&CK techniques, assign risk scores, and generate usable forensic reports. Among all implemented cases, Case 05 provided the strongest demonstration of the framework’s ability to support enriched post-memory-analysis investigation.
