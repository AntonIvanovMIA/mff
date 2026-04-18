# Case 05 – Multi-Attack Scenario Report Notes

## 1. Case Identifier
- Case Name: case05_multi_attack
- Baseline Reference: case01_baseline
- Attack Memory Image: /MFF/cases/case05_multi_attack/T_multi.raw
- Comparison Output: /MFF/analysis/comparison/case01_vs_case05

## 2. Aim of the Case
The purpose of Case 05 was to create a combined multi-technique attack scenario that could generate memory artefacts across multiple behavioural categories, including execution, discovery, defense evasion, suspicious command-line activity, staged DLL loading, and executable writable memory regions. This case was designed as the final enriched scenario in the Memory Forensics Framework (MFF) and intended to demonstrate the framework’s ability to correlate findings across several Volatility plugins and enriched Python analysis modules.

## 3. Scenario Summary
Case 05 combined visible and hidden PowerShell execution, staged execution from a non-standard directory, child process spawning through cmd.exe, discovery commands, encoded execution, AMSI-related DLL staging, and memory artefacts associated with executable writable regions. The scenario was deliberately designed to produce artefacts in process, command-line, DLL, memory, and ATT&CK-tagged outputs.

## 4. Attack Preparation and Execution
The following actions were performed in the Windows virtual machine:

1. A staging folder was created for visible PowerShell execution from a non-standard path.
2. powershell.exe was copied into C:\Temp\multiattack\ and launched from that location.
3. Discovery commands were executed, including user, system, network, and process enumeration activity.
4. cmd.exe child-command chains were launched from PowerShell to create suspicious parent-child relationships.
5. Additional commands such as ping, netstat, and tasklist were executed to enrich command-line and process artefacts.
6. Hidden PowerShell execution was performed using options such as -ExecutionPolicy Bypass, -NoProfile, -WindowStyle Hidden, and encoded command syntax.
7. A staged AMSI DLL path was used from C:\Temp\mff_multi\.
8. A PowerShell script associated with memory patching and executable writable regions was executed.
9. Start-Sleep was used to keep suspicious processes resident in memory long enough for memory acquisition.

## 5. Baseline Reference
A fresh clean VM baseline snapshot was not available at the time of Case 05 execution. Therefore, the project used the previously acquired official baseline memory image from Case 01 as the comparison reference. This introduced some expected environmental drift between the baseline and Case 05, particularly in normal background processes. However, the baseline remained suitable for identifying high-risk deviations such as suspicious PowerShell execution, staged DLL loading, RWX memory artefacts, and attack-aligned command-line activity.

## 6. Memory Acquisition Summary
Memory was acquired using a hypervisor-assisted VirtualBox dump rather than an in-guest acquisition driver. This approach was retained for forensic consistency and to avoid kernel-driver restrictions encountered earlier in the project. The resulting raw memory image was named T_multi.raw and stored in the Case 05 directory after transfer from the shared folder.

## 7. Integrity Verification
The Case 05 memory image was hashed and documented as follows:

- MD5: 8c4f8c763f78993b30b2ac4a230952a2
- SHA1: 3d1825d640cbf425b54c83464eea9076ba251463
- SHA256: a0983f4df938595db7ffdb377b743defdd02428f6b1d97b9f653821690a8f1d0

These hashes were recorded to maintain forensic integrity and chain-of-custody documentation.

## 8. Volatility Export Scope
The following Volatility 3 plugins were exported for Case 05 in CSV and/or JSONL format:

- windows.info
- windows.pslist
- windows.pstree
- windows.cmdline
- windows.dlllist
- windows.netscan
- windows.malfind
- windows.threads

These exports formed the raw forensic input for the MFF comparison and enrichment modules.

## 9. Comparison and Enrichment Stage
The Case 05 attack image was compared against case01_baseline using comparison_engine_v2.py. The output included:

- new and gone process deltas
- suspicious command-line findings
- DLL hijack / AMSI bypass findings
- malfind-derived RWX findings
- network comparison outputs
- IOC extraction
- MITRE ATT&CK tagging
- scoring and severity classification
- interactive HTML report
- PDF forensic report
- JSON threat summary

## 10. Key Findings
The strongest findings observed in Case 05 were:

- multiple powershell.exe processes scored as CRITICAL
- suspicious command-line indicators including PowerShell, hidden execution, bypass parameters, encoded execution, temp-path execution, and discovery commands
- staged loading of amsi.dll from C:\Temp\mff_multi\
- multiple PAGE_EXECUTE_READWRITE memory regions associated with powershell.exe
- ATT&CK coverage across Execution, Discovery, and Defense Evasion
- final overall severity classified as CRITICAL

## 11. Case 05 Output Summary
The final case outputs included the following key artefacts:

- report_forensics.pdf
- report_interactive.html
- threat_summary.json.txt
- attack_tags.csv
- cmdline_findings.csv
- dll_hijack.csv
- malfind.csv
- process_new.csv
- process_gone.csv
- net_new.csv
- net_flagged.csv
- scores.csv
- tactic_summary.csv
- timeline.csv
- iocs.csv

## 12. Limitations
The main limitation of Case 05 was the absence of a newly captured clean baseline snapshot taken immediately before executing the multi-attack scenario. As a result, some benign system drift appeared in the process delta and network outputs. This did not prevent detection of the most important artefacts, but it introduced some background noise in new/gone process and network comparison results.

## 13. Conclusion
Case 05 successfully demonstrated the final intended capabilities of the Memory Forensics Framework. The case produced correlated artefacts across process, command-line, DLL, and memory analysis, and these findings were enriched through ATT&CK mapping, scoring, and report generation. Despite baseline drift, the framework successfully highlighted the most significant suspicious behaviour and provided the strongest overall detection coverage of all implemented cases.
---

## 14. Detailed Analysis of Case 05 Findings

Case 05 produced the richest and most diverse set of artefacts across all implemented attack scenarios. The final report classified the case as **CRITICAL**, with 16 new processes, 16 gone processes, 8 critical processes, 8 detected ATT&CK techniques, 3 tactics, 59 extracted IOCs, and 139 new network connections. These values indicate that the multi-attack scenario successfully generated a broad range of process, command-line, memory, DLL, and enrichment artefacts suitable for end-to-end framework validation. 

The strongest evidence in Case 05 came from suspicious PowerShell activity. Command-line findings showed multiple `powershell.exe` instances executed with indicators such as `-ExecutionPolicy Bypass`, `-NoProfile`, `-WindowStyle Hidden`, encoded command syntax using `-enc`, and staged script execution from `C:\Temp\mff_multi\case05_rwx_amsi.ps1`. Additional evidence also showed PowerShell being launched from a non-standard location, `C:\Temp\multiattack\powershell.exe`, which strengthened the suspicious process execution profile. 

A second major evidence category was the DLL-related defence evasion behaviour. The DLL analysis identified `amsi.dll` loaded by `powershell.exe` from `C:\Temp\mff_multi\amsi.dll` rather than from the expected system path. This was treated by the framework as high-confidence evidence associated with AMSI bypass and DLL hijack-style behaviour, particularly where the file was linked to defence evasion rules `T1562.001` and `T1574.001`. 

Memory analysis further strengthened the findings. Malfind outputs showed multiple `PAGE_EXECUTE_READWRITE` regions associated with PowerShell processes, which is consistent with suspicious in-memory modification, shellcode staging, or process injection behaviour. The score outputs demonstrated that several PowerShell PIDs were rated as **CRITICAL** because they combined RWX memory, suspicious command-line behaviour, and AMSI-related DLL evidence in the same correlated case. 

The ATT&CK tagging outputs showed that Case 05 expanded beyond a single evasion-only scenario and covered a broader behavioural chain. The framework identified `T1059.001` (PowerShell), `T1082` (System Information Discovery), `T1016` (System Network Configuration Discovery), `T1033` (System Owner/User Discovery), `T1057` (Process Discovery), `T1055` (Process Injection), `T1562.001` (Disable or Modify Tools / AMSI bypass), and `T1574.001` (DLL Search Order Hijacking). This broader coverage is important because it shows that the framework was able to detect not only payload execution and evasion, but also pre-attack reconnaissance and system discovery behaviour. 

Although network outputs were generated successfully, they should be interpreted as supporting rather than primary evidence. The case recorded 139 new network connections and 4 flagged network connections, but a portion of these are likely influenced by background operating system activity and normal runtime drift. Therefore, the strongest analytical conclusions for Case 05 should rely on the convergence of command-line, DLL, memory, ATT&CK, and scoring outputs rather than raw network count alone. 

A further limitation of the case is that the baseline used for comparison was the existing Case 01 raw memory image rather than a newly captured clean snapshot immediately before execution of the multi-attack chain. This explains why some benign process drift appears in `process_new.csv` and `process_gone.csv`, where environmental or application processes appear alongside attack-relevant PowerShell entries. However, this limitation does not invalidate the case because the most important suspicious artefacts remain clearly visible and strongly correlated across several independent evidence sources. 

Overall, Case 05 represents the strongest validation case in the project. The cross-case comparison report showed that it had the highest number of detected techniques, the highest number of critical processes, the largest ATT&CK tactic spread, the highest IOC count, and the highest RWX and DLL-related findings when compared with Cases 02, 03, and 04. This makes Case 05 the most suitable scenario for demonstrating the final capabilities of the Memory Forensics Framework in the dissertation. 

## 15. Interpretation of the Multi-Attack Scenario

From a forensic perspective, Case 05 is significant because it demonstrates how a single attack chain can leave related traces across several independent artefact categories. In this case, suspicious PowerShell invocation, discovery commands, AMSI-related DLL staging, and executable writable memory were all visible at the same time. This makes the case especially useful for validating an automated framework, because the framework is not relying on a single plugin or one isolated suspicious string. Instead, it derives confidence from artefact correlation across command-line, memory, DLL, process, IOC, and ATT&CK-tagged outputs. 

This case also demonstrates why post-processing and enrichment are necessary after Volatility export. Raw plugin outputs alone can be large, noisy, and difficult to interpret, particularly in scenarios where benign operating system activity is present. The MFF workflow improves interpretability by generating process deltas, suspicious command-line filtering, DLL anomaly identification, IOC extraction, ATT&CK mapping, and final severity scoring. The final HTML and PDF reports show that this enrichment stage transforms low-level memory artefacts into structured forensic intelligence suitable for analyst review and academic evaluation. 

## 16. Case 05 Mini Checklist

Before freezing Case 05 as complete, confirm the following items exist:

- `T_multi.raw` stored in `/MFF/cases/case05_multi_attack/`
- hash values recorded in the integrity record
- Volatility exports present for `info`, `pslist`, `pstree`, `cmdline`, `dlllist`, `netscan`, `malfind`, and `threads`
- comparison output generated in `/MFF/analysis/comparison/case01_vs_case05`
- `report_interactive.html` generated
- `report_forensics.pdf` generated
- `threat_summary.json.txt` generated
- `scores.csv`, `attack_tags.csv`, `cmdline_findings.csv`, `dll_hijack.csv`, and `malfind.csv` present
- Case 05 evidence indexed in the documentation
- limitation note about baseline drift documented

## 17. Cross-Case Importance of Case 05

The cross-case comparison confirmed that Case 05 is the highest-value evaluation case in the project. Compared with the earlier attack cases, it achieved the largest technique set, the widest tactic coverage, and the highest count of critical processes. This means Case 05 should be used in the final dissertation as the primary showcase scenario, while Cases 02–04 should be used as supporting validation cases demonstrating progressive development from simpler attacks to a more comprehensive multi-technique scenario.
