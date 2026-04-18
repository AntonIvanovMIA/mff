md
# Case 05 – Evidence Index

## 1. Primary Evidence Files
- Memory image: /MFF/cases/case05_multi_attack/T_multi.raw
- Comparison output directory: /MFF/analysis/comparison/case01_vs_case05

## 2. Command-Line Evidence
Files:
- windows.cmdline.csv
- cmdline_findings.csv

What they prove:
- PowerShell execution from standard and non-standard paths
- hidden PowerShell execution
- bypass and no-profile parameters
- encoded PowerShell execution
- discovery commands
- temp-path staging
- execution of case05_rwx_amsi.ps1

## 3. DLL / AMSI Evidence
Files:
- windows.dlllist.csv
- dll_hijack.csv

What they prove:
- amsi.dll loaded from C:\Temp\mff_multi\
- likely AMSI bypass correlation
- staged/non-standard DLL path
- defense evasion behaviour

## 4. Memory Injection / RWX Evidence
Files:
- windows.malfind.csv
- malfind.csv

What they prove:
- PAGE_EXECUTE_READWRITE memory regions
- suspicious executable writable memory associated with powershell.exe
- possible injection or in-memory patching behaviour

## 5. Process Delta Evidence
Files:
- windows.pslist.csv
- windows.pstree.csv
- process_new.csv
- process_gone.csv
- timeline.csv

What they prove:
- attack-only process appearances
- suspicious PowerShell activity
- parent-child process relationships
- attack timeline sequence

## 6. Network Evidence
Files:
- windows.netscan.csv
- net_new.csv
- net_flagged.csv

What they prove:
- new network entries relative to baseline
- limited supporting evidence of network activity
- environmental noise also present

## 7. Enrichment Outputs
Files:
- attack_tags.csv
- tactic_summary.csv
- scores.csv
- iocs.csv
- threat_summary.json.txt

What they prove:
- ATT&CK technique mapping
- tactic coverage
- process-level risk scoring
- IOC extraction
- structured threat summary generation

## 8. Final Reports
Files:
- report_interactive.html
- report_forensics.pdf

What they prove:
- the framework can generate final visual and formal forensic reports
- the case is report-ready for dissertation inclusion

## 9. Strongest Evidence Chain
The strongest correlated evidence chain in Case 05 is:
1. suspicious PowerShell command-line behaviour
2. staged amsi.dll loading from non-standard path
3. executable writable memory regions in PowerShell
4. high-confidence ATT&CK tagging
5. CRITICAL risk scoring
6. final HTML/PDF report generation
