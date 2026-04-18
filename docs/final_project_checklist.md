# Memory Forensics Framework – Full Project Final Checklist

## 1. Core Framework Completion
- [ ] The framework has a defined project structure under /MFF
- [ ] The framework includes separate folders for cases, analysis outputs, source code, and documentation
- [ ] The framework can process baseline and attack cases using comparison_engine_v2.py
- [ ] The framework can generate HTML reports
- [ ] The framework can generate PDF reports
- [ ] The framework can perform batch processing across all completed attack cases
- [ ] The framework can generate a cross-case comparison report
- [ ] The framework includes enrichment features such as ATT&CK tagging, scoring, IOC extraction, and artifact correlation

## 2. Project Directory Structure
- [ ] /MFF/cases exists
- [ ] /MFF/analysis exists
- [ ] /MFF/src exists
- [ ] /MFF/docs exists
- [ ] /MFF/venv exists
- [ ] Folder names are consistent and readable
- [ ] Final outputs are stored in the correct locations
- [ ] No critical files are left in temporary or ambiguous folders

## 3. Baseline Case
- [ ] /MFF/cases/case01_baseline exists
- [ ] Baseline raw memory image exists
- [ ] Baseline exports are present
- [ ] Baseline is consistently used in all comparison commands
- [ ] Baseline limitation is documented where necessary

## 4. Case 02 – T1055
- [ ] /MFF/cases/case02_t1055_5_attack exists
- [ ] Raw memory image exists
- [ ] Required Volatility outputs exist
- [ ] Comparison output directory exists
- [ ] report_interactive.html exists
- [ ] report_forensics.pdf exists
- [ ] Key findings are documented
- [ ] Hash record exists or is documented in hash_values.txt

## 5. Case 03 – T1059
- [ ] /MFF/cases/case03_t1059_attack exists
- [ ] Raw memory image exists
- [ ] Required Volatility outputs exist
- [ ] Comparison output directory exists
- [ ] report_interactive.html exists
- [ ] report_forensics.pdf exists
- [ ] Key findings are documented
- [ ] Hash record exists or is documented in hash_values.txt

## 6. Case 04 – T1574
- [ ] /MFF/cases/case04_t1574_attack exists
- [ ] Raw memory image exists
- [ ] Required Volatility outputs exist
- [ ] Comparison output directory exists
- [ ] report_interactive.html exists
- [ ] report_forensics.pdf exists
- [ ] Key findings are documented
- [ ] Hash record exists or is documented in hash_values.txt

## 7. Case 05 – Multi-Attack
- [ ] /MFF/cases/case05_multi_attack exists
- [ ] T_multi.raw exists
- [ ] MD5 recorded
- [ ] SHA1 recorded
- [ ] SHA256 recorded
- [ ] Hash values added to /MFF/docs/hash_values.txt
- [ ] exports/csv exists
- [ ] exports/jsonl exists
- [ ] windows.info.csv exists
- [ ] windows.pslist.csv exists
- [ ] windows.pstree.csv exists
- [ ] windows.cmdline.csv exists
- [ ] windows.dlllist.csv exists
- [ ] windows.netscan.csv exists
- [ ] windows.malfind.csv exists
- [ ] windows.threads.csv exists
- [ ] process_new.csv exists
- [ ] process_gone.csv exists
- [ ] cmdline_findings.csv exists
- [ ] dll_hijack.csv exists
- [ ] malfind.csv exists
- [ ] net_new.csv exists
- [ ] net_flagged.csv exists
- [ ] iocs.csv exists
- [ ] attack_tags.csv exists
- [ ] scores.csv exists
- [ ] tactic_summary.csv exists
- [ ] timeline.csv exists
- [ ] threat_summary.json.txt exists
- [ ] report_interactive.html exists
- [ ] report_forensics.pdf exists
- [ ] suspicious PowerShell command-line evidence confirmed
- [ ] staged amsi.dll evidence confirmed
- [ ] PAGE_EXECUTE_READWRITE evidence confirmed
- [ ] ATT&CK mapping confirmed
- [ ] CRITICAL scoring confirmed
- [ ] Case 05 notes are documented

## 8. Integrity and Chain of Custody
- [ ] /MFF/docs/hash_values.txt exists
- [ ] Case identifiers are clearly linked to their raw images
- [ ] Hash values are present for each completed case where available
- [ ] The acquisition method is documented
- [ ] Transfer and preservation steps are documented
- [ ] Evidence integrity explanation is ready for methodology chapter

## 9. Volatility Export Coverage
- [ ] info outputs exist where needed
- [ ] pslist outputs exist for each attack case
- [ ] pstree outputs exist for each attack case
- [ ] cmdline outputs exist for each attack case
- [ ] dlllist outputs exist for each attack case
- [ ] malfind outputs exist for each attack case
- [ ] netscan outputs exist for each attack case
- [ ] threads outputs exist for each attack case
- [ ] Export naming is consistent enough for the framework to parse correctly

## 10. Comparison Engine Outputs
- [ ] case01_vs_case02 output exists
- [ ] case01_vs_case03 output exists
- [ ] case01_vs_case04 output exists
- [ ] case01_vs_case05 output exists
- [ ] Each comparison folder contains the expected CSV, JSON, HTML, and PDF outputs
- [ ] Each case has a usable executive summary
- [ ] Each case has interpretable findings
- [ ] Each case has at least one defendable evidence chain

## 11. Enrichment and Correlation Features
- [ ] Command-line detection works
- [ ] Process delta detection works
- [ ] DLL anomaly detection works
- [ ] RWX / malfind enrichment works
- [ ] ATT&CK tagging works
- [ ] Risk scoring works
- [ ] IOC extraction works
- [ ] Timeline generation works
- [ ] Final reports reflect correlated findings rather than raw plugin output only

## 12. Batch and Cross-Case Processing
- [ ] batch_summary.json.txt exists
- [ ] Batch execution completed successfully
- [ ] comparison_report.html exists
- [ ] comparison_report.pdf exists
- [ ] comparison_matrix.csv exists
- [ ] Cross-case outputs include all attack cases
- [ ] Cross-case outputs show metric comparison between cases
- [ ] Cross-case outputs are suitable for the evaluation/results chapter

## 13. Documentation in /MFF/docs
- [ ] case05_multi_attack_report_notes.md exists
- [ ] case05_memory_acquisition_and_integrity.md exists
- [ ] case05_evidence_index.md exists
- [ ] case05_commands_log.md exists
- [ ] case05_dissertation_section.md exists
- [ ] case05_final_checklist.md exists
- [ ] case05_report_mapping.md exists
- [ ] case05_artifact_schema.md exists
- [ ] final_project_checklist.md exists
- [ ] Documentation matches the real commands and outputs used in the project

## 14. Visual and Evidence Materials for the Report
- [ ] At least one Case 05 dashboard screenshot selected
- [ ] At least one command-line evidence screenshot selected
- [ ] At least one artifact summary screenshot selected
- [ ] Cross-case comparison PDF or screenshot selected
- [ ] Important tables are identified for insertion into the report
- [ ] Screenshots are clearly named and saved for later use

## 15. Report Readiness
- [ ] Methodology evidence is ready
- [ ] Implementation evidence is ready
- [ ] Results evidence is ready
- [ ] Discussion points are ready
- [ ] Limitations are identified
- [ ] Future work ideas are identified
- [ ] The framework can now be described as complete for FYP scope
- [ ] No major technical feature still needs to be added before writing

## 16. Optional Features – Not Required for Submission
- [ ] YARA integration intentionally skipped or clearly marked as future work
- [ ] VirusTotal integration intentionally skipped or clearly marked as future work
- [ ] Optional features are not blocking report writing

## 17. Final Freeze Decision
- [ ] Codebase is stable enough to stop major feature expansion
- [ ] Case outputs are preserved
- [ ] Documentation is aligned with evidence
- [ ] The project is ready to move into dissertation writing section by section
