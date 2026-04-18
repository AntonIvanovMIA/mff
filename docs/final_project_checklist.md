# Memory Forensics Framework – Full Project Final Checklist

## 1. Core Framework Completion
- [x] The framework has a defined project structure under /MFF
- [x] The framework includes separate folders for cases, analysis outputs, source code, and documentation
- [x] The framework can process baseline and attack cases using comparison_engine_v2.py
- [x] The framework can generate HTML reports
- [x] The framework can generate PDF reports
- [x] The framework can perform batch processing across all completed attack cases
- [x] The framework can generate a cross-case comparison report
- [x] The framework includes enrichment features such as ATT&CK tagging, scoring, IOC extraction, and artifact correlation

## 2. Project Directory Structure
- [x] /MFF exists
- [x] /MFF/analysis exists
- [x] /MFF/cases exists
- [x] /MFF/docs exists
- [x] /MFF/src exists
- [x] /MFF/venv exists
- [x] /MFF/lab-notes exists
- [x] /MFF/screenshots exists
- [x] README.md exists
- [x] Folder structure is suitable for final project submission
- [ ] Final folder cleanup of optional support folders has been reviewed

## 3. Source Code Structure
- [x] comparison_engine_v2.py exists inside /MFF/src
- [x] modules folder exists inside /MFF/src
- [x] Source code folder is organised enough for execution and documentation
- [ ] Backup files folder has been reviewed for what should remain in the final submission
- [ ] __pycache__ cleanup decision has been made for final packaging

## 4. Analysis Structure
- [x] /MFF/analysis/comparison exists
- [x] /MFF/analysis/single exists
- [x] /MFF/analysis/batch_run_final exists
- [x] Analysis output layout is consistent with framework workflow
- [ ] Final comparison subfolder contents have been re-checked locally

## 5. Baseline Case
- [x] /MFF/cases/case01_baseline is used as the official reference baseline
- [x] Baseline is consistently used in all comparison commands
- [x] Baseline comparison works across Cases 02–05
- [x] Baseline limitation is documented and understood
- [ ] Baseline raw image presence has been manually rechecked
- [ ] Baseline export completeness has been manually rechecked

## 6. Case 02 – T1055
- [x] Case 02 comparison command exists and was used
- [x] Case 02 comparison completed successfully
- [x] Case 02 appears in batch processing
- [x] Case 02 appears in cross-case comparison
- [x] Case 02 has HTML output
- [x] Case 02 has PDF output
- [ ] Case 02 case folder contents have been manually rechecked one final time

## 7. Case 03 – T1059
- [x] Case 03 comparison command exists and was used
- [x] Case 03 comparison completed successfully
- [x] Case 03 appears in batch processing
- [x] Case 03 appears in cross-case comparison
- [x] Case 03 has HTML output
- [x] Case 03 has PDF output
- [ ] Case 03 case folder contents have been manually rechecked one final time

## 8. Case 04 – T1574
- [x] Case 04 comparison command exists and was used
- [x] Case 04 comparison completed successfully
- [x] Case 04 appears in batch processing
- [x] Case 04 appears in cross-case comparison
- [x] Case 04 has HTML output
- [x] Case 04 has PDF output
- [ ] Case 04 case folder contents have been manually rechecked one final time

## 9. Case 05 – Multi-Attack
- [x] Case 05 comparison completed successfully
- [x] T_multi.raw exists
- [x] MD5 exists
- [x] SHA1 exists
- [x] SHA256 exists
- [x] windows.info.csv exists
- [x] windows.pslist.csv exists
- [x] windows.pstree.csv exists
- [x] windows.cmdline.csv exists
- [x] windows.dlllist.csv exists
- [x] windows.netscan.csv exists
- [x] windows.malfind.csv exists
- [x] windows.threads.csv exists
- [x] process_new.csv exists
- [x] process_gone.csv exists
- [x] cmdline_findings.csv exists
- [x] dll_hijack.csv exists
- [x] malfind.csv exists
- [x] net_new.csv exists
- [x] net_flagged.csv exists
- [x] iocs.csv exists
- [x] attack_tags.csv exists
- [x] scores.csv exists
- [x] tactic_summary.csv exists
- [x] timeline.csv exists
- [x] threat_summary.json.txt exists
- [x] report_interactive.html exists
- [x] report_forensics.pdf exists
- [x] suspicious PowerShell execution is confirmed
- [x] hidden/bypass/encoded PowerShell evidence is confirmed
- [x] staged amsi.dll evidence is confirmed
- [x] PAGE_EXECUTE_READWRITE evidence is confirmed
- [x] ATT&CK mapping is confirmed
- [x] CRITICAL scoring is confirmed
- [x] Case 05 is technically complete for dissertation writing
- [ ] Case 05 documentation files have been saved and checked locally

## 10. Integrity and Chain of Custody
- [x] Case 05 hash values are recorded
- [x] Acquisition method is documented
- [x] Hypervisor-assisted dumping method is established in the project
- [x] Integrity explanation is available for methodology writing
- [ ] /MFF/docs/hash_values.txt has been rechecked locally
- [ ] Earlier-case hash records have been rechecked locally where available

## 11. Volatility Export and Comparison Coverage
- [x] Volatility-based workflow is implemented
- [x] Process analysis is implemented
- [x] Process tree analysis is implemented
- [x] Command-line analysis is implemented
- [x] DLL analysis is implemented
- [x] Malfind/RWX analysis is implemented
- [x] Network analysis is implemented
- [x] Timeline/correlation output is implemented
- [x] Comparison workflow works across all completed cases
- [ ] Earlier-case raw export completeness has been rechecked locally

## 12. Enrichment and Correlation Features
- [x] ATT&CK tagging works
- [x] Risk scoring works
- [x] IOC extraction works
- [x] Artifact correlation works
- [x] Final reports show enriched findings, not just raw plugin outputs

## 13. Batch and Cross-Case Processing
- [x] batch_summary.json.txt exists
- [x] Batch processing completed successfully
- [x] comparison_report.html exists
- [x] comparison_report.pdf exists
- [x] comparison_matrix.csv exists
- [x] Cross-case report includes Cases 02, 03, 04, and 05
- [x] Cross-case outputs are suitable for evaluation and discussion chapters

## 14. Documentation in /MFF/docs
- [x] /MFF/docs folder exists
- [x] case05_multi_attack_report_notes.md saved locally
- [x] case05_memory_acquisition_and_integrity.md saved locally
- [x] case05_evidence_index.md saved locally
- [x] case05_commands_log.md saved locally
- [x] case05_dissertation_section.md saved locally
- [x] case05_final_checklist.md saved locally
- [x] case05_report_mapping.md saved locally
- [x] case05_artifact_schema.md saved locally
- [x] final_project_checklist.md saved locally
- [x] All documentation files have been checked after saving

## 15. Visual and Report Evidence
- [x] Case 05 dashboard screenshot exists
- [x] Case 05 command-line screenshot exists
- [x] Case 05 artifact summary screenshot exists
- [x] Cross-case comparison report exists
- [ ] Screenshots have been organised into final report figure selection

## 16. Report Readiness
- [x] Methodology evidence is ready
- [x] Implementation evidence is ready
- [x] Results evidence is ready
- [x] Discussion points are ready
- [x] Limitations are identified
- [x] Future work ideas are identified
- [x] The framework is complete for FYP scope
- [x] Major technical feature expansion can stop now

## 17. Optional Features
- [x] YARA can be left as future work
- [x] VirusTotal can be left as future work
- [x] Optional features are not required before dissertation writing

## 18. Final Freeze Decision
- [x] The framework is stable enough to freeze
- [x] The project is ready to move into report writing
- [ ] Local final cleanup has been completed
- [ ] Final documentation save-check has been completed
