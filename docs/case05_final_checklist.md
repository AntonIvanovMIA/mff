# Case 05 – Final Technical Checklist

## 1. Case Folder
- [ ] /MFF/cases/case05_multi_attack exists
- [ ] T_multi.raw exists in the Case 05 folder
- [ ] exports/csv exists
- [ ] exports/jsonl exists

## 2. Integrity and Evidence Preservation
- [ ] MD5 hash recorded
- [ ] SHA1 hash recorded
- [ ] SHA256 hash recorded
- [ ] Hash values added to /MFF/docs/hash_values.txt
- [ ] Memory image preserved as official Case 05 evidence file

## 3. Raw Volatility Outputs
- [ ] windows.info.csv
- [ ] windows.pslist.csv
- [ ] windows.pstree.csv
- [ ] windows.cmdline.csv
- [ ] windows.dlllist.csv
- [ ] windows.netscan.csv
- [ ] windows.malfind.csv
- [ ] windows.threads.csv

## 4. Processed Comparison Outputs
- [ ] process_new.csv
- [ ] process_gone.csv
- [ ] cmdline_findings.csv
- [ ] dll_hijack.csv
- [ ] malfind.csv
- [ ] net_new.csv
- [ ] net_flagged.csv
- [ ] iocs.csv
- [ ] attack_tags.csv
- [ ] scores.csv
- [ ] tactic_summary.csv
- [ ] timeline.csv
- [ ] threat_summary.json.txt

## 5. Final Reports
- [ ] report_interactive.html
- [ ] report_forensics.pdf

## 6. Core Analytical Checks
- [ ] suspicious PowerShell command-line activity confirmed
- [ ] hidden or bypass-style PowerShell execution confirmed
- [ ] encoded or staged PowerShell execution confirmed
- [ ] amsi.dll from non-standard path confirmed
- [ ] PAGE_EXECUTE_READWRITE memory regions confirmed
- [ ] high-confidence ATT&CK tagging confirmed
- [ ] CRITICAL risk-scored PowerShell processes confirmed

## 7. Documentation
- [ ] case05_multi_attack_report_notes.md completed
- [ ] case05_memory_acquisition_and_integrity.md completed
- [ ] case05_evidence_index.md completed
- [ ] case05_commands_log.md completed
- [ ] case05_dissertation_section.md completed
- [ ] case05_artifact_schema.md completed
- [ ] case05_report_mapping.md completed

## 8. Cross-Case Validation
- [ ] Case 02 comparison completed
- [ ] Case 03 comparison completed
- [ ] Case 04 comparison completed
- [ ] Case 05 comparison completed
- [ ] batch_summary.json.txt exists
- [ ] comparison_report.html exists
- [ ] comparison_report.pdf exists

## 9. Final Readiness
- [ ] Case 05 documentation is consistent with real commands used
- [ ] Case 05 findings are ready for report writing
- [ ] supporting screenshots are selected
- [ ] tables/figures for the final report are identified
