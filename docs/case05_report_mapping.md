# Case 05 – Report Mapping Guide

## 1. Methodology Chapter
The following Case 05 material belongs in the Methodology chapter:
- experimental environment summary
- attack execution design
- hypervisor-based memory acquisition method
- hashing and integrity verification
- Volatility export workflow
- baseline comparison approach
- enrichment and scoring workflow

Recommended subsection title:
### 3.X Case 05 Multi-Attack Scenario Method

## 2. Implementation Chapter
The following Case 05 material belongs in the Implementation chapter:
- how the framework consumed plugin outputs
- how comparison_engine_v2.py processed the case
- how suspicious command lines were matched
- how DLL anomalies were detected
- how malfind evidence was enriched
- how scoring and ATT&CK tagging were applied
- how HTML/PDF reports were generated

Recommended subsection title:
### 4.X Implementation of the Multi-Attack Analysis Pipeline

## 3. Results Chapter
The following Case 05 material belongs in the Results chapter:
- executive summary metrics
- key suspicious PowerShell processes
- ATT&CK tactics and techniques detected
- DLL anomaly results
- malfind/RWX results
- process delta observations
- IOC totals
- severity interpretation

Recommended subsection title:
### 5.X Results of Case 05 Multi-Attack Analysis

## 4. Discussion Chapter
The following Case 05 material belongs in the Discussion chapter:
- why Case 05 produced the strongest coverage
- why correlation was stronger than single-plugin review
- why baseline drift introduced noise
- what this means for forensic interpretation
- strengths and limitations of the framework

Recommended subsection title:
### 6.X Discussion of Multi-Technique Correlation and Baseline Limitations

## 5. Appendix
The following Case 05 material belongs in the Appendix:
- exact commands used
- full hash record
- file listings
- extended tables
- screenshot collection
- selected raw output samples

Recommended appendix entries:
- Appendix A: Case 05 command log
- Appendix B: Case 05 hash and integrity record
- Appendix C: Selected Case 05 evidence excerpts

## 6. Suggested Figures
- Figure: Case 05 attack workflow overview
- Figure: suspicious command-line evidence
- Figure: dashboard summary for Case 05
- Figure: DLL anomaly showing staged amsi.dll path
- Figure: risk-score comparison for critical PowerShell processes

## 7. Suggested Tables
- Table: Case 05 objectives and attack actions
- Table: Case 05 plugin outputs and analytical purpose
- Table: Case 05 key findings and interpretation
- Table: Case 05 ATT&CK technique coverage
- Table: Case 05 limitations and mitigation notes
