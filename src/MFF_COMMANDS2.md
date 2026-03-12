# MFF v2 — Command Reference
# Cases ready now : case01_baseline | case02_t1055_5_attack | case03_t1059_attack
# Week 4 pending  : case04_t1574_attack | case05_multi_attack
# Last updated    : 2026-03-11  (all bugs fixed, PDF working, ATT&CK FP rules fixed)

# ══════════════════════════════════════════════════════════════
# SINGLE COMPARISON
# ══════════════════════════════════════════════════════════════

# case01 vs case02  (T1055.5 — Process Injection)
python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case02_t1055_5_attack \
  --out      /MFF/analysis/comparison/case01_vs_case02 \
  --make-html --make-pdf

# case01 vs case03  (T1059 — PowerShell / Scripting)  ← CURRENT
python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case03_t1059_attack \
  --out      /MFF/analysis/comparison/case01_vs_case03 \
  --make-html --make-pdf

# ── Optional flags ────────────────────────────────────────────
#   --make-html          generate interactive HTML report
#   --make-pdf           generate professional PDF report
#   --no-csv             skip CSV exports (faster, charts + reports only)
#   --case-id  MY_ID     override auto-generated case ID string
#   --webhook  URL       send JSON alert to Slack / SIEM webhook
#   --webhook-mode slack  or  generic  (default: generic)


# ══════════════════════════════════════════════════════════════
# DASHBOARD  (terminal view of results after comparison)
# ══════════════════════════════════════════════════════════════

python /MFF/src/mff_dashboard.py \
  --out /MFF/analysis/comparison/case01_vs_case02

python /MFF/src/mff_dashboard.py \
  --out /MFF/analysis/comparison/case01_vs_case03

# Live-reload every 10s (useful during batch runs)
python /MFF/src/mff_dashboard.py \
  --out      /MFF/analysis/comparison/case01_vs_case03 \
  --watch \
  --interval 10


# ══════════════════════════════════════════════════════════════
# BATCH  (baseline vs multiple attack cases in one go)
# ══════════════════════════════════════════════════════════════

# NOW — Week 3  (case02 + case03 only)
python /MFF/src/modules/automation.py batch \
  --baseline /MFF/cases/case01_baseline \
  --attacks  /MFF/cases/case02_t1055_5_attack \
             /MFF/cases/case03_t1059_attack \
  --out-root /MFF/analysis/batch_run_01 \
  --make-html --make-pdf

# WEEK 4 — after case04 and case05 exports are generated
python /MFF/src/modules/automation.py batch \
  --baseline /MFF/cases/case01_baseline \
  --attacks  /MFF/cases/case02_t1055_5_attack \
             /MFF/cases/case03_t1059_attack \
             /MFF/cases/case04_t1574_attack \
             /MFF/cases/case05_multi_attack \
  --out-root /MFF/analysis/batch_run_02 \
  --make-html --make-pdf


# ══════════════════════════════════════════════════════════════
# VOL3 RUNNER  (generate CSV exports from raw .vmem image)
# Run BEFORE comparison — Week 4 only
# ══════════════════════════════════════════════════════════════

python /MFF/src/modules/automation.py vol3 \
  --image /MFF/images/case04_t1574.vmem \
  --out   /MFF/cases/case04_t1574_attack

python /MFF/src/modules/automation.py vol3 \
  --image /MFF/images/case05_multi.vmem \
  --out   /MFF/cases/case05_multi_attack

# ── Week 4 full pipeline (vol3 → comparison → reports) ───────
python /MFF/src/modules/automation.py vol3 \
  --image /MFF/images/case04_t1574.vmem \
  --out   /MFF/cases/case04_t1574_attack \
&& \
python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case04_t1574_attack \
  --out      /MFF/analysis/comparison/case01_vs_case04 \
  --make-html --make-pdf


# ══════════════════════════════════════════════════════════════
# WATCHDOG  (auto-analyse new cases as they drop into /cases)
# ══════════════════════════════════════════════════════════════

python /MFF/src/modules/automation.py watchdog \
  --watch-dir /MFF/cases \
  --baseline  /MFF/cases/case01_baseline \
  --out-root  /MFF/analysis/auto \
  --engine    /MFF/src/comparison_engine_v2.py \
  --make-html --make-pdf \
  --interval  15


# ══════════════════════════════════════════════════════════════
# OUTPUT FILES  (generated per comparison run)
# ══════════════════════════════════════════════════════════════
#
#  report_interactive.html       <- open in browser, filterable tables
#  report_forensics.pdf          <- professional PDF, all charts + tables
#  threat_summary.json           <- SIEM / Elastic ECS export
#  dashboard.png                 <- full visual dashboard
#  chart_process_counts.png
#  chart_risk_scores.png
#  chart_timeline.png
#  chart_process_tree.png
#  chart_attack_heatmap.png
#  chart_cmdline_patterns.png
#  chart_malfind_protection.png
#  process_new.csv
#  process_gone.csv
#  scores.csv
#  cmdline_findings.csv
#  malfind.csv
#  attack_tags.csv
#  tactic_summary.csv
#  iocs.csv
#  net_new.csv
#  net_flagged.csv
#  timeline.csv


# ══════════════════════════════════════════════════════════════
# WEEK PLAN REMINDER
# ══════════════════════════════════════════════════════════════
#
#  Week 3 (NOW)  -> comparison case01 vs case02, case01 vs case03
#  Week 4        -> vol3 run on case04 + case05, batch_run_02
#  Week 5-8      -> evaluation, write-up, charts for FYP report
#  May 3 2026    -> FYP submission deadline
#  May 4-10      -> buffer for DOCX report
