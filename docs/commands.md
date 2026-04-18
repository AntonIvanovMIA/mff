# ═══════════════════════════════════════════════════════════
# ALWAYS FIRST
# ═══════════════════════════════════════════════════════════
source /MFF/venv/bin/activate

# ═══════════════════════════════════════════════════════════
# CASE 02 — T1055.5 Process Injection
# ═══════════════════════════════════════════════════════════

python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case02_t1055_5_attack \
  --out      /MFF/analysis/comparison/case01_vs_case02 \
  --make-html --make-pdf

python /MFF/src/modules/automation.py analyse \
  --case /MFF/cases/case02_t1055_5_attack \
  --out  /MFF/analysis/single/case02 \
  --make-html --make-pdf

# ═══════════════════════════════════════════════════════════
# CASE 03 — T1059 PowerShell
# ═══════════════════════════════════════════════════════════

python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case03_t1059_attack \
  --out      /MFF/analysis/comparison/case01_vs_case03 \
  --make-html --make-pdf

python /MFF/src/modules/automation.py analyse \
  --case /MFF/cases/case03_t1059_attack \
  --out  /MFF/analysis/single/case03 \
  --make-html --make-pdf

# ═══════════════════════════════════════════════════════════
# CASE 04 — T1574 DLL Hijacking
# ═══════════════════════════════════════════════════════════

python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case04_t1574_attack \
  --out      /MFF/analysis/comparison/case01_vs_case04 \
  --make-html --make-pdf

python /MFF/src/modules/automation.py analyse \
  --case /MFF/cases/case04_t1574_attack \
  --out  /MFF/analysis/single/case04 \
  --make-html --make-pdf

# ═══════════════════════════════════════════════════════════
# CASE 05 — Multi-technique
# ═══════════════════════════════════════════════════════════

python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case05_multi_attack \
  --out      /MFF/analysis/comparison/case01_vs_case05 \
  --make-html --make-pdf

python /MFF/src/modules/automation.py analyse \
  --case /MFF/cases/case05_multi_attack \
  --out  /MFF/analysis/single/case05 \
  --make-html --make-pdf

# ═══════════════════════════════════════════════════════════
# BATCH — all 4 cases at once
# ═══════════════════════════════════════════════════════════

python /MFF/src/modules/automation.py batch \
  --baseline /MFF/cases/case01_baseline \
  --attacks  /MFF/cases/case02_t1055_5_attack \
             /MFF/cases/case03_t1059_attack \
             /MFF/cases/case04_t1574_attack \
             /MFF/cases/case05_multi_attack \
  --out-root /MFF/analysis/batch_run_final \
  --make-html --make-pdf

# ═══════════════════════════════════════════════════════════
# CROSS-CASE COMPARISON REPORT — run after batch
# ═══════════════════════════════════════════════════════════

python /MFF/src/modules/automation.py compare \
  --batch-root /MFF/analysis/batch_run_final \
  --out        /MFF/analysis/batch_run_final/comparison_report \
  --make-html --make-pdf

# ═══════════════════════════════════════════════════════════
# OPEN ALL REPORTS
# ═══════════════════════════════════════════════════════════

# Comparisons
firefox /MFF/analysis/comparison/case01_vs_case02/report_interactive.html
firefox /MFF/analysis/comparison/case01_vs_case03/report_interactive.html
firefox /MFF/analysis/comparison/case01_vs_case04/report_interactive.html
firefox /MFF/analysis/comparison/case01_vs_case05/report_interactive.html

# Standalone
firefox /MFF/analysis/single/case02/report_interactive.html
firefox /MFF/analysis/single/case03/report_interactive.html
firefox /MFF/analysis/single/case04/report_interactive.html
firefox /MFF/analysis/single/case05/report_interactive.html

# Cross-case
firefox /MFF/analysis/batch_run_final/comparison_report/comparison_report.html
