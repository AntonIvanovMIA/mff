# MFF v2 — Correct Commands Reference
# Cases: case01_baseline | case02_t1055_5_attack | case03_t1059_attack
# Week 4 pending: case04_t1574_attack | case05_multi_attack

# ─────────────────────────────────────────────────
# SINGLE COMPARISON  (one baseline vs one attack)
# ─────────────────────────────────────────────────

# case01 vs case02 (T1055.5 process injection)
python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case02_t1055_5_attack \
  --out      /MFF/analysis/comparison/case01_vs_case02 \
  --make-html

# case01 vs case03 (T1059 scripting)
python /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case03_t1059_attack \
  --out      /MFF/analysis/comparison/case01_vs_case03 \
  --make-html

# ─────────────────────────────────────────────────
# BATCH  (baseline vs all ready attack cases)
# ─────────────────────────────────────────────────

# NOW (Week 3) — only case02 and case03 exist
python /MFF/src/modules/automation.py batch \
  --baseline /MFF/cases/case01_baseline \
  --attacks  /MFF/cases/case02_t1055_5_attack \
             /MFF/cases/case03_t1059_attack \
  --out-root /MFF/analysis/batch_run_01 \
  --make-html

# WEEK 4 — after case04 and case05 exports are generated
python /MFF/src/modules/automation.py batch \
  --baseline /MFF/cases/case01_baseline \
  --attacks  /MFF/cases/case02_t1055_5_attack \
             /MFF/cases/case03_t1059_attack \
             /MFF/cases/case04_t1574_attack \
             /MFF/cases/case05_multi_attack \
  --out-root /MFF/analysis/batch_run_02 \
  --make-html

# ─────────────────────────────────────────────────
# DASHBOARD  (view results after analysis)
# ─────────────────────────────────────────────────

python /MFF/src/mff_dashboard.py \
  --out /MFF/analysis/comparison/case01_vs_case02

python /MFF/src/mff_dashboard.py \
  --out /MFF/analysis/comparison/case01_vs_case03

# ─────────────────────────────────────────────────
# VOL3 RUNNER  (generate exports from .vmem image)
# Run this FIRST before any comparison — Week 4
# ─────────────────────────────────────────────────

python /MFF/src/modules/automation.py vol3 \
  --image /MFF/images/case04_t1574.vmem \
  --out   /MFF/cases/case04_t1574_attack

python /MFF/src/modules/automation.py vol3 \
  --image /MFF/images/case05_multi.vmem \
  --out   /MFF/cases/case05_multi_attack

# ─────────────────────────────────────────────────
# WATCHDOG  (auto-analyse new cases as they appear)
# ─────────────────────────────────────────────────

python /MFF/src/modules/automation.py watchdog \
  --watch-dir /MFF/cases \
  --baseline  /MFF/cases/case01_baseline \
  --out-root  /MFF/analysis/auto \
  --engine    /MFF/src/comparison_engine_v2.py \
  --make-html \
  --interval  15
