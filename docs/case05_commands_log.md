 Case 05 – Commands Log

## 1. Python Environment
bash
source /MFF/venv/bin/activate
2. Comparison Engine Command
Copypython /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case05_multi_attack \
  --out      /MFF/analysis/comparison/case01_vs_case05 \
  --make-html --make-pdf
3. Previously Used Single-Case Comparison Commands
Case02
Copypython /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case02_t1055_5_attack \
  --out      /MFF/analysis/comparison/case01_vs_case02 \
  --make-html --make-pdf
Case03
Copypython /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case03_t1059_attack \
  --out      /MFF/analysis/comparison/case01_vs_case03 \
  --make-html --make-pdf
Case04
Copypython /MFF/src/comparison_engine_v2.py \
  --baseline /MFF/cases/case01_baseline \
  --attack   /MFF/cases/case04_t1574_attack \
  --out      /MFF/analysis/comparison/case01_vs_case04 \
  --make-html --make-pdf
4. Final Batch Command
Copypython /MFF/src/modules/automation.py batch \
  --baseline /MFF/cases/case01_baseline \
  --attacks  /MFF/cases/case02_t1055_5_attack \
             /MFF/cases/case03_t1059_attack \
             /MFF/cases/case04_t1574_attack \
             /MFF/cases/case05_multi_attack \
  --out-root /MFF/analysis/batch_run_final \
  --make-html --make-pdf
5. Cross-Case Comparison Command
Copypython /MFF/src/modules/automation.py compare \
  --batch-root /MFF/analysis/batch_run_final \
  --out        /MFF/analysis/batch_run_final/comparison_report \
  --make-html --make-pdf
6. Memory Acquisition Command
CopyVBoxManage debugvm "Windows 10" dumpvmcore --filename "D:\2.ROEHAMPTON\Final year\FYPROJECT\Memory forensics framework tools for analyse and visualisation\shared\T_multi.raw"
7. Hash Record
MD5: 8c4f8c763f78993b30b2ac4a230952a2
SHA1: 3d1825d640cbf425b54c83464eea9076ba251463
SHA256: a0983f4df938595db7ffdb377b743defdd02428f6b1d97b9f653821690a8f1d0
