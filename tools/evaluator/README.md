# AURA Evaluator

The Android app exports raw features plus the full AURA decision.
This evaluator computes comparison baselines outside the app:

- permission-only
- capability-only
- role-aware
- role + provenance
- temporal
- full AURA

Usage:

```bash
python3 tools/evaluator/evaluate.py tests/fixtures/sample_export.json
```
