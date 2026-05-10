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

Controlled scenario labels can be supplied when ground truth is available:

```bash
python3 tools/evaluator/evaluate.py artifacts/scenario_runner/aura-last-scan.json \
  --labels artifacts/scenario_runner/scenario-labels.json \
  --out artifacts/scenario_runner/evaluation.json
```

When labels are present, the main research metrics are computed over the
labelled population instead of every package visible on the emulator.
