# Expert Labels

This directory defines the lightweight label format used by the evaluator and
scenario runner.

Labels are intentionally separate from the Android app. AURA exports raw
features and its own decision; expert labels are added later by controlled
scenario scripts or human reviewers.

Validate a label file:

```bash
python3 tools/expert_labels/validate_labels.py artifacts/scenario_runner/scenario-labels.json
```

The validator checks schema shape and enum values only. It does not decide
whether a label is correct.
