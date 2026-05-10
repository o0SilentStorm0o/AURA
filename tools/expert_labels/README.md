# Expert Labels

This directory defines the lightweight label format used by the evaluator and
scenario runner.

Labels are intentionally separate from the Android app. AURA exports raw
features and its own decision; expert labels are added later by controlled
scenario scripts or human reviewers.

Create a review packet from an export:

```bash
python3 tools/expert_labels/create_review_packet.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --csv artifacts/expert_review/review-packet.csv \
  --labels-template artifacts/expert_review/labels-template.json
```

The CSV is meant for human review. The labels template is intentionally marked
with `reviewStatus: UNLABELED`; the evaluator skips those rows until a reviewer
changes them to `REVIEWED` or `NEEDS_DISCUSSION` and fills in the label fields.

Validate a label file:

```bash
python3 tools/expert_labels/validate_labels.py artifacts/scenario_runner/scenario-labels.json
```

The validator checks schema shape and enum values only. It does not decide
whether a label is correct.
