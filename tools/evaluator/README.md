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

The output includes three levels:

- `metrics`: headline AURA metrics used by the scenario runner.
- `modelMetrics`: per-model rates for permission-only, capability-only,
  role-aware, role+provenance, temporal, and full AURA.
- `comparisons`: deltas that quantify how much full AURA changes key metrics
  versus permission-only.
- `rows[].evidenceGraphNodeCount` and `rows[].evidenceGraphEdgeCount`:
  structural checks that exported decisions remain decomposable into graph
  evidence.
- `rows[].decisionTracePolicyVersion`,
  `rows[].decisionTraceMatchedRuleCount`, and
  `metrics.decision_trace_completeness`: checks that decisions include a
  replayable trace and user-facing risk story.
- `rows[].defensivePostureClass`: separates threat decisions from defensive
  surface posture.

Labelled defensive-surface expectations are reported with
`defensive_surface_recall`. These evaluate top-level
`defensiveSurfaceFindings`, not the primary threat decision.

Evaluator unit tests can be run with:

```bash
python3 -m unittest tools/evaluator/test_evaluate.py
```
