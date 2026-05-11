# AURA Report Generator

This tool turns an AURA scan export into a customer-readable Android App Risk
and Defensive Surface report.

It intentionally has no heavy runtime dependency. It writes:

- Markdown, useful for review and version control.
- Print-ready self-contained HTML, useful for browser print/save-as-PDF.

Usage:

```bash
python3 tools/report_generator/generate_report.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --evaluation artifacts/scenario_runner/evaluation.json \
  --out-dir artifacts/reports \
  --basename aura-scenario-report
```

The report separates:

- threat decision from defensive posture,
- user-actionable alerts from BLUE platform audit findings,
- concrete evidence from no-root observability limits,
- AURA decisions from permission-only/capability-only baselines.

The HTML report can be opened in a browser and printed/saved as PDF. A future
renderer may automate PDF generation, but the report data model should remain
the same.

Unit tests:

```bash
python3 -m unittest tools/report_generator/test_generate_report.py
```
