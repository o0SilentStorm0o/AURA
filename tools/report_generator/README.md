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

For customer or external expert sharing, generate reports through a privacy
mode:

```bash
python3 tools/report_generator/generate_report.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --evaluation artifacts/scenario_runner/evaluation.json \
  --privacy-mode redacted_expert \
  --salt customer-or-project-salt \
  --redacted-export-out artifacts/reports/aura-scenario-report.redacted.json \
  --out-dir artifacts/reports \
  --basename aura-scenario-report
```

Supported modes:

- `full_research`: complete local export, suitable only for trusted research.
- `redacted_expert`: full evidence/report structure with package identifiers,
  labels, source paths, component names, installers, and signing digests
  redacted.
- `minimal_support`: aggregate counts plus priority-only redacted assessment
  details, without full package inventory.

The report separates:

- threat decision from defensive posture,
- user-actionable alerts from BLUE platform audit findings,
- concrete evidence from no-root observability limits,
- provenance trust/explainability from provenance classification confidence,
- AURA decisions from permission-only/capability-only baselines.

HTML output is generated without JavaScript, escapes app-provided strings, and
includes a restrictive Content-Security-Policy meta tag. This matters because
package labels and evidence strings can be attacker-controlled.

The HTML report can be opened in a browser and printed/saved as PDF. A future
renderer may automate PDF generation, but the report data model should remain
the same.

Unit tests:

```bash
python3 -m unittest tools/report_generator/test_generate_report.py
```
