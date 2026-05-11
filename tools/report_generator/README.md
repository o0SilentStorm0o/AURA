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

Device/expert report is the default. It summarizes the visible inventory,
priority RED/YELLOW/BLUE items, grouped GRAY abstentions, defensive posture
highlights, temporal episodes, baseline comparison, and observability limits.

App-owner report mode focuses the report on one package and removes the rest of
the device inventory from the report surface:

```bash
python3 tools/report_generator/generate_report.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --report-type app_owner \
  --target-package com.example.app \
  --out-dir artifacts/reports \
  --basename aura-app-owner-report
```

For a before/after remediation review, pass a previous export:

```bash
python3 tools/report_generator/generate_report.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --report-type app_owner \
  --target-package com.example.app \
  --previous-export artifacts/scenario_runner/aura-baseline-scan.json \
  --out-dir artifacts/reports \
  --basename aura-app-owner-retest
```

App-owner reports can also include static/offline APK analyzer evidence:

```bash
python3 tools/report_generator/generate_report.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --report-type app_owner \
  --target-package com.example.app \
  --offline-analysis artifacts/scenario_runner/offline-apk-analysis.json \
  --previous-export artifacts/scenario_runner/aura-baseline-scan.json \
  --previous-offline-analysis artifacts/scenario_runner/offline-apk-analysis-before.json \
  --out-dir artifacts/reports \
  --basename aura-app-owner-offline-report
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

App-owner reports additionally include:

- target-app scope and environment,
- capability/component surface summary,
- defensive finding IDs (`AURA-DEF-###`),
- broad OWASP MASVS/MASTG review-area mapping,
- offline APK analyzer findings with `OFFLINE_APK_ANALYZER` source labels,
- remediation checklist with workflow status markers,
- optional before/after retest comparison.

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
