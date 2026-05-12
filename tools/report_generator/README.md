# AURA Report Generator

This tool turns an AURA scan export into customer-readable reports. The
app-owner report is now release-risk first: it leads with P1/P2/P3/INFO
findings, a top fix plan, acceptance criteria, verification checks, owners, and
retest fingerprints. Runtime threat decision remains technical appendix context.

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

App-owner report mode focuses the report on one package, removes the rest of
the device inventory from the report surface, and builds a release-risk audit:

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

Public-surface teaser mode is for cold outreach/demo material. It is
target-scoped, automatically forces `redacted_teaser`, and intentionally
suppresses raw evidence, exact component names, evidence graph details, policy
trace detail, signing values, source paths, and exploitability detail:

```bash
python3 tools/report_generator/generate_report.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --evaluation artifacts/scenario_runner/evaluation.json \
  --report-type public_teaser \
  --target-package com.example.app \
  --client-name "Example Studio" \
  --public-app-name "Example Public App" \
  --public-source-url "https://play.google.com/store/apps/details?id=com.example.app" \
  --max-findings 3 \
  --out-dir artifacts/demos/example-app \
  --basename aura-public-teaser
```

Teaser reports must be manually reviewed before sending. They should be framed
as a sample of AURA's reporting structure, not as a vulnerability disclosure or
a final security verdict about the target app.

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
- `redacted_teaser`: high-level target-scoped outreach mode with raw evidence,
  component names, detailed decision trace, evidence graph, permission lists,
  and exact risk vector values suppressed.
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
- release readiness: `BLOCKED`, `NEEDS_FIXES`, `REVIEW_RECOMMENDED`, or `PASS`,
- top fix plan suitable for a CTO/release owner,
- release-risk findings with `P1`, `P2`, `P3`, and `INFO` priorities,
- stable finding fingerprints for retest comparison,
- acceptance criteria, remediation, verification check, owner, and
  manual-review guidance,
- release-risk retest diff.

The release-risk findings are the canonical customer task list. Supporting
runtime abuse context, capability/component summaries, offline analyzer rows,
observability limits, and reproducibility metadata are kept in the technical
appendix so they do not compete with the customer-facing fix plan.

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
