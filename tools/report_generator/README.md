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
the device inventory from the report surface, and builds a policy-driven
release-risk audit:

```bash
python3 tools/report_generator/generate_report.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --report-type app_owner \
  --target-package com.example.app \
  --app-profile tools/app_owner_audit/profiles/fintech_high_sensitivity.example.json \
  --out-dir artifacts/reports \
  --basename aura-app-owner-report
```

For a before/after remediation review, pass a previous export:

```bash
python3 tools/report_generator/generate_report.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --report-type app_owner \
  --target-package com.example.app \
  --app-profile tools/app_owner_audit/profiles/fintech_high_sensitivity.example.json \
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
  --app-profile tools/app_owner_audit/profiles/fintech_high_sensitivity.example.json \
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

For target-scoped app-owner reports, the audit engine evaluates the internal
unredacted scoped export first, then the report renderer applies the selected
privacy mode. This preserves component classification/grouping quality while
keeping package identifiers, labels, source paths, raw evidence, and component
names redacted in shared reports.

The report separates:

- threat decision from defensive posture,
- user-actionable alerts from BLUE platform audit findings,
- concrete evidence from no-root observability limits,
- provenance trust/explainability from provenance classification confidence,
- AURA decisions from permission-only/capability-only baselines.

App-owner reports additionally include:

- target-app scope and environment,
- app/customer profile and applied policy packs,
- release readiness: `BLOCKED`, `NEEDS_FIXES`, `REVIEW_RECOMMENDED`, or `PASS`,
- top fix plan suitable for a CTO/release owner,
- top review areas / finding groups so a large SDK-heavy app is summarized as
  a few release-risk stories instead of a long manifest-component dump,
- release-risk findings with `P1`, `P2`, `P3`, and `INFO` priorities in the
  technical appendix,
- component classification and evidence strength for each group/finding,
- finding status: `BLOCKER`, `SHOULD_FIX`, `REVIEW`, `INFO`,
  `ACCEPTED_RISK`, or `NOT_APPLICABLE`,
- stable finding fingerprints for retest comparison,
- app profile impact, acceptance criteria, remediation, verification check,
  owner, and manual-review guidance,
- release-risk retest diff,
- accepted risks / not-applicable items when supplied by the app profile,
- policy quality metrics for blocker density, actionability, manual-review
  rate, grouped-finding reduction, and accepted-risk recurrence.

Optional host-side LLM/RAG wording can be generated separately and passed into
the report. The LLM layer can rewrite group summaries and review questions, but
it cannot create findings, change priorities, or add evidence:

```bash
python3 tools/app_owner_audit/audit_engine.py \
  artifacts/scenario_runner/aura-last-scan.scoped.json \
  --app-profile tools/app_owner_audit/profiles/ecommerce_marketplace.example.json \
  --out artifacts/reports/aura-audit.json

python3 tools/llm_summary/llm_summary.py \
  artifacts/reports/aura-audit.json \
  --out artifacts/reports/aura-group-summary.json \
  --llm-mode strict \
  --local-llm-url http://localhost:11434 \
  --model qwen2.5:3b \
  --qdrant-url http://localhost:6333 \
  --embedding-url http://localhost:11434 \
  --embedding-model nomic-embed-text \
  --embedding-mode ollama \
  --llm-timeout-seconds 180

python3 tools/report_generator/generate_report.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --report-type app_owner \
  --target-package com.example.app \
  --app-profile tools/app_owner_audit/profiles/ecommerce_marketplace.example.json \
  --group-summary-json artifacts/reports/aura-group-summary.json \
  --out-dir artifacts/reports \
  --basename aura-app-owner-report
```

The supported local LLM runtime is native macOS Ollama with Metal acceleration
and `qwen2.5:3b`. Qdrant should be local-only, for example
`-p 127.0.0.1:6333:6333` when using Docker. Model downloads need network
access once; customer report generation should run against local models and
local RAG docs.

The release-risk findings are the canonical customer task list. Supporting
runtime abuse context, capability/component summaries, offline analyzer rows,
observability limits, and reproducibility metadata are kept in the technical
appendix so they do not compete with the customer-facing fix plan.

The LLM/RAG payload is optional. It is only allowed to rewrite the existing
group summaries and review questions; the report generator still renders the
policy-engine `ReleaseRiskFinding` and `FindingGroup` objects as the source of
truth.

Custom policy packs passed to the app-owner audit engine are additive. The
report shows the full ladder of applied policy packs, and each finding keeps a
`policyTrace` so customer profile overrides and accepted risks remain auditable.

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
