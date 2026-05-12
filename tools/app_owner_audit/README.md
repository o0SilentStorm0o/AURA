# AURA App Owner Audit Engine

This tool is the pivot from user-protection scoring to developer-facing release
risk.

The user/device threat engine answers:

```text
Is this installed app a user-actionable threat on this device?
```

The app-owner audit engine answers:

```text
What should this Android team fix or manually verify before release?
```

Input:

- a target-scoped AURA JSON export,
- optional offline APK analyzer JSON.

Output:

- release status: `BLOCKED`, `NEEDS_FIXES`, `REVIEW_RECOMMENDED`, or `PASS`,
- P1/P2/P3/INFO counts,
- release-risk findings with stable fingerprints,
- evidence source,
- why it matters,
- how to fix,
- how to verify,
- suggested owner,
- manual-review flag,
- secondary runtime abuse context.

Standalone usage:

```bash
python3 tools/app_owner_audit/audit_engine.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --offline-analysis artifacts/scenario_runner/offline-apk-analysis.json \
  --out artifacts/reports/aura-app-owner-audit.json
```

Normally this is invoked by the report generator:

```bash
python3 tools/report_generator/generate_report.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --report-type app_owner \
  --target-package com.example.app \
  --offline-analysis artifacts/scenario_runner/offline-apk-analysis.json \
  --out-dir artifacts/reports \
  --basename aura-app-owner-release-risk
```

Unit tests:

```bash
python3 -m unittest tools/app_owner_audit/test_audit_engine.py
```
