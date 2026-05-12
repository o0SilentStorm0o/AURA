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
- optional customer/app profile JSON.

Policy flow:

```text
raw evidence + app profile + policy packs = ReleaseRiskFinding
```

Policy ladder:

```text
base_android_release_policy
→ category policy
→ release-stage policy
→ optional custom policy packs
→ customer profile overrides
→ accepted risks / not-applicable decisions
```

Custom policy packs supplied through `--policy-pack` are additive. They do not
replace the base/category/stage ladder. Every rule match and customer override is
recorded in `policyTrace`.

The canonical app-owner output is `ReleaseRiskFinding` plus customer-facing
`FindingGroup`. Device threat decision, on-device defensive rows, and offline
analyzer rows are supporting evidence, not parallel customer task lists.

Aggregate exported-component evidence is split into component-level findings so
real-world reports can become tickets instead of one long manifest string. A
rule-based component classifier then assigns classes such as
`PAYMENT_REDIRECT`, `AUTH_CALLBACK`, `DEEPLINK_ROUTER`, `WEBVIEW_ENTRYPOINT`,
`SDK_CALLBACK`, `PUSH_SERVICE`, `ANALYTICS_RECEIVER`, `PREVIEW_OR_TOOLING`,
`CUSTOMER_DATA_FLOW`, or `UNKNOWN_EXPORTED_SURFACE`. Findings are grouped into
review areas such as payment/account flow, app routing/WebView, preview tooling,
and third-party SDK surfaces. Raw component findings stay in the technical
appendix.

Output:

- release status: `BLOCKED`, `NEEDS_FIXES`, `REVIEW_RECOMMENDED`, or `PASS`,
- P1/P2/P3/INFO counts,
- release-risk findings with stable fingerprints,
- grouped top review areas with evidence strength and exploitability caveats,
- group-level acceptance criteria and verification checks, so payment, SDK,
  WebView/routing, preview/tooling, backup, and network areas do not inherit
  overly mechanical component-level remediation text,
- finding status: `BLOCKER`, `SHOULD_FIX`, `REVIEW`, `INFO`,
  `ACCEPTED_RISK`, or `NOT_APPLICABLE`,
- evidence source,
- app profile impact,
- acceptance criteria,
- why it matters,
- how to fix,
- verification command/check,
- suggested owner,
- manual-review flag,
- secondary runtime abuse context.
- policy quality metrics for tuning blocker density, actionability, manual
  review rate, grouped-finding reduction, and accepted-risk recurrence.

The component classifier catalog lives in
`tools/app_owner_audit/component_surface_catalog.json`. It is conservative:
classification explains review context; it does not prove exploitability.

Customer-facing group summaries should describe the customer's release-review
area, not the report mechanics. Avoid copy such as "AURA has grouped..." in
deliverables; raw component rows remain available in the technical appendix.

Standalone usage:

```bash
python3 tools/app_owner_audit/audit_engine.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --offline-analysis artifacts/scenario_runner/offline-apk-analysis.json \
  --app-profile tools/app_owner_audit/profiles/fintech_high_sensitivity.example.json \
  --out artifacts/reports/aura-app-owner-audit.json
```

Normally this is invoked by the report generator:

```bash
python3 tools/report_generator/generate_report.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --report-type app_owner \
  --target-package com.example.app \
  --offline-analysis artifacts/scenario_runner/offline-apk-analysis.json \
  --app-profile tools/app_owner_audit/profiles/fintech_high_sensitivity.example.json \
  --out-dir artifacts/reports \
  --basename aura-app-owner-release-risk
```

Built-in policy packs live in `tools/app_owner_audit/policies/`:

- `base_android_release_policy.json`
- `fintech_policy.json`
- `health_policy.json`
- `ecommerce_policy.json`
- `public_info_policy.json`
- `internal_enterprise_policy.json`
- `sdk_library_policy.json`
- `debug_build_policy.json`
- `production_release_policy.json`

Example profiles live in `tools/app_owner_audit/profiles/`. A customer can also
mark expected surfaces through `knownExportedComponents`, scope cleartext via
`allowedCleartextDomains`, or suppress already-decided items through
`acceptedRisks`.

Status semantics:

- `BLOCKER`: do not ship until fixed or explicitly accepted.
- `SHOULD_FIX`: fix before production unless a reviewer accepts the trade-off.
- `REVIEW`: AURA needs human context; this is not automatically a bug.
- `INFO`: context only.
- `ACCEPTED_RISK`: customer explicitly accepts it and the item stays traceable.
- `NOT_APPLICABLE`: customer/reviewer decided the item does not apply.

Fallback findings use `UNCLASSIFIED_RELEASE_REVIEW_FINDING`. If this appears
often for a customer segment, promote it into a specific evidence type and policy
rule instead of letting vague review items accumulate.

Unit tests:

```bash
python3 -m unittest tools/app_owner_audit/test_audit_engine.py
```
