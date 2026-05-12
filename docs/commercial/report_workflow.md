# AURA Report Workflow

AURA should not be sold first as a consumer antivirus app. The near-term
commercial artifact is an evidence-backed Android App Owner Release Risk
report. For developer/customer delivery, threat decision is secondary context;
release-risk findings are the product.

## Report Offer

Suggested first offer:

- Android App Owner Release Risk Report
- fixed scope for one APK or one controlled device export
- PDF/HTML report plus JSON appendix
- privacy mode selected for the audience:
  `full_research` for trusted local research, `redacted_expert` for external
  expert review, `redacted_teaser` for cold outreach/public-surface demos, or
  `minimal_support` for support-style sharing without full inventory
- optional retest after fixes

The report is not a malware guarantee and not a replacement for a full mobile
pentest. It is a no-root, role-normalized, provenance-aware triage and
explainability layer.

## App-Owner Output Contract

The app-owner report should answer:

```text
What should this Android team fix or manually verify before release?
```

It should be policy-driven:

```text
normalized evidence + app profile + build context + policy pack = release-risk finding
```

It should not lead with:

```text
Threat decision: GREEN
```

It should lead with:

```text
Release readiness: BLOCKED / NEEDS_FIXES / REVIEW_RECOMMENDED / PASS
P1 blocker findings: N
P2 should-fix findings: N
P3 review findings: N
Retest recommended: yes/no
```

Each release-risk finding includes:

- stable `id` and `fingerprint`,
- type and title,
- priority: `P1`, `P2`, `P3`, or `INFO`,
- confidence,
- evidence source,
- acceptance criteria,
- why it matters,
- how to fix,
- verification command/check,
- suggested owner,
- whether manual review is required.

The app-owner report must have one canonical task list: grouped release-risk
review areas. Raw `ReleaseRiskFinding` rows remain the source of truth and
belong in the technical appendix. Older AURA surfaces such as device threat
decision, defensive posture summaries, offline analyzer rows, policy versions,
and raw observability detail belong in the technical appendix. They must not
become a second competing checklist for the customer.

For component-heavy apps, AURA should group findings before customer delivery:

- payment/account flow entry points,
- deep link / WebView routing entry points,
- preview/tooling surfaces,
- third-party SDK exported surfaces,
- other app-owned exported surfaces only when no better class exists.

Each group must show evidence strength and caveat language:

```text
Evidence strength: Manifest-level only
Exploitability: Not proven
Needs: APK offline analysis / source review / dynamic test
```

Optional LLM/RAG wording can be used after policy evaluation. It may summarize
groups and suggest review questions, but it must not create findings, change
priority/status, or cite evidence outside the audit JSON.

Current local runtime standard:

```text
native macOS Ollama + Metal
model: qwen2.5:3b
embedding: nomic-embed-text
retrieval: local Qdrant bound to 127.0.0.1
```

The LLM is a wording assistant, not an adjudicator. Strict mode validates
`groupId`, `findingIds`, and `doc_id` references, treats app labels/package
names/component names/evidence strings as untrusted prompt-injection surface,
and rejects customer-hostile copy such as report-mechanics phrasing,
unsupported vulnerability/exploit claims, "unsafe", "guarantee", or first-person
"our app" wording.

## App Profile

Every app-owner audit should receive an app/customer profile where possible.
When no profile is provided, AURA uses a conservative generic utility profile.

Example:

```json
{
  "appCategory": "fintech",
  "dataSensitivity": "high",
  "releaseStage": "production_candidate",
  "distribution": "google_play",
  "authFlow": true,
  "payments": true,
  "webviewUsageExpected": false,
  "externalIntegrationsExpected": true,
  "allowedCleartextDomains": [],
  "knownExportedComponents": [
    "com.example.PaymentCallbackActivity"
  ],
  "acceptedRisks": []
}
```

Policy packs live under `tools/app_owner_audit/policies/`. The base Android
policy is always applied, then profile/category policy and build-stage policy
adjust priority, status, owner, manual-review requirement, acceptance criteria,
and profile impact.

Policy ladder:

```text
base Android release policy
→ category policy
→ release-stage policy
→ optional additive customer policy packs
→ customer profile overrides
→ accepted risks / not-applicable decisions
```

The last two layers must leave a `policyTrace`. A known exported component is
not a pass; it is downgraded to `REVIEW` unless there is a separate accepted
risk. Accepted risks remain visible in a dedicated section so repeat audits do
not reintroduce the same finding as new noise.

## Policy Quality Metrics

Track these after each report:

- `blockerDensity`: P1 findings per target app. Healthy apps should usually
  have 0-2; broken fixtures can have more.
- `actionableRate`: customer-visible findings with fix, verification, and
  acceptance criteria.
- `manualReviewRate`: how much of the report needs a human reviewer.
- `acceptedRiskRecurrence`: accepted items retained for traceability.
- `retestResolutionRate`: fixed findings divided by fixed plus remaining
  findings when a previous audit is supplied.
- `ctoNoiseScore`: manual pilot feedback. Ask which three findings felt least
  useful, then downgrade, suppress, or specialize the policy.

Every recurring rule in `tools/app_owner_audit/policies/` should have a test in
`tools/app_owner_audit/test_audit_engine.py` covering default priority,
category/build-stage override, accepted risk behavior, and fingerprint stability
where applicable.

## Required Inputs

- APK or AURA device export
- intended app role or product category
- target Android version when known
- app profile intake from `docs/commercial/app_profile_intake.md`
- optional evaluator output for baseline comparison

## Output Sections

- release readiness
- top fix plan
- top review areas / finding groups
- release-risk findings in the technical appendix
- release-risk retest diff
- methodology and privacy stance
- technical appendix with runtime abuse context as secondary context
- report privacy mode and export-sharing warning
- technical appendix with capability/component surface summary, offline APK
  analyzer evidence, observability limits, and concise reproducibility metadata
- accepted risks / not-applicable items when supplied in the profile

Before sending the report, run
`docs/commercial/pre_send_triage_checklist.md`.

## Real-World Validation

Do not treat fixture reports as commercial proof. Before outreach, run the
real-world validation harness against a scan with public apps:

```bash
python3 tools/real_world_validation/validate_real_world.py \
  artifacts/real_world_validation/live/aura-last-scan.json
```

This generates one app-owner report per configured target and an internal
summary that classifies findings as:

- valuable,
- manual review,
- needs SDK/customer context,
- trivial context,
- noise risk.

Use the summary to decide whether a target is:

- a strong teaser candidate,
- a useful negative control,
- a stress case requiring manual triage,
- or evidence that policy tuning/offline APK analysis needs more work.

## Public-Surface Teaser

For first contact, use a public-surface teaser rather than a full audit.

The teaser is intentionally narrow:

- public Google Play build only,
- no target-app login,
- no payment, health, bank, or account workflow,
- no root, Frida, MITM, TLS interception, exploit attempt, or protection bypass,
- no screen contents, notification contents, keystrokes, or network payloads,
- no exact exported component names or raw manifest evidence,
- no full device inventory.

Generate a teaser from an existing AURA export:

```bash
python3 tools/public_demo/create_teaser_report.py \
  artifacts/public-demo/first-wave/aura-last-scan.json \
  gastromapa \
  --evaluation artifacts/scenario_runner/evaluation.json
```

The active first-wave public-demo targets are configured in
`tools/public_demo/targets.json`:

- `gastromapa` for Futured,
- `bikeflip` for Pixelmate,
- `bistro` for GoodRequest,
- `isnemovna` for Ackee.

Do not keep unsupported, abandoned, or unavailable apps in the active outreach
list. Dudelo was intentionally removed from this first-wave target set.

The teaser should say:

```text
This is a sample of the reporting structure AURA can produce.
Full technical findings require authorization and preferably a test build.
```

It should not say:

```text
We found a vulnerability.
Your app is unsafe.
This is proof of compromise.
```

## Positioning

Use:

```text
Explainable Android app risk report.
No-root, evidence-backed, role-normalized assessment.
```

Avoid:

```text
Android antivirus
Play Protect replacement
malware guarantee
kernel or forensic EDR
```
