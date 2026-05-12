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

The app-owner report must have one canonical task list: `Release Risk
Findings`. Older AURA surfaces such as device threat decision, defensive posture
summaries, offline analyzer rows, policy versions, and raw observability detail
belong in the technical appendix. They must not become a second competing
checklist for the customer.

## Required Inputs

- APK or AURA device export
- intended app role or product category
- target Android version when known
- optional evaluator output for baseline comparison

## Output Sections

- release readiness
- top fix plan
- release-risk findings
- release-risk retest diff
- methodology and privacy stance
- technical appendix with runtime abuse context as secondary context
- report privacy mode and export-sharing warning
- technical appendix with capability/component surface summary, offline APK
  analyzer evidence, observability limits, and concise reproducibility metadata

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
