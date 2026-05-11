# AURA Report Workflow

AURA should not be sold first as a consumer antivirus app. The near-term
commercial artifact is an evidence-backed Android App Risk and Defensive
Surface report.

## Report Offer

Suggested first offer:

- Android App Risk & Defensive Surface Report
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

## Required Inputs

- APK or AURA device export
- intended app role or product category
- target Android version when known
- optional evaluator output for baseline comparison

## Output Sections

- executive summary
- methodology and privacy stance
- threat decision overview
- baseline comparison
- report privacy mode and export-sharing warning
- priority app findings
- defensive posture highlights
- temporal episodes
- observability limits
- appendix metadata

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
