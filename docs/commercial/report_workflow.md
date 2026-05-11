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
  expert review, or `minimal_support` for support-style sharing without full
  inventory
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
