# AURA Real-World Validation

This harness tests whether AURA is commercially useful on normal public apps,
not only on intentionally broken fixture APKs.

It answers:

```text
Can AURA reduce a real app's noisy metadata into a small, useful release-risk
conversation?
```

Run it against a real AURA scan export:

```bash
python3 tools/real_world_validation/validate_real_world.py \
  artifacts/public-demo/first-wave/aura-last-scan.json
```

Outputs:

- `artifacts/real_world_validation/validation-summary.md`
- `artifacts/real_world_validation/validation-results.json`
- one app-owner report per validation target under
  `artifacts/real_world_validation/reports/`

The harness now scores both raw findings and grouped review areas. This matters
for real apps: a target with 19 exported component findings may still be
customer-readable if those collapse into 4-5 meaningful review areas such as
payment/account flow, app routing/WebView, preview tooling, and third-party SDK
surfaces.

Classification buckets:

- `valuable`: likely useful release-risk conversation, such as auth/payment,
  cleartext, backup, WebView, secrets, or deep-link review.
- `manual_review`: valid but not yet customer-ready without human context.
- `needs_context`: often SDK/integration-driven component surface.
- `trivial_context`: INFO-only context.
- `noise_risk`: unclassified or too broad for a customer report.

The summary intentionally calls out AURA weaknesses, for example:

- too many customer-visible review areas,
- SDK component context needed,
- manual-review-heavy output,
- low-wow negative-control reports.

This is the place to decide whether a report is a good sales demo, a good
negative control, or evidence that policy/reporting needs more tuning.
