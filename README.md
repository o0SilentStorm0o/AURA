# AURA

AURA is a research-first Android security agent prototype:

**Actionable, Uncertainty-aware, Role-normalized Android Security Agent**

It is not a permission scanner with a single risk score. AURA separates:

- capability exposure
- role legitimacy
- provenance confidence
- abuse evidence
- user actionability
- uncertainty

The default MVP target is:

```bash
sh gradlew :app:assembleResearchFullStandardDebug
sh gradlew :app:testResearchFullStandardDebugUnitTest
```

## Build Flavors

AURA uses two flavor dimensions:

- `distribution`: `researchFull`, `playSafe`
- `capability`: `standard`, `labAccessibility`, `enterprisePrototype`

`researchFull` may include full inventory support such as `QUERY_ALL_PACKAGES`.
`playSafe` avoids Play-policy-sensitive full inventory.
`labAccessibility` is only a future placeholder; the MVP does not implement AURA's own AccessibilityService.

## Research Contract

`BLUE` findings are expert/platform audit findings, never primary panic alerts.
Unknown evidence increases uncertainty; it does not imply maliciousness.
Each assessment exports a `DecisionTrace`, a `UserRiskStory`, and a separate
defensive-posture summary so threat decisions are not conflated with app
hardening findings.

See:

- [MIGRATION.md](MIGRATION.md)
- [LIMITATIONS.md](LIMITATIONS.md)
- [privacy_and_ethics.md](docs/research/privacy_and_ethics.md)
- [export_privacy.md](docs/research/export_privacy.md)
- [observability_matrix.md](docs/research/observability_matrix.md)
- [risk_vector_model.md](docs/research/risk_vector_model.md)
- [development_status.md](docs/research/development_status.md)
- [emulator_scenarios.md](docs/testing/emulator_scenarios.md)
- [report_workflow.md](docs/commercial/report_workflow.md)
