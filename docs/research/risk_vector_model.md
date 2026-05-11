# Risk Vector Model

AURA avoids a single permission score. Each app receives:

```text
H: capability harm potential
L: role legitimacy fit
E: abuse evidence
PT: provenance trust / explainability
PC: provenance classification confidence
A: user actionability
U: uncertainty
```

`PT` and `PC` are intentionally separate. AURA can be confident that an app
belongs to `UNKNOWN_SIDELOAD` while still assigning low trust/explainability to
that provenance class. In schema v1, older exports may still contain
`provenanceConfidence`; report and evaluator tooling interpret that field as
classification confidence and derive provenance trust from the provenance class.

Decision policy:

- `RED`: high harm, high abuse evidence, low role legitimacy, active risky capability, high user actionability.
- `BLUE`: platform/OEM/security-research audit relevance; never a primary panic alert.
- `GRAY`: insufficient evidence or high uncertainty without concrete abuse evidence.
- `GREEN`: expected for role, sufficient provenance trust/explainability, low abuse evidence.
- `YELLOW`: review recommended but not a panic alert.

Each `AuraDecision` also exports deterministic `recommendedActions`.
These are derived from decision color, `ActionabilityClass`, provenance, and
active risky capability state. They are not free-form detector output:

- `RED` actions may be user-facing, such as disabling active special access or
  uninstalling a user-removable app.
- `BLUE` actions are expert/platform audit actions and must not appear as
  primary panic guidance.
- `GRAY` actions emphasize abstention and collecting more context.
- `GREEN` actions generally state that no user action is required for the
  observed scan evidence.

Each assessment exports a `DecisionTrace`:

- `policyVersion`
- evaluated policy rules and whether each matched
- selected decision
- rejected decision alternatives
- threshold inputs
- counterfactuals for how the decision could change
- invariant checks such as `BLUE_MUST_NOT_BE_PRIMARY_USER_ALERT` and
  `RED_REQUIRES_ACTIVE_RISKY_CAPABILITY`

This trace is intended to make the decision reproducible and explainable
without turning unknown evidence into maliciousness.

Each assessment also exports a `UserRiskStory`. This is a user-facing
translation of the same structured evidence:

- what AURA observed
- what AURA did not observe
- why it matters
- what the recommended next step is
- what limitations remain because AURA is a no-root agent

Each assessment also exports an `evidenceGraph` with typed nodes and edges.
The graph links the app, machine-readable evidence, role/provenance inference,
risk vector, final decision, and recommended actions. It is deterministic and
derived from already exported evidence IDs; it is not an additional detector.

Threat decisions and defensive posture are separate. A `GREEN` threat decision
means AURA did not find concrete abuse evidence for the app in the current
scan; it does not mean that the app has perfect defensive design. Defensive
surface findings are summarized separately as defensive posture.

Primary evaluation metrics:

- `non_actionable_critical_alert_rate`
- `user_actionable_precision`
- `red_recall_controlled_abuse`
- `blue_platform_audit_separation`
- `abstention_correctness`
- `decision_trace_completeness`
