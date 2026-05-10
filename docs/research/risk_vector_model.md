# Risk Vector Model

AURA avoids a single permission score. Each app receives:

```text
H: capability harm potential
L: role legitimacy fit
E: abuse evidence
P: provenance confidence
A: user actionability
U: uncertainty
```

Decision policy:

- `RED`: high harm, high abuse evidence, low role legitimacy, active risky capability, high user actionability.
- `BLUE`: platform/OEM/security-research audit relevance; never a primary panic alert.
- `GRAY`: insufficient evidence or high uncertainty without concrete abuse evidence.
- `GREEN`: expected for role, sufficient provenance confidence, low abuse evidence.
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

Each assessment also exports an `evidenceGraph` with typed nodes and edges.
The graph links the app, machine-readable evidence, role/provenance inference,
risk vector, final decision, and recommended actions. It is deterministic and
derived from already exported evidence IDs; it is not an additional detector.

Primary evaluation metrics:

- `non_actionable_critical_alert_rate`
- `user_actionable_precision`
- `red_recall_controlled_abuse`
- `blue_platform_audit_separation`
- `abstention_correctness`
