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

Primary evaluation metrics:

- `non_actionable_critical_alert_rate`
- `user_actionable_precision`
- `red_recall_controlled_abuse`
- `blue_platform_audit_separation`
- `abstention_correctness`
