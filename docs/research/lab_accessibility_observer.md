# Lab Accessibility Observer Boundary

AURA's MVP intentionally does not include its own `AccessibilityService`.

Rationale:

- AURA evaluates risky Accessibility abuse patterns and should not request the
  same sensitive capability in the default research build.
- Accessibility-based observation would change the threat model, Play policy
  posture, and user-consent requirements.
- Current temporal detection is snapshot-first and uses PackageManager,
  settings snapshots, UsageStats opt-in, and controlled scenario runner state.

If a lab observer is ever added, it must remain isolated to the
`labAccessibility` capability flavor, require explicit consent, collect no
screen text or credentials, and be evaluated separately from the default MVP.
