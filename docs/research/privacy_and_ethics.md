# Privacy And Ethics

AURA's MVP is local-first and metadata-only.

Privacy defaults:

- no TLS interception or MITM
- no keylogging
- no notification-content reading
- no AccessibilityService in the MVP
- no external telemetry
- local-only JSON export
- test abuse apps must not contain real harmful payloads
- offline APK analysis is static-only and must not execute third-party APK code

Research outputs should avoid naming vulnerable third-party apps publicly without coordinated disclosure. Defensive-surface findings for real financial, health, government, or identity apps should be aggregated or anonymized unless disclosure permission exists.

Public-surface demo reports are allowed only as non-invasive teasers:

- use public Google Play builds or owner-provided builds only,
- do not log into the target app,
- do not exercise payment, health, banking, account, or sensitive workflows,
- do not use root, Frida, MITM, exploit attempts, or protection bypasses,
- do not publish exact component names, raw manifest evidence, or remediation
  details without authorization,
- frame the output as a sample of AURA's reporting structure, not as a
  vulnerability report or final security verdict.
