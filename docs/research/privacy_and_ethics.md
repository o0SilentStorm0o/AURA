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
