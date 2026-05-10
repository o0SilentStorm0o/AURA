# Observability Matrix

Use this `ObservabilityState` enum exactly:

```text
OBSERVED_ENABLED
OBSERVED_DISABLED
DECLARED_ONLY
USER_GRANT_REQUIRED
REQUIRES_RESEARCH_FLAVOR
ADB_ONLY
DEVICE_OWNER_ONLY
ROOT_OR_OEM_ONLY
NOT_OBSERVABLE
UNKNOWN_API_LIMITATION
```

Unknown or limited evidence must not collapse into "risky." It should increase uncertainty, mark abstention, or route the finding into expert review depending on context.

Examples:

- `QUERY_ALL_PACKAGES`: `REQUIRES_RESEARCH_FLAVOR` in `playSafe`, available in `researchFull`.
- Usage foreground history: `USER_GRANT_REQUIRED`.
- Hidden privileged permission allowlists: usually `ROOT_OR_OEM_ONLY` or `ADB_ONLY`.
- Per-app overlay state: `OBSERVED_ENABLED`, `OBSERVED_DISABLED`, or `UNKNOWN_API_LIMITATION` depending on API/AppOps availability.
