# Enterprise / Device Owner Boundary

The `enterprisePrototype` capability flavor is a placeholder for future
Device Owner or MDM-style experiments.

Current MVP behavior:

- no Device Owner enrollment flow,
- no policy management,
- no silent install/uninstall,
- no enterprise-only permissions,
- no claim that user builds can observe enterprise-only state.

Research use:

- keep `DEVICE_OWNER_ONLY` observability states explicit,
- compare what the no-root user build cannot see against what a controlled
  enterprise testbed could see later,
- avoid mixing enterprise assumptions into the default `researchFullStandard`
  results.
