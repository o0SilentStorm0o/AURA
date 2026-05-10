# Emulator Scenarios

AURA includes harmless fixture APKs under `testapps/` and a host-side runner:

```bash
python3 tools/scenario_runner/run_emulator_scenarios.py
```

The runner uses a booted emulator via `adb`, builds AURA plus fixture APKs,
installs them, toggles special-access state for the suspicious fixture, launches
AURA, pulls `files/exports/aura-last-scan.json`, runs the Python evaluator, and
asserts the expected decisions.

For repeatability, the runner uses `adb shell settings`, `adb shell appops`, and
`adb shell cmd notification allow_listener` to simulate user-enabled special
access in the lab. It also restores Accessibility, notification-listener, and
overlay state in a `finally` block so one run does not contaminate the next.

The suspicious scenario is intentionally two-phase:

1. Launch AURA once with the fixture installed but special access disabled.
   This seeds AURA's private previous-snapshot state.
2. Enable Accessibility, notification listener, and overlay through adb, launch
   AURA again without clearing app data, then assert both the final decision and
   the temporal episodes derived from the snapshot diff.

## Fixture Apps

- `com.flashlight.cleaner.update`: suspicious lab app declaring overlay,
  install-packages, boot persistence, Accessibility service, and notification
  listener. The services are intentionally empty and harmless.
- `org.fdroid.example.screenreader`: benign accessibility-tool-shaped app with
  assistive naming, but no active special access in the default scenario.
- `com.example.lowriskutility`: unknown low-exposure app expected to become
  `GRAY`, not `RED` or `YELLOW`.
- `com.example.sensitivebank`: sensitive-app fixture with `FLAG_SECURE`, used
  for future defensive-surface and UsageStats scenarios.

## Expected Decisions

- Suspicious agent: `RED`
- Low-risk unknown utility: `GRAY`
- Benign accessibility fixture: `GREEN`
- Sensitive bank fixture: `GREEN`

The suspicious agent must also be observed with:

- `accessibility_service = OBSERVED_ENABLED`
- `notification_listener = OBSERVED_ENABLED`
- `overlay = OBSERVED_ENABLED`
- `request_install_packages = DECLARED_ONLY`

It must also produce temporal episodes:

- `SIDELOAD_TO_ACCESSIBILITY`
- `SIDELOAD_TO_NOTIFICATION_LISTENER`

The runner fails if the decision is correct but these evidence states are not
actually present in the exported snapshot, or if the temporal episodes are
missing from the second-phase export.

## Labelled Metrics

The runner writes `artifacts/scenario_runner/scenario-labels.json` and passes it
to `tools/evaluator/evaluate.py`. This makes controlled metrics explicit:

- `red_recall_controlled_abuse`
- `user_actionable_precision`
- `non_actionable_critical_alert_rate`
- `abstention_correctness`
- `blue_platform_audit_separation`

These scenarios are not malware. They are controlled capability-shape fixtures
used to test role normalization, provenance handling, actionability, and
uncertainty behavior.
