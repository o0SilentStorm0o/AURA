# Emulator Scenarios

AURA includes harmless fixture APKs under `testapps/` and a host-side runner:

```bash
python3 tools/scenario_runner/run_emulator_scenarios.py
```

The runner uses a booted emulator via `adb`, builds AURA plus fixture APKs,
installs them, toggles special-access state for the suspicious fixture, grants
AURA UsageStats only for the second-phase lab scan, launches AURA, pulls
`files/exports/aura-last-scan.json`, runs the Python evaluator, runs the
offline APK analyzer for defensive-surface details, and asserts the expected
decisions.

For repeatability, the runner uses `adb shell settings`, `adb shell appops`, and
`adb shell cmd notification allow_listener` to simulate user-enabled special
access in the lab. It also restores Accessibility, notification-listener,
overlay, and AURA UsageStats app-op state in a `finally` block so one run does
not contaminate the next.

The suspicious scenario is intentionally two-phase:

1. Launch AURA once with the fixture installed but special access disabled.
   This seeds AURA's private previous-snapshot state.
2. Enable Accessibility, notification listener, overlay, and UsageStats through
   adb, foreground the sensitive bank fixture, launch AURA again without
   clearing app data, then assert both the final decision and the temporal
   episodes derived from the snapshot diff.

## Fixture Apps

- `com.flashlight.cleaner.update`: suspicious lab app declaring overlay,
  install-packages, boot persistence, Accessibility service, and notification
  listener. The services are intentionally empty and harmless.
- `org.fdroid.example.screenreader`: benign accessibility-tool-shaped app with
  assistive naming, but no active special access in the default scenario.
- `com.example.lowriskutility`: unknown low-exposure app expected to become
  `GRAY`, not `RED` or `YELLOW`.
- `com.example.benigncamera`: camera-shaped high-capability app declaring
  camera, microphone, and location permissions. It is used to verify that a
  role-normalized model can avoid a non-actionable panic alert that a
  permission-only baseline would tend to raise.
- `com.example.sensitivebank`: sensitive-app fixture with `FLAG_SECURE`, used
  as a benign sensitive-app baseline.
- `com.example.leakybank`: sensitive-app fixture with intentionally weak
  defensive surface: backup allowed, debug build metadata, cleartext traffic
  allowed, and unprotected exported non-launcher components. It is still
  harmless and has no malicious payload.

## Expected Decisions

- Suspicious agent: `RED`
- Low-risk unknown utility: `GRAY`
- Benign accessibility fixture: `GREEN`
- Benign camera fixture: `GREEN`
- Sensitive bank fixture: `GREEN`
- Leaky bank fixture: `GREEN` as a threat decision, with separate defensive
  surface findings.

The suspicious agent must also be observed with:

- `accessibility_service = OBSERVED_ENABLED`
- `notification_listener = OBSERVED_ENABLED`
- `overlay = OBSERVED_ENABLED`
- `request_install_packages = DECLARED_ONLY`

It must also produce temporal episodes:

- `SIDELOAD_TO_ACCESSIBILITY`
- `SIDELOAD_TO_NOTIFICATION_LISTENER`
- `SPECIAL_ACCESS_PLUS_SENSITIVE_APP`

The runner fails if the decision is correct but these evidence states are not
actually present in the exported snapshot, or if the temporal episodes are
missing from the second-phase export. For the sensitive-foreground episode it
also asserts `usageStatsObservability = OBSERVED_ENABLED`,
`foregroundSensitiveAppRecentlyObserved = true`, and
`foregroundSensitiveAppPackage = com.example.sensitivebank`.

The leaky bank fixture must produce defensive surface findings:

- `BACKUP_ALLOWED_SENSITIVE_APP`
- `CLEARTEXT_TRAFFIC_ALLOWED`
- `DEBUGGABLE_SENSITIVE_APP`
- `UNPROTECTED_EXPORTED_COMPONENT`

These findings are exported under `defensiveSurfaceFindings`; they are not
primary panic alerts and do not turn the fixture into a malware-like `RED`
decision.

The runner also writes `artifacts/scenario_runner/offline-apk-analysis.json`.
That host-side analyzer checks detailed static signals that are intentionally
outside the no-root on-device MVP, including `network_security_config`,
`FLAG_SECURE`, `filterTouchesWhenObscured`, and
`accessibilityDataSensitive` heuristics. Static absence findings are low
confidence audit signals, not runtime proof.

## Labelled Metrics

The runner writes `artifacts/scenario_runner/scenario-labels.json` and passes it
to `tools/evaluator/evaluate.py`. This makes controlled metrics explicit:

- `red_recall_controlled_abuse`
- `user_actionable_precision`
- `non_actionable_critical_alert_rate`
- `abstention_correctness`
- `blue_platform_audit_separation`
- `defensive_surface_recall`

These scenarios are not malware. They are controlled capability-shape fixtures
used to test role normalization, provenance handling, actionability, and
uncertainty behavior.

The evaluator also writes `modelMetrics` and `comparisons`, which make the
baseline comparison explicit. In particular, the scenario output can show
whether full AURA reduces non-actionable critical alerts compared with
permission-only scoring while preserving recall on the controlled abuse
fixture.
