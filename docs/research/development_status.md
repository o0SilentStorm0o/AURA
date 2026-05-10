# Development Status

This document separates what exists in the current Research MVP from planned work.

## Implemented

- Clean standalone AURA Android project with `cz.davidstrnadel.aura` namespace.
- Two flavor dimensions: `distribution` and `capability`.
- `researchFullStandardDebug` and `playSafeStandardDebug` builds.
- `QUERY_ALL_PACKAGES` and `PACKAGE_USAGE_STATS` only in the `researchFull` manifest.
- PackageManager snapshot collector for package identity, permissions, components, signing digests, installer, source path, partition hints, and special-access metadata.
- Versioned `ObservedAppSnapshot`, first-class `EvidenceItem`, exact `ObservabilityState`, `ActionabilityClass`, `RiskVector`, and `AuraDecision`.
- PackageManager-first role inference, provenance classification, role/provenance-aware decision policy, and snapshot-first temporal episode detector.
- Stable JSON export saved locally in app-private storage as `files/exports/aura-last-scan.json`.
- Atomic export/history writes so adb pulls do not observe partially written JSON.
- Private previous-snapshot state saved as `files/state/previous-snapshots.json` for snapshot-diff temporal episodes.
- On-device defensive surface findings for observable manifest/app metadata: debuggable sensitive apps, backup allowed for sensitive apps, best-effort cleartext traffic allowance, and unprotected exported non-launcher components.
- Offline APK analyzer for detailed defensive-surface heuristics: `network_security_config`, `FLAG_SECURE`, `filterTouchesWhenObscured`, `accessibilityDataSensitive`, and manifest component metadata, all with confidence and observability state.
- Opt-in UsageStats foreground correlation for the `SPECIAL_ACCESS_PLUS_SENSITIVE_APP` temporal episode in `researchFull`; this uses only package-level foreground events, not screen, notification, or network content.
- Python evaluator for permission-only, capability-only, role-aware, role+provenance, temporal, and full AURA baselines, including per-model metrics and AURA-vs-permission-only comparisons.
- Unit tests for observability enum contract, actionability enum contract, role/risk/provenance decisions, JSON shape, and temporal TTL behavior.
- Harmless emulator fixture APKs for suspicious, benign accessibility, low-risk unknown, benign high-capability camera, benign sensitive-app, and leaky defensive-surface scenarios.
- ADB scenario runner that installs fixture APKs, performs a two-phase temporal scan, toggles special-access state, runs AURA, pulls local export, evaluates baselines, and asserts expected decisions/evidence/episodes/defensive findings.
- Research docs for limitations, observability, risk vector, migration, and privacy/ethics.

## Not Yet Implemented

- Multi-scan history beyond the immediately previous snapshot set.
- Asset-driven rules loaded directly from JSON assets; current rules are mirrored in code for the MVP.
- Human-facing detailed app drill-down with evidence graph and remediation.
- Expert review labeling workflow beyond the current controlled-scenario labels.
- Firmware-scale OEM/preinstall dataset ingestion.
- Binary Transparency verification.
- Enterprise/Device Owner mode.
- Lab Accessibility observer; intentionally absent from MVP.

## Known Weaknesses

- The current UI is a functional research console, not the final UX.
- The evaluator supports labelled controlled scenarios; broader ground truth still needs more devices, API levels, OEM images, and expert review.
- Role inference is deliberately conservative and rule-based; it will need fixture-driven expansion.
- No-root observability gaps remain explicit and should not be hidden by UI wording.
- The current emulator scenarios use `adb shell settings`, `cmd notification`, and `appops` to simulate user-enabled special access; this is appropriate for repeatable lab validation, but must be described as a controlled test setup.
