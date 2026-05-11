# Development Status

This document separates what exists in the current Research MVP from planned work.

## Implemented

- Clean standalone AURA Android project with `cz.davidstrnadel.aura` namespace.
- Two flavor dimensions: `distribution` and `capability`.
- `researchFullStandardDebug` and `playSafeStandardDebug` builds.
- `QUERY_ALL_PACKAGES` and `PACKAGE_USAGE_STATS` only in the `researchFull` manifest.
- PackageManager snapshot collector for package identity, permissions, components, signing digests, installer, source path, partition hints, and special-access metadata.
- Versioned `ObservedAppSnapshot`, first-class `EvidenceItem`, exact `ObservabilityState`, `ActionabilityClass`, `RiskVector`, `AuraDecision`, deterministic `RecommendedAction`, per-assessment `DecisionTrace`, `UserRiskStory`, and per-assessment `EvidenceGraph`.
- PackageManager-first role inference, provenance classification,
  role/provenance-aware decision policy, and snapshot-first temporal episode
  detector. The current rule set includes explicit marketplace/e-commerce and
  public-information roles so camera permission alone does not force a
  `CAMERA` role.
- Stable JSON export saved locally in app-private storage as `files/exports/aura-last-scan.json`.
- Export now includes a scan-history summary with retained scan counts, package
  history counts, and package add/change/remove diffs.
- Atomic export/history writes so adb pulls do not observe partially written JSON.
- Private previous-snapshot state saved as `files/state/previous-snapshots.json` for snapshot-diff temporal episodes and bounded multi-scan history.
- On-device defensive surface findings for observable manifest/app metadata: debuggable sensitive apps, backup allowed for sensitive apps, best-effort cleartext traffic allowance, and unprotected exported non-launcher components.
- Separate defensive-posture summaries so threat decisions stay distinct from
  defensive-surface weakness findings.
- Offline APK analyzer for detailed defensive-surface heuristics: `network_security_config`, `FLAG_SECURE`, `filterTouchesWhenObscured`, `accessibilityDataSensitive`, and manifest component metadata, all with confidence and observability state.
- Opt-in UsageStats foreground correlation for the `SPECIAL_ACCESS_PLUS_SENSITIVE_APP` temporal episode in `researchFull`; this uses only package-level foreground events or aggregated UsageStats fallback, not screen, notification, or network content. The export records the signal source in `foregroundSensitiveAppSignalSource`.
- Role, permission harm, known package, OEM pattern, F-Droid signature, provenance,
  and decision-policy assets are split under `app/src/main/assets/aura/`; the
  Android app loads rule assets with code fallback for clean MVP builds.
- Python evaluator for permission-only, capability-only, role-aware, role+provenance, temporal, and full AURA baselines, including per-model metrics, decision-trace completeness, and AURA-vs-permission-only comparisons.
- Unit tests for observability enum contract, actionability enum contract, role/risk/provenance decisions, asset-driven rules, JSON shape, scan history, BLUE audit separation, and temporal TTL behavior.
- Harmless emulator fixture APKs for suspicious, benign accessibility, low-risk unknown, benign high-capability camera, benign sensitive-app, and leaky defensive-surface scenarios.
- ADB scenario runner that installs fixture APKs, performs a two-phase temporal scan, toggles special-access state, runs AURA, pulls local export, evaluates baselines, and asserts expected decisions/evidence/episodes/defensive findings.
- Research docs for limitations, observability, risk vector, migration, and privacy/ethics.
- Expert-label validation tooling, firmware APK inventory tooling, and explicit
  integration-boundary docs for Binary Transparency, enterprise Device Owner,
  and lab Accessibility observer work.
- Expert review packet generator that converts an AURA export into reviewer CSV
  plus an `UNLABELED` labels template that is skipped by the evaluator until
  explicitly reviewed.
- Report generator that turns AURA JSON exports and optional evaluator output
  into Markdown plus print-ready HTML Android App Risk reports.
- Export privacy redactor with `full_research`, `redacted_expert`,
  `redacted_teaser`, and `minimal_support` modes; report generation can now
  render from a privacy processed export and optionally save that redacted JSON
  artifact.
- Public-surface demo workflow under `tools/public_demo/` for non-invasive
  Google Play teaser reports. The current first-wave target list is
  Gastromapa, Bikeflip, Bistro.sk, and iSnemovna; unsupported or abandoned
  targets such as Dudelo are intentionally not kept in the active list.
- Explainability UI v1 with Basic, Power, and Research modes; action-first
  dashboard; selectable app detail; user risk story; observed/not-observed
  sections; recommended actions; scan-change summary; temporal episodes;
  special-access states; risk-vector bars; baseline preview; decision trace;
  counterfactual remediation; observability contract; evidence graph summary;
  first-class evidence items; raw-feature preview; and separate defensive
  posture findings.
- Real-public-app teaser generation has been exercised on a Google Play
  emulator with AURA scan export, logcat capture, target-scoped
  `redacted_teaser` exports, and print-ready HTML reports.

## Not Yet Implemented

- Interactive evidence graph visualization beyond the current typed node/edge summary.
- Automated user action launchers for settings/remediation; current UI explains
  actions but does not deep-link into Android settings screens.
- Automated PDF rendering beyond browser print/save-as-PDF from generated HTML.
- Automated Play Store installation/download orchestration for public demos;
  the current workflow opens Play Store targets and expects manual install with
  a test Google account.
- Multi-reviewer adjudication workflow beyond generated packets, schema
  validation, and controlled-scenario labels.
- Firmware-scale OEM/preinstall analysis beyond safe APK inventory collection.
- Binary Transparency verification.
- Enterprise/Device Owner mode; only boundary docs and flavor placeholder exist.
- Lab Accessibility observer; intentionally absent from MVP except for boundary docs and flavor placeholder.

## Known Weaknesses

- The current UI is a functional research console, not the final UX.
- The evaluator supports labelled controlled scenarios; broader ground truth still needs more devices, API levels, OEM images, and expert review.
- Role inference is deliberately conservative and rule-based; asset coverage will need fixture-driven expansion.
- Some decision-policy thresholds remain code-level guardrails, with asset text
  documenting the policy rather than configuring every numeric threshold.
- No-root observability gaps remain explicit and should not be hidden by UI wording.
- The current emulator scenarios use `adb shell settings`, `cmd notification`, and `appops` to simulate user-enabled special access; this is appropriate for repeatable lab validation, but must be described as a controlled test setup.
