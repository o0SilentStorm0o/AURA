# AURA

AURA is a research-first Android security agent prototype:

**Actionable, Uncertainty-aware, Role-normalized Android Security Agent**

It is not a permission scanner with a single risk score. AURA separates:

- capability exposure
- role legitimacy
- provenance trust and provenance classification confidence
- abuse evidence
- user actionability
- uncertainty

The current MVP is best understood as a no-root Android risk reasoning and
reporting system. It collects observable app metadata on device, exports a
stable JSON evidence record, evaluates decisions against baseline models, and
generates customer/research reports that keep threat decisions separate from
defensive posture.

The default MVP target is:

```bash
sh gradlew :app:assembleResearchFullStandardDebug
sh gradlew :app:testResearchFullStandardDebugUnitTest
```

## Build Flavors

AURA uses two flavor dimensions:

- `distribution`: `researchFull`, `playSafe`
- `capability`: `standard`, `labAccessibility`, `enterprisePrototype`

`researchFull` may include full inventory support such as `QUERY_ALL_PACKAGES`.
`playSafe` avoids Play-policy-sensitive full inventory.
`labAccessibility` is only a future placeholder; the MVP does not implement AURA's own AccessibilityService.

## What Exists Now

- Android app namespace/application ID base: `cz.davidstrnadel.aura`.
- Default installed research package: `cz.davidstrnadel.aura.research`.
- PackageManager-first snapshot collector with permissions, components,
  signing digests, installer/source metadata, partition hints, special-access
  states, UsageStats opt-in signals, and scan-history diffs.
- Role/provenance/actionability-aware reasoning with first-class
  `EvidenceItem`, `DecisionTrace`, `UserRiskStory`, `EvidenceGraph`,
  `ActionabilityClass`, and exact `ObservabilityState` values.
- Separate defensive-posture analysis so app-hardening findings do not become
  threat decisions by themselves.
- Python evaluator that computes permission-only, capability-only, role-aware,
  role+provenance, temporal, and full AURA baseline metrics outside the Android
  app.
- App-owner release-risk audit engine that converts AURA/offline analyzer
  evidence into a policy-driven CTO-facing release checklist: app profile,
  policy ladder, additive policy packs, accepted risks, component
  classification, grouped top review areas, evidence-strength caveats, top fix
  plan, P1/P2/P3/INFO findings, status, acceptance criteria, verification
  checks, owners, policy-quality metrics, and stable retest fingerprints.
- Optional host-side LLM/RAG summary layer under `tools/llm_summary/`. It uses
  controlled AURA docs/templates, optional Qdrant retrieval, Ollama embeddings,
  and optional local Ollama wording, but cannot create findings or change
  policy decisions.
- Report generator for:
  - `device_expert` reports,
  - `app_owner` release-risk reports,
  - `public_teaser` outreach reports.
- Export redaction modes:
  - `full_research`,
  - `redacted_expert`,
  - `redacted_teaser`,
  - `minimal_support`.
- Public-demo tooling for non-invasive Google Play app teasers under
  `tools/public_demo/`.
- Real-world validation harness under `tools/real_world_validation/` that
  generates target app-owner reports from public-app scans and scores whether
  findings are valuable, context-dependent, noisy, or good teaser candidates.
- Local AURA Studio under `tools/aura_studio/`, a localhost web workbench for
  pulling exports, selecting a target package, editing the app profile, running
  the app-owner audit engine, invoking native Ollama/Qdrant LLM/RAG wording,
  previewing reports, and opening generated artifacts.
- Harmless emulator fixture apps plus an ADB scenario runner for controlled
  abuse, abstention, role-normalization, and defensive-posture tests.

## Research Contract

`BLUE` findings are expert/platform audit findings, never primary panic alerts.
Unknown evidence increases uncertainty; it does not imply maliciousness.
Each assessment exports a `DecisionTrace`, a `UserRiskStory`, and a separate
defensive-posture summary so threat decisions are not conflated with app
hardening findings.

## Common Workflows

Run the emulator-backed controlled scenarios:

```bash
python3 tools/scenario_runner/run_emulator_scenarios.py
```

Generate a device/expert report from an export:

```bash
python3 tools/report_generator/generate_report.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --evaluation artifacts/scenario_runner/evaluation.json \
  --out-dir artifacts/reports \
  --basename aura-scenario-report
```

Generate a public-surface teaser for a configured Google Play target:

```bash
python3 tools/public_demo/create_teaser_report.py \
  artifacts/public-demo/first-wave/aura-last-scan.json \
  gastromapa \
  --evaluation artifacts/scenario_runner/evaluation.json
```

Public teasers are not vulnerability reports. They are target-scoped,
`redacted_teaser` reports that suppress raw evidence, exact component names,
full evidence graph details, policy trace detail, source paths, signing values,
and exact risk-vector values.

Generate an app-owner release-risk report:

```bash
python3 tools/report_generator/generate_report.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --report-type app_owner \
  --target-package com.example.app \
  --app-profile tools/app_owner_audit/profiles/fintech_high_sensitivity.example.json \
  --offline-analysis artifacts/scenario_runner/offline-apk-analysis.json \
  --out-dir artifacts/reports \
  --basename aura-app-owner-release-risk
```

Generate deterministic RAG-backed wording for an existing app-owner audit:

```bash
python3 tools/llm_summary/llm_summary.py \
  artifacts/reports/aura-app-owner-audit.json \
  --out artifacts/reports/aura-group-summary.json \
  --llm-mode off
```

Run the optional local LLM/RAG path. The supported local setup is native macOS
Ollama with Metal acceleration, `qwen2.5:3b`, and Dockerized Qdrant bound to
localhost:

```bash
brew install ollama
OLLAMA_FLASH_ATTENTION=1 OLLAMA_KV_CACHE_TYPE=q8_0 OLLAMA_HOST=127.0.0.1:11434 ollama serve
ollama pull qwen2.5:3b
ollama pull nomic-embed-text

docker start aura-qdrant || docker run -d --name aura-qdrant -p 127.0.0.1:6333:6333 qdrant/qdrant

python3 tools/llm_summary/llm_summary.py \
  artifacts/reports/aura-app-owner-audit.json \
  --out artifacts/reports/aura-group-summary.llm-rag.json \
  --llm-mode strict \
  --local-llm-url http://localhost:11434 \
  --model qwen2.5:3b \
  --qdrant-url http://localhost:6333 \
  --embedding-url http://localhost:11434 \
  --embedding-model nomic-embed-text \
  --embedding-mode ollama \
  --llm-timeout-seconds 180
```

Model pulls need network access during setup. Report generation can then run
locally/offline against already pulled models and the local Qdrant store.

The LLM/RAG layer is a wording layer only. In strict mode it works
group-by-group, validates all `groupId`, `findingIds`, and `docIds`, and falls
back to templates when the model times out or tries to invent unsupported
content.

See:

- [MIGRATION.md](MIGRATION.md)
- [LIMITATIONS.md](LIMITATIONS.md)
- [privacy_and_ethics.md](docs/research/privacy_and_ethics.md)
- [export_privacy.md](docs/research/export_privacy.md)
- [observability_matrix.md](docs/research/observability_matrix.md)
- [risk_vector_model.md](docs/research/risk_vector_model.md)
- [development_status.md](docs/research/development_status.md)
- [emulator_scenarios.md](docs/testing/emulator_scenarios.md)
- [report_workflow.md](docs/commercial/report_workflow.md)
- [app_profile_intake.md](docs/commercial/app_profile_intake.md)
- [pre_send_triage_checklist.md](docs/commercial/pre_send_triage_checklist.md)
- [public demo workflow](tools/public_demo/README.md)
- [real-world validation](tools/real_world_validation/README.md)
- [report generator](tools/report_generator/README.md)
- [LLM/RAG group summary](tools/llm_summary/README.md)
- [AURA Studio](tools/aura_studio/README.md)
- [export redactor](tools/export_redactor/README.md)
