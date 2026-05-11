# Export Privacy Modes

AURA exports are sensitive because an installed-app inventory can reveal banks,
health apps, employer tooling, personal habits, and device configuration. The
research JSON export is therefore separated from sharing-oriented export modes.

## Modes

### FULL_RESEARCH

Use for trusted local research and reproducibility.

- Includes full package names, app labels, source paths, installer package
  names, signing digests, component names, raw evidence values, decision trace,
  evidence graph, temporal episodes, defensive posture, and scan history.
- Suitable for evaluator runs, emulator scenarios, and paper artifact
  debugging.
- Not suitable for customer support or public sharing unless the device/app
  inventory is intentionally public.

### REDACTED_EXPERT

Use for external expert review when per-app evidence structure is still needed.

- Replaces package names with per-report HMAC-SHA256 aliases.
- Redacts app labels, source paths, installer package identifiers, component
  names, version names, UIDs, and raw signing digests.
- Keeps role/provenance/risk/decision/evidence structure so the reviewer can
  inspect why AURA decided `RED`, `YELLOW`, `BLUE`, `GRAY`, or `GREEN`.
- Keeps full inventory count and per-app records, but without raw identifiers.
- Requires a project/customer-specific salt for real sharing. Treat that salt as
  the HMAC secret and do not include it in public sample reports.

### REDACTED_TEASER

Use only for target-scoped public-surface demos and cold outreach.

- Includes only the selected target app, not the full device inventory.
- Replaces the target package identifier with a per-report HMAC-SHA256 alias.
- Redacts app label-derived raw values, source paths, component names, signing
  digests, installer identifiers, detailed evidence graph data, detailed
  decision trace data, permission lists, and exact risk-vector values.
- Shows only high-level categories such as role fit, provenance class,
  special-access summary, broad defensive review areas, and observability
  limits.
- May include the public Play Store/source URL supplied by the operator so the
  recipient can understand which public app the demo references. That URL is
  not an inventory leak; it is the explicit target of the teaser.
- Must be manually reviewed before sending. It is a sample of AURA's report
  structure, not a vulnerability disclosure or final security verdict.

### MINIMAL_SUPPORT

Use for low-friction support sharing.

- Preserves aggregate counts for decisions, defensive posture, temporal
  episodes, and findings.
- Includes only a priority subset of redacted assessments.
- Does not include the full package inventory.
- Suitable when the reviewer only needs to understand the high-priority outcome
  and not the whole device/app inventory.

## Redaction Rules

The redactor treats these fields as sensitive:

- `snapshot.packageName`
- `snapshot.appLabel`
- `snapshot.versionName`
- `snapshot.uid`
- `snapshot.installerPackageName`
- `snapshot.sourceDir`
- `snapshot.signingCertDigestsSha256`
- `snapshot.components[].name`
- raw evidence values containing APK paths, package names, signing digests, or
  manifest component names
- temporal episode package identifiers
- defensive finding/posture package identifiers and finding IDs
- scan-history package lists
- detailed evidence graph, decision trace, permission lists, exact risk-vector
  values, and component names in `REDACTED_TEASER`

Redaction is not a malware decision. It changes only the sharing surface of the
export and must not change AURA's threat decision, defensive posture, risk
vector, policy trace, or observability states.

## Commands

Standalone redaction:

```bash
python3 tools/export_redactor/redact_export.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --mode redacted_expert \
  --salt customer-or-project-salt \
  --out artifacts/privacy/aura-redacted-expert.json
```

Report generation with a redacted export:

```bash
python3 tools/report_generator/generate_report.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --evaluation artifacts/scenario_runner/evaluation.json \
  --privacy-mode redacted_expert \
  --salt customer-or-project-salt \
  --redacted-export-out artifacts/reports/aura-redacted-expert.export.json \
  --out-dir artifacts/reports \
  --basename aura-redacted-expert-report
```

Public teaser generation:

```bash
python3 tools/public_demo/create_teaser_report.py \
  artifacts/public-demo/first-wave/aura-last-scan.json \
  gastromapa \
  --evaluation artifacts/scenario_runner/evaluation.json \
  --salt customer-or-demo-specific-salt
```

## Verification

Before sharing an export or report, grep for expected sensitive values from the
source export, for example:

```bash
rg "com\\.example\\.sensitive|/data/app/|[a-fA-F0-9]{64}" artifacts/privacy artifacts/reports
```

Expected result for `REDACTED_EXPERT`, `REDACTED_TEASER`, and
`MINIMAL_SUPPORT` artifacts: no raw inventory package identifiers, APK source
paths, or full signing digests from the source export. `REDACTED_TEASER` may
contain the intentionally supplied public target URL, for example a Google Play
URL for the one app being demonstrated.
