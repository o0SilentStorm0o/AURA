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

## Verification

Before sharing an export or report, grep for expected sensitive values from the
source export, for example:

```bash
rg "com\\.example\\.sensitive|/data/app/|[a-fA-F0-9]{64}" artifacts/privacy artifacts/reports
```

Expected result for `REDACTED_EXPERT` and `MINIMAL_SUPPORT` artifacts: no raw
package identifiers, APK source paths, or full signing digests from the source
export.
