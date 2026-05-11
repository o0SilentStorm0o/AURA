# AURA Export Redactor

This tool converts a full AURA JSON scan export into sharing-oriented privacy
profiles. It is intentionally dependency-free so it can run anywhere the
evaluator/report tools run.

Privacy modes:

- `full_research`: preserves the full export and annotates it with privacy
  metadata. Use only for trusted local research workflows.
- `redacted_expert`: keeps the per-app evidence structure but replaces package
  names with stable salted aliases, removes labels, source paths, component
  names, raw signing digests, and installer package identifiers.
- `minimal_support`: keeps aggregate counts plus a priority-only redacted subset
  of assessments. It does not include the full package inventory.

Usage:

```bash
python3 tools/export_redactor/redact_export.py \
  artifacts/scenario_runner/aura-last-scan.json \
  --mode redacted_expert \
  --salt customer-or-project-salt \
  --out artifacts/privacy/aura-redacted-expert.json
```

For real customer or expert sharing, pass a project-specific `--salt`. The
default salt is reproducible for tests and demos, but it should not be treated
as unlinkability protection across public exports.

Unit tests:

```bash
python3 -m unittest tools/export_redactor/test_redact_export.py
```
