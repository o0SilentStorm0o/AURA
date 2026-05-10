#!/usr/bin/env python3
"""Validate AURA evaluator expert labels.

This is deliberately dependency-free so it can run in clean research
environments before broader evaluation tooling is installed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


DECISIONS = {"GREEN", "YELLOW", "RED", "BLUE", "GRAY"}
DEFENSIVE_FINDINGS = {
    "DEBUGGABLE_SENSITIVE_APP",
    "BACKUP_ALLOWED_SENSITIVE_APP",
    "CLEARTEXT_TRAFFIC_ALLOWED",
    "UNPROTECTED_EXPORTED_COMPONENT",
}


def _require_bool(item: dict[str, Any], key: str, errors: list[str], index: int) -> None:
    if key in item and not isinstance(item[key], bool):
        errors.append(f"labels[{index}].{key} must be boolean")


def validate(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if payload.get("schemaVersion") != 1:
        errors.append("schemaVersion must be 1")
    labels = payload.get("labels")
    if not isinstance(labels, list):
        return errors + ["labels must be a list"]

    seen_packages: set[str] = set()
    for index, item in enumerate(labels):
        if not isinstance(item, dict):
            errors.append(f"labels[{index}] must be an object")
            continue
        package_name = item.get("packageName")
        if not isinstance(package_name, str) or not package_name:
            errors.append(f"labels[{index}].packageName must be a non-empty string")
        elif package_name in seen_packages:
            errors.append(f"labels[{index}].packageName duplicates {package_name}")
        else:
            seen_packages.add(package_name)

        expected_decision = item.get("expectedDecision")
        if expected_decision is not None and expected_decision not in DECISIONS:
            errors.append(f"labels[{index}].expectedDecision must be one of {sorted(DECISIONS)}")

        for key in ("controlledAbuse", "userActionable", "platformAudit", "abstentionExpected"):
            _require_bool(item, key, errors, index)

        expected_findings = item.get("expectedDefensiveFindings", [])
        if not isinstance(expected_findings, list):
            errors.append(f"labels[{index}].expectedDefensiveFindings must be a list")
        else:
            for finding in expected_findings:
                if finding not in DEFENSIVE_FINDINGS:
                    errors.append(
                        f"labels[{index}].expectedDefensiveFindings contains unknown finding {finding!r}"
                    )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("labels", type=Path, help="Path to a scenario/expert labels JSON file")
    args = parser.parse_args()

    payload = json.loads(args.labels.read_text())
    errors = validate(payload)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(f"OK: {args.labels} contains {len(payload.get('labels', []))} valid labels")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
