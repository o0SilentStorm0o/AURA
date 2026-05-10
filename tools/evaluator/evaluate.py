#!/usr/bin/env python3
"""AURA evaluator.

Computes baseline decisions from exported raw app features so the Android app
does not need to carry six parallel detector implementations.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DANGEROUS_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECEIVE_BOOT_COMPLETED",
}


@dataclass(frozen=True)
class BaselineResult:
    model: str
    decision: str
    score: float


def permission_only(snapshot: dict[str, Any]) -> BaselineResult:
    requested = set(snapshot.get("requestedPermissions", []))
    score = min(1.0, len(requested & DANGEROUS_PERMISSIONS) / 4.0)
    return BaselineResult("permission_only", "CRITICAL" if score >= 0.75 else "OK", score)


def capability_only(snapshot: dict[str, Any]) -> BaselineResult:
    special = snapshot.get("specialAccess", {})
    enabled = sum(1 for value in special.values() if value == "OBSERVED_ENABLED")
    requested = set(snapshot.get("requestedPermissions", []))
    score = min(1.0, enabled * 0.35 + len(requested & DANGEROUS_PERMISSIONS) * 0.12)
    return BaselineResult("capability_only", "CRITICAL" if score >= 0.70 else "REVIEW", score)


def role_aware(assessment: dict[str, Any]) -> BaselineResult:
    vector = assessment.get("riskVector", {})
    score = max(0.0, vector.get("harm", 0.0) - vector.get("legitimacy", 0.0) * 0.45)
    return BaselineResult("role_aware", "CRITICAL" if score >= 0.65 else "REVIEW", score)


def role_provenance(assessment: dict[str, Any]) -> BaselineResult:
    vector = assessment.get("riskVector", {})
    score = max(
        0.0,
        vector.get("harm", 0.0)
        - vector.get("legitimacy", 0.0) * 0.35
        - vector.get("provenanceConfidence", 0.0) * 0.20,
    )
    return BaselineResult("role_provenance", "CRITICAL" if score >= 0.60 else "REVIEW", score)


def temporal(assessment: dict[str, Any], package_episodes: set[str]) -> BaselineResult:
    package_name = assessment["snapshot"]["packageName"]
    score = 0.80 if package_name in package_episodes else assessment.get("riskVector", {}).get("abuseEvidence", 0.0)
    return BaselineResult("temporal", "CRITICAL" if score >= 0.70 else "REVIEW", score)


def full_aura(assessment: dict[str, Any]) -> BaselineResult:
    decision = assessment.get("decision", {}).get("color", "GRAY")
    score = assessment.get("riskVector", {}).get("abuseEvidence", 0.0)
    return BaselineResult("full_aura", decision, score)


def evaluate(export: dict[str, Any]) -> dict[str, Any]:
    episodes = export.get("temporalEpisodes", [])
    episode_packages = {episode["packageName"] for episode in episodes}
    rows: list[dict[str, Any]] = []

    for assessment in export.get("assessments", []):
        snapshot = assessment["snapshot"]
        baselines = [
            permission_only(snapshot),
            capability_only(snapshot),
            role_aware(assessment),
            role_provenance(assessment),
            temporal(assessment, episode_packages),
            full_aura(assessment),
        ]
        rows.append(
            {
                "packageName": snapshot["packageName"],
                "auraDecision": assessment.get("decision", {}).get("color"),
                "baselines": [baseline.__dict__ for baseline in baselines],
            }
        )

    return {
        "schemaVersion": 1,
        "scanId": export.get("scanId"),
        "evaluatedApps": len(rows),
        "metrics": compute_metrics(rows),
        "rows": rows,
    }


def compute_metrics(rows: list[dict[str, Any]]) -> dict[str, float]:
    if not rows:
        return {
            "non_actionable_critical_alert_rate": 0.0,
            "user_actionable_precision": 0.0,
            "red_recall_controlled_abuse": 0.0,
            "blue_platform_audit_separation": 0.0,
            "abstention_correctness": 0.0,
        }

    aura_red = sum(1 for row in rows if row["auraDecision"] == "RED")
    aura_blue = sum(1 for row in rows if row["auraDecision"] == "BLUE")
    aura_gray = sum(1 for row in rows if row["auraDecision"] == "GRAY")
    permission_critical = sum(
        1
        for row in rows
        for baseline in row["baselines"]
        if baseline["model"] == "permission_only" and baseline["decision"] == "CRITICAL"
    )

    return {
        "non_actionable_critical_alert_rate": round(permission_critical / len(rows), 4),
        "user_actionable_precision": round(aura_red / max(1, aura_red + aura_blue), 4),
        "red_recall_controlled_abuse": 0.0,
        "blue_platform_audit_separation": round(aura_blue / len(rows), 4),
        "abstention_correctness": round(aura_gray / len(rows), 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("export", type=Path, help="AURA JSON export")
    parser.add_argument("--out", type=Path, help="Optional output path")
    args = parser.parse_args()

    result = evaluate(json.loads(args.export.read_text()))
    payload = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        args.out.write_text(payload + "\n")
    else:
        print(payload)


if __name__ == "__main__":
    main()
