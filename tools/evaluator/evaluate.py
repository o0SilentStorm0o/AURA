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


@dataclass(frozen=True)
class ScenarioLabel:
    package_name: str
    expected_decision: str | None = None
    controlled_abuse: bool = False
    user_actionable: bool = False
    platform_audit: bool = False
    abstention_expected: bool = False
    expected_defensive_findings: tuple[str, ...] = ()


def is_critical_decision(decision: str | None) -> bool:
    return decision in {"CRITICAL", "RED"}


def is_abstention_decision(decision: str | None) -> bool:
    return decision in {"GRAY", "ABSTAIN", "UNKNOWN"}


def component_permissions(snapshot: dict[str, Any]) -> set[str]:
    return {
        component.get("permission")
        for component in snapshot.get("components", [])
        if component.get("permission")
    }


def permission_only(snapshot: dict[str, Any]) -> BaselineResult:
    requested = set(snapshot.get("requestedPermissions", [])) | component_permissions(snapshot)
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


def load_labels(path: Path | None) -> dict[str, ScenarioLabel]:
    if path is None:
        return {}
    payload = json.loads(path.read_text())
    return {
        item["packageName"]: ScenarioLabel(
            package_name=item["packageName"],
            expected_decision=item.get("expectedDecision"),
            controlled_abuse=bool(item.get("controlledAbuse", False)),
            user_actionable=bool(item.get("userActionable", False)),
            platform_audit=bool(item.get("platformAudit", False)),
            abstention_expected=bool(item.get("abstentionExpected", False)),
            expected_defensive_findings=tuple(item.get("expectedDefensiveFindings", [])),
        )
        for item in payload.get("labels", [])
    }


def evaluate(export: dict[str, Any], labels: dict[str, ScenarioLabel] | None = None) -> dict[str, Any]:
    labels = labels or {}
    episodes = export.get("temporalEpisodes", [])
    episode_packages = {episode["packageName"] for episode in episodes}
    defensive_findings_by_package: dict[str, list[str]] = {}
    for finding in export.get("defensiveSurfaceFindings", []):
        defensive_findings_by_package.setdefault(finding["packageName"], []).append(finding["findingType"])
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
        package_name = snapshot["packageName"]
        label = labels.get(package_name)
        row = {
            "packageName": package_name,
            "auraDecision": assessment.get("decision", {}).get("color"),
            "auraUserAlert": bool(assessment.get("decision", {}).get("userAlert", False)),
            "auraActionabilityClass": assessment.get("decision", {}).get("actionabilityClass"),
            "defensiveFindingTypes": sorted(defensive_findings_by_package.get(package_name, [])),
            "baselines": [baseline.__dict__ for baseline in baselines],
        }
        if label is not None:
            row["label"] = {
                "expectedDecision": label.expected_decision,
                "controlledAbuse": label.controlled_abuse,
                "userActionable": label.user_actionable,
                "platformAudit": label.platform_audit,
                "abstentionExpected": label.abstention_expected,
                "expectedDefensiveFindings": list(label.expected_defensive_findings),
            }
        rows.append(row)

    return {
        "schemaVersion": 1,
        "scanId": export.get("scanId"),
        "evaluatedApps": len(rows),
        "labelledApps": len(labels),
        "metrics": compute_metrics(rows),
        "modelMetrics": compute_model_metrics(rows),
        "comparisons": compute_comparisons(rows),
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
            "defensive_surface_recall": 0.0,
        }

    labelled = [row for row in rows if "label" in row]
    metric_rows = labelled if labelled else rows

    aura_red = sum(1 for row in metric_rows if row["auraDecision"] == "RED")
    aura_blue = sum(1 for row in metric_rows if row["auraDecision"] == "BLUE")
    aura_gray = sum(1 for row in metric_rows if row["auraDecision"] == "GRAY")
    permission_critical = sum(
        1
        for row in metric_rows
        for baseline in row["baselines"]
        if baseline["model"] == "permission_only" and baseline["decision"] == "CRITICAL"
    )

    non_actionable = [
        row
        for row in metric_rows
        if row.get("label", {}).get("userActionable") is False
    ]
    non_actionable_red = sum(1 for row in non_actionable if row["auraDecision"] == "RED")
    red_rows = [row for row in metric_rows if row["auraDecision"] == "RED"]
    red_user_actionable = sum(1 for row in red_rows if row.get("label", {}).get("userActionable") is True)
    controlled_abuse = [row for row in metric_rows if row.get("label", {}).get("controlledAbuse") is True]
    controlled_abuse_red = sum(1 for row in controlled_abuse if row["auraDecision"] == "RED")
    platform_audit = [row for row in metric_rows if row.get("label", {}).get("platformAudit") is True]
    platform_audit_blue = sum(1 for row in platform_audit if row["auraDecision"] == "BLUE")
    abstention_expected = [row for row in metric_rows if row.get("label", {}).get("abstentionExpected") is True]
    abstention_gray = sum(1 for row in abstention_expected if row["auraDecision"] == "GRAY")
    expected_defensive = [
        (row, finding)
        for row in metric_rows
        for finding in row.get("label", {}).get("expectedDefensiveFindings", [])
    ]
    observed_expected_defensive = sum(
        1
        for row, finding in expected_defensive
        if finding in row.get("defensiveFindingTypes", [])
    )

    return {
        "non_actionable_critical_alert_rate": round(
            non_actionable_red / max(1, len(non_actionable)),
            4,
        ),
        "user_actionable_precision": round(red_user_actionable / max(1, len(red_rows)), 4),
        "red_recall_controlled_abuse": round(
            controlled_abuse_red / max(1, len(controlled_abuse)),
            4,
        ),
        "blue_platform_audit_separation": round(
            platform_audit_blue / max(1, len(platform_audit)),
            4,
        ),
        "abstention_correctness": round(
            abstention_gray / max(1, len(abstention_expected)),
            4,
        ),
        "defensive_surface_recall": round(
            observed_expected_defensive / max(1, len(expected_defensive)),
            4,
        ),
        "permission_only_critical_rate": round(permission_critical / len(metric_rows), 4),
        "aura_red_rate": round(aura_red / len(metric_rows), 4),
        "aura_blue_rate": round(aura_blue / len(metric_rows), 4),
        "aura_gray_rate": round(aura_gray / len(metric_rows), 4),
        "metric_population": float(len(metric_rows)),
    }


def row_population(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    labelled = [row for row in rows if "label" in row]
    return labelled if labelled else rows


def baseline_by_model(row: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        baseline["model"]: baseline
        for baseline in row.get("baselines", [])
    }


def model_decision(row: dict[str, Any], model: str) -> str | None:
    if model == "full_aura":
        return row.get("auraDecision")
    baseline = baseline_by_model(row).get(model)
    if baseline is None:
        return None
    return baseline.get("decision")


def model_names(rows: list[dict[str, Any]]) -> list[str]:
    names = {
        baseline["model"]
        for row in rows
        for baseline in row.get("baselines", [])
    }
    return sorted(names)


def compute_model_metrics(rows: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    metric_rows = row_population(rows)
    if not metric_rows:
        return {}

    output: dict[str, dict[str, float]] = {}
    for model in model_names(metric_rows):
        alerts = [
            row
            for row in metric_rows
            if is_critical_decision(model_decision(row, model))
        ]
        non_actionable = [
            row
            for row in metric_rows
            if row.get("label", {}).get("userActionable") is False
        ]
        non_actionable_alerts = [
            row
            for row in non_actionable
            if is_critical_decision(model_decision(row, model))
        ]
        actionable_alerts = [
            row
            for row in alerts
            if row.get("label", {}).get("userActionable") is True
        ]
        controlled_abuse = [
            row
            for row in metric_rows
            if row.get("label", {}).get("controlledAbuse") is True
        ]
        controlled_abuse_alerts = [
            row
            for row in controlled_abuse
            if is_critical_decision(model_decision(row, model))
        ]
        platform_audit = [
            row
            for row in metric_rows
            if row.get("label", {}).get("platformAudit") is True
        ]
        platform_audit_separated = [
            row
            for row in platform_audit
            if model_decision(row, model) == "BLUE"
        ]
        abstention_expected = [
            row
            for row in metric_rows
            if row.get("label", {}).get("abstentionExpected") is True
        ]
        abstentions = [
            row
            for row in abstention_expected
            if is_abstention_decision(model_decision(row, model))
        ]

        output[model] = {
            "critical_alert_rate": round(len(alerts) / len(metric_rows), 4),
            "non_actionable_critical_alert_rate": round(
                len(non_actionable_alerts) / max(1, len(non_actionable)),
                4,
            ),
            "user_actionable_precision": round(
                len(actionable_alerts) / max(1, len(alerts)),
                4,
            ),
            "controlled_abuse_recall": round(
                len(controlled_abuse_alerts) / max(1, len(controlled_abuse)),
                4,
            ),
            "platform_audit_separation": round(
                len(platform_audit_separated) / max(1, len(platform_audit)),
                4,
            ),
            "abstention_correctness": round(
                len(abstentions) / max(1, len(abstention_expected)),
                4,
            ),
        }
    return output


def compute_comparisons(rows: list[dict[str, Any]]) -> dict[str, float]:
    metrics = compute_model_metrics(rows)
    permission = metrics.get("permission_only")
    full = metrics.get("full_aura")
    if not permission or not full:
        return {}
    return {
        "aura_non_actionable_critical_alert_rate_reduction_vs_permission_only": round(
            permission["non_actionable_critical_alert_rate"] -
            full["non_actionable_critical_alert_rate"],
            4,
        ),
        "aura_user_actionable_precision_delta_vs_permission_only": round(
            full["user_actionable_precision"] -
            permission["user_actionable_precision"],
            4,
        ),
        "aura_controlled_abuse_recall_delta_vs_permission_only": round(
            full["controlled_abuse_recall"] -
            permission["controlled_abuse_recall"],
            4,
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("export", type=Path, help="AURA JSON export")
    parser.add_argument("--labels", type=Path, help="Optional scenario labels for controlled metrics")
    parser.add_argument("--out", type=Path, help="Optional output path")
    args = parser.parse_args()

    result = evaluate(json.loads(args.export.read_text()), load_labels(args.labels))
    payload = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        args.out.write_text(payload + "\n")
    else:
        print(payload)


if __name__ == "__main__":
    main()
