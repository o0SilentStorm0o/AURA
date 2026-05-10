#!/usr/bin/env python3
from __future__ import annotations

import unittest
import sys
import tempfile
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate import ScenarioLabel, evaluate, load_labels


def assessment(
    package_name: str,
    decision: str,
    requested_permissions: list[str] | None = None,
    components: list[dict] | None = None,
    special_access: dict[str, str] | None = None,
    risk_vector: dict[str, float] | None = None,
) -> dict:
    return {
        "snapshot": {
            "packageName": package_name,
            "requestedPermissions": requested_permissions or [],
            "components": components or [],
            "specialAccess": special_access or {
                "accessibility_service": "OBSERVED_DISABLED",
                "notification_listener": "OBSERVED_DISABLED",
                "overlay": "OBSERVED_DISABLED",
                "request_install_packages": "OBSERVED_DISABLED",
            },
        },
        "riskVector": risk_vector or {
            "harm": 0.1,
            "legitimacy": 0.9,
            "abuseEvidence": 0.1,
            "provenanceConfidence": 0.8,
        },
        "decision": {
            "color": decision,
            "userAlert": decision == "RED",
            "actionabilityClass": "USER_CAN_ONLY_REVIEW",
            "recommendedActions": [
                {
                    "actionId": "unit_action",
                    "userFacing": decision == "RED",
                }
            ],
        },
        "evidenceGraph": {
            "nodes": [{"nodeId": "decision:unit", "type": "DECISION"}],
            "edges": [{"from": "risk-vector:unit", "to": "decision:unit", "relation": "DERIVES"}],
        },
    }


class EvaluatorMetricsTest(unittest.TestCase):
    def test_load_labels_skips_unlabeled_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "labels.json"
            path.write_text(
                """{
                  "schemaVersion": 1,
                  "labels": [
                    {"packageName": "com.example.unlabeled", "reviewStatus": "UNLABELED"},
                    {"packageName": "com.example.reviewed", "reviewStatus": "REVIEWED", "expectedDecision": "RED"}
                  ]
                }"""
            )

            labels = load_labels(path)

        self.assertEqual({"com.example.reviewed"}, set(labels))

    def test_model_metrics_show_aura_false_positive_reduction(self) -> None:
        export = {
            "scanId": "unit-scan",
            "assessments": [
                assessment(
                    "com.android.camera",
                    "GREEN",
                    requested_permissions=[
                        "android.permission.CAMERA",
                        "android.permission.RECORD_AUDIO",
                        "android.permission.ACCESS_FINE_LOCATION",
                    ],
                    risk_vector={
                        "harm": 0.76,
                        "legitimacy": 0.9,
                        "abuseEvidence": 0.1,
                        "provenanceConfidence": 0.85,
                    },
                ),
                assessment(
                    "com.flashlight.cleaner.update",
                    "RED",
                    requested_permissions=[
                        "android.permission.SYSTEM_ALERT_WINDOW",
                        "android.permission.REQUEST_INSTALL_PACKAGES",
                        "android.permission.RECEIVE_BOOT_COMPLETED",
                    ],
                    components=[
                        {"permission": "android.permission.BIND_ACCESSIBILITY_SERVICE"},
                        {"permission": "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"},
                    ],
                    special_access={
                        "accessibility_service": "OBSERVED_ENABLED",
                        "notification_listener": "OBSERVED_ENABLED",
                        "overlay": "OBSERVED_ENABLED",
                        "request_install_packages": "DECLARED_ONLY",
                    },
                    risk_vector={
                        "harm": 0.9,
                        "legitimacy": 0.1,
                        "abuseEvidence": 0.9,
                        "provenanceConfidence": 0.1,
                    },
                ),
                assessment("com.example.lowriskutility", "GRAY"),
                assessment(
                    "com.oem.telemetry",
                    "BLUE",
                    requested_permissions=["android.permission.READ_SMS"],
                    risk_vector={
                        "harm": 0.65,
                        "legitimacy": 0.45,
                        "abuseEvidence": 0.2,
                        "provenanceConfidence": 0.5,
                    },
                ),
            ],
        }
        labels = {
            "com.android.camera": ScenarioLabel(
                package_name="com.android.camera",
                user_actionable=False,
            ),
            "com.flashlight.cleaner.update": ScenarioLabel(
                package_name="com.flashlight.cleaner.update",
                controlled_abuse=True,
                user_actionable=True,
            ),
            "com.example.lowriskutility": ScenarioLabel(
                package_name="com.example.lowriskutility",
                user_actionable=False,
                abstention_expected=True,
            ),
            "com.oem.telemetry": ScenarioLabel(
                package_name="com.oem.telemetry",
                user_actionable=False,
                platform_audit=True,
            ),
        }

        result = evaluate(export, labels)

        self.assertEqual(0.3333, result["modelMetrics"]["permission_only"]["non_actionable_critical_alert_rate"])
        self.assertEqual(0.0, result["modelMetrics"]["full_aura"]["non_actionable_critical_alert_rate"])
        self.assertEqual(0.5, result["modelMetrics"]["permission_only"]["user_actionable_precision"])
        self.assertEqual(1.0, result["modelMetrics"]["full_aura"]["user_actionable_precision"])
        self.assertEqual(1.0, result["modelMetrics"]["full_aura"]["platform_audit_separation"])
        self.assertEqual(1.0, result["modelMetrics"]["full_aura"]["abstention_correctness"])
        self.assertEqual(["unit_action"], result["rows"][0]["auraRecommendedActionIds"])
        self.assertEqual(1, result["rows"][0]["evidenceGraphNodeCount"])
        self.assertEqual(1, result["rows"][0]["evidenceGraphEdgeCount"])
        self.assertEqual(
            0.3333,
            result["comparisons"]["aura_non_actionable_critical_alert_rate_reduction_vs_permission_only"],
        )


if __name__ == "__main__":
    unittest.main()
