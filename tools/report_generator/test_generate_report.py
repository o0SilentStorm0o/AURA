#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_report import render_html, render_markdown, write_report

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "export_redactor"))
from redact_export import REDACTED_EXPERT, redact_export


def export_fixture() -> dict:
    return {
        "schemaVersion": 1,
        "scanId": "scan-1",
        "generatedAt": 1_700_000_000_000,
        "flavor": "researchFull/standard",
        "assessments": [
            {
                "snapshot": {
                    "packageName": "com.flashlight.cleaner.update",
                    "appLabel": "Security Update",
                    "installerPackageName": None,
                    "rawFeatures": {"sourcePartition": "data_app"},
                    "specialAccess": {
                        "accessibility_service": "OBSERVED_ENABLED",
                        "notification_listener": "OBSERVED_ENABLED",
                        "overlay": "OBSERVED_ENABLED",
                    },
                    "apiLevel": 34,
                    "androidVersion": "14",
                    "securityPatchLevel": "2023-09-05",
                    "collectorVersion": "aura-collector-test",
                    "deviceModel": "Pixel Test",
                    "flavor": "researchFull/standard",
                },
                "role": {"predicted": "UNKNOWN_SIDELOAD", "confidence": 0.62},
                "provenance": {"provenanceClass": "UNKNOWN_SIDELOAD", "confidence": 0.66},
                "riskVector": {
                    "harm": 0.9,
                    "legitimacy": 0.18,
                    "abuseEvidence": 0.86,
                    "provenanceConfidence": 0.66,
                    "provenanceTrust": 0.18,
                    "actionability": 0.86,
                    "uncertainty": 0.2,
                },
                "decision": {
                    "color": "RED",
                    "title": "User-actionable threat",
                    "userAlert": True,
                    "expertFinding": True,
                    "actionabilityClass": "USER_CAN_DISABLE_SPECIAL_ACCESS",
                    "explanation": "Concrete abuse evidence is active.",
                    "recommendedActions": [
                        {
                            "title": "Disable risky special access",
                            "description": "Disable active Accessibility or overlay access.",
                        }
                    ],
                },
                "decisionTrace": {
                    "policyVersion": "0.1.0",
                    "evaluatedRules": [
                        {"ruleId": "RED_USER_ACTIONABLE_THREAT", "matched": True},
                    ],
                    "counterfactuals": [
                        {
                            "targetDecision": "YELLOW",
                            "requiredChanges": ["Disable active risky special access."],
                        }
                    ],
                    "invariantChecks": [
                        {"invariantId": "RED_REQUIRES_ACTIVE_RISKY_CAPABILITY", "passed": True}
                    ],
                },
                "userRiskStory": {
                    "headline": "Action required",
                    "primaryReason": "Unknown app has active risky special access.",
                    "whatWasObserved": ["Active special access: accessibility_service, overlay"],
                },
                "evidence": [
                    {
                        "source": "DECISION_POLICY",
                        "observabilityState": "OBSERVED_ENABLED",
                        "confidence": 0.88,
                        "humanExplanation": "Risk vector separates harm from actionability.",
                    }
                ],
                "evidenceGraph": {"nodes": [{"nodeId": "app"}], "edges": []},
            }
        ],
        "temporalEpisodes": [
            {
                "packageName": "com.flashlight.cleaner.update",
                "type": "SIDELOAD_TO_ACCESSIBILITY",
                "explanation": "Accessibility enabled after install.",
            }
        ],
        "defensiveSurfaceFindings": [
            {
                "packageName": "com.flashlight.cleaner.update",
                "findingType": "UNPROTECTED_EXPORTED_COMPONENT",
                "severity": "HIGH",
                "confidence": 0.86,
                "humanExplanation": "Exported component has no permission.",
            }
        ],
        "defensivePostures": [
            {
                "packageName": "com.flashlight.cleaner.update",
                "postureClass": "WEAK_DEFENSIVE_SURFACE",
                "findingCount": 1,
                "highestSeverity": "HIGH",
            }
        ],
        "scanHistory": {"retainedScanCount": 1, "retainedPackageCount": 1},
    }


def evaluation_fixture() -> dict:
    return {
        "evaluatedApps": 10,
        "labelledApps": 1,
        "metrics": {"decision_trace_completeness": 1.0},
        "modelMetrics": {
            "permission_only": {
                "critical_alert_rate": 1.0,
                "non_actionable_critical_alert_rate": 0.5,
                "user_actionable_precision": 0.5,
                "controlled_abuse_recall": 1.0,
                "platform_audit_separation": 0.0,
            },
            "full_aura": {
                "critical_alert_rate": 1.0,
                "non_actionable_critical_alert_rate": 0.0,
                "user_actionable_precision": 1.0,
                "controlled_abuse_recall": 1.0,
                "platform_audit_separation": 1.0,
            },
        },
        "comparisons": {
            "aura_non_actionable_critical_alert_rate_reduction_vs_permission_only": 0.5,
            "aura_user_actionable_precision_delta_vs_permission_only": 0.5,
            "aura_controlled_abuse_recall_delta_vs_permission_only": 0.0,
        },
    }


class GenerateReportTest(unittest.TestCase):
    def test_markdown_contains_core_report_sections(self) -> None:
        markdown = render_markdown(export_fixture(), evaluation_fixture())

        self.assertIn("AURA Android App Risk Report", markdown)
        self.assertIn("Overall Conclusion", markdown)
        self.assertIn("Scope and Environment", markdown)
        self.assertIn("Threat decision: `RED`", markdown)
        self.assertIn("Defensive posture: `WEAK_DEFENSIVE_SURFACE`", markdown)
        self.assertIn("Decision trace:", markdown)
        self.assertIn("Baseline Comparison on Labelled Scenario Subset", markdown)
        self.assertIn("Unlabelled apps excluded from baseline metrics: `9`", markdown)
        self.assertIn("Non-actionable critical alert reduction", markdown)
        self.assertIn("Provenance trust/explainability: `0.18`", markdown)
        self.assertIn("SETTINGS_SNAPSHOT / OBSERVED_ENABLED: `accessibility_service`", markdown)
        self.assertNotIn("DECISION_POLICY / OBSERVED_ENABLED", markdown)
        self.assertIn("Observability Limits", markdown)

    def test_html_is_print_ready_and_escapes_content(self) -> None:
        html = render_html("# Title\n\n- value with <tag>\n")

        self.assertIn("<!doctype html>", html)
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("@media print", html)
        self.assertIn("&lt;tag&gt;", html)

    def test_html_escapes_attacker_controlled_app_strings(self) -> None:
        payload = export_fixture()
        payload["assessments"][0]["snapshot"]["appLabel"] = "<script>alert(1)</script>"
        payload["assessments"][0]["snapshot"]["specialAccess"] = {}
        payload["temporalEpisodes"] = []
        payload["assessments"][0]["evidence"].append(
            {
                "source": "ROLE_RULE",
                "observabilityState": "OBSERVED_ENABLED",
                "confidence": 0.7,
                "humanExplanation": "<img src=x onerror=alert(1)>",
            }
        )

        html = render_html(render_markdown(payload, evaluation_fixture()))

        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("<img src=x onerror=alert(1)>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)

    def test_write_report_creates_markdown_and_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            md_path, html_path = write_report(
                export_fixture(),
                evaluation_fixture(),
                Path(tmp),
                "sample-report",
                top_apps=3,
            )

            self.assertTrue(md_path.exists())
            self.assertTrue(html_path.exists())
            self.assertIn("sample", md_path.name)

    def test_markdown_honors_redacted_export_privacy(self) -> None:
        redacted = redact_export(export_fixture(), mode=REDACTED_EXPERT, salt="report-test", salt_provided=True)
        markdown = render_markdown(redacted, evaluation_fixture())

        self.assertIn("Report privacy mode: `REDACTED_EXPERT`", markdown)
        self.assertIn("Package identifiers: `hmac_sha256_alias`", markdown)
        self.assertNotIn("com.flashlight.cleaner.update", markdown)
        self.assertNotIn("Security Update", markdown)


if __name__ == "__main__":
    unittest.main()
