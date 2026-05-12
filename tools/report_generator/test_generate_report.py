#!/usr/bin/env python3
from __future__ import annotations

import copy
import tempfile
import unittest
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_report import render_html, render_markdown, write_report
from generate_report import scope_export_to_package

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "export_redactor"))
from redact_export import REDACTED_EXPERT, REDACTED_TEASER, redact_export


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


def offline_analysis_fixture(finding_type: str = "CLEARTEXT_TRAFFIC_ALLOWED_MANIFEST") -> dict:
    return {
        "schemaVersion": 1,
        "analyzerVersion": "aura-offline-apk-analyzer-test",
        "generatedAt": 1_700_000_000_000,
        "apks": [
            {
                "schemaVersion": 1,
                "analyzerVersion": "aura-offline-apk-analyzer-test",
                "apk": {
                    "path": "/Users/david/AURA/testapps/suspicious/build/outputs/apk/debug/suspicious.apk",
                    "sha256": "a" * 64,
                    "packageName": "com.flashlight.cleaner.update",
                    "label": "Security Update",
                    "targetSdkVersion": "35",
                },
                "observations": {
                    "sensitiveRoleHint": True,
                    "debuggable": True,
                    "allowBackup": False,
                    "usesCleartextTraffic": True,
                    "networkSecurityConfig": {
                        "observabilityState": "OBSERVED_ENABLED",
                        "referenced": "@xml/network_security_config",
                    },
                    "flagSecure": {
                        "observed": False,
                        "observabilityState": "UNKNOWN_API_LIMITATION",
                        "confidence": 0.5,
                    },
                    "filterTouchesWhenObscured": {
                        "observed": False,
                        "observabilityState": "UNKNOWN_API_LIMITATION",
                        "confidence": 0.42,
                    },
                    "accessibilityDataSensitive": {
                        "observed": False,
                        "observabilityState": "UNKNOWN_API_LIMITATION",
                        "confidence": 0.35,
                    },
                },
                "findings": [
                    {
                        "findingId": "offline-1",
                        "findingType": finding_type,
                        "severity": "MEDIUM",
                        "confidence": 0.92,
                        "observabilityState": "OBSERVED_ENABLED",
                        "evidenceSource": "manifest",
                        "rawValue": "android:usesCleartextTraffic=true",
                        "explanation": "The manifest permits cleartext traffic.",
                    }
                ],
                "limitations": [
                    "Static absence of UI defensive controls is not runtime proof.",
                ],
            }
        ],
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
        html = render_html("# Title\n\nRelease readiness: **Blocked before release**.\n\n- value with <tag>\n")

        self.assertIn("<!doctype html>", html)
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("<title>Title</title>", html)
        self.assertIn("@media print", html)
        self.assertIn("<strong>Blocked before release</strong>", html)
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

    def test_app_owner_report_focuses_target_and_remediation(self) -> None:
        payload = export_fixture()
        payload["assessments"].append(
            {
                "snapshot": {
                    "packageName": "com.example.camera",
                    "appLabel": "Camera",
                    "rawFeatures": {"sourcePartition": "data_app"},
                    "specialAccess": {},
                },
                "role": {"predicted": "CAMERA", "confidence": 0.9},
                "provenance": {"provenanceClass": "PLAY_INSTALLED", "confidence": 0.78},
                "riskVector": {
                    "harm": 0.3,
                    "legitimacy": 0.9,
                    "abuseEvidence": 0.1,
                    "provenanceTrust": 0.76,
                    "provenanceConfidence": 0.78,
                    "actionability": 0.1,
                    "uncertainty": 0.1,
                },
                "decision": {"color": "GREEN", "title": "Expected for role", "recommendedActions": []},
                "decisionTrace": {"policyVersion": "0.1.0", "evaluatedRules": [], "invariantChecks": []},
                "userRiskStory": {},
                "evidence": [],
            }
        )
        scoped = scope_export_to_package(payload, "com.flashlight.cleaner.update")
        scoped["privacy"] = {
            "mode": "REDACTED_EXPERT",
            "redactionApplied": True,
            "fullInventoryIncluded": False,
            "packageIdentifierStrategy": "hmac_sha256_alias",
        }

        markdown = render_markdown(
            scoped,
            report_type="app_owner",
            offline_analysis=offline_analysis_fixture(),
            app_profile={
                "appCategory": "fintech",
                "dataSensitivity": "high",
                "releaseStage": "production_candidate",
                "payments": True,
            },
        )

        self.assertIn("AURA App Owner Release Risk Report", markdown)
        self.assertIn("Release Readiness", markdown)
        self.assertIn("Top Fix Plan", markdown)
        self.assertIn("Top Review Areas", markdown)
        self.assertIn("Release Risk Findings", markdown)
        self.assertIn("Blocked before release", markdown)
        self.assertIn("App profile | `fintech` / `high` / `production_candidate`", markdown)
        self.assertIn("fintech_policy", markdown)
        self.assertIn("For fintech apps", markdown)
        self.assertIn("P1", markdown)
        self.assertIn("EXPORTED_COMPONENT_WITHOUT_GUARD", markdown)
        self.assertIn("Release-Risk Retest Diff", markdown)
        self.assertIn("Accepted Risks and Not Applicable Items", markdown)
        self.assertIn("Policy Quality Metrics", markdown)
        self.assertIn("Acceptance criteria", markdown)
        self.assertIn("Verification command/check", markdown)
        self.assertIn("Evidence strength", markdown)
        self.assertIn("Exploitability", markdown)
        self.assertIn("Suggested owner", markdown)
        self.assertIn("Capability and Component Surface", markdown)
        self.assertIn("Offline APK Analyzer Findings", markdown)
        self.assertIn("OFFLINE_APK_ANALYZER", markdown)
        self.assertIn("MASVS-NETWORK", markdown)
        self.assertIn("AURA-OFF-001", markdown)
        self.assertIn("<redacted:apk_path>", markdown)
        self.assertIn("Runtime Abuse Context", markdown)
        self.assertIn("The release-risk list above is canonical", markdown)
        self.assertNotIn("Legacy Defensive Finding Appendix", markdown)
        self.assertNotIn("## Remediation Checklist", markdown)
        self.assertNotIn("[open] No user action required", markdown)
        self.assertNotIn("## Retest Comparison", markdown)
        self.assertIn("Report scope: `target_app_only`", markdown)
        self.assertIn("Full device inventory rows included: `no`", markdown)
        self.assertNotIn("com.example.camera", markdown)

    def test_app_owner_retest_comparison_shows_fixed_and_new_findings(self) -> None:
        previous = export_fixture()
        current = copy.deepcopy(previous)
        current["defensiveSurfaceFindings"] = [
            {
                "packageName": "com.flashlight.cleaner.update",
                "findingType": "CLEARTEXT_TRAFFIC_ALLOWED",
                "severity": "MEDIUM",
                "confidence": 0.7,
            }
        ]
        previous_scoped = scope_export_to_package(previous, "com.flashlight.cleaner.update")
        current_scoped = scope_export_to_package(current, "com.flashlight.cleaner.update")

        markdown = render_markdown(
            current_scoped,
            report_type="app_owner",
            previous_export=previous_scoped,
            offline_analysis=offline_analysis_fixture("NETWORK_SECURITY_CONFIG_CLEARTEXT_PERMITTED"),
            previous_offline_analysis=offline_analysis_fixture("CLEARTEXT_TRAFFIC_ALLOWED_MANIFEST"),
        )

        self.assertIn("| Fixed | 1 | `EXPORTED_COMPONENT_WITHOUT_GUARD` |", markdown)
        self.assertIn("| Remaining | 1 | `CLEARTEXT_TRAFFIC_ALLOWED` |", markdown)
        self.assertIn("| New/regressed | 0 | `none` |", markdown)

    def test_app_owner_report_accepts_validated_group_summary_payload(self) -> None:
        scoped = scope_export_to_package(export_fixture(), "com.flashlight.cleaner.update")

        markdown = render_markdown(
            scoped,
            report_type="app_owner",
            offline_analysis=offline_analysis_fixture("NETWORK_SECURITY_CONFIG_CLEARTEXT_PERMITTED"),
            group_summary_payload={
                "groupSummaries": [
                    {
                        "groupId": "NETWORK_TRANSPORT_REVIEW",
                        "customerSummary": "Validated local LLM wording for the network review area.",
                        "recommendedReview": ["Confirm release config has no broad cleartext exception."],
                        "confidenceText": "Static APK analysis only; exploitability not proven.",
                    }
                ]
            },
        )

        self.assertIn("Validated local LLM wording for the network review area.", markdown)
        self.assertIn("Confirm release config has no broad cleartext exception.", markdown)
        self.assertIn("Static APK analysis only; exploitability not proven.", markdown)

    def test_app_owner_report_can_audit_unredacted_source_while_rendering_redacted_export(self) -> None:
        scoped = scope_export_to_package(export_fixture(), "com.flashlight.cleaner.update")
        scoped["defensiveSurfaceFindings"][0]["rawValue"] = (
            "activity:com.stripe.android.payments.StripeBrowserProxyReturnActivity;"
            "activity:com.stripe.android.link.LinkRedirectHandlerActivity"
        )
        redacted = redact_export(scoped, mode=REDACTED_EXPERT, salt="report-test", salt_provided=True)

        markdown = render_markdown(
            redacted,
            report_type="app_owner",
            audit_export=scoped,
            app_profile={
                "appCategory": "ecommerce",
                "dataSensitivity": "medium",
                "releaseStage": "production_candidate",
                "payments": True,
            },
        )

        self.assertIn("Payment / financial redirect surfaces need review", markdown)
        self.assertIn("callback state/nonce", markdown)
        self.assertIn("Report privacy mode: `REDACTED_EXPERT`", markdown)
        self.assertNotIn("StripeBrowserProxyReturnActivity", markdown)

    def test_public_teaser_suppresses_raw_detail_and_sets_scope(self) -> None:
        scoped = scope_export_to_package(export_fixture(), "com.flashlight.cleaner.update")
        redacted = redact_export(scoped, mode=REDACTED_TEASER, salt="teaser-test", salt_provided=True)
        redacted.setdefault("reportScope", {})
        redacted["reportScope"] = {
            **redacted["reportScope"],
            "reportType": "public_teaser",
            "clientName": "Example Studio",
            "publicAppName": "Example Public App",
            "publicSourceUrl": "https://play.google.com/store/apps/details?id=example",
        }
        redacted["privacy"]["fullInventoryIncluded"] = False
        redacted["privacy"]["reportScope"] = "public_surface_teaser_target_only"

        markdown = render_markdown(
            redacted,
            evaluation_fixture(),
            report_type="public_teaser",
            max_findings=2,
        )

        self.assertIn("AURA Public-Surface Demo Report", markdown)
        self.assertIn("This is not a vulnerability report", markdown)
        self.assertIn("Public-surface teaser / outreach demo", markdown)
        self.assertIn("Example Public App", markdown)
        self.assertIn("Example Studio", markdown)
        self.assertIn("No account login", markdown)
        self.assertIn("What the Authorized Full Report Would Add", markdown)
        self.assertIn("Report privacy mode: `REDACTED_TEASER`", markdown)
        self.assertIn("priority review area available in full report", markdown)
        self.assertIn("Component names: `suppressed`", markdown)
        self.assertIn("Raw evidence detail: `suppressed`", markdown)
        self.assertIn("Policy thresholds: `suppressed`", markdown)
        self.assertIn("Full device inventory rows included: `no`", markdown)
        self.assertIn("platform/component surface review", markdown)
        self.assertNotIn("UNPROTECTED_EXPORTED_COMPONENT", markdown)
        self.assertNotIn("WEAK_DEFENSIVE_SURFACE", markdown)
        self.assertNotIn("component has no permission", markdown)
        self.assertNotIn("Exported component has no permission.", markdown)
        self.assertNotIn("Risk vector:", markdown)
        self.assertNotIn("Decision trace:", markdown)


if __name__ == "__main__":
    unittest.main()
