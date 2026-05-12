#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_engine import build_audit, compare_audits


def export_fixture() -> dict:
    return {
        "assessments": [
            {
                "snapshot": {
                    "packageName": "com.example.app",
                },
                "decision": {
                    "color": "GREEN",
                    "title": "Expected for role",
                },
                "role": {"predicted": "ECOMMERCE_MARKETPLACE"},
                "provenance": {"provenanceClass": "PLAY_INSTALLED"},
            }
        ],
        "defensiveSurfaceFindings": [
            {
                "packageName": "com.example.app",
                "findingId": "on-device-exported",
                "findingType": "UNPROTECTED_EXPORTED_COMPONENT",
                "severity": "HIGH",
                "confidence": 0.91,
                "observabilityState": "OBSERVED_ENABLED",
                "rawValue": "provider:.LeakyProvider",
            }
        ],
    }


def offline_fixture() -> dict:
    return {
        "apks": [
            {
                "apk": {"packageName": "com.example.app"},
                "findings": [
                    {
                        "findingId": "offline-cleartext",
                        "findingType": "NETWORK_SECURITY_CONFIG_CLEARTEXT_PERMITTED",
                        "severity": "MEDIUM",
                        "confidence": 0.88,
                        "observabilityState": "OBSERVED_ENABLED",
                        "rawValue": "res/xml/network_security_config.xml",
                    },
                    {
                        "findingId": "offline-sdk",
                        "findingType": "THIRD_PARTY_SDK_PRIVACY_SURFACE",
                        "severity": "INFO",
                        "confidence": 0.66,
                        "observabilityState": "OBSERVED_ENABLED",
                        "rawValue": "AppsFlyer,Sentry",
                    },
                ],
            }
        ]
    }


class AppOwnerAuditEngineTest(unittest.TestCase):
    def test_build_audit_prioritizes_release_risk_over_threat_decision(self) -> None:
        audit = build_audit(export_fixture(), offline_analysis=offline_fixture())

        self.assertEqual("BLOCKED", audit["releaseStatus"]["status"])
        self.assertFalse(audit["releaseStatus"]["readyForProduction"])
        self.assertEqual("GREEN", audit["threatContext"]["decision"])
        self.assertEqual({"P1": 1, "P2": 1, "P3": 0, "INFO": 1}, audit["priorityCounts"])
        self.assertEqual("EXPORTED_COMPONENT_WITHOUT_GUARD", audit["findings"][0]["type"])
        self.assertEqual("Exported provider without permission guard: LeakyProvider", audit["findings"][0]["title"])
        self.assertIn("Acceptance criteria", f"Acceptance criteria: {audit['findings'][0]['acceptanceCriteria']}")
        self.assertIn("offline APK analyzer", audit["findings"][0]["verificationCheck"])
        self.assertIn("Set exported=false", audit["findings"][0]["howToFix"])
        self.assertTrue(audit["findings"][0]["requiresManualReview"])
        self.assertRegex(audit["findings"][0]["fingerprint"], r"^[a-f0-9]{24}$")

    def test_offline_findings_suppress_on_device_aggregate_duplicates(self) -> None:
        export = export_fixture()
        export["defensiveSurfaceFindings"].append(
            {
                "packageName": "com.example.app",
                "findingId": "on-device-cleartext",
                "findingType": "CLEARTEXT_TRAFFIC_ALLOWED",
                "severity": "MEDIUM",
                "confidence": 0.7,
                "observabilityState": "OBSERVED_ENABLED",
                "rawValue": "usesCleartextTraffic=true;networkSecurityConfig=not-parsed-on-device",
            }
        )

        audit = build_audit(export, offline_analysis=offline_fixture())
        cleartext_findings = [
            finding for finding in audit["findings"]
            if finding["type"] == "CLEARTEXT_TRAFFIC_ALLOWED"
        ]

        self.assertEqual(1, len(cleartext_findings))
        self.assertEqual("OFFLINE_APK_ANALYZER", cleartext_findings[0]["evidence"]["source"])
        self.assertEqual("ON_DEVICE", cleartext_findings[0]["additionalEvidence"][0]["source"])

    def test_type_level_offline_findings_are_merged_into_single_release_task(self) -> None:
        offline = {
            "apks": [
                {
                    "apk": {"packageName": "com.example.app"},
                    "findings": [
                        {
                            "findingId": "offline-backup",
                            "findingType": "BACKUP_ALLOWED",
                            "severity": "MEDIUM",
                            "confidence": 0.82,
                            "observabilityState": "OBSERVED_ENABLED",
                            "rawValue": "allowBackup=true",
                        },
                        {
                            "findingId": "offline-backup-rules",
                            "findingType": "BACKUP_ALLOWED_WITHOUT_EXPLICIT_RULES",
                            "severity": "LOW",
                            "confidence": 0.74,
                            "observabilityState": "OBSERVED_ENABLED",
                            "rawValue": "No backup_rules.xml or data_extraction_rules.xml observed",
                        },
                    ],
                }
            ]
        }

        audit = build_audit(export_fixture(), offline_analysis=offline)
        backup_findings = [
            finding for finding in audit["findings"]
            if finding["type"] == "BACKUP_MAY_INCLUDE_SENSITIVE_DATA"
        ]

        self.assertEqual(1, len(backup_findings))
        self.assertEqual(0.82, backup_findings[0]["confidence"])
        self.assertEqual(1, len(backup_findings[0]["additionalEvidence"]))

    def test_aggregate_exported_components_split_into_ticket_ready_findings(self) -> None:
        export = export_fixture()
        export["defensiveSurfaceFindings"][0]["rawValue"] = "activity:.PaymentReturnActivity;receiver:.CampaignReceiver;service:.SyncService"

        audit = build_audit(
            export,
            app_profile={
                "appCategory": "ecommerce",
                "dataSensitivity": "medium",
                "releaseStage": "production_candidate",
            },
        )
        exported = [
            finding for finding in audit["findings"]
            if finding["type"] == "EXPORTED_COMPONENT_WITHOUT_GUARD"
        ]

        self.assertEqual(3, len(exported))
        self.assertEqual(
            ["activity", "receiver", "service"],
            sorted(finding["affectedSurface"]["kind"] for finding in exported),
        )
        activity = [
            finding for finding in exported
            if finding["affectedSurface"]["kind"] == "activity"
        ][0]
        self.assertIn("PaymentReturnActivity", activity["evidence"]["rawValue"])
        self.assertIn("PaymentReturnActivity", activity["title"])
        self.assertEqual("P2", activity["priority"])
        self.assertIn("ecommerce_policy.ecommerce_exported_payment_auth_activity_should_fix", activity["policyTrace"])

    def test_payment_redirect_components_are_grouped_into_review_area(self) -> None:
        export = export_fixture()
        export["defensiveSurfaceFindings"][0]["rawValue"] = (
            "activity:com.stripe.android.financialconnections.FinancialConnectionsSheetLiteRedirectActivity;"
            "activity:com.stripe.android.link.LinkRedirectHandlerActivity;"
            "activity:com.stripe.android.payments.StripeBrowserProxyReturnActivity"
        )

        audit = build_audit(
            export,
            app_profile={
                "appCategory": "ecommerce",
                "dataSensitivity": "medium",
                "releaseStage": "production_candidate",
                "payments": True,
            },
        )
        payment_group = [
            group for group in audit["findingGroups"]
            if group["title"] == "Payment / financial redirect surfaces need review"
        ][0]

        self.assertEqual(3, payment_group["componentCount"])
        self.assertEqual(3, payment_group["findingCount"])
        self.assertEqual("PAYMENT_ACCOUNT_FLOW_SURFACE_REVIEW", payment_group["groupId"])
        self.assertEqual("Payment / financial redirect surfaces need review", payment_group["title"])
        self.assertEqual("Manifest-level only", payment_group["evidenceStrength"]["level"])
        self.assertEqual("Not proven", payment_group["evidenceStrength"]["exploitability"])
        self.assertIn("APK offline analysis", payment_group["evidenceStrength"]["needs"])
        self.assertIn("callback state/nonce", payment_group["groupAcceptanceCriteria"])
        self.assertIn("offline APK analysis or source review", payment_group["groupVerificationCheck"])
        self.assertIn("externally reachable", payment_group["customerSummary"])
        self.assertNotIn("AURA grouped", payment_group["customerSummary"])
        self.assertGreaterEqual(audit["policyQualityMetrics"]["groupedFindingReduction"], 2)
        self.assertEqual(
            {"PAYMENT_REDIRECT"},
            {finding["componentClassification"]["componentClass"] for finding in audit["findings"]},
        )

    def test_sdk_preview_and_browser_surfaces_are_classified_before_policy_copy(self) -> None:
        export = export_fixture()
        export["defensiveSurfaceFindings"][0]["rawValue"] = (
            "activity:com.google.android.gms.tagmanager.TagManagerPreviewActivity;"
            "activity:com.facebook.CustomTabActivity;"
            "service:com.huawei.hms.push.HmsMsgService;"
            "activity:com.example.WebViewActivity"
        )

        audit = build_audit(
            export,
            app_profile={
                "appCategory": "ecommerce",
                "dataSensitivity": "medium",
                "releaseStage": "production_candidate",
            },
        )
        classes = {
            finding["title"]: finding["componentClassification"]["componentClass"]
            for finding in audit["findings"]
        }
        group_ids = {group["groupId"] for group in audit["findingGroups"]}

        self.assertIn("PREVIEW_OR_TOOLING", set(classes.values()))
        self.assertIn("SDK_CALLBACK", set(classes.values()))
        self.assertIn("PUSH_SERVICE", set(classes.values()))
        self.assertIn("WEBVIEW_ENTRYPOINT", set(classes.values()))
        self.assertIn("PREVIEW_TOOLING_RELEASE_REVIEW", group_ids)
        self.assertIn("THIRD_PARTY_SDK_EXPORTED_SURFACES", group_ids)
        self.assertIn("APP_ROUTING_ENTRYPOINT_REVIEW", group_ids)
        sdk_group = [
            group for group in audit["findingGroups"]
            if group["groupId"] == "THIRD_PARTY_SDK_EXPORTED_SURFACES"
        ][0]
        self.assertIn("SDK callback surface is expected", sdk_group["groupAcceptanceCriteria"])
        self.assertIn("privacy/disclosure", sdk_group["groupAcceptanceCriteria"])

    def test_app_profile_changes_backup_priority_by_context(self) -> None:
        offline = {
            "apks": [
                {
                    "apk": {"packageName": "com.example.app"},
                    "findings": [
                        {
                            "findingId": "offline-backup",
                            "findingType": "BACKUP_ALLOWED",
                            "severity": "MEDIUM",
                            "confidence": 0.82,
                            "observabilityState": "OBSERVED_ENABLED",
                            "rawValue": "allowBackup=true",
                        },
                    ],
                }
            ]
        }

        fintech = build_audit(
            export_fixture(),
            offline_analysis=offline,
            app_profile={
                "appCategory": "fintech",
                "dataSensitivity": "high",
                "releaseStage": "production_candidate",
                "payments": True,
            },
        )
        public_info = build_audit(
            export_fixture(),
            offline_analysis=offline,
            app_profile={
                "appCategory": "public_info",
                "dataSensitivity": "low",
                "releaseStage": "production_candidate",
            },
        )

        fintech_backup = [
            finding for finding in fintech["findings"]
            if finding["type"] == "BACKUP_MAY_INCLUDE_SENSITIVE_DATA"
        ][0]
        public_backup = [
            finding for finding in public_info["findings"]
            if finding["type"] == "BACKUP_MAY_INCLUDE_SENSITIVE_DATA"
        ][0]

        self.assertEqual("P1", fintech_backup["priority"])
        self.assertEqual("BLOCKER", fintech_backup["status"])
        self.assertIn("fintech", fintech_backup["appProfileImpact"].lower())
        self.assertEqual("P3", public_backup["priority"])
        self.assertEqual("REVIEW", public_backup["status"])
        self.assertIn("public-info", public_backup["appProfileImpact"])

    def test_debug_build_profile_downgrades_debuggable(self) -> None:
        offline = {
            "apks": [
                {
                    "apk": {"packageName": "com.example.app"},
                    "findings": [
                        {
                            "findingId": "offline-debuggable",
                            "findingType": "DEBUGGABLE_ENABLED",
                            "severity": "HIGH",
                            "confidence": 0.96,
                            "observabilityState": "OBSERVED_ENABLED",
                            "rawValue": "android:debuggable=true",
                        },
                    ],
                }
            ]
        }

        audit = build_audit(
            export_fixture(),
            offline_analysis=offline,
            app_profile={
                "appCategory": "internal_enterprise",
                "releaseStage": "debug",
                "dataSensitivity": "medium",
            },
        )
        debuggable = [
            finding for finding in audit["findings"]
            if finding["type"] == "DEBUGGABLE_OR_TEST_CONFIG_IN_RELEASE"
        ][0]

        self.assertEqual("INFO", debuggable["priority"])
        self.assertEqual("INFO", debuggable["status"])
        self.assertEqual(0, audit["priorityCounts"]["P1"])
        self.assertIn("debug/development", debuggable["appProfileImpact"])

    def test_known_exported_component_is_contextual_review_not_blocker(self) -> None:
        audit = build_audit(
            export_fixture(),
            offline_analysis=None,
            app_profile={
                "appCategory": "fintech",
                "dataSensitivity": "high",
                "knownExportedComponents": [".LeakyProvider"],
            },
        )
        exported = [
            finding for finding in audit["findings"]
            if finding["type"] == "EXPORTED_COMPONENT_WITHOUT_GUARD"
        ][0]

        self.assertEqual("P3", exported["priority"])
        self.assertEqual("REVIEW", exported["status"])
        self.assertIn("expected", exported["appProfileImpact"])
        self.assertIn("customer_profile.known_exported_component", exported["policyTrace"])

    def test_public_info_exported_receiver_is_review_not_blocker(self) -> None:
        export = export_fixture()
        export["defensiveSurfaceFindings"][0]["rawValue"] = "receiver:.ShareReceiver"

        audit = build_audit(
            export,
            app_profile={
                "appCategory": "public_info",
                "dataSensitivity": "low",
                "releaseStage": "production_candidate",
            },
        )
        exported = [
            finding for finding in audit["findings"]
            if finding["type"] == "EXPORTED_COMPONENT_WITHOUT_GUARD"
        ][0]

        self.assertEqual("P3", exported["priority"])
        self.assertEqual("REVIEW", exported["status"])
        self.assertIn("public-info", exported["appProfileImpact"])

    def test_allowed_cleartext_domain_has_last_word_after_sensitive_policy(self) -> None:
        offline = {
            "apks": [
                {
                    "apk": {"packageName": "com.example.app"},
                    "findings": [
                        {
                            "findingId": "debug-cleartext",
                            "findingType": "NETWORK_SECURITY_CONFIG_CLEARTEXT_PERMITTED",
                            "severity": "MEDIUM",
                            "confidence": 0.88,
                            "observabilityState": "OBSERVED_ENABLED",
                            "rawValue": "domain-config cleartextTrafficPermitted=true domain=10.0.2.2",
                        }
                    ],
                }
            ]
        }

        audit = build_audit(
            export_fixture(),
            offline_analysis=offline,
            app_profile={
                "appCategory": "fintech",
                "dataSensitivity": "high",
                "releaseStage": "production_candidate",
                "allowedCleartextDomains": ["10.0.2.2"],
            },
        )
        cleartext = [
            finding for finding in audit["findings"]
            if finding["type"] == "CLEARTEXT_TRAFFIC_ALLOWED"
        ][0]

        self.assertEqual("INFO", cleartext["priority"])
        self.assertEqual("ACCEPTED_RISK", cleartext["status"])
        self.assertIn("fintech_policy.fintech_cleartext_should_fix", cleartext["policyTrace"])
        self.assertIn("customer_profile.allowed_cleartext_domain", cleartext["policyTrace"])

    def test_accepted_risk_has_last_word_and_remains_traceable(self) -> None:
        audit = build_audit(
            export_fixture(),
            offline_analysis=None,
            app_profile={
                "appCategory": "fintech",
                "dataSensitivity": "high",
                "releaseStage": "production_candidate",
                "acceptedRisks": [
                    {
                        "type": "EXPORTED_COMPONENT_WITHOUT_GUARD",
                        "rawContains": ".LeakyProvider",
                        "reason": "Temporary partner callback accepted until v2 contract migration.",
                    }
                ],
            },
        )
        exported = [
            finding for finding in audit["findings"]
            if finding["type"] == "EXPORTED_COMPONENT_WITHOUT_GUARD"
        ][0]

        self.assertEqual("INFO", exported["priority"])
        self.assertEqual("ACCEPTED_RISK", exported["status"])
        self.assertIn("Temporary partner callback", exported["appProfileImpact"])
        self.assertIn("customer_profile.accepted_risk", exported["policyTrace"])
        self.assertEqual(0, audit["priorityCounts"]["P1"])
        self.assertEqual(1, audit["policyQualityMetrics"]["acceptedRiskRecurrence"])

    def test_custom_policy_pack_is_additive_not_replacement(self) -> None:
        custom_policy = {
            "policyPackId": "customer_policy",
            "version": "0.1.0",
            "rules": [
                {
                    "ruleId": "customer_cleartext_blocker",
                    "when": {"evidenceType": "CLEARTEXT_TRAFFIC_ALLOWED"},
                    "effect": {
                        "priority": "P1",
                        "status": "BLOCKER",
                        "appProfileImpact": "Customer policy blocks all cleartext in this release.",
                    },
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "customer_policy.json"
            policy_path.write_text(json.dumps(custom_policy))
            audit = build_audit(
                export_fixture(),
                offline_analysis=offline_fixture(),
                app_profile={
                    "appCategory": "public_info",
                    "dataSensitivity": "low",
                    "releaseStage": "production_candidate",
                },
                policy_paths=[policy_path],
            )

        self.assertEqual(
            ["base_android_release_policy", "public_info_policy", "production_release_policy", "customer_policy"],
            audit["policyPacksApplied"],
        )
        cleartext = [
            finding for finding in audit["findings"]
            if finding["type"] == "CLEARTEXT_TRAFFIC_ALLOWED"
        ][0]
        backup_or_exported = [
            finding for finding in audit["findings"]
            if finding["type"] == "EXPORTED_COMPONENT_WITHOUT_GUARD"
        ][0]
        self.assertEqual("P1", cleartext["priority"])
        self.assertIn("customer_policy.customer_cleartext_blocker", cleartext["policyTrace"])
        self.assertIn("public_info_policy.public_info_exported_provider_should_fix", backup_or_exported["policyTrace"])

    def test_unclassified_fallback_is_review_not_dangerous_language(self) -> None:
        offline = {
            "apks": [
                {
                    "apk": {"packageName": "com.example.app"},
                    "findings": [
                        {
                            "findingId": "unknown",
                            "findingType": "SOME_NEW_STATIC_SIGNAL",
                            "severity": "MEDIUM",
                            "confidence": 0.5,
                            "rawValue": "new signal",
                        }
                    ],
                }
            ]
        }

        audit = build_audit(export_fixture(), offline_analysis=offline)
        fallback = [
            finding for finding in audit["findings"]
            if finding["type"] == "UNCLASSIFIED_RELEASE_REVIEW_FINDING"
        ][0]

        self.assertEqual("REVIEW", fallback["status"])
        self.assertNotIn("DANGEROUS", fallback["type"])

    def test_beta_debuggable_is_should_fix_not_blocker(self) -> None:
        offline = {
            "apks": [
                {
                    "apk": {"packageName": "com.example.app"},
                    "findings": [
                        {
                            "findingId": "offline-debuggable",
                            "findingType": "DEBUGGABLE_ENABLED",
                            "severity": "HIGH",
                            "confidence": 0.96,
                            "observabilityState": "OBSERVED_ENABLED",
                            "rawValue": "android:debuggable=true",
                        },
                    ],
                }
            ]
        }

        audit = build_audit(
            export_fixture(),
            offline_analysis=offline,
            app_profile={
                "appCategory": "ecommerce",
                "releaseStage": "beta",
                "dataSensitivity": "medium",
            },
        )
        debuggable = [
            finding for finding in audit["findings"]
            if finding["type"] == "DEBUGGABLE_OR_TEST_CONFIG_IN_RELEASE"
        ][0]

        self.assertEqual("P2", debuggable["priority"])
        self.assertEqual("SHOULD_FIX", debuggable["status"])

    def test_compare_audits_uses_stable_fingerprints(self) -> None:
        previous = build_audit(export_fixture(), offline_analysis=offline_fixture())
        current_export = copy.deepcopy(export_fixture())
        current_export["defensiveSurfaceFindings"] = []
        current = build_audit(current_export, offline_analysis=offline_fixture())

        diff = compare_audits(previous, current)

        self.assertTrue(diff["available"])
        self.assertEqual(["EXPORTED_COMPONENT_WITHOUT_GUARD"], [finding["type"] for finding in diff["fixed"]])
        self.assertEqual(
            ["CLEARTEXT_TRAFFIC_ALLOWED", "THIRD_PARTY_SDK_PRIVACY_SURFACE"],
            [finding["type"] for finding in diff["remaining"]],
        )
        self.assertEqual([], diff["new"])


if __name__ == "__main__":
    unittest.main()
