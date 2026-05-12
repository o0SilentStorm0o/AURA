#!/usr/bin/env python3
from __future__ import annotations

import copy
import sys
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
        self.assertEqual("Exported provider without permission guard", audit["findings"][0]["title"])
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
