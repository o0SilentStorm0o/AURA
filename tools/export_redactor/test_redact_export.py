#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
from redact_export import FULL_RESEARCH, MINIMAL_SUPPORT, REDACTED_EXPERT, REDACTED_TEASER, redact_export


SECRET_PACKAGE = "com.flashlight.cleaner.update"
SECRET_LABEL = "Security Update"
SECRET_SOURCE = "/data/app/~~secret/com.flashlight.cleaner.update-abc/base.apk"
SECRET_DIGEST = "12206d517b68f280e5fd90ffcfcf4dc3554b07addaeabafa2fcbc7e28aedefd6"


def export_fixture() -> dict:
    return {
        "schemaVersion": 1,
        "scanId": "scan-1",
        "generatedAt": 1_700_000_000_000,
        "flavor": "researchFull/standard",
        "assessments": [
            {
                "snapshot": {
                    "snapshotId": "snap-1",
                    "packageName": SECRET_PACKAGE,
                    "appLabel": SECRET_LABEL,
                    "versionName": "1.2.3-private",
                    "uid": 12345,
                    "installerPackageName": "com.android.shell",
                    "sourceDir": SECRET_SOURCE,
                    "signingCertDigestsSha256": [SECRET_DIGEST],
                    "components": [
                        {
                            "name": f"{SECRET_PACKAGE}.FakeAccessibilityService",
                            "type": "service",
                            "exported": True,
                            "permission": "android.permission.BIND_ACCESSIBILITY_SERVICE",
                        }
                    ],
                    "requestedPermissions": ["android.permission.SYSTEM_ALERT_WINDOW"],
                    "grantedPermissions": [],
                    "rawFeatures": {
                        "sourcePartition": "data_app",
                        "foregroundSensitiveAppPackage": "com.example.bank",
                    },
                },
                "role": {"predicted": "UNKNOWN_SIDELOAD", "confidence": 0.62},
                "provenance": {"provenanceClass": "UNKNOWN_SIDELOAD", "confidence": 0.66},
                "riskVector": {
                    "harm": 0.9,
                    "legitimacy": 0.18,
                    "abuseEvidence": 0.86,
                    "provenanceConfidence": 0.66,
                    "actionability": 0.86,
                    "uncertainty": 0.2,
                },
                "decision": {
                    "color": "RED",
                    "userAlert": True,
                    "actionabilityClass": "USER_CAN_DISABLE_SPECIAL_ACCESS",
                    "recommendedActions": [
                        {
                            "actionId": "disable_risky_special_access",
                            "title": "Disable risky special access",
                            "description": f"Disable access for {SECRET_PACKAGE}.",
                        }
                    ],
                },
                "decisionTrace": {
                    "policyVersion": "0.1.0",
                    "evaluatedRules": [
                        {"ruleId": "RED_USER_ACTIONABLE_THREAT", "matched": True},
                    ],
                },
                "userRiskStory": {
                    "primaryReason": f"{SECRET_LABEL} has active risky special access.",
                    "whatWasObserved": [f"Observed {SECRET_PACKAGE} in sensitive context."],
                },
                "evidence": [
                    {
                        "evidenceId": "ev_provenance_secret",
                        "source": "PROVENANCE_RULE",
                        "rawValue": f"installer=com.android.shell;sourceDir={SECRET_SOURCE};signingDigests={SECRET_DIGEST}",
                        "normalizedValue": "UNKNOWN_SIDELOAD",
                        "confidence": 0.66,
                        "observabilityState": "OBSERVED_ENABLED",
                        "privacyImpact": "APP_METADATA",
                        "supports": ["provenance.unknown_sideload"],
                        "contradicts": [],
                        "humanExplanation": f"{SECRET_LABEL} has unknown provenance.",
                    },
                    {
                        "evidenceId": "ev_component_secret",
                        "source": "MANIFEST_COMPONENT",
                        "rawValue": f"service:{SECRET_PACKAGE}.FakeAccessibilityService",
                        "normalizedValue": "unprotected-exported-component",
                        "confidence": 0.8,
                        "observabilityState": "DECLARED_ONLY",
                        "privacyImpact": "APP_METADATA",
                        "supports": ["defensive.component"],
                        "contradicts": [],
                        "humanExplanation": "Manifest component was declared.",
                    },
                ],
                "evidenceGraph": {
                    "nodes": [
                        {
                            "nodeId": f"app:{SECRET_PACKAGE}",
                            "type": "APP",
                            "label": SECRET_LABEL,
                            "value": SECRET_PACKAGE,
                            "confidence": 1.0,
                        }
                    ],
                    "edges": [
                        {
                            "from": "evidence:ev_provenance_secret",
                            "to": f"app:{SECRET_PACKAGE}",
                            "relation": "OBSERVED_FOR",
                            "evidenceId": "ev_provenance_secret",
                        }
                    ],
                },
            },
            {
                "snapshot": {
                    "packageName": "com.example.camera",
                    "appLabel": "Camera Fixture",
                    "installerPackageName": "com.android.vending",
                    "sourceDir": "/data/app/com.example.camera/base.apk",
                    "signingCertDigestsSha256": ["f" * 64],
                    "components": [],
                    "rawFeatures": {"sourcePartition": "data_app"},
                },
                "decision": {"color": "GREEN"},
                "riskVector": {"harm": 0.5, "abuseEvidence": 0.0},
                "evidence": [],
            },
        ],
        "temporalEpisodes": [
            {
                "episodeId": "episode-secret",
                "packageName": SECRET_PACKAGE,
                "type": "SIDELOAD_TO_ACCESSIBILITY",
                "supportingEvidenceIds": ["ev_provenance_secret"],
                "explanation": f"{SECRET_PACKAGE} enabled Accessibility.",
            }
        ],
        "defensiveSurfaceFindings": [
            {
                "findingId": f"def_{SECRET_PACKAGE}_component",
                "packageName": SECRET_PACKAGE,
                "findingType": "UNPROTECTED_EXPORTED_COMPONENT",
                "severity": "HIGH",
                "confidence": 0.86,
                "evidence": [
                    {
                        "evidenceId": "ev_component_secret",
                        "source": "MANIFEST_COMPONENT",
                        "rawValue": f"service:{SECRET_PACKAGE}.FakeAccessibilityService",
                    }
                ],
            }
        ],
        "defensivePostures": [
            {
                "packageName": SECRET_PACKAGE,
                "postureClass": "WEAK_DEFENSIVE_SURFACE",
                "findingCount": 1,
                "highestSeverity": "HIGH",
                "findingIds": [f"def_{SECRET_PACKAGE}_component"],
            }
        ],
        "scanHistory": {
            "schemaVersion": 1,
            "retainedScanCount": 1,
            "retainedPackageCount": 2,
            "scans": [{"scanId": "scan-1", "packageCount": 2}],
            "packagesChangedSincePreviousScan": [SECRET_PACKAGE],
            "packagesNewInThisScan": ["com.example.camera"],
            "packagesRemovedSincePreviousScan": [],
        },
    }


def serialized(data: dict) -> str:
    return json.dumps(data, sort_keys=True)


class RedactExportTest(unittest.TestCase):
    def assert_no_secret_values(self, data: dict) -> None:
        text = serialized(data)
        self.assertNotIn(SECRET_PACKAGE, text)
        self.assertNotIn(SECRET_LABEL, text)
        self.assertNotIn(SECRET_SOURCE, text)
        self.assertNotIn(SECRET_DIGEST, text)
        self.assertNotIn("FakeAccessibilityService", text)
        self.assertNotIn("1.2.3-private", text)

    def test_redacted_expert_keeps_decisions_but_removes_identifiers(self) -> None:
        redacted = redact_export(export_fixture(), mode=REDACTED_EXPERT, salt="test-salt", salt_provided=True)

        self.assertEqual(redacted["privacy"]["mode"], "REDACTED_EXPERT")
        self.assertTrue(redacted["privacy"]["fullInventoryIncluded"])
        self.assertEqual(redacted["privacy"]["packageIdentifierStrategy"], "hmac_sha256_alias")
        self.assertEqual(len(redacted["assessments"]), 2)
        self.assertEqual(redacted["assessments"][0]["decision"]["color"], "RED")
        self.assertIn("app_", redacted["assessments"][0]["snapshot"]["packageName"])
        self.assertEqual(redacted["assessments"][0]["snapshot"]["installerPackageName"], "adb_or_shell")
        self.assertEqual(redacted["assessments"][0]["snapshot"]["sourceDir"], "<redacted:data_app>")
        self.assertEqual(redacted["assessments"][0]["evidence"][1]["rawValue"], "<redacted_component_metadata>")
        self.assert_no_secret_values(redacted)

    def test_redacted_aliases_are_consistent_across_sections(self) -> None:
        redacted = redact_export(export_fixture(), mode=REDACTED_EXPERT, salt="test-salt", salt_provided=True)
        alias = redacted["assessments"][0]["snapshot"]["packageName"]

        self.assertEqual(redacted["temporalEpisodes"][0]["packageName"], alias)
        self.assertEqual(redacted["defensiveSurfaceFindings"][0]["packageName"], alias)
        self.assertEqual(redacted["defensivePostures"][0]["packageName"], alias)
        self.assertIn(alias, redacted["scanHistory"]["packagesChangedSincePreviousScan"])

    def test_minimal_support_keeps_summary_and_priority_only(self) -> None:
        minimal = redact_export(
            export_fixture(),
            mode=MINIMAL_SUPPORT,
            salt="test-salt",
            salt_provided=True,
            max_minimal_assessments=1,
        )

        self.assertEqual(minimal["privacy"]["mode"], "MINIMAL_SUPPORT")
        self.assertFalse(minimal["privacy"]["fullInventoryIncluded"])
        self.assertEqual(minimal["summary"]["assessedAppCount"], 2)
        self.assertEqual(minimal["summary"]["includedAssessmentCount"], 1)
        self.assertEqual(len(minimal["assessments"]), 1)
        self.assertEqual(minimal["assessments"][0]["decision"]["color"], "RED")
        self.assertIn("packagesChangedSincePreviousScanCount", minimal["scanHistory"])
        self.assert_no_secret_values(minimal)

    def test_redacted_teaser_suppresses_raw_report_detail(self) -> None:
        teaser = redact_export(export_fixture(), mode=REDACTED_TEASER, salt="teaser-salt", salt_provided=True)

        self.assertEqual(teaser["privacy"]["mode"], "REDACTED_TEASER")
        self.assertEqual(teaser["privacy"]["componentNames"], "suppressed")
        self.assertEqual(teaser["privacy"]["rawEvidence"], "suppressed")
        self.assertEqual(teaser["privacy"]["policyThresholds"], "suppressed")
        self.assertEqual(teaser["assessments"][0]["snapshot"]["components"], [])
        self.assertEqual(teaser["assessments"][0]["snapshot"]["signingCertDigestsSha256"], [])
        self.assertEqual(teaser["assessments"][0]["snapshot"]["requestedPermissions"], [])
        self.assertEqual(teaser["assessments"][0]["snapshot"]["grantedPermissions"], [])
        self.assertNotIn("rawValue", serialized(teaser["assessments"][0]["evidence"]))
        self.assertNotIn("evidenceIds", serialized(teaser["assessments"][0]["decision"]))
        self.assertNotIn("evidenceIds", serialized(teaser["assessments"][0]["role"]))
        self.assertNotIn("evidenceIds", serialized(teaser["assessments"][0]["provenance"]))
        self.assertTrue(teaser["assessments"][0]["riskVector"]["suppressed"])
        self.assertTrue(teaser["assessments"][0]["evidenceGraph"]["suppressed"])
        self.assertTrue(teaser["assessments"][0]["decisionTrace"]["suppressed"])
        self.assertTrue(teaser["defensiveSurfaceFindings"][0]["detailSuppressed"])
        self.assertEqual(teaser["defensiveSurfaceFindings"][0]["evidence"], [])
        self.assertTrue(teaser["scanHistory"]["packageListsSuppressed"])
        self.assertNotIn("packagesChangedSincePreviousScan", teaser["scanHistory"])
        self.assertNotIn("packagesNewInThisScan", teaser["scanHistory"])
        self.assert_no_secret_values(teaser)

    def test_full_research_marks_mode_without_redaction(self) -> None:
        full = redact_export(export_fixture(), mode=FULL_RESEARCH)

        self.assertEqual(full["privacy"]["mode"], "FULL_RESEARCH")
        self.assertFalse(full["privacy"]["redactionApplied"])
        self.assertIn(SECRET_PACKAGE, serialized(full))


if __name__ == "__main__":
    unittest.main()
