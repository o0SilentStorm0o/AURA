#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
from create_review_packet import build_label_template, build_rows, write_csv


def assessment(package_name: str = "com.example.app") -> dict:
    return {
        "snapshot": {
            "packageName": package_name,
            "appLabel": "Example App",
            "installerPackageName": None,
            "rawFeatures": {"sourcePartition": "data_app"},
        },
        "role": {"predicted": "UNKNOWN_SIDELOAD", "confidence": 0.62},
        "provenance": {"provenanceClass": "UNKNOWN_SIDELOAD", "confidence": 0.66},
        "riskVector": {
            "harm": 0.9,
            "legitimacy": 0.18,
            "abuseEvidence": 0.86,
            "actionability": 0.86,
            "uncertainty": 0.2,
        },
        "decision": {
            "color": "RED",
            "title": "User-actionable threat",
            "userAlert": True,
            "expertFinding": True,
            "actionabilityClass": "USER_CAN_DISABLE_SPECIAL_ACCESS",
            "recommendedActions": [
                {"actionId": "disable_risky_special_access"},
                {"actionId": "uninstall_or_disable_app"},
            ],
        },
        "evidence": [
            {
                "source": "ROLE_RULE",
                "normalizedValue": "UNKNOWN_SIDELOAD",
                "confidence": 0.62,
                "observabilityState": "OBSERVED_ENABLED",
            }
        ],
        "evidenceGraph": {
            "nodes": [{"nodeId": "app:com.example.app"}],
            "edges": [{"from": "risk", "to": "decision:RED"}],
        },
    }


class ReviewPacketTest(unittest.TestCase):
    def test_build_rows_flattens_export_for_review(self) -> None:
        export = {
            "scanId": "scan-1",
            "assessments": [assessment()],
            "defensiveSurfaceFindings": [
                {
                    "packageName": "com.example.app",
                    "findingType": "DEBUGGABLE_SENSITIVE_APP",
                }
            ],
        }

        rows = build_rows(export)

        self.assertEqual(1, len(rows))
        self.assertEqual("com.example.app", rows[0]["packageName"])
        self.assertEqual("RED", rows[0]["decisionColor"])
        self.assertEqual(
            "disable_risky_special_access;uninstall_or_disable_app",
            rows[0]["recommendedActions"],
        )
        self.assertEqual("DEBUGGABLE_SENSITIVE_APP", rows[0]["defensiveFindings"])
        self.assertEqual(1, rows[0]["evidenceGraphNodes"])
        self.assertEqual(1, rows[0]["evidenceGraphEdges"])

    def test_label_template_is_unlabeled_by_default(self) -> None:
        template = build_label_template({"scanId": "scan-1", "assessments": [assessment()]})

        self.assertEqual("scan-1", template["sourceScanId"])
        self.assertEqual("UNLABELED", template["labels"][0]["reviewStatus"])
        self.assertIsNone(template["labels"][0]["expectedDecision"])

    def test_write_csv_creates_reviewable_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.csv"
            write_csv(build_rows({"assessments": [assessment()]}), path)

            text = path.read_text()

        self.assertIn("packageName", text)
        self.assertIn("com.example.app", text)


if __name__ == "__main__":
    unittest.main()
