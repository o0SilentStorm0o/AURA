#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_real_world import classify_report, markdown_summary


class RealWorldValidationTest(unittest.TestCase):
    def test_classifies_sensitive_component_as_promising(self) -> None:
        audit = {
            "findings": [
                {
                    "type": "EXPORTED_COMPONENT_WITHOUT_GUARD",
                    "status": "SHOULD_FIX",
                    "priority": "P2",
                    "evidence": {"rawValue": "activity:com.example.PaymentRedirectActivity"},
                    "requiresManualReview": True,
                }
            ],
            "priorityCounts": {"P1": 0, "P2": 1, "P3": 0, "INFO": 0},
            "policyQualityMetrics": {"manualReviewRate": 1.0},
        }

        result = classify_report(audit)

        self.assertEqual("promising_but_needs_triage", result["commercialValue"])
        self.assertEqual(1, result["findingClassCounts"]["valuable"])
        self.assertTrue(result["goodTeaserCandidate"])

    def test_flags_large_sdk_component_surface_as_noise_risk(self) -> None:
        findings = []
        for index in range(12):
            findings.append(
                {
                    "type": "EXPORTED_COMPONENT_WITHOUT_GUARD",
                    "status": "REVIEW",
                    "priority": "P3",
                    "evidence": {"rawValue": f"activity:com.facebook.Component{index}"},
                    "requiresManualReview": True,
                }
            )
        audit = {
            "findings": findings,
            "priorityCounts": {"P1": 0, "P2": 0, "P3": 12, "INFO": 0},
            "policyQualityMetrics": {"manualReviewRate": 1.0},
        }

        result = classify_report(audit)

        self.assertIn("too_many_customer_visible_review_areas", result["noiseFlags"])
        self.assertIn("sdk_component_context_needed", result["noiseFlags"])
        self.assertFalse(result["goodTeaserCandidate"])

    def test_summary_contains_product_interpretation(self) -> None:
        summary = markdown_summary(
            [
                {
                    "targetId": "demo",
                    "clientName": "Client",
                    "appName": "App",
                    "packageName": "com.example",
                    "profile": {"appCategory": "public_info", "dataSensitivity": "low"},
                    "validationRole": "negative_control",
                    "releaseStatus": {"status": "PASS"},
                    "priorityCounts": {"P1": 0, "P2": 0, "P3": 0},
                    "policyQualityMetrics": {"manualReviewRate": 0.0, "actionableRate": 0.0},
                    "classification": {
                        "commercialValue": "negative_control",
                        "noiseFlags": [],
                        "goodTeaserCandidate": False,
                        "customerVisibleFindingCount": 0,
                        "customerVisibleReviewAreaCount": 0,
                        "findingClassCounts": {},
                        "sdkLikeComponentCount": 0,
                    },
                    "validationNote": "No panic.",
                    "reportHtml": "artifacts/demo.html",
                    "topFindings": [],
                }
            ],
            Path("export.json"),
        )

        self.assertIn("Product Interpretation", summary)
        self.assertIn("Negative-control apps", summary)


if __name__ == "__main__":
    unittest.main()
