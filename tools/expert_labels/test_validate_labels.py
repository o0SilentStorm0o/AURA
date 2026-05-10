#!/usr/bin/env python3
from __future__ import annotations

import unittest
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_labels import validate


class ExpertLabelValidatorTest(unittest.TestCase):
    def test_accepts_valid_minimal_labels(self) -> None:
        errors = validate(
            {
                "schemaVersion": 1,
                "labels": [
                    {
                        "packageName": "com.example.app",
                        "expectedDecision": "GRAY",
                        "controlledAbuse": False,
                        "userActionable": False,
                        "platformAudit": False,
                        "abstentionExpected": True,
                        "expectedDefensiveFindings": [],
                    }
                ],
            }
        )

        self.assertEqual([], errors)

    def test_rejects_duplicate_packages_and_unknown_findings(self) -> None:
        errors = validate(
            {
                "schemaVersion": 1,
                "labels": [
                    {
                        "packageName": "com.example.app",
                        "expectedDecision": "RED",
                    },
                    {
                        "packageName": "com.example.app",
                        "expectedDefensiveFindings": ["NOT_A_FINDING"],
                    },
                ],
            }
        )

        self.assertTrue(any("duplicates" in error for error in errors))
        self.assertTrue(any("unknown finding" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
