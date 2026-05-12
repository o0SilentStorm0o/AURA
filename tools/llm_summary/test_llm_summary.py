#!/usr/bin/env python3
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from llm_summary import product_copy_lint, sanitize_llm_text, summarize_audit, validate_llm_output


def audit_fixture() -> dict:
    return {
        "findingGroups": [
            {
                "groupId": "PAYMENT_REDIRECT_SURFACE_REVIEW",
                "id": "AURA-GRP-12345678",
                "title": "Payment / financial redirect surfaces need review",
                "status": "SHOULD_FIX",
                "priority": "P2",
                "findingIds": ["AURA-REL-11111111", "AURA-REL-22222222"],
                "componentClass": "PAYMENT_REDIRECT",
                "sdk": "Stripe",
                "componentCount": 2,
                "sourceFindingTypes": ["UNPROTECTED_EXPORTED_COMPONENT"],
                "recommendedReview": ["Confirm URI scheme, host, and path constraints."],
                "customerSummary": "AURA grouped 2 component-level items into this review area.",
                "evidenceStrength": {
                    "level": "Manifest-level only",
                    "exploitability": "Not proven",
                    "needs": ["APK offline analysis", "source review", "dynamic test"],
                    "summary": "Manifest-level only; exploitability not proven; needs: APK offline analysis / source review / dynamic test.",
                },
            }
        ]
    }


class LlmSummaryTest(unittest.TestCase):
    def test_template_summary_references_existing_group_and_docs(self) -> None:
        payload = summarize_audit(audit_fixture(), llm_mode="off")

        self.assertEqual("rule_based_template", payload["source"])
        self.assertTrue(payload["validation"]["accepted"])
        self.assertEqual("PAYMENT_REDIRECT_SURFACE_REVIEW", payload["groupSummaries"][0]["groupId"])
        self.assertEqual(["AURA-REL-11111111", "AURA-REL-22222222"], payload["groupSummaries"][0]["findingIds"])
        self.assertIn("Manifest-level only", payload["groupSummaries"][0]["confidenceText"])
        self.assertNotIn("AURA grouped", payload["groupSummaries"][0]["customerSummary"])
        self.assertTrue(payload["groupSummaries"][0]["docIds"])

    def test_empty_audit_does_not_report_llm_failure(self) -> None:
        payload = summarize_audit(
            {"findingGroups": []},
            llm_mode="strict",
            local_llm_url="http://127.0.0.1:1",
        )

        self.assertEqual("rule_based_template_no_review_areas", payload["source"])
        self.assertEqual([], payload["groupSummaries"])
        self.assertTrue(payload["validation"]["accepted"])
        self.assertFalse(payload["validation"]["fallbackUsed"])
        self.assertIn("nothing for the LLM to summarize", payload["validation"]["reason"])

    def test_validation_rejects_hallucinated_finding_and_doc_ids(self) -> None:
        candidate = {
            "groups": [
                {
                    "groupId": "PAYMENT_REDIRECT_SURFACE_REVIEW",
                    "findingIds": ["AURA-REL-NOTREAL"],
                    "customerSummary": "Looks exploitable.",
                    "recommendedReview": [],
                    "confidenceText": "bad",
                    "docIds": ["unknown_doc"],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            doc_path = Path(tmp) / "doc.md"
            doc_path.write_text("# Doc\n\ndoc_id: allowed_doc\n\ntext")
            docs = [{"doc_id": "allowed_doc", "text": doc_path.read_text()}]
            valid, errors = validate_llm_output(candidate, audit_fixture(), docs)

        self.assertFalse(valid)
        self.assertTrue(any("unknown ID" in error for error in errors))
        self.assertTrue(any("unknown doc_id" in error for error in errors))
        self.assertTrue(any("exploit" in error for error in errors))

    def test_validation_rejects_product_copy_antipatterns(self) -> None:
        candidate = {
            "groups": [
                {
                    "groupId": "PAYMENT_REDIRECT_SURFACE_REVIEW",
                    "findingIds": ["AURA-REL-11111111"],
                    "customerSummary": "AURA has grouped these issues and found a vulnerability in our app.",
                    "recommendedReview": ["Guarantee this is safe before release."],
                    "confidenceText": "Manifest-level only; exploitability not proven.",
                    "docIds": ["allowed_doc"],
                }
            ]
        }
        docs = [{"doc_id": "allowed_doc", "text": "doc"}]
        valid, errors = validate_llm_output(candidate, audit_fixture(), docs)

        self.assertFalse(valid)
        self.assertTrue(any("grouping narration" in error for error in errors))
        self.assertTrue(any("vulnerability" in error for error in errors))
        self.assertTrue(any("guarantee" in error.lower() for error in errors))
        self.assertFalse(any("exploitability not proven" in error for error in errors))

    def test_product_copy_lint_allows_evidence_limit_language(self) -> None:
        errors = product_copy_lint("Manifest-level only; exploitability not proven.")

        self.assertEqual([], errors)

    def test_sanitizer_removes_first_person_customer_copy(self) -> None:
        text = sanitize_llm_text("These issues affect our app and our application.")

        self.assertNotIn("our app", text.lower())
        self.assertNotIn("our application", text.lower())
        self.assertIn("the assessed app", text)
        self.assertIn("the assessed application", text)


if __name__ == "__main__":
    unittest.main()
