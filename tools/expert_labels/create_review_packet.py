#!/usr/bin/env python3
"""Create a human-review packet from an AURA JSON export."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


CSV_FIELDS = [
    "packageName",
    "appLabel",
    "decisionColor",
    "decisionTitle",
    "userAlert",
    "expertFinding",
    "actionabilityClass",
    "role",
    "roleConfidence",
    "provenance",
    "provenanceConfidence",
    "harm",
    "legitimacy",
    "abuseEvidence",
    "actionability",
    "uncertainty",
    "sourcePartition",
    "installerPackageName",
    "recommendedActions",
    "riskStoryHeadline",
    "riskStoryPrimaryReason",
    "decisionTracePolicyVersion",
    "matchedPolicyRules",
    "counterfactuals",
    "evidenceGraphNodes",
    "evidenceGraphEdges",
    "evidenceSummary",
    "defensivePosture",
    "defensiveFindings",
    "reviewerExpectedDecision",
    "reviewerControlledAbuse",
    "reviewerUserActionable",
    "reviewerPlatformAudit",
    "reviewerAbstentionExpected",
    "reviewerNotes",
]


def compact(value: Any, limit: int = 240) -> str:
    text = str(value or "").replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 1] + "..."


def score(value: Any) -> str:
    try:
        return f"{float(value):.4f}"
    except (TypeError, ValueError):
        return ""


def defensive_findings_by_package(export: dict[str, Any]) -> dict[str, list[str]]:
    output: dict[str, list[str]] = {}
    for finding in export.get("defensiveSurfaceFindings", []):
        output.setdefault(finding.get("packageName", ""), []).append(finding.get("findingType", ""))
    return output


def defensive_postures_by_package(export: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        posture.get("packageName", ""): posture
        for posture in export.get("defensivePostures", [])
    }


def evidence_summary(assessment: dict[str, Any], limit: int) -> str:
    entries = []
    for item in assessment.get("evidence", [])[:limit]:
        entries.append(
            compact(
                f"{item.get('source')}:{item.get('normalizedValue')} "
                f"conf={item.get('confidence')} obs={item.get('observabilityState')}"
            )
        )
    return " | ".join(entries)


def action_summary(assessment: dict[str, Any]) -> str:
    return ";".join(
        action.get("actionId", "")
        for action in assessment.get("decision", {}).get("recommendedActions", [])
        if action.get("actionId")
    )


def matched_rule_summary(assessment: dict[str, Any]) -> str:
    return ";".join(
        rule.get("ruleId", "")
        for rule in assessment.get("decisionTrace", {}).get("evaluatedRules", [])
        if rule.get("matched") is True and rule.get("ruleId")
    )


def counterfactual_summary(assessment: dict[str, Any]) -> str:
    entries = []
    for item in assessment.get("decisionTrace", {}).get("counterfactuals", []):
        entries.append(
            compact(
                f"{item.get('targetDecision')}: "
                f"{'; '.join(item.get('requiredChanges', []))}"
            )
        )
    return " | ".join(entries)


def row_for_assessment(
    assessment: dict[str, Any],
    findings_by_package: dict[str, list[str]],
    postures_by_package: dict[str, dict[str, Any]],
    evidence_limit: int,
) -> dict[str, Any]:
    snapshot = assessment.get("snapshot", {})
    decision = assessment.get("decision", {})
    role = assessment.get("role", {})
    provenance = assessment.get("provenance", {})
    risk = assessment.get("riskVector", {})
    graph = assessment.get("evidenceGraph", {})
    trace = assessment.get("decisionTrace", {})
    story = assessment.get("userRiskStory", {})
    package_name = snapshot.get("packageName", "")
    posture = postures_by_package.get(package_name, {})
    return {
        "packageName": package_name,
        "appLabel": snapshot.get("appLabel", ""),
        "decisionColor": decision.get("color", ""),
        "decisionTitle": decision.get("title", ""),
        "userAlert": decision.get("userAlert", False),
        "expertFinding": decision.get("expertFinding", False),
        "actionabilityClass": decision.get("actionabilityClass", ""),
        "role": role.get("predicted", ""),
        "roleConfidence": score(role.get("confidence")),
        "provenance": provenance.get("provenanceClass", ""),
        "provenanceConfidence": score(provenance.get("confidence")),
        "harm": score(risk.get("harm")),
        "legitimacy": score(risk.get("legitimacy")),
        "abuseEvidence": score(risk.get("abuseEvidence")),
        "actionability": score(risk.get("actionability")),
        "uncertainty": score(risk.get("uncertainty")),
        "sourcePartition": snapshot.get("rawFeatures", {}).get("sourcePartition", ""),
        "installerPackageName": snapshot.get("installerPackageName") or "",
        "recommendedActions": action_summary(assessment),
        "riskStoryHeadline": story.get("headline", ""),
        "riskStoryPrimaryReason": story.get("primaryReason", ""),
        "decisionTracePolicyVersion": trace.get("policyVersion", ""),
        "matchedPolicyRules": matched_rule_summary(assessment),
        "counterfactuals": counterfactual_summary(assessment),
        "evidenceGraphNodes": len(graph.get("nodes", [])),
        "evidenceGraphEdges": len(graph.get("edges", [])),
        "evidenceSummary": evidence_summary(assessment, evidence_limit),
        "defensivePosture": posture.get("postureClass", ""),
        "defensiveFindings": ";".join(sorted(findings_by_package.get(package_name, []))),
        "reviewerExpectedDecision": "",
        "reviewerControlledAbuse": "",
        "reviewerUserActionable": "",
        "reviewerPlatformAudit": "",
        "reviewerAbstentionExpected": "",
        "reviewerNotes": "",
    }


def build_rows(export: dict[str, Any], evidence_limit: int = 3) -> list[dict[str, Any]]:
    findings = defensive_findings_by_package(export)
    postures = defensive_postures_by_package(export)
    return [
        row_for_assessment(assessment, findings, postures, evidence_limit)
        for assessment in export.get("assessments", [])
    ]


def label_item_for_assessment(assessment: dict[str, Any]) -> dict[str, Any]:
    snapshot = assessment.get("snapshot", {})
    decision = assessment.get("decision", {})
    return {
        "packageName": snapshot.get("packageName", ""),
        "reviewStatus": "UNLABELED",
        "observedDecision": decision.get("color"),
        "expectedDecision": None,
        "controlledAbuse": False,
        "userActionable": False,
        "platformAudit": False,
        "abstentionExpected": False,
        "expectedDefensiveFindings": [],
        "reviewerNotes": "",
    }


def build_label_template(export: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "sourceScanId": export.get("scanId"),
        "labels": [
            label_item_for_assessment(assessment)
            for assessment in export.get("assessments", [])
        ],
    }


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def write_json(payload: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="Path to an AURA JSON export")
    parser.add_argument("--csv", type=Path, required=True, help="Output reviewer CSV path")
    parser.add_argument(
        "--labels-template",
        type=Path,
        required=True,
        help="Output labels JSON template path",
    )
    parser.add_argument("--evidence-limit", type=int, default=3)
    args = parser.parse_args()

    export = json.loads(args.export.read_text())
    rows = build_rows(export, evidence_limit=args.evidence_limit)
    write_csv(rows, args.csv)
    write_json(build_label_template(export), args.labels_template)
    print(f"Wrote {len(rows)} review rows to {args.csv}")
    print(f"Wrote labels template to {args.labels_template}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
