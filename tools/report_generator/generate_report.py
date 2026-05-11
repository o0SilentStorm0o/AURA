#!/usr/bin/env python3
"""Generate a print-ready AURA app risk report from a JSON export."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "export_redactor"))
from redact_export import DEFAULT_SALT, FULL_RESEARCH, PRIVACY_MODES, redact_export


REPORT_GENERATOR_VERSION = "0.2.0"
DECISION_ORDER = {"RED": 0, "YELLOW": 1, "BLUE": 2, "GRAY": 3, "GREEN": 4}
POSTURE_ORDER = {
    "WEAK_DEFENSIVE_SURFACE": 0,
    "REVIEW_RECOMMENDED": 1,
    "NO_OBSERVED_WEAKNESS": 2,
}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def load_json(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    return json.loads(path.read_text())


def decision_counts(export: dict[str, Any]) -> Counter[str]:
    summary_counts = (export.get("summary") or {}).get("decisionCounts")
    if isinstance(summary_counts, dict):
        return Counter({str(key): int(value) for key, value in summary_counts.items()})
    return Counter(
        assessment.get("decision", {}).get("color", "UNKNOWN")
        for assessment in export.get("assessments", [])
    )


def posture_counts(export: dict[str, Any]) -> Counter[str]:
    summary_counts = (export.get("summary") or {}).get("defensivePostureCounts")
    if isinstance(summary_counts, dict):
        return Counter({str(key): int(value) for key, value in summary_counts.items()})
    return Counter(
        posture.get("postureClass", "NO_OBSERVED_WEAKNESS")
        for posture in export.get("defensivePostures", [])
    )


def assessed_app_count(export: dict[str, Any]) -> int:
    summary = export.get("summary") or {}
    if summary.get("assessedAppCount") is not None:
        return int(summary["assessedAppCount"])
    return len(export.get("assessments", []))


def temporal_episode_count(export: dict[str, Any]) -> int:
    summary = export.get("summary") or {}
    if summary.get("temporalEpisodeCount") is not None:
        return int(summary["temporalEpisodeCount"])
    return len(export.get("temporalEpisodes", []))


def defensive_finding_count(export: dict[str, Any]) -> int:
    summary = export.get("summary") or {}
    if summary.get("defensiveFindingCount") is not None:
        return int(summary["defensiveFindingCount"])
    return len(export.get("defensiveSurfaceFindings", []))


def postures_by_package(export: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        posture.get("packageName", ""): posture
        for posture in export.get("defensivePostures", [])
    }


def findings_by_package(export: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in export.get("defensiveSurfaceFindings", []):
        output[finding.get("packageName", "")].append(finding)
    return output


def episodes_by_package(export: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for episode in export.get("temporalEpisodes", []):
        output[episode.get("packageName", "")].append(episode)
    return output


def first_snapshot(export: dict[str, Any]) -> dict[str, Any]:
    assessments = export.get("assessments", [])
    if not assessments:
        return {}
    return assessments[0].get("snapshot", {})


def sorted_assessments(export: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        export.get("assessments", []),
        key=lambda assessment: (
            DECISION_ORDER.get(assessment.get("decision", {}).get("color", "GREEN"), 9),
            assessment.get("snapshot", {}).get("packageName", ""),
        ),
    )


def top_posture_items(export: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        export.get("defensivePostures", []),
        key=lambda posture: (
            POSTURE_ORDER.get(posture.get("postureClass", "NO_OBSERVED_WEAKNESS"), 9),
            -int(posture.get("findingCount", 0)),
            posture.get("packageName", ""),
        ),
    )


def top_finding_types(package_findings: list[dict[str, Any]], limit: int = 3) -> str:
    if not package_findings:
        return "n/a"
    ranked = sorted(
        package_findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.get("severity", "INFO"), 9),
            str(finding.get("findingType", "")),
        ),
    )
    return ", ".join(dict.fromkeys(str(item.get("findingType", "unknown")) for item in ranked[:limit]))


def iso_time(millis: int | float | None) -> str:
    if not millis:
        return "unknown"
    return datetime.fromtimestamp(float(millis) / 1000, timezone.utc).isoformat()


def score(value: Any) -> str:
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "n/a"


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "item"


def md_escape(value: Any) -> str:
    text = str(value or "")
    return text.replace("|", "\\|").replace("\n", " ").strip()


def bool_text(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value is None:
        return "unknown"
    return str(value)


def title_for_app(assessment: dict[str, Any]) -> str:
    snapshot = assessment.get("snapshot", {})
    label = snapshot.get("appLabel") or snapshot.get("packageName", "")
    return f"{label} ({snapshot.get('packageName', '')})"


def privacy_lines(export: dict[str, Any]) -> list[str]:
    privacy = export.get("privacy") or {}
    mode = privacy.get("mode", "FULL_RESEARCH")
    lines = [f"- Report privacy mode: `{mode}`"]
    if mode == "FULL_RESEARCH":
        lines.append("- Full research exports may contain package inventory, app labels, source paths, and signing digests.")
        lines.append("- Direct package names included: `yes`")
        lines.append("")
        return lines

    lines += [
        f"- Full inventory rows included: `{bool_text(privacy.get('fullInventoryIncluded', False))}`",
        "- Direct package names included: `no`",
        "- Package aliases are per-report pseudonyms; the alias mapping is not included in this redacted report.",
        f"- Package identifiers: `{privacy.get('packageIdentifierStrategy', 'unknown')}`",
        f"- App labels: `{privacy.get('appLabels', 'unknown')}`",
        f"- Source paths: `{privacy.get('sourcePaths', 'unknown')}`",
        f"- Signing digests: `{privacy.get('signingDigests', 'unknown')}`",
        f"- Redaction salt status: `{privacy.get('salt', 'unknown')}`",
    ]
    if mode == "MINIMAL_SUPPORT":
        included = (export.get("summary") or {}).get("includedAssessmentCount", len(export.get("assessments", [])))
        lines.append(f"- Priority assessments included in this support export: `{included}`")
    lines.append("")
    return lines


def provenance_classification_confidence(assessment: dict[str, Any]) -> float:
    vector = assessment.get("riskVector", {})
    provenance = assessment.get("provenance", {})
    try:
        return float(provenance.get("confidence", vector.get("provenanceConfidence", 0.0)) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def provenance_trust(assessment: dict[str, Any]) -> float:
    vector = assessment.get("riskVector", {})
    if "provenanceTrust" in vector:
        try:
            return float(vector.get("provenanceTrust", 0.0) or 0.0)
        except (TypeError, ValueError):
            return 0.0
    provenance_class = str((assessment.get("provenance") or {}).get("provenanceClass", "UNKNOWN"))
    class_trust_ceiling = {
        "AOSP_KNOWN": 0.88,
        "GOOGLE_KNOWN": 0.88,
        "PLAY_INSTALLED": 0.76,
        "FDROID_OR_OPEN_SOURCE": 0.72,
        "OEM_SIGNED_SYSTEM": 0.54,
        "CARRIER_COMPONENT": 0.46,
        "THIRD_PARTY_PREINSTALL": 0.42,
        "OPAQUE_PRIVILEGED": 0.34,
        "UNKNOWN_SIDELOAD": 0.18,
        "UNKNOWN": 0.24,
    }.get(provenance_class, 0.24)
    return max(0.0, min(class_trust_ceiling, provenance_classification_confidence(assessment)))


def level(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "n/a"
    if number >= 0.70:
        return "High"
    if number >= 0.40:
        return "Medium"
    return "Low"


def risk_vector_text(assessment: dict[str, Any]) -> str:
    risk = assessment.get("riskVector", {})
    return (
        f"H={score(risk.get('harm'))} "
        f"L={score(risk.get('legitimacy'))} "
        f"E={score(risk.get('abuseEvidence'))} "
        f"PT={score(provenance_trust(assessment))} "
        f"PC={score(provenance_classification_confidence(assessment))} "
        f"A={score(risk.get('actionability'))} "
        f"U={score(risk.get('uncertainty'))}"
    )


def risk_vector_rows(assessment: dict[str, Any]) -> list[str]:
    risk = assessment.get("riskVector", {})
    rows = [
        ("Harm", risk.get("harm")),
        ("Role legitimacy", risk.get("legitimacy")),
        ("Abuse evidence", risk.get("abuseEvidence")),
        ("Provenance trust / explainability", provenance_trust(assessment)),
        ("Provenance classification confidence", provenance_classification_confidence(assessment)),
        ("Actionability", risk.get("actionability")),
        ("Uncertainty", risk.get("uncertainty")),
    ]
    lines = ["| Dimension | Level | Value |", "| --- | --- | ---: |"]
    for label, value in rows:
        lines.append(f"| {label} | {level(value)} | {score(value)} |")
    return lines


def matched_rules(assessment: dict[str, Any]) -> list[str]:
    return [
        rule.get("ruleId", "")
        for rule in assessment.get("decisionTrace", {}).get("evaluatedRules", [])
        if rule.get("matched") is True and rule.get("ruleId")
    ]


def invariant_failures(assessment: dict[str, Any]) -> list[str]:
    return [
        item.get("invariantId", "")
        for item in assessment.get("decisionTrace", {}).get("invariantChecks", [])
        if item.get("passed") is False
    ]


def recommended_actions(assessment: dict[str, Any]) -> list[str]:
    return [
        f"{action.get('title', action.get('actionId', 'action'))}: {action.get('description', '')}"
        for action in assessment.get("decision", {}).get("recommendedActions", [])
    ]


def concrete_top_evidence(
    assessment: dict[str, Any],
    package_episodes: list[dict[str, Any]],
    limit: int = 6,
) -> list[str]:
    snapshot = assessment.get("snapshot", {})
    provenance = assessment.get("provenance", {})
    lines: list[str] = []

    for name, state in sorted((snapshot.get("specialAccess") or {}).items()):
        if state == "OBSERVED_ENABLED":
            lines.append(f"SETTINGS_SNAPSHOT / OBSERVED_ENABLED: `{name}` is active for this app.")
    for episode in package_episodes:
        lines.append(
            f"TEMPORAL_ENGINE / OBSERVED_ENABLED: `{episode.get('type')}` within "
            f"{int((episode.get('ttlMillis') or 0) / 60000)} minute TTL."
        )

    installer = snapshot.get("installerPackageName")
    provenance_class = provenance.get("provenanceClass", "UNKNOWN")
    if provenance_class in {"UNKNOWN_SIDELOAD", "UNKNOWN"}:
        installer_text = "no installer package observed" if not installer else f"installer `{installer}`"
        lines.append(
            f"INSTALLER_SOURCE / OBSERVED_ENABLED: provenance class `{provenance_class}` from {installer_text}."
        )
    elif installer:
        lines.append(f"INSTALLER_SOURCE / OBSERVED_ENABLED: installer source `{installer}`.")

    source_partition = (snapshot.get("rawFeatures") or {}).get("sourcePartition")
    if source_partition:
        lines.append(f"SOURCE_PARTITION / OBSERVED_ENABLED: source partition `{source_partition}`.")

    for evidence in assessment.get("evidence", []):
        if evidence.get("source") == "DECISION_POLICY":
            continue
        lines.append(
            f"{evidence.get('source')} / {evidence.get('observabilityState')} / "
            f"conf={score(evidence.get('confidence'))}: {evidence.get('humanExplanation', '')}"
        )
        if len(lines) >= limit:
            break
    return lines[:limit]


def baseline_section(evaluation: dict[str, Any] | None) -> list[str]:
    if not evaluation:
        return [
            "## Baseline Comparison on Labelled Scenario Subset",
            "",
            "No evaluator output was supplied for this report.",
            "",
        ]
    metrics = evaluation.get("metrics", {})
    model_metrics = evaluation.get("modelMetrics", {})
    permission = model_metrics.get("permission_only", {})
    full = model_metrics.get("full_aura", {})
    labelled = int(evaluation.get("labelledApps") or metrics.get("metric_population") or 0)
    evaluated = int(evaluation.get("evaluatedApps") or 0)
    unlabelled = max(evaluated - labelled, 0)
    lines = [
        "## Baseline Comparison on Labelled Scenario Subset",
        "",
        f"- Scope: labelled scenario subset only.",
        f"- Labelled apps: `{labelled}`",
        f"- Unlabelled apps excluded from baseline metrics: `{unlabelled}`",
        f"- Evaluated inventory rows retained for report context: `{evaluated}`",
        "",
        "| Metric | Permission-only | Full AURA |",
        "| --- | ---: | ---: |",
        f"| Critical alert rate | {score(permission.get('critical_alert_rate'))} | {score(full.get('critical_alert_rate'))} |",
        f"| Non-actionable critical alert rate | {score(permission.get('non_actionable_critical_alert_rate'))} | {score(full.get('non_actionable_critical_alert_rate'))} |",
        f"| User-actionable precision | {score(permission.get('user_actionable_precision'))} | {score(full.get('user_actionable_precision'))} |",
        f"| Controlled-abuse recall | {score(permission.get('controlled_abuse_recall'))} | {score(full.get('controlled_abuse_recall'))} |",
        f"| BLUE platform audit separation | {score(permission.get('platform_audit_separation'))} | {score(full.get('platform_audit_separation'))} |",
        "",
        f"Decision trace completeness: `{score(metrics.get('decision_trace_completeness'))}`",
        "",
        "Metric definitions:",
        "",
        "- Critical alert rate = critical decisions divided by labelled apps in the scenario subset.",
        "- Non-actionable critical alert rate = critical alerts whose label is not user-actionable divided by critical alerts.",
        "- User-actionable precision = user-actionable true positives divided by user-alert decisions.",
        "- BLUE platform audit separation = platform-audit labels that AURA kept in BLUE instead of the primary user-alert queue.",
        "",
        "Interpretation: permission-only baselines can mark role-expected or non-actionable cases as critical. AURA requires concrete abuse evidence, low role legitimacy, active risky capability, and high user actionability before issuing RED.",
        "",
    ]
    comparisons = evaluation.get("comparisons", {})
    if comparisons:
        lines += [
            "Key comparison deltas:",
            "",
            f"- Non-actionable critical alert reduction vs permission-only: `{score(comparisons.get('aura_non_actionable_critical_alert_rate_reduction_vs_permission_only'))}`",
            f"- User-actionable precision delta vs permission-only: `{score(comparisons.get('aura_user_actionable_precision_delta_vs_permission_only'))}`",
            f"- Controlled-abuse recall delta vs permission-only: `{score(comparisons.get('aura_controlled_abuse_recall_delta_vs_permission_only'))}`",
            "",
        ]
    return lines


def environment_section(export: dict[str, Any]) -> list[str]:
    snapshot = first_snapshot(export)
    raw_features = snapshot.get("rawFeatures", {})
    out_of_scope = [
        "kernel/rootkit compromise",
        "baseband/TEE/bootloader compromise",
        "server-side account abuse",
        "runtime malware payload proof",
        "notification contents, screen contents, and network payloads",
    ]
    return [
        "## Scope and Environment",
        "",
        "| Field | Value |",
        "| --- | --- |",
        "| Scan type | No-root on-device scan + offline/static report generation |",
        f"| Build/flavor | `{export.get('flavor', snapshot.get('flavor', 'unknown'))}` |",
        f"| Device model | `{snapshot.get('deviceModel', 'unknown')}` |",
        f"| Android version / API | `{snapshot.get('androidVersion', 'unknown')}` / `{snapshot.get('apiLevel', 'unknown')}` |",
        f"| Security patch level | `{snapshot.get('securityPatchLevel', 'unknown')}` |",
        f"| Collector version | `{snapshot.get('collectorVersion', 'unknown')}` |",
        f"| Inventory rows visible | `{assessed_app_count(export)}` |",
        f"| Inventory mode | `{raw_features.get('distributionFlavor', 'unknown')}` / full inventory `{bool_text(raw_features.get('fullInventory'))}` |",
        f"| UsageStats signal | `{raw_features.get('usageStatsObservability', 'unknown')}` |",
        f"| Accessibility observer | `not implemented in MVP` |",
        f"| Notification content | `not read` |",
        f"| Network content | `not inspected` |",
        "",
        "Out of scope:",
        "",
    ] + [f"- {item}" for item in out_of_scope] + [""]


def overall_conclusion_section(export: dict[str, Any]) -> list[str]:
    counts = decision_counts(export)
    red = counts.get("RED", 0)
    yellow = counts.get("YELLOW", 0)
    blue = counts.get("BLUE", 0)
    gray = counts.get("GRAY", 0)
    weak = posture_counts(export).get("WEAK_DEFENSIVE_SURFACE", 0)
    if red:
        headline = f"AURA found {red} user-actionable threat item(s) requiring immediate review."
    elif yellow:
        headline = f"AURA found no RED user-alerts, but {yellow} item(s) need review."
    else:
        headline = "AURA found no RED user-actionable threat items in this scan."
    return [
        "## Overall Conclusion",
        "",
        headline,
        "",
        f"AURA also separated `{blue}` BLUE expert/platform audit finding(s), `{gray}` GRAY insufficient-evidence item(s), and `{weak}` weak defensive posture item(s). BLUE findings are not primary panic alerts; GRAY means AURA is abstaining rather than guessing.",
        "",
        "This report is a whole-device expert report. For app-owner/customer delivery, the same engine should normally be scoped to the target APK plus its controlled test context.",
        "",
    ]


def recommended_next_actions_section(export: dict[str, Any]) -> list[str]:
    counts = decision_counts(export)
    lines = ["## Recommended Next Actions", ""]
    red_assessments = [
        item for item in sorted_assessments(export)
        if item.get("decision", {}).get("color") == "RED"
    ]
    if red_assessments:
        first = title_for_app(red_assessments[0])
        lines.append(f"1. Review `{md_escape(first)}` first; disable active special accesses or uninstall/disable it if it is not needed.")
    else:
        lines.append("1. No immediate RED user-actionable threat remediation was generated by this scan.")
    lines += [
        f"2. Review `{counts.get('BLUE', 0)}` BLUE platform/OEM findings with an Android/OEM expert; do not treat them as panic alerts.",
        "3. Review HIGH defensive posture findings, especially unprotected exported components and cleartext/debuggable/backup indicators.",
        "4. Keep the JSON export and this report together for reproducibility and retest comparison.",
        "",
    ]
    return lines


def asset_hash_lines() -> list[str]:
    asset_dir = Path("app/src/main/assets/aura")
    if not asset_dir.exists():
        return ["- Policy/assets directory hash: `not available from current working directory`"]
    lines = []
    for path in sorted(asset_dir.glob("*.json")):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
        lines.append(f"- `{path.name}` SHA-256 prefix: `{digest}`")
    return lines or ["- Policy/assets directory hash: `no JSON assets found`"]


def reproducibility_section(export: dict[str, Any]) -> list[str]:
    snapshot = first_snapshot(export)
    policy_versions = {
        assessment.get("decisionTrace", {}).get("policyVersion")
        for assessment in export.get("assessments", [])
        if assessment.get("decisionTrace", {}).get("policyVersion")
    }
    return [
        "## Reproducibility Appendix",
        "",
        f"- Export schema version: `{export.get('schemaVersion')}`",
        f"- Report generator version: `{REPORT_GENERATOR_VERSION}`",
        f"- Collector version: `{snapshot.get('collectorVersion', 'unknown')}`",
        f"- Decision policy version(s): `{', '.join(sorted(policy_versions)) if policy_versions else 'unknown'}`",
        f"- Scan ID: `{export.get('scanId', 'unknown')}`",
        f"- Generated at: `{iso_time(export.get('generatedAt'))}`",
        f"- Scan history retained scans: `{(export.get('scanHistory') or {}).get('retainedScanCount', 'n/a')}`",
        f"- Scan history retained packages: `{(export.get('scanHistory') or {}).get('retainedPackageCount', 'n/a')}`",
        "",
        "Policy and asset hashes:",
        "",
    ] + asset_hash_lines() + [""]


def grouped_gray_section(assessments: list[dict[str, Any]]) -> list[str]:
    gray_items = [
        assessment for assessment in assessments
        if assessment.get("decision", {}).get("color") == "GRAY"
    ]
    lines = ["## Grouped GRAY / Limited Evidence", ""]
    if not gray_items:
        return lines + ["No GRAY insufficient-evidence groups were present.", ""]

    groups: dict[tuple[str, str, bool, str], list[dict[str, Any]]] = defaultdict(list)
    for assessment in gray_items:
        role = assessment.get("role", {}).get("predicted", "UNKNOWN")
        provenance = assessment.get("provenance", {}).get("provenanceClass", "UNKNOWN")
        active = any(
            state == "OBSERVED_ENABLED"
            for state in (assessment.get("snapshot", {}).get("specialAccess") or {}).values()
        )
        harm_level = level(assessment.get("riskVector", {}).get("harm"))
        groups[(role, provenance, active, harm_level)].append(assessment)

    lines += ["| Group | Count | Common reason | Aliases |", "| --- | ---: | --- | --- |"]
    for (role, provenance, active, harm_level), items in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
        aliases = ", ".join(md_escape(item.get("snapshot", {}).get("packageName")) for item in items[:6])
        if len(items) > 6:
            aliases += ", ..."
        reason = f"role `{role}`, provenance `{provenance}`, active risky access `{active}`, harm `{harm_level}`"
        lines.append(f"| `{role}/{provenance}` | {len(items)} | {reason} | `{aliases}` |")
    lines += [
        "",
        "GRAY groups are abstentions. They mean the scan lacks enough concrete evidence for a stronger claim; they do not mean malware by default.",
        "",
    ]
    return lines


def temporal_causal_strength(episode: dict[str, Any]) -> str:
    episode_type = str(episode.get("type", ""))
    if episode_type.startswith("SIDELOAD_TO_"):
        return "STRONG_SEQUENCE_PATTERN"
    if episode_type == "SPECIAL_ACCESS_PLUS_SENSITIVE_APP":
        return "TEMPORAL_CORRELATION_ONLY"
    return "TEMPORAL_CORRELATION_ONLY"


def temporal_decision_impact(episode: dict[str, Any], assessment_by_package: dict[str, dict[str, Any]]) -> str:
    assessment = assessment_by_package.get(episode.get("packageName", ""))
    decision = (assessment or {}).get("decision", {}).get("color", "unknown")
    if decision == "RED":
        return "supports abuseEvidence and RED eligibility with active risky capability"
    if decision in {"BLUE", "GREEN"}:
        return "context signal only; policy did not convert it into a user-alert"
    if decision == "GRAY":
        return "insufficient alone; contributes to uncertainty/context"
    return "context signal"


def temporal_window(episode: dict[str, Any]) -> str:
    ttl = episode.get("ttlMillis")
    if ttl is None:
        return "unknown"
    try:
        return f"{int(ttl) // 60000} min"
    except (TypeError, ValueError):
        return "unknown"


def app_detail_section(
    assessment: dict[str, Any],
    posture: dict[str, Any] | None,
    findings: list[dict[str, Any]],
    package_episodes: list[dict[str, Any]],
    finding_id: str,
) -> list[str]:
    snapshot = assessment.get("snapshot", {})
    decision = assessment.get("decision", {})
    role = assessment.get("role", {})
    provenance = assessment.get("provenance", {})
    story = assessment.get("userRiskStory", {})
    trace = assessment.get("decisionTrace", {})
    lines = [
        f"### {md_escape(finding_id)} {md_escape(title_for_app(assessment))}",
        "",
        f"- Finding ID: `{finding_id}`",
        f"- Threat decision: `{decision.get('color')}` / {decision.get('title', '')}",
        f"- Defensive posture: `{(posture or {}).get('postureClass', 'NO_OBSERVED_WEAKNESS')}` with `{(posture or {}).get('findingCount', 0)}` finding(s)",
        f"- Role: `{role.get('predicted')}` confidence `{score(role.get('confidence'))}`",
        f"- Provenance class: `{provenance.get('provenanceClass')}`",
        f"- Provenance trust/explainability: `{score(provenance_trust(assessment))}`",
        f"- Provenance classification confidence: `{score(provenance_classification_confidence(assessment))}`",
        f"- Actionability: `{decision.get('actionabilityClass')}`",
        f"- Risk vector: `{risk_vector_text(assessment)}`",
        f"- Source partition: `{snapshot.get('rawFeatures', {}).get('sourcePartition', 'unknown')}`",
        "",
        f"Risk story: {story.get('primaryReason', decision.get('explanation', ''))}",
        "",
        "Risk vector interpretation:",
        "",
    ]
    lines += risk_vector_rows(assessment)
    lines += [
        "",
    ]
    observed = story.get("whatWasObserved", [])
    if observed:
        lines += ["Observed:", ""]
        lines += [f"- {item}" for item in observed[:6]]
        lines += [""]
    actions = recommended_actions(assessment)
    if actions:
        lines += ["Recommended actions:", ""]
        lines += [f"- {action}" for action in actions[:5]]
        lines += [""]
    rules = matched_rules(assessment)
    lines += [
        "Decision trace:",
        "",
        f"- Policy version: `{trace.get('policyVersion', 'unknown')}`",
        f"- Matched rules: `{', '.join(rules) if rules else 'none'}`",
        f"- Invariant failures: `{', '.join(invariant_failures(assessment)) or 'none'}`",
        "",
    ]
    counterfactuals = trace.get("counterfactuals", [])
    if counterfactuals:
        counterfactual_heading = "Counterfactual downgrade:" if decision.get("color") == "RED" else "Decision counterfactuals:"
        lines += [counterfactual_heading, ""]
        for item in counterfactuals[:3]:
            changes_list = [
                change for change in item.get("requiredChanges", [])
                if "uninstall" not in str(change).lower() and "disable the app" not in str(change).lower()
            ]
            changes = "; ".join(changes_list or item.get("requiredChanges", []))
            lines.append(f"- To reach `{item.get('targetDecision')}`: {changes}")
        lines += [""]
    destructive_actions = [
        action for action in decision.get("recommendedActions", [])
        if action.get("destructive") is True or "uninstall" in str(action.get("actionId", "")).lower()
    ]
    if destructive_actions:
        lines += ["Resolution actions:", ""]
        lines += [
            f"- {action.get('title', action.get('actionId', 'action'))}: {action.get('description', '')}"
            for action in destructive_actions[:3]
        ]
        lines += [""]
    evidence = concrete_top_evidence(assessment, package_episodes)
    if evidence:
        lines += ["Top evidence:", ""]
        lines += [f"- {line}" for line in evidence]
        lines += [""]
    if findings:
        lines += ["Defensive surface findings:", ""]
        for finding in findings[:6]:
            lines.append(
                f"- `{finding.get('findingType')}` severity `{finding.get('severity')}` "
                f"confidence `{score(finding.get('confidence'))}`: {finding.get('humanExplanation', '')}"
            )
        lines += [""]
    return lines


def render_markdown(
    export: dict[str, Any],
    evaluation: dict[str, Any] | None = None,
    *,
    top_apps: int = 12,
) -> str:
    counts = decision_counts(export)
    postures = postures_by_package(export)
    findings = findings_by_package(export)
    episodes = episodes_by_package(export)
    assessments = sorted_assessments(export)
    defensive_posture_counts = posture_counts(export)
    red = counts.get("RED", 0)
    yellow = counts.get("YELLOW", 0)
    blue = counts.get("BLUE", 0)
    gray = counts.get("GRAY", 0)
    green = counts.get("GREEN", 0)
    lines = [
        "# AURA Android App Risk Report",
        "",
        f"Generated from scan `{export.get('scanId', 'unknown')}`.",
        "",
        "## Executive Summary",
        "",
        f"- Generated at: `{iso_time(export.get('generatedAt'))}`",
        f"- Flavor: `{export.get('flavor', 'unknown')}`",
        f"- Applications assessed: `{assessed_app_count(export)}`",
        f"- Threat decisions: RED `{red}`, YELLOW `{yellow}`, BLUE `{blue}`, GRAY `{gray}`, GREEN `{green}`",
        f"- Defensive posture: weak `{defensive_posture_counts.get('WEAK_DEFENSIVE_SURFACE', 0)}`, review `{defensive_posture_counts.get('REVIEW_RECOMMENDED', 0)}`, no observed weakness `{defensive_posture_counts.get('NO_OBSERVED_WEAKNESS', 0)}`",
        f"- Temporal episodes: `{temporal_episode_count(export)}`",
        f"- Defensive findings: `{defensive_finding_count(export)}`",
        "",
        "AURA separates threat decisions from defensive posture. A `GREEN` threat decision means the current scan did not find concrete abuse evidence; it does not mean the app has perfect defensive design.",
        "",
    ]
    lines += overall_conclusion_section(export)
    lines += recommended_next_actions_section(export)
    lines += environment_section(export)
    lines += [
        "## Methodology",
        "",
        "AURA is a no-root Android risk reasoning engine. It evaluates app capabilities in relation to inferred role, provenance trust, provenance classification confidence, abuse evidence, user actionability, and observability limits. It does not replace Play Protect, MDM/MTD, or a manual mobile application pentest.",
        "",
        "The report distinguishes `provenance trust/explainability` from `provenance classification confidence`. For example, AURA can be fairly confident that an app belongs to `UNKNOWN_SIDELOAD`, while still assigning low trust/explainability to that origin.",
        "",
        "Privacy defaults: no TLS interception, no keylogging, no screen scraping, no notification-content reading, and no external telemetry in the MVP.",
        "",
        "Report privacy:",
        "",
    ]
    lines += privacy_lines(export)
    lines += [
        "## Threat Decision Overview",
        "",
        "| Decision | Meaning | Count |",
        "| --- | --- | ---: |",
        f"| RED | User-actionable threat | {red} |",
        f"| YELLOW | Review recommended | {yellow} |",
        f"| BLUE | Expert/platform audit finding, not primary panic | {blue} |",
        f"| GRAY | Insufficient evidence / abstention | {gray} |",
        f"| GREEN | No user action required from current threat evidence | {green} |",
        "",
    ]
    lines += baseline_section(evaluation)
    lines += [
        "## Priority Items",
        "",
    ]
    priority = [
        item
        for item in assessments
        if item.get("decision", {}).get("color") in {"RED", "YELLOW", "BLUE"}
    ][:top_apps]
    if not priority:
        lines += ["No RED/YELLOW/BLUE priority items were present in this export.", ""]
    else:
        for index, assessment in enumerate(priority, start=1):
            package_name = assessment.get("snapshot", {}).get("packageName", "")
            color = assessment.get("decision", {}).get("color", "ITEM")
            finding_id = f"AURA-{color}-{index:03d}"
            lines += app_detail_section(
                assessment,
                postures.get(package_name),
                findings.get(package_name, []),
                episodes.get(package_name, []),
                finding_id,
            )
    lines += grouped_gray_section(assessments)
    weak_postures = [
        posture
        for posture in top_posture_items(export)
        if posture.get("postureClass") != "NO_OBSERVED_WEAKNESS"
    ][:top_apps]
    lines += [
        "## Defensive Posture Highlights",
        "",
    ]
    if not weak_postures:
        lines += ["No defensive posture findings were exported.", ""]
    else:
        lines += ["| Package | Posture | Findings | Highest severity | Top finding types |", "| --- | --- | ---: | --- | --- |"]
        for posture in weak_postures:
            package_name = posture.get("packageName")
            lines.append(
                f"| `{md_escape(package_name)}` | `{posture.get('postureClass')}` | "
                f"{posture.get('findingCount', 0)} | `{posture.get('highestSeverity') or 'n/a'}` | "
                f"{md_escape(top_finding_types(findings.get(package_name, [])))} |"
            )
        lines += [""]
    flat_episodes = export.get("temporalEpisodes", [])
    assessment_by_package = {
        assessment.get("snapshot", {}).get("packageName", ""): assessment
        for assessment in export.get("assessments", [])
    }
    lines += ["## Temporal Episodes", ""]
    if not flat_episodes:
        lines += ["No temporal episodes were exported.", ""]
    else:
        lines += [
            "Temporal correlation does not prove malicious behavior. AURA does not read sensitive app contents or user input.",
            "",
            "| Package | Type | Decision impact | Causal strength | Window | Explanation |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for episode in flat_episodes[:top_apps]:
            lines.append(
                f"| `{md_escape(episode.get('packageName'))}` | `{episode.get('type')}` | "
                f"{md_escape(temporal_decision_impact(episode, assessment_by_package))} | "
                f"`{temporal_causal_strength(episode)}` | `{temporal_window(episode)}` | "
                f"{md_escape(episode.get('explanation'))} |"
            )
        lines += [""]
    lines += [
        "## Observability Limits",
        "",
        "- AURA is a no-root agent and cannot observe kernel, baseband, TEE, bootloader, or hidden OEM framework compromise.",
        "- Declared-only capabilities are not treated the same as active risky access.",
        "- Unknown evidence increases uncertainty; it is not treated as malicious by default.",
        "- BLUE findings are expert/platform audit items and must not appear in the primary panic queue.",
        "- Defensive posture findings are app-hardening signals, not malware verdicts.",
        "",
    ]
    lines += reproducibility_section(export)
    lines += [
        "## Technical Appendix",
        "",
        "- The machine-readable JSON export remains the source of truth for raw features, evidence IDs, decision traces, and baseline replay.",
        "- HTML output escapes app-provided strings and includes a restrictive Content-Security-Policy meta tag because app labels and evidence strings can be attacker-controlled.",
        "",
    ]
    return "\n".join(lines)


def markdown_to_html(markdown_text: str) -> str:
    body = []
    in_table = False
    list_kind: str | None = None
    ordered_item = re.compile(r"^\d+\. (.*)$")
    for raw_line in markdown_text.splitlines():
        line = raw_line.rstrip()
        if not line:
            if list_kind:
                body.append(f"</{list_kind}>")
                list_kind = None
            if in_table:
                body.append("</tbody></table>")
                in_table = False
            continue
        if line.startswith("# "):
            body.append(f"<h1>{escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{escape(line[3:])}</h2>")
        elif line.startswith("### "):
            body.append(f"<h3>{escape(line[4:])}</h3>")
        elif line.startswith("- "):
            if list_kind and list_kind != "ul":
                body.append(f"</{list_kind}>")
                list_kind = None
            if not list_kind:
                body.append("<ul>")
                list_kind = "ul"
            body.append(f"<li>{inline_html(line[2:])}</li>")
        elif ordered_item.match(line):
            if list_kind and list_kind != "ol":
                body.append(f"</{list_kind}>")
                list_kind = None
            if not list_kind:
                body.append("<ol>")
                list_kind = "ol"
            body.append(f"<li>{inline_html(ordered_item.match(line).group(1))}</li>")
        elif line.startswith("| ") and line.endswith(" |"):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if all(set(cell) <= {"-", ":", " "} for cell in cells):
                continue
            if not in_table:
                body.append("<table><tbody>")
                in_table = True
                tag = "th"
            else:
                tag = "td"
            body.append("<tr>" + "".join(f"<{tag}>{inline_html(cell)}</{tag}>" for cell in cells) + "</tr>")
        else:
            if list_kind:
                body.append(f"</{list_kind}>")
                list_kind = None
            if in_table:
                body.append("</tbody></table>")
                in_table = False
            body.append(f"<p>{inline_html(line)}</p>")
    if list_kind:
        body.append(f"</{list_kind}>")
    if in_table:
        body.append("</tbody></table>")
    return "\n".join(body)


def inline_html(text: str) -> str:
    escaped = escape(text)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    return escaped


def render_html(markdown_text: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AURA Android App Risk Report</title>
  <style>
    :root {{
      --ink: #14211f;
      --muted: #5c6865;
      --line: #d9e1dd;
      --surface: #f8faf7;
      --accent: #145c58;
      --danger: #b3261e;
    }}
    body {{
      margin: 0;
      color: var(--ink);
      background: white;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    main {{
      max-width: 980px;
      margin: 0 auto;
      padding: 42px 28px 80px;
    }}
    h1 {{
      font-size: 34px;
      margin: 0 0 12px;
      color: var(--accent);
    }}
    h2 {{
      margin-top: 34px;
      padding-top: 18px;
      border-top: 1px solid var(--line);
      font-size: 23px;
    }}
    h3 {{
      margin-top: 26px;
      font-size: 18px;
    }}
    p, li, td, th {{
      font-size: 14px;
    }}
    p {{
      margin: 8px 0;
    }}
    code {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 4px;
      padding: 1px 5px;
      font-family: "SFMono-Regular", Consolas, monospace;
      font-size: 12px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 12px 0 18px;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 8px 7px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-weight: 700;
      background: var(--surface);
    }}
    ul {{
      margin-top: 6px;
    }}
    @media print {{
      main {{
        max-width: none;
        padding: 18mm;
      }}
      h2 {{
        break-after: avoid;
      }}
      h3, table {{
        break-inside: avoid;
      }}
    }}
  </style>
</head>
<body>
<main>
{markdown_to_html(markdown_text)}
</main>
</body>
</html>
"""


def write_report(
    export: dict[str, Any],
    evaluation: dict[str, Any] | None,
    out_dir: Path,
    basename: str,
    top_apps: int,
) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    markdown = render_markdown(export, evaluation, top_apps=top_apps)
    markdown_path = out_dir / f"{basename}.md"
    html_path = out_dir / f"{basename}.html"
    markdown_path.write_text(markdown + "\n")
    html_path.write_text(render_html(markdown))
    return markdown_path, html_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="AURA scan export JSON")
    parser.add_argument("--evaluation", type=Path, help="Optional evaluator JSON output")
    parser.add_argument("--out-dir", type=Path, default=Path("artifacts/reports"))
    parser.add_argument("--basename", default="aura-app-risk-report")
    parser.add_argument("--top-apps", type=int, default=12)
    parser.add_argument("--privacy-mode", choices=PRIVACY_MODES, default=FULL_RESEARCH)
    parser.add_argument("--salt", default=DEFAULT_SALT, help="Project/customer-specific redaction salt")
    parser.add_argument(
        "--redacted-export-out",
        type=Path,
        help="Optional path for the privacy-processed JSON used by the report",
    )
    args = parser.parse_args()

    export = load_json(args.export)
    if export is None:
        raise ValueError(f"Could not load export {args.export}")
    export = redact_export(
        export,
        mode=args.privacy_mode,
        salt=args.salt,
        salt_provided=args.salt != DEFAULT_SALT,
    )
    if args.redacted_export_out:
        args.redacted_export_out.parent.mkdir(parents=True, exist_ok=True)
        args.redacted_export_out.write_text(json.dumps(export, indent=2, sort_keys=True) + "\n")
    evaluation = load_json(args.evaluation)
    markdown_path, html_path = write_report(
        export=export,
        evaluation=evaluation,
        out_dir=args.out_dir,
        basename=args.basename,
        top_apps=args.top_apps,
    )
    print(f"Wrote Markdown report to {markdown_path}")
    print(f"Wrote HTML report to {html_path}")
    print("Open the HTML report in a browser and print/save as PDF when a PDF artifact is needed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
