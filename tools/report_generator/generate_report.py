#!/usr/bin/env python3
"""Generate a print-ready AURA app risk report from a JSON export."""

from __future__ import annotations

import argparse
import copy
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
from redact_export import DEFAULT_SALT, FULL_RESEARCH, REDACTED_TEASER, PRIVACY_MODES, redact_export
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app_owner_audit"))
from audit_engine import build_audit as build_app_owner_audit
from audit_engine import compare_audits as compare_app_owner_audits


REPORT_GENERATOR_VERSION = "0.3.0"
REPORT_TYPES = ("device_expert", "app_owner", "public_teaser")
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


def top_offline_finding_types(offline_apk: dict[str, Any] | None, limit: int = 3) -> str:
    if not offline_apk:
        return "n/a"
    findings = offline_apk.get("findings", [])
    if not findings:
        return "none"
    return top_finding_types(findings, limit=limit)


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


def package_name(assessment: dict[str, Any]) -> str:
    return str(assessment.get("snapshot", {}).get("packageName", ""))


def scope_export_to_package(export: dict[str, Any], target_package: str) -> dict[str, Any]:
    scoped = copy.deepcopy(export)
    assessments = [
        assessment for assessment in scoped.get("assessments", [])
        if package_name(assessment) == target_package
    ]
    if not assessments:
        raise ValueError(f"Target package {target_package!r} was not found in export {export.get('scanId', 'unknown')}")
    scoped["assessments"] = assessments
    scoped["temporalEpisodes"] = [
        episode for episode in scoped.get("temporalEpisodes", [])
        if episode.get("packageName") == target_package
    ]
    scoped["defensiveSurfaceFindings"] = [
        finding for finding in scoped.get("defensiveSurfaceFindings", [])
        if finding.get("packageName") == target_package
    ]
    scoped["defensivePostures"] = [
        posture for posture in scoped.get("defensivePostures", [])
        if posture.get("packageName") == target_package
    ]
    scoped["summary"] = {
        **(scoped.get("summary") or {}),
        "assessedAppCount": len(scoped["assessments"]),
        "decisionCounts": dict(decision_counts(scoped)),
        "defensivePostureCounts": dict(posture_counts(scoped)),
        "temporalEpisodeCount": len(scoped.get("temporalEpisodes", [])),
        "defensiveFindingCount": len(scoped.get("defensiveSurfaceFindings", [])),
    }
    scoped.setdefault("reportScope", {})
    scoped["reportScope"] = {
        **scoped["reportScope"],
        "reportType": "app_owner",
        "targetPackage": target_package,
    }
    return scoped


def mark_target_only_privacy(export: dict[str, Any]) -> dict[str, Any]:
    privacy = export.setdefault("privacy", {})
    privacy["fullInventoryIncluded"] = False
    privacy["reportScope"] = "target_app_only"
    return export


def mark_public_teaser_privacy(export: dict[str, Any]) -> dict[str, Any]:
    export = mark_target_only_privacy(export)
    privacy = export.setdefault("privacy", {})
    privacy["componentNames"] = "suppressed"
    privacy["rawEvidence"] = "suppressed"
    privacy["policyThresholds"] = "suppressed"
    privacy["reportScope"] = "public_surface_teaser_target_only"
    return export


def offline_apk_for_package(offline_analysis: dict[str, Any] | None, target_package: str) -> dict[str, Any] | None:
    if not offline_analysis:
        return None
    candidates = offline_analysis.get("apks")
    if isinstance(candidates, list):
        for item in candidates:
            if (item.get("apk") or {}).get("packageName") == target_package:
                return item
        return None
    if "apk" in offline_analysis and "apks" not in offline_analysis:
        apk_package = (offline_analysis.get("apk") or {}).get("packageName")
        if apk_package == target_package or str(target_package).startswith("app_"):
            return offline_analysis
    if (offline_analysis.get("apk") or {}).get("packageName") == target_package:
        return offline_analysis
    return None


def report_is_redacted(export: dict[str, Any]) -> bool:
    return bool((export.get("privacy") or {}).get("redactionApplied"))


def target_report_package(export: dict[str, Any]) -> str:
    return (export.get("assessments") or [{}])[0].get("snapshot", {}).get("packageName", "")


def redact_offline_value(value: Any, offline_apk: dict[str, Any], export: dict[str, Any]) -> str:
    text = str(value or "")
    if not report_is_redacted(export):
        return text
    apk = offline_apk.get("apk") or {}
    raw_package = str(apk.get("packageName") or "")
    raw_label = str(apk.get("label") or "")
    raw_path = str(apk.get("path") or "")
    alias = target_report_package(export) or "<target_app>"
    output = text
    if raw_path:
        output = output.replace(raw_path, "<redacted:apk_path>")
    if raw_package:
        output = output.replace(raw_package, alias)
    if raw_label:
        output = output.replace(raw_label, "<app_label_redacted>")
    return output


def offline_apk_path_text(offline_apk: dict[str, Any], export: dict[str, Any]) -> str:
    path = (offline_apk.get("apk") or {}).get("path", "")
    return "<redacted:apk_path>" if report_is_redacted(export) and path else str(path or "unknown")


def offline_sha_prefix(offline_apk: dict[str, Any]) -> str:
    digest = (offline_apk.get("apk") or {}).get("sha256")
    return str(digest)[:16] if digest else "unknown"


def privacy_lines(export: dict[str, Any]) -> list[str]:
    privacy = export.get("privacy") or {}
    report_scope = export.get("reportScope") or {}
    app_owner_scope = report_scope.get("reportType") == "app_owner"
    teaser_scope = report_scope.get("reportType") == "public_teaser"
    target_only = app_owner_scope or teaser_scope
    mode = privacy.get("mode", "FULL_RESEARCH")
    lines = [f"- Report privacy mode: `{mode}`"]
    if target_only:
        lines.append("- Report scope: `target_app_only`")
    if teaser_scope:
        lines.append("- Public teaser detail level: `high_level_only`")
    if mode == "FULL_RESEARCH":
        lines.append("- Full research exports may contain package inventory, app labels, source paths, and signing digests.")
        lines.append(f"- Full device inventory rows included: `{'no' if target_only else 'yes'}`")
        lines.append("- Direct package names included: `yes`")
        lines.append("")
        return lines

    lines += [
        f"- Full device inventory rows included: `{'no' if target_only else bool_text(privacy.get('fullInventoryIncluded', False))}`",
        "- Direct package names included: `no`",
        "- Package aliases are per-report pseudonyms; the alias mapping is not included in this redacted report.",
        f"- Package identifiers: `{privacy.get('packageIdentifierStrategy', 'unknown')}`",
        f"- App labels: `{privacy.get('appLabels', 'unknown')}`",
        f"- Source paths: `{privacy.get('sourcePaths', 'unknown')}`",
        f"- Signing digests: `{privacy.get('signingDigests', 'unknown')}`",
        f"- Component names: `{privacy.get('componentNames', 'unknown')}`",
        f"- Raw evidence detail: `{privacy.get('rawEvidence', 'unknown')}`",
        f"- Policy thresholds: `{privacy.get('policyThresholds', 'unknown')}`",
        f"- Redaction salt status: `{privacy.get('salt', 'unknown')}`",
    ]
    if mode == "REDACTED_TEASER":
        lines.append("- Public target source URL may identify the single target app; raw inventory package names remain suppressed.")
        lines.append("- Teaser reports suppress detailed component names, raw manifest values, full evidence graph, and exact internal policy trace.")
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


def masvs_mapping(finding_type: str | None) -> tuple[str, str]:
    mapping = {
        "UNPROTECTED_EXPORTED_COMPONENT": (
            "MASVS-PLATFORM",
            "Platform interaction and exposed Android component review",
        ),
        "CLEARTEXT_TRAFFIC_ALLOWED": (
            "MASVS-NETWORK",
            "Network transport security and cleartext traffic review",
        ),
        "BACKUP_ALLOWED_SENSITIVE_APP": (
            "MASVS-STORAGE",
            "Sensitive data persistence, backup, and restore surface review",
        ),
        "DEBUGGABLE_SENSITIVE_APP": (
            "MASVS-CODE / MASVS-RESILIENCE",
            "Build hardening and debug configuration review",
        ),
        "DEBUGGABLE_ENABLED": (
            "MASVS-CODE / MASVS-RESILIENCE",
            "Build hardening and debug configuration review",
        ),
        "BACKUP_ALLOWED": (
            "MASVS-STORAGE",
            "Sensitive data persistence, backup, and restore surface review",
        ),
        "CLEARTEXT_TRAFFIC_ALLOWED_MANIFEST": (
            "MASVS-NETWORK",
            "Network transport security and cleartext traffic review",
        ),
        "NETWORK_SECURITY_CONFIG_CLEARTEXT_PERMITTED": (
            "MASVS-NETWORK",
            "Network security config cleartext traffic review",
        ),
        "FLAG_SECURE_NOT_OBSERVED_SENSITIVE_APP": (
            "MASVS-PLATFORM",
            "Sensitive UI exposure and screenshot/screen-sharing hardening review",
        ),
        "FILTER_TOUCHES_WHEN_OBSCURED_NOT_OBSERVED_SENSITIVE_APP": (
            "MASVS-PLATFORM",
            "Tapjacking and obscured-touch protection review",
        ),
        "ACCESSIBILITY_DATA_SENSITIVE_NOT_OBSERVED": (
            "MASVS-PLATFORM",
            "Accessibility exposure controls for sensitive UI review",
        ),
    }
    return mapping.get(str(finding_type), ("MASVS-GENERAL", "Manual mobile security review"))


def remediation_for_finding(finding_type: str | None) -> str:
    return {
        "UNPROTECTED_EXPORTED_COMPONENT": "Set exported=false when external entry is not needed, or protect the component with an appropriate permission/signature permission and validate all inbound intents/deep links.",
        "CLEARTEXT_TRAFFIC_ALLOWED": "Disable cleartext by default and move detailed network_security_config review to the offline APK analyzer or source review.",
        "CLEARTEXT_TRAFFIC_ALLOWED_MANIFEST": "Set android:usesCleartextTraffic=false for release builds unless a tightly justified domain-specific exception is documented.",
        "NETWORK_SECURITY_CONFIG_CLEARTEXT_PERMITTED": "Remove cleartextTrafficPermitted=true from network security config or scope it narrowly to non-sensitive debug/test endpoints.",
        "BACKUP_ALLOWED_SENSITIVE_APP": "Disable unrestricted backup for sensitive apps or define explicit backup/data-extraction rules that exclude secrets and regulated data.",
        "BACKUP_ALLOWED": "Disable unrestricted backup for sensitive apps or define explicit backup/data-extraction rules that exclude secrets and regulated data.",
        "DEBUGGABLE_SENSITIVE_APP": "Ship release builds with debuggable=false and verify the final APK/AAB generated for distribution.",
        "DEBUGGABLE_ENABLED": "Ship release builds with debuggable=false and verify the final APK/AAB generated for distribution.",
        "FLAG_SECURE_NOT_OBSERVED_SENSITIVE_APP": "Review sensitive screens and add FLAG_SECURE where screenshots/screen-sharing exposure is unacceptable. Treat this as best-effort static evidence, not runtime proof.",
        "FILTER_TOUCHES_WHEN_OBSCURED_NOT_OBSERVED_SENSITIVE_APP": "Review sensitive click targets for tapjacking defenses such as filterTouchesWhenObscured or equivalent UI handling.",
        "ACCESSIBILITY_DATA_SENSITIVE_NOT_OBSERVED": "For Android versions that support it, review sensitive views for accessibilityDataSensitive or equivalent protections.",
    }.get(str(finding_type), "Review the finding manually and document whether it is fixed, accepted risk, or not applicable.")


def defensive_finding_id(index: int) -> str:
    return f"AURA-DEF-{index:03d}"


def defensive_findings_section(findings: list[dict[str, Any]]) -> list[str]:
    lines = ["## Defensive Findings and Remediation", ""]
    if not findings:
        return lines + ["No defensive surface findings were exported for the target app.", ""]
    lines += [
        "| Finding ID | Source | Type | Severity | Confidence | MASVS/MASTG area | Status | Remediation |",
        "| --- | --- | --- | --- | ---: | --- | --- | --- |",
    ]
    for index, finding in enumerate(
        sorted(
            findings,
            key=lambda item: (
                SEVERITY_ORDER.get(item.get("severity", "INFO"), 9),
                str(item.get("findingType", "")),
            ),
        ),
        start=1,
    ):
        area, detail = masvs_mapping(finding.get("findingType"))
        lines.append(
            f"| `{defensive_finding_id(index)}` | `ON_DEVICE` | `{finding.get('findingType')}` | `{finding.get('severity')}` | "
            f"{score(finding.get('confidence'))} | {md_escape(area)}: {md_escape(detail)} | `open` | "
            f"{md_escape(remediation_for_finding(finding.get('findingType')))} |"
        )
    lines += [
        "",
        "Status values are report workflow markers. Use `open`, `fixed`, `accepted risk`, or `not reproducible` during retest review.",
        "",
    ]
    return lines


def offline_finding_id(index: int) -> str:
    return f"AURA-OFF-{index:03d}"


def offline_observation_rows(offline_apk: dict[str, Any]) -> list[str]:
    observations = offline_apk.get("observations") or {}
    network_config = observations.get("networkSecurityConfig") or {}
    rows = [
        ("Sensitive role hint", bool_text(observations.get("sensitiveRoleHint"))),
        ("debuggable", bool_text(observations.get("debuggable"))),
        ("allowBackup", bool_text(observations.get("allowBackup"))),
        ("usesCleartextTraffic", bool_text(observations.get("usesCleartextTraffic"))),
        ("networkSecurityConfig observability", network_config.get("observabilityState", "unknown")),
        ("networkSecurityConfig referenced", network_config.get("referenced") or "none"),
    ]
    for key, label in (
        ("flagSecure", "FLAG_SECURE"),
        ("filterTouchesWhenObscured", "filterTouchesWhenObscured"),
        ("accessibilityDataSensitive", "accessibilityDataSensitive"),
    ):
        item = observations.get(key) or {}
        rows.append(
            (
                label,
                f"observed={bool_text(item.get('observed'))}; obs={item.get('observabilityState', 'unknown')}; conf={score(item.get('confidence'))}",
            )
        )
    return [f"| {label} | `{md_escape(value)}` |" for label, value in rows]


def offline_apk_analyzer_section(
    offline_apk: dict[str, Any] | None,
    export: dict[str, Any],
) -> list[str]:
    lines = ["## Offline APK Analyzer Findings", ""]
    if not offline_apk:
        return lines + [
            "No offline APK analyzer JSON was supplied for the target app. Use `--offline-analysis <path>` to include static APK/code/layout evidence.",
            "",
        ]

    apk = offline_apk.get("apk") or {}
    findings = offline_apk.get("findings", [])
    lines += [
        "| Field | Value |",
        "| --- | --- |",
        f"| Analyzer version | `{offline_apk.get('analyzerVersion', 'unknown')}` |",
        f"| APK path | `{md_escape(offline_apk_path_text(offline_apk, export))}` |",
        f"| APK SHA-256 prefix | `{offline_sha_prefix(offline_apk)}` |",
        f"| APK package | `{md_escape(redact_offline_value(apk.get('packageName', 'unknown'), offline_apk, export))}` |",
        f"| APK label | `{md_escape(redact_offline_value(apk.get('label', 'unknown'), offline_apk, export))}` |",
        f"| targetSdkVersion | `{apk.get('targetSdkVersion', 'unknown')}` |",
        "",
        "Static observations:",
        "",
        "| Observation | Value |",
        "| --- | --- |",
    ]
    lines += offline_observation_rows(offline_apk)
    lines += [""]

    if findings:
        lines += [
            "| Finding ID | Source | Type | Severity | Confidence | Observability | MASVS/MASTG area | Evidence | Remediation |",
            "| --- | --- | --- | --- | ---: | --- | --- | --- | --- |",
        ]
        for index, finding in enumerate(
            sorted(
                findings,
                key=lambda item: (
                    SEVERITY_ORDER.get(item.get("severity", "INFO"), 9),
                    str(item.get("findingType", "")),
                ),
            ),
            start=1,
        ):
            area, detail = masvs_mapping(finding.get("findingType"))
            evidence_value = redact_offline_value(finding.get("rawValue", ""), offline_apk, export)
            lines.append(
                f"| `{offline_finding_id(index)}` | `OFFLINE_APK_ANALYZER` | `{finding.get('findingType')}` | `{finding.get('severity')}` | "
                f"{score(finding.get('confidence'))} | `{finding.get('observabilityState', 'unknown')}` | "
                f"{md_escape(area)}: {md_escape(detail)} | {md_escape(evidence_value)} | "
                f"{md_escape(remediation_for_finding(finding.get('findingType')))} |"
            )
    else:
        lines += ["No offline APK analyzer findings were emitted for the target APK."]
    lines += [
        "",
        "Offline findings are static evidence. Absence of a defensive API pattern is a best-effort signal, not runtime proof.",
        "",
    ]
    for limitation in offline_apk.get("limitations", []):
        lines.append(f"- {limitation}")
    if offline_apk.get("limitations"):
        lines.append("")
    return lines


def capability_surface_section(assessment: dict[str, Any]) -> list[str]:
    snapshot = assessment.get("snapshot", {})
    raw = snapshot.get("rawFeatures", {})
    requested = snapshot.get("requestedPermissions", [])
    granted = snapshot.get("grantedPermissions", [])
    special = snapshot.get("specialAccess", {})
    components = snapshot.get("components", [])
    exported_components = [component for component in components if component.get("exported") is True]
    unprotected_exported = [
        component for component in exported_components
        if not component.get("permission") and not component.get("isLauncherEntryPoint", False)
    ]
    lines = [
        "## Capability and Component Surface",
        "",
        "| Surface | Value |",
        "| --- | --- |",
        f"| Requested permissions | `{len(requested)}` |",
        f"| Granted permissions | `{len(granted)}` |",
        f"| Declared components | `{len(components) or raw.get('componentCount', 'unknown')}` |",
        f"| Exported components | `{len(exported_components) or raw.get('exportedComponentCount', 'unknown')}` |",
        f"| Unprotected exported components | `{len(unprotected_exported) or raw.get('unprotectedExportedComponentCount', 'unknown')}` |",
        f"| allowBackup | `{raw.get('allowBackup', 'unknown')}` |",
        f"| debuggable | `{raw.get('debuggable', 'unknown')}` |",
        f"| usesCleartextTraffic | `{raw.get('usesCleartextTraffic', 'unknown')}` |",
        f"| network security config observability | `{raw.get('networkSecurityConfigObservability', 'unknown')}` |",
        "",
    ]
    if special:
        lines += ["Special access states:", ""]
        lines += [f"- `{name}`: `{state}`" for name, state in sorted(special.items())]
        lines += [""]
    if requested:
        lines += ["Requested permissions sample:", ""]
        lines += [f"- `{permission}`" for permission in requested[:16]]
        if len(requested) > 16:
            lines.append(f"- ... `{len(requested) - 16}` more")
        lines += [""]
    return lines


def remediation_checklist_section(
    assessment: dict[str, Any],
    findings: list[dict[str, Any]],
    offline_apk: dict[str, Any] | None = None,
) -> list[str]:
    lines = ["## Remediation Checklist", ""]
    items: list[str] = []
    seen: set[str] = set()
    for action in assessment.get("decision", {}).get("recommendedActions", []):
        if action.get("actionId") == "no_user_action_required":
            continue
        item = f"{action.get('title', action.get('actionId', 'Action'))}: {action.get('description', '')}"
        key = f"action:{action.get('actionId', item)}"
        if key not in seen:
            items.append(item)
            seen.add(key)
    for finding in findings:
        key = f"on-device:{finding.get('findingType')}"
        if key not in seen:
            items.append(f"{finding.get('findingType')}: {remediation_for_finding(finding.get('findingType'))}")
            seen.add(key)
    for finding in (offline_apk or {}).get("findings", []):
        key = f"offline:{finding.get('findingType')}"
        if key not in seen:
            items.append(f"{finding.get('findingType')} (offline): {remediation_for_finding(finding.get('findingType'))}")
            seen.add(key)
    if not items:
        return lines + ["No remediation checklist items were generated for the target app.", ""]
    for index, item in enumerate(items, start=1):
        lines.append(f"{index}. [open] {item}")
    lines += [
        "",
        "Retest expectation: rerun AURA after changes and compare threat decision, defensive posture, finding types, and evidence IDs against this report.",
        "",
    ]
    return lines


def retest_comparison_section(
    current_export: dict[str, Any],
    previous_export: dict[str, Any] | None,
    current_offline_apk: dict[str, Any] | None = None,
    previous_offline_apk: dict[str, Any] | None = None,
) -> list[str]:
    lines = ["## Retest Comparison", ""]
    if previous_export is None:
        return lines + [
            "No previous export was supplied. Generate a before/after comparison with `--previous-export <path>`.",
            "",
        ]
    current_assessment = current_export.get("assessments", [{}])[0]
    previous_assessment = previous_export.get("assessments", [{}])[0]
    current_package = package_name(current_assessment)
    previous_package = package_name(previous_assessment)
    current_posture = postures_by_package(current_export).get(current_package, {})
    previous_posture = postures_by_package(previous_export).get(previous_package, {})
    current_findings = {finding.get("findingType") for finding in current_export.get("defensiveSurfaceFindings", [])}
    previous_findings = {finding.get("findingType") for finding in previous_export.get("defensiveSurfaceFindings", [])}
    current_offline_findings = {finding.get("findingType") for finding in (current_offline_apk or {}).get("findings", [])}
    previous_offline_findings = {finding.get("findingType") for finding in (previous_offline_apk or {}).get("findings", [])}
    fixed = sorted(previous_findings - current_findings)
    remaining = sorted(previous_findings & current_findings)
    new = sorted(current_findings - previous_findings)
    offline_fixed = sorted(previous_offline_findings - current_offline_findings)
    offline_remaining = sorted(previous_offline_findings & current_offline_findings)
    offline_new = sorted(current_offline_findings - previous_offline_findings)
    lines += [
        "| Field | Previous | Current |",
        "| --- | --- | --- |",
        f"| Threat decision | `{previous_assessment.get('decision', {}).get('color', 'unknown')}` | `{current_assessment.get('decision', {}).get('color', 'unknown')}` |",
        f"| Defensive posture | `{previous_posture.get('postureClass', 'unknown')}` | `{current_posture.get('postureClass', 'unknown')}` |",
        f"| On-device defensive finding types | `{', '.join(sorted(previous_findings)) or 'none'}` | `{', '.join(sorted(current_findings)) or 'none'}` |",
        f"| Offline APK finding types | `{', '.join(sorted(previous_offline_findings)) or 'none'}` | `{', '.join(sorted(current_offline_findings)) or 'none'}` |",
        "",
        f"- Fixed on-device finding types: `{', '.join(fixed) or 'none'}`",
        f"- Remaining on-device finding types: `{', '.join(remaining) or 'none'}`",
        f"- New/regressed on-device finding types: `{', '.join(new) or 'none'}`",
        f"- Fixed offline APK finding types: `{', '.join(offline_fixed) or 'none'}`",
        f"- Remaining offline APK finding types: `{', '.join(offline_remaining) or 'none'}`",
        f"- New/regressed offline APK finding types: `{', '.join(offline_new) or 'none'}`",
        "",
    ]
    return lines


def release_status_label(status: str) -> str:
    return {
        "BLOCKED": "Blocked before release",
        "NEEDS_FIXES": "Needs fixes before production",
        "REVIEW_RECOMMENDED": "Review recommended",
        "PASS": "No release blockers observed",
    }.get(status, status or "unknown")


def release_readiness_section(
    export: dict[str, Any],
    assessment: dict[str, Any],
    audit: dict[str, Any],
    episodes: list[dict[str, Any]],
) -> list[str]:
    status = audit.get("releaseStatus", {})
    counts = audit.get("priorityCounts", {})
    return [
        "## Release Readiness",
        "",
        f"Release readiness: **{md_escape(release_status_label(status.get('status', 'unknown')))}**.",
        "",
        "| Axis | Result |",
        "| --- | --- |",
        f"| Target app | `{md_escape(title_for_app(assessment))}` |",
        f"| Generated at | `{iso_time(export.get('generatedAt'))}` |",
        f"| Release status | `{status.get('status', 'unknown')}` |",
        f"| P1 blocker findings | `{counts.get('P1', 0)}` |",
        f"| P2 should-fix findings | `{counts.get('P2', 0)}` |",
        f"| P3 review findings | `{counts.get('P3', 0)}` |",
        f"| INFO items | `{counts.get('INFO', 0)}` |",
        f"| Ready for external beta | `{bool_text(status.get('readyForExternalBeta'))}` |",
        f"| Ready for production | `{bool_text(status.get('readyForProduction'))}` |",
        f"| Retest recommended | `{bool_text(status.get('retestRecommended'))}` |",
        f"| Temporal episodes for target | `{len(episodes)}` |",
        "",
        f"Reason: {md_escape(status.get('reason', 'No release status reason exported.'))}",
        "",
        "For app-owner reports, release-risk findings are the primary output. The runtime threat decision is retained only as secondary context because a non-malicious app can still have release-blocking hardening gaps.",
        "",
    ]


def top_fix_action(finding: dict[str, Any]) -> str:
    finding_type = finding.get("type")
    title = str(finding.get("title") or "")
    if finding_type == "DEBUGGABLE_OR_TEST_CONFIG_IN_RELEASE":
        return "Fix release build configuration"
    if finding_type == "EXPORTED_COMPONENT_WITHOUT_GUARD":
        return f"Protect or remove {title.replace('Exported ', '').replace(' without permission guard', '')}"
    if finding_type == "CLEARTEXT_TRAFFIC_ALLOWED":
        return "Disable or narrowly scope cleartext traffic"
    if finding_type == "BACKUP_MAY_INCLUDE_SENSITIVE_DATA":
        return "Define backup/data extraction policy"
    if finding_type == "MISSING_TAPJACKING_DEFENSE_ON_SENSITIVE_ACTION":
        return "Review tapjacking defenses on sensitive screens"
    if finding_type == "DEEPLINK_ACCEPTS_UNTRUSTED_INPUT":
        return "Constrain and validate deep link input"
    if finding_type == "WEBVIEW_RISKY_CONFIGURATION":
        return "Review WebView configuration"
    if finding_type == "SECRETS_OR_ENDPOINTS_IN_APK":
        return "Classify embedded keys/endpoints"
    return title or str(finding_type or "Review release-risk finding")


def top_fix_plan_section(audit: dict[str, Any], limit: int = 8) -> list[str]:
    findings = audit.get("findings", [])
    lines = ["## Top Fix Plan", ""]
    if not findings:
        return lines + ["No release-risk fix plan was generated from supplied evidence.", ""]
    seen: set[str] = set()
    plan: list[str] = []
    for finding in findings:
        action = top_fix_action(finding)
        key = f"{finding.get('priority')}:{action}"
        if key in seen:
            continue
        seen.add(key)
        plan.append(
            f"{finding.get('priority')}: {action} "
            f"({finding.get('owner')}; verify: {finding.get('verificationCheck')})"
        )
        if len(plan) >= limit:
            break
    lines += [f"{index}. {md_escape(item)}" for index, item in enumerate(plan, start=1)]
    lines += [""]
    return lines


def audit_finding_rows(findings: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| ID | Priority | Finding | Confidence | Owner | Manual review | Evidence |",
        "| --- | --- | --- | ---: | --- | --- | --- |",
    ]
    for finding in findings:
        evidence = finding.get("evidence") or {}
        evidence_text = f"{evidence.get('source')} / {evidence.get('sourceFindingType')}: {evidence.get('rawValue') or 'evidence exported'}"
        lines.append(
            f"| `{finding.get('id')}` | `{finding.get('priority')}` | {md_escape(finding.get('title'))} | "
            f"{score(finding.get('confidence'))} | {md_escape(finding.get('owner'))} | "
            f"`{bool_text(finding.get('requiresManualReview'))}` | {md_escape(evidence_text)} |"
        )
    return lines


def release_risk_findings_section(audit: dict[str, Any]) -> list[str]:
    findings = audit.get("findings", [])
    lines = ["## Release Risk Findings", ""]
    if not findings:
        return lines + [
            "No release-risk findings were generated from the supplied AURA export and offline APK analyzer evidence.",
            "",
        ]
    lines += audit_finding_rows(findings)
    lines += [""]
    for finding in findings:
        lines += [
            f"### {finding.get('priority')} {md_escape(finding.get('title'))}",
            "",
            f"- Finding ID: `{finding.get('id')}`",
            f"- Type: `{finding.get('type')}`",
            f"- Fingerprint: `{finding.get('fingerprint')}`",
            f"- Suggested owner: `{md_escape(finding.get('owner'))}`",
            f"- Requires manual review: `{bool_text(finding.get('requiresManualReview'))}`",
            f"- Acceptance criteria: {md_escape(finding.get('acceptanceCriteria'))}",
            f"- Why it matters: {md_escape(finding.get('whyItMatters'))}",
            f"- How to fix: {md_escape(finding.get('howToFix'))}",
            f"- Verification command/check: {md_escape(finding.get('verificationCheck') or finding.get('howToVerify'))}",
            "",
        ]
    return lines


def audit_retest_section(
    current_audit: dict[str, Any],
    previous_audit: dict[str, Any] | None,
) -> list[str]:
    diff = compare_app_owner_audits(previous_audit, current_audit)
    lines = ["## Release-Risk Retest Diff", ""]
    if not diff.get("available"):
        return lines + [
            "No previous app-owner audit was supplied. Retest diffs use stable release-risk fingerprints when `--previous-export` and matching offline evidence are available.",
            "",
        ]
    lines += [
        "| Status | Count | Types |",
        "| --- | ---: | --- |",
        f"| Fixed | {len(diff.get('fixed', []))} | `{', '.join(item.get('type', '') for item in diff.get('fixed', [])) or 'none'}` |",
        f"| Remaining | {len(diff.get('remaining', []))} | `{', '.join(item.get('type', '') for item in diff.get('remaining', [])) or 'none'}` |",
        f"| New/regressed | {len(diff.get('new', []))} | `{', '.join(item.get('type', '') for item in diff.get('new', [])) or 'none'}` |",
        "",
    ]
    return lines


def runtime_abuse_context_section(
    assessment: dict[str, Any],
    posture: dict[str, Any],
) -> list[str]:
    decision = assessment.get("decision", {})
    role = assessment.get("role", {})
    provenance = assessment.get("provenance", {})
    return [
        "## Runtime Abuse Context",
        "",
        "This section is secondary in app-owner mode. It answers whether AURA observed user/device abuse evidence, not whether the release artifact is ready.",
        "",
        "| Axis | Value |",
        "| --- | --- |",
        f"| Threat behavior decision | `{decision.get('color', 'unknown')}` / {md_escape(decision.get('title', ''))} |",
        f"| Defensive posture class | `{posture.get('postureClass', 'NO_OBSERVED_WEAKNESS')}` |",
        f"| Inferred role | `{role.get('predicted', 'unknown')}` / confidence `{score(role.get('confidence'))}` |",
        f"| Provenance class | `{provenance.get('provenanceClass', 'unknown')}` |",
        f"| Actionability class | `{decision.get('actionabilityClass', 'unknown')}` |",
        "",
        "A `GREEN` threat behavior decision is not a release-readiness pass. Release risk is determined by the findings above.",
        "",
    ]


def app_owner_reproducibility_summary(export: dict[str, Any], audit: dict[str, Any], offline_apk: dict[str, Any] | None) -> list[str]:
    snapshot = first_snapshot(export)
    return [
        "### Reproducibility",
        "",
        f"- Export schema version: `{export.get('schemaVersion')}`",
        f"- Report generator version: `{REPORT_GENERATOR_VERSION}`",
        f"- App-owner audit engine version: `{audit.get('auditEngineVersion', 'unknown')}`",
        f"- Offline APK analyzer version: `{(offline_apk or {}).get('analyzerVersion', 'not supplied')}`",
        f"- Collector version: `{snapshot.get('collectorVersion', 'unknown')}`",
        f"- Scan ID: `{export.get('scanId', 'unknown')}`",
        f"- Generated at: `{iso_time(export.get('generatedAt'))}`",
        "",
    ]


def demote_section(lines: list[str]) -> list[str]:
    output: list[str] = []
    for line in lines:
        if line.startswith("### "):
            output.append(f"**{line[4:]}**")
        elif line.startswith("## "):
            output.append(f"### {line[3:]}")
        else:
            output.append(line)
    return output


def app_owner_scope_section(export: dict[str, Any], assessment: dict[str, Any]) -> list[str]:
    snapshot = assessment.get("snapshot", {})
    raw = snapshot.get("rawFeatures", {})
    return [
        "## Scope and Environment",
        "",
        "| Field | Value |",
        "| --- | --- |",
        "| Report type | App owner / developer release-risk report |",
        f"| Target package | `{snapshot.get('packageName', 'unknown')}` |",
        f"| Target label | `{snapshot.get('appLabel', 'unknown')}` |",
        f"| Version | `{snapshot.get('versionName', 'unknown')}` / `{snapshot.get('versionCode', 'unknown')}` |",
        f"| Scan ID | `{export.get('scanId', 'unknown')}` |",
        f"| Build/flavor | `{export.get('flavor', snapshot.get('flavor', 'unknown'))}` |",
        f"| Device model | `{snapshot.get('deviceModel', 'unknown')}` |",
        f"| Android version / API | `{snapshot.get('androidVersion', 'unknown')}` / `{snapshot.get('apiLevel', 'unknown')}` |",
        f"| Security patch level | `{snapshot.get('securityPatchLevel', 'unknown')}` |",
        f"| Collector version | `{snapshot.get('collectorVersion', 'unknown')}` |",
        f"| Source partition | `{raw.get('sourcePartition', 'unknown')}` |",
        f"| Installer | `{snapshot.get('installerPackageName') or 'none_or_unknown'}` |",
        "",
        "Out of scope: no TLS MITM, no screen or notification content reading, no dynamic exploit proof, no root/kernel/baseband/TEE forensics.",
        "",
    ]


def render_app_owner_markdown(
    export: dict[str, Any],
    *,
    previous_export: dict[str, Any] | None = None,
    offline_analysis: dict[str, Any] | None = None,
    previous_offline_analysis: dict[str, Any] | None = None,
) -> str:
    assessment = export.get("assessments", [{}])[0]
    package = package_name(assessment)
    postures = postures_by_package(export)
    findings = findings_by_package(export).get(package, [])
    package_episodes = episodes_by_package(export).get(package, [])
    posture = postures.get(package, {})
    previous_package = package_name((previous_export or {}).get("assessments", [{}])[0]) if previous_export else ""
    current_offline_apk = offline_apk_for_package(offline_analysis, (export.get("reportScope") or {}).get("targetPackage", package))
    previous_offline_apk = offline_apk_for_package(
        previous_offline_analysis,
        (previous_export or {}).get("reportScope", {}).get("targetPackage", previous_package),
    )
    current_audit = build_app_owner_audit(export, offline_analysis=offline_analysis)
    previous_audit = (
        build_app_owner_audit(previous_export, offline_analysis=previous_offline_analysis)
        if previous_export is not None
        else None
    )
    lines = [
        "# AURA App Owner Release Risk Report",
        "",
        f"Generated from scan `{export.get('scanId', 'unknown')}`.",
        "",
    ]
    lines += release_readiness_section(export, assessment, current_audit, package_episodes)
    lines += top_fix_plan_section(current_audit)
    lines += release_risk_findings_section(current_audit)
    lines += audit_retest_section(current_audit, previous_audit)
    lines += [
        "## Scope and Methodology",
        "",
        "This app-owner report focuses on release readiness for one target APK/app context. It does not try to certify that the app is malware-free. It converts AURA and offline APK evidence into release-risk findings with priority, evidence, remediation, verification, owner, and stable retest fingerprints.",
        "",
        "MASVS/MASTG mappings are broad review areas, not a claim that AURA is a complete OWASP MASVS scanner.",
        "",
        "Report privacy:",
        "",
    ]
    lines += privacy_lines(export)
    lines += [
        "## Technical Appendix",
        "",
        "The release-risk list above is canonical for app-owner delivery. The sections below preserve supporting context for review and reproducibility; they should not be copied into tickets unless needed.",
        "",
    ]
    lines += demote_section(app_owner_scope_section(export, assessment))
    lines += demote_section(capability_surface_section(assessment))
    lines += demote_section(offline_apk_analyzer_section(current_offline_apk, export))
    lines += demote_section(runtime_abuse_context_section(assessment, posture))
    lines += [
        "### Observability Limits",
        "",
        "- On-device AURA observes manifest/component metadata and best-effort cleartext/debuggable/backup indicators where Android exposes them.",
        "- Detailed `network_security_config`, `FLAG_SECURE`, `filterTouchesWhenObscured`, and `accessibilityDataSensitive` checks belong to the offline APK analyzer or source review.",
        "- Defensive findings are app-hardening signals, not malware verdicts.",
        "",
    ]
    lines += app_owner_reproducibility_summary(export, current_audit, current_offline_apk)
    return "\n".join(lines)


def teaser_public_name(export: dict[str, Any], assessment: dict[str, Any]) -> str:
    scope = export.get("reportScope") or {}
    return str(scope.get("publicAppName") or assessment.get("snapshot", {}).get("appLabel") or "target app")


def teaser_source_url(export: dict[str, Any]) -> str:
    return str((export.get("reportScope") or {}).get("publicSourceUrl") or "not supplied")


def teaser_scope_section(export: dict[str, Any], assessment: dict[str, Any]) -> list[str]:
    scope = export.get("reportScope") or {}
    snapshot = assessment.get("snapshot", {})
    return [
        "## Authorization and Scope",
        "",
        "This is not a vulnerability report. It is a non-invasive public-surface demo of the reporting structure AURA can produce.",
        "",
        "| Field | Value |",
        "| --- | --- |",
        "| Report type | Public-surface teaser / outreach demo |",
        f"| Intended recipient | `{scope.get('clientName', 'unspecified')}` |",
        f"| Public target app | `{md_escape(teaser_public_name(export, assessment))}` |",
        f"| Target alias in this report | `{snapshot.get('packageName', 'unknown')}` |",
        f"| Public source | `{md_escape(teaser_source_url(export))}` |",
        f"| Scan ID | `{export.get('scanId', 'unknown')}` |",
        f"| Build/flavor | `{export.get('flavor', snapshot.get('flavor', 'unknown'))}` |",
        f"| Android version / API | `{snapshot.get('androidVersion', 'unknown')}` / `{snapshot.get('apiLevel', 'unknown')}` |",
        f"| Device model | `{snapshot.get('deviceModel', 'unknown')}` |",
        "",
        "Scope boundaries:",
        "",
        "- Publicly available Android app build only.",
        "- No account login, payment flow, or sensitive in-app workflow was exercised.",
        "- No root, Frida, exploit attempt, MITM, TLS interception, or protection bypass.",
        "- No screen contents, notification contents, keystrokes, or network payloads were read.",
        "- Detailed findings and remediation require authorization and preferably a test build supplied by the owner.",
        "",
    ]


def teaser_summary_section(
    export: dict[str, Any],
    assessment: dict[str, Any],
    posture: dict[str, Any],
    findings: list[dict[str, Any]],
    episodes: list[dict[str, Any]],
) -> list[str]:
    decision = assessment.get("decision", {})
    role = assessment.get("role", {})
    provenance = assessment.get("provenance", {})
    story = assessment.get("userRiskStory", {})
    finding_text = "none exported in teaser scope"
    if findings:
        categories = sorted({teaser_finding_category(finding) for finding in findings})
        finding_text = f"{len(categories)} high-level review area(s): {', '.join(categories[:3])}"
    return [
        "## Teaser Conclusion",
        "",
        f"AURA evaluated the public target app `{md_escape(teaser_public_name(export, assessment))}` using a no-root, metadata-only scope. The teaser is designed to show report semantics, not to make a final security verdict about the app.",
        "",
        "| Axis | Teaser result |",
        "| --- | --- |",
        f"| Threat decision | `{decision.get('color', 'unknown')}` / {md_escape(decision.get('title', ''))} |",
        f"| Defensive posture | {teaser_posture_label(posture)} |",
        f"| Role inference | `{role.get('predicted', 'unknown')}` / confidence `{score(role.get('confidence'))}` |",
        f"| Provenance class | `{provenance.get('provenanceClass', 'unknown')}` |",
        f"| Provenance trust level | `{level(provenance_trust(assessment))}` |",
        f"| Temporal episodes in teaser scope | `{len(episodes)}` |",
        f"| Defensive categories shown | `{finding_text}` |",
        "",
        f"High-level risk story: {md_escape(story.get('primaryReason', decision.get('explanation', 'No detailed story exported in teaser mode.')))}",
        "",
    ]


def teaser_posture_label(posture: dict[str, Any]) -> str:
    posture_class = str(posture.get("postureClass", "NO_OBSERVED_WEAKNESS"))
    if posture_class == "NO_OBSERVED_WEAKNESS":
        return "`no high-level review area shown in teaser`"
    if posture_class == "REVIEW_RECOMMENDED":
        return "`review area available in full report`"
    if posture_class == "WEAK_DEFENSIVE_SURFACE":
        return "`priority review area available in full report`"
    return "`manual review area available in full report`"


def teaser_finding_category(finding: dict[str, Any]) -> str:
    finding_type = str(finding.get("findingType", ""))
    if "EXPORTED_COMPONENT" in finding_type:
        return "platform/component surface review"
    if "CLEARTEXT" in finding_type or "NETWORK_SECURITY_CONFIG" in finding_type:
        return "network transport configuration review"
    if "BACKUP" in finding_type:
        return "backup/data extraction configuration review"
    if "DEBUGGABLE" in finding_type:
        return "release build hardening review"
    if "FLAG_SECURE" in finding_type or "FILTER_TOUCHES" in finding_type or "ACCESSIBILITY_DATA" in finding_type:
        return "sensitive UI hardening review"
    return "manual mobile security review"


def teaser_capability_section(
    assessment: dict[str, Any],
    findings: list[dict[str, Any]],
    max_findings: int,
) -> list[str]:
    snapshot = assessment.get("snapshot", {})
    requested = snapshot.get("requestedPermissions", [])
    granted = snapshot.get("grantedPermissions", [])
    special = snapshot.get("specialAccess") or {}
    active_special = [name for name, state in special.items() if state == "OBSERVED_ENABLED"]
    declared_special = [name for name, state in special.items() if state == "DECLARED_ONLY"]
    raw = snapshot.get("rawFeatures") or {}
    requested_count = len(requested) or raw.get("requestedPermissionCount", "unknown")
    granted_count = len(granted) or raw.get("grantedPermissionCount", "unknown")
    lines = [
        "## High-Level Observed Categories",
        "",
        "| Category | Teaser-safe summary |",
        "| --- | --- |",
        f"| Permissions/capabilities | `{requested_count}` requested, `{granted_count}` granted in observed metadata |",
        f"| Active special access | `{', '.join(sorted(active_special)) if active_special else 'none observed'}` |",
        f"| Declared-only special access | `{', '.join(sorted(declared_special)) if declared_special else 'none exported in teaser'}` |",
        f"| Component surface | counts only; exact component names are suppressed |",
        f"| Backup/debuggable/cleartext indicators | backup `{raw.get('allowBackup', 'unknown')}`, debuggable `{raw.get('debuggable', 'unknown')}`, cleartext `{raw.get('usesCleartextTraffic', 'unknown')}` |",
        "",
    ]
    if findings:
        lines += [
            "Defensive posture review areas shown without raw component names or exact findings:",
            "",
        ]
        categories = []
        for finding in sorted(findings, key=lambda item: teaser_finding_category(item)):
            category = teaser_finding_category(finding)
            if category not in categories:
                categories.append(category)
        for category in categories[:max_findings]:
            lines.append(
                f"- {category}: detailed evidence and remediation are reserved for the authorized full report."
            )
        lines.append("")
    else:
        lines += ["No defensive posture categories were exported in the teaser scope.", ""]
    return lines


def teaser_baseline_section(evaluation: dict[str, Any] | None) -> list[str]:
    if not evaluation:
        return [
            "## Baseline Teaser",
            "",
            "No evaluator output was supplied for this teaser. Full authorized reports can include a replayable baseline comparison.",
            "",
        ]
    model_metrics = evaluation.get("modelMetrics", {})
    permission = model_metrics.get("permission_only", {})
    full = model_metrics.get("full_aura", {})
    labelled = int(evaluation.get("labelledApps") or (evaluation.get("metrics") or {}).get("metric_population") or 0)
    lines = [
        "## Baseline Teaser",
        "",
        f"- Baseline scope: labelled scenario subset only (`{labelled}` labelled app(s)); this is a demo of AURA semantics, not a claim about the target app owner without authorization.",
        f"- Permission-only non-actionable critical alert rate: `{score(permission.get('non_actionable_critical_alert_rate'))}`",
        f"- Full AURA non-actionable critical alert rate: `{score(full.get('non_actionable_critical_alert_rate'))}`",
        f"- Permission-only user-actionable precision: `{score(permission.get('user_actionable_precision'))}`",
        f"- Full AURA user-actionable precision: `{score(full.get('user_actionable_precision'))}`",
        "",
        "The point of the teaser is the reporting distinction: AURA avoids treating capability exposure alone as a final threat verdict.",
        "",
    ]
    return lines


def teaser_full_report_section() -> list[str]:
    return [
        "## What the Authorized Full Report Would Add",
        "",
        "With explicit authorization and preferably a supplied test build, a full AURA report can add:",
        "",
        "- App-owner release readiness with P1/P2/P3/INFO findings and stable retest fingerprints.",
        "- Component-level evidence with exact manifest entries and exported component review.",
        "- Offline APK analyzer evidence for `network_security_config`, defensive UI patterns, and static code/layout heuristics.",
        "- Full evidence graph, decision trace, counterfactual remediation, and release-risk retest comparison.",
        "- Concrete remediation checklist with finding IDs, owner-friendly status tracking, and before/after diffs.",
        "- JSON appendix suitable for reproducibility, expert review, and policy replay.",
        "",
        "The teaser intentionally withholds raw evidence, exact component names, signing details, source paths, internal thresholds, and exploitability detail.",
        "",
    ]


def render_public_teaser_markdown(
    export: dict[str, Any],
    evaluation: dict[str, Any] | None = None,
    *,
    max_findings: int = 3,
) -> str:
    assessment = export.get("assessments", [{}])[0]
    package = package_name(assessment)
    posture = postures_by_package(export).get(package, {})
    findings = findings_by_package(export).get(package, [])
    package_episodes = episodes_by_package(export).get(package, [])
    lines = [
        "# AURA Public-Surface Demo Report",
        "",
        "> This is not a vulnerability report. It is a non-invasive teaser showing how AURA structures Android app risk, defensive posture, actionability, and observability limits.",
        "",
    ]
    lines += teaser_summary_section(export, assessment, posture, findings, package_episodes)
    lines += teaser_scope_section(export, assessment)
    lines += [
        "## Why AURA Is Different",
        "",
        "AURA does not equate \"more permissions\" with a final threat verdict. It asks whether observed capabilities fit the app role, whether provenance is explainable, whether there is concrete abuse evidence, whether the result is user-actionable, and what the no-root scan could not observe.",
        "",
        "Threat decision and defensive posture are separate axes. A public app can have no user-actionable threat finding in this teaser while still having app-hardening categories that would deserve review in an authorized report.",
        "",
    ]
    lines += teaser_capability_section(assessment, findings, max_findings=max_findings)
    lines += teaser_baseline_section(evaluation)
    lines += [
        "## Observability Limits",
        "",
        "- Teaser mode uses no-root metadata and suppresses raw evidence details.",
        "- Missing evidence is treated as uncertainty, not as proof of compromise.",
        "- Temporal correlation, when present, is not proof of attack.",
        "- AURA cannot assess kernel, baseband, TEE, bootloader, server-side account abuse, or hidden OEM framework compromise from this public-surface scan.",
        "",
        "Report privacy:",
        "",
    ]
    lines += privacy_lines(export)
    lines += teaser_full_report_section()
    lines += [
        "## Manual Review Gate",
        "",
        "Before sending this teaser externally, manually review the wording and remove anything that could be read as an accusation or unauthorized vulnerability disclosure.",
        "",
        "Suggested outreach line: `This is not a finding against your application; it is a sample of the report structure AURA can generate with proper authorization.`",
        "",
    ]
    return "\n".join(lines)


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
    report_type: str = "device_expert",
    previous_export: dict[str, Any] | None = None,
    offline_analysis: dict[str, Any] | None = None,
    previous_offline_analysis: dict[str, Any] | None = None,
    max_findings: int = 3,
) -> str:
    if report_type == "public_teaser":
        return render_public_teaser_markdown(export, evaluation, max_findings=max_findings)
    if report_type == "app_owner":
        return render_app_owner_markdown(
            export,
            previous_export=previous_export,
            offline_analysis=offline_analysis,
            previous_offline_analysis=previous_offline_analysis,
        )
    if report_type != "device_expert":
        raise ValueError(f"Unsupported report_type {report_type!r}")

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
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    return escaped


def html_title(markdown_text: str) -> str:
    for line in markdown_text.splitlines():
        if line.startswith("# "):
            return line[2:].strip() or "AURA Report"
    return "AURA Report"


def render_html(markdown_text: str) -> str:
    title = escape(html_title(markdown_text))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
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
    report_type: str = "device_expert",
    previous_export: dict[str, Any] | None = None,
    offline_analysis: dict[str, Any] | None = None,
    previous_offline_analysis: dict[str, Any] | None = None,
    max_findings: int = 3,
) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    markdown = render_markdown(
        export,
        evaluation,
        top_apps=top_apps,
        report_type=report_type,
        previous_export=previous_export,
        offline_analysis=offline_analysis,
        previous_offline_analysis=previous_offline_analysis,
        max_findings=max_findings,
    )
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
    parser.add_argument("--max-findings", type=int, default=3, help="Maximum high-level finding categories in public teaser reports")
    parser.add_argument("--report-type", choices=REPORT_TYPES, default="device_expert")
    parser.add_argument("--target-package", help="Required for target-scoped report types; package to scope the report to")
    parser.add_argument("--client-name", help="Optional recipient/client name for public teaser reports")
    parser.add_argument("--public-app-name", help="Optional public app display name for public teaser reports")
    parser.add_argument("--public-source-url", help="Optional public Play Store or case-study URL for public teaser reports")
    parser.add_argument("--previous-export", type=Path, help="Optional previous AURA export for app-owner retest comparison")
    parser.add_argument("--offline-analysis", type=Path, help="Optional tools/apk_analyzer JSON output for the target APK")
    parser.add_argument("--previous-offline-analysis", type=Path, help="Optional previous offline APK analyzer JSON for retest comparison")
    parser.add_argument("--privacy-mode", choices=PRIVACY_MODES, default=FULL_RESEARCH)
    parser.add_argument("--salt", default=DEFAULT_SALT, help="Project/customer-specific redaction salt")
    parser.add_argument(
        "--redacted-export-out",
        type=Path,
        help="Optional path for the privacy-processed JSON used by the report",
    )
    args = parser.parse_args()
    privacy_mode = args.privacy_mode
    if args.report_type == "public_teaser":
        privacy_mode = REDACTED_TEASER

    export = load_json(args.export)
    if export is None:
        raise ValueError(f"Could not load export {args.export}")
    previous_export = load_json(args.previous_export)
    offline_analysis = load_json(args.offline_analysis)
    previous_offline_analysis = load_json(args.previous_offline_analysis)
    if args.report_type in {"app_owner", "public_teaser"}:
        if not args.target_package:
            raise ValueError(f"--target-package is required when --report-type {args.report_type}")
        export = scope_export_to_package(export, args.target_package)
        export.setdefault("reportScope", {})
        export["reportScope"] = {
            **export["reportScope"],
            "reportType": args.report_type,
            "clientName": args.client_name,
            "publicAppName": args.public_app_name,
            "publicSourceUrl": args.public_source_url,
        }
        if previous_export is not None:
            previous_export = scope_export_to_package(previous_export, args.target_package)
        if offline_analysis is not None:
            offline_analysis = offline_apk_for_package(offline_analysis, args.target_package)
            if offline_analysis is None:
                raise ValueError(f"No offline APK analysis entry matched target package {args.target_package!r}")
        if previous_offline_analysis is not None:
            previous_offline_analysis = offline_apk_for_package(previous_offline_analysis, args.target_package)
            if previous_offline_analysis is None:
                raise ValueError(f"No previous offline APK analysis entry matched target package {args.target_package!r}")
    export = redact_export(
        export,
        mode=privacy_mode,
        salt=args.salt,
        salt_provided=args.salt != DEFAULT_SALT,
    )
    if args.report_type == "app_owner":
        export = mark_target_only_privacy(export)
    if args.report_type == "public_teaser":
        export = mark_public_teaser_privacy(export)
        export.setdefault("reportScope", {})
        export["reportScope"] = {
            **export["reportScope"],
            "reportType": "public_teaser",
            "clientName": args.client_name,
            "publicAppName": args.public_app_name,
            "publicSourceUrl": args.public_source_url,
        }
    if previous_export is not None:
        previous_export = redact_export(
            previous_export,
            mode=privacy_mode,
            salt=args.salt,
            salt_provided=args.salt != DEFAULT_SALT,
        )
        if args.report_type == "app_owner":
            previous_export = mark_target_only_privacy(previous_export)
        if args.report_type == "public_teaser":
            previous_export = mark_public_teaser_privacy(previous_export)
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
        report_type=args.report_type,
        previous_export=previous_export,
        offline_analysis=offline_analysis,
        previous_offline_analysis=previous_offline_analysis,
        max_findings=args.max_findings,
    )
    print(f"Wrote Markdown report to {markdown_path}")
    print(f"Wrote HTML report to {html_path}")
    print("Open the HTML report in a browser and print/save as PDF when a PDF artifact is needed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
