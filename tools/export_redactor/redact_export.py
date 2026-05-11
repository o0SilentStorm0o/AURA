#!/usr/bin/env python3
"""Redact AURA JSON exports for safe sharing and customer-facing reports."""

from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


FULL_RESEARCH = "full_research"
REDACTED_EXPERT = "redacted_expert"
MINIMAL_SUPPORT = "minimal_support"
PRIVACY_MODES = (FULL_RESEARCH, REDACTED_EXPERT, MINIMAL_SUPPORT)
DEFAULT_SALT = "aura-public-redaction-v1"
GENERIC_LABELS = {
    "android",
    "android system",
    "aura",
    "google",
    "settings",
    "phone",
    "contacts",
    "camera",
    "messages",
    "files",
    "calendar",
}

SOURCE_PATH_RE = re.compile(
    r"/(?:data|system|system_ext|product|vendor|odm|apex)[^\s;,:\"']*?\.apk",
    re.IGNORECASE,
)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def stable_hash(value: str, salt: str) -> str:
    return hmac.new(salt.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def source_partition(source_dir: str) -> str:
    lower = source_dir.lower()
    if lower.startswith("/system/priv-app"):
        return "system_priv_app"
    if lower.startswith("/system/app"):
        return "system_app"
    if lower.startswith("/system_ext/priv-app"):
        return "system_ext_priv_app"
    if lower.startswith("/system_ext/app"):
        return "system_ext_app"
    if lower.startswith("/product/priv-app"):
        return "product_priv_app"
    if lower.startswith("/product/app"):
        return "product_app"
    if lower.startswith("/vendor/priv-app"):
        return "vendor_priv_app"
    if lower.startswith("/vendor/app"):
        return "vendor_app"
    if lower.startswith("/odm/priv-app"):
        return "odm_priv_app"
    if lower.startswith("/odm/app"):
        return "odm_app"
    if lower.startswith("/data/app"):
        return "data_app"
    if lower.startswith("/apex/"):
        return "apex"
    return "unknown_partition"


def installer_class(installer: str | None) -> str:
    if not installer:
        return "none_or_unknown"
    lower = installer.lower()
    if lower == "com.android.vending":
        return "google_play"
    if "fdroid" in lower or "f-droid" in lower:
        return "fdroid_like"
    if lower in {"com.android.shell", "shell"}:
        return "adb_or_shell"
    if lower in {"com.android.packageinstaller", "com.google.android.packageinstaller"}:
        return "android_package_installer"
    if "galaxy" in lower or "samsung" in lower:
        return "oem_store_or_installer"
    if lower.startswith("com.google.android."):
        return "google_platform_or_store"
    if lower.startswith("com.android."):
        return "android_platform"
    return "other_redacted"


class RedactionContext:
    def __init__(self, export: dict[str, Any], salt: str) -> None:
        self.salt = salt
        self.package_aliases: dict[str, str] = {}
        self.label_values: set[str] = set()
        self.source_paths: set[str] = set()
        self.digest_aliases: dict[str, str] = {}
        self.installer_aliases: dict[str, str] = {}
        self.evidence_id_aliases: dict[str, str] = {}
        self.finding_id_aliases: dict[str, str] = {}
        self.episode_id_aliases: dict[str, str] = {}
        self._collect(export)

    def _collect(self, export: dict[str, Any]) -> None:
        packages: set[str] = set()
        for assessment in export.get("assessments", []):
            snapshot = assessment.get("snapshot", {})
            self._collect_snapshot(snapshot, packages)
            for evidence in assessment.get("evidence", []):
                self._collect_evidence(evidence)
        for episode in export.get("temporalEpisodes", []):
            if episode.get("packageName"):
                packages.add(str(episode["packageName"]))
            if episode.get("episodeId"):
                self.episode_id_alias(str(episode["episodeId"]))
        for finding in export.get("defensiveSurfaceFindings", []):
            if finding.get("packageName"):
                packages.add(str(finding["packageName"]))
            if finding.get("findingId"):
                self.finding_id_alias(str(finding["findingId"]))
            for evidence in finding.get("evidence", []):
                self._collect_evidence(evidence)
        for posture in export.get("defensivePostures", []):
            if posture.get("packageName"):
                packages.add(str(posture["packageName"]))
            for finding_id in posture.get("findingIds", []):
                self.finding_id_alias(str(finding_id))
        history = export.get("scanHistory") or {}
        for key in (
            "packagesChangedSincePreviousScan",
            "packagesNewInThisScan",
            "packagesRemovedSincePreviousScan",
        ):
            for package_name in history.get(key, []):
                packages.add(str(package_name))
        for item in history.get("packageHistory", []):
            if item.get("packageName"):
                packages.add(str(item["packageName"]))

        for index, package_name in enumerate(sorted(packages), start=1):
            short = stable_hash(package_name, self.salt)[:8]
            self.package_aliases[package_name] = f"app_{index:03d}_{short}"

    def _collect_snapshot(self, snapshot: dict[str, Any], packages: set[str]) -> None:
        if snapshot.get("packageName"):
            packages.add(str(snapshot["packageName"]))
        if snapshot.get("appLabel"):
            label = str(snapshot["appLabel"])
            if label.strip().lower() not in GENERIC_LABELS:
                self.label_values.add(label)
        if snapshot.get("sourceDir"):
            self.source_paths.add(str(snapshot["sourceDir"]))
        if snapshot.get("installerPackageName"):
            installer = str(snapshot["installerPackageName"])
            self.installer_aliases[installer] = installer_class(installer)
        for digest in snapshot.get("signingCertDigestsSha256", []):
            self.digest_alias(str(digest))
        for component in snapshot.get("components", []):
            if component.get("permission"):
                permission = str(component["permission"])
                if permission.count(".") >= 2:
                    packages.add(permission.rsplit(".", 1)[0])
        raw_features = snapshot.get("rawFeatures", {})
        if raw_features.get("foregroundSensitiveAppPackage"):
            packages.add(str(raw_features["foregroundSensitiveAppPackage"]))

    def _collect_evidence(self, evidence: dict[str, Any]) -> None:
        if evidence.get("evidenceId"):
            self.evidence_id_alias(str(evidence["evidenceId"]))
        raw_value = str(evidence.get("rawValue", ""))
        for path in SOURCE_PATH_RE.findall(raw_value):
            self.source_paths.add(path)
        for digest in SHA256_RE.findall(raw_value):
            self.digest_alias(digest)

    def package_alias(self, package_name: str | None) -> str:
        if not package_name:
            return ""
        value = str(package_name)
        return self.package_aliases.get(value, f"app_unknown_{stable_hash(value, self.salt)[:8]}")

    def digest_alias(self, digest: str) -> str:
        lower = digest.lower()
        alias = self.digest_aliases.get(lower)
        if alias is None:
            alias = f"digest_{stable_hash(lower, self.salt)[:16]}"
            self.digest_aliases[lower] = alias
        return alias

    def evidence_id_alias(self, evidence_id: str) -> str:
        alias = self.evidence_id_aliases.get(evidence_id)
        if alias is None:
            alias = f"ev_{stable_hash(evidence_id, self.salt)[:16]}"
            self.evidence_id_aliases[evidence_id] = alias
        return alias

    def finding_id_alias(self, finding_id: str) -> str:
        alias = self.finding_id_aliases.get(finding_id)
        if alias is None:
            alias = f"finding_{stable_hash(finding_id, self.salt)[:16]}"
            self.finding_id_aliases[finding_id] = alias
        return alias

    def episode_id_alias(self, episode_id: str) -> str:
        alias = self.episode_id_aliases.get(episode_id)
        if alias is None:
            alias = f"episode_{stable_hash(episode_id, self.salt)[:16]}"
            self.episode_id_aliases[episode_id] = alias
        return alias

    def source_descriptor(self, source_dir: str | None, fallback_partition: str | None = None) -> str:
        partition = fallback_partition or source_partition(source_dir or "")
        return f"<redacted:{partition}>"

    def sanitize_string(self, value: str) -> str:
        output = value
        for source in sorted(self.source_paths, key=len, reverse=True):
            output = output.replace(source, self.source_descriptor(source))
        output = SOURCE_PATH_RE.sub(lambda match: self.source_descriptor(match.group(0)), output)
        for digest, alias in sorted(self.digest_aliases.items(), key=lambda item: len(item[0]), reverse=True):
            output = output.replace(digest, alias)
            output = output.replace(digest.upper(), alias)
        output = SHA256_RE.sub(lambda match: self.digest_alias(match.group(0)), output)
        for installer, alias in sorted(self.installer_aliases.items(), key=lambda item: len(item[0]), reverse=True):
            output = output.replace(installer, alias)
        for package_name, alias in sorted(self.package_aliases.items(), key=lambda item: len(item[0]), reverse=True):
            if "." in package_name:
                output = output.replace(package_name, alias)
        for label in sorted(self.label_values, key=len, reverse=True):
            if label:
                output = output.replace(label, "<app_label_redacted>")
        return output


def privacy_metadata(mode: str, *, full_inventory: bool, salt_provided: bool) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "mode": mode.upper(),
        "redactionApplied": mode != FULL_RESEARCH,
        "fullInventoryIncluded": full_inventory,
        "packageIdentifierStrategy": "hmac_sha256_alias" if mode != FULL_RESEARCH else "raw",
        "appLabels": "redacted" if mode != FULL_RESEARCH else "raw",
        "sourcePaths": "redacted_to_partition" if mode != FULL_RESEARCH else "raw",
        "signingDigests": "short_hmac_hash" if mode != FULL_RESEARCH else "raw",
        "salt": "provided" if salt_provided else "default_reproducible",
        "notice": "Exports can reveal installed apps and device context; share only with trusted reviewers.",
    }


def summarize_export(export: dict[str, Any]) -> dict[str, Any]:
    decision_counts = Counter(
        assessment.get("decision", {}).get("color", "UNKNOWN")
        for assessment in export.get("assessments", [])
    )
    posture_counts = Counter(
        posture.get("postureClass", "UNKNOWN")
        for posture in export.get("defensivePostures", [])
    )
    return {
        "assessedAppCount": len(export.get("assessments", [])),
        "decisionCounts": dict(sorted(decision_counts.items())),
        "defensivePostureCounts": dict(sorted(posture_counts.items())),
        "temporalEpisodeCount": len(export.get("temporalEpisodes", [])),
        "defensiveFindingCount": len(export.get("defensiveSurfaceFindings", [])),
        "retainedScanCount": (export.get("scanHistory") or {}).get("retainedScanCount"),
        "retainedPackageCount": (export.get("scanHistory") or {}).get("retainedPackageCount"),
    }


def sanitize_tree(value: Any, context: RedactionContext) -> Any:
    if isinstance(value, dict):
        return {key: sanitize_tree(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_tree(item, context) for item in value]
    if isinstance(value, str):
        return context.sanitize_string(value)
    return value


def redact_evidence(evidence: dict[str, Any], context: RedactionContext) -> dict[str, Any]:
    redacted = sanitize_tree(evidence, context)
    original_id = evidence.get("evidenceId")
    if original_id:
        redacted["evidenceId"] = context.evidence_id_alias(str(original_id))
    raw_value = str(evidence.get("rawValue", ""))
    source = str(evidence.get("source", ""))
    if source == "MANIFEST_COMPONENT" or "component:" in raw_value or "activity:" in raw_value:
        redacted["rawValue"] = "<redacted_component_metadata>"
    return redacted


def redact_component(component: dict[str, Any], index: int, context: RedactionContext) -> dict[str, Any]:
    component_type = str(component.get("type", "component"))
    redacted = sanitize_tree(component, context)
    redacted["name"] = f"{component_type}_{index:03d}"
    return redacted


def redact_snapshot(snapshot: dict[str, Any], context: RedactionContext) -> dict[str, Any]:
    redacted = sanitize_tree(snapshot, context)
    package_name = str(snapshot.get("packageName", ""))
    alias = context.package_alias(package_name)
    raw_features = dict(snapshot.get("rawFeatures", {}))
    partition = str(raw_features.get("sourcePartition") or source_partition(str(snapshot.get("sourceDir", ""))))

    redacted["packageName"] = alias
    redacted["appLabel"] = f"Redacted app {alias}"
    redacted["versionName"] = "<redacted>"
    redacted["uid"] = -1
    redacted["installerPackageName"] = installer_class(snapshot.get("installerPackageName"))
    redacted["sourceDir"] = context.source_descriptor(snapshot.get("sourceDir"), partition)
    redacted["signingCertDigestsSha256"] = [
        context.digest_alias(str(digest)) for digest in snapshot.get("signingCertDigestsSha256", [])
    ]
    redacted["components"] = [
        redact_component(component, index, context)
        for index, component in enumerate(snapshot.get("components", []), start=1)
    ]

    redacted_raw_features = sanitize_tree(raw_features, context)
    if raw_features.get("foregroundSensitiveAppPackage"):
        redacted_raw_features["foregroundSensitiveAppPackage"] = context.package_alias(
            str(raw_features["foregroundSensitiveAppPackage"])
        )
    redacted["rawFeatures"] = redacted_raw_features
    return redacted


def redact_assessment(assessment: dict[str, Any], context: RedactionContext) -> dict[str, Any]:
    redacted = sanitize_tree(assessment, context)
    redacted["snapshot"] = redact_snapshot(assessment.get("snapshot", {}), context)
    redacted["evidence"] = [
        redact_evidence(evidence, context) for evidence in assessment.get("evidence", [])
    ]
    redacted["evidenceGraph"] = redact_evidence_graph(assessment.get("evidenceGraph", {}), context)
    return redacted


def redact_evidence_graph(graph: dict[str, Any], context: RedactionContext) -> dict[str, Any]:
    redacted = sanitize_tree(graph, context)
    for node in redacted.get("nodes", []):
        node_id = node.get("nodeId")
        if isinstance(node_id, str) and node_id.startswith("app:"):
            original = node_id.split(":", 1)[1]
            node["nodeId"] = f"app:{context.package_alias(original)}"
        if node.get("type") == "APP":
            node["label"] = "<app_label_redacted>"
    for edge in redacted.get("edges", []):
        evidence_id = edge.get("evidenceId")
        if evidence_id:
            edge["evidenceId"] = context.evidence_id_alias(str(evidence_id))
        for key in ("from", "to"):
            value = edge.get(key)
            if isinstance(value, str) and value.startswith("app:"):
                edge[key] = f"app:{context.package_alias(value.split(':', 1)[1])}"
    return redacted


def redact_episode(episode: dict[str, Any], context: RedactionContext) -> dict[str, Any]:
    redacted = sanitize_tree(episode, context)
    if episode.get("packageName"):
        redacted["packageName"] = context.package_alias(str(episode["packageName"]))
    if episode.get("episodeId"):
        redacted["episodeId"] = context.episode_id_alias(str(episode["episodeId"]))
    if episode.get("supportingEvidenceIds"):
        redacted["supportingEvidenceIds"] = [
            context.evidence_id_alias(str(item)) for item in episode.get("supportingEvidenceIds", [])
        ]
    return redacted


def redact_finding(finding: dict[str, Any], context: RedactionContext) -> dict[str, Any]:
    redacted = sanitize_tree(finding, context)
    if finding.get("packageName"):
        redacted["packageName"] = context.package_alias(str(finding["packageName"]))
    if finding.get("findingId"):
        redacted["findingId"] = context.finding_id_alias(str(finding["findingId"]))
    redacted["evidence"] = [
        redact_evidence(evidence, context) for evidence in finding.get("evidence", [])
    ]
    return redacted


def redact_posture(posture: dict[str, Any], context: RedactionContext) -> dict[str, Any]:
    redacted = sanitize_tree(posture, context)
    if posture.get("packageName"):
        redacted["packageName"] = context.package_alias(str(posture["packageName"]))
    if posture.get("findingIds"):
        redacted["findingIds"] = [
            context.finding_id_alias(str(finding_id)) for finding_id in posture.get("findingIds", [])
        ]
    return redacted


def redact_scan_history(history: dict[str, Any], context: RedactionContext, *, minimal: bool) -> dict[str, Any]:
    redacted = sanitize_tree(history, context)
    if minimal:
        return {
            "schemaVersion": history.get("schemaVersion", 1),
            "retainedScanCount": history.get("retainedScanCount"),
            "retainedPackageCount": history.get("retainedPackageCount"),
            "scans": history.get("scans", []),
            "packagesChangedSincePreviousScanCount": len(history.get("packagesChangedSincePreviousScan", [])),
            "packagesNewInThisScanCount": len(history.get("packagesNewInThisScan", [])),
            "packagesRemovedSincePreviousScanCount": len(history.get("packagesRemovedSincePreviousScan", [])),
        }
    for key in (
        "packagesChangedSincePreviousScan",
        "packagesNewInThisScan",
        "packagesRemovedSincePreviousScan",
    ):
        redacted[key] = [context.package_alias(str(item)) for item in history.get(key, [])]
    if history.get("packageHistory"):
        redacted["packageHistory"] = [
            {**sanitize_tree(item, context), "packageName": context.package_alias(str(item.get("packageName", "")))}
            for item in history.get("packageHistory", [])
        ]
    return redacted


def redacted_expert_export(
    export: dict[str, Any],
    context: RedactionContext,
    *,
    salt_provided: bool,
) -> dict[str, Any]:
    redacted = sanitize_tree(export, context)
    redacted["privacy"] = privacy_metadata(REDACTED_EXPERT, full_inventory=True, salt_provided=salt_provided)
    redacted["summary"] = summarize_export(export)
    redacted["assessments"] = [
        redact_assessment(assessment, context) for assessment in export.get("assessments", [])
    ]
    redacted["temporalEpisodes"] = [
        redact_episode(episode, context) for episode in export.get("temporalEpisodes", [])
    ]
    redacted["defensiveSurfaceFindings"] = [
        redact_finding(finding, context) for finding in export.get("defensiveSurfaceFindings", [])
    ]
    redacted["defensivePostures"] = [
        redact_posture(posture, context) for posture in export.get("defensivePostures", [])
    ]
    if export.get("scanHistory"):
        redacted["scanHistory"] = redact_scan_history(export["scanHistory"], context, minimal=False)
    return redacted


def priority_score(assessment: dict[str, Any], posture: dict[str, Any] | None) -> tuple[int, float]:
    color_order = {"RED": 0, "YELLOW": 1, "BLUE": 2, "GRAY": 3, "GREEN": 4}
    color = assessment.get("decision", {}).get("color", "GREEN")
    risk = assessment.get("riskVector", {})
    posture_bonus = 0.2 if posture and posture.get("postureClass") != "NO_OBSERVED_WEAKNESS" else 0.0
    try:
        risk_score = float(risk.get("abuseEvidence", 0)) + float(risk.get("harm", 0)) + posture_bonus
    except (TypeError, ValueError):
        risk_score = posture_bonus
    return (color_order.get(color, 5), -risk_score)


def minimal_support_export(
    export: dict[str, Any],
    context: RedactionContext,
    *,
    salt_provided: bool,
    max_assessments: int = 12,
) -> dict[str, Any]:
    full = redacted_expert_export(export, context, salt_provided=salt_provided)
    postures_by_package = {
        posture.get("packageName"): posture for posture in full.get("defensivePostures", [])
    }
    priority = [
        assessment
        for assessment in full.get("assessments", [])
        if assessment.get("decision", {}).get("color") in {"RED", "YELLOW", "BLUE", "GRAY"}
        or postures_by_package.get(assessment.get("snapshot", {}).get("packageName"), {}).get("postureClass")
        in {"WEAK_DEFENSIVE_SURFACE", "REVIEW_RECOMMENDED"}
    ]
    priority = sorted(
        priority,
        key=lambda item: priority_score(
            item,
            postures_by_package.get(item.get("snapshot", {}).get("packageName")),
        ),
    )[:max_assessments]
    priority_packages = {
        assessment.get("snapshot", {}).get("packageName")
        for assessment in priority
        if assessment.get("snapshot", {}).get("packageName")
    }
    minimal = {
        "schemaVersion": full.get("schemaVersion"),
        "scanId": full.get("scanId"),
        "generatedAt": full.get("generatedAt"),
        "flavor": full.get("flavor"),
        "privacy": privacy_metadata(MINIMAL_SUPPORT, full_inventory=False, salt_provided=salt_provided),
        "summary": {
            **summarize_export(export),
            "includedAssessmentCount": len(priority),
            "inventoryScope": "priority_only",
        },
        "assessments": priority,
        "temporalEpisodes": [
            episode
            for episode in full.get("temporalEpisodes", [])
            if episode.get("packageName") in priority_packages
        ],
        "defensiveSurfaceFindings": [
            finding
            for finding in full.get("defensiveSurfaceFindings", [])
            if finding.get("packageName") in priority_packages
        ],
        "defensivePostures": [
            posture
            for posture in full.get("defensivePostures", [])
            if posture.get("packageName") in priority_packages
            and posture.get("postureClass") != "NO_OBSERVED_WEAKNESS"
        ],
    }
    if full.get("scanHistory"):
        minimal["scanHistory"] = redact_scan_history(export.get("scanHistory", {}), context, minimal=True)
    return minimal


def redact_export(
    export: dict[str, Any],
    *,
    mode: str,
    salt: str = DEFAULT_SALT,
    max_minimal_assessments: int = 12,
    salt_provided: bool = False,
) -> dict[str, Any]:
    if mode not in PRIVACY_MODES:
        raise ValueError(f"Unsupported privacy mode: {mode}")
    if mode == FULL_RESEARCH:
        output = copy.deepcopy(export)
        output["privacy"] = privacy_metadata(FULL_RESEARCH, full_inventory=True, salt_provided=salt_provided)
        output.setdefault("summary", summarize_export(export))
        return output
    context = RedactionContext(export, salt=salt)
    if mode == REDACTED_EXPERT:
        return redacted_expert_export(export, context, salt_provided=salt_provided)
    return minimal_support_export(
        export,
        context,
        salt_provided=salt_provided,
        max_assessments=max_minimal_assessments,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="AURA scan export JSON")
    parser.add_argument("--mode", choices=PRIVACY_MODES, default=REDACTED_EXPERT)
    parser.add_argument("--salt", default=DEFAULT_SALT, help="Project/customer-specific redaction salt")
    parser.add_argument("--out", type=Path, required=True, help="Output JSON path")
    parser.add_argument("--max-minimal-assessments", type=int, default=12)
    args = parser.parse_args()

    export = load_json(args.export)
    redacted = redact_export(
        export,
        mode=args.mode,
        salt=args.salt,
        max_minimal_assessments=args.max_minimal_assessments,
        salt_provided=args.salt != DEFAULT_SALT,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(redacted, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {args.mode} export to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
