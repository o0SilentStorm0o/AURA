#!/usr/bin/env python3
"""Release-risk audit engine for app-owner AURA reports.

This engine is deliberately separate from AURA's user/device threat decision.
It turns on-device defensive findings and offline APK analyzer observations into
developer-facing release-risk findings with stable fingerprints, remediation,
and retest semantics.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


AUDIT_ENGINE_VERSION = "aura-app-owner-audit-0.1.0"
PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "INFO": 3}
SURFACE_PREFIXES = ("activity:", "service:", "receiver:", "provider:")
TYPE_LEVEL_FINDINGS = {
    "BACKUP_MAY_INCLUDE_SENSITIVE_DATA",
    "CLEARTEXT_TRAFFIC_ALLOWED",
    "DEBUGGABLE_OR_TEST_CONFIG_IN_RELEASE",
    "WEBVIEW_RISKY_CONFIGURATION",
    "SENSITIVE_SCREEN_NOT_PROTECTED",
    "MISSING_TAPJACKING_DEFENSE_ON_SENSITIVE_ACTION",
    "SENSITIVE_UI_ACCESSIBILITY_EXPOSURE_REVIEW",
    "SDK_OR_TARGET_API_POLICY_RISK",
    "SECRETS_OR_ENDPOINTS_IN_APK",
    "THIRD_PARTY_SDK_PRIVACY_SURFACE",
    "DANGEROUS_INTENT_SURFACE_NEEDS_MANUAL_REVIEW",
}


@dataclass(frozen=True)
class AuditDefinition:
    title: str
    default_priority: str
    owner: str
    requires_manual_review: bool
    why_it_matters: str
    how_to_fix: str
    how_to_verify: str


DEFINITIONS: dict[str, AuditDefinition] = {
    "EXPORTED_COMPONENT_WITHOUT_GUARD": AuditDefinition(
        "Exported component without permission guard",
        "P1",
        "Android team",
        True,
        "Other apps may be able to call this component. Exploitability depends on component logic, so AURA routes it to manual review instead of claiming proof of exploit.",
        "Set exported=false when external access is not required. Otherwise protect the component with an appropriate permission or signature permission and validate all inbound intents, paths, and extras.",
        "Rebuild and rerun AURA. The finding is fixed when the component is non-exported or has an appropriate manifest permission guard.",
    ),
    "DEEPLINK_ACCEPTS_UNTRUSTED_INPUT": AuditDefinition(
        "Deep link or app link accepts external input",
        "P2",
        "Android team",
        True,
        "Browsable links are entry points from browsers and other apps. They frequently carry redirect, token, callback, payment, or routing data that must be validated.",
        "Constrain schemes, hosts, and paths; prefer verified app links for public domains; validate all parameters; reject unexpected callers and states.",
        "Rerun AURA and manually test representative links. The finding is resolved when the exposed link surface is intentionally constrained or documented as accepted risk.",
    ),
    "BACKUP_MAY_INCLUDE_SENSITIVE_DATA": AuditDefinition(
        "Backup or data extraction may include sensitive data",
        "P2",
        "Android team",
        True,
        "Android backup and device-transfer paths can persist tokens, user state, or regulated data if rules are not explicit.",
        "Disable backup for sensitive apps or define fullBackupContent/dataExtractionRules that exclude secrets, auth state, caches, and regulated data.",
        "Rerun AURA against the release build. The finding is fixed when backup is disabled or explicit rules are observed and reviewed.",
    ),
    "CLEARTEXT_TRAFFIC_ALLOWED": AuditDefinition(
        "Cleartext traffic is allowed",
        "P2",
        "Android team",
        False,
        "Cleartext allowance can expose traffic to downgrade, interception, or accidental non-TLS endpoints depending on runtime code paths.",
        "Set usesCleartextTraffic=false for release builds and remove broad cleartextTrafficPermitted=true rules unless a tightly scoped exception is documented.",
        "Rerun AURA/offline analyzer. The finding is fixed when cleartext is disabled or narrowly scoped to an approved non-sensitive endpoint.",
    ),
    "DEBUGGABLE_OR_TEST_CONFIG_IN_RELEASE": AuditDefinition(
        "Debuggable or test configuration in release candidate",
        "P1",
        "Build/release owner",
        False,
        "Debuggable release candidates can expose debug tooling, alter runtime behavior, and fail enterprise/security review expectations.",
        "Ensure the distributed APK/AAB is built from the release variant with debuggable=false and no test-only config.",
        "Analyze the exact release artifact. The finding is fixed when debuggable=false is observed in the final build.",
    ),
    "WEBVIEW_RISKY_CONFIGURATION": AuditDefinition(
        "WebView configuration needs security review",
        "P2",
        "Android team",
        True,
        "WebView settings such as JavaScript bridges, file access, universal file URL access, or mixed content can become high-impact when combined with untrusted content.",
        "Review loaded origins, disable unnecessary risky settings, avoid exposing broad JavaScript bridges, and validate all URL loading decisions.",
        "Rerun static analysis and perform manual WebView tests. The finding is fixed or downgraded when risky settings are removed or documented with origin restrictions.",
    ),
    "SENSITIVE_SCREEN_NOT_PROTECTED": AuditDefinition(
        "Sensitive screen protection not observed",
        "P3",
        "Android team",
        True,
        "Static analysis did not observe screenshot/screen-sharing hardening for a sensitive app. This is a low-confidence absence signal, not runtime proof.",
        "Review sensitive flows and apply FLAG_SECURE where screenshot, recents, and screen-sharing exposure is unacceptable.",
        "Verify in source/runtime UI tests and rerun AURA. Absence findings should be closed only after manual validation.",
    ),
    "MISSING_TAPJACKING_DEFENSE_ON_SENSITIVE_ACTION": AuditDefinition(
        "Tapjacking defense not observed on sensitive action",
        "P3",
        "Android team",
        True,
        "Static analysis did not observe obscured-touch filtering for sensitive actions. This may be acceptable for some screens but deserves manual review.",
        "Apply filterTouchesWhenObscured or equivalent handling on sensitive click targets where overlay manipulation would be harmful.",
        "Verify with source review or UI tests and rerun AURA/offline analyzer.",
    ),
    "SENSITIVE_UI_ACCESSIBILITY_EXPOSURE_REVIEW": AuditDefinition(
        "Sensitive UI accessibility exposure needs review",
        "P3",
        "Android team",
        True,
        "Static analysis did not observe accessibilityDataSensitive-style protection for sensitive UI. This is API/version dependent.",
        "Review sensitive views and apply accessibilityDataSensitive or equivalent privacy controls where appropriate.",
        "Verify on the supported Android API range and rerun static checks.",
    ),
    "SDK_OR_TARGET_API_POLICY_RISK": AuditDefinition(
        "Target SDK or platform policy risk",
        "P2",
        "Release owner",
        False,
        "Older target SDK levels may miss newer Android security defaults and can trigger platform or store policy concerns.",
        "Update targetSdkVersion to the current release policy target and retest behavior changes.",
        "Analyze the release artifact. The finding is fixed when targetSdkVersion meets the chosen release policy.",
    ),
    "SECRETS_OR_ENDPOINTS_IN_APK": AuditDefinition(
        "Embedded secret or endpoint configuration needs review",
        "P2",
        "Security reviewer",
        True,
        "APK resources often contain public identifiers, endpoints, and sometimes real secrets. AURA flags secret-like patterns for classification, not as automatic leaks.",
        "Classify each value. Move true secrets server-side or rotate them; restrict public API keys by package/signing certificate/domain where possible.",
        "Rerun static analysis. The finding is fixed when sensitive credentials are removed or documented as public/restricted identifiers.",
    ),
    "THIRD_PARTY_SDK_PRIVACY_SURFACE": AuditDefinition(
        "Third-party SDK privacy surface",
        "INFO",
        "Product/security reviewer",
        True,
        "Third-party SDKs may affect privacy disclosures, data-safety forms, consent flows, and enterprise customer review.",
        "Review detected SDKs against privacy disclosures, consent requirements, data processing agreements, and actual app functionality.",
        "Rerun static analysis and review release notes when SDKs are added, removed, or updated.",
    ),
    "DANGEROUS_INTENT_SURFACE_NEEDS_MANUAL_REVIEW": AuditDefinition(
        "Intent/component surface needs manual review",
        "P2",
        "Android team",
        True,
        "AURA observed an externally reachable Android surface but cannot prove safety without understanding app logic.",
        "Review caller validation, intent extras, URI handling, permissions, and state-changing behavior.",
        "Close the finding only after source review or by constraining the manifest surface and rerunning AURA.",
    ),
}


TYPE_MAP = {
    "UNPROTECTED_EXPORTED_COMPONENT": "EXPORTED_COMPONENT_WITHOUT_GUARD",
    "BACKUP_ALLOWED": "BACKUP_MAY_INCLUDE_SENSITIVE_DATA",
    "BACKUP_ALLOWED_SENSITIVE_APP": "BACKUP_MAY_INCLUDE_SENSITIVE_DATA",
    "BACKUP_ALLOWED_WITHOUT_EXPLICIT_RULES": "BACKUP_MAY_INCLUDE_SENSITIVE_DATA",
    "CLEARTEXT_TRAFFIC_ALLOWED": "CLEARTEXT_TRAFFIC_ALLOWED",
    "CLEARTEXT_TRAFFIC_ALLOWED_MANIFEST": "CLEARTEXT_TRAFFIC_ALLOWED",
    "NETWORK_SECURITY_CONFIG_CLEARTEXT_PERMITTED": "CLEARTEXT_TRAFFIC_ALLOWED",
    "NETWORK_SECURITY_CONFIG_DEBUG_OVERRIDES": "CLEARTEXT_TRAFFIC_ALLOWED",
    "NETWORK_SECURITY_CONFIG_USER_CA_TRUST": "CLEARTEXT_TRAFFIC_ALLOWED",
    "DEBUGGABLE_SENSITIVE_APP": "DEBUGGABLE_OR_TEST_CONFIG_IN_RELEASE",
    "DEBUGGABLE_ENABLED": "DEBUGGABLE_OR_TEST_CONFIG_IN_RELEASE",
    "DEEPLINK_SURFACE_NEEDS_MANUAL_REVIEW": "DEEPLINK_ACCEPTS_UNTRUSTED_INPUT",
    "WEBVIEW_JAVASCRIPT_INTERFACE": "WEBVIEW_RISKY_CONFIGURATION",
    "WEBVIEW_RISKY_CONFIGURATION": "WEBVIEW_RISKY_CONFIGURATION",
    "FLAG_SECURE_NOT_OBSERVED_SENSITIVE_APP": "SENSITIVE_SCREEN_NOT_PROTECTED",
    "FILTER_TOUCHES_WHEN_OBSCURED_NOT_OBSERVED_SENSITIVE_APP": "MISSING_TAPJACKING_DEFENSE_ON_SENSITIVE_ACTION",
    "ACCESSIBILITY_DATA_SENSITIVE_NOT_OBSERVED": "SENSITIVE_UI_ACCESSIBILITY_EXPOSURE_REVIEW",
    "SDK_OR_TARGET_API_POLICY_RISK": "SDK_OR_TARGET_API_POLICY_RISK",
    "EMBEDDED_SECRET_OR_ENDPOINT_REVIEW": "SECRETS_OR_ENDPOINTS_IN_APK",
    "THIRD_PARTY_SDK_PRIVACY_SURFACE": "THIRD_PARTY_SDK_PRIVACY_SURFACE",
}


def normalize_type(finding_type: str | None) -> str:
    return TYPE_MAP.get(str(finding_type), "DANGEROUS_INTENT_SURFACE_NEEDS_MANUAL_REVIEW")


def offline_apk_for_package(offline_analysis: dict[str, Any] | None, target_package: str) -> dict[str, Any] | None:
    if not offline_analysis:
        return None
    if isinstance(offline_analysis.get("apks"), list):
        for apk in offline_analysis["apks"]:
            if (apk.get("apk") or {}).get("packageName") == target_package:
                return apk
        return None
    if "apk" in offline_analysis and (offline_analysis.get("apk") or {}).get("packageName") == target_package:
        return offline_analysis
    return None


def package_name(assessment: dict[str, Any]) -> str:
    return str((assessment.get("snapshot") or {}).get("packageName") or "")


def raw_evidence_key(finding: dict[str, Any]) -> str:
    raw = str(finding.get("rawValue") or "")
    if not raw and isinstance(finding.get("evidence"), list):
        raw_values = [
            str(item.get("rawValue") or item.get("humanExplanation") or "")
            for item in finding["evidence"]
            if item.get("rawValue") or item.get("humanExplanation")
        ]
        raw = ";".join(raw_values)
    if not raw:
        raw = str(finding.get("humanExplanation") or finding.get("explanation") or "")
    if not raw:
        raw = str(finding.get("findingId") or finding.get("findingType") or "")
    return raw


def fingerprint(package_name_value: str, normalized_type: str, evidence_key: str) -> str:
    seed = f"{package_name_value}:{normalized_type}:{evidence_key}"
    return hashlib.sha256(seed.encode()).hexdigest()[:24]


def surface_count(raw_value: str) -> int:
    lower = raw_value.lower()
    return sum(lower.count(prefix) for prefix in SURFACE_PREFIXES)


def evidence_specificity(normalized_type: str, raw_value: str, source: str) -> str:
    if normalized_type in TYPE_LEVEL_FINDINGS:
        return "aggregate"
    if source == "ON_DEVICE" and surface_count(raw_value) > 1:
        return "aggregate"
    if surface_count(raw_value) == 1:
        return "specific"
    if normalized_type in {"EXPORTED_COMPONENT_WITHOUT_GUARD", "DEEPLINK_ACCEPTS_UNTRUSTED_INPUT"}:
        return "specific"
    return "aggregate"


def evidence_subject(normalized_type: str, raw_value: str, specificity: str) -> str:
    if specificity == "aggregate":
        return normalized_type
    return " ".join(raw_value.split()).lower()


def component_kind(raw_value: str) -> str | None:
    lower = raw_value.lower().strip()
    for prefix in SURFACE_PREFIXES:
        if lower.startswith(prefix):
            return prefix[:-1]
    return None


def finding_title(normalized_type: str, default_title: str, evidence_key: str) -> str:
    if normalized_type == "EXPORTED_COMPONENT_WITHOUT_GUARD":
        kind = component_kind(evidence_key)
        if kind:
            return f"Exported {kind} without permission guard"
    return default_title


def acceptance_criteria(normalized_type: str, evidence_key: str) -> str:
    kind = component_kind(evidence_key)
    if normalized_type == "EXPORTED_COMPONENT_WITHOUT_GUARD" and kind:
        return f"The {kind} is either `exported=false` or protected by an appropriate manifest permission; inbound data is validated in code."
    criteria = {
        "EXPORTED_COMPONENT_WITHOUT_GUARD": "Each externally reachable component is intentionally exposed and protected by an appropriate manifest permission or source-reviewed caller validation.",
        "DEEPLINK_ACCEPTS_UNTRUSTED_INPUT": "Allowed schemes, hosts, paths, and parameters are constrained; redirect, token, payment, and callback flows have documented validation.",
        "BACKUP_MAY_INCLUDE_SENSITIVE_DATA": "Backup is disabled for sensitive apps or explicit backup/data-extraction rules exclude secrets, auth state, caches, and regulated data.",
        "CLEARTEXT_TRAFFIC_ALLOWED": "The release artifact does not broadly allow cleartext traffic; any exception is narrowly scoped and documented.",
        "DEBUGGABLE_OR_TEST_CONFIG_IN_RELEASE": "The exact release artifact has `debuggable=false` and contains no test-only build configuration.",
        "WEBVIEW_RISKY_CONFIGURATION": "Risky WebView settings are removed or restricted to trusted origins with documented URL-loading and bridge validation.",
        "SENSITIVE_SCREEN_NOT_PROTECTED": "Sensitive screens are reviewed and screenshot/screen-sharing exposure is either protected or explicitly accepted.",
        "MISSING_TAPJACKING_DEFENSE_ON_SENSITIVE_ACTION": "Sensitive actions are reviewed for obscured-touch handling; required controls are implemented or accepted as documented risk.",
        "SENSITIVE_UI_ACCESSIBILITY_EXPOSURE_REVIEW": "Sensitive views are reviewed on supported API levels and protected where accessibility exposure is not intended.",
        "SDK_OR_TARGET_API_POLICY_RISK": "Target SDK and platform policy level match the planned release channel.",
        "SECRETS_OR_ENDPOINTS_IN_APK": "All embedded keys/endpoints are classified; true secrets are removed or rotated and public keys are restricted where possible.",
        "THIRD_PARTY_SDK_PRIVACY_SURFACE": "Detected SDKs are reconciled with privacy disclosures, consent flows, and data-processing obligations.",
        "DANGEROUS_INTENT_SURFACE_NEEDS_MANUAL_REVIEW": "Externally reachable intent surfaces have caller validation, input validation, and documented expected behavior.",
    }
    return criteria.get(normalized_type, "The release owner has reviewed the finding and documented the fix or accepted risk.")


def verification_check(normalized_type: str, evidence_key: str) -> str:
    generic = "Run `python3 tools/apk_analyzer/analyze_apk.py <release.apk> --out <analysis.json>` and regenerate the app-owner report; this finding fingerprint should disappear or move to accepted manual review."
    checks = {
        "EXPORTED_COMPONENT_WITHOUT_GUARD": "Re-run the offline APK analyzer on the rebuilt APK. The component should no longer appear as an unprotected exported component.",
        "BACKUP_MAY_INCLUDE_SENSITIVE_DATA": "Re-run the offline APK analyzer. Confirm backup is disabled or explicit backup/data-extraction rules are present and reviewed.",
        "CLEARTEXT_TRAFFIC_ALLOWED": "Re-run the offline APK analyzer. Confirm manifest and network security config no longer broadly permit cleartext traffic.",
        "DEBUGGABLE_OR_TEST_CONFIG_IN_RELEASE": "Analyze the exact release APK/AAB-derived artifact. Confirm `android:debuggable=false`.",
        "WEBVIEW_RISKY_CONFIGURATION": "Re-run static analysis and pair it with source review for WebView origin, bridge, and URL-loading restrictions.",
        "SDK_OR_TARGET_API_POLICY_RISK": "Analyze the release artifact and confirm targetSdkVersion matches the release policy target.",
    }
    return checks.get(normalized_type, generic)


def priority_for(normalized_type: str, source_severity: str | None) -> str:
    default = DEFINITIONS[normalized_type].default_priority
    severity = str(source_severity or "").upper()
    if normalized_type == "EXPORTED_COMPONENT_WITHOUT_GUARD" and severity == "MEDIUM":
        return "P2"
    if normalized_type == "BACKUP_MAY_INCLUDE_SENSITIVE_DATA" and severity == "LOW":
        return "P3"
    if normalized_type == "CLEARTEXT_TRAFFIC_ALLOWED" and severity == "LOW":
        return "P3"
    return default


def audit_finding_from_source(
    *,
    package_name_value: str,
    source: str,
    source_finding: dict[str, Any],
) -> dict[str, Any]:
    normalized = normalize_type(source_finding.get("findingType"))
    definition = DEFINITIONS[normalized]
    evidence_key = raw_evidence_key(source_finding)
    specificity = evidence_specificity(normalized, evidence_key, source)
    subject = evidence_subject(normalized, evidence_key, specificity)
    priority = priority_for(normalized, source_finding.get("severity"))
    item_fingerprint = fingerprint(package_name_value, normalized, subject)
    return {
        "id": f"AURA-REL-{item_fingerprint[:8].upper()}",
        "type": normalized,
        "title": finding_title(normalized, definition.title, evidence_key),
        "priority": priority,
        "confidence": float(source_finding.get("confidence") or 0.0),
        "evidence": {
            "source": source,
            "sourceFindingType": source_finding.get("findingType"),
            "sourceFindingId": source_finding.get("findingId"),
            "observabilityState": source_finding.get("observabilityState"),
            "rawValue": source_finding.get("rawValue") or source_finding.get("humanExplanation") or source_finding.get("explanation"),
        },
        "evidenceSubject": subject,
        "sourceSpecificity": specificity,
        "whyItMatters": definition.why_it_matters,
        "howToFix": definition.how_to_fix,
        "howToVerify": definition.how_to_verify,
        "acceptanceCriteria": acceptance_criteria(normalized, evidence_key),
        "verificationCheck": verification_check(normalized, evidence_key),
        "owner": definition.owner,
        "requiresManualReview": definition.requires_manual_review,
        "fingerprint": item_fingerprint,
    }


def suppress_superseded_aggregate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prefer precise offline APK findings over broad on-device summaries.

    On-device metadata is still valuable, but in app-owner mode the offline APK
    analyzer often knows the exact component or XML file. When both sources
    describe the same release-risk type, the broad on-device item is kept only
    as additional evidence instead of becoming a separate customer-facing task.
    """

    offline_types = {
        finding["type"]
        for finding in findings
        if (finding.get("evidence") or {}).get("source") == "OFFLINE_APK_ANALYZER"
    }
    suppressed_by_type: dict[str, list[dict[str, Any]]] = {}
    filtered: list[dict[str, Any]] = []
    for finding in findings:
        evidence = finding.get("evidence") or {}
        should_suppress = (
            evidence.get("source") == "ON_DEVICE"
            and finding.get("sourceSpecificity") == "aggregate"
            and finding.get("type") in offline_types
        )
        if should_suppress:
            suppressed_by_type.setdefault(finding["type"], []).append(evidence)
            continue
        filtered.append(finding)

    attached: set[str] = set()
    for finding in filtered:
        finding_type = finding.get("type")
        if (
            finding_type in suppressed_by_type
            and (finding.get("evidence") or {}).get("source") == "OFFLINE_APK_ANALYZER"
            and finding_type not in attached
        ):
            finding.setdefault("additionalEvidence", []).extend(suppressed_by_type[finding_type])
            attached.add(finding_type)
    return filtered


def merge_duplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for finding in suppress_superseded_aggregate_findings(findings):
        key = finding["fingerprint"]
        if key not in merged:
            merged[key] = finding
            continue
        current = merged[key]
        current["confidence"] = max(float(current.get("confidence") or 0.0), float(finding.get("confidence") or 0.0))
        current.setdefault("additionalEvidence", []).append(finding["evidence"])
    return sorted(
        merged.values(),
        key=finding_sort_key,
    )


def finding_sort_key(item: dict[str, Any]) -> tuple[int, str, str]:
    return (
        PRIORITY_ORDER.get(item.get("priority", "INFO"), 9),
        item.get("type", ""),
        item.get("fingerprint", ""),
    )


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=finding_sort_key)


def release_status(priority_counts: Counter[str]) -> dict[str, Any]:
    p1 = priority_counts.get("P1", 0)
    p2 = priority_counts.get("P2", 0)
    p3 = priority_counts.get("P3", 0)
    if p1:
        status = "BLOCKED"
        production = False
        beta = False
        reason = f"{p1} blocker finding(s) remain."
    elif p2:
        status = "NEEDS_FIXES"
        production = False
        beta = True
        reason = f"{p2} should-fix finding(s) remain before production."
    elif p3:
        status = "REVIEW_RECOMMENDED"
        production = True
        beta = True
        reason = f"{p3} review finding(s) remain."
    else:
        status = "PASS"
        production = True
        beta = True
        reason = "No release-risk findings were generated from supplied evidence."
    return {
        "status": status,
        "readyForExternalBeta": beta,
        "readyForProduction": production,
        "retestRecommended": bool(p1 or p2 or p3),
        "reason": reason,
    }


def build_audit(
    export: dict[str, Any],
    *,
    offline_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    assessments = export.get("assessments") or []
    if not assessments:
        raise ValueError("App-owner audit requires at least one scoped assessment")
    assessment = assessments[0]
    target_package = package_name(assessment)
    on_device = [
        finding for finding in export.get("defensiveSurfaceFindings", [])
        if finding.get("packageName") == target_package
    ]
    offline_apk = offline_apk_for_package(offline_analysis, target_package)
    raw_findings: list[dict[str, Any]] = []
    raw_findings.extend(
        audit_finding_from_source(
            package_name_value=target_package,
            source="ON_DEVICE",
            source_finding=finding,
        )
        for finding in on_device
    )
    if offline_apk:
        raw_findings.extend(
            audit_finding_from_source(
                package_name_value=target_package,
                source="OFFLINE_APK_ANALYZER",
                source_finding=finding,
            )
            for finding in offline_apk.get("findings", [])
        )
    findings = merge_duplicate_findings(raw_findings)
    counts = Counter(finding["priority"] for finding in findings)
    return {
        "schemaVersion": 1,
        "auditEngineVersion": AUDIT_ENGINE_VERSION,
        "targetPackage": target_package,
        "releaseStatus": release_status(counts),
        "priorityCounts": {
            "P1": counts.get("P1", 0),
            "P2": counts.get("P2", 0),
            "P3": counts.get("P3", 0),
            "INFO": counts.get("INFO", 0),
        },
        "findings": findings,
        "threatContext": {
            "decision": (assessment.get("decision") or {}).get("color"),
            "title": (assessment.get("decision") or {}).get("title"),
            "role": (assessment.get("role") or {}).get("predicted"),
            "provenance": (assessment.get("provenance") or {}).get("provenanceClass"),
        },
    }


def compare_audits(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    if previous is None:
        return {
            "available": False,
            "fixed": [],
            "remaining": [],
            "new": [],
        }
    previous_by_fp = {finding["fingerprint"]: finding for finding in previous.get("findings", [])}
    current_by_fp = {finding["fingerprint"]: finding for finding in current.get("findings", [])}
    fixed = sort_findings([previous_by_fp[key] for key in set(previous_by_fp) - set(current_by_fp)])
    remaining = sort_findings([current_by_fp[key] for key in set(previous_by_fp) & set(current_by_fp)])
    new = sort_findings([current_by_fp[key] for key in set(current_by_fp) - set(previous_by_fp)])
    return {
        "available": True,
        "fixed": fixed,
        "remaining": remaining,
        "new": new,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--offline-analysis", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    export = json.loads(args.export.read_text())
    offline = json.loads(args.offline_analysis.read_text()) if args.offline_analysis else None
    audit = build_audit(export, offline_analysis=offline)
    payload = json.dumps(audit, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload)
    else:
        print(payload)


if __name__ == "__main__":
    main()
