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
DEFAULT_POLICY_PACK_VERSION = "0.1.0"
POLICY_DIR = Path(__file__).resolve().parent / "policies"
COMPONENT_SURFACE_CATALOG_PATH = Path(__file__).resolve().parent / "component_surface_catalog.json"
PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "INFO": 3}
STATUS_ORDER = {
    "BLOCKER": 0,
    "SHOULD_FIX": 1,
    "REVIEW": 2,
    "INFO": 3,
    "ACCEPTED_RISK": 4,
    "NOT_APPLICABLE": 5,
}
STATUS_BY_PRIORITY = {
    "P1": "BLOCKER",
    "P2": "SHOULD_FIX",
    "P3": "REVIEW",
    "INFO": "INFO",
}
GROUP_ORDER = {
    "RELEASE_BUILD_HYGIENE": 0,
    "PAYMENT_ACCOUNT_FLOW_SURFACE_REVIEW": 1,
    "PAYMENT_REDIRECT_SURFACE_REVIEW": 1,
    "AUTH_CALLBACK_SURFACE_REVIEW": 2,
    "CUSTOMER_DATA_FLOW_ENTRYPOINT_REVIEW": 3,
    "APP_ROUTING_ENTRYPOINT_REVIEW": 4,
    "DEEPLINK_ROUTING_ENTRYPOINT_REVIEW": 4,
    "WEBVIEW_BROWSER_ENTRYPOINT_REVIEW": 5,
    "COMPONENT_EXPOSURE_REVIEW": 6,
    "PREVIEW_TOOLING_RELEASE_REVIEW": 7,
    "THIRD_PARTY_SDK_EXPORTED_SURFACES": 8,
    "BACKUP_DATA_EXTRACTION_REVIEW": 9,
    "NETWORK_TRANSPORT_REVIEW": 10,
    "WEBVIEW_CONFIGURATION_REVIEW": 11,
    "SENSITIVE_UI_REVIEW": 12,
    "SECRETS_CONFIG_REVIEW": 13,
    "SDK_PRIVACY_SURFACE_REVIEW": 14,
    "TARGET_API_POLICY_REVIEW": 15,
    "UNCLASSIFIED_RELEASE_REVIEW": 99,
}
ACTIONABLE_STATUSES = {"BLOCKER", "SHOULD_FIX", "REVIEW"}
CUSTOMER_VISIBLE_STATUSES = {"BLOCKER", "SHOULD_FIX", "REVIEW"}
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
    "UNCLASSIFIED_RELEASE_REVIEW_FINDING",
}
DEFAULT_APP_PROFILE = {
    "appCategory": "utility",
    "dataSensitivity": "medium",
    "releaseStage": "production_candidate",
    "distribution": "unknown",
    "authFlow": False,
    "payments": False,
    "webviewUsageExpected": None,
    "externalIntegrationsExpected": None,
    "allowedCleartextDomains": [],
    "knownExportedComponents": [],
    "acceptedRisks": [],
}
CATEGORY_POLICY_PACKS = {
    "fintech": "fintech_policy.json",
    "banking": "fintech_policy.json",
    "health": "health_policy.json",
    "ecommerce": "ecommerce_policy.json",
    "chat_social": "ecommerce_policy.json",
    "media": "public_info_policy.json",
    "public_info": "public_info_policy.json",
    "public_sector": "public_info_policy.json",
    "internal_enterprise": "internal_enterprise_policy.json",
    "sdk_library": "sdk_library_policy.json",
}
DEBUG_RELEASE_STAGES = {"debug", "development", "internal_debug"}

TYPE_GROUPS = {
    "DEBUGGABLE_OR_TEST_CONFIG_IN_RELEASE": {
        "componentClass": "RELEASE_BUILD_HYGIENE",
        "groupId": "RELEASE_BUILD_HYGIENE",
        "groupTitle": "Release build hygiene needs review",
        "recommendedReview": [
            "Confirm the distributed artifact is built from the intended release variant.",
            "Confirm debug/test-only settings are absent from production candidates.",
        ],
    },
    "BACKUP_MAY_INCLUDE_SENSITIVE_DATA": {
        "componentClass": "DATA_PERSISTENCE",
        "groupId": "BACKUP_DATA_EXTRACTION_REVIEW",
        "groupTitle": "Backup and data extraction policy needs review",
        "recommendedReview": [
            "Confirm backup/data extraction behavior matches the app data sensitivity.",
            "Confirm tokens, secrets, regulated data, and caches are excluded or backup is disabled.",
        ],
    },
    "CLEARTEXT_TRAFFIC_ALLOWED": {
        "componentClass": "NETWORK_CONFIGURATION",
        "groupId": "NETWORK_TRANSPORT_REVIEW",
        "groupTitle": "Network transport configuration needs review",
        "recommendedReview": [
            "Confirm cleartext is disabled or scoped to an approved non-sensitive endpoint.",
            "Confirm release network security config differs from debug-only exceptions where needed.",
        ],
    },
    "WEBVIEW_RISKY_CONFIGURATION": {
        "componentClass": "WEBVIEW_CONFIGURATION",
        "groupId": "WEBVIEW_CONFIGURATION_REVIEW",
        "groupTitle": "WebView configuration needs review",
        "recommendedReview": [
            "Confirm loaded origins, JavaScript bridges, mixed content, and file access settings are constrained.",
            "Confirm untrusted URLs cannot reach privileged app code paths.",
        ],
    },
    "SENSITIVE_SCREEN_NOT_PROTECTED": {
        "componentClass": "SENSITIVE_UI",
        "groupId": "SENSITIVE_UI_REVIEW",
        "groupTitle": "Sensitive UI protection needs review",
        "recommendedReview": [
            "Confirm screenshots, screen sharing, and accessibility exposure are acceptable for sensitive flows.",
            "Apply UI hardening controls where exposure is not intended.",
        ],
    },
    "MISSING_TAPJACKING_DEFENSE_ON_SENSITIVE_ACTION": {
        "componentClass": "SENSITIVE_UI",
        "groupId": "SENSITIVE_UI_REVIEW",
        "groupTitle": "Sensitive UI protection needs review",
        "recommendedReview": [
            "Confirm obscured-touch handling is appropriate for sensitive actions.",
            "Add tapjacking defenses or document why the control is not applicable.",
        ],
    },
    "SENSITIVE_UI_ACCESSIBILITY_EXPOSURE_REVIEW": {
        "componentClass": "SENSITIVE_UI",
        "groupId": "SENSITIVE_UI_REVIEW",
        "groupTitle": "Sensitive UI protection needs review",
        "recommendedReview": [
            "Confirm accessibility exposure is appropriate for sensitive views on supported Android versions.",
            "Apply accessibility privacy controls where the platform and product requirements allow it.",
        ],
    },
    "SDK_OR_TARGET_API_POLICY_RISK": {
        "componentClass": "TARGET_API_POLICY",
        "groupId": "TARGET_API_POLICY_REVIEW",
        "groupTitle": "Target SDK / platform policy needs review",
        "recommendedReview": [
            "Confirm target SDK level matches the planned release channel and store policy expectations.",
            "Retest behavior changes introduced by target SDK upgrades.",
        ],
    },
    "SECRETS_OR_ENDPOINTS_IN_APK": {
        "componentClass": "SECRETS_CONFIG",
        "groupId": "SECRETS_CONFIG_REVIEW",
        "groupTitle": "Embedded secrets and endpoint configuration need review",
        "recommendedReview": [
            "Classify each candidate as public identifier, restricted key, endpoint, or true secret.",
            "Remove or restrict true secrets and document public identifiers.",
        ],
    },
    "THIRD_PARTY_SDK_PRIVACY_SURFACE": {
        "componentClass": "SDK_PRIVACY_SURFACE",
        "groupId": "SDK_PRIVACY_SURFACE_REVIEW",
        "groupTitle": "Third-party SDK privacy surface needs review",
        "recommendedReview": [
            "Reconcile detected SDKs with privacy disclosures and consent flows.",
            "Confirm data-safety statements match SDK behavior in the release artifact.",
        ],
    },
    "UNCLASSIFIED_RELEASE_REVIEW_FINDING": {
        "componentClass": "UNCLASSIFIED_RELEASE_REVIEW",
        "groupId": "UNCLASSIFIED_RELEASE_REVIEW",
        "groupTitle": "Unclassified release review signals need triage",
        "recommendedReview": [
            "Classify the signal during manual triage.",
            "Promote recurring signals into a specific policy rule or mark them not applicable.",
        ],
    },
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
    "UNCLASSIFIED_RELEASE_REVIEW_FINDING": AuditDefinition(
        "Unclassified release review finding",
        "P3",
        "Android team",
        True,
        "AURA observed a release-relevant signal that does not yet map to a more specific release-risk type. It is intentionally routed to review instead of being overstated.",
        "Classify the signal during triage. Convert it to a more specific policy rule when it recurs, or document why it is accepted/not applicable.",
        "Close the finding after source review, policy refinement, or by rerunning AURA with evidence that maps to a specific release-risk type.",
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
    "DANGEROUS_INTENT_SURFACE_NEEDS_MANUAL_REVIEW": "UNCLASSIFIED_RELEASE_REVIEW_FINDING",
}


def normalize_type(finding_type: str | None) -> str:
    return TYPE_MAP.get(str(finding_type), "UNCLASSIFIED_RELEASE_REVIEW_FINDING")


def load_app_profile(profile: dict[str, Any] | Path | str | None = None) -> dict[str, Any]:
    if profile is None:
        payload: dict[str, Any] = {}
    elif isinstance(profile, (str, Path)):
        payload = json.loads(Path(profile).read_text())
    else:
        payload = dict(profile)
    merged = {
        **DEFAULT_APP_PROFILE,
        **payload,
    }
    for list_key in ("allowedCleartextDomains", "knownExportedComponents", "acceptedRisks"):
        value = merged.get(list_key)
        if value is None:
            merged[list_key] = []
        elif not isinstance(value, list):
            merged[list_key] = [value]
    return merged


def policy_pack_paths(app_profile: dict[str, Any], policy_paths: list[Path | str] | None = None) -> list[Path]:
    paths = [POLICY_DIR / "base_android_release_policy.json"]
    category = str(app_profile.get("appCategory") or "").lower()
    category_pack = CATEGORY_POLICY_PACKS.get(category)
    if category_pack:
        paths.append(POLICY_DIR / category_pack)
    release_stage = str(app_profile.get("releaseStage") or "").lower()
    if release_stage in DEBUG_RELEASE_STAGES:
        paths.append(POLICY_DIR / "debug_build_policy.json")
    else:
        paths.append(POLICY_DIR / "production_release_policy.json")
    if policy_paths:
        paths.extend(Path(path) for path in policy_paths)

    deduped: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path.resolve()) if path.exists() else str(path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def load_policy_packs(
    app_profile: dict[str, Any],
    policy_paths: list[Path | str] | None = None,
) -> list[dict[str, Any]]:
    packs: list[dict[str, Any]] = []
    for path in policy_pack_paths(app_profile, policy_paths):
        if not path.exists():
            continue
        payload = json.loads(path.read_text())
        payload["_path"] = str(path)
        packs.append(payload)
    return packs


def load_component_surface_catalog() -> dict[str, Any]:
    if not COMPONENT_SURFACE_CATALOG_PATH.exists():
        return {
            "rules": [],
            "defaults": {
                "componentClass": "UNKNOWN_EXPORTED_SURFACE",
                "groupId": "COMPONENT_EXPOSURE_REVIEW",
                "groupTitle": "Other exported surfaces need review",
                "recommendedReview": [
                    "Confirm the component is intentionally reachable from other apps.",
                    "Confirm manifest permission guards, caller validation, and input validation are sufficient.",
                ],
            },
        }
    return json.loads(COMPONENT_SURFACE_CATALOG_PATH.read_text())


def token_matches(raw_value: str, rule: dict[str, Any]) -> bool:
    raw = raw_value.lower()
    match_all = [str(item).lower() for item in rule.get("matchAll", [])]
    match_any = [str(item).lower() for item in rule.get("matchAny", [])]
    if match_all and not all(token in raw for token in match_all):
        return False
    if match_any and not any(token in raw for token in match_any):
        return False
    return bool(match_all or match_any)


def component_classification(normalized_type: str, evidence_key: str) -> dict[str, Any]:
    if normalized_type != "EXPORTED_COMPONENT_WITHOUT_GUARD":
        fallback = TYPE_GROUPS.get(normalized_type, TYPE_GROUPS["UNCLASSIFIED_RELEASE_REVIEW_FINDING"])
        return {
            "componentClass": fallback["componentClass"],
            "groupId": fallback["groupId"],
            "groupTitle": fallback["groupTitle"],
            "recommendedReview": list(fallback.get("recommendedReview", [])),
            "catalogId": "type_level_policy",
            "sdk": None,
        }

    catalog = load_component_surface_catalog()
    for rule in catalog.get("rules", []):
        if rule.get("componentClass") == "PREVIEW_OR_TOOLING" and token_matches(evidence_key, rule):
            return {
                "componentClass": rule.get("componentClass", "UNKNOWN_EXPORTED_SURFACE"),
                "groupId": rule.get("groupId", "COMPONENT_EXPOSURE_REVIEW"),
                "groupTitle": rule.get("groupTitle", "Other exported surfaces need review"),
                "recommendedReview": list(rule.get("recommendedReview", [])),
                "catalogId": rule.get("catalogId", "component_catalog"),
                "sdk": rule.get("sdk"),
            }
    for rule in catalog.get("rules", []):
        if rule.get("sdk") and token_matches(evidence_key, rule):
            return {
                "componentClass": rule.get("componentClass", "UNKNOWN_EXPORTED_SURFACE"),
                "groupId": rule.get("groupId", "COMPONENT_EXPOSURE_REVIEW"),
                "groupTitle": rule.get("groupTitle", "Other exported surfaces need review"),
                "recommendedReview": list(rule.get("recommendedReview", [])),
                "catalogId": rule.get("catalogId", "component_catalog"),
                "sdk": rule.get("sdk"),
            }
    for rule in catalog.get("rules", []):
        if token_matches(evidence_key, rule):
            return {
                "componentClass": rule.get("componentClass", "UNKNOWN_EXPORTED_SURFACE"),
                "groupId": rule.get("groupId", "COMPONENT_EXPOSURE_REVIEW"),
                "groupTitle": rule.get("groupTitle", "Other exported surfaces need review"),
                "recommendedReview": list(rule.get("recommendedReview", [])),
                "catalogId": rule.get("catalogId", "component_catalog"),
                "sdk": rule.get("sdk"),
            }
    defaults = catalog.get("defaults", {})
    return {
        "componentClass": defaults.get("componentClass", "UNKNOWN_EXPORTED_SURFACE"),
        "groupId": defaults.get("groupId", "COMPONENT_EXPOSURE_REVIEW"),
        "groupTitle": defaults.get("groupTitle", "Other exported surfaces need review"),
        "recommendedReview": list(defaults.get("recommendedReview", [])),
        "catalogId": "component_catalog.default",
        "sdk": None,
    }


def evidence_strength(source: str, normalized_type: str) -> dict[str, Any]:
    if normalized_type == "EXPORTED_COMPONENT_WITHOUT_GUARD":
        if source == "OFFLINE_APK_ANALYZER":
            return {
                "level": "Static manifest analysis",
                "exploitability": "Not proven",
                "needs": ["source review", "targeted dynamic test"],
                "summary": "Static APK manifest evidence identifies a review target; exploitability still depends on component logic.",
            }
        return {
            "level": "Manifest-level only",
            "exploitability": "Not proven",
            "needs": ["APK offline analysis", "source review", "dynamic test"],
            "summary": "Installed-app metadata is enough to identify an exported surface, not enough to prove misconfiguration.",
        }
    if source == "OFFLINE_APK_ANALYZER":
        return {
            "level": "Static APK analysis",
            "exploitability": "Not proven",
            "needs": ["source review", "targeted dynamic test"],
            "summary": "Static evidence supports a release-risk review item, but runtime exploitability is not claimed.",
        }
    return {
        "level": "On-device metadata",
        "exploitability": "Not proven",
        "needs": ["APK offline analysis", "source review"],
        "summary": "No-root metadata supports triage, not a vulnerability proof.",
    }


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


def component_short_name(raw_value: str) -> str | None:
    if ":" not in str(raw_value):
        return None
    name = str(raw_value).split(":", 1)[1].strip()
    if not name:
        return None
    return name.rsplit(".", 1)[-1] or name


def split_manifest_surface_values(raw_value: str) -> list[str]:
    parts = [
        item.strip()
        for item in str(raw_value or "").split(";")
        if item.strip()
    ]
    surface_parts = [
        item for item in parts
        if component_kind(item) is not None
    ]
    if len(surface_parts) <= 1:
        return []
    return surface_parts


def expand_source_finding(source_finding: dict[str, Any]) -> list[dict[str, Any]]:
    """Split aggregate manifest component evidence into ticket-ready surfaces."""

    normalized = normalize_type(source_finding.get("findingType"))
    if normalized != "EXPORTED_COMPONENT_WITHOUT_GUARD":
        return [source_finding]
    surface_values = split_manifest_surface_values(raw_evidence_key(source_finding))
    if not surface_values:
        return [source_finding]
    expanded: list[dict[str, Any]] = []
    for index, value in enumerate(surface_values, start=1):
        item = dict(source_finding)
        item["rawValue"] = value
        item["findingId"] = f"{source_finding.get('findingId', 'component')}_{index}"
        item["humanExplanation"] = (
            "The app exposes this non-launcher component without a component-level permission. "
            "AURA split the aggregate manifest evidence into a component-level release-risk item."
        )
        expanded.append(item)
    return expanded


def finding_title(normalized_type: str, default_title: str, evidence_key: str) -> str:
    if normalized_type == "EXPORTED_COMPONENT_WITHOUT_GUARD":
        kind = component_kind(evidence_key)
        if kind:
            short_name = component_short_name(evidence_key)
            suffix = f": {short_name}" if short_name else ""
            return f"Exported {kind} without permission guard{suffix}"
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
        "UNCLASSIFIED_RELEASE_REVIEW_FINDING": "The release-relevant signal is classified, reviewed, and either converted to a specific rule, fixed, accepted, or marked not applicable.",
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


def default_app_profile_impact(normalized_type: str, app_profile: dict[str, Any]) -> str:
    category = app_profile.get("appCategory", "utility")
    sensitivity = app_profile.get("dataSensitivity", "medium")
    stage = app_profile.get("releaseStage", "production_candidate")
    return (
        f"In `{category}` / `{sensitivity}` / `{stage}` context, this release surface "
        "requires either a fix, explicit manual validation, or documented accepted risk."
    )


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


def normalized_evidence(
    source: str,
    source_finding: dict[str, Any],
    normalized_type: str,
    evidence_key: str,
) -> dict[str, Any]:
    return {
        "evidenceType": normalized_type,
        "source": source,
        "sourceFindingType": source_finding.get("findingType"),
        "sourceFindingId": source_finding.get("findingId"),
        "observabilityState": source_finding.get("observabilityState"),
        "rawValue": source_finding.get("rawValue") or source_finding.get("humanExplanation") or source_finding.get("explanation"),
        "componentKind": component_kind(evidence_key),
    }


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
    classification = component_classification(normalized, evidence_key)
    strength = evidence_strength(source, normalized)
    return {
        "id": f"AURA-REL-{item_fingerprint[:8].upper()}",
        "type": normalized,
        "title": finding_title(normalized, definition.title, evidence_key),
        "priority": priority,
        "status": STATUS_BY_PRIORITY.get(priority, "INFO"),
        "confidence": float(source_finding.get("confidence") or 0.0),
        "evidence": normalized_evidence(source, source_finding, normalized, evidence_key),
        "evidenceSubject": subject,
        "sourceSpecificity": specificity,
        "affectedSurface": {
            "kind": component_kind(evidence_key) or "app",
            "value": subject,
            "componentClass": classification.get("componentClass"),
        },
        "componentClassification": classification,
        "evidenceStrength": strength,
        "appProfileImpact": default_app_profile_impact(normalized, DEFAULT_APP_PROFILE),
        "whyItMatters": definition.why_it_matters,
        "howToFix": definition.how_to_fix,
        "howToVerify": definition.how_to_verify,
        "acceptanceCriteria": acceptance_criteria(normalized, evidence_key),
        "verificationCheck": verification_check(normalized, evidence_key),
        "owner": definition.owner,
        "requiresManualReview": definition.requires_manual_review,
        "fingerprint": item_fingerprint,
        "policyTrace": [],
    }


def values_match(actual: Any, expected: Any) -> bool:
    if expected is None:
        return True
    if isinstance(expected, list):
        return any(values_match(actual, item) for item in expected)
    if isinstance(actual, bool) or isinstance(expected, bool):
        return bool(actual) is bool(expected)
    return str(actual).lower() == str(expected).lower()


def rule_context(finding: dict[str, Any], app_profile: dict[str, Any]) -> dict[str, Any]:
    evidence = finding.get("evidence") or {}
    return {
        **app_profile,
        "evidenceType": finding.get("type"),
        "type": finding.get("type"),
        "priority": finding.get("priority"),
        "status": finding.get("status"),
        "source": evidence.get("source"),
        "sourceFindingType": evidence.get("sourceFindingType"),
        "observabilityState": evidence.get("observabilityState"),
        "componentKind": evidence.get("componentKind") or component_kind(str(evidence.get("rawValue") or "")),
        "rawValue": evidence.get("rawValue") or "",
        "evidenceSubject": finding.get("evidenceSubject"),
    }


def rule_matches(rule: dict[str, Any], finding: dict[str, Any], app_profile: dict[str, Any]) -> bool:
    context = rule_context(finding, app_profile)
    conditions = rule.get("when") or {}
    for key, expected in conditions.items():
        if key == "rawContains":
            raw = str(context.get("rawValue") or "").lower()
            if isinstance(expected, list):
                if not any(str(item).lower() in raw for item in expected):
                    return False
            elif str(expected).lower() not in raw:
                return False
            continue
        if key == "rawNotContains":
            raw = str(context.get("rawValue") or "").lower()
            if isinstance(expected, list):
                if any(str(item).lower() in raw for item in expected):
                    return False
            elif str(expected).lower() in raw:
                return False
            continue
        if not values_match(context.get(key), expected):
            return False
    return True


def matches_accepted_risk(finding: dict[str, Any], accepted: dict[str, Any]) -> bool:
    if accepted.get("fingerprint") and accepted.get("fingerprint") == finding.get("fingerprint"):
        return True
    if accepted.get("type") and accepted.get("type") != finding.get("type"):
        return False
    subject = str(finding.get("evidenceSubject") or "")
    if accepted.get("evidenceSubject") and str(accepted["evidenceSubject"]).lower() != subject.lower():
        return False
    raw = str((finding.get("evidence") or {}).get("rawValue") or "")
    if accepted.get("rawContains") and str(accepted["rawContains"]).lower() not in raw.lower():
        return False
    return bool(accepted.get("type"))


def apply_expected_surface_overrides(finding: dict[str, Any], app_profile: dict[str, Any]) -> None:
    """Apply customer context that downgrades, but does not erase, review work."""

    raw = str((finding.get("evidence") or {}).get("rawValue") or "")
    if finding.get("type") == "EXPORTED_COMPONENT_WITHOUT_GUARD":
        for component in app_profile.get("knownExportedComponents", []):
            if component and str(component) in raw:
                finding["priority"] = "P3"
                finding["status"] = "REVIEW"
                finding["appProfileImpact"] = (
                    "The app profile declares this exported component as expected. "
                    "AURA downgrades it to review, but still requires validation and a narrow contract."
                )
                finding.setdefault("policyTrace", []).append("customer_profile.known_exported_component")
                return

    if finding.get("type") == "CLEARTEXT_TRAFFIC_ALLOWED":
        for domain in app_profile.get("allowedCleartextDomains", []):
            if domain and str(domain).lower() in raw.lower():
                finding["priority"] = "INFO"
                finding["status"] = "ACCEPTED_RISK"
                finding["appProfileImpact"] = (
                    f"The app profile explicitly allows cleartext for `{domain}`. "
                    "AURA keeps it as accepted release context rather than a blocker."
                )
                finding.setdefault("policyTrace", []).append("customer_profile.allowed_cleartext_domain")
                return


def apply_accepted_risk_overrides(finding: dict[str, Any], app_profile: dict[str, Any]) -> None:
    """Apply explicit customer decisions after all policy packs and profile downgrades."""

    for accepted in app_profile.get("acceptedRisks", []):
        if isinstance(accepted, dict) and matches_accepted_risk(finding, accepted):
            accepted_status = str(accepted.get("status") or "ACCEPTED_RISK")
            if accepted_status not in {"ACCEPTED_RISK", "NOT_APPLICABLE"}:
                accepted_status = "ACCEPTED_RISK"
            finding["status"] = accepted_status
            finding["priority"] = "INFO"
            finding["appProfileImpact"] = str(accepted.get("reason") or "Customer profile marks this finding as accepted risk.")
            finding.setdefault("policyTrace", []).append(f"customer_profile.{accepted_status.lower()}")
            return


def apply_policy_effect(finding: dict[str, Any], effect: dict[str, Any]) -> None:
    for source_key, target_key in (
        ("priority", "priority"),
        ("status", "status"),
        ("owner", "owner"),
        ("manualReviewRequired", "requiresManualReview"),
        ("appProfileImpact", "appProfileImpact"),
        ("whyItMatters", "whyItMatters"),
        ("howToFix", "howToFix"),
        ("acceptanceCriteria", "acceptanceCriteria"),
        ("verification", "verificationCheck"),
        ("verificationCheck", "verificationCheck"),
        ("title", "title"),
    ):
        if source_key in effect:
            finding[target_key] = effect[source_key]
    if "priority" in effect and "status" not in effect:
        finding["status"] = STATUS_BY_PRIORITY.get(finding.get("priority"), finding.get("status", "INFO"))


def apply_policy_engine(
    findings: list[dict[str, Any]],
    app_profile: dict[str, Any],
    policy_packs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    for finding in findings:
        finding["appProfileImpact"] = default_app_profile_impact(finding.get("type", ""), app_profile)
        for pack in policy_packs:
            for rule in pack.get("rules", []):
                if not rule_matches(rule, finding, app_profile):
                    continue
                apply_policy_effect(finding, rule.get("effect") or {})
                finding.setdefault("policyTrace", []).append(f"{pack.get('policyPackId', 'policy')}.{rule.get('ruleId', 'rule')}")
        apply_expected_surface_overrides(finding, app_profile)
        apply_accepted_risk_overrides(finding, app_profile)
    return sort_findings(findings)


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


def group_sort_key(group: dict[str, Any]) -> tuple[int, int, str]:
    return (
        PRIORITY_ORDER.get(group.get("priority", "INFO"), 9),
        GROUP_ORDER.get(group.get("groupId", "UNCLASSIFIED_RELEASE_REVIEW"), 99),
        group.get("groupId", ""),
    )


def group_component_name(finding: dict[str, Any]) -> str:
    raw = str((finding.get("evidence") or {}).get("rawValue") or "")
    short_name = component_short_name(raw)
    if short_name:
        return short_name
    if raw:
        return raw
    return str(finding.get("evidenceSubject") or finding.get("id") or "surface")


def group_priority(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "INFO"
    return sorted(
        (finding.get("priority", "INFO") for finding in findings),
        key=lambda priority: PRIORITY_ORDER.get(priority, 9),
    )[0]


def group_status(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "INFO"
    return sorted(
        (finding.get("status", "INFO") for finding in findings),
        key=lambda status: STATUS_ORDER.get(status, 9),
    )[0]


def merged_recommended_review(findings: list[dict[str, Any]]) -> list[str]:
    output: list[str] = []
    for finding in findings:
        classification = finding.get("componentClassification") or {}
        for item in classification.get("recommendedReview") or []:
            if item not in output:
                output.append(str(item))
    return output[:6]


def merged_needs(findings: list[dict[str, Any]]) -> list[str]:
    output: list[str] = []
    for finding in findings:
        strength = finding.get("evidenceStrength") or {}
        for item in strength.get("needs") or []:
            if item not in output:
                output.append(str(item))
    return output


def merged_evidence_level(findings: list[dict[str, Any]]) -> str:
    levels = []
    for finding in findings:
        level = (finding.get("evidenceStrength") or {}).get("level")
        if level and level not in levels:
            levels.append(str(level))
    if not levels:
        return "Unknown"
    if len(levels) == 1:
        return levels[0]
    return "Mixed evidence: " + ", ".join(levels)


def group_customer_summary(group_id: str, group_title: str, findings: list[dict[str, Any]]) -> str:
    component_count = sum(
        1 for finding in findings
        if finding.get("type") == "EXPORTED_COMPONENT_WITHOUT_GUARD"
    )
    if group_id == "PAYMENT_ACCOUNT_FLOW_SURFACE_REVIEW":
        return (
            "These payment/account entry points are externally reachable and should be reviewed together because they may process callback, redirect, or account-flow input. "
            "The current evidence identifies review targets; it does not prove a payment or authentication bypass."
        )
    if group_id == "APP_ROUTING_ENTRYPOINT_REVIEW":
        return (
            "These routing entry points can receive external navigation input and should be reviewed as one app-flow surface. "
            "Confirm routes, hosts, parameters, and sensitive destinations are constrained before production release."
        )
    if group_id == "THIRD_PARTY_SDK_EXPORTED_SURFACES":
        return (
            "These exported SDK callback surfaces appear to come from third-party integrations and should be checked against the intended production SDK configuration. "
            "The review should confirm the components are expected, documented, and reflected in privacy disclosures."
        )
    if group_id == "PREVIEW_TOOLING_RELEASE_REVIEW":
        return (
            "Preview or tooling components appear in the release artifact and should be removed, guarded, or explicitly justified before customer delivery. "
            "This is a release hygiene review area, not proof of runtime abuse."
        )
    if group_id == "BACKUP_DATA_EXTRACTION_REVIEW":
        return (
            "The app backup/data extraction posture should be checked against the app profile and data sensitivity. "
            "Sensitive tokens, caches, regulated data, and account state should be excluded or backup should be disabled."
        )
    if group_id == "NETWORK_TRANSPORT_REVIEW":
        return (
            "The release network transport configuration should be reviewed for cleartext allowances, debug-only exceptions, and scoped domain rules. "
            "Broad production cleartext should be fixed or explicitly accepted with evidence."
        )
    if group_id == "WEBVIEW_CONFIGURATION_REVIEW":
        return (
            "The WebView configuration should be reviewed as a single browser/runtime surface. "
            "Focus on trusted origins, JavaScript bridges, mixed content, file access, and URL handoff behavior."
        )
    if component_count:
        return (
            "Externally reachable components should be reviewed as one release-risk area rather than as isolated manifest rows. "
            "Confirm each surface is expected, narrowly scoped, and guarded by caller/input validation where needed."
        )
    return (
        f"{group_title} should be handled as a ticket-ready release review workstream with clear owner, acceptance criteria, and retest evidence."
    )


def group_acceptance_criteria(group_id: str, items: list[dict[str, Any]]) -> str:
    if group_id == "PAYMENT_ACCOUNT_FLOW_SURFACE_REVIEW":
        return (
            "Payment/account callback surfaces are confirmed as expected; URI schemes, hosts, paths, and intent filters match documented SDK or app setup; "
            "callback state/nonce/session validation is confirmed in source review; SDK configuration matches the production package/signing identity."
        )
    if group_id == "APP_ROUTING_ENTRYPOINT_REVIEW":
        return (
            "External routing entry points accept only documented schemes, hosts, paths, and parameters; sensitive destinations require the expected authenticated state; "
            "unexpected routes are rejected or safely ignored."
        )
    if group_id == "THIRD_PARTY_SDK_EXPORTED_SURFACES":
        return (
            "Each SDK callback surface is expected for the production integration; documented SDK setup matches the release artifact; "
            "callback handling is scoped to intended inputs; privacy/disclosure impact has been reviewed."
        )
    if group_id == "PREVIEW_TOOLING_RELEASE_REVIEW":
        return (
            "Preview/debug/tooling components are removed from the production artifact, non-exported, or protected by an explicit release guard with documented business justification."
        )
    if group_id == "BACKUP_DATA_EXTRACTION_REVIEW":
        return (
            "Backup/data extraction is disabled for sensitive apps or rules explicitly exclude tokens, credentials, regulated data, caches, and other sensitive local state."
        )
    if group_id == "NETWORK_TRANSPORT_REVIEW":
        return (
            "Production network security config has no broad cleartext allowance; any exception is domain-scoped, documented, and accepted in the app profile."
        )
    if group_id == "WEBVIEW_CONFIGURATION_REVIEW":
        return (
            "WebView loads only expected origins; JavaScript bridges are restricted to trusted content; file access, mixed content, and external URL handoff are explicitly reviewed."
        )
    if group_id == "SENSITIVE_UI_REVIEW":
        return (
            "Sensitive screens and actions have documented screenshot, accessibility, and obscured-touch behavior; missing controls are either fixed or marked not applicable after review."
        )
    first = items[0] if items else {}
    return str(first.get("acceptanceCriteria") or "Release owner confirms the review area is fixed, accepted, or not applicable with evidence.")


def group_verification_check(group_id: str, items: list[dict[str, Any]]) -> str:
    if group_id in {
        "PAYMENT_ACCOUNT_FLOW_SURFACE_REVIEW",
        "APP_ROUTING_ENTRYPOINT_REVIEW",
        "THIRD_PARTY_SDK_EXPORTED_SURFACES",
        "PREVIEW_TOOLING_RELEASE_REVIEW",
    }:
        return (
            "Next verification: run offline APK analysis or source review to inspect intent filters, schemes, hosts, exported flags, SDK configuration, and callback handling. "
            "After fixes, rerun AURA and compare stable finding fingerprints."
        )
    if group_id == "BACKUP_DATA_EXTRACTION_REVIEW":
        return (
            "Inspect AndroidManifest backup settings plus backup_rules.xml/data_extraction_rules.xml, then rerun AURA/offline analysis and verify the data-persistence finding is fixed or accepted."
        )
    if group_id == "NETWORK_TRANSPORT_REVIEW":
        return (
            "Inspect AndroidManifest and network_security_config.xml for broad cleartext or debug trust exceptions, then rerun AURA/offline analysis and compare the network finding fingerprint."
        )
    if group_id == "WEBVIEW_CONFIGURATION_REVIEW":
        return (
            "Review WebView setup in source/offline analysis for JavaScript bridges, file access, mixed content, and URL loading, then rerun AURA after configuration changes."
        )
    first = items[0] if items else {}
    return str(first.get("verificationCheck") or "Rerun AURA and compare stable finding fingerprints after the release owner applies or accepts the fix.")


def report_group_id_for_finding(finding: dict[str, Any]) -> str:
    classification = finding.get("componentClassification") or {}
    component_class = str(classification.get("componentClass") or "")
    kind = str((finding.get("affectedSurface") or {}).get("kind") or "")
    if component_class in {"PAYMENT_REDIRECT", "AUTH_CALLBACK", "CUSTOMER_DATA_FLOW"}:
        return "PAYMENT_ACCOUNT_FLOW_SURFACE_REVIEW"
    if component_class in {"DEEPLINK_ROUTER", "WEBVIEW_ENTRYPOINT"}:
        return "APP_ROUTING_ENTRYPOINT_REVIEW"
    if component_class == "UNKNOWN_EXPORTED_SURFACE" and kind == "activity":
        return "APP_ROUTING_ENTRYPOINT_REVIEW"
    if component_class in {"SDK_CALLBACK", "PUSH_SERVICE", "ANALYTICS_RECEIVER"}:
        return "THIRD_PARTY_SDK_EXPORTED_SURFACES"
    if component_class == "PREVIEW_OR_TOOLING":
        return "PREVIEW_TOOLING_RELEASE_REVIEW"
    return str(classification.get("groupId") or "UNCLASSIFIED_RELEASE_REVIEW")


def report_group_title(group_id: str, items: list[dict[str, Any]]) -> str:
    classes = {
        str((item.get("componentClassification") or {}).get("componentClass") or "")
        for item in items
    }
    if group_id == "PAYMENT_ACCOUNT_FLOW_SURFACE_REVIEW":
        if classes <= {"PAYMENT_REDIRECT"}:
            return "Payment / financial redirect surfaces need review"
        return "Payment / account flow entry points need review"
    if group_id == "APP_ROUTING_ENTRYPOINT_REVIEW":
        if "WEBVIEW_ENTRYPOINT" in classes and "DEEPLINK_ROUTER" in classes:
            return "Deep link / WebView routing entry points need review"
        if "WEBVIEW_ENTRYPOINT" in classes:
            return "WebView / browser entry points need review"
        return "Deep link / routing entry points need review"
    if group_id == "THIRD_PARTY_SDK_EXPORTED_SURFACES":
        return "Third-party SDK exported surfaces need review"
    if group_id == "PREVIEW_TOOLING_RELEASE_REVIEW":
        return "Preview/tooling components in release artifact need review"
    return str((items[0].get("componentClassification") or {}).get("groupTitle") or group_id.replace("_", " ").title())


def build_finding_groups(findings: list[dict[str, Any]], app_profile: dict[str, Any]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        grouped.setdefault(report_group_id_for_finding(finding), []).append(finding)

    groups: list[dict[str, Any]] = []
    for group_id, items in grouped.items():
        first = items[0]
        title = report_group_title(group_id, items)
        priority = group_priority(items)
        status = group_status(items)
        needs = merged_needs(items)
        evidence_level = merged_evidence_level(items)
        component_items = [
            item for item in items
            if item.get("type") == "EXPORTED_COMPONENT_WITHOUT_GUARD"
        ]
        affected_components = []
        for finding in component_items:
            component_name = group_component_name(finding)
            if component_name not in affected_components:
                affected_components.append(component_name)
        seed = group_id + ":" + ":".join(sorted(str(item.get("fingerprint")) for item in items))
        groups.append(
            {
                "groupId": group_id,
                "id": f"AURA-GRP-{hashlib.sha256(seed.encode()).hexdigest()[:8].upper()}",
                "title": title,
                "status": status,
                "priority": priority,
                "findingIds": [str(item.get("id")) for item in items],
                "findingFingerprints": [str(item.get("fingerprint")) for item in items],
                "findingCount": len(items),
                "componentClass": ", ".join(sorted({
                    str((item.get("componentClassification") or {}).get("componentClass") or "n/a")
                    for item in items
                })),
                "sdk": ", ".join(sorted({
                    str((item.get("componentClassification") or {}).get("sdk"))
                    for item in items
                    if (item.get("componentClassification") or {}).get("sdk")
                })) or None,
                "componentCount": len(affected_components),
                "affectedComponents": affected_components,
                "evidenceStrength": {
                    "level": evidence_level,
                    "exploitability": "Not proven",
                    "needs": needs,
                    "summary": (
                        f"{evidence_level}; exploitability not proven; needs: "
                        f"{' / '.join(needs) if needs else 'manual review'}."
                    ),
                },
                "customerSummary": group_customer_summary(group_id, title, items),
                "recommendedReview": merged_recommended_review(items),
                "acceptanceCriteria": group_acceptance_criteria(group_id, items),
                "groupAcceptanceCriteria": group_acceptance_criteria(group_id, items),
                "verificationCheck": group_verification_check(group_id, items),
                "groupVerificationCheck": group_verification_check(group_id, items),
                "owner": first.get("owner"),
                "manualReviewRequired": any(item.get("requiresManualReview") is True for item in items),
                "appProfileImpact": default_app_profile_impact(first.get("type", ""), app_profile),
                "sourceFindingTypes": sorted({
                    str((item.get("evidence") or {}).get("sourceFindingType"))
                    for item in items
                    if (item.get("evidence") or {}).get("sourceFindingType")
                }),
            }
        )
    return sorted(groups, key=group_sort_key)


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


def ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 4)


def policy_quality_metrics(
    findings: list[dict[str, Any]],
    priority_counts: Counter[str],
    groups: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    customer_visible = [
        finding for finding in findings
        if finding.get("status") in CUSTOMER_VISIBLE_STATUSES
    ]
    actionable = [
        finding for finding in customer_visible
        if finding.get("howToFix") and finding.get("verificationCheck") and finding.get("acceptanceCriteria")
    ]
    manual_review = [
        finding for finding in customer_visible
        if finding.get("requiresManualReview") is True
    ]
    accepted = [
        finding for finding in findings
        if finding.get("status") == "ACCEPTED_RISK"
    ]
    not_applicable = [
        finding for finding in findings
        if finding.get("status") == "NOT_APPLICABLE"
    ]
    visible_groups = [
        group for group in (groups or [])
        if group.get("status") in CUSTOMER_VISIBLE_STATUSES
    ]
    largest_group = max((int(group.get("findingCount") or 0) for group in visible_groups), default=0)
    return {
        "blockerDensity": priority_counts.get("P1", 0),
        "customerVisibleFindingCount": len(customer_visible),
        "customerVisibleReviewAreaCount": len(visible_groups),
        "largestReviewAreaSize": largest_group,
        "groupedFindingReduction": max(len(customer_visible) - len(visible_groups), 0),
        "actionableRate": ratio(len(actionable), len(customer_visible)),
        "manualReviewRate": ratio(len(manual_review), len(customer_visible)),
        "acceptedRiskRecurrence": len(accepted),
        "notApplicableCount": len(not_applicable),
        "infoCount": sum(1 for finding in findings if finding.get("priority") == "INFO"),
    }


def build_audit(
    export: dict[str, Any],
    *,
    offline_analysis: dict[str, Any] | None = None,
    app_profile: dict[str, Any] | Path | str | None = None,
    policy_paths: list[Path | str] | None = None,
) -> dict[str, Any]:
    assessments = export.get("assessments") or []
    if not assessments:
        raise ValueError("App-owner audit requires at least one scoped assessment")
    profile = load_app_profile(app_profile)
    policy_packs = load_policy_packs(profile, policy_paths)
    assessment = assessments[0]
    target_package = package_name(assessment)
    on_device = [
        finding for finding in export.get("defensiveSurfaceFindings", [])
        if finding.get("packageName") == target_package
    ]
    offline_apk = offline_apk_for_package(offline_analysis, target_package)
    raw_findings: list[dict[str, Any]] = []
    for finding in on_device:
        raw_findings.extend(
            audit_finding_from_source(
                package_name_value=target_package,
                source="ON_DEVICE",
                source_finding=expanded,
            )
            for expanded in expand_source_finding(finding)
        )
    if offline_apk:
        for finding in offline_apk.get("findings", []):
            raw_findings.extend(
                audit_finding_from_source(
                    package_name_value=target_package,
                    source="OFFLINE_APK_ANALYZER",
                    source_finding=expanded,
                )
                for expanded in expand_source_finding(finding)
            )
    findings = merge_duplicate_findings(raw_findings)
    findings = apply_policy_engine(findings, profile, policy_packs)
    finding_groups = build_finding_groups(findings, profile)
    actionable_findings = [
        finding for finding in findings
        if finding.get("status") in ACTIONABLE_STATUSES and finding.get("priority") != "INFO"
    ]
    counts = Counter(finding["priority"] for finding in actionable_findings)
    status_counts = Counter(finding.get("status", "INFO") for finding in findings)
    return {
        "schemaVersion": 1,
        "auditEngineVersion": AUDIT_ENGINE_VERSION,
        "policyPackVersion": DEFAULT_POLICY_PACK_VERSION,
        "targetPackage": target_package,
        "appProfile": profile,
        "policyPacksApplied": [
            pack.get("policyPackId", "unknown") for pack in policy_packs
        ],
        "releaseStatus": release_status(counts),
        "priorityCounts": {
            "P1": counts.get("P1", 0),
            "P2": counts.get("P2", 0),
            "P3": counts.get("P3", 0),
            "INFO": sum(1 for finding in findings if finding.get("priority") == "INFO"),
        },
        "statusCounts": dict(status_counts),
        "policyQualityMetrics": policy_quality_metrics(findings, counts, finding_groups),
        "findingGroups": finding_groups,
        "releaseRiskGroups": finding_groups,
        "findings": findings,
        "releaseRiskFindings": findings,
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
            "resolutionRate": 0.0,
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
        "resolutionRate": ratio(len(fixed), len(fixed) + len(remaining)),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--offline-analysis", type=Path)
    parser.add_argument("--app-profile", type=Path)
    parser.add_argument("--policy-pack", action="append", type=Path, dest="policy_packs")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    export = json.loads(args.export.read_text())
    offline = json.loads(args.offline_analysis.read_text()) if args.offline_analysis else None
    app_profile = json.loads(args.app_profile.read_text()) if args.app_profile else None
    audit = build_audit(
        export,
        offline_analysis=offline,
        app_profile=app_profile,
        policy_paths=args.policy_packs,
    )
    payload = json.dumps(audit, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload)
    else:
        print(payload)


if __name__ == "__main__":
    main()
