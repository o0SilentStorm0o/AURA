#!/usr/bin/env python3
"""Offline APK defensive-surface analyzer for AURA research fixtures.

The analyzer is intentionally conservative. It reports static evidence and
confidence, not runtime proof. It does not execute APK code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
ANALYZER_VERSION = "aura-offline-apk-analyzer-0.1.0"
ANDROID_NS = "http://schemas.android.com/apk/res/android"
SENSITIVE_MARKERS = ("bank", "pay", "wallet", "password", "authenticator", "health", "eid")
TEXT_ENTRY_SUFFIXES = (
    ".json",
    ".xml",
    ".properties",
    ".txt",
    ".html",
    ".js",
    ".map",
    ".conf",
    ".config",
)
SECRET_PATTERNS = {
    "google_api_key": re.compile(rb"AIza[0-9A-Za-z_-]{20,}"),
    "stripe_live_key": re.compile(rb"\b(?:sk|pk)_live_[0-9A-Za-z]{16,}\b"),
    "aws_access_key": re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    "sentry_dsn": re.compile(rb"https://[0-9a-fA-F]{16,}@[A-Za-z0-9_.-]+/\d+"),
    "generic_secret_assignment": re.compile(rb"(?i)(api[_-]?key|secret|token|client[_-]?secret)\s*[:=]\s*[\"'][^\"']{12,}[\"']"),
}
THIRD_PARTY_SDK_MARKERS = {
    "Firebase": ("Lcom/google/firebase/",),
    "Google Mobile Ads": ("Lcom/google/android/gms/ads/",),
    "Meta/Facebook": ("Lcom/facebook/",),
    "AppsFlyer": ("Lcom/appsflyer/",),
    "Adjust": ("Lcom/adjust/",),
    "Segment": ("Lcom/segment/analytics/",),
    "Amplitude": ("Lcom/amplitude/",),
    "Sentry": ("Lio/sentry/",),
    "Bugsnag": ("Lcom/bugsnag/",),
    "Braze": ("Lcom/braze/",),
    "Datadog": ("Lcom/datadog/",),
}


@dataclass(frozen=True)
class ToolPaths:
    apkanalyzer: Path | None
    aapt: Path | None
    dexdump: Path | None


@dataclass(frozen=True)
class Finding:
    finding_type: str
    severity: str
    confidence: float
    observability_state: str
    evidence_source: str
    raw_value: str
    explanation: str

    def to_json(self, package_name: str) -> dict[str, Any]:
        seed = f"{package_name}:{self.finding_type}:{self.raw_value}"
        return {
            "findingId": hashlib.sha256(seed.encode()).hexdigest()[:24],
            "findingType": self.finding_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "observabilityState": self.observability_state,
            "evidenceSource": self.evidence_source,
            "rawValue": self.raw_value,
            "explanation": self.explanation,
        }


def android_attr(name: str) -> str:
    return f"{{{ANDROID_NS}}}{name}"


def run_tool(args: list[str | Path]) -> str:
    completed = subprocess.run(
        [str(arg) for arg in args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return completed.stdout


def newest_sdk_tool(tool_name: str) -> Path | None:
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not sdk_root:
        return None
    sdk = Path(sdk_root)
    candidates = sorted(
        sdk.glob(f"build-tools/*/{tool_name}"),
        key=lambda path: tuple(int(part) if part.isdigit() else 0 for part in path.parent.name.split(".")),
        reverse=True,
    )
    return candidates[0] if candidates else None


def cmdline_tool(tool_name: str) -> Path | None:
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not sdk_root:
        return None
    candidate = Path(sdk_root) / "cmdline-tools" / "latest" / "bin" / tool_name
    return candidate if candidate.exists() else None


def discover_tools() -> ToolPaths:
    return ToolPaths(
        apkanalyzer=cmdline_tool("apkanalyzer"),
        aapt=newest_sdk_tool("aapt"),
        dexdump=newest_sdk_tool("dexdump"),
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_manifest(apk_path: Path, tools: ToolPaths) -> ET.Element:
    if tools.apkanalyzer is None:
        raise RuntimeError("apkanalyzer not found; set ANDROID_HOME or ANDROID_SDK_ROOT")
    manifest_xml = run_tool([tools.apkanalyzer, "manifest", "print", apk_path])
    return ET.fromstring(manifest_xml)


def apk_xml_entries(apk_path: Path) -> list[str]:
    with zipfile.ZipFile(apk_path) as archive:
        return sorted(
            name
            for name in archive.namelist()
            if name.startswith("res/") and name.endswith(".xml")
        )


def dump_xmltree(apk_path: Path, entry: str, tools: ToolPaths) -> str:
    if tools.aapt is None:
        return ""
    return subprocess.run(
        [str(tools.aapt), "dump", "xmltree", str(apk_path), entry],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout


def dexdump(apk_path: Path, tools: ToolPaths) -> str:
    if tools.dexdump is None:
        return ""
    return subprocess.run(
        [str(tools.dexdump), "-d", str(apk_path)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout


def bool_attr(element: ET.Element | None, name: str) -> bool | None:
    if element is None:
        return None
    value = element.get(android_attr(name))
    if value is None:
        return None
    return value.lower() == "true"


def text_attr(element: ET.Element | None, name: str) -> str | None:
    if element is None:
        return None
    return element.get(android_attr(name))


def component_name(component: ET.Element) -> str:
    return text_attr(component, "name") or "<unknown>"


def package_label(root: ET.Element, application: ET.Element | None) -> str:
    label = text_attr(application, "label")
    if label and not label.startswith("@"):
        return label
    return root.get("package", "")


def looks_sensitive(package_name: str, label: str) -> bool:
    haystack = f"{package_name} {label}".lower()
    return any(marker in haystack for marker in SENSITIVE_MARKERS)


def has_launcher_intent(component: ET.Element) -> bool:
    for intent_filter in component.findall("intent-filter"):
        has_main = any(
            action.get(android_attr("name")) == "android.intent.action.MAIN"
            for action in intent_filter.findall("action")
        )
        has_launcher = any(
            category.get(android_attr("name")) == "android.intent.category.LAUNCHER"
            for category in intent_filter.findall("category")
        )
        if has_main and has_launcher:
            return True
    return False


def unprotected_exported_components(application: ET.Element | None) -> list[str]:
    if application is None:
        return []
    output: list[str] = []
    for tag in ("activity", "service", "receiver", "provider"):
        for component in application.findall(tag):
            if bool_attr(component, "exported") is not True:
                continue
            if text_attr(component, "permission") or text_attr(component, "readPermission") or text_attr(component, "writePermission"):
                continue
            if tag == "activity" and has_launcher_intent(component):
                continue
            output.append(f"{tag}:{component_name(component)}")
    return output


def has_action(intent_filter: ET.Element, value: str) -> bool:
    return any(
        action.get(android_attr("name")) == value
        for action in intent_filter.findall("action")
    )


def has_category(intent_filter: ET.Element, value: str) -> bool:
    return any(
        category.get(android_attr("name")) == value
        for category in intent_filter.findall("category")
    )


def deep_link_surfaces(application: ET.Element | None) -> list[dict[str, str]]:
    if application is None:
        return []
    surfaces: list[dict[str, str]] = []
    for activity in application.findall("activity"):
        exported = bool_attr(activity, "exported")
        for intent_filter in activity.findall("intent-filter"):
            if not has_action(intent_filter, "android.intent.action.VIEW"):
                continue
            if not has_category(intent_filter, "android.intent.category.BROWSABLE"):
                continue
            data_nodes = intent_filter.findall("data") or [ET.Element("data")]
            for data in data_nodes:
                path = (
                    text_attr(data, "path")
                    or text_attr(data, "pathPrefix")
                    or text_attr(data, "pathPattern")
                    or "*"
                )
                surfaces.append(
                    {
                        "activity": component_name(activity),
                        "scheme": text_attr(data, "scheme") or "*",
                        "host": text_attr(data, "host") or "*",
                        "path": path,
                        "autoVerify": str(bool_attr(intent_filter, "autoVerify")),
                        "exported": str(exported),
                    }
                )
    return surfaces


def backup_rules_observation(
    application: ET.Element | None,
    xml_entries: list[str],
) -> dict[str, Any]:
    allow_backup = bool_attr(application, "allowBackup")
    full_backup_content = text_attr(application, "fullBackupContent")
    data_extraction_rules = text_attr(application, "dataExtractionRules")
    candidate_files = [
        entry for entry in xml_entries
        if "backup" in entry.lower() or "data_extraction" in entry.lower()
    ]
    return {
        "allowBackup": allow_backup,
        "fullBackupContent": full_backup_content,
        "dataExtractionRules": data_extraction_rules,
        "candidateFiles": candidate_files,
        "hasExplicitRules": bool(full_backup_content or data_extraction_rules or candidate_files),
        "observabilityState": "OBSERVED_ENABLED" if allow_backup is not None else "DECLARED_ONLY",
    }


def detect_flag_secure(dexdump_text: str) -> bool:
    if "FLAG_SECURE" in dexdump_text:
        return True
    lines = dexdump_text.splitlines()
    for index, line in enumerate(lines):
        if "Landroid/view/Window;.setFlags:(II)V" not in line and "Landroid/view/Window;.addFlags:(I)V" not in line:
            continue
        window = "\n".join(lines[max(0, index - 12): index + 1])
        if "#int 8192" in window or "#2000" in window:
            return True
    return False


def detect_filter_touches(dexdump_text: str, xmltree_texts: dict[str, str]) -> bool:
    if "setFilterTouchesWhenObscured" in dexdump_text:
        return True
    return any(
        "filterTouchesWhenObscured" in text and ("true" in text or "0xffffffff" in text)
        for text in xmltree_texts.values()
    )


def detect_accessibility_data_sensitive(dexdump_text: str, xmltree_texts: dict[str, str]) -> bool:
    if "accessibilityDataSensitive" in dexdump_text or "setAccessibilityDataSensitive" in dexdump_text:
        return True
    return any("accessibilityDataSensitive" in text for text in xmltree_texts.values())


def network_config_observation(xmltree_texts: dict[str, str], referenced: str | None) -> dict[str, Any]:
    candidates = {
        name: text
        for name, text in xmltree_texts.items()
        if "network-security-config" in text or "network_security" in name
    }
    cleartext_true = [
        name
        for name, text in candidates.items()
        if "cleartextTrafficPermitted" in text and ("0xffffffff" in text or re.search(r'true"', text))
    ]
    debug_overrides = [
        name for name, text in candidates.items()
        if "debug-overrides" in text
    ]
    user_ca_trust = [
        name for name, text in candidates.items()
        if "certificates" in text and re.search(r"src.*user|user.*src", text, re.IGNORECASE | re.DOTALL)
    ]
    return {
        "referenced": referenced,
        "candidateFiles": sorted(candidates),
        "cleartextPermittedFiles": sorted(cleartext_true),
        "debugOverridesFiles": sorted(debug_overrides),
        "userCaTrustFiles": sorted(user_ca_trust),
        "observabilityState": "OBSERVED_ENABLED" if candidates else "DECLARED_ONLY" if referenced else "NOT_OBSERVABLE",
    }


def webview_observation(dexdump_text: str) -> dict[str, Any]:
    patterns = {
        "javascriptEnabled": "setJavaScriptEnabled" in dexdump_text,
        "addJavascriptInterface": "addJavascriptInterface" in dexdump_text,
        "allowFileAccess": "setAllowFileAccess" in dexdump_text,
        "allowContentAccess": "setAllowContentAccess" in dexdump_text,
        "universalAccessFromFileUrls": "setAllowUniversalAccessFromFileURLs" in dexdump_text,
        "mixedContentMode": "setMixedContentMode" in dexdump_text,
        "webViewClient": "setWebViewClient" in dexdump_text,
    }
    return {
        **patterns,
        "observed": any(patterns.values()),
        "observabilityState": "OBSERVED_ENABLED" if any(patterns.values()) else "UNKNOWN_API_LIMITATION",
    }


def embedded_config_observation(apk_path: Path) -> dict[str, Any]:
    secret_hits: list[dict[str, str]] = []
    endpoint_hosts: set[str] = set()
    with zipfile.ZipFile(apk_path) as archive:
        for entry in archive.infolist():
            if entry.file_size > 512_000:
                continue
            lower = entry.filename.lower()
            if not lower.endswith(TEXT_ENTRY_SUFFIXES) and not lower.startswith("assets/"):
                continue
            try:
                payload = archive.read(entry)
            except (KeyError, RuntimeError, zipfile.BadZipFile):
                continue
            for pattern_name, pattern in SECRET_PATTERNS.items():
                if pattern.search(payload):
                    secret_hits.append({
                        "entry": entry.filename,
                        "pattern": pattern_name,
                    })
            for match in re.finditer(rb"https?://([A-Za-z0-9.-]+)", payload):
                host = match.group(1).decode("ascii", errors="ignore").lower()
                if host and not host.endswith(".android.com") and host not in {"localhost", "127.0.0.1"}:
                    endpoint_hosts.add(host)
    return {
        "secretPatternHits": secret_hits[:25],
        "endpointHostSample": sorted(endpoint_hosts)[:25],
        "secretPatternHitCount": len(secret_hits),
        "endpointHostCount": len(endpoint_hosts),
        "observabilityState": "OBSERVED_ENABLED",
    }


def third_party_sdk_observation(dexdump_text: str) -> dict[str, Any]:
    detected = sorted(
        name for name, markers in THIRD_PARTY_SDK_MARKERS.items()
        if any(marker in dexdump_text for marker in markers)
    )
    return {
        "detectedSdks": detected,
        "observabilityState": "OBSERVED_ENABLED" if detected else "UNKNOWN_API_LIMITATION",
        "confidence": 0.66 if detected else 0.30,
    }


def parse_int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def analyze_apk(apk_path: Path, tools: ToolPaths | None = None) -> dict[str, Any]:
    tools = tools or discover_tools()
    root = parse_manifest(apk_path, tools)
    application = root.find("application")
    package_name = root.get("package", "")
    label = package_label(root, application)
    sensitive = looks_sensitive(package_name, label)
    xml_entries = apk_xml_entries(apk_path)

    xmltree_texts = {
        entry: dump_xmltree(apk_path, entry, tools)
        for entry in xml_entries
    }
    dexdump_text = dexdump(apk_path, tools)
    network_config = network_config_observation(
        xmltree_texts,
        text_attr(application, "networkSecurityConfig"),
    )
    backup_rules = backup_rules_observation(application, xml_entries)
    deep_links = deep_link_surfaces(application)
    webview = webview_observation(dexdump_text)
    embedded_config = embedded_config_observation(apk_path)
    third_party_sdks = third_party_sdk_observation(dexdump_text)

    flag_secure = detect_flag_secure(dexdump_text)
    filter_touches = detect_filter_touches(dexdump_text, xmltree_texts)
    accessibility_sensitive = detect_accessibility_data_sensitive(dexdump_text, xmltree_texts)
    target_sdk = root.find("uses-sdk").get(android_attr("targetSdkVersion")) if root.find("uses-sdk") is not None else None
    target_sdk_number = parse_int(target_sdk)

    findings: list[Finding] = []
    if bool_attr(application, "debuggable") is True:
        findings.append(Finding(
            "DEBUGGABLE_ENABLED",
            "HIGH" if sensitive else "MEDIUM",
            0.96,
            "OBSERVED_ENABLED",
            "manifest",
            "android:debuggable=true",
            "The APK manifest declares a debuggable application.",
        ))
    if bool_attr(application, "allowBackup") is True:
        findings.append(Finding(
            "BACKUP_ALLOWED",
            "MEDIUM" if sensitive else "LOW",
            0.93,
            "OBSERVED_ENABLED",
            "manifest",
            "android:allowBackup=true",
            "The APK manifest allows application data backup.",
        ))
    if bool_attr(application, "usesCleartextTraffic") is True:
        findings.append(Finding(
            "CLEARTEXT_TRAFFIC_ALLOWED_MANIFEST",
            "MEDIUM",
            0.92,
            "OBSERVED_ENABLED",
            "manifest",
            "android:usesCleartextTraffic=true",
            "The manifest permits cleartext traffic at the application level.",
        ))
    for entry in network_config["cleartextPermittedFiles"]:
        findings.append(Finding(
            "NETWORK_SECURITY_CONFIG_CLEARTEXT_PERMITTED",
            "MEDIUM",
            0.88,
            "OBSERVED_ENABLED",
            "resource_xml",
            entry,
            "A network security config resource permits cleartext traffic.",
        ))
    for entry in network_config["debugOverridesFiles"]:
        findings.append(Finding(
            "NETWORK_SECURITY_CONFIG_DEBUG_OVERRIDES",
            "MEDIUM",
            0.72,
            "OBSERVED_ENABLED",
            "resource_xml",
            entry,
            "A network security config contains debug-overrides. Verify this is not shipped in production trust policy.",
        ))
    for entry in network_config["userCaTrustFiles"]:
        findings.append(Finding(
            "NETWORK_SECURITY_CONFIG_USER_CA_TRUST",
            "MEDIUM",
            0.70,
            "OBSERVED_ENABLED",
            "resource_xml",
            entry,
            "A network security config appears to trust user-installed certificate authorities.",
        ))
    if bool_attr(application, "allowBackup") is True and not backup_rules["hasExplicitRules"]:
        findings.append(Finding(
            "BACKUP_ALLOWED_WITHOUT_EXPLICIT_RULES",
            "MEDIUM" if sensitive else "LOW",
            0.76,
            "OBSERVED_ENABLED",
            "manifest_and_resource_xml",
            "allowBackup=true; no fullBackupContent/dataExtractionRules resource observed",
            "Backup is allowed and no explicit backup/data-extraction rules were observed in the APK.",
        ))
    for component in unprotected_exported_components(application):
        findings.append(Finding(
            "UNPROTECTED_EXPORTED_COMPONENT",
            "HIGH" if sensitive else "MEDIUM",
            0.91,
            "OBSERVED_ENABLED",
            "manifest",
            component,
            "An exported non-launcher component has no manifest permission guard.",
        ))
    for surface in deep_links:
        broad = surface["host"] == "*" or surface["path"] == "*"
        risky_words = re.search(r"callback|redirect|token|auth|payment|pay|checkout", " ".join(surface.values()), re.IGNORECASE)
        findings.append(Finding(
            "DEEPLINK_SURFACE_NEEDS_MANUAL_REVIEW",
            "MEDIUM" if broad or risky_words else "LOW",
            0.68,
            "OBSERVED_ENABLED",
            "manifest",
            (
                f"activity:{surface['activity']} scheme={surface['scheme']} "
                f"host={surface['host']} path={surface['path']} autoVerify={surface['autoVerify']}"
            ),
            "An exported BROWSABLE deep link/app link surface accepts external intents and needs input-validation review.",
        ))
    if target_sdk_number is not None and target_sdk_number < 31:
        findings.append(Finding(
            "SDK_OR_TARGET_API_POLICY_RISK",
            "MEDIUM",
            0.90,
            "OBSERVED_ENABLED",
            "manifest",
            f"targetSdkVersion={target_sdk}",
            "The APK targets an older Android API level and may miss newer platform security defaults or policy expectations.",
        ))
    if webview["addJavascriptInterface"]:
        findings.append(Finding(
            "WEBVIEW_JAVASCRIPT_INTERFACE",
            "HIGH",
            0.70,
            "UNKNOWN_API_LIMITATION",
            "dex_static_heuristic",
            "addJavascriptInterface pattern observed",
            "A static scan observed a JavaScript bridge pattern. Review exposed methods and loaded origins manually.",
        ))
    elif webview["javascriptEnabled"] or webview["universalAccessFromFileUrls"] or webview["mixedContentMode"]:
        observed = [
            name for name, value in webview.items()
            if value is True and name not in {"observed"}
        ]
        findings.append(Finding(
            "WEBVIEW_RISKY_CONFIGURATION",
            "MEDIUM",
            0.55,
            "UNKNOWN_API_LIMITATION",
            "dex_static_heuristic",
            ",".join(observed),
            "A static scan observed WebView configuration APIs that should be manually reviewed with the loaded content model.",
        ))
    if embedded_config["secretPatternHits"]:
        patterns = sorted({item["pattern"] for item in embedded_config["secretPatternHits"]})
        entries = sorted({item["entry"] for item in embedded_config["secretPatternHits"]})[:5]
        findings.append(Finding(
            "EMBEDDED_SECRET_OR_ENDPOINT_REVIEW",
            "MEDIUM",
            0.58,
            "OBSERVED_ENABLED",
            "apk_static_text_scan",
            f"patterns={','.join(patterns)} entries={','.join(entries)}",
            "Static text scanning found API key/secret-like configuration patterns. Classify whether they are public identifiers or sensitive credentials.",
        ))
    privacy_sdks = [
        sdk for sdk in third_party_sdks["detectedSdks"]
        if sdk not in {"Firebase"}
    ]
    if privacy_sdks:
        findings.append(Finding(
            "THIRD_PARTY_SDK_PRIVACY_SURFACE",
            "INFO",
            0.66,
            "OBSERVED_ENABLED",
            "dex_static_heuristic",
            ",".join(privacy_sdks),
            "Static class-name heuristics detected third-party SDK namespaces that should be reviewed for data collection and disclosure alignment.",
        ))
    if sensitive and not flag_secure:
        findings.append(Finding(
            "FLAG_SECURE_NOT_OBSERVED_SENSITIVE_APP",
            "MEDIUM",
            0.50,
            "UNKNOWN_API_LIMITATION",
            "dex_static_heuristic",
            "no Window FLAG_SECURE pattern found",
            "A static scan did not find FLAG_SECURE. This is a best-effort absence signal, not runtime proof.",
        ))
    if sensitive and not filter_touches:
        findings.append(Finding(
            "FILTER_TOUCHES_WHEN_OBSCURED_NOT_OBSERVED_SENSITIVE_APP",
            "LOW",
            0.42,
            "UNKNOWN_API_LIMITATION",
            "dex_or_resource_static_heuristic",
            "no filterTouchesWhenObscured pattern found",
            "A static scan did not find tapjacking touch filtering. This absence signal has limited confidence.",
        ))

    return {
        "schemaVersion": SCHEMA_VERSION,
        "analyzerVersion": ANALYZER_VERSION,
        "generatedAt": int(time.time() * 1000),
        "apk": {
            "path": str(apk_path),
            "sha256": sha256_file(apk_path),
            "packageName": package_name,
            "label": label,
            "targetSdkVersion": target_sdk,
        },
        "observations": {
            "sensitiveRoleHint": sensitive,
            "debuggable": bool_attr(application, "debuggable"),
            "allowBackup": bool_attr(application, "allowBackup"),
            "backupRules": backup_rules,
            "usesCleartextTraffic": bool_attr(application, "usesCleartextTraffic"),
            "networkSecurityConfig": network_config,
            "deepLinks": deep_links,
            "webView": webview,
            "embeddedConfig": embedded_config,
            "thirdPartySdks": third_party_sdks,
            "flagSecure": {
                "observed": flag_secure,
                "observabilityState": "OBSERVED_ENABLED" if flag_secure else "UNKNOWN_API_LIMITATION",
                "confidence": 0.82 if flag_secure else 0.50,
            },
            "filterTouchesWhenObscured": {
                "observed": filter_touches,
                "observabilityState": "OBSERVED_ENABLED" if filter_touches else "UNKNOWN_API_LIMITATION",
                "confidence": 0.78 if filter_touches else 0.42,
            },
            "accessibilityDataSensitive": {
                "observed": accessibility_sensitive,
                "observabilityState": "OBSERVED_ENABLED" if accessibility_sensitive else "UNKNOWN_API_LIMITATION",
                "confidence": 0.70 if accessibility_sensitive else 0.35,
            },
            "unprotectedExportedComponents": unprotected_exported_components(application),
        },
        "findings": [finding.to_json(package_name) for finding in findings],
        "limitations": [
            "Static absence of FLAG_SECURE, filterTouchesWhenObscured, or accessibilityDataSensitive is not runtime proof.",
            "The analyzer does not execute code, inspect native behavior, or verify dynamic view-level protection.",
            "Resource references may be obfuscated; findings include confidence to avoid overclaiming.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("apks", nargs="+", type=Path, help="APK files to analyze")
    parser.add_argument("--out", type=Path, help="Optional JSON output path")
    args = parser.parse_args()

    tools = discover_tools()
    result = {
        "schemaVersion": SCHEMA_VERSION,
        "analyzerVersion": ANALYZER_VERSION,
        "generatedAt": int(time.time() * 1000),
        "apks": [analyze_apk(path, tools) for path in args.apks],
    }
    payload = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload + "\n")
    else:
        print(payload)


if __name__ == "__main__":
    main()
