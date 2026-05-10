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
            output.append(f"{tag}:{text_attr(component, 'name') or '<unknown>'}")
    return output


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
    return {
        "referenced": referenced,
        "candidateFiles": sorted(candidates),
        "cleartextPermittedFiles": sorted(cleartext_true),
        "observabilityState": "OBSERVED_ENABLED" if candidates else "DECLARED_ONLY" if referenced else "NOT_OBSERVABLE",
    }


def analyze_apk(apk_path: Path, tools: ToolPaths | None = None) -> dict[str, Any]:
    tools = tools or discover_tools()
    root = parse_manifest(apk_path, tools)
    application = root.find("application")
    package_name = root.get("package", "")
    label = package_label(root, application)
    sensitive = looks_sensitive(package_name, label)

    xmltree_texts = {
        entry: dump_xmltree(apk_path, entry, tools)
        for entry in apk_xml_entries(apk_path)
    }
    dexdump_text = dexdump(apk_path, tools)
    network_config = network_config_observation(
        xmltree_texts,
        text_attr(application, "networkSecurityConfig"),
    )

    flag_secure = detect_flag_secure(dexdump_text)
    filter_touches = detect_filter_touches(dexdump_text, xmltree_texts)
    accessibility_sensitive = detect_accessibility_data_sensitive(dexdump_text, xmltree_texts)
    target_sdk = root.find("uses-sdk").get(android_attr("targetSdkVersion")) if root.find("uses-sdk") is not None else None

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
            "usesCleartextTraffic": bool_attr(application, "usesCleartextTraffic"),
            "networkSecurityConfig": network_config,
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
