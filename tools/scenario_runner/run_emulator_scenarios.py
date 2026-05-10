#!/usr/bin/env python3
"""Run AURA's emulator-backed research scenarios.

The scenario apps are harmless fixtures. The runner uses adb to install them,
toggle special-access state in the emulator, run AURA, pull the local JSON
export, and assert expected decisions.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AURA_PACKAGE = "cz.davidstrnadel.aura.research"
OUT_DIR = ROOT / "artifacts" / "scenario_runner"
OFFLINE_ANALYSIS_PATH = OUT_DIR / "offline-apk-analysis.json"
SUSPICIOUS_ACCESSIBILITY = (
    "com.flashlight.cleaner.update/"
    "com.flashlight.cleaner.update.FakeAccessibilityService"
)
SUSPICIOUS_NOTIFICATION = (
    "com.flashlight.cleaner.update/"
    "com.flashlight.cleaner.update.FakeNotificationListenerService"
)
FIXTURE_PACKAGES = [
    "com.flashlight.cleaner.update",
    "org.fdroid.example.screenreader",
    "com.example.lowriskutility",
    "com.example.benigncamera",
    "com.example.sensitivebank",
    "com.example.leakybank",
]
OPTIONAL_PLATFORM_AUDIT_PACKAGES = {
    "com.android.providers.contacts": "AOSP contacts provider with privileged/contact exposure is a BLUE platform audit item, not a user panic alert.",
    "com.android.server.telecom": "AOSP telecom service with phone/call exposure is a BLUE platform audit item, not a user panic alert.",
}


@dataclass(frozen=True)
class ScenarioExpectation:
    package_name: str
    expected_color: str
    description: str
    controlled_abuse: bool = False
    user_actionable: bool = False
    platform_audit: bool = False
    abstention_expected: bool = False
    expected_special_access: dict[str, str] | None = None
    expected_temporal_episodes: list[str] | None = None
    expected_defensive_findings: list[str] | None = None


EXPECTATIONS = [
    ScenarioExpectation(
        "com.flashlight.cleaner.update",
        "RED",
        "ADB sideload + active Accessibility + notification listener + overlay + boot persistence",
        controlled_abuse=True,
        user_actionable=True,
        expected_special_access={
            "accessibility_service": "OBSERVED_ENABLED",
            "notification_listener": "OBSERVED_ENABLED",
            "overlay": "OBSERVED_ENABLED",
            "request_install_packages": "DECLARED_ONLY",
        },
        expected_temporal_episodes=[
            "SIDELOAD_TO_ACCESSIBILITY",
            "SIDELOAD_TO_NOTIFICATION_LISTENER",
            "SPECIAL_ACCESS_PLUS_SENSITIVE_APP",
        ],
    ),
    ScenarioExpectation(
        "com.example.lowriskutility",
        "GRAY",
        "Unknown low-exposure sideload should abstain instead of warning",
        abstention_expected=True,
    ),
    ScenarioExpectation(
        "org.fdroid.example.screenreader",
        "GREEN",
        "Declared accessibility tool with assistive label but no active special access",
    ),
    ScenarioExpectation(
        "com.example.benigncamera",
        "GREEN",
        "High-capability camera-shaped fixture should be role-normalized out of the panic queue",
    ),
    ScenarioExpectation(
        "com.example.sensitivebank",
        "GREEN",
        "Sensitive app fixture without risky capability should not be an alert",
    ),
    ScenarioExpectation(
        "com.example.leakybank",
        "GREEN",
        "Sensitive app fixture with weak defensive surface should stay out of the panic queue",
        expected_defensive_findings=[
            "BACKUP_ALLOWED_SENSITIVE_APP",
            "CLEARTEXT_TRAFFIC_ALLOWED",
            "DEBUGGABLE_SENSITIVE_APP",
            "UNPROTECTED_EXPORTED_COMPONENT",
        ],
    ),
]


def run(cmd: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd))
    return subprocess.run(
        cmd,
        cwd=ROOT,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def adb(*args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return run(["adb", *args], check=check, capture=capture)


def build_all() -> None:
    run(
        [
            "sh",
            "gradlew",
            ":app:assembleResearchFullStandardDebug",
            ":testapps:suspicious-agent:assembleDebug",
            ":testapps:benign-accessibility:assembleDebug",
            ":testapps:lowrisk-utility:assembleDebug",
            ":testapps:benign-camera:assembleDebug",
            ":testapps:sensitive-bank:assembleDebug",
            ":testapps:leaky-bank:assembleDebug",
        ]
    )


def ensure_device() -> None:
    adb("wait-for-device")
    for _ in range(90):
        value = adb("shell", "getprop", "sys.boot_completed", capture=True).stdout.strip()
        if value == "1":
            return
        time.sleep(2)
    raise RuntimeError("Emulator did not finish booting")


def apk(path: str) -> str:
    return str(ROOT / path)


def install_apps() -> None:
    for package_name in FIXTURE_PACKAGES:
        adb("uninstall", package_name, check=False)

    apks = [
        "app/build/outputs/apk/researchFullStandard/debug/app-researchFull-standard-debug.apk",
        "testapps/suspicious-agent/build/outputs/apk/debug/suspicious-agent-debug.apk",
        "testapps/benign-accessibility/build/outputs/apk/debug/benign-accessibility-debug.apk",
        "testapps/lowrisk-utility/build/outputs/apk/debug/lowrisk-utility-debug.apk",
        "testapps/benign-camera/build/outputs/apk/debug/benign-camera-debug.apk",
        "testapps/sensitive-bank/build/outputs/apk/debug/sensitive-bank-debug.apk",
        "testapps/leaky-bank/build/outputs/apk/debug/leaky-bank-debug.apk",
    ]
    for candidate in apks:
        adb("install", "-r", apk(candidate))


def secure_setting(name: str) -> str:
    return adb("shell", "settings", "get", "secure", name, capture=True).stdout.strip()


def put_secure_setting(name: str, value: str) -> None:
    adb("shell", "settings", "put", "secure", name, value)


def append_component(setting_value: str, component: str) -> str:
    if setting_value in {"", "null"}:
        return component
    values = [item for item in setting_value.split(":") if item]
    if component not in values:
        values.append(component)
    return ":".join(values)


def remove_component(setting_value: str, component: str) -> str:
    if setting_value in {"", "null"}:
        return ""
    values = [item for item in setting_value.split(":") if item and item != component]
    return ":".join(values)


def restore_secure_setting(name: str, value: str) -> None:
    if value in {"", "null"}:
        adb("shell", "settings", "delete", "secure", name, check=False)
    else:
        put_secure_setting(name, value)


def clean_restore_state(raw_original: dict[str, str]) -> dict[str, str]:
    clean_accessibility = remove_component(
        raw_original["enabled_accessibility_services"],
        SUSPICIOUS_ACCESSIBILITY,
    )
    clean_notification = remove_component(
        raw_original["enabled_notification_listeners"],
        SUSPICIOUS_NOTIFICATION,
    )
    return {
        "enabled_accessibility_services": clean_accessibility,
        "accessibility_enabled": raw_original["accessibility_enabled"] if clean_accessibility else "0",
        "enabled_notification_listeners": clean_notification,
    }


def current_special_access_state() -> dict[str, str]:
    return {
        "enabled_accessibility_services": secure_setting("enabled_accessibility_services"),
        "accessibility_enabled": secure_setting("accessibility_enabled"),
        "enabled_notification_listeners": secure_setting("enabled_notification_listeners"),
    }


def remove_lab_special_access() -> dict[str, str]:
    restore_state = clean_restore_state(current_special_access_state())
    restore_special_access(restore_state)
    return restore_state


def configure_special_access() -> dict[str, str]:
    raw_original = {
        "enabled_accessibility_services": secure_setting("enabled_accessibility_services"),
        "accessibility_enabled": secure_setting("accessibility_enabled"),
        "enabled_notification_listeners": secure_setting("enabled_notification_listeners"),
    }
    restore_state = clean_restore_state(raw_original)

    put_secure_setting("accessibility_enabled", "1")
    put_secure_setting(
        "enabled_accessibility_services",
        append_component(restore_state["enabled_accessibility_services"], SUSPICIOUS_ACCESSIBILITY),
    )
    put_secure_setting(
        "enabled_notification_listeners",
        append_component(restore_state["enabled_notification_listeners"], SUSPICIOUS_NOTIFICATION),
    )
    adb("shell", "cmd", "notification", "allow_listener", SUSPICIOUS_NOTIFICATION, "0")
    adb("shell", "appops", "set", "com.flashlight.cleaner.update", "SYSTEM_ALERT_WINDOW", "allow")
    return restore_state


def restore_special_access(restore_state: dict[str, str] | None) -> None:
    if restore_state is None:
        return
    restore_secure_setting("enabled_accessibility_services", restore_state["enabled_accessibility_services"])
    restore_secure_setting("accessibility_enabled", restore_state["accessibility_enabled"])
    restore_secure_setting("enabled_notification_listeners", restore_state["enabled_notification_listeners"])
    adb(
        "shell",
        "cmd",
        "notification",
        "disallow_listener",
        SUSPICIOUS_NOTIFICATION,
        "0",
        check=False,
    )
    adb("shell", "appops", "set", "com.flashlight.cleaner.update", "SYSTEM_ALERT_WINDOW", "deny", check=False)


def current_usage_stats_mode() -> str:
    result = adb(
        "shell",
        "appops",
        "get",
        AURA_PACKAGE,
        "GET_USAGE_STATS",
        check=False,
        capture=True,
    )
    output = result.stdout.strip()
    for mode in ["allow", "foreground", "ignore", "deny", "default"]:
        if f"GET_USAGE_STATS: {mode}" in output:
            return mode
    return "default"


def set_usage_stats_mode(mode: str) -> None:
    adb("shell", "appops", "set", AURA_PACKAGE, "GET_USAGE_STATS", mode, check=False)


def restore_usage_stats_mode(mode: str | None) -> None:
    if mode:
        set_usage_stats_mode(mode)


def launch_sensitive_app() -> None:
    adb(
        "shell",
        "monkey",
        "-p",
        "com.example.sensitivebank",
        "-c",
        "android.intent.category.LAUNCHER",
        "1",
    )
    time.sleep(2)


def run_aura_and_pull_export(output_name: str, *, clear_data: bool) -> Path:
    if clear_data:
        adb("shell", "pm", "clear", AURA_PACKAGE)
    else:
        adb("shell", "am", "force-stop", AURA_PACKAGE, check=False)
        adb("shell", "run-as", AURA_PACKAGE, "rm", "-f", "files/exports/aura-last-scan.json", check=False)

    adb("shell", "monkey", "-p", AURA_PACKAGE, "-c", "android.intent.category.LAUNCHER", "1")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    export_path = OUT_DIR / output_name

    last_payload = ""
    for _ in range(60):
        probe = adb(
            "shell",
            "run-as",
            AURA_PACKAGE,
            "ls",
            "files/exports/aura-last-scan.json",
            check=False,
            capture=True,
        )
        if probe.returncode == 0:
            payload = adb(
                "exec-out",
                "run-as",
                AURA_PACKAGE,
                "cat",
                "files/exports/aura-last-scan.json",
                capture=True,
            ).stdout
            last_payload = payload
            if not is_valid_export(payload):
                time.sleep(1)
                continue
            export_path.write_text(payload)
            return export_path
        time.sleep(2)
    raise RuntimeError(
        "AURA export was not produced as valid JSON; "
        f"last payload length={len(last_payload)}"
    )


def is_valid_export(payload: str) -> bool:
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return False
    return isinstance(parsed.get("assessments"), list) and isinstance(parsed.get("scanId"), str)


def write_labels(export_path: Path) -> Path:
    export = json.loads(export_path.read_text())
    present_packages = {
        assessment["snapshot"]["packageName"]
        for assessment in export.get("assessments", [])
    }
    optional_platform_labels = [
        {
            "packageName": package_name,
            "expectedDecision": "BLUE",
            "controlledAbuse": False,
            "userActionable": False,
            "platformAudit": True,
            "abstentionExpected": False,
            "expectedDefensiveFindings": [],
        }
        for package_name in sorted(OPTIONAL_PLATFORM_AUDIT_PACKAGES)
        if package_name in present_packages
    ]
    labels_path = OUT_DIR / "scenario-labels.json"
    labels_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "labels": [
                    {
                        "packageName": expectation.package_name,
                        "expectedDecision": expectation.expected_color,
                        "controlledAbuse": expectation.controlled_abuse,
                        "userActionable": expectation.user_actionable,
                        "platformAudit": expectation.platform_audit,
                        "abstentionExpected": expectation.abstention_expected,
                        "expectedDefensiveFindings": expectation.expected_defensive_findings or [],
                    }
                    for expectation in EXPECTATIONS
                ]
                + optional_platform_labels,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    return labels_path


def evaluate(export_path: Path) -> Path:
    output_path = OUT_DIR / "evaluation.json"
    labels_path = write_labels(export_path)
    run(
        [
            "python3",
            "tools/evaluator/evaluate.py",
            str(export_path),
            "--labels",
            str(labels_path),
            "--out",
            str(output_path),
        ]
    )
    return output_path


def analyze_offline_apks() -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    run(
        [
            "python3",
            "tools/apk_analyzer/analyze_apk.py",
            apk("testapps/sensitive-bank/build/outputs/apk/debug/sensitive-bank-debug.apk"),
            apk("testapps/leaky-bank/build/outputs/apk/debug/leaky-bank-debug.apk"),
            "--out",
            str(OFFLINE_ANALYSIS_PATH),
        ]
    )
    return OFFLINE_ANALYSIS_PATH


def assert_offline_analysis(analysis_path: Path) -> None:
    payload = json.loads(analysis_path.read_text())
    by_package = {
        item["apk"]["packageName"]: item
        for item in payload.get("apks", [])
    }
    failures: list[str] = []

    sensitive = by_package.get("com.example.sensitivebank")
    leaky = by_package.get("com.example.leakybank")
    if sensitive is None:
        failures.append("missing offline analysis for sensitive bank fixture")
    elif sensitive.get("observations", {}).get("flagSecure", {}).get("observed") is not True:
        failures.append("expected sensitive bank FLAG_SECURE static signal")

    if leaky is None:
        failures.append("missing offline analysis for leaky bank fixture")
    else:
        finding_types = {finding["findingType"] for finding in leaky.get("findings", [])}
        expected = {
            "BACKUP_ALLOWED",
            "CLEARTEXT_TRAFFIC_ALLOWED_MANIFEST",
            "DEBUGGABLE_ENABLED",
            "FILTER_TOUCHES_WHEN_OBSCURED_NOT_OBSERVED_SENSITIVE_APP",
            "NETWORK_SECURITY_CONFIG_CLEARTEXT_PERMITTED",
            "UNPROTECTED_EXPORTED_COMPONENT",
        }
        missing = expected - finding_types
        if missing:
            failures.append(f"leaky bank missing offline findings: {sorted(missing)}")
        if leaky.get("observations", {}).get("flagSecure", {}).get("observed") is not True:
            failures.append("expected leaky bank FLAG_SECURE static signal")

    if failures:
        raise AssertionError("\n".join(failures))


def assert_expectations(export_path: Path) -> None:
    export = json.loads(export_path.read_text())
    by_package = {
        assessment["snapshot"]["packageName"]: assessment
        for assessment in export.get("assessments", [])
    }
    failures: list[str] = []
    for expectation in EXPECTATIONS:
        assessment = by_package.get(expectation.package_name)
        if assessment is None:
            failures.append(f"{expectation.package_name}: missing from AURA export")
            continue
        actual = assessment["decision"]["color"]
        title = assessment["decision"]["title"]
        role = assessment["role"]["predicted"]
        provenance = assessment["provenance"]["provenanceClass"]
        print(
            f"{expectation.package_name}: {actual} / {title} "
            f"role={role} provenance={provenance} :: {expectation.description}"
        )
        if actual != expectation.expected_color:
            failures.append(
                f"{expectation.package_name}: expected {expectation.expected_color}, got {actual}"
            )
        if expectation.expected_special_access:
            special_access = assessment["snapshot"].get("specialAccess", {})
            for name, expected_state in expectation.expected_special_access.items():
                actual_state = special_access.get(name)
                if actual_state != expected_state:
                    failures.append(
                        f"{expectation.package_name}: expected specialAccess[{name}]="
                        f"{expected_state}, got {actual_state}"
                    )
        if expectation.expected_temporal_episodes:
            actual_temporal = {
                episode["type"]
                for episode in export.get("temporalEpisodes", [])
                if episode["packageName"] == expectation.package_name
            }
            for expected_type in expectation.expected_temporal_episodes:
                if expected_type not in actual_temporal:
                    failures.append(
                        f"{expectation.package_name}: missing temporal episode {expected_type}; "
                        f"observed {sorted(actual_temporal)}"
                    )
            if expectation.package_name == "com.flashlight.cleaner.update":
                raw_features = assessment["snapshot"].get("rawFeatures", {})
                if raw_features.get("usageStatsObservability") != "OBSERVED_ENABLED":
                    failures.append(
                        f"{expectation.package_name}: expected UsageStats OBSERVED_ENABLED, "
                        f"got {raw_features.get('usageStatsObservability')}"
                    )
                if raw_features.get("foregroundSensitiveAppRecentlyObserved") != "true":
                    failures.append(
                        f"{expectation.package_name}: expected foreground sensitive signal, "
                        f"got {raw_features.get('foregroundSensitiveAppRecentlyObserved')}"
                    )
                if raw_features.get("foregroundSensitiveAppPackage") != "com.example.sensitivebank":
                    failures.append(
                        f"{expectation.package_name}: expected sensitive foreground package "
                        "com.example.sensitivebank, got "
                        f"{raw_features.get('foregroundSensitiveAppPackage')}"
                    )
        if expectation.expected_defensive_findings:
            actual_defensive = {
                finding["findingType"]
                for finding in export.get("defensiveSurfaceFindings", [])
                if finding["packageName"] == expectation.package_name
            }
            for expected_type in expectation.expected_defensive_findings:
                if expected_type not in actual_defensive:
                    failures.append(
                        f"{expectation.package_name}: missing defensive finding {expected_type}; "
                        f"observed {sorted(actual_defensive)}"
                    )

    for package_name, description in OPTIONAL_PLATFORM_AUDIT_PACKAGES.items():
        assessment = by_package.get(package_name)
        if assessment is None:
            continue
        actual = assessment["decision"]["color"]
        print(f"{package_name}: {actual} / optional platform audit :: {description}")
        if actual != "BLUE":
            failures.append(f"{package_name}: expected optional platform audit BLUE, got {actual}")
        if assessment["decision"].get("userAlert") is not False:
            failures.append(f"{package_name}: BLUE platform audit must not be a user alert")

    if failures:
        raise AssertionError("\n".join(failures))


def assert_evaluation_metrics(evaluation_path: Path) -> None:
    evaluation = json.loads(evaluation_path.read_text())
    comparisons = evaluation.get("comparisons", {})
    model_metrics = evaluation.get("modelMetrics", {})
    failures: list[str] = []

    false_positive_reduction = comparisons.get(
        "aura_non_actionable_critical_alert_rate_reduction_vs_permission_only",
        0.0,
    )
    precision_delta = comparisons.get(
        "aura_user_actionable_precision_delta_vs_permission_only",
        0.0,
    )
    if false_positive_reduction <= 0:
        failures.append(
            "expected full AURA to reduce non-actionable critical alerts versus permission-only"
        )
    if precision_delta <= 0:
        failures.append(
            "expected full AURA to improve user-actionable precision versus permission-only"
        )
    if model_metrics.get("full_aura", {}).get("controlled_abuse_recall") != 1.0:
        failures.append("expected full AURA controlled-abuse recall to stay at 1.0")
    has_platform_audit_labels = any(
        row.get("label", {}).get("platformAudit") is True
        for row in evaluation.get("rows", [])
    )
    if has_platform_audit_labels and model_metrics.get("full_aura", {}).get("platform_audit_separation") != 1.0:
        failures.append("expected full AURA BLUE platform-audit separation to stay at 1.0")

    if failures:
        raise AssertionError("\n".join(failures))


def capture_logcat() -> None:
    log_path = OUT_DIR / "logcat-tail.txt"
    result = adb("logcat", "-d", "-t", "400", capture=True)
    lines = [
        line
        for line in result.stdout.splitlines()
        if "aura" in line.lower()
        or "flashlight.cleaner.update" in line
        or "FATAL EXCEPTION" in line
    ]
    log_path.write_text("\n".join(lines) + "\n")


def main() -> int:
    restore_state: dict[str, str] | None = None
    original_usage_stats_mode: str | None = None
    build_all()
    offline_analysis_path = analyze_offline_apks()
    assert_offline_analysis(offline_analysis_path)
    ensure_device()
    install_apps()
    try:
        original_usage_stats_mode = current_usage_stats_mode()
        set_usage_stats_mode("ignore")
        remove_lab_special_access()
        baseline_export_path = run_aura_and_pull_export("aura-baseline-scan.json", clear_data=True)
        print(f"Baseline AURA export: {baseline_export_path}")
        restore_state = configure_special_access()
        set_usage_stats_mode("allow")
        launch_sensitive_app()
        export_path = run_aura_and_pull_export("aura-last-scan.json", clear_data=False)
        evaluation_path = evaluate(export_path)
        assert_expectations(export_path)
        assert_evaluation_metrics(evaluation_path)
        capture_logcat()
        print(f"AURA export: {export_path}")
        print(f"Evaluation: {evaluation_path}")
        print("Scenario runner completed successfully.")
        return 0
    finally:
        restore_special_access(restore_state)
        restore_usage_stats_mode(original_usage_stats_mode)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Scenario runner failed: {exc}", file=sys.stderr)
        raise
