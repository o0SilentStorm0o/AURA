#!/usr/bin/env python3
from __future__ import annotations

import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyze_apk import (  # noqa: E402
    ANDROID_NS,
    backup_rules_observation,
    deep_link_surfaces,
    detect_accessibility_data_sensitive,
    detect_filter_touches,
    detect_flag_secure,
    embedded_config_observation,
    network_config_observation,
    third_party_sdk_observation,
    webview_observation,
)


class ApkAnalyzerHeuristicsTest(unittest.TestCase):
    def android_attr(self, name: str) -> str:
        return f"{{{ANDROID_NS}}}{name}"

    def test_detects_deep_link_surfaces(self) -> None:
        application = ET.Element("application")
        activity = ET.SubElement(application, "activity", {self.android_attr("name"): ".CallbackActivity", self.android_attr("exported"): "true"})
        intent_filter = ET.SubElement(activity, "intent-filter", {self.android_attr("autoVerify"): "false"})
        ET.SubElement(intent_filter, "action", {self.android_attr("name"): "android.intent.action.VIEW"})
        ET.SubElement(intent_filter, "category", {self.android_attr("name"): "android.intent.category.BROWSABLE"})
        ET.SubElement(intent_filter, "data", {self.android_attr("scheme"): "demo", self.android_attr("host"): "callback"})

        surfaces = deep_link_surfaces(application)

        self.assertEqual(1, len(surfaces))
        self.assertEqual(".CallbackActivity", surfaces[0]["activity"])
        self.assertEqual("demo", surfaces[0]["scheme"])
        self.assertEqual("callback", surfaces[0]["host"])

    def test_backup_rules_observation_flags_missing_explicit_rules(self) -> None:
        application = ET.Element("application", {self.android_attr("allowBackup"): "true"})

        observation = backup_rules_observation(application, ["res/xml/preferences.xml"])

        self.assertTrue(observation["allowBackup"])
        self.assertFalse(observation["hasExplicitRules"])

    def test_detects_flag_secure_set_flags_pattern(self) -> None:
        dexdump = """
        00020a: invoke-virtual {v2}, Lcom/example/Main;.getWindow:()Landroid/view/Window;
        000212: const/16 v1, #int 8192 // #2000
        000216: invoke-virtual {v0, v1, v1}, Landroid/view/Window;.setFlags:(II)V
        """

        self.assertTrue(detect_flag_secure(dexdump))

    def test_detects_filter_touches_from_code_or_xml(self) -> None:
        self.assertTrue(detect_filter_touches("invoke setFilterTouchesWhenObscured", {}))
        self.assertTrue(
            detect_filter_touches(
                "",
                {"res/layout/screen.xml": 'A: android:filterTouchesWhenObscured="true"'},
            )
        )

    def test_detects_accessibility_data_sensitive_from_xml(self) -> None:
        self.assertTrue(
            detect_accessibility_data_sensitive(
                "",
                {"res/layout/screen.xml": "A: android:accessibilityDataSensitive"},
            )
        )

    def test_network_config_reports_cleartext_files(self) -> None:
        observation = network_config_observation(
            {
                "res/xml/network_security_config.xml": """
                E: network-security-config
                  E: base-config
                    A: android:cleartextTrafficPermitted=(type 0x12)0xffffffff
                  E: debug-overrides
                    E: trust-anchors
                      E: certificates
                        A: android:src="user"
                """
            },
            "@xml/network_security_config",
        )

        self.assertEqual("OBSERVED_ENABLED", observation["observabilityState"])
        self.assertEqual(
            ["res/xml/network_security_config.xml"],
            observation["cleartextPermittedFiles"],
        )
        self.assertEqual(["res/xml/network_security_config.xml"], observation["debugOverridesFiles"])
        self.assertEqual(["res/xml/network_security_config.xml"], observation["userCaTrustFiles"])

    def test_detects_webview_risky_configuration_patterns(self) -> None:
        observation = webview_observation("setJavaScriptEnabled addJavascriptInterface setAllowUniversalAccessFromFileURLs")

        self.assertTrue(observation["observed"])
        self.assertTrue(observation["javascriptEnabled"])
        self.assertTrue(observation["addJavascriptInterface"])
        self.assertTrue(observation["universalAccessFromFileUrls"])

    def test_detects_embedded_config_without_returning_secret_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk_path = Path(tmp) / "sample.apk"
            with zipfile.ZipFile(apk_path, "w") as archive:
                archive.writestr(
                    "assets/config.json",
                    '{"api_key":"AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAA","baseUrl":"https://api.example.com/v1"}',
                )

            observation = embedded_config_observation(apk_path)

            self.assertEqual(1, observation["secretPatternHitCount"])
            self.assertEqual("google_api_key", observation["secretPatternHits"][0]["pattern"])
            self.assertIn("api.example.com", observation["endpointHostSample"])
            self.assertNotIn("AIzaSy", str(observation["secretPatternHits"]))

    def test_detects_third_party_sdk_namespaces(self) -> None:
        observation = third_party_sdk_observation("Lcom/appsflyer/Foo; Lio/sentry/Hub;")

        self.assertEqual(["AppsFlyer", "Sentry"], observation["detectedSdks"])


if __name__ == "__main__":
    unittest.main()
