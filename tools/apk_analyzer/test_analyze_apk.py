#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyze_apk import (  # noqa: E402
    detect_accessibility_data_sensitive,
    detect_filter_touches,
    detect_flag_secure,
    network_config_observation,
)


class ApkAnalyzerHeuristicsTest(unittest.TestCase):
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
                """
            },
            "@xml/network_security_config",
        )

        self.assertEqual("OBSERVED_ENABLED", observation["observabilityState"])
        self.assertEqual(
            ["res/xml/network_security_config.xml"],
            observation["cleartextPermittedFiles"],
        )


if __name__ == "__main__":
    unittest.main()
