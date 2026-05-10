#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
from collect_apks import collect, partition_guess


class FirmwareInventoryTest(unittest.TestCase):
    def test_partition_guess_uses_android_top_level_directories(self) -> None:
        self.assertEqual("system", partition_guess("system/priv-app/A/A.apk"))
        self.assertEqual("vendor", partition_guess("vendor/app/B/B.apk"))
        self.assertEqual("unknown", partition_guess("random/app/C.apk"))

    def test_collects_apk_metadata_without_parsing_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "system" / "priv-app" / "Demo" / "Demo.apk"
            apk.parent.mkdir(parents=True)
            apk.write_bytes(b"not a real apk")

            payload = collect(root)

        self.assertEqual(1, payload["apkCount"])
        self.assertEqual("system/priv-app/Demo/Demo.apk", payload["apks"][0]["relativePath"])
        self.assertEqual("system", payload["apks"][0]["partitionGuess"])
        self.assertEqual(64, len(payload["apks"][0]["sha256"]))


if __name__ == "__main__":
    unittest.main()
