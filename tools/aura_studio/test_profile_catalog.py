#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO_ROOT / "tools" / "app_owner_audit"))

from audit_engine import CATEGORY_POLICY_PACKS, load_policy_packs, policy_pack_paths  # noqa: E402
from server import APP_PROFILE_CATEGORIES, profile_presets  # noqa: E402


class AuraStudioProfileCatalogTest(unittest.TestCase):
    def test_every_studio_category_has_a_policy_pack(self) -> None:
        categories = set(APP_PROFILE_CATEGORIES)

        self.assertEqual(categories, set(CATEGORY_POLICY_PACKS))
        for category in APP_PROFILE_CATEGORIES:
            profile = {"appCategory": category, "releaseStage": "production_candidate"}
            path_names = [path.name for path in policy_pack_paths(profile)]
            policy_pack_ids = [pack["policyPackId"] for pack in load_policy_packs(profile)]

            self.assertIn("base_android_release_policy.json", path_names)
            self.assertIn(CATEGORY_POLICY_PACKS[category], path_names)
            self.assertIn("production_release_policy.json", path_names)
            self.assertIn(Path(CATEGORY_POLICY_PACKS[category]).stem, policy_pack_ids)

    def test_every_profile_preset_uses_a_known_studio_category(self) -> None:
        payload = profile_presets()
        categories = set(payload["categories"])

        self.assertEqual(categories, set(APP_PROFILE_CATEGORIES))
        self.assertIn("public_sector.example", payload["presets"])
        for name, profile in payload["presets"].items():
            with self.subTest(profile=name):
                self.assertIn(profile.get("appCategory"), categories)


if __name__ == "__main__":
    unittest.main()
