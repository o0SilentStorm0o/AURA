#!/usr/bin/env python3
"""Open a public demo target in Google Play on a connected emulator/device."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any


TARGETS_PATH = Path(__file__).with_name("targets.json")


def load_targets() -> dict[str, dict[str, Any]]:
    data = json.loads(TARGETS_PATH.read_text())
    return {str(item["id"]): item for item in data.get("targets", [])}


def main() -> int:
    targets = load_targets()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target_id", choices=sorted(targets))
    parser.add_argument("--adb", default=os.environ.get("ADB", "adb"))
    args = parser.parse_args()

    target = targets[args.target_id]
    package_name = target["packageName"]
    print(f"Opening Google Play target {target['appName']} ({package_name}) for {target['clientName']}.")
    print("Public demo scope: no login to target app, no MITM, no root, no exploit attempt, no sensitive workflow.")
    print("If Google Play asks for sign-in, stop and sign in manually with a test account before installing.")
    subprocess.run(
        [
            args.adb,
            "shell",
            "am",
            "start",
            "-a",
            "android.intent.action.VIEW",
            "-d",
            f"market://details?id={package_name}",
        ],
        check=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
