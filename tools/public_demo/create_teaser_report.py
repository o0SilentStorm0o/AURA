#!/usr/bin/env python3
"""Create a target-scoped AURA public-surface teaser report from a scan export."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


TARGETS_PATH = Path(__file__).with_name("targets.json")
REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT_GENERATOR = REPO_ROOT / "tools" / "report_generator" / "generate_report.py"


def load_targets() -> dict[str, dict[str, Any]]:
    data = json.loads(TARGETS_PATH.read_text())
    return {str(item["id"]): item for item in data.get("targets", [])}


def main() -> int:
    targets = load_targets()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="AURA scan export JSON")
    parser.add_argument("target_id", choices=sorted(targets))
    parser.add_argument("--evaluation", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--basename")
    parser.add_argument("--salt", default="aura-public-redaction-v1")
    parser.add_argument("--max-findings", type=int, default=3)
    parser.add_argument("--redacted-export-out", type=Path)
    args = parser.parse_args()

    target = targets[args.target_id]
    out_dir = args.out_dir or REPO_ROOT / "artifacts" / "demos" / args.target_id
    basename = args.basename or f"aura-public-teaser-{args.target_id}"
    redacted_out = args.redacted_export_out or out_dir / f"{basename}.export.json"
    command = [
        sys.executable,
        str(REPORT_GENERATOR),
        str(args.export),
        "--report-type",
        "public_teaser",
        "--target-package",
        target["packageName"],
        "--client-name",
        target["clientName"],
        "--public-app-name",
        target["appName"],
        "--public-source-url",
        target["playStoreUrl"],
        "--max-findings",
        str(args.max_findings),
        "--salt",
        args.salt,
        "--out-dir",
        str(out_dir),
        "--basename",
        basename,
        "--redacted-export-out",
        str(redacted_out),
    ]
    if args.evaluation:
        command.extend(["--evaluation", str(args.evaluation)])
    subprocess.run(command, check=True)
    print(f"Teaser generated for {target['clientName']} / {target['appName']}.")
    print("Manual review gate: read the HTML/PDF before sending and remove any wording that sounds accusatory.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
