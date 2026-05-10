#!/usr/bin/env python3
"""Collect APK metadata from an extracted Android firmware tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def partition_guess(relative_path: str) -> str:
    first = relative_path.split("/", 1)[0].lower()
    if first in {"system", "product", "vendor", "odm", "oem", "system_ext"}:
        return first
    return "unknown"


def collect(root: Path) -> dict:
    root = root.resolve()
    apks = []
    for apk in sorted(root.rglob("*.apk")):
        if not apk.is_file():
            continue
        relative = apk.relative_to(root).as_posix()
        stat = apk.stat()
        apks.append(
            {
                "path": str(apk),
                "relativePath": relative,
                "sizeBytes": stat.st_size,
                "sha256": sha256(apk),
                "partitionGuess": partition_guess(relative),
            }
        )
    return {
        "schemaVersion": 1,
        "generatedAt": int(time.time() * 1000),
        "root": str(root),
        "apkCount": len(apks),
        "apks": apks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Extracted firmware/root directory")
    parser.add_argument("--out", type=Path, help="Optional output JSON path")
    args = parser.parse_args()

    if not args.root.exists() or not args.root.is_dir():
        parser.error(f"{args.root} is not a directory")

    payload = collect(args.root)
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
