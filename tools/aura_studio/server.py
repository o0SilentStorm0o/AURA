#!/usr/bin/env python3
"""Local AURA Studio workbench.

This is a small localhost-only web UI over the existing host-side AURA report
pipeline. It intentionally avoids cloud services and heavy frontend tooling:
the Android app remains the collector, while Studio orchestrates profile
selection, app-owner audit generation, optional LLM/RAG wording, and report
rendering on the MacBook host.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


REPO_ROOT = Path(__file__).resolve().parents[2]
STATIC_DIR = Path(__file__).resolve().parent / "static"
STUDIO_ROOT = REPO_ROOT / "artifacts" / "studio"
DEFAULT_EXPORT = REPO_ROOT / "artifacts" / "real_world_validation" / "live" / "aura-last-scan.json"
DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_QDRANT_URL = "http://localhost:6333"
DEFAULT_LLM_MODEL = "qwen2.5:3b"
DEFAULT_EMBEDDING_MODEL = "nomic-embed-text"
DEFAULT_AURA_PACKAGE = "cz.davidstrnadel.aura.research"
APP_PROFILE_CATEGORIES = [
    "ecommerce",
    "chat_social",
    "fintech",
    "banking",
    "health",
    "public_info",
    "public_sector",
    "media",
    "internal_enterprise",
    "sdk_library",
    "utility",
]

sys.path.insert(0, str(REPO_ROOT / "tools" / "report_generator"))
sys.path.insert(0, str(REPO_ROOT / "tools" / "app_owner_audit"))
sys.path.insert(0, str(REPO_ROOT / "tools" / "llm_summary"))

from audit_engine import build_audit  # noqa: E402
from generate_report import mark_target_only_privacy, scope_export_to_package  # noqa: E402
from llm_summary import summarize_audit  # noqa: E402


@dataclass
class StudioConfig:
    host: str
    port: int
    ollama_url: str
    qdrant_url: str
    llm_model: str
    embedding_model: str


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def json_response(handler: BaseHTTPRequestHandler, payload: Any, status: int = 200) -> None:
    body = json.dumps(payload, indent=2, sort_keys=True).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def text_response(handler: BaseHTTPRequestHandler, text: str, status: int = 200, content_type: str = "text/plain; charset=utf-8") -> None:
    body = text.encode()
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def request_json(url: str, timeout: float = 2.0) -> dict[str, Any]:
    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode() or "{}")


def repo_path(value: str | None, *, must_exist: bool = False) -> Path | None:
    if not value:
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = REPO_ROOT / path
    resolved = path.resolve()
    try:
        resolved.relative_to(REPO_ROOT)
    except ValueError as error:
        raise ValueError(f"Path must stay inside the AURA workspace: {value}") from error
    if must_exist and not resolved.exists():
        raise ValueError(f"Path does not exist: {resolved}")
    return resolved


def public_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def safe_artifact_path(value: str) -> Path:
    path = repo_path(value, must_exist=True)
    if path is None:
        raise ValueError("Missing artifact path")
    return path


def run_command(command: list[str], *, timeout: float = 30.0) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            command,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"ok": False, "error": str(error), "stdout": "", "stderr": ""}


def package_rows(export: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for assessment in export.get("assessments", []):
        snapshot = assessment.get("snapshot") or {}
        rows.append(
            {
                "packageName": snapshot.get("packageName"),
                "appLabel": snapshot.get("appLabel") or snapshot.get("packageName"),
                "decision": (assessment.get("decision") or {}).get("color"),
                "role": (assessment.get("role") or {}).get("predicted"),
                "installer": snapshot.get("installerPackageName") or "none_or_unknown",
                "versionCode": snapshot.get("versionCode"),
            }
        )
    return sorted(rows, key=lambda row: str(row.get("appLabel") or row.get("packageName") or "").lower())


def default_profile() -> dict[str, Any]:
    return {
        "appCategory": "ecommerce",
        "dataSensitivity": "medium",
        "releaseStage": "production_candidate",
        "distribution": "google_play",
        "authFlow": True,
        "payments": True,
        "webviewUsageExpected": True,
        "externalIntegrationsExpected": True,
        "allowedCleartextDomains": [],
        "knownExportedComponents": [],
        "acceptedRisks": [],
    }


def health(config: StudioConfig) -> dict[str, Any]:
    adb = run_command(["adb", "devices"], timeout=5.0) if shutil.which("adb") else {"ok": False, "error": "adb not found"}
    devices = []
    if adb.get("ok"):
        for line in adb.get("stdout", "").splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                devices.append({"serial": parts[0], "state": parts[1]})

    ollama_ok = False
    ollama_models: list[str] = []
    try:
        tags = request_json(config.ollama_url.rstrip("/") + "/api/tags")
        ollama_models = [item.get("name") for item in tags.get("models", []) if item.get("name")]
        ollama_ok = True
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
        pass

    qdrant_ok = False
    try:
        request_json(config.qdrant_url.rstrip("/") + "/collections")
        qdrant_ok = True
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
        pass

    return {
        "adb": {"ok": bool(adb.get("ok")), "devices": devices, "detail": adb.get("stderr") or adb.get("error") or ""},
        "ollama": {
            "ok": ollama_ok,
            "url": config.ollama_url,
            "model": config.llm_model,
            "embeddingModel": config.embedding_model,
            "modelReady": config.llm_model in ollama_models,
            "embeddingReady": any(name.startswith(config.embedding_model) for name in ollama_models),
            "models": ollama_models,
        },
        "qdrant": {"ok": qdrant_ok, "url": config.qdrant_url},
        "workspace": str(REPO_ROOT),
    }


def profile_presets() -> dict[str, Any]:
    presets = {"default_ecommerce": default_profile()}
    profile_dir = REPO_ROOT / "tools" / "app_owner_audit" / "profiles"
    for path in sorted(profile_dir.glob("*.json")):
        try:
            presets[path.stem] = load_json(path)
        except ValueError:
            continue
    return {"categories": APP_PROFILE_CATEGORIES, "presets": presets}


def create_run_dir(basename: str) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    clean = "".join(char if char.isalnum() or char in "-_" else "-" for char in basename).strip("-") or "audit"
    path = STUDIO_ROOT / "runs" / f"{stamp}-{clean}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def pull_export_from_adb(body: dict[str, Any]) -> dict[str, Any]:
    package_id = body.get("auraPackage") or DEFAULT_AURA_PACKAGE
    out_dir = STUDIO_ROOT / "imports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"aura-last-scan-{time.strftime('%Y%m%d-%H%M%S')}.json"
    if not shutil.which("adb"):
        raise RuntimeError("adb was not found on PATH")
    proc = subprocess.run(
        ["adb", "exec-out", "run-as", package_id, "cat", "files/exports/aura-last-scan.json"],
        cwd=REPO_ROOT,
        capture_output=True,
        timeout=20.0,
    )
    if proc.returncode != 0 or not proc.stdout:
        raise RuntimeError((proc.stderr or b"ADB export pull failed").decode(errors="replace"))
    out_path.write_bytes(proc.stdout)
    return {"exportPath": public_path(out_path), "bytes": len(proc.stdout)}


def run_audit_pipeline(body: dict[str, Any], config: StudioConfig) -> dict[str, Any]:
    export_path = repo_path(body.get("exportPath") or str(DEFAULT_EXPORT), must_exist=True)
    if export_path is None:
        raise ValueError("exportPath is required")
    target_package = body.get("targetPackage")
    if not target_package:
        raise ValueError("targetPackage is required")

    profile = body.get("profile") if isinstance(body.get("profile"), dict) else default_profile()
    privacy_mode = body.get("privacyMode") or "redacted_expert"
    basename = body.get("basename") or f"aura-studio-{target_package.split('.')[-1]}"
    run_dir = create_run_dir(basename)
    audit_dir = run_dir / "audit"
    report_dir = run_dir / "report"
    profile_path = audit_dir / "app-profile.json"
    scoped_export_path = audit_dir / "scoped-export.json"
    audit_path = audit_dir / "app-owner-audit.json"
    group_summary_path = audit_dir / "group-summary.json"
    redacted_export_path = audit_dir / "redacted-export.json"

    export = load_json(export_path)
    scoped = mark_target_only_privacy(scope_export_to_package(export, target_package))
    write_json(scoped_export_path, scoped)
    write_json(profile_path, profile)

    offline_path = repo_path(body.get("offlineAnalysisPath"), must_exist=True)
    previous_export_path = repo_path(body.get("previousExportPath"), must_exist=True)
    previous_offline_path = repo_path(body.get("previousOfflineAnalysisPath"), must_exist=True)
    offline = load_json(offline_path) if offline_path else None
    audit = build_audit(scoped, offline_analysis=offline, app_profile=profile)
    write_json(audit_path, audit)

    llm_enabled = bool(body.get("llmEnabled", True))
    group_summary: dict[str, Any] | None = None
    if llm_enabled:
        group_summary = summarize_audit(
            audit,
            llm_mode="strict",
            local_llm_url=config.ollama_url,
            model=config.llm_model,
            qdrant_url=config.qdrant_url,
            qdrant_collection="aura_studio_release_risk_docs",
            embedding_url=config.ollama_url,
            embedding_model=config.embedding_model,
            embedding_mode="ollama",
            llm_timeout_seconds=180.0,
        )
    else:
        group_summary = summarize_audit(audit, llm_mode="off")
    write_json(group_summary_path, group_summary)

    command = [
        sys.executable,
        "tools/report_generator/generate_report.py",
        str(export_path),
        "--report-type",
        "app_owner",
        "--target-package",
        target_package,
        "--app-profile",
        str(profile_path),
        "--group-summary-json",
        str(group_summary_path),
        "--out-dir",
        str(report_dir),
        "--basename",
        basename,
        "--privacy-mode",
        privacy_mode,
        "--redacted-export-out",
        str(redacted_export_path),
    ]
    if offline_path:
        command += ["--offline-analysis", str(offline_path)]
    if previous_export_path:
        command += ["--previous-export", str(previous_export_path)]
    if previous_offline_path:
        command += ["--previous-offline-analysis", str(previous_offline_path)]
    report_proc = run_command(command, timeout=240.0)
    if not report_proc.get("ok"):
        raise RuntimeError(report_proc.get("stderr") or report_proc.get("stdout") or "Report generation failed")

    md_path = report_dir / f"{basename}.md"
    html_path = report_dir / f"{basename}.html"
    return {
        "runDir": public_path(run_dir),
        "auditPath": public_path(audit_path),
        "groupSummaryPath": public_path(group_summary_path),
        "reportMarkdownPath": public_path(md_path),
        "reportHtmlPath": public_path(html_path),
        "reportUrl": f"/artifact?path={public_path(html_path)}",
        "redactedExportPath": public_path(redacted_export_path),
        "audit": audit,
        "groupSummary": group_summary,
        "llm": {
            "enabled": llm_enabled,
            "source": group_summary.get("source") if group_summary else "none",
            "validation": group_summary.get("validation") if group_summary else None,
        },
        "reportCommand": report_proc,
    }


class StudioHandler(BaseHTTPRequestHandler):
    config: StudioConfig

    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self.serve_static("index.html")
            elif parsed.path.startswith("/static/"):
                self.serve_static(parsed.path.removeprefix("/static/"))
            elif parsed.path == "/api/health":
                json_response(self, health(self.config))
            elif parsed.path == "/api/profiles":
                json_response(self, profile_presets())
            elif parsed.path == "/api/packages":
                params = parse_qs(parsed.query)
                path = repo_path((params.get("exportPath") or [str(DEFAULT_EXPORT)])[0], must_exist=True)
                json_response(self, {"packages": package_rows(load_json(path)) if path else []})
            elif parsed.path == "/artifact":
                params = parse_qs(parsed.query)
                path = safe_artifact_path(unquote((params.get("path") or [""])[0]))
                content_type = "text/html; charset=utf-8" if path.suffix == ".html" else "text/plain; charset=utf-8"
                text_response(self, path.read_text(errors="replace"), content_type=content_type)
            else:
                json_response(self, {"error": "not_found"}, status=HTTPStatus.NOT_FOUND)
        except Exception as error:  # noqa: BLE001
            json_response(self, {"error": str(error)}, status=HTTPStatus.BAD_REQUEST)

    def do_POST(self) -> None:  # noqa: N802
        try:
            body = self.read_json()
            parsed = urlparse(self.path)
            if parsed.path == "/api/pull-export":
                json_response(self, pull_export_from_adb(body))
            elif parsed.path == "/api/run-audit":
                json_response(self, run_audit_pipeline(body, self.config))
            else:
                json_response(self, {"error": "not_found"}, status=HTTPStatus.NOT_FOUND)
        except Exception as error:  # noqa: BLE001
            json_response(self, {"error": str(error)}, status=HTTPStatus.BAD_REQUEST)

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode())

    def serve_static(self, name: str) -> None:
        path = (STATIC_DIR / name).resolve()
        try:
            path.relative_to(STATIC_DIR.resolve())
        except ValueError as error:
            raise ValueError("Invalid static path") from error
        if not path.exists() or not path.is_file():
            json_response(self, {"error": "static_not_found"}, status=HTTPStatus.NOT_FOUND)
            return
        content_type = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
        }.get(path.suffix, "application/octet-stream")
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        try:
            print(f"[studio] {self.address_string()} - {format % args}", file=sys.stderr)
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    parser.add_argument("--qdrant-url", default=DEFAULT_QDRANT_URL)
    parser.add_argument("--llm-model", default=DEFAULT_LLM_MODEL)
    parser.add_argument("--embedding-model", default=DEFAULT_EMBEDDING_MODEL)
    args = parser.parse_args()
    config = StudioConfig(
        host=args.host,
        port=args.port,
        ollama_url=args.ollama_url,
        qdrant_url=args.qdrant_url,
        llm_model=args.llm_model,
        embedding_model=args.embedding_model,
    )
    StudioHandler.config = config
    server = ThreadingHTTPServer((config.host, config.port), StudioHandler)
    print(f"AURA Studio running at http://{config.host}:{config.port}")
    print(f"Workspace: {REPO_ROOT}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
