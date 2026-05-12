#!/usr/bin/env python3
"""Run a local Ollama + Qdrant smoke test for the AURA LLM/RAG layer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from llm_summary import DEFAULT_COLLECTION, DEFAULT_EMBEDDING_MODEL, load_json, summarize_audit


DEFAULT_AUDIT = Path("artifacts/real_world_validation/grouped/audits/bikeflip-audit.json")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    parser.add_argument("--out", type=Path, default=Path("artifacts/real_world_validation/grouped/audits/llm-rag-smoke-summary.json"))
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--qdrant-url", default="http://localhost:6333")
    parser.add_argument("--model", default="qwen2.5:3b")
    parser.add_argument("--embedding-model", default=DEFAULT_EMBEDDING_MODEL)
    parser.add_argument("--qdrant-collection", default=DEFAULT_COLLECTION + "_ollama")
    parser.add_argument("--llm-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--allow-fallback", action="store_true")
    args = parser.parse_args()

    payload = summarize_audit(
        load_json(args.audit),
        llm_mode="strict",
        local_llm_url=args.ollama_url,
        model=args.model,
        qdrant_url=args.qdrant_url,
        qdrant_collection=args.qdrant_collection,
        embedding_url=args.ollama_url,
        embedding_model=args.embedding_model,
        embedding_mode="ollama",
        llm_timeout_seconds=args.llm_timeout_seconds,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    validation = payload.get("validation") or {}
    retrieval = payload.get("retrieval") or {}
    embedding = retrieval.get("embedding") or {}
    print(f"Wrote {args.out}")
    print(f"source={payload.get('source')}")
    print(f"retrieval={retrieval.get('mode')} embedding={embedding.get('mode')}:{embedding.get('model')}")
    print(f"validation={validation}")

    errors: list[str] = []
    if retrieval.get("mode") != "qdrant":
        errors.append("expected Qdrant retrieval")
    if embedding.get("mode") != "ollama":
        errors.append("expected Ollama embeddings")
    if not args.allow_fallback and validation.get("fallbackUsed"):
        errors.append("LLM fallback was used")
    if not payload.get("groupSummaries"):
        errors.append("no group summaries produced")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
