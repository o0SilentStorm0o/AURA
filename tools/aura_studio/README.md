# AURA Studio

AURA Studio is a local browser workbench for app-owner report generation. It
does not replace the Android app. The Android app remains the no-root collector;
Studio runs on the MacBook host and orchestrates the existing host-side tools.

Pipeline:

```text
AURA Android app / emulator
  -> JSON export

AURA Studio on MacBook
  -> target package selection
  -> app profile
  -> app-owner audit engine
  -> optional native Ollama + Qdrant LLM/RAG group wording
  -> report generator
  -> HTML/Markdown report preview
```

Start the local stack:

```bash
OLLAMA_FLASH_ATTENTION=1 OLLAMA_KV_CACHE_TYPE=q8_0 OLLAMA_HOST=127.0.0.1:11434 ollama serve
docker start aura-qdrant || docker run -d --name aura-qdrant -p 127.0.0.1:6333:6333 qdrant/qdrant
```

Required local models:

```bash
ollama pull qwen2.5:3b
ollama pull nomic-embed-text
```

Start Studio:

```bash
python3 tools/aura_studio/server.py
```

Then open:

```text
http://127.0.0.1:8765
```

What the UI can do:

- check ADB, native Ollama, the configured `qwen2.5:3b` model, Ollama
  embeddings, and local Qdrant,
- pull `files/exports/aura-last-scan.json` from the installed research app via
  ADB,
- load packages from an existing AURA export,
- collect a minimal app/customer profile,
- run the app-owner audit engine,
- run strict local LLM/RAG group wording or deterministic template wording,
- generate a redacted app-owner report,
- preview the generated HTML report and show the release status, counts, and
  top review areas.

Design constraints:

- localhost only by default,
- no cloud calls during report generation,
- no frontend build step,
- no LLM decisions: policy findings remain owned by the audit engine,
- artifacts are written under `artifacts/studio/runs/`.

This is intentionally a small operator UI. It should make the report workflow
pleasant without hiding the underlying evidence, policy, and retest artifacts.
