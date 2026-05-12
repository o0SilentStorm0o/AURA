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
python3 tools/aura_studio/server.py --host 127.0.0.1 --port 8765
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

Recommended operator flow:

1. Start native Ollama and local Qdrant.
2. Start Studio and confirm the health panel is green for ADB, Ollama,
   embeddings, and Qdrant.
3. Pull the latest AURA export from the emulator or load an existing export.
4. Select the target package.
5. Pick or edit the app profile: category, sensitivity, release stage, expected
   auth/payment/WebView/integration behavior, known exported components, and
   cleartext exceptions.
6. Run the audit with LLM enabled for customer-facing wording, or disabled for
   deterministic template wording.
7. Review the generated HTML report, Markdown report, audit JSON, and group
   summary JSON before sending anything to a customer.

LLM/RAG status meanings:

- `Local LLM validated`: native Ollama returned schema-valid wording and strict
  validation accepted it.
- `Template summary`: deterministic wording was used, usually because LLM was
  disabled.
- `Template fallback after LLM error` or `Template fallback after invalid LLM`:
  the audit/report is still usable, but the LLM wording was rejected or timed
  out and the deterministic template was used.
- `No review areas to summarize`: the app-owner audit generated no release-risk
  finding groups. This is a valid PASS/no-findings state, not an LLM failure.

Design constraints:

- localhost only by default,
- no cloud calls during report generation,
- no frontend build step,
- no LLM decisions: policy findings remain owned by the audit engine,
- artifacts are written under `artifacts/studio/runs/`.

Current product boundary:

- Studio is an operator workbench, not the Android app UI.
- Studio does not install Google Play apps automatically.
- Studio does not run root, Frida, MITM, or exploit checks.
- Studio does not replace the pre-send triage checklist. Every customer-facing
  report still needs human review for tone, duplicates, context, and P1
  calibration.

This is intentionally a small operator UI. It should make the report workflow
pleasant without hiding the underlying evidence, policy, and retest artifacts.
