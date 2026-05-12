# AURA LLM/RAG Summary Layer

This host-side tool turns already-computed app-owner `FindingGroup` objects into concise CTO-facing summaries.

It is intentionally not part of policy scoring:

- it cannot create findings,
- it cannot change priority/status/severity,
- it cannot add evidence,
- it must reference existing `groupId`, `findingIds`, and retrieved `doc_id` values.

Basic deterministic mode:

```bash
python3 tools/llm_summary/llm_summary.py \
  artifacts/audit.json \
  --out artifacts/audit-group-summaries.json \
  --llm-mode off
```

Supported local Ollama mode:

```bash
python3 tools/llm_summary/llm_summary.py \
  artifacts/audit.json \
  --out artifacts/audit-group-summaries.json \
  --llm-mode strict \
  --local-llm-url http://localhost:11434 \
  --model qwen2.5:3b
```

The recommended runtime for AURA report wording is native macOS Ollama with
Metal acceleration and `qwen2.5:3b`. Smaller models such as `qwen2.5:1.5b`
were faster in smoke tests but failed the strict output schema for this use
case. Keep Qdrant local and bound to localhost:

```bash
brew install ollama
OLLAMA_FLASH_ATTENTION=1 OLLAMA_KV_CACHE_TYPE=q8_0 OLLAMA_HOST=127.0.0.1:11434 ollama serve
ollama pull qwen2.5:3b
ollama pull nomic-embed-text
docker run -d --name aura-qdrant -p 127.0.0.1:6333:6333 qdrant/qdrant

python3 tools/llm_summary/llm_summary.py \
  artifacts/audit.json \
  --out artifacts/audit-group-summaries.json \
  --llm-mode strict \
  --local-llm-url http://localhost:11434 \
  --model qwen2.5:3b \
  --qdrant-url http://localhost:6333 \
  --embedding-url http://localhost:11434 \
  --embedding-model nomic-embed-text \
  --embedding-mode ollama \
  --llm-timeout-seconds 180
```

Model pulls require network access during setup. Once the models and RAG docs
are local, report wording can run without sending audit data to a cloud service.

The RAG path stores the controlled local docs in Qdrant using Ollama embeddings
and records retrieval metadata in the output:

```json
{
  "retrieval": {
    "mode": "qdrant",
    "embedding": {
      "mode": "ollama",
      "model": "nomic-embed-text",
      "dimension": 768
    }
  }
}
```

Manual integration smoke test:

```bash
python3 tools/llm_summary/run_llm_rag_smoke.py \
  --audit artifacts/real_world_validation/grouped/audits/bikeflip-audit.json
```

If Qdrant or the local LLM is unavailable, the tool falls back to deterministic local retrieval and template summaries.

In `strict` mode the tool prompts the LLM one finding group at a time. This is
slower on small local models, but safer for large real-world apps: a timeout or
invalid model response for one group can fall back to the deterministic template
without allowing the LLM to invent group IDs, finding IDs, evidence, or severity.

Prompt-injection and product-copy guardrails:

- app labels, package names, component names, evidence strings, and retrieved
  docs are treated as untrusted input in the system prompt,
- output is rejected if it references unknown `groupId`, `findingIds`, or
  `doc_id` values,
- customer-facing wording is linted for unsafe claims and report-mechanics
  phrasing such as "AURA has grouped", "vulnerability", "unsafe", "guarantee",
  or first-person "our app" copy,
- validated LLM text may improve summaries and review questions only; policy
  findings, priority, status, evidence, and retest fingerprints remain owned by
  the app-owner audit engine.
