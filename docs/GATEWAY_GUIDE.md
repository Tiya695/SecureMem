# SecureMem Gateway

`backend/gateway.py` — the single entry point for an external AI application. All endpoints are
under `/v1/`.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/gateway/chat` | none (mirrors `/firewall/check`) | Runs the full pipeline (firewall → PII → poison → policy engine → Investigator Agent on FLAG). If blocked, returns `{blocked: true, reason, confidence}` without ever calling an LLM. If allowed, forwards to the configured LLM provider and returns its response plus security metadata. |
| `POST` | `/v1/security/check` | none | Same pipeline, never forwards to an LLM — for testing/preview. |
| `POST` | `/v1/memory/write` | JWT (forwarded) | Proxies to `POST /memory/write`. |
| `GET` | `/v1/memory/search` | JWT (forwarded) | Proxies to `GET /memory/search`. |
| `DELETE` | `/v1/memory/{id}` | JWT (forwarded) | Proxies to `DELETE /memory/delete`. |
| `GET` | `/v1/trust/{agent_id}` | none | Proxies to `GET /trust/score/{agent_id}`. |
| `GET` | `/v1/audit/logs` | **ADMIN** | Filtered audit log — the properly gated equivalent of the legacy open `/provenance/logs` (kept open for existing dashboard pages, see `docs/AUTH_AUDIT.md`). |
| `GET` | `/v1/quarantine` | **ADMIN** | Quarantine queue (same data as `GET /quarantine/list`). |

None of these duplicate logic — every `/v1/*` handler delegates to the already-tested code in
`firewall/*.py` and `memory/api.py` (via an in-process HTTP call to `http://127.0.0.1:8000`, the
same pattern `memory/api.py`'s own provenance logging already uses).

## Model-agnostic LLM routing (Phase 10A)

`backend/llm_providers.py`'s `call_llm(prompt, conversation_history, provider=None)` reads
`SECUREMEM_LLM_PROVIDER` from `.env`:

```
SECUREMEM_LLM_PROVIDER=groq       # default — free, fast, the only one with a real key here
SECUREMEM_LLM_PROVIDER=openai     # gpt-3.5-turbo
SECUREMEM_LLM_PROVIDER=anthropic  # claude-haiku-4-5
SECUREMEM_LLM_PROVIDER=gemini     # gemini-1.5-flash-8b
SECUREMEM_LLM_PROVIDER=ollama     # local model, no API cost, http://localhost:11434
```

Every provider takes the same input and returns the same shape:
`{"provider": ..., "model": ..., "text": ...}`, or, if the key isn't set (or the package isn't
installed), `{"error": "provider_not_configured", "provider": ...}` — the gateway never crashes
just because an operator hasn't paid for every API. Only Groq has a real key in this project;
the other four connectors are present and switch on cleanly, but their outputs are
`provider_not_configured` until a key is added to `.env`.

## Example

```bash
curl -X POST http://localhost:8000/v1/gateway/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is the capital of France?", "agent_id": "demo_agent"}'
```
