# SecureMem AI — Architecture

SecureMem is an **LLM-agnostic security middleware** that sits between an AI application (or
agent) and both its memory store and its LLM provider. Any request — a prompt about to be sent to
an LLM, or a memory write/read — passes through the same security pipeline before it reaches
storage or a model.

## System overview

Two entry points share the same underlying pipeline:

- **Gateway path** (`/v1/gateway/chat`, `/v1/security/check`) — full request: auth → firewall →
  LLM.
- **Memory path** (`/memory/write`, `/memory/search`, `/memory/delete`) — auth → firewall (memory
  poisoning) → policy → encrypted storage.

## Request flow (ASCII)

```
                              AI Application / Agent
                                       |
                                       v
                         ┌─────────────────────────┐
                         │   SecureMem Gateway      │  POST /v1/gateway/chat
                         │  (backend/gateway.py)    │  POST /v1/security/check
                         └────────────┬─────────────┘
                                      v
                         ┌─────────────────────────┐
                         │  Auth / Rate Limit       │  JWT (memory/auth.py)
                         │                          │  slowapi limits
                         └────────────┬─────────────┘
                                      v
                         ┌─────────────────────────┐
                         │  Prompt Firewall         │  firewall/detector.py
                         │  (injection classifier)  │  Groq LLaMA + keyword fallback
                         └────────────┬─────────────┘
                                      v
                         ┌─────────────────────────┐
                         │  PII / Poison Detection  │  firewall/pii_detector.py
                         │                          │  firewall/poison_detector.py
                         └────────────┬─────────────┘
                                      v
                         ┌─────────────────────────┐
                         │  Policy Engine           │  firewall/policy_engine.py
                         │  ALLOW / BLOCK / REDACT / │
                         │  QUARANTINE / FLAG        │
                         └──────┬──────────┬────────┘
                     confidence │          │ confidence
                       > 0.85   │          │ 0.40–0.85 (FLAG)
                                v          v
                        ┌───────────┐  ┌─────────────────────────┐
                        │  BLOCK    │  │  Investigator Agent      │
                        │  (return  │  │  firewall/investigator_  │
                        │  error)   │  │  agent.py — tool calls:  │
                        └───────────┘  │  trust history + vector  │
                                       │  search of past memories,│
                                       │  LLM reasoning over both │
                                       └──────┬──────────┬────────┘
                                    AUTO_CLEAR │          │ QUARANTINE / ESCALATE
                                               v          v
                                          (continue)  quarantine_store
                                               |       (ADMIN review)
                                               v
                         ┌─────────────────────────┐
                         │  Encryption / Memory      │  memory/encryption.py (Fernet)
                         │                            │  memory/models.py (pgvector)
                         └────────────┬───────────────┘
                                      v
                         ┌─────────────────────────┐
                         │  Trust / Provenance        │  firewall/trust_engine.py
                         │                            │  firewall/provenance.py
                         └────────────┬───────────────┘
                                      v
                                     LLM
                          (call_llm(), provider set by
                           SECUREMEM_LLM_PROVIDER env var:
                           groq | openai | anthropic | gemini | ollama)
```

## Component descriptions

- **Gateway** (`backend/gateway.py`) — single entry point for external applications. Runs the full
  pipeline and either returns a block reason or forwards the (now-safe) prompt to an LLM.
- **Auth / Rate Limit** — JWT issuance and verification (`memory/auth.py`), role (ADMIN/AGENT/
  READONLY) and namespace-isolation checks, `slowapi` rate limits on sensitive endpoints.
- **Prompt Firewall** (`firewall/detector.py`) — classifies a prompt for injection/jailbreak
  patterns using Groq LLaMA, with a keyword-based fallback if the LLM call errors or times out.
- **PII / Poison Detection** — `firewall/pii_detector.py` finds and redacts personally identifiable
  information before storage; `firewall/poison_detector.py` scores a memory write for
  poisoning/outlier risk.
- **Policy Engine** (`firewall/policy_engine.py`) — the single decision layer. Combines the
  firewall/PII/poison/trust signals into one of: `ALLOW`, `BLOCK`, `REDACT`, `QUARANTINE`, `FLAG`.
- **Investigator Agent** (`firewall/investigator_agent.py`) — only runs on `FLAG` (confidence
  0.40–0.85, i.e. too uncertain for an automatic block or allow). Pulls the agent's trust history
  and semantically similar past memories as tool calls, reasons over both plus the current input
  with an LLM, and returns `AUTO_CLEAR`, `QUARANTINE`, or `ESCALATE` with a logged rationale —
  instead of a human always having to review every medium-confidence case.
- **Encryption / Memory** — Fernet (AES) encryption of memory content at rest; pgvector-backed
  semantic search scoped by namespace.
- **Trust / Provenance** — every security-relevant event updates the acting agent's trust score and
  is written to an auditable, filterable log.

## Data flow — safe request

```
prompt → auth OK → firewall: not injection → PII: none → policy: ALLOW
       → forwarded to LLM → response returned → provenance logged (outcome=success)
```

## Data flow — blocked attack

```
prompt → auth OK → firewall: injection, confidence 0.93 → policy: BLOCK
       → LLM never called → {blocked: true, reason, confidence} returned
       → trust score decremented → provenance logged (outcome=blocked)
```

## Data flow — medium-confidence (Investigator Agent)

```
prompt → auth OK → firewall: confidence 0.62 → policy: FLAG
       → Investigator Agent:
           tool call 1: get agent's trust history
           tool call 2: vector-search agent's own past memories for similar content
           LLM reasoning over (trust history + similar memories + current input)
           → decision: AUTO_CLEAR | QUARANTINE | ESCALATE, with reasoning
       → AUTO_CLEAR: pipeline continues as ALLOW
       → QUARANTINE/ESCALATE: added to quarantine_store, not forwarded to the LLM
       → full decision trail logged to provenance + investigator_log (replayable)
```

## Technology stack

| Layer | Technology |
|---|---|
| API framework | FastAPI + Uvicorn |
| Prompt classifier / LLM | Groq (LLaMA 3.1 8B Instant); model-agnostic router for OpenAI/Anthropic/Gemini/Ollama |
| Vector search | pgvector (production, per-agent namespace) + ChromaDB (legacy/demo path) |
| Embeddings | sentence-transformers (`all-MiniLM-L6-v2`, 384-dim) |
| Relational storage | PostgreSQL + SQLAlchemy |
| Encryption | Fernet (AES) via `cryptography` |
| Auth | JWT (HS256) via `python-jose` |
| Rate limiting | `slowapi` |
| Testing | `pytest` |
| Deployment | Docker + docker-compose |
