# API Specification

Base URL: `http://localhost:8000` (dev) — see `docs/DOCKER.md` for the containerized deployment.

Auth: JWT bearer token (`Authorization: Bearer <token>`), obtained from `POST /auth/token`.
Three roles: `ADMIN` (any namespace), `AGENT` (own namespace only), `READONLY` (read-only, own
namespace only). See `docs/AUTH_AUDIT.md` for exactly which endpoints require which role.

## Auth

| Method | Endpoint | Auth | Body | Notes |
|---|---|---|---|---|
| `POST` | `/auth/token` | none | `{agent_id, role, admin_secret?}` | Issues a JWT. `role: "ADMIN"` requires `admin_secret` to match `ADMIN_BOOTSTRAP_SECRET`. Rate limited 150/min/IP. |

## Memory

| Method | Endpoint | Auth | Body / Params | Notes |
|---|---|---|---|---|
| `POST` | `/memory/write` | JWT | `{agent_id, content, namespace, metadata?}` | Runs sanitize → PII redact → poison check → policy engine before storing. Returns `{status: stored\|blocked\|quarantined, ...}`. Rate limited 100/min/IP. |
| `GET` | `/memory/search` | JWT | `agent_id, query, namespace, top_k?` | pgvector cosine-similarity search, namespace-scoped. |
| `DELETE` | `/memory/delete` | JWT | `{memory_id}` | |
| `POST` | `/memory/{id}/update` | JWT | `{content, change_reason?}` | Same write-time pipeline as `/memory/write`; versions the prior content first. Rate limited 100/min/IP. |
| `GET` | `/memory/{id}/history` | **ADMIN** | — | Full version history, oldest first. |
| `POST` | `/memory/{id}/rollback/{version}` | **ADMIN** | — | Restores prior content as a new version (doesn't delete newer versions). |

## Firewall / security pipeline

| Method | Endpoint | Auth | Body | Notes |
|---|---|---|---|---|
| `POST` | `/firewall/check` | none | `{prompt, agent_id}` | Groq-classified injection detection + policy engine + Investigator Agent (on FLAG). Rate limited 30/min/IP. |
| `POST` | `/firewall/check-memory` | none | `{content, agent_id}` | Keyword + outlier poison detection. |

## Policy / quarantine

| Method | Endpoint | Auth | Notes |
|---|---|---|---|
| `GET` | `/quarantine/list` | **ADMIN** | Pending items from `firewall/policy_engine.py`'s `quarantine_store`. |
| `POST` | `/quarantine/approve/{id}` | **ADMIN** | |
| `DELETE` | `/quarantine/reject/{id}` | **ADMIN** | |

## Investigator Agent

| Method | Endpoint | Auth | Notes |
|---|---|---|---|
| `GET` | `/investigator/logs` | **ADMIN** | Last 100 investigations — tool-call trail (trust history, similar memories) + decision + reasoning. |

## Attack replay

| Method | Endpoint | Auth | Notes |
|---|---|---|---|
| `GET` | `/v1/audit/replay` | **ADMIN** | Last 100 non-ALLOW events, full decision trail. |
| `GET` | `/v1/audit/replay/{event_id}` | **ADMIN** | One event's full trail. |

## Trust / provenance

| Method | Endpoint | Auth | Notes |
|---|---|---|---|
| `POST` | `/trust/record/{agent_id}/{event}` | none | `event`: `injection_attempt \| poisoning_attempt \| read \| write \| role_violation`. |
| `GET` | `/trust/score/{agent_id}` | none | |
| `GET` | `/trust/all` | none | All tracked agents. |
| `POST` | `/provenance/log` | none | Extended fields all optional — see `docs/AUTH_AUDIT.md` for why this stays open. |
| `GET` | `/provenance/logs` | none | Filters: `agent_id, outcome, decision, date_from, date_to`. |
| `GET` | `/provenance/logs/{agent_id}` | none | |

## Gateway (`/v1/*`)

| Method | Endpoint | Auth | Notes |
|---|---|---|---|
| `POST` | `/v1/gateway/chat` | none | `{message, agent_id, conversation_history?}`. Full pipeline; forwards to the LLM configured by `SECUREMEM_LLM_PROVIDER` only if allowed. |
| `POST` | `/v1/security/check` | none | Same pipeline, never forwards to an LLM. |
| `POST` | `/v1/memory/write` | JWT (forwarded) | Proxies `/memory/write`. |
| `GET` | `/v1/memory/search` | JWT (forwarded) | Proxies `/memory/search`. |
| `DELETE` | `/v1/memory/{id}` | JWT (forwarded) | Proxies `/memory/delete`. |
| `GET` | `/v1/trust/{agent_id}` | none | Proxies `/trust/score/{agent_id}`. |
| `GET` | `/v1/audit/logs` | **ADMIN** | Filtered audit log — the gated equivalent of `/provenance/logs`. |
| `GET` | `/v1/quarantine` | **ADMIN** | Same data as `/quarantine/list`. |

## Legacy / demo (unauthenticated, unencrypted — see `docs/PROJECT_AUDIT.md`)

| Method | Endpoint | Notes |
|---|---|---|
| `POST` | `/add_memory` | ChromaDB direct write, no RBAC/encryption. Sanitized (Phase 4) but otherwise not part of the secured pipeline. |
| `POST` | `/search_memory` | ChromaDB direct search. |

## Misc

| Method | Endpoint | Notes |
|---|---|---|
| `GET` | `/api/health` | |
| `GET` | `/api/agents` | Known agent IDs (falls back to a 5-name demo set if none tracked yet). |
| `GET` | `/api/stats` | Dashboard aggregate stats — all real, see Batch 13 in `docs/PROJECT_AUDIT.md`. |

## Error shapes

- `401` — `{"detail": "..."}` (auth failures)
- `403` — `{"detail": "..."}` (RBAC/namespace failures)
- `404` — `{"detail": "..."}`
- `422` — FastAPI validation error (oversized/malformed input)
- `429` — `{"error": "Rate limit exceeded: ..."}`
- `500` — `{"error": "Internal server error", "correlation_id": "<uuid>"}` — never a raw traceback.
