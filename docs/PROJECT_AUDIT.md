# SecureMem AI — Project Audit

**Date:** 2026-08-27
**Scope:** Full repository audit per Phase 0 of the Master Cloud Playbook. Read every file in
`backend/`, `firewall/`, `memory/`, `frontend/`, `sdk/`, `tests/`, `docs/`. No files were modified
during this audit — this document reflects the state of the repo *before* the implementation
batches described in the project plan.

This audit found the codebase to be a genuinely early build. The README describes a more complete
system than what is implemented — several claims (100% JWT-enforced, fully encrypted memory,
"25/25 attacks caught" as a live figure) are only partially true today. That gap is exactly what
the batches following this audit close.

---

## Component status

| Component | File(s) | What it does | Working | Security status | Action needed |
|---|---|---|---|---|---|
| Prompt injection firewall | `firewall/detector.py`, `backend/main.py:/firewall/check` | Groq LLaMA classifies a prompt for injection/jailbreak; keyword fallback if the LLM call fails or times out | YES | NEEDS_REVIEW — no auth, no rate limit | Add auth/rate limiting (Batch 2); wire into policy engine (Batch 5) |
| Memory poisoning detector | `firewall/poison_detector.py` | Keyword scan + toy character-frequency cosine-similarity outlier check on `/firewall/check-memory` | YES (basic) | NEEDS_REVIEW — trivially bypassable by rephrasing, no auth | Add `memory_risk_score`, integrate with policy engine (Batch 5) |
| Trust scoring engine | `firewall/trust_engine.py` | In-memory per-agent trust score (0–1) from injection/poison/role-violation counts; auto-downgrades to READONLY below 0.30 | YES | NEEDS_REVIEW — in-memory only, lost on restart | Persist to DB (Batch 7) |
| Provenance log | `firewall/provenance.py` | In-memory append-only log of memory operations | YES (basic) | NEEDS_REVIEW — in-memory only, minimal fields, no filters | Extend fields + filters + persistence (Batch 7) |
| Authenticated memory API | `memory/api.py`, `memory/auth.py`, `memory/models.py` | JWT-issued via `/auth/token`; `POST /memory/write`, `GET /memory/search`, `DELETE /memory/delete` all require a valid token; RBAC (ADMIN/AGENT/READONLY) and namespace isolation enforced per-route; content AES-256(Fernet)-encrypted at rest in Postgres+pgvector | YES | **INSECURE** — `/auth/token` performs **zero credential verification**; any caller can self-issue a valid ADMIN JWT | Gate ADMIN token issuance behind a bootstrap secret (Batch 2) |
| Legacy unauthenticated memory path | `backend/main.py:/add_memory`, `/search_memory` | Direct ChromaDB read/write, no auth, no encryption, no RBAC | YES (but insecure) | **INSECURE** — completely bypasses every control built into `memory/api.py` | Document as legacy/demo-only; do not use for anything sensitive; superseded by the Batch 8 gateway |
| CORS | `backend/main.py` | `allow_origins=["*"]`, all methods/headers | YES | **INSECURE** — wide open | Restrict to explicit allow-list (Batch 2) |
| Rate limiting | — | None anywhere in the repo (`slowapi` not installed) | NO | **INSECURE** — `/auth/token`, `/firewall/check`, memory endpoints all unthrottled | Add `slowapi` limits (Batch 2) |
| Global error handling | `backend/main.py` | None — unhandled exceptions return default FastAPI 500 with traceback details | NO | NEEDS_REVIEW — no info leakage confirmed but no protection either | Add global handler returning `{error, correlation_id}` (Batch 2) |
| Input validation | `memory/api.py`, `backend/main.py` | Pydantic models exist but no `max_length` constraints; ORM used everywhere (no raw SQL, no injection risk found) | PARTIAL | NEEDS_REVIEW | Add length limits + basic sanitization (Batch 3) |
| PII detection | — | Does not exist | NO | INSECURE — PII can be written to memory unredacted | Build `firewall/pii_detector.py` (Batch 4) |
| Policy engine | — | Does not exist | NO | — | Build `firewall/policy_engine.py` (Batch 5) |
| Quarantine | — | Does not exist | NO | — | Build alongside policy engine (Batch 5) |
| Investigator Agent | — | Does not exist | NO | — | Build `firewall/investigator_agent.py` (Batch 5) — the user-specified centerpiece feature |
| Memory versioning/rollback | — | Does not exist | NO | — | Build (Batch 6) |
| Gateway | — | `backend/gateway.py` does not exist | NO | — | Build (Batch 8) |
| SDK | `sdk/securemem_sdk.py` | `write_memory`, `search_memory`, `delete_memory`, `get_trust_score` all work against the real backend | PARTIAL | SECURE | Add `connect()`, `protect()`, `rollback()` (Batch 9); fix broken README usage example |
| Docker | — | No `Dockerfile`/`docker-compose.yml` | NO | — | Build (Batch 10) — Docker confirmed available in this environment |
| Multi-LLM connectors | — | Only Groq is wired; no OpenAI/Anthropic/Gemini keys in `.env` | PARTIAL | — | Build connectors, mark unavailable providers PENDING (Batch 11) |
| Dashboard (`frontend/dashboard.html`) | — | Two of its four backend calls (`/provenance/logs`, `/trust/score/{id}`) use a broken string-concatenation fetch URL and always fail silently into randomized fallback data; `/api/stats` itself pads real counts with a hardcoded floor/constant | PARTIAL | NEEDS_REVIEW | Fix the two broken fetch calls and stop padding `/api/stats` (Batch 2 & 13) — **no visual change** |
| Admin panel (`frontend/admin.html`) | — | A dead, unclosed `loadAgents()` function breaks parsing of its entire second `<script>` block, so the review-queue UI never runs live | NO (silently) | NEEDS_REVIEW | Close the function properly (Batch 2) — **no visual change** |
| Login (`frontend/login.html`) | — | Same broken-fetch bug as dashboard; real `/auth/token` login never actually reaches the backend today — all "successful" logins are a client-side `localStorage` fallback with base64("encoded") passwords | NO (silently) | NEEDS_REVIEW | Fix the fetch bug (Batch 2) — **no visual change** |
| Simulation / sandbox (`frontend/simulation.html`) | — | Working 5-step live pipeline against the real backend (auth → firewall → poison-check → trust → memory write); intentionally continues past an auth failure in "demo mode" (commit `446b407`) | YES | NEEDS_REVIEW (intentional demo behavior, left as-is) | Reused as the project's sandbox per user decision — no new page built |
| Documentation | `docs/*.md`, `sdk/README.md` | RBAC test results, trust simulation, firewall F1 results, protocol spec all exist; most `docs/*.md` and `sdk/README.md` contain escaped-Markdown artifacts (`\#`, `\*\*`, `&amp;#x20;`); port numbers are inconsistent across docs (8000/8001/8002) | PARTIAL | — | Clean up as touched; reconcile ports (ongoing) |

---

## Additional finding during Batch 2 verification: dead LLM classifier model

While running the test suite live against the server, `/firewall/check` was found to be silently
falling back to its keyword-matching branch on *every* request — the configured
`GROQ_MODEL=llama-3.1-8b-instant` no longer exists on Groq's API (`404 model_not_found`; confirmed
via `client.models.list()`, which no longer lists any `llama-3.x` model at all). This means the
"Groq LLaMA classifier" the README and `docs/firewall_results.md` describe has likely been running
as the much weaker keyword fallback for some time, which calls into question the historical
"F1 = 1.00 / 25 attacks caught" figures (they may have been computed before Groq deprecated the
model, or against the fallback path — undetermined from the repo alone).

**Fixed:** `.env`'s `GROQ_MODEL` updated to `openai/gpt-oss-20b` (verified live against Groq: fast,
returns clean JSON matching the classifier's expected schema, correctly classifies both the
previously-failing extraction-attack test case and normal prompts). `.env.example` documents why.
Real F1/precision/recall numbers should be re-run (see Batch 11 / `docs/MULTI_LLM_RESULTS.md`)
now that the classifier is actually calling an LLM again rather than the keyword fallback.

## Summary of INSECURE findings (highest priority)

1. `POST /auth/token` mints a valid ADMIN JWT for any caller with zero credential check.
2. Wildcard CORS (`*` for origins/methods/headers).
3. No rate limiting on any endpoint.
4. `/add_memory` / `/search_memory` bypass all authentication, encryption, and RBAC that
   `memory/api.py` enforces.
5. `/api/stats` reports partially fabricated numbers (`max(blocked, 25)`, hardcoded
   `safe_memories: 45205`) instead of only real computed values.

All five are addressed starting in Batch 2 of the implementation plan.
