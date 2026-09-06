# Security Model

## What SecureMem protects against

An LLM-agnostic security middleware sitting between an AI application, its memory store, and its
LLM provider — see `docs/ARCHITECTURE.md` for the full pipeline diagram. Every prompt and every
memory write passes through the same layered defense before it reaches storage or a model.

## Attack types and defenses

| Attack | Defense | Where |
|---|---|---|
| Prompt injection / instruction override | Groq-classified confidence score, keyword fallback if the LLM call fails | `firewall/detector.py`, `backend/main.py` |
| Jailbreak (role-play, "DAN", etc.) | Same classifier, `attack_type` field distinguishes it | same |
| System prompt extraction | Same classifier | same |
| Memory poisoning | Keyword scan + character-frequency outlier check, combined into `memory_risk_score` | `firewall/poison_detector.py` |
| PII leakage into memory | Regex detection (email, phone, Aadhaar, PAN, credit card, secrets) + redaction before storage | `firewall/pii_detector.py` |
| XSS via memory content | `<script>`/`on*=` stripped before embedding or storage | `firewall/sanitizer.py` |
| Rogue/compromised agent | Trust score decays with injection/poison/role-violation counts; auto-downgrade to READONLY below 0.30 | `firewall/trust_engine.py` |
| Repeated attack bursts | 5+ attacks in 10 minutes → 1-hour agent ban | `firewall/policy_engine.py` |
| Privilege escalation | ADMIN token minting gated behind `ADMIN_BOOTSTRAP_SECRET`; every memory endpoint checks role | `memory/auth.py` |
| IDOR / cross-namespace access | Namespace must equal or be prefixed by the caller's `agent_id` (ADMIN bypasses) | `memory/auth.py::check_namespace_access` |
| Rate/DoS abuse | Per-endpoint slowapi limits (see `docs/AUTH_AUDIT.md` for exact numbers and why) | `firewall/rate_limit.py` |
| Data-at-rest exposure | Fernet (AES) encryption of memory content | `memory/encryption.py` |
| Ambiguous/medium-confidence threats | **Investigator Agent** — real trust-history + similar-memory tool calls, LLM reasoning, fails safe to QUARANTINE on error | `firewall/investigator_agent.py`, `docs/INVESTIGATOR_AGENT.md` |
| Undetected security incidents | Full decision-trail replay for every non-ALLOW event | `firewall/replay.py` |

## Trust model

Every agent has a trust score (0.0–1.0), recalculated from weighted penalties (injection
attempts, poisoning attempts, read/write ratio anomaly, time since last violation, role
violations — see `docs/PROJECT_AUDIT.md`'s formula). Falls below 0.30 → automatic downgrade to
READONLY. Persisted to Postgres so it survives a restart (Batch 7).

## Known, accepted gaps (documented, not silently hidden)

- **`/add_memory` / `/search_memory` (legacy ChromaDB path)** bypass RBAC and encryption
  entirely. Kept for backward compatibility/demo purposes; not used by the gateway or SDK.
  Documented in `docs/PROJECT_AUDIT.md` and `docs/AUTH_AUDIT.md`.
- **`/firewall/check`, `/firewall/check-memory`, `/provenance/*`, `/trust/*` are unauthenticated
  by design** — they're preview/read-only endpoints that don't carry raw sensitive content (see
  `docs/AUTH_AUDIT.md`). The properly ADMIN-gated equivalent for audit data is
  `GET /v1/audit/logs`.
- **AGENT/READONLY token issuance has no real credential check** — there's no user-account system
  in this project. Only ADMIN issuance is gated (`ADMIN_BOOTSTRAP_SECRET`). Documented as a
  deliberate scope tradeoff, not an oversight.
- **PII/poison detection is regex/keyword-based**, not a trained NLP model — will miss
  unusual phrasing. See `docs/PII_SECURITY.md`'s "Known limitations".
- **Embeddings are not separately encrypted** (only `content` is) — see `docs/PROJECT_AUDIT.md`.

See `docs/THREAT_MODEL.md` for attacker-scenario walkthroughs and the OWASP LLM Top 10 mapping.
