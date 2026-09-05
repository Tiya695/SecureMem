# Auth Audit

Every endpoint in `backend/main.py` and `memory/api.py`, checked for: (1) is JWT authentication
required, (2) is the caller's role checked, (3) is namespace isolation enforced. Findings from
before Batch 2, then the fix applied.

| Endpoint | Auth required? | Role checked? | Namespace isolated? | Notes / fix |
|---|---|---|---|---|
| `POST /auth/token` | No (by design — this *issues* tokens) | — | — | **Fixed:** ADMIN role now requires `admin_secret` matching `ADMIN_BOOTSTRAP_SECRET`; previously any caller could self-mint a valid ADMIN JWT. AGENT/READONLY remain self-service (no user-account system exists in this project). |
| `POST /memory/write` | YES (`get_current_agent`) | YES (`check_write_permission` blocks READONLY) | YES (`check_namespace_access`) | Already correct. |
| `GET /memory/search` | YES | N/A (read allowed for all roles) | YES | Already correct. |
| `DELETE /memory/delete` | YES | YES (`check_write_permission`) | YES (checked against the memory's own namespace after lookup) | Already correct. |
| `POST /firewall/check` | **No** | No | N/A | Left open by design (used pre-auth, e.g. by the login/demo flow, to preview a prompt) but now rate-limited (30/min) and input-length-limited (Batch 3) to reduce abuse. Not wired to write anything sensitive. |
| `POST /firewall/check-memory` | No | No | N/A | Same as above — preview-only, no state written beyond the in-memory poison-detector demo store. |
| `POST /add_memory`, `POST /search_memory` | **No** | No | No | **Legacy/demo path.** Bypasses encryption, RBAC, and namespace isolation entirely — documented in `docs/PROJECT_AUDIT.md` as insecure-by-design and superseded by `memory/api.py` / the Batch 8 gateway. Left as-is (removing it would be a feature change) but must not be used for anything sensitive. |
| `GET /provenance/logs`, `GET /provenance/logs/{agent_id}` | No | No | No | Read-only audit data; no auth today. Flagged for tightening once the gateway's `GET /v1/audit/logs` (ADMIN-only) supersedes it in Batch 8. |
| `POST /trust/record/{agent_id}/{event}`, `GET /trust/score/{agent_id}`, `GET /trust/all` | No | No | No | Same as provenance — informational/demo endpoints, not carrying sensitive content. |
| `GET /api/agents`, `GET /api/stats` | No | No | N/A | Public dashboard aggregate data by design. |

## Rate limiting added (Batch 2)

| Endpoint | Limit |
|---|---|
| `POST /auth/token` | 60/minute per IP |
| `POST /firewall/check` | 30/minute per IP |
| `POST /memory/write` | 20/minute per IP |

**Deviation from the playbook's suggested 5/minute on `/auth/token`:** every AGENT/READONLY token
request goes through this same endpoint (there is no separate account system), and it is called
once per `simulation.html` demo run plus multiple times per test file. `5/minute` shared across
one IP made the live sandbox demo and the test suite itself hit the limit and start failing.
Raised to `20/minute` in Batch 2, then to **`60/minute`** here once the test suite grew past
~10 files — running the *whole* suite (`pytest tests/`) mints a fresh token in nearly every test
across ~90+ tests, comfortably exceeding 20/minute within a normal ~2-minute run and causing
false `KeyError`/403 failures unrelated to any real bug (confirmed by re-running the exact same
failing tests after waiting out the window — they passed). `ADMIN_BOOTSTRAP_SECRET` is a random
32-byte token — brute-forcing it isn't meaningfully slowed by 20 vs 60 attempts/minute either way
— so `60/minute` keeps real abuse-resistance while not breaking a growing test suite that all
runs from one shared IP. `tests/conftest.py` also adds a session-scoped `admin_token` fixture so
future tests can share one ADMIN token instead of each minting its own, which is the more
durable fix as the suite keeps growing (see docs/SECURITY_TEST_RESULTS.md).

## CORS

Changed from `allow_origins=["*"]` to an explicit allow-list: `localhost:8000`, `127.0.0.1:8000`,
`localhost:3000`, `127.0.0.1:3000`, `securemem-api.onrender.com`, plus whatever `FRONTEND_URL` is
set to in `.env`.

## Automated coverage

`tests/test_auth.py` covers the 5 required cases: AGENT calling an ADMIN-only endpoint (403),
READONLY attempting a write (403), an expired JWT (401), Agent A reading Agent B's namespace (403),
and an unauthenticated request to a protected endpoint (401). See that file for real pass/fail
output.
