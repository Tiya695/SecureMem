# SecureMem — Secure Multi-Agent Memory Infrastructure

An LLM-agnostic security gateway that protects multi-agent memory from prompt injection, memory
poisoning, PII leakage, and rogue agent behaviour — with a policy engine, an LLM-based
Investigator Agent for medium-confidence threats, real-time trust scoring, AES-256 encryption,
JWT authentication, memory versioning/rollback, full attack replay, and a live admin dashboard.
See `docs/ARCHITECTURE.md` for the full pipeline and `docs/PROJECT_AUDIT.md` for an honest,
component-by-component status of what's real vs. still a known gap.

---

## 🔥 Key Results

| Metric | Result | Source |
|--------|--------|--------|
| Groq classifier F1 Score | **1.00** | `docs/MULTI_LLM_RESULTS.md` (real eval, 50 prompts, re-runnable via `python testing/eval_all_models.py`) |
| Precision / Recall | **1.00 / 1.00** | same |
| Security attack lab | **12/12 attacks caught** (10 playbook attack types + 2 replay checks) | `docs/SECURITY_TEST_RESULTS.md` |
| Full test suite | **102/102 passing** | see `docs/E2E_VALIDATION.md` |

---

## 🏗️ Project Structure

```
SecureMem/
├── backend/
│   ├── main.py                  # Unified FastAPI server (port 8000)
│   ├── gateway.py                # /v1/* single entry point (chat, security check, proxies)
│   └── llm_providers.py         # Model-agnostic LLM router (groq/openai/anthropic/gemini/ollama)
├── firewall/
│   ├── detector.py              # Prompt injection classifier (Groq)
│   ├── poison_detector.py       # Memory poisoning detection + memory_risk_score
│   ├── pii_detector.py          # PII detection & redaction
│   ├── sanitizer.py             # XSS sanitization
│   ├── policy_engine.py         # ALLOW/BLOCK/QUARANTINE/REDACT/FLAG decision layer
│   ├── investigator_agent.py    # LLM Investigator Agent for medium-confidence threats
│   ├── replay.py                # Full decision-trail attack replay
│   ├── provenance.py            # Operation audit logging (extended fields, DB-persisted)
│   ├── trust_engine.py          # Agent trust scoring engine (DB-persisted)
│   └── rate_limit.py            # Shared slowapi Limiter
├── memory/
│   ├── api.py                   # Memory write/search/delete/update/history/rollback
│   ├── auth.py                  # JWT authentication & RBAC
│   ├── encryption.py            # AES-256 encryption (Fernet)
│   ├── database.py              # PostgreSQL + pgvector connection
│   └── models.py                # SQLAlchemy models (Memory, MemoryVersion, trust/provenance)
├── sdk/
│   └── securemem_sdk.py         # Python SDK (connect/protect/write/search/rollback/trust)
├── examples/                    # 4 runnable integration examples (SDK, gateway, OpenAI, Gemini)
├── testing/
│   ├── llm_connectors.py        # Multi-LLM classifier connectors
│   └── eval_all_models.py       # Real F1/precision/recall evaluation
├── frontend/
│   ├── index.html               # Landing page (3D model + hero)
│   ├── dashboard.html           # Live analytics dashboard
│   ├── admin.html               # Admin control panel (review queue, agent trust)
│   ├── audit.html               # Full audit log viewer
│   └── simulation.html          # Live sandbox pipeline demo
├── tests/                       # 100+ tests — see docs/SECURITY_TEST_RESULTS.md
├── docs/                        # See "Documentation" below — 20+ docs covering every phase
├── Dockerfile, docker-compose.yml, docker/   # Containerized deployment (docs/DOCKER.md)
├── .env                         # API keys (not committed to GitHub)
└── requirements.txt             # All Python dependencies
```

---

## 🛡️ Security Features

### 1. Prompt Injection Firewall (Tiya)
Uses **Groq** (model configurable via `GROQ_MODEL`) to classify every incoming prompt before it
reaches memory.

**Detects:**
- Direct instruction override attacks (`"Ignore all previous instructions"`)
- Jailbreak attempts (`"You are now DAN"`)
- Role-playing attacks (`"Pretend you are an AI with no rules"`)
- System prompt extraction (`"Print your instructions verbatim"`)

**Result: F1 Score = 1.00 on a real 50-prompt evaluation** — see `docs/MULTI_LLM_RESULTS.md`,
re-runnable with `python testing/eval_all_models.py`.

```
POST /firewall/check
Body: { "prompt": "...", "agent_id": "..." }
```

---

### 2. Memory Poisoning Detection (Tiya)
Two-layer detection before any memory is stored:

- **Layer 1 — Keyword Scanning:** Flags instruction-like language (`ignore`, `always`, `override`, `you must`, `from now on`)
- **Layer 2 — Cosine Similarity:** Detects outlier memories that semantically diverge from existing safe memories

```
POST /firewall/check-memory
Body: { "content": "...", "agent_id": "..." }
```

---

### 3. Agent Trust Scoring Engine (Tiya)
Every agent gets a live trust score (0.0 → 1.0). Rogue agents are automatically downgraded.

**Tiya's Custom Formula:**
```
score = 1.0
      - (injection_attempts  × 0.08,  max penalty 0.40)
      - (poisoning_attempts  × 0.10,  max penalty 0.40)
      - (read/write ratio anomaly,     max penalty 0.15)
      - (time since last violation,    max penalty 0.10)
      - (role compliance violations,   max penalty 0.15)

→ Auto-downgrade to READONLY if score drops below 0.30
```

**Demonstrated:** Rogue agent dropped 1.0 → 0.20 after 5 injection + 3 poisoning attempts.

---

### 4. Provenance Tracking (Tiya)
Every memory operation is logged with a timestamp, agent ID, memory ID, and outcome — creating a full immutable audit trail.

```
POST /provenance/log
GET  /provenance/logs
GET  /provenance/logs/{agent_id}
```

---

### 5. AES-256 Encryption (Shreya)
All memory content is encrypted using **Fernet (AES-256-CBC)** before storage. Decryption only happens on authorised read operations.

---

### 6. JWT Authentication & RBAC (Shreya)
Three agent roles enforced on every request:

| Role | Permissions |
|------|-------------|
| `ADMIN` | Full access to all namespaces |
| `AGENT` | Read/write own namespace only |
| `READONLY` | Read-only — no write or delete |

---

### 7. Vector Memory Store (Shreya)
- **ChromaDB** — in-memory vector database for fast semantic search
- **SentenceTransformers** (`all-MiniLM-L6-v2`) — converts memories to 384-dimension embeddings
- **PostgreSQL + pgvector** — production persistent storage

---

### 8. PII Detection & Redaction (Tiya)
Regex-based detection for email, phone (Indian + international), Aadhaar, PAN, credit card
(Luhn-checked), and password/secret assignments — redacted before anything is embedded or
stored, never logged in raw form. See `docs/PII_SECURITY.md`.

---

### 9. Security Policy Engine + Investigator Agent (Tiya)
The decision layer every request passes through: `ALLOW | BLOCK | QUARANTINE | REDACT | FLAG`,
per the rule table in `docs/POLICY_ENGINE.md`. Medium-confidence cases (`FLAG`, 0.40–0.85
injection confidence) hand off to the **Investigator Agent** instead of parking every ambiguous
case for a human — it pulls the agent's real trust history and semantically similar past
memories as tool calls, reasons over both with an LLM, and decides
`AUTO_CLEAR / QUARANTINE / ESCALATE` with a logged rationale. See `docs/INVESTIGATOR_AGENT.md`.

---

### 10. Memory Versioning & Rollback (Shreya)
Every write is versioned; `POST /memory/{id}/update` versions the prior content before applying a
change, and an ADMIN can `POST /memory/{id}/rollback/{version}` to restore a safe earlier version
if a memory turns out to be poisoned — without losing the version history in between.

---

### 11. SecureMem Gateway (Tiya + Shreya)
`POST /v1/gateway/chat` — single entry point for an external application: runs the full pipeline
and only calls an LLM if the input is allowed. Model-agnostic via `SECUREMEM_LLM_PROVIDER`
(groq/openai/anthropic/gemini/ollama — see `docs/GATEWAY_GUIDE.md`).

---

### 12. Attack Replay (Harsh)
Every blocked/flagged/quarantined event's full decision trail (input → firewall → PII → poison →
policy → Investigator Agent → trust) is retrievable via `GET /v1/audit/replay/{event_id}` for
post-incident review.

---

### 13. Docker Deployment (Shreya + Harsh)
`docker compose up -d` — FastAPI + Postgres/pgvector, CPU-only build (~2.5GB image), auto table
creation on first start. See `docs/DOCKER.md`.

---

## 🚀 How to Run

### Prerequisites
- Python 3.14+
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/Tiya695/SecureMem.git
cd SecureMem
```

### 2. Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Mac/Linux
python -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Set Up Environment Variables
Copy `.env.example` to `.env` and fill in real values (see that file for the full reference,
including why `GROQ_MODEL` matters — Groq deprecates models over time, see
`docs/PROJECT_AUDIT.md`):
```env
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-20b
JWT_SECRET_KEY=your_secret_key_here
ENCRYPTION_KEY=your_fernet_key_here
ADMIN_BOOTSTRAP_SECRET=your_admin_bootstrap_secret_here
DATABASE_URL=postgresql://user:password@localhost:5432/securemem
```

### Alternative: Docker
```bash
docker compose build
docker compose up -d
curl http://localhost:8000/api/health
```
See `docs/DOCKER.md` for port-conflict handling and the full env var reference.

### 5. Start the Backend Server
```bash
uvicorn backend.main:app --reload --port 8000
```

### 6. Open the Frontend
```bash
cd frontend
python -m http.server 3000
```
Then visit: **http://localhost:3000**

### 7. View API Documentation
Visit: **http://localhost:8000/docs**

---

## 🧪 Running Tests

```bash
# Full suite (100+ tests) — needs a running server + Postgres, see docs/PROJECT_AUDIT.md
uvicorn backend.main:app --port 8000 &
pytest tests/ -v

# Real multi-LLM F1/precision/recall evaluation (50 prompts)
python testing/eval_all_models.py

# Just the security attack lab (all 10 playbook attack types)
pytest tests/test_security_attack_lab.py -v
```

---

## 📊 API Endpoints

Full reference with auth requirements, request/response shapes, and error codes:
**[`docs/API_SPEC.md`](docs/API_SPEC.md)**.

---

## 🔧 Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend Framework | FastAPI + Uvicorn |
| AI Classifier / LLM | Groq (default), OpenAI/Anthropic/Gemini/Ollama connectors (`SECUREMEM_LLM_PROVIDER`) |
| Vector Database | ChromaDB (legacy) + PostgreSQL + pgvector (production) + SentenceTransformers |
| Encryption | AES-256 via Fernet (cryptography library) |
| Authentication | JWT (python-jose) |
| Rate limiting | slowapi |
| Frontend | HTML5, CSS3, JavaScript, Three.js, Chart.js |
| Testing | pytest (100+ tests) |
| Deployment | Docker + docker-compose |
| Version Control | Git / GitHub |

---

## 🔗 Integration Examples

Any existing AI application can adopt SecureMem as a security layer without touching SecureMem's
own internals:

```
┌─────────────────────────────────────────────────────┐
│ Existing AI Application                              │
│ (ChatGPT wrapper / customer service bot / agent)     │
└──────────────────┬────────────────────────────────────┘
                    │ user_prompt
                    ▼
┌─────────────────────────────────────────────────────┐
│ SecureMem SDK / Gateway                              │
│ securemem.protect(prompt)                             │
│ → JWT auth → Firewall → PII → Poison → Policy        │
└──────────────────┬────────────────────────────────────┘
        ↓ BLOCKED              ↓ ALLOWED
   {blocked: true,        Forward to LLM provider
    reason: "..."}                ↓
                        ┌──────────┴──────────┐
                        │                     │
                      Groq                  OpenAI / Gemini
                        │                     │
                        └──────────┬──────────┘
                                   ↓
                        AI Response returned
                         (safe, unmodified)
```

### Quick start — protect an existing app in 3 lines

```python
from sdk.securemem_sdk import SecureMemClient

client = SecureMemClient(base_url="http://localhost:8000", agent_id="my_agent", role="AGENT")
check = client.protect(user_input)
if not check["safe"]:
    raise RuntimeError(f"Blocked by SecureMem: {check['reason']}")
# ... otherwise call your LLM as normal, then optionally client.write_memory(...) to store it
```

### Example files

| File | What it demonstrates |
|---|---|
| [`examples/basic_python_app.py`](examples/basic_python_app.py) | Simplest possible integration — a plain Python app that sends a prompt through SecureMem before any LLM call |
| [`examples/securemem_gateway.py`](examples/securemem_gateway.py) | Direct gateway integration (no SDK, just HTTP) — the full pipeline: auth → security check → LLM → response |
| [`examples/securemem_openai.py`](examples/securemem_openai.py) | Wraps OpenAI's official client — drop SecureMem into an existing OpenAI app in 3 lines |
| [`examples/securemem_gemini.py`](examples/securemem_gemini.py) | Same pattern for Google Gemini — proves the integration is model-agnostic |

### Supported LLM providers

| Provider | Set via | Demonstrated by |
|---|---|---|
| Groq (default, real key configured) | `SECUREMEM_LLM_PROVIDER=groq` | all examples, `/v1/gateway/chat` |
| OpenAI | `SECUREMEM_LLM_PROVIDER=openai` | `examples/securemem_openai.py` |
| Google Gemini | `SECUREMEM_LLM_PROVIDER=gemini` | `examples/securemem_gemini.py` |
| Anthropic | `SECUREMEM_LLM_PROVIDER=anthropic` | `backend/llm_providers.py` connector |
| Ollama (local) | `SECUREMEM_LLM_PROVIDER=ollama` | `backend/llm_providers.py` connector |

Run any example against a running SecureMem backend:

```bash
uvicorn backend.main:app --reload --port 8000
python examples/basic_python_app.py
```

---

## 📄 Documentation

- [Project Audit](docs/PROJECT_AUDIT.md) — honest, component-by-component status
- [Architecture Overview](docs/ARCHITECTURE.md)
- [API Specification](docs/API_SPEC.md)
- [Security Model](docs/SECURITY_MODEL.md)
- [Threat Model](docs/THREAT_MODEL.md) — attacker scenarios + OWASP LLM Top 10 mapping
- [Auth Audit](docs/AUTH_AUDIT.md)
- [PII Security](docs/PII_SECURITY.md)
- [Policy Engine](docs/POLICY_ENGINE.md)
- [Investigator Agent](docs/INVESTIGATOR_AGENT.md)
- [Gateway Guide](docs/GATEWAY_GUIDE.md)
- [Docker Deployment](docs/DOCKER.md)
- [Multi-LLM Evaluation Results](docs/MULTI_LLM_RESULTS.md)
- [Security Attack Lab Results](docs/SECURITY_TEST_RESULTS.md)
- [End-to-End Validation](docs/E2E_VALIDATION.md)
- [SDK Guide](sdk/README.md)
- [Protocol Specification](docs/PROTOCOL_SPEC.md)
- [Firewall Test Results](docs/firewall_results.md)
- [Trust Score Simulation](docs/trust_score_simulation.md)

---


