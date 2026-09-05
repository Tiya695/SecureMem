# Docker Deployment

## Prerequisites

- Docker + Docker Compose (Docker Desktop on Windows/Mac, or `docker-compose-plugin` on Linux).
- A `.env` file in the project root (copy `.env.example` and fill in real values — at minimum
  `GROQ_API_KEY`, `JWT_SECRET_KEY`, `ENCRYPTION_KEY`, `ADMIN_BOOTSTRAP_SECRET`).

## Install & run

```bash
docker compose build
docker compose up -d
docker compose ps
curl http://localhost:8000/api/health
```

`docker compose up -d` starts two services:

- `postgres` — `pgvector/pgvector:pg15`, with the `vector` extension enabled automatically on
  first init (`docker/init-pgvector.sql`), data persisted in the `securemem_pgdata` volume.
- `securemem-api` — builds from the project `Dockerfile`, waits for Postgres to report healthy
  (`depends_on: condition: service_healthy`), creates tables if they don't exist yet
  (`docker/entrypoint.sh`, idempotent), then starts Uvicorn on port 8000.

## Viewing logs

```bash
docker compose logs -f securemem-api
docker compose logs -f postgres
```

## Stopping

```bash
docker compose down          # stops containers, keeps the Postgres volume (your data)
docker compose down -v       # also deletes the Postgres volume — full reset
```

## Image size

The `Dockerfile` installs the CPU-only build of `torch` before the rest of `requirements.txt`.
Without that, `pip` resolves `torch==2.12.0` to its default CUDA build and pulls in ~6GB of
`nvidia-*` packages the container will never use (there's no GPU in a typical deployment target
for this project) — final image ~9GB vs ~2.5GB with the CPU wheel. Verified: sentence-transformers
embeddings and semantic search work identically on CPU (that's what it was already using without
a GPU present).

## Port 8000 already in use

If another project on your machine already binds host port 8000, override it without editing
`docker-compose.yml`:

```bash
HOST_PORT=8010 docker compose up -d
```

(or set `HOST_PORT=8010` in your `.env`) — the container still listens on 8000 internally, only
the host-side mapping changes. Note that the *static frontend files* hardcode
`http://localhost:8000` as their dev `API_BASE` (see any `frontend/*.html`), so if you remap the
host port you'll need to open the app at `http://localhost:<HOST_PORT>` directly, or set
`FRONTEND_URL` so CORS still allows it.

## Environment variable reference

| Variable | Required | Default | Notes |
|---|---|---|---|
| `GROQ_API_KEY` | yes | — | Powers the firewall classifier and the default `SECUREMEM_LLM_PROVIDER=groq`. |
| `GROQ_MODEL` | no | `openai/gpt-oss-20b` | See docs/PROJECT_AUDIT.md for why the older `llama-3.1-8b-instant` no longer works. |
| `JWT_SECRET_KEY` | yes | — | Signs issued JWTs. |
| `ENCRYPTION_KEY` | yes | — | Fernet key for encrypting memory content at rest. |
| `ADMIN_BOOTSTRAP_SECRET` | yes (to mint ADMIN tokens) | — | Required by `POST /auth/token` for `role: "ADMIN"`. |
| `DATABASE_URL` | set automatically in compose | — | Points at the `postgres` service inside the compose network; only needed manually when running outside Docker. |
| `SECUREMEM_LLM_PROVIDER` | no | `groq` | `groq \| openai \| anthropic \| gemini \| ollama`. |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` | no | — | Only needed if you switch `SECUREMEM_LLM_PROVIDER` to that provider. |
| `FRONTEND_URL` | no | — | Added to the CORS allow-list alongside the built-in localhost/Render defaults. |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | no | `postgres` / `postgres123` / `securemem` | Change together with `DATABASE_URL` if you override these. |
| `HOST_PORT` | no | `8000` | Host-side port mapping for `securemem-api`. |
| `POSTGRES_HOST_PORT` | no | `5432` | Host-side port mapping for `postgres`, in case you also run Postgres natively on 5432. |
