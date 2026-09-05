FROM python:3.11-slim

WORKDIR /app

# psycopg2-binary/cryptography/torch all ship prebuilt wheels for this platform, but curl is
# needed for the container healthcheck below and isn't in the slim base image.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# requirements.txt pins torch==2.12.0 with no index preference, which pulls the default CUDA
# build (~6GB of nvidia-* packages) even though this container has no GPU. Installing the
# matching CPU-only wheel first satisfies that pin without pip reaching for CUDA — cuts the
# final image from ~9GB to a couple GB.
RUN pip install --no-cache-dir torch==2.12.0 --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Creates tables if they don't exist yet (idempotent), then starts the API. Postgres readiness
# is handled by docker-compose's `depends_on: condition: service_healthy`, not here.
COPY docker/entrypoint.sh /app/docker/entrypoint.sh
RUN chmod +x /app/docker/entrypoint.sh

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=5 \
    CMD curl -f http://localhost:8000/api/health || exit 1

ENTRYPOINT ["/app/docker/entrypoint.sh"]
