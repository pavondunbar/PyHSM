# PyHSM Production Dockerfile
#
# Multi-stage build:
#   Stage 1 (builder) — installs dependencies with hash verification
#   Stage 2 (runtime) — minimal image, no build tools, no pip, no shell history
#
# Build:
#   docker build -t pyhsm:2.1.0 .
#
# Run (see docker-compose.yml for full hardened example):
#   docker run --name pyhsm --user pyhsm:pyhsm --read-only \
#     -v /var/lib/pyhsm:/data:Z \
#     -v /run/secrets/pyhsm-password:/run/secrets/pyhsm-password:ro,Z \
#     pyhsm:2.1.0

# ---- Stage 1: builder -------------------------------------------------------
FROM python:3.13-slim AS builder

# Install only what we need to compile C extensions (cffi, cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy dependency files first so Docker layer cache is reused when only
# application code changes.
COPY requirements.lock pyproject.toml ./
COPY hsm/ ./hsm/
COPY cli.py ./

# Install ALL dependencies with hash verification into a prefix directory.
# --require-hashes: reject any package whose SHA-256 does not match the lockfile.
# --no-deps: we manage the full dependency graph explicitly in requirements.lock.
# --prefix: install into /install so Stage 2 can copy the exact set of files.
RUN pip install --require-hashes --no-deps --prefix=/install -r requirements.lock \
 && pip install --no-deps --prefix=/install -e .

# ---- Stage 2: runtime -------------------------------------------------------
FROM python:3.13-slim AS runtime

# Security: create a dedicated non-root user
RUN groupadd --system --gid 1000 pyhsm \
 && useradd --system --uid 1000 --gid 1000 \
            --no-create-home --shell /usr/sbin/nologin pyhsm

# Runtime C libraries needed by cryptography / cffi
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        libffi8 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source (already installed via pip -e, but include for
# reference and so the CLI entry point resolves correctly)
COPY --from=builder /build/hsm /app/hsm
COPY --from=builder /build/cli.py /app/cli.py

# Runtime directories
RUN install -d -m 750 -o pyhsm -g pyhsm /data \
 && install -d -m 700 -o pyhsm -g pyhsm /run/pyhsm \
 && install -d -m 750 -o pyhsm -g pyhsm /var/log/pyhsm

WORKDIR /app

# Drop to the service account
USER pyhsm:pyhsm

# Expose the Unix socket directory as a volume so the application container
# can connect to the IPC server.
VOLUME ["/data", "/run/pyhsm", "/var/log/pyhsm"]

# Health check — verify the IPC server responds
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python3 -c "
from hsm.ipc_client import IPCClient
try:
    with IPCClient('/run/pyhsm/pyhsm.sock') as c:
        r = c.health()
        assert r.get('status') == 'ok', r
    exit(0)
except Exception as e:
    print(e)
    exit(1)
"

# Default: run the IPC server.
# Override CMD or use docker-compose to run the CLI instead.
CMD ["vectorguard-pyhsm-server", \
     "--store", "/data/keystore.enc", \
     "--password-file", "/run/secrets/pyhsm-password", \
     "--socket", "/run/pyhsm/pyhsm.sock"]
