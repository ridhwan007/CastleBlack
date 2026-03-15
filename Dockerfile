# syntax=docker/dockerfile:1
# =============================================================================
# CastleBlack — Autonomous Penetration Testing Tool
# =============================================================================
#
# Build (default — no Metasploit):
#   docker build -t castleblack:latest .
#
# Build (with Metasploit Framework — adds ~1.5 GB):
#   docker build --build-arg INCLUDE_MSF=true -t castleblack:full .
#
# Run (interactive shell, host network for scanning):
#   docker run --rm -it \
#     --network host \
#     --cap-add NET_RAW --cap-add NET_ADMIN \
#     -v $(pwd)/pentest_output:/output \
#     -v $(pwd)/engagements:/data \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     --env-file .env \
#     -e AIPTT_HOST_WORKDIR=$(pwd)/pentest_output \
#     castleblack:latest validate run /input/scan.nessus --execute
#
# Use docker-compose.yml for the full stack (with neo4j / postgres options).
# =============================================================================

ARG INCLUDE_MSF=false

# -----------------------------------------------------------------------------
# Stage 1 — dependency builder (needs gcc / compile deps)
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ make \
    libffi-dev libssl-dev \
    libldap2-dev libsasl2-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Install Python deps into a relocatable prefix
COPY pyproject.toml .
COPY aiptt/ ./aiptt/

# Non-editable install so package files end up in site-packages (not /build)
RUN pip install --no-cache-dir --prefix=/pkg .

# -----------------------------------------------------------------------------
# Stage 2 — runtime image
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ARG INCLUDE_MSF

# Pentest runtime tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    netcat-openbsd \
    curl \
    wget \
    iputils-ping \
    bash \
    # Runtime libs needed by compiled Python packages
    libffi8 \
    libssl3 \
    libldap-2.5-0 \
    libsasl2-2 \
    && rm -rf /var/lib/apt/lists/*

# Optional: Metasploit Framework (skipped by default — adds ~1.5 GB)
RUN if [ "$INCLUDE_MSF" = "true" ]; then \
      apt-get update && apt-get install -y --no-install-recommends gnupg curl && \
      curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/metasploit.gpg && \
      echo "deb [signed-by=/usr/share/keyrings/metasploit.gpg] https://apt.metasploit.com/ buster main" \
        > /etc/apt/sources.list.d/metasploit.list && \
      apt-get update && apt-get install -y metasploit-framework && \
      rm -rf /var/lib/apt/lists/* ; \
    fi

# Copy installed Python packages from builder
COPY --from=builder /pkg/lib /usr/local/lib
COPY --from=builder /pkg/bin /usr/local/bin

# Copy application source (needed for data files + module discovery)
WORKDIR /app
COPY aiptt/ ./aiptt/
COPY modules/ ./modules/
COPY data/ ./data/
COPY pyproject.toml .

# Persistent data directories — overridden by volume mounts at runtime
RUN mkdir -p /output /data /data/vault /output/sandbox_tmp

# Entrypoint bootstraps config, then delegates to aiptt CLI
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose volume mount points for documentation purposes
VOLUME ["/output", "/data"]

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--help"]
