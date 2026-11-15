# =============================================================================
# CastleBlack — Sandbox Image
# =============================================================================
# Lightweight isolated container for running generated PoC exploit scripts.
# No network access by default (controlled by ScopeEnforcer iptables rules).
# No AIPTT source code installed — only exploit dependencies.
#
# Build:
#   docker build -f docker/sandbox.Dockerfile -t castleblack-sandbox:latest .
# =============================================================================

FROM python:3.12-slim

# Runtime libs for compiled Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev libssl-dev \
    libldap2-dev libsasl2-dev \
    netcat-openbsd \
    curl \
    wget \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Exploit libraries available to generated PoC scripts
RUN pip install --no-cache-dir \
    requests \
    paramiko \
    impacket \
    pycryptodome \
    pysnmp \
    ldap3 \
    scapy

# Drop to non-root for exploit execution
RUN useradd -m -s /bin/bash sandbox
USER sandbox

WORKDIR /exploit

# Default: just launch python (overridden per-execution by SandboxExecutor)
ENTRYPOINT ["python"]
CMD ["--help"]
