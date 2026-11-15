#!/usr/bin/env bash
# =============================================================================
# CastleBlack container entrypoint
#
# Bootstraps ~/.config/aiptt/config.toml with container-appropriate paths
# on first run, then delegates all arguments to the aiptt CLI.
# =============================================================================
set -euo pipefail

CONFIG_DIR="/root/.config/aiptt"
CONFIG_FILE="$CONFIG_DIR/config.toml"

# ---------------------------------------------------------------------------
# Write default config only if it doesn't already exist.
# All persistent paths point to /output or /data (volume-mounted from host).
# ---------------------------------------------------------------------------
if [ ! -f "$CONFIG_FILE" ]; then
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" <<'TOML'
# CastleBlack — container configuration
# Generated automatically on first start. Edit as needed.

[core]
log_level        = "INFO"
output_base_dir  = "/output"
ai_model         = "claude-sonnet-4-6"
ai_api_key_env   = "AIPTT_AI_API_KEY"
max_pivot_depth  = 3

[database]
engine      = "sqlite"
sqlite_path = "/data/aiptt.db"
# Uncomment for PostgreSQL (set POSTGRESQL_URL env var):
# engine         = "postgresql"
# postgresql_url = ""

[encryption]
key_env           = "AIPTT_MASTER_KEY"
key_rotation_days = 90
vault_path        = "/data/vault"

[audit]
log_path         = "/data/audit.db"
syslog_forward   = false
retention_months = 12

[sandbox]
docker_socket  = "unix:///var/run/docker.sock"
sandbox_image  = "castleblack-sandbox:latest"
timeout_seconds = 120
network_mode   = "none"

[guardrail]
fail_open                  = false
circuit_breaker_enabled    = true
anomaly_cpu_threshold_pct  = 80
anomaly_io_threshold_mbps  = 500

[discovery]
default_scan_rate     = "T3"
max_concurrent_hosts  = 256
udp_scan_enabled      = false
honeypot_detection    = true

[credential_attacks]
default_max_attempts_per_account = 2
lockout_safety_margin            = 2
spray_window_minutes             = 60

[retention]
artefact_retention_days = 90
max_retention_days      = 365
TOML
    echo "[castleblack] Config written to $CONFIG_FILE"
fi

# ---------------------------------------------------------------------------
# If the Anthropic API key env var is missing, warn clearly rather than
# letting the tool fail silently mid-engagement.
# ---------------------------------------------------------------------------
if [ -z "${AIPTT_AI_API_KEY:-}" ]; then
    echo ""
    echo "  WARNING: AIPTT_AI_API_KEY is not set."
    echo "  AI-driven features (PoC generation, triage, interpretation) will fail."
    echo "  Set it via --env-file .env or -e AIPTT_AI_API_KEY=sk-ant-..."
    echo ""
fi

# ---------------------------------------------------------------------------
# Hand off to the aiptt CLI
# ---------------------------------------------------------------------------
exec aiptt "$@"
