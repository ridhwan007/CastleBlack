# AIPTT — Autonomous Internal Penetration Testing Tool

> **⚠ AUTHORISED USE ONLY**
> This tool is designed exclusively for security professionals conducting **authorised** penetration tests within a defined scope and under a signed Rules of Engagement (RoE) document. Unauthorised use against systems you do not have explicit permission to test is illegal and unethical.

---

AIPTT is a Claude-powered CLI tool that autonomously discovers, exploits, and reports vulnerabilities within a scoped network environment. It uses the **OPAV loop** (Observe → Plan → Act → Validate) with Anthropic's `claude-sonnet-4-6` as the AI planning brain.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Quickstart](#quickstart)
- [Command Reference](#command-reference)
  - [engage](#engage--engagement-lifecycle)
  - [scan](#scan--discovery)
  - [attack](#attack--opav-loop)
  - [report](#report--output)
  - [verify](#verify--fix-verify)
  - [session](#session--session-management)
  - [admin](#admin--administration)
- [Running Unit Tests](#running-unit-tests)
- [Docker / Sandbox Setup](#docker--sandbox-setup)
- [Neo4j Knowledge Graph](#neo4j-knowledge-graph)
- [Vault & Key Management](#vault--key-management)
- [Audit Log](#audit-log)
- [Deployment on Linux](#deployment-on-linux)
- [Security Controls Summary](#security-controls-summary)
- [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        AIPTT CLI                            │
│  aiptt engage │ scan │ attack │ report │ verify │ admin     │
└──────────────────────────┬──────────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │      OPAV Loop Core     │
              │  Observe→Plan→Act→Validate│
              └──┬──────────┬───────────┘
                 │          │
    ┌────────────▼──┐  ┌────▼──────────────┐
    │  AI Planner   │  │  Guardrail System  │
    │ claude-sonnet │  │  Scope / Blast /   │
    │    -4-6       │  │  Rate / Circuit    │
    └───────────────┘  └────────────────────┘
                 │
    ┌────────────▼──────────────────────────┐
    │           Attack Modules              │
    │  AD: Kerberoast │ DCSync │ PTH │ ADCS │
    │  Net: RCE │ CredSpray                 │
    │  Lateral: SMB │ Token Theft           │
    └────────────┬──────────────────────────┘
                 │
    ┌────────────▼──────────────────────────┐
    │      Storage & Output                 │
    │  SQLite/PG DB │ AES-256-GCM Vault     │
    │  HMAC Audit Log │ Neo4j Graph         │
    │  Reports: PDF │ JSON │ CSV │ HTML     │
    └───────────────────────────────────────┘
```

---

## Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | ≥ 3.12 | `python3 --version` |
| pip | ≥ 23 | `pip --version` |
| Docker | ≥ 24 | For sandboxed exploit execution (Linux) |
| Neo4j | ≥ 5 | Optional — attack path graph |
| nmap | ≥ 7.9 | Must be on `PATH` |
| Anthropic API key | — | `console.anthropic.com` |

> **Platform note:** AIPTT is developed on Windows but **deployed and run on Linux**. The iptables scope enforcement, Docker unix socket (`/var/run/docker.sock`), and syslog audit alerting all require Linux. On Windows, these features degrade gracefully (no iptables, Docker Desktop TCP socket, stderr fallback for syslog).

---

## Installation

### 1. Clone the repository

```bash
git clone <your-repo-url> /opt/aiptt
cd /opt/aiptt
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate           # Windows
```

### 3. Install the package

```bash
pip install -e .
```

For development (includes pytest):

```bash
pip install -e ".[dev]"
```

### 4. Verify the install

```bash
aiptt --version
aiptt --help
```

Expected output:
```
AIPTT version 1.1.0

 Usage: aiptt [OPTIONS] COMMAND [ARGS]...
 ...
```

---

## Configuration

### Step 1 — Create your `.env` file

```bash
cp .env.example .env
```

Edit `.env` and fill in the three required values:

```env
# Your Anthropic API key (get one at https://console.anthropic.com)
AIPTT_AI_API_KEY=sk-ant-api03-YOUR_KEY_HERE

# AES-256 master key — generate with:
# python -c "import os,binascii; print(binascii.hexlify(os.urandom(32)).decode())"
AIPTT_MASTER_KEY=aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899

# HMAC key for audit log chain integrity — any strong secret
AIPTT_AUDIT_KEY=my-strong-audit-hmac-secret
```

> **Security note:** Never commit `.env` to version control. Add it to `.gitignore`.

### Step 2 — Load environment variables

```bash
source .env                   # Linux/macOS (bash)
# or use direnv / dotenv CLI
export $(cat .env | xargs)    # Alternative
```

### Step 3 — Create the AIPTT config file

AIPTT reads `~/.config/aiptt/config.toml` on startup.
Create it with:

```bash
mkdir -p ~/.config/aiptt
cat > ~/.config/aiptt/config.toml << 'EOF'
[core]
ai_model       = "claude-sonnet-4-6"
ai_api_key_env = "AIPTT_AI_API_KEY"
max_pivots     = 3
output_dir     = "~/aiptt_engagements"

[database]
url     = "sqlite:///~/.config/aiptt/aiptt.db"
echo    = false

[encryption]
vault_dir       = "~/.config/aiptt/vault"
master_key_env  = "AIPTT_MASTER_KEY"
retention_days  = 90

[audit]
db_path        = "~/.config/aiptt/audit.db"
audit_key_env  = "AIPTT_AUDIT_KEY"

[neo4j]
uri      = "bolt://localhost:7687"
user     = "neo4j"
password = "neo4j"
enabled  = false
EOF
```

Set `neo4j.enabled = true` if you have Neo4j running (recommended for large engagements).

### Optional — PostgreSQL (production)

For production deployments replace the SQLite URL:

```toml
[database]
url = "postgresql://aiptt_user:password@localhost:5432/aiptt"
```

And set the env var:

```env
POSTGRESQL_URL=postgresql://aiptt_user:password@localhost:5432/aiptt
```

---

## Quickstart

This walks through a complete engagement from init to report.

### 1. Prepare your RoE document

AIPTT requires a signed Rules of Engagement document before any attack activity.

```bash
# Get the SHA-256 hash of your RoE PDF
aiptt admin roe-sign /path/to/roe_document.pdf
# Output: RoE SHA-256: 3a7bd3e2...
```

### 2. Initialise the engagement

```bash
aiptt engage init \
  --name "Corp Internal PT 2025" \
  --cidr "10.0.0.0/24" \
  --roe /path/to/roe_document.pdf \
  --output-dir ./engagements \
  --max-pivots 3
```

Output:
```
✓ RoE document accepted (SHA-256: 3a7bd3e2...)
✓ Scope validated — 1 CIDR(s): 10.0.0.0/24

╭─ Engagement Initialised ─────────────────────╮
│ ID:         ENG-A1B2C3D4                      │
│ Name:       Corp Internal PT 2025             │
│ Scope:      10.0.0.0/24                       │
│ Output dir: ./engagements/ENG-A1B2C3D4        │
╰───────────────────────────────────────────────╯

To start the attack loop:
  aiptt attack run --engagement-id ENG-A1B2C3D4
```

### 3. Run discovery

```bash
# Sweep for live hosts
aiptt scan discover --engagement-id ENG-A1B2C3D4 --cidr 10.0.0.0/24

# Fingerprint a specific host
aiptt scan fingerprint --engagement-id ENG-A1B2C3D4 --target 10.0.0.5

# Vulnerability scan
aiptt scan vulnscan --engagement-id ENG-A1B2C3D4 --target 10.0.0.5

# Active Directory enumeration (if domain target)
aiptt scan ad-map \
  --engagement-id ENG-A1B2C3D4 \
  --dc-ip 10.0.0.1 \
  --domain CORP.LOCAL \
  --username user \
  --password 'Password123'
```

### 4. Preview Claude's attack plan (dry-run)

```bash
aiptt attack plan \
  --engagement-id ENG-A1B2C3D4 \
  --target 10.0.0.5 \
  --vulns "CVE-2021-44228,CVE-2021-21985"
```

This calls Claude and prints a scored, ranked attack queue — **no attacks are executed**.

### 5. Run the autonomous OPAV loop

```bash
aiptt attack run \
  --engagement-id ENG-A1B2C3D4 \
  --max-cycles 10 \
  --verbose
```

The loop will:
1. **Observe** — pull scan data + compromised hosts from the knowledge graph
2. **Plan** — ask Claude to rank attack vectors
3. **Act** — execute modules through the guardrail gate
4. **Validate** — capture PoE artefacts (encrypted to vault)

Press `Ctrl+C` to pause safely. Use `aiptt engage resume` to continue.

### 6. Generate reports

```bash
# Executive summary (Markdown)
aiptt report executive --engagement-id ENG-A1B2C3D4 --output-dir ./reports

# Full technical report (Markdown)
aiptt report technical --engagement-id ENG-A1B2C3D4 --output-dir ./reports

# Compliance mapping (PCI-DSS, NIS2, ISO27001, SOC2, HIPAA)
aiptt report compliance --engagement-id ENG-A1B2C3D4 --output-dir ./reports

# Export findings as PDF / JSON / CSV / HTML
aiptt report export --engagement-id ENG-A1B2C3D4 --format pdf --output-dir ./reports
aiptt report export --engagement-id ENG-A1B2C3D4 --format json --output-dir ./reports
```

### 7. Retest after remediation

```bash
aiptt verify retest \
  --finding-id FIND-AB12CD34 \
  --engagement-id ENG-A1B2C3D4
```

Output:
```
╭─ Retest Result — FIND-AB12CD34 ──────────────╮
│ Outcome:       REMEDIATED                     │
│ Original CVSS: 7.5                            │
│ Retest CVSS:   7.5                            │
│ Detail:        Vulnerability is no longer...  │
╰───────────────────────────────────────────────╯
```

---

## Command Reference

### `engage` — Engagement Lifecycle

```
aiptt engage init      --name NAME --cidr CIDR --roe FILE [--max-pivots N] [--dry-run]
aiptt engage status    --engagement-id ENG-XXXXXXXX
aiptt engage pause     ENGAGEMENT_ID
aiptt engage resume    ENGAGEMENT_ID
aiptt engage close     ENGAGEMENT_ID [--yes]
```

| Flag | Description |
|------|-------------|
| `--name` | Human-readable engagement name |
| `--cidr` | Target scope, comma-separated (e.g. `10.0.0.0/24,172.16.0.0/16`) |
| `--roe` | Path to the signed RoE document (PDF or any file) |
| `--max-pivots` | Maximum lateral movement hops (default: 3) |
| `--dry-run` | Validate RoE + scope only, do not create DB records |

---

### `scan` — Discovery

```
aiptt scan discover     --engagement-id ENG-X --cidr CIDR [--udp]
aiptt scan fingerprint  --engagement-id ENG-X --target IP
aiptt scan vulnscan     --engagement-id ENG-X --target IP [--cve-cache PATH]
aiptt scan ad-map       --engagement-id ENG-X --dc-ip IP --domain DOMAIN
                        --username USER [--password PASS | --nt-hash HASH]
```

---

### `attack` — OPAV Loop

```
aiptt attack run     --engagement-id ENG-X [--max-cycles N] [--max-pivots N] [--verbose]
aiptt attack plan    --engagement-id ENG-X --target IP [--vulns CVE1,CVE2]
aiptt attack exec    --engagement-id ENG-X --module MODULE_ID --target IP [--params JSON]
aiptt attack lateral --engagement-id ENG-X --source IP --destination IP
                     --username USER [--nt-hash HASH | --password PASS]
```

**Available module IDs:**

| Module ID | Technique | Description |
|-----------|-----------|-------------|
| `AD-KERB-001` | T1558.003 | Kerberoasting |
| `AD-ASREP-001` | T1558.004 | AS-REP Roasting |
| `AD-DCSYNC-001` | T1003.006 | DCSync |
| `AD-PTH-001` | T1550.002 | Pass-the-Hash |
| `AD-DELEG-001` | T1558 | Kerberos Delegation abuse |
| `AD-ADCS-001` | T1649 | ADCS ESC1–ESC4 |
| `AD-BH-001` | — | BloodHound path analysis |
| `NET-RCE-001` | T1190 | CVE-based RCE |
| `CRED-SPRAY-001` | T1110.003 | Password spray (lockout-safe) |
| `LAT-SMB-001` | T1021.002 | SMB lateral movement |
| `LAT-TOKEN-001` | T1134 | Token impersonation |

---

### `report` — Output

```
aiptt report executive  --engagement-id ENG-X [--name NAME] [--output-dir DIR]
aiptt report technical  --engagement-id ENG-X [--name NAME] [--output-dir DIR]
aiptt report compliance --engagement-id ENG-X [--frameworks LIST] [--output-dir DIR]
aiptt report export     --engagement-id ENG-X --format FORMAT [--output-dir DIR]
```

`--frameworks` accepts comma-separated: `pci_dss,nis2,iso27001,soc2,hipaa` (default: all five)

`--format` accepts: `json` | `csv` | `html` | `pdf`

---

### `verify` — Fix-Verify

```
aiptt verify retest --finding-id FIND-XXXXXXXX --engagement-id ENG-X
```

Outcomes:

| Outcome | Meaning |
|---------|---------|
| `REMEDIATED` | Exploit no longer succeeds — close the finding |
| `STILL_VULNERABLE` | Same severity, not yet fixed |
| `REGRESSION` | Severity escalated (+1.0 CVSS) — new finding auto-created |

---

### `session` — Session Management

```
aiptt session list
aiptt session load    ENGAGEMENT_ID [--checkpoint PATH]
aiptt session export  ENGAGEMENT_ID [--output FILE]
```

---

### `admin` — Administration

```
aiptt admin kill          [--yes]           # Emergency halt — writes /tmp/aiptt_kill
aiptt admin roe-sign      ROE_FILE          # Print SHA-256 hash of RoE document
aiptt admin key-rotate    [--yes]           # Generate new AES-256 master key
aiptt admin purge         [--yes] [--vault-dir DIR]  # Delete artefacts >90 days old
aiptt admin module-update [--cve-cache-dir DIR]      # Refresh CVE cache manifest
```

---

## Running Unit Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all unit tests
pytest tests/unit/ -v

# Run with coverage report
pytest tests/unit/ --cov=aiptt --cov-report=term-missing

# Run a specific test file
pytest tests/unit/test_guardrail.py -v

# Run by marker
pytest -m "not integration" -v
```

Expected output (all green):
```
tests/unit/test_guardrail.py::TestScopeEnforcer::test_ip_in_scope PASSED
tests/unit/test_guardrail.py::TestGuardrailController::test_exception_in_scope_check_fails_closed PASSED
tests/unit/test_audit_logger.py::TestAuditLogger::test_tampered_chain_detected PASSED
tests/unit/test_path_scorer.py::TestPathScorer::test_rce_override_sets_priority_1 PASSED
tests/unit/test_poe_capture.py::TestPoECapture::test_successful_capture_is_confirmed PASSED
tests/unit/test_fix_verify.py::TestFixVerifyEngine::test_regression_opens_new_finding PASSED
...
```

---

## Docker / Sandbox Setup

Attack modules that generate novel exploit code via Claude are executed inside Docker containers for isolation.

### Linux (recommended)

```bash
# Install Docker Engine
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Verify
docker run --rm hello-world
```

AIPTT automatically connects via the unix socket: `unix:///var/run/docker.sock`

### Windows (development only)

Install Docker Desktop and ensure the TCP socket is enabled:
`Settings → General → Expose daemon on tcp://localhost:2375`

The sandbox will connect automatically on Windows.

### Sandbox limits

Each sandboxed exploit gets:
- Memory: **512 MB**
- CPU: **50%** of one core
- Timeout: **120 seconds**
- Network: **isolated** (no external calls)

---

## Neo4j Knowledge Graph

Neo4j is optional but significantly improves attack path ranking for large networks.

### Install Neo4j (Docker)

```bash
docker run -d \
  --name neo4j-aiptt \
  -p 7687:7687 -p 7474:7474 \
  -e NEO4J_AUTH=neo4j/aiptt_password \
  neo4j:5
```

### Enable in config

```toml
# ~/.config/aiptt/config.toml
[neo4j]
uri      = "bolt://localhost:7687"
user     = "neo4j"
password = "aiptt_password"
enabled  = true
```

### Browser UI

Open `http://localhost:7474` to explore the attack graph visually.

---

## Vault & Key Management

All proof-of-exploit artefacts (credentials, hashes, command output) are stored AES-256-GCM encrypted.

### Generate a master key

```bash
python -c "import os, binascii; print(binascii.hexlify(os.urandom(32)).decode())"
# Example: a3f1c9e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8
```

Set it in `.env`:
```env
AIPTT_MASTER_KEY=a3f1c9e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8
```

### Rotate the key

```bash
aiptt admin key-rotate --yes
# Prints a new 64-char hex key — update your .env immediately
```

### Automatic purge (90-day retention)

AIPTT enforces a **90-day retention window** on all vault artefacts (BR-SAFE-07).

Run manually:
```bash
aiptt admin purge --yes
```

Or add to cron (Linux):
```bash
# /etc/cron.weekly/aiptt-purge
#!/bin/bash
source /opt/aiptt/.env
/opt/aiptt/.venv/bin/aiptt admin purge --yes
```

---

## Audit Log

Every action AIPTT takes is recorded in an **HMAC-chained append-only SQLite audit log** stored at `~/.config/aiptt/audit.db`.

Key properties:
- **Intent-first logging** — `INTENT_*` events are written *before* any action is taken (FR-AI-05)
- **Tamper-evident** — each row's HMAC covers the previous row's HMAC + timestamp + payload
- **Verify integrity** at any time:

```bash
python -c "
from aiptt.audit.logger import get_audit_logger
ok = get_audit_logger().verify_chain_integrity()
print('INTEGRITY OK' if ok else 'TAMPERED — ALERT')
"
```

- **Emergency alert** — if a write fails, AIPTT calls `syslog(LOG_CRIT, ...)` on Linux (stderr on Windows)

---

## Deployment on Linux

### Recommended directory layout

```
/opt/aiptt/              ← repo root
/opt/aiptt/.venv/        ← virtualenv
/opt/aiptt/.env          ← secrets (chmod 600)
~/.config/aiptt/         ← config + DBs + vault
/var/log/aiptt/          ← optional — symlink audit log here
```

### systemd service (optional)

```ini
# /etc/systemd/system/aiptt-worker.service
[Unit]
Description=AIPTT OPAV Worker
After=network.target

[Service]
Type=simple
User=aiptt
WorkingDirectory=/opt/aiptt
EnvironmentFile=/opt/aiptt/.env
ExecStart=/opt/aiptt/.venv/bin/aiptt attack run \
    --engagement-id %i --max-cycles 50
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl start aiptt-worker@ENG-A1B2C3D4
sudo systemctl status aiptt-worker@ENG-A1B2C3D4
```

### iptables scope enforcement

On Linux, AIPTT can apply iptables rules to enforce that the agent process only reaches in-scope IPs. This requires running as root or with `CAP_NET_ADMIN`:

```bash
sudo aiptt engage init --name "Corp PT" --cidr 10.0.0.0/24 --roe roe.pdf
```

The scope enforcer calls `apply_iptables_rules()` automatically on engagement init.

---

## Security Controls Summary

| Control | Description |
|---------|-------------|
| **RoE validation** | SHA-256 hash check on RoE document before any activity |
| **Scope enforcement** | All target IPs validated against allowed CIDRs before execution |
| **Blast radius gate** | Conservative / Standard / Aggressive modes; `DOS`, `WIPE`, `RANSOM` always blocked |
| **Credential rate limiter** | Reads AD lockout policy; stays 50% below threshold |
| **Circuit breaker** | Trips on high CPU / IO / DNS anomalies; halts loop |
| **AES-256-GCM vault** | All PoE artefacts encrypted at rest |
| **HMAC audit chain** | Tamper-evident append-only log |
| **90-day retention** | Automatic secure deletion of expired artefacts |
| **Docker sandbox** | AI-generated exploits executed in isolated containers |
| **Intent-first logging** | `INTENT_*` written before every action (non-repudiation) |
| **Production-hours gate** | DCSync blocked during business hours by default |
| **Crown-jewel HITL gate** | Human approval required before targeting critical assets |

---

## Troubleshooting

### `ModuleNotFoundError: aiptt`

```bash
# Ensure the venv is active and package is installed
source .venv/bin/activate
pip install -e .
```

### `KeyError: 'AIPTT_AI_API_KEY'`

The Anthropic API key is not set. Load your `.env`:
```bash
export $(cat .env | xargs)
```

### `KeyError: 'AIPTT_MASTER_KEY'`

Generate and set the AES-256 master key (see [Vault & Key Management](#vault--key-management)).

### `ChatAnthropic authentication error`

Your API key is invalid or expired. Get a new one at `https://console.anthropic.com` and update `AIPTT_AI_API_KEY` in `.env`.

### `docker.errors.DockerException: Error while fetching server API version`

Docker is not running or not accessible:
```bash
# Linux
sudo systemctl start docker

# Check socket
ls -la /var/run/docker.sock
```

### `nmap: command not found`

```bash
# Debian/Ubuntu
sudo apt install nmap

# RHEL/CentOS
sudo yum install nmap
```

### Audit chain integrity check fails

```
TAMPERED — ALERT
```

The audit database may have been modified directly. Do not delete it — preserve it for forensic review. Start a new engagement with a fresh audit DB.

### `impacket` install fails on Windows

```bash
pip install impacket --no-binary impacket
# or
pip install git+https://github.com/fortra/impacket.git
```

---

## Generating the Anthropic API Key

1. Go to [https://console.anthropic.com](https://console.anthropic.com)
2. Sign in → **API Keys** → **Create Key**
3. Copy the key (starts with `sk-ant-api03-...`)
4. Add to `.env`:
   ```env
   AIPTT_AI_API_KEY=sk-ant-api03-YOUR_KEY_HERE
   ```

The free tier includes limited usage. For production engagements, use a paid plan with sufficient rate limits.

---

## License

**CONFIDENTIAL** — For authorised security assessment use only.
Redistribution, modification, or use outside of explicitly authorised penetration tests is prohibited.

---

*AIPTT v1.1.0 
