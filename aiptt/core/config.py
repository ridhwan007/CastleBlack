"""
Configuration loader for AIPTT.

Reads ~/.config/aiptt/config.toml (TOML format, Python 3.11+ tomllib).
Falls back to built-in defaults when no config file exists.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from functools import lru_cache

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[no-redef]
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]

CONFIG_PATH = Path("~/.config/aiptt/config.toml").expanduser()

# ---------------------------------------------------------------------------
# Typed config dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CoreConfig:
    log_level: str = "INFO"
    output_base_dir: str = "~/.aiptt/engagements"
    ai_model: str = "claude-sonnet-4-6"
    ai_api_key_env: str = "AIPTT_AI_API_KEY"
    max_pivot_depth: int = 3


@dataclass
class DatabaseConfig:
    engine: str = "sqlite"
    sqlite_path: str = "~/.aiptt/aiptt.db"
    postgresql_url: str = ""


@dataclass
class EncryptionConfig:
    key_env: str = "AIPTT_MASTER_KEY"
    key_rotation_days: int = 90
    vault_path: str = "~/.aiptt/vault"


@dataclass
class AuditConfig:
    log_path: str = "~/.aiptt/audit.db"
    syslog_forward: bool = False
    syslog_host: str = "siem.corp.local"
    syslog_port: int = 514
    retention_months: int = 12


@dataclass
class SandboxConfig:
    docker_socket: str = "unix:///var/run/docker.sock"
    sandbox_image: str = "aiptt-sandbox:latest"
    timeout_seconds: int = 120
    network_mode: str = "none"


@dataclass
class GuardrailConfig:
    fail_open: bool = False
    circuit_breaker_enabled: bool = True
    anomaly_cpu_threshold_pct: int = 80
    anomaly_io_threshold_mbps: int = 500


@dataclass
class DiscoveryConfig:
    default_scan_rate: str = "T3"
    max_concurrent_hosts: int = 256
    udp_scan_enabled: bool = True
    honeypot_detection: bool = True


@dataclass
class CredentialAttacksConfig:
    default_max_attempts_per_account: int = 2
    lockout_safety_margin: int = 2
    spray_window_minutes: int = 60


@dataclass
class RetentionConfig:
    artefact_retention_days: int = 90
    max_retention_days: int = 365


@dataclass
class Neo4jConfig:
    uri: str = "bolt://localhost:7687"
    user: str = "neo4j"
    password_env: str = "NEO4J_PASSWORD"


@dataclass
class AIPTTConfig:
    core: CoreConfig = field(default_factory=CoreConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    guardrail: GuardrailConfig = field(default_factory=GuardrailConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    credential_attacks: CredentialAttacksConfig = field(default_factory=CredentialAttacksConfig)
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    neo4j: Neo4jConfig = field(default_factory=Neo4jConfig)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def _parse_config(raw: dict) -> AIPTTConfig:
    cfg = AIPTTConfig()

    if "core" in raw:
        c = raw["core"]
        cfg.core = CoreConfig(
            log_level=c.get("log_level", cfg.core.log_level),
            output_base_dir=c.get("output_base_dir", cfg.core.output_base_dir),
            ai_model=c.get("ai_model", cfg.core.ai_model),
            ai_api_key_env=c.get("ai_api_key_env", cfg.core.ai_api_key_env),
            max_pivot_depth=c.get("max_pivot_depth", cfg.core.max_pivot_depth),
        )

    if "database" in raw:
        d = raw["database"]
        cfg.database = DatabaseConfig(
            engine=d.get("engine", cfg.database.engine),
            sqlite_path=d.get("sqlite_path", cfg.database.sqlite_path),
            postgresql_url=d.get("postgresql_url", cfg.database.postgresql_url),
        )

    if "encryption" in raw:
        e = raw["encryption"]
        cfg.encryption = EncryptionConfig(
            key_env=e.get("key_env", cfg.encryption.key_env),
            key_rotation_days=e.get("key_rotation_days", cfg.encryption.key_rotation_days),
            vault_path=e.get("vault_path", cfg.encryption.vault_path),
        )

    if "audit" in raw:
        a = raw["audit"]
        cfg.audit = AuditConfig(
            log_path=a.get("log_path", cfg.audit.log_path),
            syslog_forward=a.get("syslog_forward", cfg.audit.syslog_forward),
            syslog_host=a.get("syslog_host", cfg.audit.syslog_host),
            syslog_port=a.get("syslog_port", cfg.audit.syslog_port),
            retention_months=a.get("retention_months", cfg.audit.retention_months),
        )

    if "sandbox" in raw:
        s = raw["sandbox"]
        cfg.sandbox = SandboxConfig(
            docker_socket=s.get("docker_socket", cfg.sandbox.docker_socket),
            sandbox_image=s.get("sandbox_image", cfg.sandbox.sandbox_image),
            timeout_seconds=s.get("timeout_seconds", cfg.sandbox.timeout_seconds),
            network_mode=s.get("network_mode", cfg.sandbox.network_mode),
        )

    if "guardrail" in raw:
        g = raw["guardrail"]
        cfg.guardrail = GuardrailConfig(
            fail_open=g.get("fail_open", cfg.guardrail.fail_open),
            circuit_breaker_enabled=g.get("circuit_breaker_enabled",
                                          cfg.guardrail.circuit_breaker_enabled),
            anomaly_cpu_threshold_pct=g.get("anomaly_cpu_threshold_pct",
                                            cfg.guardrail.anomaly_cpu_threshold_pct),
            anomaly_io_threshold_mbps=g.get("anomaly_io_threshold_mbps",
                                            cfg.guardrail.anomaly_io_threshold_mbps),
        )

    if "discovery" in raw:
        d = raw["discovery"]
        cfg.discovery = DiscoveryConfig(
            default_scan_rate=d.get("default_scan_rate", cfg.discovery.default_scan_rate),
            max_concurrent_hosts=d.get("max_concurrent_hosts",
                                       cfg.discovery.max_concurrent_hosts),
            udp_scan_enabled=d.get("udp_scan_enabled", cfg.discovery.udp_scan_enabled),
            honeypot_detection=d.get("honeypot_detection", cfg.discovery.honeypot_detection),
        )

    if "credential_attacks" in raw:
        ca = raw["credential_attacks"]
        cfg.credential_attacks = CredentialAttacksConfig(
            default_max_attempts_per_account=ca.get(
                "default_max_attempts_per_account",
                cfg.credential_attacks.default_max_attempts_per_account),
            lockout_safety_margin=ca.get("lockout_safety_margin",
                                         cfg.credential_attacks.lockout_safety_margin),
            spray_window_minutes=ca.get("spray_window_minutes",
                                        cfg.credential_attacks.spray_window_minutes),
        )

    if "retention" in raw:
        r = raw["retention"]
        cfg.retention = RetentionConfig(
            artefact_retention_days=r.get("artefact_retention_days",
                                          cfg.retention.artefact_retention_days),
            max_retention_days=r.get("max_retention_days", cfg.retention.max_retention_days),
        )

    if "neo4j" in raw:
        n = raw["neo4j"]
        cfg.neo4j = Neo4jConfig(
            uri=n.get("uri", cfg.neo4j.uri),
            user=n.get("user", cfg.neo4j.user),
            password_env=n.get("password_env", cfg.neo4j.password_env),
        )

    return cfg


@lru_cache(maxsize=1)
def get_config() -> AIPTTConfig:
    """Load and cache the global AIPTT configuration."""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "rb") as f:
            raw = tomllib.load(f)
        return _parse_config(raw)
    return AIPTTConfig()  # All defaults


def reload_config() -> AIPTTConfig:
    """Force reload config (clears lru_cache). Useful for tests."""
    get_config.cache_clear()
    return get_config()


def write_default_config() -> None:
    """Write the default config.toml to ~/.config/aiptt/config.toml."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(
        """\
[core]
log_level        = "INFO"
output_base_dir  = "~/.aiptt/engagements"
ai_model         = "claude-sonnet-4-6"
ai_api_key_env   = "AIPTT_AI_API_KEY"
max_pivot_depth  = 3

[database]
engine           = "sqlite"
sqlite_path      = "~/.aiptt/aiptt.db"
# postgresql_url = "postgresql://user:pass@localhost/aiptt"

[encryption]
key_env          = "AIPTT_MASTER_KEY"
key_rotation_days = 90
vault_path       = "~/.aiptt/vault"

[audit]
log_path         = "~/.aiptt/audit.db"
syslog_forward   = false
syslog_host      = "siem.corp.local"
syslog_port      = 514
retention_months = 12

[sandbox]
docker_socket    = "unix:///var/run/docker.sock"
sandbox_image    = "aiptt-sandbox:latest"
timeout_seconds  = 120
network_mode     = "none"

[guardrail]
fail_open                  = false
circuit_breaker_enabled    = true
anomaly_cpu_threshold_pct  = 80
anomaly_io_threshold_mbps  = 500

[discovery]
default_scan_rate    = "T3"
max_concurrent_hosts = 256
udp_scan_enabled     = true
honeypot_detection   = true

[credential_attacks]
default_max_attempts_per_account = 2
lockout_safety_margin            = 2
spray_window_minutes             = 60

[retention]
artefact_retention_days = 90
max_retention_days      = 365

[neo4j]
uri          = "bolt://localhost:7687"
user         = "neo4j"
password_env = "NEO4J_PASSWORD"
"""
    )
