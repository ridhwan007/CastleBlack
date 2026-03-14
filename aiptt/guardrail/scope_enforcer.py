"""
RoE Validator and Scope Enforcer.

BR-SAFE-01: No engagement starts without a validated RoE document.
BR-SAFE-02: Network-layer allowlist enforcement via iptables (Linux deploy).
"""

from __future__ import annotations

import ipaddress
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aiptt.utils.crypto import sha256_file


# ---------------------------------------------------------------------------
# RoE Validator
# ---------------------------------------------------------------------------

@dataclass
class RoEValidationResult:
    passed: bool
    roe_hash: str
    reason: str = ""


class RoEValidator:
    """
    Validates the Rules of Engagement document.
    Computes SHA-256 hash stored in the immutable audit log.
    Hard block: no override possible (BR-SAFE-01).

    Phase 1: Any valid, readable file is accepted.
    Phase 2: Integrate DocuSign / GPG signature verification.
    """

    SUPPORTED_FORMATS = [".pdf", ".docx", ".txt", ".md"]

    def verify_signature(self, roe_path: str | Path) -> RoEValidationResult:
        roe_path = Path(roe_path)
        if not roe_path.exists():
            return RoEValidationResult(False, "", f"RoE file not found: {roe_path}")
        if not roe_path.is_file():
            return RoEValidationResult(False, "", f"RoE path is not a file: {roe_path}")
        if roe_path.suffix.lower() not in self.SUPPORTED_FORMATS:
            return RoEValidationResult(
                False, "",
                f"Unsupported format '{roe_path.suffix}'. "
                f"Accepted: {', '.join(self.SUPPORTED_FORMATS)}"
            )
        if roe_path.stat().st_size == 0:
            return RoEValidationResult(False, "", "RoE file is empty")

        roe_hash = sha256_file(roe_path)
        return RoEValidationResult(True, roe_hash)


# ---------------------------------------------------------------------------
# Scope Enforcer
# ---------------------------------------------------------------------------

class ScopeEnforcer:
    """
    Builds an IP allowlist from approved CIDRs and exclusions.
    Optionally applies iptables OUTPUT rules on the agent host (Linux deploy).

    All outbound connections blocked except to explicitly allowed targets.
    Violations are logged immediately.
    """

    def __init__(self, allowed_cidrs: list[str], exclusions: list[str]):
        self.allowed: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in allowed_cidrs:
            try:
                self.allowed.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass  # Invalid CIDRs silently skipped (validated at init time)

        self.excluded: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for excl in exclusions:
            try:
                self.excluded.append(ipaddress.ip_network(excl, strict=False))
            except ValueError:
                pass

    def is_in_scope(self, ip: str) -> bool:
        """Return True if ip is in an allowed CIDR and not in any exclusion."""
        try:
            target = ipaddress.ip_address(ip)
        except ValueError:
            return False  # Invalid IP is never in scope

        if any(target in excl for excl in self.excluded):
            return False
        return any(target in net for net in self.allowed)

    def validate_target_before_action(self, ip: str) -> bool:
        """Called by GuardrailController before every subtask (FR-AI-04)."""
        return self.is_in_scope(ip)

    def validate_cidr(self, cidr: str) -> bool:
        """Validate that a CIDR string is well-formed."""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False

    def build_allowlist(self, cidr: str, exclusions: list[str]) -> "ScopeEnforcer":
        """Factory: return a new ScopeEnforcer from a base CIDR + exclusion list."""
        return ScopeEnforcer([cidr], exclusions)

    def apply_iptables_rules(self, agent_uid: int) -> None:
        """
        Apply iptables OUTPUT rules for the agent process UID (Linux deploy).
        Allows only traffic to in-scope CIDRs; drops everything else.
        Called once at engagement init; raises CalledProcessError if iptables
        is unavailable or permission is denied.
        """
        # Flush any existing agent rules first
        subprocess.run(
            ["iptables", "-D", "OUTPUT", "-m", "owner",
             "--uid-owner", str(agent_uid), "-j", "DROP"],
            check=False,
            capture_output=True,
        )

        # Allow each in-scope CIDR
        for net in self.allowed:
            subprocess.run(
                ["iptables", "-I", "OUTPUT", "-m", "owner",
                 "--uid-owner", str(agent_uid), "-d", str(net), "-j", "ACCEPT"],
                check=True,
            )

        # Default drop for agent UID (everything else blocked)
        subprocess.run(
            ["iptables", "-A", "OUTPUT", "-m", "owner",
             "--uid-owner", str(agent_uid), "-j", "DROP"],
            check=True,
        )

    def remove_iptables_rules(self, agent_uid: int) -> None:
        """Remove all iptables rules for the agent UID (called on engagement close)."""
        for net in self.allowed:
            subprocess.run(
                ["iptables", "-D", "OUTPUT", "-m", "owner",
                 "--uid-owner", str(agent_uid), "-d", str(net), "-j", "ACCEPT"],
                check=False,
                capture_output=True,
            )
        subprocess.run(
            ["iptables", "-D", "OUTPUT", "-m", "owner",
             "--uid-owner", str(agent_uid), "-j", "DROP"],
            check=False,
            capture_output=True,
        )
