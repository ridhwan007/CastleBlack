"""
Abstract base class for all AIPTT attack modules.

All attack modules must subclass AbstractAttackModule and implement execute().
Metadata is loaded from companion TOML manifests at startup.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class AttackResult:
    """
    Standardised result returned by every attack module.

    success              — True if exploit achieved its objective
    outcome              — Human-readable outcome string
    gained_access        — True if the module obtained shell/auth access
    access_level         — none | user | local_admin | domain_admin
    output               — Raw command/tool output (stored in PoE vault)
    credentials_captured — List of credential dicts (vault refs after capture)
    elapsed              — Wall-clock execution time in seconds
    error                — Error message if outcome == ERROR
    """
    success:              bool
    outcome:              str    # SUCCESS | FAILURE | PARTIAL | ERROR | SKIPPED
    gained_access:        bool
    access_level:         str    # none | user | local_admin | domain_admin
    output:               str
    credentials_captured: list[dict] = field(default_factory=list)
    elapsed:              float = 0.0
    error:                str   = ""


class AbstractAttackModule(ABC):
    """
    Base class for all attack modules.

    Subclass contract:
      - Set class attributes: module_id, mitre_technique
      - Implement execute()
      - Optionally override preflight() for pre-run validation

    Metadata (destructive, sandboxable, etc.) is also declared as class attrs
    and overridden by the TOML manifest at load time by AttackRegistry.
    """

    module_id:       str  = "UNKNOWN"
    mitre_technique: str  = "T0000"
    destructive:     bool = False   # BR-SAFE-03: must be False for auto-execution
    sandboxable:     bool = True

    @abstractmethod
    def execute(self, target: str, parameters: dict) -> AttackResult:
        """
        Execute the attack against target with the given parameters.
        Must not be destructive unless explicitly gated.
        Must return within the sandbox timeout (120s default).
        """
        ...

    def preflight(self, target: str, parameters: dict) -> bool:
        """
        Optional pre-execution validation.
        Return False to skip this module for this target/parameter set.
        Default: always returns True.
        """
        return True
