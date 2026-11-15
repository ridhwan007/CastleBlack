"""
Attack module registry.

Loads all attack modules from TOML manifests + Python implementations.
Dispatches execution: registered module → sandbox, or ExploitGenerator fallback.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from aiptt.attacks.base import AbstractAttackModule, AttackResult
from aiptt.attacks.sandbox import SandboxExecutor
from aiptt.guardrail.blast_radius import BlastRadiusGate


class AttackRegistry:
    """
    Loads, validates, and dispatches attack modules.

    Discovery: scans modules/**/*.toml for manifests.
    Each manifest has a companion .py file with a Module() class.

    FR-AI-06: If no module matches → fallback to ExploitGenerator.
    BR-SAFE-03: Destructive modules are gated by BlastRadiusGate.
    """

    MODULES_DIR = Path("modules")

    def __init__(
        self,
        sandbox: SandboxExecutor,
        blast_gate: BlastRadiusGate,
        audit,
    ):
        self.sandbox    = sandbox
        self.blast_gate = blast_gate
        self.audit      = audit

        self._modules: dict[str, AbstractAttackModule] = {}
        self._manifests: dict[str, dict] = {}
        self._load_all()

    # ------------------------------------------------------------------
    # Module loading
    # ------------------------------------------------------------------

    def _load_all(self) -> None:
        """Discover and load all TOML-manifested attack modules."""
        if not self.MODULES_DIR.exists():
            return

        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore
            except ImportError:
                self.audit.log_event("REGISTRY_TOMLLIB_MISSING")
                return

        for manifest_path in self.MODULES_DIR.rglob("*.toml"):
            try:
                with open(manifest_path, "rb") as f:
                    manifest = tomllib.load(f)

                module_id = manifest.get("module", {}).get("id")
                if not module_id:
                    continue

                self._manifests[module_id] = manifest

                # Load companion Python implementation
                impl_path = manifest_path.with_suffix(".py")
                if impl_path.exists():
                    spec = importlib.util.spec_from_file_location(
                        module_id, impl_path)
                    mod  = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    instance = mod.Module()

                    # Inject manifest metadata onto the instance
                    instance.module_id       = module_id
                    instance.mitre_technique = manifest["module"].get(
                        "mitre_technique", "T0000")
                    instance.destructive     = manifest["module"].get(
                        "destructive", False)
                    instance.sandboxable     = manifest["module"].get(
                        "sandboxable", True)

                    self._modules[module_id] = instance
                    self.audit.log_event("MODULE_LOADED", module_id=module_id)

            except Exception as e:
                self.audit.log_event("MODULE_LOAD_ERROR",
                                      path=str(manifest_path), error=str(e))

    # ------------------------------------------------------------------
    # Execution dispatcher
    # ------------------------------------------------------------------

    def execute(self, task) -> AttackResult:
        """
        Dispatch a task to its registered module or ExploitGenerator fallback.

        Steps:
          1. Look up module in registry
          2. If not found → ExploitGenerator (FR-AI-06)
          3. Run preflight() check
          4. Blast radius gate (BR-SAFE-03)
          5. Execute in sandbox if sandboxable, else direct
        """
        manifest = self._manifests.get(task.module_id)
        module   = self._modules.get(task.module_id)

        if not module:
            # FR-AI-06: No matching module → on-the-fly exploit generation
            self.audit.log_event("MODULE_NOT_FOUND_GENERATING",
                                  module_id=task.module_id)
            from aiptt.engine.exploit_generator import ExploitGenerator
            return ExploitGenerator(self.audit).generate_and_execute(
                task, self.sandbox)

        # Preflight check
        if not module.preflight(task.target, task.parameters):
            self.audit.log_event("MODULE_PREFLIGHT_FAILED",
                                  module_id=task.module_id, target=task.target)
            return AttackResult(False, "PREFLIGHT_FAILED", False, "none",
                                "Module preflight() returned False")

        # Blast radius gate (BR-SAFE-03)
        if module.destructive or (manifest and manifest.get("module", {}).get("destructive", False)):
            if not self.blast_gate.approve(task):
                return AttackResult(False, "BLAST_RADIUS_BLOCKED", False, "none",
                                    "Blocked by blast radius policy")

        # Execute
        if module.sandboxable and self.sandbox.client is not None:
            return self.sandbox.run(module, task)
        else:
            # Direct execution (sandbox unavailable or module not sandboxable)
            import time
            start = time.time()
            try:
                result = module.execute(task.target, task.parameters)
                result.elapsed = time.time() - start
                return result
            except Exception as e:
                return AttackResult(False, "EXEC_ERROR", False, "none",
                                    str(e), elapsed=time.time() - start)

    def list_modules(self) -> list[dict]:
        """Return summary of all loaded modules."""
        return [
            {
                "id":        mid,
                "technique": m.get("module", {}).get("mitre_technique", ""),
                "name":      m.get("module", {}).get("name", mid),
                "destructive": m.get("module", {}).get("destructive", False),
            }
            for mid, m in self._manifests.items()
        ]
