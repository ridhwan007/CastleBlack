"""
Docker sandbox executor.

All attack modules run inside isolated Docker containers.
Network mode: bridge (scoped by iptables on the host).
CPU: 50% cap. Memory: 512 MB cap. Timeout: 120 seconds.
"""

from __future__ import annotations

import json
import time
import tempfile
import os
from pathlib import Path

from aiptt.attacks.base import AbstractAttackModule, AttackResult
from aiptt.core.config import get_config


class SandboxExecutor:
    """
    Runs exploit modules inside isolated Docker containers.

    Container constraints:
      - network_mode: bridge (iptables scope rules applied by ScopeEnforcer)
      - mem_limit:    512m
      - cpu_quota:    50000 / 100000  (50% CPU cap)
      - remove:       True (auto-cleanup)
      - timeout:      120 seconds (configurable)
    """

    def __init__(self, docker_socket: str | None = None, audit=None):
        cfg            = get_config()
        self.socket    = docker_socket or cfg.sandbox.docker_socket
        self.image     = cfg.sandbox.sandbox_image
        self.timeout   = cfg.sandbox.timeout_seconds
        self.audit     = audit

        try:
            import docker
            self.client = docker.DockerClient(base_url=self.socket)
        except Exception as e:
            self.client = None
            if audit:
                audit.log_event("SANDBOX_DOCKER_UNAVAILABLE", error=str(e))

    # ------------------------------------------------------------------
    # Run a registered module
    # ------------------------------------------------------------------

    def run(self, module: AbstractAttackModule, task) -> AttackResult:
        """Execute a registered module inside a Docker container."""
        if self.client is None:
            return AttackResult(False, "SANDBOX_UNAVAILABLE", False, "none",
                                "Docker client not available")

        start = time.time()
        cmd   = self._build_command(module, task)

        if self.audit:
            self.audit.log_intent("SANDBOX_EXEC_START",
                                   module=task.module_id, target=task.target)
        try:
            import docker
            container_output = self.client.containers.run(
                self.image,
                command=cmd,
                network_mode="bridge",
                remove=True,
                detach=False,
                timeout=self.timeout,
                mem_limit="512m",
                cpu_period=100000,
                cpu_quota=50000,        # 50% CPU cap
                environment={
                    "AIPTT_TARGET": task.target,
                    "AIPTT_MODULE": task.module_id,
                },
            )
            output  = container_output.decode("utf-8", errors="replace")
            result  = self._parse_output(output)
            result.elapsed = time.time() - start

            if self.audit:
                self.audit.log_event("SANDBOX_EXEC_COMPLETE",
                                      module=task.module_id,
                                      outcome=result.outcome,
                                      elapsed=result.elapsed)
            return result

        except Exception as e:
            elapsed = time.time() - start
            if "timeout" in str(e).lower():
                if self.audit:
                    self.audit.log_event("SANDBOX_TIMEOUT",
                                          module=task.module_id)
                self._queue_for_review(task, reason="sandbox_timeout")
                return AttackResult(False, "SANDBOX_TIMEOUT", False, "none",
                                    str(e), elapsed=elapsed)

            return AttackResult(False, "CONTAINER_ERROR", False, "none",
                                str(e), elapsed=elapsed)

    # ------------------------------------------------------------------
    # Run raw generated code
    # ------------------------------------------------------------------

    def run_raw_code(self, code: str, task) -> AttackResult:
        """
        Execute raw Python exploit code (from ExploitGenerator) in a container.
        Writes code to a temp file, mounts it into the container.
        """
        if self.client is None:
            raise RuntimeError("Docker client not available")

        start = time.time()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as tf:
            tf.write(code)
            tmp_path = tf.name

        try:
            import docker
            container_output = self.client.containers.run(
                self.image,
                command=f"python /exploit/exploit.py",
                network_mode="bridge",
                remove=True,
                detach=False,
                timeout=90,   # Generated exploits have a shorter timeout
                mem_limit="256m",
                cpu_quota=25000,
                volumes={tmp_path: {"bind": "/exploit/exploit.py", "mode": "ro"}},
                environment={"AIPTT_TARGET": task.target},
            )
            output = container_output.decode("utf-8", errors="replace")
            result = self._parse_output(output)
            result.elapsed = time.time() - start
            return result

        finally:
            os.unlink(tmp_path)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_command(self, module, task) -> str:
        """Build the container invocation command."""
        payload = json.dumps({
            "module":     task.module_id,
            "target":     task.target,
            "parameters": task.parameters,
        })
        return f"python -m aiptt_runner '{payload}'"

    def _parse_output(self, output: str) -> AttackResult:
        """Parse the last JSON line from container stdout."""
        lines = [l for l in output.strip().split("\n") if l.strip()]
        for line in reversed(lines):
            try:
                data = json.loads(line)
                return AttackResult(
                    success=data.get("success", False),
                    outcome=data.get("outcome", "SUCCESS" if data.get("success") else "FAILURE"),
                    gained_access=data.get("gained_access", False),
                    access_level=data.get("access_level", "none"),
                    output=data.get("output", output[:1000]),
                    credentials_captured=data.get("credentials_captured", []),
                    error=data.get("error", ""),
                )
            except json.JSONDecodeError:
                continue

        return AttackResult(False, "PARSE_ERROR", False, "none", output[:1000])

    def _queue_for_review(self, task, reason: str) -> None:
        try:
            from aiptt.storage.db import get_session
            from aiptt.storage.models import HumanReviewQueue
            with get_session() as session:
                session.add(HumanReviewQueue(
                    task_id=task.id,
                    module_id=task.module_id,
                    target=task.target,
                    reason=reason,
                ))
        except Exception:
            pass
