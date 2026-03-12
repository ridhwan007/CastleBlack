"""
Lateral movement engine.

FR-ATK-04 | Edge case: production-critical hosts require HITL gate.
Domain trust boundaries are checked before crossing.
"""

from __future__ import annotations

from aiptt.attacks.base import AttackResult
from aiptt.audit.logger import get_audit_logger


class LateralMovementEngine:
    """
    Orchestrates multi-hop lateral movement across compromised hosts.

    Crown-jewel gate: if next hop is tagged as database / payment_processor /
    HSM / DC / CA — pause and require HITL approval token.

    Domain trust boundary: if next hop is in a different domain not in scope,
    log an informational finding and halt.
    """

    CROWN_JEWEL_TAGS = {
        "database", "payment_processor", "hsm",
        "domain_controller", "certificate_authority",
    }

    def __init__(self, guardrail, graph, audit=None):
        self.guardrail = guardrail
        self.graph     = graph
        self.audit     = audit or get_audit_logger()

    def attempt_pivot(
        self,
        source_ip: str,
        target_ip: str,
        technique: str,
        credentials: dict,
        state,
    ) -> AttackResult:
        """Attempt lateral movement from source_ip to target_ip."""
        self.audit.log_intent("LATERAL_MOVE_ATTEMPT",
                               source=source_ip,
                               target=target_ip,
                               technique=technique)

        # Crown-jewel gate (FR-ATK-04 edge case)
        target_meta = self.graph.get_host_metadata(target_ip)
        target_tags = set(target_meta.get("tags", []))
        if target_tags & self.CROWN_JEWEL_TAGS:
            return self._request_hitl_approval(
                source_ip, target_ip, target_tags, state)

        # Domain trust boundary check (Edge case 4.6)
        target_domain = target_meta.get("domain", "")
        source_domain = self.graph.get_host_metadata(source_ip).get("domain", "")
        if target_domain and target_domain != source_domain:
            if not state.is_domain_in_scope(target_domain):
                self.audit.log_event(
                    "TRUST_BOUNDARY_BLOCKED",
                    source_domain=source_domain,
                    target_domain=target_domain,
                    target_ip=target_ip,
                )
                state.record_informational_finding(
                    title="Unvalidated Trust Boundary",
                    description=(
                        f"Domain trust detected from {source_domain} to "
                        f"{target_domain} — not in approved scope."
                    ),
                    target=target_ip,
                )
                return AttackResult(False, "TRUST_BOUNDARY_OUT_OF_SCOPE",
                                    False, "none", "")

        # Execute pivot
        module = self._select_pivot_module(technique)
        return module.execute(target_ip, {"source_ip": source_ip, **credentials})

    def _request_hitl_approval(
        self, source: str, target: str, tags: set, state
    ) -> AttackResult:
        """Pause and request human approval for crown-jewel pivot."""
        from rich.prompt import Prompt
        from rich import print as rprint

        rprint(f"\n[bold red]>>> CROWN-JEWEL TARGET DETECTED[/bold red]")
        rprint(f"Target: [yellow]{target}[/yellow]  Tags: [yellow]{sorted(tags)}[/yellow]")
        rprint("[dim]Partial report generated. Review before approving.[/dim]")

        # Generate partial report
        try:
            from aiptt.reporting.technical import TechnicalReporter
            report_path = f"/tmp/partial_report_{getattr(state, 'engagement_id', 'unknown')}.pdf"
            TechnicalReporter(state).generate_partial(output_path=report_path)
            rprint(f"Report saved: [cyan]{report_path}[/cyan]")
        except Exception:
            pass

        token = Prompt.ask("Enter HITL approval token (leave blank to skip)",
                           default="", password=True)
        if not token or not state.validate_hitl_token(token):
            self.audit.log_event("HITL_CROWN_JEWEL_DENIED", target=target)
            return AttackResult(
                False, "CROWN_JEWEL_HITL_DENIED", False, "none",
                "Crown-jewel target — operator declined or token invalid",
            )

        self.audit.log_event("HITL_CROWN_JEWEL_APPROVED",
                              target=target, token_used=True)
        return self._execute_crown_jewel_pivot(source, target, state)

    def _execute_crown_jewel_pivot(
        self, source: str, target: str, state
    ) -> AttackResult:
        """Execute approved crown-jewel pivot with full audit trail."""
        from aiptt.attacks.lateral.smb_pivot import Module as SMBPivot
        module = SMBPivot()
        creds  = state.credential_cache[0] if state.credential_cache else {}
        return module.execute(target, {"source_ip": source, **creds})

    def _select_pivot_module(self, technique: str):
        """Select the appropriate pivot module for the given MITRE technique."""
        from aiptt.attacks.lateral.smb_pivot   import Module as SMBPivot
        from aiptt.attacks.lateral.token_theft import Module as TokenTheft
        mapping = {
            "T1021.002": SMBPivot(),
            "T1134":     TokenTheft(),
            "T1134.001": TokenTheft(),
        }
        return mapping.get(technique, SMBPivot())
