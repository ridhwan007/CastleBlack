"""
Nessus-mode engagement bootstrap.

Replaces the live discovery phase (HostSweeper + VulnerabilityScanner +
ServiceFingerprinter) with a parsed .nessus file.

The output of this module is identical to what the live scan phase produces:
  - Knowledge graph populated with HostNode / ServiceNode / VulnerabilityNode
  - SessionState populated with discovered hosts and scope
  - NessusScanResult returned for AI planner context injection

Typical flow:
    bootstrap = NessusEngagementBootstrap(audit, config)
    result    = bootstrap.prepare(nessus_file_path, session_state, knowledge_graph)
    # Then hand result.summary_dict() to AIPlannerEngine as extra context
    planner.inject_scan_context(result.summary_dict())
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from aiptt.discovery.nessus_parser import NessusParser, NessusScanResult
from aiptt.guardrail.scope_enforcer import ScopeEnforcer
from aiptt.discovery.honeypot_detector import HoneypotDetector
from aiptt.utils.display import console

if TYPE_CHECKING:
    from aiptt.audit.logger import AuditLogger
    from aiptt.core.state_manager import SessionState, EngagementConfig
    from aiptt.graph.knowledge_graph import KnowledgeGraph


class NessusEngagementBootstrap:
    """
    Bootstraps an engagement from a Nessus file instead of live scanning.

    Steps:
      1. Validate the .nessus file path and integrity
      2. Parse with NessusParser (scope-aware, honeypot detection)
      3. Load all findings into the Neo4j knowledge graph
      4. Print a Rich discovery summary to the console
      5. Return NessusScanResult for planner context injection
    """

    def __init__(
        self,
        audit: "AuditLogger",
        config: "EngagementConfig",
    ):
        self.audit  = audit
        self.config = config

        scope_enforcer = ScopeEnforcer(
            allowed_cidrs=([config.cidr] if config.cidr else []),
            exclusions=config.exclusions,
        )

        self.parser = NessusParser(
            audit=audit,
            scope_enforcer=scope_enforcer if config.cidr else None,
            honeypot_detector=HoneypotDetector(),
        )

    def prepare(
        self,
        nessus_file: str | Path,
        state: "SessionState",
        kg: "KnowledgeGraph | None" = None,
    ) -> NessusScanResult:
        """
        Full bootstrap sequence.

        Args:
            nessus_file:  Path to .nessus or .nessus.gz file
            state:        SessionState to register discovered hosts into
            kg:           KnowledgeGraph to populate (optional — skip if no Neo4j)

        Returns:
            NessusScanResult — pass .summary_dict() to AI planner
        """
        nessus_file = Path(nessus_file)
        self._validate_file(nessus_file)

        console.print(f"\n[bold cyan]► Nessus import:[/bold cyan] {nessus_file.name}")

        # Parse
        result = self.parser.parse(nessus_file)

        # Print discovery summary
        self._print_summary(result)

        # Populate knowledge graph
        if kg is not None:
            console.print("[dim]  Loading into knowledge graph…[/dim]")
            self.parser.load_into_knowledge_graph(result, kg)
            console.print(
                f"[green]  ✓ {len(result.in_scope_hosts)} hosts, "
                f"{result.total_vulns} findings loaded[/green]"
            )

        # Wire KG into state
        if kg is not None:
            state.knowledge_graph = kg

        # Build in-memory observations for OPAV OBSERVE phase.
        # This is used when Neo4j is unavailable — the OPAV loop reads
        # state.nessus_observations as a fallback instead of querying the KG.
        state.nessus_observations = [
            {
                "ip": nhost.ip,
                "hostname": nhost.fqdn or nhost.hostname,
                "os": nhost.os_guess,
                "visit_count": 0,
                "vulnerabilities": [
                    {
                        "cve": v.cve_id,
                        "cvss": v.cvss_score,
                        "severity": v.severity,
                        "port": v.port,
                        "service": v.service,
                        "description": v.description[:200],
                        "evidence": v.evidence[:200],
                    }
                    for v in sorted(
                        nhost.vulnerabilities,
                        key=lambda v: v.cvss_score,
                        reverse=True,
                    )
                ],
                "services": [
                    {"port": s.port, "proto": s.protocol, "name": s.svc_name}
                    for s in nhost.services
                ],
                "exploit_available": nhost.exploit_available,
                "ad_surface": nhost.ad_surface,
            }
            for nhost in result.in_scope_hosts
            if not nhost.suspected_honeypot
        ]

        self.audit.log_event(
            "NESSUS_BOOTSTRAP_COMPLETE",
            engagement_id=state.engagement_id,
            scan_file=str(nessus_file),
            sha256=result.file_sha256,
            hosts_loaded=len(result.in_scope_hosts),
            vulns_loaded=result.total_vulns,
            exploit_ready=len(result.exploit_ready_hosts),
        )

        return result

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_file(self, path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(f"Nessus file not found: {path}")

        suffix = path.suffix.lower()
        if suffix not in (".nessus", ".gz", ".xml"):
            raise ValueError(
                f"Unsupported file type: {path.suffix}. "
                "Expected .nessus, .nessus.gz, or .xml"
            )

        size_mb = path.stat().st_size / (1024 * 1024)
        if size_mb > 2048:
            self.audit.log_event(
                "NESSUS_FILE_LARGE_WARNING",
                size_mb=round(size_mb, 1),
                file=str(path),
            )

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def _print_summary(self, result: NessusScanResult) -> None:
        """Print a Rich discovery summary table to the console."""
        from rich.table import Table

        console.print(f"\n[bold]Scan:[/bold] {result.scan_name}")
        console.print(f"[dim]SHA-256: {result.file_sha256[:16]}…[/dim]")

        table = Table(
            title="Nessus Discovery Summary",
            show_header=True,
            header_style="bold magenta",
            box=None,
            padding=(0, 2),
        )
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="bold white", justify="right")

        in_scope   = len(result.in_scope_hosts)
        excluded   = result.total_hosts - in_scope
        honeypots  = sum(1 for h in result.hosts if h.suspected_honeypot)
        critical   = sum(h.critical_count for h in result.in_scope_hosts)
        high       = sum(h.high_count for h in result.in_scope_hosts)
        exploit_rdy = len(result.exploit_ready_hosts)
        ad_hosts   = sum(1 for h in result.in_scope_hosts if h.ad_surface)

        table.add_row("Total hosts in file",     str(result.total_hosts))
        table.add_row("In-scope hosts",          f"[green]{in_scope}[/green]")
        table.add_row("Scope-excluded",          str(excluded) if excluded else "[dim]0[/dim]")
        table.add_row("Suspected honeypots",     f"[yellow]{honeypots}[/yellow]" if honeypots else "[dim]0[/dim]")
        table.add_row("Total findings",          str(result.total_vulns))
        table.add_row("  Critical",              f"[red bold]{critical}[/red bold]" if critical else "[dim]0[/dim]")
        table.add_row("  High",                  f"[orange1]{high}[/orange1]" if high else "[dim]0[/dim]")
        table.add_row("Exploit-available hosts", f"[red]{exploit_rdy}[/red]" if exploit_rdy else "[dim]0[/dim]")
        table.add_row("AD surface hosts",        f"[cyan]{ad_hosts}[/cyan]" if ad_hosts else "[dim]0[/dim]")

        console.print(table)

        # Top targets preview
        if result.in_scope_hosts:
            console.print("\n[bold]Top attack targets:[/bold]")
            for i, h in enumerate(result.prioritized_hosts()[:5], 1):
                exploit_tag = " [red][EXPLOIT][/red]" if h.exploit_available else ""
                ad_tag      = " [cyan][AD][/cyan]" if h.ad_surface else ""
                console.print(
                    f"  {i}. [bold]{h.ip}[/bold] "
                    f"({h.fqdn or h.os_guess or 'Unknown OS'}) "
                    f"CVSS {h.max_cvss:.1f} — "
                    f"[red]{h.critical_count}C[/red]/"
                    f"[orange1]{h.high_count}H[/orange1]"
                    f"{exploit_tag}{ad_tag}"
                )
        console.print()
