"""
Attack execution commands.

  aiptt attack run    — start/stream the OPAV autonomous loop
  aiptt attack plan   — dry-run: show Claude's ranked attack queue
  aiptt attack exec   — execute a single module manually
  aiptt attack lateral — trigger lateral movement from a compromised host
"""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

app     = typer.Typer(help="Attack execution commands.")
console = Console()


@app.command("run")
def run(
    engagement_id: str  = typer.Option(..., "--engagement-id", "-e"),
    max_cycles:    int  = typer.Option(10,  "--max-cycles",  help="Max OPAV cycles"),
    max_pivots:    int  = typer.Option(3,   "--max-pivots"),
    verbose:       bool = typer.Option(False, "--verbose", "-v"),
):
    """Start the autonomous OPAV attack loop."""
    from aiptt.storage.db import init_db, get_session_factory
    from aiptt.storage.models import Engagement
    from aiptt.core.state_manager import SessionState, EngagementConfig
    from aiptt.core.opav_loop import OPAVLoop
    from aiptt.utils.display import build_findings_table

    init_db()
    session_factory = get_session_factory()

    with session_factory() as session:
        eng = session.query(Engagement).filter(Engagement.id == engagement_id).first()
        if not eng:
            console.print(f"[red]Engagement not found:[/red] {engagement_id}")
            raise typer.Exit(1)
        cidr = eng.target_cidr

    cfg = EngagementConfig(
        engagement_id=engagement_id,
        target_cidrs=[c.strip() for c in cidr.split(",")],
        excluded_ips=[],
        max_pivots=max_pivots,
        output_dir=f"./engagements/{engagement_id}",
    )

    loop = OPAVLoop(config=cfg, session_factory=session_factory)

    console.print(Panel(
        f"[bold cyan]Starting OPAV loop[/bold cyan]\n"
        f"Engagement: [cyan]{engagement_id}[/cyan]  |  Max cycles: {max_cycles}",
        expand=False,
    ))

    all_results = []
    try:
        for result in loop.run(max_cycles=max_cycles):
            all_results.append(result)
            icon = "[green]✓[/green]" if result.success else "[red]✗[/red]"
            console.print(
                f"{icon} [{result.task_id}] {result.module_id} → "
                f"{result.classification} "
                f"({'CVSS ' + str(result.cvss) if result.cvss else ''})"
            )
            if verbose and result.output:
                console.print(f"  [dim]{result.output[:200]}[/dim]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Loop interrupted by user.[/yellow]")

    console.print(f"\n[bold]Run complete.[/bold] {len(all_results)} tasks executed.")


@app.command("plan")
def plan(
    engagement_id: str = typer.Option(..., "--engagement-id", "-e"),
    target:        str = typer.Option(..., "--target",         "-t", help="Target IP"),
    vulnerabilities: str = typer.Option("", "--vulns", help="Comma-separated CVE list"),
):
    """Dry-run: ask Claude to generate a ranked attack plan."""
    from aiptt.engine.ai_planner import AIPlannerEngine
    from aiptt.engine.path_scorer import PathScorer
    from aiptt.engine.replan_engine import ReplanEngine
    from aiptt.audit.logger import get_audit_logger
    from aiptt.utils.display import build_attack_queue_table

    audit    = get_audit_logger()
    scorer   = PathScorer()
    replanner = ReplanEngine()
    planner  = AIPlannerEngine(audit=audit, scorer=scorer, replanner=replanner)

    vuln_list = [v.strip() for v in vulnerabilities.split(",") if v.strip()]

    context = {
        "target":          target,
        "engagement_id":   engagement_id,
        "vulnerabilities": vuln_list,
        "compromised":     [],
    }

    console.print(f"[cyan]Asking Claude for attack plan...[/cyan]")

    tasks = planner.score_and_queue(context)

    table = build_attack_queue_table(tasks)
    console.print(table)
    console.print(f"\n[dim](Dry-run — no attacks executed)[/dim]")


@app.command("exec")
def exec_module(
    engagement_id: str = typer.Option(..., "--engagement-id", "-e"),
    module:        str = typer.Option(..., "--module",         "-m", help="Module ID (e.g. AD-KERB-001)"),
    target:        str = typer.Option(..., "--target",         "-t"),
    params:        str = typer.Option("{}","--params",              help="JSON params string"),
):
    """Execute a single attack module manually."""
    import json as _json
    from aiptt.attacks.registry import AttackRegistry
    from aiptt.audit.logger import get_audit_logger
    from aiptt.engine.exploit_generator import ExploitGenerator

    audit    = get_audit_logger()
    gen      = ExploitGenerator()
    registry = AttackRegistry(exploit_generator=gen, audit=audit)

    try:
        parameters = _json.loads(params)
    except _json.JSONDecodeError:
        console.print("[red]ERROR:[/red] --params must be valid JSON")
        raise typer.Exit(1)

    class _ManualTask:
        id          = "MANUAL-001"
        module_id   = module
        target      = target
        technique   = ""
        parameters  = parameters
        destructive = False

    audit.log_intent("MANUAL_EXEC", engagement=engagement_id, module=module, target=target)
    console.print(f"[cyan]Executing[/cyan] {module} → {target}")

    result = registry.execute(_ManualTask())

    if result.success:
        console.print(f"[green]SUCCESS[/green] — CVSS {result.cvss_score}")
    else:
        console.print(f"[red]FAILED[/red] — {result.error or 'no details'}")

    if result.output:
        console.print(Panel(result.output[:1000], title="Output", expand=False))


@app.command("lateral")
def lateral(
    engagement_id:  str = typer.Option(..., "--engagement-id", "-e"),
    source:         str = typer.Option(..., "--source",         help="Source (compromised) host IP"),
    destination:    str = typer.Option(..., "--destination",    help="Target host IP"),
    username:       str = typer.Option(..., "--username"),
    nt_hash:        str = typer.Option("", "--nt-hash"),
    password:       str = typer.Option("", "--password"),
):
    """Attempt lateral movement from a compromised host."""
    from aiptt.attacks.lateral.movement import LateralMovementEngine
    from aiptt.audit.logger import get_audit_logger

    audit = get_audit_logger()
    audit.log_intent("LATERAL_MOVEMENT",
                     engagement=engagement_id, source=source, destination=destination)

    engine = LateralMovementEngine(audit=audit)
    result = engine.move(
        source=source, destination=destination,
        username=username, nt_hash=nt_hash, password=password,
    )

    if result.success:
        console.print(f"[green]Lateral movement succeeded[/green] → {destination}")
    else:
        console.print(f"[red]Lateral movement failed[/red]: {result.error}")
