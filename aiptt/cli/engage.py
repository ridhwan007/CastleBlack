"""
Engagement management commands.

  aiptt engage init    — initialise and validate a new engagement
  aiptt engage status  — show current engagement status
  aiptt engage pause   — pause the OPAV loop
  aiptt engage resume  — resume a paused engagement
  aiptt engage close   — close and archive engagement
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app     = typer.Typer(help="Manage engagement lifecycle.")
console = Console()


@app.command("init")
def init(
    name:        str  = typer.Option(...,  "--name",         "-n", help="Engagement name"),
    cidr:        str  = typer.Option(...,  "--cidr",         "-c", help="Target CIDR (comma-separated)"),
    roe:         str  = typer.Option(...,  "--roe",               help="Path to signed RoE document"),
    output_dir:  str  = typer.Option("./engagements", "--output-dir", help="Output directory"),
    max_pivots:  int  = typer.Option(3,    "--max-pivots",         help="Max lateral movement hops"),
    dry_run:     bool = typer.Option(False, "--dry-run",            help="Validate only, do not persist"),
):
    """Initialise a new penetration testing engagement."""
    from aiptt.core.config import get_config
    from aiptt.guardrail.scope_enforcer import RoEValidator, ScopeEnforcer
    from aiptt.audit.logger import get_audit_logger
    from aiptt.storage.db import init_db, get_session_factory
    from aiptt.storage.models import Engagement
    from aiptt.core.state_manager import EngagementConfig
    import uuid, datetime

    console.print(Panel("[bold cyan]AIPTT — Engagement Initialisation[/bold cyan]", expand=False))

    # 1. Validate RoE
    roe_path = Path(roe)
    if not roe_path.exists():
        console.print(f"[red]ERROR:[/red] RoE file not found: {roe}")
        raise typer.Exit(1)

    validator = RoEValidator()
    roe_hash  = validator.verify_signature(str(roe_path))
    console.print(f"[green]✓[/green] RoE document accepted (SHA-256: {roe_hash[:16]}...)")

    # 2. Parse and validate CIDRs
    cidrs = [c.strip() for c in cidr.split(",") if c.strip()]
    from aiptt.utils.net import is_valid_cidr
    for c in cidrs:
        if not is_valid_cidr(c):
            console.print(f"[red]ERROR:[/red] Invalid CIDR: {c}")
            raise typer.Exit(1)

    scope = ScopeEnforcer(allowed_cidrs=cidrs, excluded_ips=[])
    console.print(f"[green]✓[/green] Scope validated — {len(cidrs)} CIDR(s): {', '.join(cidrs)}")

    if dry_run:
        console.print("[yellow]Dry-run mode — no changes persisted.[/yellow]")
        raise typer.Exit(0)

    # 3. Initialise DB
    cfg = get_config()
    init_db()
    session_factory = get_session_factory()

    # 4. Create Engagement record
    engagement_id = f"ENG-{str(uuid.uuid4())[:8].upper()}"
    with session_factory() as session:
        eng = Engagement(
            id=engagement_id,
            name=name,
            target_cidr=cidr,
            roe_document_hash=roe_hash,
            status="ACTIVE",
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        session.add(eng)
        session.commit()

    # 5. Audit log
    audit = get_audit_logger()
    audit.log_intent("ENGAGEMENT_INIT", engagement=engagement_id, name=name, cidr=cidr)

    # 6. Write state
    out_path = Path(output_dir) / engagement_id
    out_path.mkdir(parents=True, exist_ok=True)

    cfg_text = (
        f"engagement_id = \"{engagement_id}\"\n"
        f"name          = \"{name}\"\n"
        f"cidr          = \"{cidr}\"\n"
        f"output_dir    = \"{out_path}\"\n"
        f"max_pivots    = {max_pivots}\n"
    )
    (out_path / "engagement.toml").write_text(cfg_text, encoding="utf-8")

    console.print()
    console.print(Panel(
        f"[bold green]Engagement created successfully![/bold green]\n\n"
        f"ID:         [cyan]{engagement_id}[/cyan]\n"
        f"Name:       {name}\n"
        f"Scope:      {cidr}\n"
        f"Output dir: {out_path}",
        title="Engagement Initialised",
        expand=False,
    ))
    console.print(f"\nTo start the attack loop:\n  [bold]aiptt attack run --engagement-id {engagement_id}[/bold]")


@app.command("status")
def status(
    engagement_id: str = typer.Option(..., "--engagement-id", "-e", help="Engagement ID"),
):
    """Show current engagement status."""
    from aiptt.storage.db import get_session_factory, init_db
    from aiptt.storage.models import Engagement, Finding

    init_db()
    session_factory = get_session_factory()

    with session_factory() as session:
        eng = session.query(Engagement).filter(Engagement.id == engagement_id).first()
        if not eng:
            console.print(f"[red]Engagement not found:[/red] {engagement_id}")
            raise typer.Exit(1)

        findings = session.query(Finding).filter(Finding.engagement_id == engagement_id).all()

    from collections import Counter
    by_sev = Counter(f.severity for f in findings)

    table = Table(title=f"Engagement: {eng.name} ({engagement_id})")
    table.add_column("Field",  style="cyan")
    table.add_column("Value",  style="white")
    table.add_row("Status",   eng.status)
    table.add_row("CIDR",     eng.target_cidr)
    table.add_row("Created",  str(eng.created_at))
    table.add_row("Findings", str(len(findings)))
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if by_sev.get(sev, 0) > 0:
            table.add_row(f"  {sev}", str(by_sev[sev]))
    console.print(table)


@app.command("pause")
def pause(
    engagement_id: str = typer.Argument(..., help="Engagement ID to pause"),
):
    """Pause the OPAV loop for an engagement."""
    from aiptt.storage.db import get_session_factory, init_db
    from aiptt.storage.models import Engagement
    init_db()
    with get_session_factory()() as session:
        eng = session.query(Engagement).filter(Engagement.id == engagement_id).first()
        if not eng:
            console.print(f"[red]Not found:[/red] {engagement_id}")
            raise typer.Exit(1)
        eng.status = "PAUSED"
        session.commit()
    console.print(f"[yellow]Paused:[/yellow] {engagement_id}")


@app.command("resume")
def resume(
    engagement_id: str = typer.Argument(..., help="Engagement ID to resume"),
):
    """Resume a paused engagement."""
    from aiptt.storage.db import get_session_factory, init_db
    from aiptt.storage.models import Engagement
    init_db()
    with get_session_factory()() as session:
        eng = session.query(Engagement).filter(Engagement.id == engagement_id).first()
        if not eng:
            console.print(f"[red]Not found:[/red] {engagement_id}")
            raise typer.Exit(1)
        eng.status = "ACTIVE"
        session.commit()
    console.print(f"[green]Resumed:[/green] {engagement_id}")


@app.command("close")
def close(
    engagement_id: str = typer.Argument(..., help="Engagement ID to close"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
):
    """Close and archive an engagement."""
    from aiptt.storage.db import get_session_factory, init_db
    from aiptt.storage.models import Engagement
    if not confirm:
        typer.confirm(f"Close engagement {engagement_id}?", abort=True)
    init_db()
    with get_session_factory()() as session:
        eng = session.query(Engagement).filter(Engagement.id == engagement_id).first()
        if not eng:
            console.print(f"[red]Not found:[/red] {engagement_id}")
            raise typer.Exit(1)
        eng.status = "CLOSED"
        session.commit()
    console.print(f"[green]Closed:[/green] {engagement_id}")
