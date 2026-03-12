"""
Session management commands.

  aiptt session list    — list all engagements
  aiptt session load    — load / restore a session checkpoint
  aiptt session export  — export session state to JSON
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

app     = typer.Typer(help="Session management commands.")
console = Console()


@app.command("list")
def list_sessions():
    """List all engagements in the database."""
    from aiptt.storage.db import init_db, get_session_factory
    from aiptt.storage.models import Engagement, Finding
    from collections import Counter

    init_db()
    with get_session_factory()() as session:
        engagements = session.query(Engagement).all()
        if not engagements:
            console.print("[yellow]No engagements found.[/yellow]")
            return

        table = Table(title="Engagements")
        table.add_column("ID",       style="cyan")
        table.add_column("Name",     style="white")
        table.add_column("Status",   style="green")
        table.add_column("CIDR",     style="dim")
        table.add_column("Findings", style="yellow")
        table.add_column("Created",  style="dim")

        for eng in engagements:
            n_findings = session.query(Finding).filter(
                Finding.engagement_id == eng.id
            ).count()
            table.add_row(
                eng.id,
                eng.name,
                eng.status,
                eng.target_cidr,
                str(n_findings),
                str(eng.created_at)[:19] if eng.created_at else "",
            )

    console.print(table)


@app.command("load")
def load(
    engagement_id: str = typer.Argument(..., help="Engagement ID to restore"),
    checkpoint:    str = typer.Option("", "--checkpoint", "-c",
                                      help="Path to state.json checkpoint file"),
):
    """Restore a session from a checkpoint file."""
    from pathlib import Path
    from aiptt.core.state_manager import SessionState, EngagementConfig
    from aiptt.storage.db import init_db, get_session_factory
    from aiptt.storage.models import Engagement

    init_db()
    with get_session_factory()() as session:
        eng = session.query(Engagement).filter(Engagement.id == engagement_id).first()
        if not eng:
            console.print(f"[red]Engagement not found:[/red] {engagement_id}")
            raise typer.Exit(1)

    checkpoint_path = checkpoint or f"./engagements/{engagement_id}/state.json"

    if not Path(checkpoint_path).exists():
        console.print(f"[red]Checkpoint not found:[/red] {checkpoint_path}")
        raise typer.Exit(1)

    state = SessionState.restore_from_checkpoint(checkpoint_path)
    console.print(f"[green]Session loaded:[/green] {engagement_id}")
    console.print(f"  Cycle:             {state.cycle}")
    console.print(f"  Compromised hosts: {len(state.compromised_hosts)}")
    console.print(f"  Credentials:       {len(state.credential_cache)}")
    console.print(f"  Pivot count:       {state.pivot_count}")


@app.command("export")
def export(
    engagement_id: str = typer.Argument(..., help="Engagement ID"),
    output:        str = typer.Option("",  "--output", "-o", help="Output file path"),
):
    """Export session state to JSON."""
    import json
    from pathlib import Path
    from aiptt.storage.db import init_db, get_session_factory
    from aiptt.storage.models import Engagement, Finding

    init_db()
    with get_session_factory()() as session:
        eng = session.query(Engagement).filter(Engagement.id == engagement_id).first()
        if not eng:
            console.print(f"[red]Engagement not found:[/red] {engagement_id}")
            raise typer.Exit(1)

        findings = session.query(Finding).filter(
            Finding.engagement_id == engagement_id
        ).all()

        data = {
            "engagement_id":   eng.id,
            "name":            eng.name,
            "status":          eng.status,
            "target_cidr":     eng.target_cidr,
            "created_at":      str(eng.created_at),
            "total_findings":  len(findings),
            "findings":        [f.to_dict() for f in findings],
        }

    out_path = output or f"./engagements/{engagement_id}/session_export.json"
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    console.print(f"[green]Session exported:[/green] {out_path}")
