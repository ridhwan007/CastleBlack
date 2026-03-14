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
    name:         str           = typer.Option(...,   "--name",         "-n", help="Engagement name"),
    cidr:         Optional[str] = typer.Option(None,  "--cidr",         "-c", help="Target CIDR (live scan). Omit when using --nessus-file."),
    roe:          str           = typer.Option(...,   "--roe",               help="Path to signed RoE document"),
    nessus_file:  Optional[str] = typer.Option(None,  "--nessus-file",  "-f", help="Path to .nessus export. Skips live scanning."),
    scope_cidr:   Optional[str] = typer.Option(None,  "--scope-cidr",        help="CIDR filter when using --nessus-file."),
    output_dir:   str           = typer.Option("./engagements", "--output-dir", help="Output directory"),
    max_pivots:   int           = typer.Option(3,     "--max-pivots",         help="Max lateral movement hops"),
    blast_radius: str           = typer.Option("conservative", "--blast-radius", help="conservative | standard | aggressive"),
    dry_run:      bool          = typer.Option(False,  "--dry-run",            help="Validate only, do not persist"),
    skip_roe:     bool          = typer.Option(False,  "--skip-roe",           help="Skip RoE validation (dev/test only — do NOT use in production)."),
):
    """
    Initialise a new penetration testing engagement.

    \b
    Two input modes:
      Live scan:     --cidr 10.0.0.0/8 --roe roe.pdf
      Nessus import: --nessus-file scan.nessus --roe roe.pdf [--scope-cidr 10.0.0.0/8]
    """
    from aiptt.guardrail.scope_enforcer import RoEValidator, ScopeEnforcer
    from aiptt.audit.logger import get_audit_logger
    from aiptt.storage.db import init_db, get_session_factory
    from aiptt.storage.models import Engagement
    import uuid, datetime

    console.print(Panel("[bold cyan]AIPTT — Engagement Initialisation[/bold cyan]", expand=False))

    # ── Mode validation ────────────────────────────────────────────────
    if nessus_file and cidr:
        console.print("[red]ERROR:[/red] Use --cidr (live scan) OR --nessus-file, not both.")
        raise typer.Exit(1)
    if not nessus_file and not cidr:
        console.print("[red]ERROR:[/red] Provide --cidr (live scan) or --nessus-file (Nessus import).")
        raise typer.Exit(1)

    mode = "nessus" if nessus_file else "live"
    console.print(f"[dim]Mode: {'Nessus import' if mode == 'nessus' else 'Live scan'}[/dim]")

    # ── Validate RoE ───────────────────────────────────────────────────
    roe_path = Path(roe)
    if not roe_path.exists():
        console.print(f"[red]ERROR:[/red] RoE file not found: {roe}")
        raise typer.Exit(1)

    if skip_roe:
        console.print("[yellow]⚠ --skip-roe set — RoE validation bypassed (dev/test only)[/yellow]")
        roe_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    else:
        validator  = RoEValidator()
        roe_result = validator.verify_signature(roe_path)
        if not roe_result.passed:
            console.print(f"[red]ERROR:[/red] RoE validation failed: {roe_result.reason}")
            console.print("[dim]  Tip: use --skip-roe to bypass this check during development.[/dim]")
            raise typer.Exit(1)
        roe_hash = roe_result.roe_hash
        console.print(f"[green]✓[/green] RoE document accepted (SHA-256: {roe_hash[:16]}...)")

    # ── Mode-specific validation ───────────────────────────────────────
    effective_cidr = ""
    nessus_path: Optional[Path] = None

    if mode == "live":
        cidrs = [c.strip() for c in cidr.split(",") if c.strip()]
        from aiptt.utils.net import is_valid_cidr
        for c in cidrs:
            if not is_valid_cidr(c):
                console.print(f"[red]ERROR:[/red] Invalid CIDR: {c}")
                raise typer.Exit(1)
        ScopeEnforcer(allowed_cidrs=cidrs, exclusions=[])
        console.print(f"[green]✓[/green] Scope validated — {len(cidrs)} CIDR(s): {', '.join(cidrs)}")
        effective_cidr = cidr

    else:  # nessus mode
        nessus_path = Path(nessus_file)
        if not nessus_path.exists():
            console.print(f"[red]ERROR:[/red] Nessus file not found: {nessus_file}")
            raise typer.Exit(1)
        if nessus_path.suffix.lower() not in (".nessus", ".gz", ".xml"):
            console.print(f"[red]ERROR:[/red] Expected .nessus or .nessus.gz — got: {nessus_path.suffix}")
            raise typer.Exit(1)

        # Quick XML validation + host count
        try:
            import gzip as _gzip
            import xml.etree.ElementTree as _ET
            _opener = _gzip.open if nessus_path.suffix == ".gz" else open
            with _opener(nessus_path, "rb") as _f:
                _root = _ET.parse(_f).getroot()
            _hosts = _root.findall(".//ReportHost")
            console.print(f"[green]✓[/green] Nessus file valid — {len(_hosts)} host(s) in file")
        except Exception as exc:
            console.print(f"[red]ERROR:[/red] Cannot parse Nessus file: {exc}")
            raise typer.Exit(1)

        if scope_cidr:
            from aiptt.utils.net import is_valid_cidr
            if not is_valid_cidr(scope_cidr):
                console.print(f"[red]ERROR:[/red] Invalid --scope-cidr: {scope_cidr}")
                raise typer.Exit(1)
            console.print(f"[green]✓[/green] Scope filter applied: {scope_cidr}")
            effective_cidr = scope_cidr
        else:
            console.print("[dim]  No --scope-cidr — all hosts in file will be imported.[/dim]")

    if dry_run:
        console.print("[yellow]Dry-run complete — no changes persisted.[/yellow]")
        raise typer.Exit(0)

    # ── Initialise DB ──────────────────────────────────────────────────
    init_db()
    session_factory = get_session_factory()

    # ── Create Engagement record ───────────────────────────────────────
    engagement_id = f"ENG-{str(uuid.uuid4())[:8].upper()}"
    target_ref    = effective_cidr or (str(nessus_path.resolve()) if nessus_path else "")

    with session_factory() as session:
        eng = Engagement(
            id=engagement_id,
            name=name,
            cidr=target_ref,
            roe_hash=roe_hash,
            status="ACTIVE",
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        session.add(eng)
        session.commit()

    # ── Audit log ──────────────────────────────────────────────────────
    audit = get_audit_logger()
    audit.log_intent(
        "ENGAGEMENT_INIT",
        engagement=engagement_id,
        name=name,
        mode=mode,
        cidr=effective_cidr or "N/A",
        nessus_file=str(nessus_path) if nessus_path else None,
    )

    # ── Write engagement.toml ──────────────────────────────────────────
    out_path = Path(output_dir) / engagement_id
    out_path.mkdir(parents=True, exist_ok=True)

    nessus_line = f'nessus_file   = "{nessus_path.resolve()}"\n' if nessus_path else ""
    cidr_line   = f'cidr          = "{effective_cidr}"\n'

    cfg_text = (
        f'engagement_id = "{engagement_id}"\n'
        f'name          = "{name}"\n'
        f'mode          = "{mode}"\n'
        f"{cidr_line}"
        f"{nessus_line}"
        f'blast_radius  = "{blast_radius}"\n'
        f'output_dir    = "{out_path}"\n'
        f"max_pivots    = {max_pivots}\n"
    )
    (out_path / "engagement.toml").write_text(cfg_text, encoding="utf-8")

    # ── Summary ────────────────────────────────────────────────────────
    scope_line = (
        f"Nessus file: {nessus_path.name}" if nessus_path
        else f"Scope:       {effective_cidr}"
    )
    console.print()
    console.print(Panel(
        f"[bold green]Engagement created![/bold green]\n\n"
        f"ID:           [cyan]{engagement_id}[/cyan]\n"
        f"Name:         {name}\n"
        f"{scope_line}\n"
        f"Blast radius: {blast_radius}\n"
        f"Output dir:   {out_path}",
        title="Engagement Initialised",
        expand=False,
    ))
    if nessus_path:
        console.print("[dim]  The Nessus file is parsed automatically when the attack loop starts.[/dim]")
    console.print(f"\nNext step:\n  [bold]aiptt attack run --engagement-id {engagement_id}[/bold]")


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
    table.add_row("CIDR",     eng.cidr)
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
