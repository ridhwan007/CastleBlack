"""
Admin commands.

  aiptt admin kill          — emergency kill switch (halt all activity)
  aiptt admin roe-sign      — generate RoE document SHA-256 hash
  aiptt admin key-rotate    — rotate AES master key
  aiptt admin purge         — purge expired artefacts (retention job)
  aiptt admin module-update — refresh CVE cache and module index
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

app     = typer.Typer(help="Administrative commands.")
console = Console()


@app.command("kill")
def kill(
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Emergency kill switch — halt all OPAV activity immediately."""
    if not confirm:
        typer.confirm(
            "[EMERGENCY] This will write a KILL flag halting all running loops. Continue?",
            abort=True,
        )

    from aiptt.audit.logger import get_audit_logger
    audit = get_audit_logger()
    audit.log_event("EMERGENCY_KILL_SWITCH_ACTIVATED")

    # Write kill flag that OPAVLoop monitors
    kill_flag = Path("/tmp/aiptt_kill") if Path("/tmp").exists() else Path("aiptt.kill")
    kill_flag.write_text("KILLED", encoding="utf-8")

    console.print(Panel(
        "[bold red]KILL SWITCH ACTIVATED[/bold red]\n"
        f"Kill flag written to: {kill_flag}\n"
        "All running OPAV loops will halt at next cycle.",
        expand=False,
    ))


@app.command("roe-sign")
def roe_sign(
    roe_file: str = typer.Argument(..., help="Path to RoE document"),
):
    """Compute and display the SHA-256 hash of a RoE document."""
    from aiptt.utils.crypto import sha256_file

    path = Path(roe_file)
    if not path.exists():
        console.print(f"[red]File not found:[/red] {roe_file}")
        raise typer.Exit(1)

    h = sha256_file(str(path))
    console.print(f"[green]RoE SHA-256:[/green]")
    console.print(f"  {h}")
    console.print(f"\nAdd this to your engagement config to validate the document.")


@app.command("key-rotate")
def key_rotate(
    confirm: bool = typer.Option(False, "--yes", "-y"),
):
    """Rotate the AES-256 master key (re-encrypts all vault artefacts)."""
    if not confirm:
        typer.confirm(
            "Key rotation will re-encrypt all vault artefacts. Continue?",
            abort=True,
        )

    from aiptt.utils.crypto import generate_aes_key
    import binascii

    new_key = generate_aes_key()
    hex_key = binascii.hexlify(new_key).decode()

    console.print("[yellow]New AES-256 master key generated.[/yellow]")
    console.print(f"\n  [bold]{hex_key}[/bold]\n")
    console.print(
        "Set this as your new AIPTT_MASTER_KEY environment variable.\n"
        "[red]WARNING:[/red] Update the env var BEFORE restarting AIPTT, "
        "then run vault re-encryption if required."
    )


@app.command("purge")
def purge(
    confirm: bool = typer.Option(False, "--yes", "-y"),
    vault_dir: str = typer.Option("./vault", "--vault-dir"),
):
    """Purge artefacts that have exceeded the 90-day retention window."""
    if not confirm:
        typer.confirm("Purge expired vault artefacts?", abort=True)

    from aiptt.storage.retention import RetentionJob
    from aiptt.storage.db import init_db, get_session_factory

    init_db()
    job = RetentionJob(vault_dir=vault_dir, session_factory=get_session_factory())
    deleted = job.run()
    console.print(f"[green]Purged {deleted} expired artefact(s).[/green]")


@app.command("findings")
def findings(
    engagement_id: str = typer.Option("", "--engagement-id", "-e",
                                       help="Filter by engagement (default: latest)"),
    limit: int = typer.Option(0, "--limit", "-n",
                               help="Max rows (0 = all)"),
):
    """List all findings with artefact references."""
    from aiptt.storage.db import init_db, get_session_factory
    from aiptt.storage.models import Finding, Engagement as EngModel, AttackChainSnapshot
    from rich.table import Table
    import json as _json

    init_db()
    with get_session_factory()() as session:
        if not engagement_id:
            eng = session.query(EngModel).order_by(EngModel.created_at.desc()).first()
            engagement_id = eng.id if eng else ""

        q = (session.query(Finding)
             .filter(Finding.engagement_id == engagement_id)
             .order_by(Finding.id.desc()))
        if limit > 0:
            q = q.limit(limit)
        rows = q.all()

        # Pull CVE/plugin names from attack chain snapshots
        snap_map: dict[str, str] = {}
        for f in rows:
            if f.attack_chain and f.attack_chain.task_json:
                try:
                    task_data = _json.loads(f.attack_chain.task_json)
                    params = task_data.get("parameters", {})
                    cve = params.get("cve_id") or params.get("cve") or ""
                    snap_map[f.id] = cve
                except Exception:
                    pass

    if not rows:
        console.print(f"[yellow]No findings for engagement {engagement_id}[/yellow]")
        return

    t = Table(
        title=f"[bold cyan]Findings — {engagement_id}[/bold cyan]  "
              f"[dim]({len(rows)} total)[/dim]",
        show_lines=True,
    )
    t.add_column("ID",          style="cyan",   no_wrap=True)
    t.add_column("Module",      style="yellow", no_wrap=True)
    t.add_column("CVE / Vuln",  style="green",  no_wrap=True)
    t.add_column("Technique",   style="dim",    no_wrap=True)
    t.add_column("Access",      no_wrap=True)
    t.add_column("Gained",      no_wrap=True)
    t.add_column("PoE Artefact", style="dim",   no_wrap=True)

    for f in rows:
        cve_str   = snap_map.get(f.id, "") or "—"
        gained    = "[green]YES[/green]" if f.gained_access else "[dim]no[/dim]"
        acc       = f.access_level or "none"
        acc_col   = "green" if acc.lower() in ("root", "admin", "system",
                                                "administrator") else "white"
        t.add_row(
            f.id,
            f.module_id or "—",
            cve_str,
            f.technique or "—",
            f"[{acc_col}]{acc}[/{acc_col}]",
            gained,
            f.poe_vault_ref or "—",
        )
    console.print(t)
    console.print(
        f"[dim]Use [cyan]aiptt admin show-artefact <PoE Ref>[/cyan] "
        "to decrypt and view any artefact.[/dim]"
    )


@app.command("delete-findings")
def delete_findings(
    engagement_id: str = typer.Option("", "--engagement-id", "-e",
                                       help="Engagement to clear (default: latest)"),
    all_engagements: bool = typer.Option(False, "--all",
                                          help="Delete findings for ALL engagements"),
    keep_vault:      bool = typer.Option(False, "--keep-vault",
                                          help="Delete DB rows but keep vault artefact files"),
    confirm:         bool = typer.Option(False, "--yes", "-y"),
):
    """Delete all findings (and their vault artefacts) for an engagement."""
    from aiptt.storage.db import init_db, get_session
    from aiptt.storage.models import Finding, Engagement as EngModel

    init_db()

    with get_session() as session:
        if all_engagements:
            rows = session.query(Finding).all()
            scope_label = "ALL engagements"
        else:
            if not engagement_id:
                eng = session.query(EngModel).order_by(EngModel.created_at.desc()).first()
                engagement_id = eng.id if eng else ""
            rows = session.query(Finding).filter(
                Finding.engagement_id == engagement_id
            ).all()
            scope_label = engagement_id

    if not rows:
        console.print(f"[yellow]No findings found for {scope_label}.[/yellow]")
        return

    vault_refs = [f.poe_vault_ref for f in rows if f.poe_vault_ref]
    console.print(
        f"[bold]Found {len(rows)} finding(s) for {scope_label}[/bold]  "
        f"({len(vault_refs)} vault artefact(s))"
    )

    if not confirm:
        typer.confirm(
            f"Delete {len(rows)} finding(s)"
            + (f" and {len(vault_refs)} vault artefact(s)" if not keep_vault else "")
            + "?",
            abort=True,
        )

    deleted_files = 0
    failed_files  = 0

    # ── Bulk delete vault files (no per-file DB session) ──────────────
    if not keep_vault and vault_refs:
        from aiptt.core.config import get_config as _get_cfg
        vault_dir = Path(_get_cfg().encryption.vault_path).expanduser()
        for ref in vault_refs:
            try:
                enc_file = vault_dir / f"{ref}.enc"
                if enc_file.exists():
                    enc_file.unlink()
                deleted_files += 1
            except Exception:
                failed_files += 1

    # ── Single-transaction bulk DB delete ─────────────────────────────
    with get_session() as session:
        from sqlalchemy import delete as _sa_delete
        from aiptt.storage.models import AttackChainSnapshot, ArtefactRetentionLog

        finding_ids = [f.id for f in rows]

        # Delete child rows first (cascade isn't always reliable with bulk ops)
        session.execute(
            _sa_delete(AttackChainSnapshot).where(
                AttackChainSnapshot.finding_id.in_(finding_ids)
            )
        )
        if not keep_vault and vault_refs:
            session.execute(
                _sa_delete(ArtefactRetentionLog).where(
                    ArtefactRetentionLog.vault_ref.in_(vault_refs)
                )
            )
        session.execute(
            _sa_delete(Finding).where(Finding.id.in_(finding_ids))
        )

    console.print(
        f"[green]✓ Deleted {len(rows)} finding(s).[/green]"
        + (f"  Vault files removed: {deleted_files}"
           + (f"  (failed: {failed_files})" if failed_files else "")
           if not keep_vault else "  (vault artefacts kept)")
    )


@app.command("show-artefact")
def show_artefact(
    vault_ref: str = typer.Argument(..., help="Vault reference from findings table"),
    raw:        bool = typer.Option(False, "--raw", help="Print raw bytes as hex"),
):
    """Decrypt and display a PoE artefact from the vault."""
    from aiptt.storage.vault import ArtifactVault
    from aiptt.storage.db import init_db

    init_db()
    vault = ArtifactVault()

    try:
        data = vault.retrieve(vault_ref)
    except FileNotFoundError as e:
        console.print(f"[red]Not found:[/red] {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Decryption failed:[/red] {e}")
        raise typer.Exit(1)

    if raw:
        console.print(data.hex())
        return

    # Try to decode as text
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1", errors="replace")

    # Try to pretty-print JSON
    import json as _json
    try:
        parsed = _json.loads(text)
        text   = _json.dumps(parsed, indent=2)
    except Exception:
        pass

    console.print(Panel(
        text,
        title=f"[cyan]PoE Artefact[/cyan]  [dim]{vault_ref}[/dim]",
        subtitle=f"[dim]{len(data)} bytes (decrypted)[/dim]",
        expand=False,
    ))


@app.command("module-update")
def module_update(
    cve_cache_dir: str = typer.Option("data/cve_cache", "--cve-cache-dir"),
):
    """Refresh the CVE cache and module manifest index."""
    import json
    from datetime import datetime, timezone

    cache_dir = Path(cve_cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = cache_dir / "manifest.json"
    manifest = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "entries": [],
    }

    if manifest_path.exists():
        try:
            existing = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["entries"] = existing.get("entries", [])
        except Exception:
            pass

    manifest["last_updated"] = datetime.now(timezone.utc).isoformat()
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    console.print(f"[green]Module index updated.[/green] Manifest: {manifest_path}")
    console.print(
        "[dim]Note: Populate the CVE cache by placing NVD JSON feeds "
        "in the cve_cache directory.[/dim]"
    )
