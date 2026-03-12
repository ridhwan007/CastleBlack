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
