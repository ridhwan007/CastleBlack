"""
AIPTT — Autonomous Internal Penetration Testing Tool
CLI entry point.

Usage:
  aiptt --help
  aiptt engage init --name "Corp PT" --cidr 10.0.0.0/24 --roe roe.pdf
  aiptt attack run --engagement-id ENG-ABCD1234
  aiptt report executive --engagement-id ENG-ABCD1234
"""

from __future__ import annotations

import os
from pathlib import Path

import typer
from rich.console import Console


def _load_dotenv() -> None:
    """
    Load .env into os.environ at startup.
    Searches: ./. env → ~/.config/aiptt/.env
    Uses python-dotenv if installed, otherwise parses manually.
    Does NOT override variables already set in the shell environment.
    """
    candidates = [
        Path.cwd() / ".env",
        Path.home() / ".config" / "aiptt" / ".env",
    ]
    env_file = next((p for p in candidates if p.exists()), None)
    if env_file is None:
        return

    try:
        from dotenv import load_dotenv
        load_dotenv(env_file, override=False)
        return
    except ImportError:
        pass

    # Built-in fallback — no extra deps needed
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key   = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv()

from aiptt.cli.engage   import app as engage_app
from aiptt.cli.scan     import app as scan_app
from aiptt.cli.attack   import app as attack_app
from aiptt.cli.report   import app as report_app
from aiptt.cli.verify   import app as verify_app
from aiptt.cli.session  import app as session_app
from aiptt.cli.admin    import app as admin_app
from aiptt.cli.validate import app as validate_app

app = typer.Typer(
    name="aiptt",
    help=(
        "AIPTT — Autonomous Internal Penetration Testing Tool\n\n"
        "A Claude-powered security assessment platform that autonomously discovers, "
        "exploits, and reports vulnerabilities within an authorised scope."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
)

app.add_typer(engage_app,   name="engage",   help="Manage engagement lifecycle")
app.add_typer(scan_app,     name="scan",     help="Discovery and scanning")
app.add_typer(attack_app,   name="attack",   help="Attack execution (OPAV loop)")
app.add_typer(report_app,   name="report",   help="Report generation")
app.add_typer(verify_app,   name="verify",   help="Fix-verify (retest findings)")
app.add_typer(session_app,  name="session",  help="Session management")
app.add_typer(admin_app,    name="admin",    help="Administrative operations")
app.add_typer(validate_app, name="validate", help="Nessus exploit validation (PoC generation + report)")

console = Console()


@app.callback(invoke_without_command=True)
def main(
    ctx:     typer.Context = typer.Argument(None),
    version: bool = typer.Option(False, "--version", "-V", help="Show version and exit"),
):
    """AIPTT entry point."""
    if version:
        from importlib.metadata import version as pkg_version
        try:
            v = pkg_version("aiptt")
        except Exception:
            v = "dev"
        console.print(f"[cyan]AIPTT[/cyan] version [bold]{v}[/bold]")
        raise typer.Exit(0)


def _wire_event_bus() -> None:
    """Wire EventBus handlers for cross-module events."""
    try:
        from aiptt.core.event_bus import EventBus
        bus = EventBus()

        def _on_finding(finding_id: str, severity: str, **kwargs: object) -> None:
            if severity in ("CRITICAL", "HIGH"):
                console.print(
                    f"[bold red]⚠  {severity} finding:[/bold red] {finding_id}"
                )

        bus.subscribe("FINDING_CREATED", _on_finding)
    except Exception:
        pass  # Non-fatal — event bus is optional for CLI-only use


_wire_event_bus()
