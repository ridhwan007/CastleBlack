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

import typer
from rich.console import Console

from aiptt.cli.engage  import app as engage_app
from aiptt.cli.scan    import app as scan_app
from aiptt.cli.attack  import app as attack_app
from aiptt.cli.report  import app as report_app
from aiptt.cli.verify  import app as verify_app
from aiptt.cli.session import app as session_app
from aiptt.cli.admin   import app as admin_app

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

app.add_typer(engage_app,  name="engage",  help="Manage engagement lifecycle")
app.add_typer(scan_app,    name="scan",    help="Discovery and scanning")
app.add_typer(attack_app,  name="attack",  help="Attack execution (OPAV loop)")
app.add_typer(report_app,  name="report",  help="Report generation")
app.add_typer(verify_app,  name="verify",  help="Fix-verify (retest findings)")
app.add_typer(session_app, name="session", help="Session management")
app.add_typer(admin_app,   name="admin",   help="Administrative operations")

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
