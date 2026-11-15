"""
Fix-Verify commands.

  aiptt verify retest — retest a finding after remediation
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel

app     = typer.Typer(help="Fix-verify (retest) commands.")
console = Console()


@app.command("retest")
def retest(
    finding_id:    str  = typer.Option(..., "--finding-id",    "-f"),
    engagement_id: str  = typer.Option(..., "--engagement-id", "-e"),
):
    """Retest a finding to verify remediation."""
    from aiptt.storage.db import init_db, get_session_factory
    from aiptt.attacks.registry import AttackRegistry
    from aiptt.engine.exploit_generator import ExploitGenerator
    from aiptt.audit.logger import get_audit_logger
    from aiptt.fixverify.engine import FixVerifyEngine, RetestOutcome

    init_db()
    session_factory = get_session_factory()

    audit    = get_audit_logger()
    gen      = ExploitGenerator()
    registry = AttackRegistry(exploit_generator=gen, audit=audit)
    engine   = FixVerifyEngine(
        attack_registry=registry,
        audit=audit,
        db_session=session_factory,
    )

    console.print(f"[cyan]Retesting finding:[/cyan] {finding_id}")
    result = engine.retest(finding_id)

    colour = {
        RetestOutcome.REMEDIATED:       "green",
        RetestOutcome.STILL_VULNERABLE: "red",
        RetestOutcome.REGRESSION:       "bold red",
    }.get(result.outcome, "white")

    console.print(Panel(
        f"Outcome:       [{colour}]{result.outcome.value}[/{colour}]\n"
        f"Original CVSS: {result.original_cvss}\n"
        f"Retest CVSS:   {result.retest_cvss}\n"
        f"Detail:        {result.detail}"
        + (f"\nNew Finding:   {result.new_finding_id}" if result.new_finding_id else ""),
        title=f"Retest Result — {finding_id}",
        expand=False,
    ))
