"""
Rich console display helpers.

Centralised console, status helpers, progress bars, and formatted tables
used throughout the AIPTT CLI.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn,
)
from rich.theme import Theme

# ---------------------------------------------------------------------------
# Shared console instance (import this everywhere)
# ---------------------------------------------------------------------------

AIPTT_THEME = Theme({
    "info":      "cyan",
    "success":   "bold green",
    "warning":   "bold yellow",
    "error":     "bold red",
    "critical":  "bold red reverse",
    "finding":   "bold magenta",
    "muted":     "dim white",
    "highlight": "bold white",
})

console = Console(theme=AIPTT_THEME)


# ---------------------------------------------------------------------------
# Severity colours
# ---------------------------------------------------------------------------

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "blue",
    "INFO":     "dim white",
}

CLASSIFICATION_STYLE = {
    "CONFIRMED":    "bold green",
    "UNCONFIRMED":  "yellow",
    "THEORETICAL":  "dim",
}

STATUS_STYLE = {
    "RUNNING":   "bold green",
    "PAUSED":    "yellow",
    "COMPLETE":  "bold cyan",
    "KILLED":    "bold red",
    "INIT":      "dim white",
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def print_banner() -> None:
    """Print the AIPTT startup banner."""
    console.print(Panel.fit(
        "[bold red]AIPTT[/bold red] — Autonomous Internal Penetration Testing Tool\n"
        "[dim]Classification: CONFIDENTIAL — Internal Engineering Use Only[/dim]",
        border_style="red",
    ))


def print_finding(finding: dict) -> None:
    """Print a single finding in a formatted panel."""
    sev    = finding.get("severity", "INFO")
    cls    = finding.get("classification", "THEORETICAL")
    style  = SEVERITY_STYLE.get(sev, "white")
    c_style = CLASSIFICATION_STYLE.get(cls, "white")

    console.print(Panel(
        f"[{style}]{sev}[/{style}]  [{c_style}]{cls}[/{c_style}]  "
        f"[highlight]{finding.get('title', 'Unknown')}[/highlight]\n"
        f"Target: [cyan]{finding.get('target', 'N/A')}[/cyan]  "
        f"CVSSv3: [bold]{finding.get('cvss_score', 0.0):.1f}[/bold]  "
        f"Technique: [dim]{finding.get('technique', 'N/A')}[/dim]",
        title=f"[muted]{finding.get('id', '')}[/muted]",
        border_style=style,
    ))


def build_findings_table(findings: list[dict]) -> Table:
    """Build a Rich Table for a list of finding dicts."""
    table = Table(title="Findings", show_lines=True)
    table.add_column("ID",             style="muted",   no_wrap=True)
    table.add_column("Severity",       no_wrap=True)
    table.add_column("Class",          no_wrap=True)
    table.add_column("Title",          max_width=45)
    table.add_column("Target",         style="cyan",    no_wrap=True)
    table.add_column("CVSS",           justify="right", no_wrap=True)
    table.add_column("Technique",      style="dim",     no_wrap=True)

    for f in findings:
        sev    = f.get("severity", "INFO")
        cls    = f.get("classification", "THEORETICAL")
        table.add_row(
            f.get("id", ""),
            f"[{SEVERITY_STYLE.get(sev,'white')}]{sev}[/]",
            f"[{CLASSIFICATION_STYLE.get(cls,'white')}]{cls}[/]",
            f.get("title", ""),
            f.get("target", ""),
            f"{f.get('cvss_score', 0.0):.1f}",
            f.get("technique", ""),
        )
    return table


def build_attack_queue_table(tasks: list) -> Table:
    """Build a Rich Table for the AI-planned attack queue."""
    table = Table(title="AI Attack Queue", show_lines=True)
    table.add_column("Pos",     justify="center", style="muted",   no_wrap=True)
    table.add_column("Attack Path",               max_width=35)
    table.add_column("Score",   justify="right",  no_wrap=True)
    table.add_column("Technique",                 no_wrap=True)
    table.add_column("Target",  style="cyan",     no_wrap=True)

    for idx, t in enumerate(tasks, 1):
        score = getattr(t, "priority_score", 0.0)
        colour = "green" if score >= 0.8 else ("yellow" if score >= 0.5 else "red")
        table.add_row(
            str(idx),
            getattr(t, "module_id", str(t)),
            f"[{colour}]{score:.2f}[/{colour}]",
            getattr(t, "technique", ""),
            getattr(t, "target", ""),
        )
    return table


def make_progress() -> Progress:
    """Create a standard AIPTT progress bar."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )
