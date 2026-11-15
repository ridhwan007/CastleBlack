"""
Reporting commands.

  aiptt report executive   — executive summary
  aiptt report technical   — full technical report
  aiptt report compliance  — compliance mapping
  aiptt report export      — export findings (pdf/json/csv/html)
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app     = typer.Typer(help="Reporting commands.")
console = Console()


def _load_findings(engagement_id: str) -> list[dict]:
    from aiptt.storage.db import init_db, get_session_factory
    from aiptt.storage.models import Finding
    init_db()
    with get_session_factory()() as session:
        findings = session.query(Finding).filter(
            Finding.engagement_id == engagement_id
        ).all()
        return [f.to_dict() for f in findings]


@app.command("executive")
def executive(
    engagement_id: str  = typer.Option(..., "--engagement-id", "-e"),
    output_dir:    str  = typer.Option("./reports", "--output-dir"),
    name:          str  = typer.Option("Penetration Test", "--name"),
):
    """Generate an executive summary report."""
    from aiptt.reporting.executive import ExecutiveReporter

    findings = _load_findings(engagement_id)
    reporter = ExecutiveReporter()
    summary  = reporter.generate(findings, engagement_id=engagement_id, engagement_name=name)
    md       = reporter.to_markdown(summary)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{engagement_id}_executive.md"
    path.write_text(md, encoding="utf-8")

    console.print(f"[green]Executive summary written:[/green] {path}")
    console.print(f"Overall Risk: [bold]{summary.risk_rating}[/bold] | Findings: {summary.total_findings}")


@app.command("technical")
def technical(
    engagement_id: str = typer.Option(..., "--engagement-id", "-e"),
    output_dir:    str = typer.Option("./reports", "--output-dir"),
    name:          str = typer.Option("Penetration Test", "--name"),
):
    """Generate a full technical report."""
    from aiptt.reporting.technical import TechnicalReporter

    findings = _load_findings(engagement_id)
    reporter = TechnicalReporter()
    report   = reporter.generate(findings, engagement_id=engagement_id, engagement_name=name)
    path     = reporter.save(report, output_dir)

    console.print(f"[green]Technical report written:[/green] {path}")


@app.command("compliance")
def compliance(
    engagement_id: str  = typer.Option(..., "--engagement-id", "-e"),
    output_dir:    str  = typer.Option("./reports", "--output-dir"),
    frameworks:    str  = typer.Option("pci_dss,nis2,iso27001,soc2,hipaa",
                                       "--frameworks", help="Comma-separated framework list"),
):
    """Generate a compliance mapping report."""
    from aiptt.reporting.compliance import ComplianceReporter

    findings   = _load_findings(engagement_id)
    fw_list    = [f.strip() for f in frameworks.split(",") if f.strip()]
    reporter   = ComplianceReporter()
    report     = reporter.generate(findings, engagement_id=engagement_id, frameworks=fw_list)
    path       = reporter.save(report, output_dir)

    console.print(f"[green]Compliance report written:[/green] {path}")
    console.print(f"Mapped {len(report.mappings)} control(s) across {len(fw_list)} framework(s).")


@app.command("export")
def export(
    engagement_id: str  = typer.Option(..., "--engagement-id", "-e"),
    output_dir:    str  = typer.Option("./reports", "--output-dir"),
    fmt:           str  = typer.Option("json", "--format", "-f",
                                       help="Output format: json | csv | html | pdf"),
):
    """Export findings in a specified format."""
    from aiptt.reporting.exporters import ReportExporter

    findings = _load_findings(engagement_id)
    exporter = ReportExporter(output_dir=output_dir)

    fmt = fmt.lower()
    if fmt == "json":
        path = exporter.export_json(findings, engagement_id)
    elif fmt == "csv":
        path = exporter.export_csv(findings, engagement_id)
    elif fmt == "html":
        path = exporter.export_html(findings, engagement_id)
    elif fmt == "pdf":
        path = exporter.export_pdf(findings, engagement_id)
    else:
        console.print(f"[red]Unknown format:[/red] {fmt} (use json, csv, html, pdf)")
        raise typer.Exit(1)

    console.print(f"[green]Exported {len(findings)} finding(s) to:[/green] {path}")
