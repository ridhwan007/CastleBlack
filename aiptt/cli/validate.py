"""
Nessus exploit validation workflow.

  aiptt validate run <file.nessus>
  aiptt validate run <file.nessus> --execute        # also runs each PoC

Phases:
  1. Parse & triage  — print sorted table, save triage_table.md
  2. AI analysis     — per Critical/High finding: context, PoC, severity re-score
  3. PoC artefacts   — save poc_<pluginid>_<cve>.py/.sh/.txt per finding
  4. Execution       — (--execute only) run each PoC, capture output, save poe/ artefacts
  5. Report          — write findings_report.md and chains.md
"""

from __future__ import annotations

import gzip
import hashlib
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
from rich.table import Table
from rich.text import Text

from aiptt.engine.vuln_validator import RawFinding, ValidationResult, ExploitChain, VulnValidator
from aiptt.engine.poc_executor   import PoCExecutor, PoCExecutionResult

app     = typer.Typer(help="Nessus exploit validation workflow.")
console = Console()

# Nessus severity integer → string
_SEV_STR = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
_SEV_INT  = {v: k for k, v in _SEV_STR.items()}

# Rich colours per severity
_SEV_COLOUR = {
    "CRITICAL":       "bold red",
    "HIGH":           "red",
    "MEDIUM":         "yellow",
    "LOW":            "cyan",
    "INFO":           "dim",
    "FALSE_POSITIVE": "dim green",
}

def _sev_colour(s: str) -> str:
    return _SEV_COLOUR.get(s.upper(), "white")


# ---------------------------------------------------------------------------
# Lightweight Nessus XML parser (extracts everything the workflow needs)
# ---------------------------------------------------------------------------

def _load_xml(path: Path) -> ET.ElementTree:
    if path.suffix == ".gz" or path.name.endswith(".nessus.gz"):
        with gzip.open(path, "rb") as f:
            return ET.parse(f)
    return ET.parse(path)


def _txt(el: ET.Element, tag: str, default: str = "") -> str:
    child = el.find(tag)
    return child.text.strip() if child is not None and child.text else default


def _cvss(item: ET.Element, nessus_sev: int) -> tuple[float, float, float]:
    _SEV_CVSS = {0: 0.0, 1: 3.0, 2: 5.5, 3: 7.5, 4: 9.5}
    v2 = v3 = 0.0
    try:
        v2 = float(_txt(item, "cvss_base_score", "0"))
    except ValueError:
        pass
    try:
        v3 = float(_txt(item, "cvss3_base_score", "0"))
    except ValueError:
        pass
    best = v3 or v2 or _SEV_CVSS.get(nessus_sev, 0.0)
    return v2, v3, best


def parse_nessus(path: Path) -> tuple[str, list[RawFinding]]:
    """
    Parse a .nessus XML file and return (scan_name, list[RawFinding]).
    Each ReportItem becomes one RawFinding (per-CVE expansion NOT done here —
    multi-CVE plugins create one RawFinding with all CVEs in the cves list).
    Plugin ID 19506 (Nessus scan info) is skipped.
    """
    tree  = _load_xml(path)
    root  = tree.getroot()
    reports   = root.findall(".//Report")
    scan_name = reports[0].get("name", "Unknown") if reports else "Unknown"

    findings: list[RawFinding] = []
    seen: set[str] = set()      # dedup: host:port:plugin_id

    for report in reports:
        for rhost in report.findall("ReportHost"):
            # Host properties
            props: dict[str, str] = {}
            hp = rhost.find("HostProperties")
            if hp is not None:
                for tag in hp.findall("tag"):
                    name = tag.get("name", "")
                    if name:
                        props[name] = (tag.text or "").strip()

            host_ip   = props.get("host-ip", rhost.get("name", ""))
            host_fqdn = props.get("host-fqdn", "")
            host_os   = props.get("operating-system", "")

            for item in rhost.findall("ReportItem"):
                plugin_id = item.get("pluginID", "")
                if plugin_id == "19506":
                    continue

                port        = int(item.get("port", 0))
                protocol    = item.get("protocol", "tcp").lower()
                svc_name    = item.get("svc_name", "").lower()
                nessus_sev  = int(item.get("severity", 0))
                plugin_name = item.get("pluginName", "")
                plugin_fam  = item.get("pluginFamily", "")

                dedup_key = f"{host_ip}:{port}:{plugin_id}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                cves  = [el.text.strip() for el in item.findall("cve") if el.text]
                v2, v3, best_cvss = _cvss(item, nessus_sev)

                exploit_avail = _txt(item, "exploit_available", "false").lower() == "true"
                msf_name      = _txt(item, "metasploit_name", "")
                if msf_name:
                    exploit_avail = True

                findings.append(RawFinding(
                    host_ip=host_ip,
                    host_fqdn=host_fqdn,
                    host_os=host_os,
                    port=port,
                    protocol=protocol,
                    svc_name=svc_name,
                    plugin_id=plugin_id,
                    plugin_name=plugin_name,
                    plugin_family=plugin_fam,
                    nessus_severity=nessus_sev,
                    nessus_severity_str=_SEV_STR.get(nessus_sev, "INFO"),
                    cvss_v2=v2,
                    cvss_v3=v3,
                    cvss=best_cvss,
                    cves=cves,
                    synopsis=_txt(item, "synopsis"),
                    description=_txt(item, "description"),
                    solution=_txt(item, "solution"),
                    plugin_output=_txt(item, "plugin_output"),
                    exploit_available=exploit_avail,
                    exploitability_ease=_txt(item, "exploitability_ease"),
                    metasploit_name=msf_name,
                    see_also=_txt(item, "see_also"),
                ))

    # Sort: by host, then CVSS descending
    findings.sort(key=lambda f: (f.host_ip, -f.cvss))
    return scan_name, findings


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _triage_table(findings: list[RawFinding]) -> Table:
    t = Table(
        title="[bold]Nessus Triage[/bold]",
        show_lines=False,
        header_style="bold cyan",
    )
    t.add_column("Host",        style="cyan",   no_wrap=True)
    t.add_column("Port",        style="dim",    no_wrap=True)
    t.add_column("Svc",         style="dim",    no_wrap=True)
    t.add_column("CVSSv3",      no_wrap=True)
    t.add_column("Sev",         no_wrap=True)
    t.add_column("Exploit?",    no_wrap=True)
    t.add_column("Plugin Name", overflow="fold")
    t.add_column("CVE(s)",      overflow="fold")

    for f in findings:
        sev_col  = _sev_colour(f.nessus_severity_str)
        exp_col  = "[green]YES[/green]" if f.exploit_available else "[dim]no[/dim]"
        cve_str  = ", ".join(f.cves[:3]) + ("…" if len(f.cves) > 3 else "") if f.cves else "—"
        cvss_str = f"[{sev_col}]{f.cvss:.1f}[/{sev_col}]" if f.cvss else "[dim]—[/dim]"
        t.add_row(
            f.host_ip,
            str(f.port) if f.port else "—",
            f.svc_name,
            cvss_str,
            f"[{sev_col}]{f.nessus_severity_str}[/{sev_col}]",
            exp_col,
            f.plugin_name,
            cve_str,
        )
    return t


def _result_panel(r: ValidationResult, idx: int, total: int) -> Panel:
    f = r.finding
    cve_str = ", ".join(f.cves) or "—"
    orig    = f.nessus_severity_str
    real    = r.realistic_severity

    arrow = ""
    if r.severity_changed:
        orig_n = _SEV_INT.get(orig, 2)
        real_n = _SEV_INT.get(real, 2)
        arrow  = " [green]↓[/green]" if real_n < orig_n else " [red]↑[/red]"

    col = _sev_colour(real)
    title = (
        f"[{col}]{real}[/{col}]{arrow}  "
        f"[bold]{f.plugin_name}[/bold]  "
        f"[dim]{f.host_ip}:{f.port}[/dim]  "
        f"[dim]({idx}/{total})[/dim]"
    )

    lines = []
    lines.append(f"[bold]CVE:[/bold] {cve_str}   [bold]CVSS:[/bold] {f.cvss}   [bold]Svc:[/bold] {f.svc_name}/{f.protocol}")
    lines.append(f"[bold]Evidence quality:[/bold] {r.evidence_quality}")
    lines.append("")
    lines.append(f"[bold cyan]Context:[/bold cyan]")
    lines.append(r.context_notes)
    lines.append("")
    lines.append(f"[bold cyan]Exploit Research:[/bold cyan]")
    lines.append(r.exploit_research)
    lines.append("")
    lines.append(f"[bold cyan]Exploitation Outcome:[/bold cyan] {r.exploitation_outcome}")
    lines.append("")
    lines.append(f"[bold cyan]PoC Type {r.poc_type}:[/bold cyan] {r.poc_filename or 'N/A'}  "
                 f"[dim](reliability: {r.poc_reliability})[/dim]")
    if r.poc_type == "D":
        lines.append(f"  [dim]{r.poc_no_reason}[/dim]")
    elif r.poc_filename:
        lines.append(f"  [green]Saved → {r.poc_filename}[/green]")
    lines.append("")
    lines.append(f"[bold cyan]Severity Re-score:[/bold cyan]  {orig} → [{col}]{real}[/{col}]")
    lines.append(f"  {r.severity_justification}")
    lines.append("")
    lines.append(f"[bold cyan]Remediation:[/bold cyan]")
    lines.append(r.remediation)
    if r.chain_hint:
        lines.append("")
        lines.append(f"[bold yellow]Chain:[/bold yellow] {r.chain_hint}")

    return Panel("\n".join(lines), title=title, expand=False)


# ---------------------------------------------------------------------------
# File writers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "FALSE_POSITIVE": 5
}


def _save_poc(result: ValidationResult, poc_dir: Path) -> Path | None:
    """Write PoC file to poc_dir. Returns path written, or None."""
    if result.poc_type == "D" or not result.poc_code.strip():
        return None
    poc_dir.mkdir(parents=True, exist_ok=True)
    out = poc_dir / result.poc_filename
    out.write_text(result.poc_code, encoding="utf-8")
    return out


_OUTCOME_COLOUR = {
    "SUCCESS": "bold green",
    "PARTIAL": "yellow",
    "FAILURE": "red",
    "ERROR":   "dim red",
    "SKIPPED": "dim",
}


def _exec_panel(exec_result: PoCExecutionResult, finding_name: str) -> Panel:
    """Rich panel displaying PoC execution result."""
    col   = _OUTCOME_COLOUR.get(exec_result.outcome, "white")
    title = (
        f"[{col}]{exec_result.outcome}[/{col}]  "
        f"[bold]{finding_name}[/bold]  "
        f"[dim]{exec_result.target_ip}:{exec_result.target_port}[/dim]  "
        f"[dim]{exec_result.duration_s:.1f}s[/dim]"
    )

    lines = []
    lines.append(f"[bold]Command:[/bold] {exec_result.command_run}")
    lines.append(f"[bold]Return code:[/bold] {exec_result.return_code}"
                 + (" [yellow][TIMEOUT][/yellow]" if exec_result.timed_out else ""))

    if exec_result.stdout.strip():
        preview = exec_result.stdout[:600].rstrip()
        if len(exec_result.stdout) > 600:
            preview += "\n... [dim][truncated — see PoE artefact for full output][/dim]"
        lines.append("")
        lines.append("[bold cyan]STDOUT:[/bold cyan]")
        lines.append(preview)

    if exec_result.stderr.strip():
        preview = exec_result.stderr[:300].rstrip()
        lines.append("")
        lines.append("[bold red]STDERR:[/bold red]")
        lines.append(preview)

    if exec_result.captured_data.strip():
        lines.append("")
        lines.append(f"[bold green]CAPTURED DATA:[/bold green]")
        lines.append(exec_result.captured_data)

    lines.append("")
    lines.append(f"[bold cyan]AI Interpretation:[/bold cyan]")
    lines.append(exec_result.ai_interpretation)

    if exec_result.poe_artefact_path:
        lines.append("")
        lines.append(f"[dim]PoE artefact → {exec_result.poe_artefact_path}[/dim]")

    return Panel("\n".join(lines), title=title, expand=False)


def _triage_md(scan_name: str, findings: list[RawFinding]) -> str:
    lines = [
        f"# Triage Table — {scan_name}",
        f"Generated: {date.today().isoformat()}",
        f"Total findings parsed: {len(findings)}",
        "",
        "| Host | Port | Svc | CVSSv3 | Severity | Exploit? | Plugin Name | CVE(s) |",
        "|------|------|-----|--------|----------|----------|-------------|--------|",
    ]
    for f in findings:
        cve_str = ", ".join(f.cves[:3]) + ("…" if len(f.cves) > 3 else "") if f.cves else "—"
        exp     = "YES" if f.exploit_available else "no"
        lines.append(
            f"| {f.host_ip} | {f.port or '—'} | {f.svc_name} | {f.cvss:.1f} | "
            f"{f.nessus_severity_str} | {exp} | {f.plugin_name} | {cve_str} |"
        )
    return "\n".join(lines)


def _findings_report_md(
    scan_file: str,
    scan_name: str,
    all_findings: list[RawFinding],
    results: list[ValidationResult],
    chains: list[ExploitChain],
    poc_dir: Path,
    exec_results: dict[str, PoCExecutionResult] | None = None,
) -> str:
    today = date.today().isoformat()

    # Count realistic severities
    sev_counts: dict[str, int] = {}
    for r in results:
        sev_counts[r.realistic_severity] = sev_counts.get(r.realistic_severity, 0) + 1

    upgraded   = [r for r in results if r.severity_changed and
                  _SEV_INT.get(r.realistic_severity, 2) > _SEV_INT.get(r.finding.nessus_severity_str, 2)]
    downgraded = [r for r in results if r.severity_changed and
                  _SEV_INT.get(r.realistic_severity, 2) < _SEV_INT.get(r.finding.nessus_severity_str, 2)]
    fps        = [r for r in results if r.realistic_severity == "FALSE_POSITIVE"]

    hosts = sorted({f.host_ip for f in all_findings})

    # Most impactful finding
    best = min(results, key=lambda r: _SEVERITY_ORDER.get(r.realistic_severity, 5)) if results else None

    lines: list[str] = []
    lines += [
        "# Vulnerability Assessment — Exploit Validation Report",
        f"## Scope: {', '.join(hosts)}",
        f"## Assessment Date: {today}",
        f"## File Analysed: {Path(scan_file).name}",
        f"## Scan Name: {scan_name}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"- **Total Nessus findings parsed:** {len(all_findings)}",
        f"- **Findings validated (Critical/High):** {len(results)}",
        "- **After validation:**",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "FALSE_POSITIVE"):
        n = sev_counts.get(sev, 0)
        if n:
            lines.append(f"  - {sev}: {n}")
    lines.append("")

    if upgraded:
        lines.append("- **Findings upgraded in severity:**")
        for r in upgraded:
            cve = r.finding.cves[0] if r.finding.cves else r.finding.plugin_id
            lines.append(f"  - {r.finding.plugin_name} ({cve}): "
                         f"{r.finding.nessus_severity_str} → {r.realistic_severity}")
        lines.append("")

    if downgraded:
        lines.append("- **Findings downgraded in severity:**")
        for r in downgraded:
            cve = r.finding.cves[0] if r.finding.cves else r.finding.plugin_id
            lines.append(f"  - {r.finding.plugin_name} ({cve}): "
                         f"{r.finding.nessus_severity_str} → {r.realistic_severity}")
        lines.append("")

    if fps:
        lines.append("- **Findings marked False Positive:**")
        for r in fps:
            cve = r.finding.cves[0] if r.finding.cves else r.finding.plugin_id
            lines.append(f"  - {r.finding.plugin_name} ({cve}): {r.severity_justification}")
        lines.append("")

    if best:
        cve = best.finding.cves[0] if best.finding.cves else best.finding.plugin_id
        lines.append(f"- **Most impactful finding:** {best.finding.plugin_name} ({cve}) "
                     f"on {best.finding.host_ip}:{best.finding.port} — "
                     f"{best.exploitation_outcome}")
        lines.append("")

    # Top 3 recommendations
    crits = [r for r in results if r.realistic_severity in ("CRITICAL", "HIGH")][:3]
    if crits:
        lines.append("- **Recommended immediate actions:**")
        for i, r in enumerate(crits, 1):
            lines.append(f"  {i}. **{r.finding.plugin_name}** ({r.finding.host_ip}:{r.finding.port}): "
                         f"{r.remediation[:120]}")
        lines.append("")

    lines += ["---", "", "## Findings Detail", ""]

    # Sort results by realistic severity
    sorted_results = sorted(
        results,
        key=lambda r: _SEVERITY_ORDER.get(r.realistic_severity, 5)
    )

    for r in sorted_results:
        f      = r.finding
        cve    = ", ".join(f.cves) or "—"
        orig   = f.nessus_severity_str
        real   = r.realistic_severity
        arrow  = " ↑" if _SEV_INT.get(real, 2) > _SEV_INT.get(orig, 2) else (
                 " ↓" if _SEV_INT.get(real, 2) < _SEV_INT.get(orig, 2) else " =")

        poc_ref = (poc_dir / r.poc_filename).as_posix() if r.poc_filename and r.poc_type != "D" else "No viable PoC"

        lines += [
            f"### [{real}] {f.plugin_name} — {f.host_ip}:{f.port}",
            f"**CVE:** {cve}",
            f"**CVSS:** {f.cvss} (v2: {f.cvss_v2} / v3: {f.cvss_v3})",
            f"**Service:** {f.svc_name}/{f.protocol}",
            f"**Original Nessus Severity:** {orig}",
            f"**Realistic Severity:** {real}{arrow}",
            f"**Metasploit Module:** {f.metasploit_name or '—'}",
            "",
            "**Evidence from scan:**",
            "```",
            (f.plugin_output[:800] if f.plugin_output else "No plugin output captured."),
            "```",
            "",
            f"**Evidence Quality:** {r.evidence_quality}",
            "",
            "**Context:**",
            r.context_notes,
            "",
            "**Exploitability:**",
            r.exploit_research,
            "",
            f"**Exploitation Outcome:** {r.exploitation_outcome}",
            "",
            f"**PoC:** `{poc_ref}`",
            f"**PoC Type:** {r.poc_type}  **Reliability:** {r.poc_reliability}",
        ]
        if r.poc_type == "D":
            lines.append(f"**Why no PoC:** {r.poc_no_reason}")
        lines += [
            "",
            "**Severity Justification:**",
            r.severity_justification,
            "",
            "**Remediation:**",
            r.remediation,
        ]
        if r.chain_hint:
            lines.append("")
            lines.append(f"**Exploit Chain:** {r.chain_hint}")

        # ── Execution / PoE section ──────────────────────────────────
        exec_key = r.poc_filename
        er = (exec_results or {}).get(exec_key)
        if er:
            outcome_icon = {
                "SUCCESS": "✅", "PARTIAL": "⚠️", "FAILURE": "❌",
                "ERROR": "💥", "SKIPPED": "⏭️",
            }.get(er.outcome, "")
            lines += [
                "",
                "### Exploitation Attempt",
                f"**Outcome:** {outcome_icon} {er.outcome}",
                f"**Command:** `{er.command_run}`",
                f"**Duration:** {er.duration_s:.1f}s"
                + (" *(timed out)*" if er.timed_out else ""),
                f"**Return Code:** {er.return_code}",
                "",
                "**Raw Output (stdout):**",
                "```",
                (er.stdout[:1200] if er.stdout.strip() else "(no output)"),
                "```",
            ]
            if er.stderr.strip():
                lines += [
                    "**Stderr:**",
                    "```",
                    er.stderr[:400],
                    "```",
                ]
            if er.captured_data.strip():
                lines += [
                    "",
                    f"**Captured Data:** `{er.captured_data}`",
                ]
            lines += [
                "",
                f"**AI Interpretation:** {er.ai_interpretation}",
                f"**PoE Artefact:** `{er.poe_artefact_path}`",
            ]

        lines += ["", "---", ""]

    # Chains section
    if chains:
        lines += ["## Exploit Chains Identified", ""]
        for c in chains:
            lines += [
                f"### {c.label}",
                f"**Vuln A:** {c.vuln_a}",
                f"**Vuln B:** {c.vuln_b}",
                f"**Impact:** {c.impact}",
                "",
                c.description,
                "",
                "---",
                "",
            ]

    # Appendix: reclassifications
    reclassified = [r for r in results if r.severity_changed]
    if reclassified:
        lines += [
            "## Appendix: Severity Reclassifications",
            "",
            "| Finding | CVE | Nessus | Realistic | Reason |",
            "|---------|-----|--------|-----------|--------|",
        ]
        for r in reclassified:
            cve = r.finding.cves[0] if r.finding.cves else r.finding.plugin_id
            reason = r.severity_justification.replace("|", "\\|")[:100]
            lines.append(
                f"| {r.finding.plugin_name} | {cve} | "
                f"{r.finding.nessus_severity_str} | {r.realistic_severity} | {reason} |"
            )
        lines.append("")

    return "\n".join(lines)


def _chains_md(chains: list[ExploitChain]) -> str:
    if not chains:
        return "# Exploit Chains\n\nNo exploit chains identified.\n"
    lines = ["# Exploit Chains Identified", ""]
    for c in chains:
        lines += [
            f"## {c.label}",
            f"**Vuln A:** {c.vuln_a}",
            f"**Vuln B:** {c.vuln_b}",
            f"**Impact:** {c.impact}",
            "",
            c.description,
            "",
        ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------

@app.command("run")
def run(
    nessus_file: str = typer.Argument(..., help="Path to .nessus scan file"),
    output_dir:  str = typer.Option(
        "./pentest_output",
        "--output-dir", "-o",
        help="Directory for PoC files and report output",
    ),
    min_severity: str = typer.Option(
        "HIGH",
        "--severity", "-s",
        help="Minimum Nessus severity to validate: CRITICAL | HIGH | MEDIUM",
    ),
    limit: int = typer.Option(
        0,
        "--limit", "-n",
        help="Validate at most N findings (0 = all)",
    ),
    skip_chains: bool = typer.Option(
        False,
        "--skip-chains",
        help="Skip the exploit chain detection pass (faster)",
    ),
    execute: bool = typer.Option(
        False,
        "--execute", "-x",
        help="Execute each generated PoC against the target and capture PoE output",
    ),
    exec_timeout: int = typer.Option(
        45,
        "--timeout",
        help="Per-PoC execution timeout in seconds (--execute only)",
    ),
):
    """
    Parse a Nessus file, validate every Critical/High finding with AI,
    generate PoC artefacts, and produce findings_report.md.

    Add --execute / -x to also run each PoC and capture proof-of-exploitation output.
    """
    nessus_path = Path(nessus_file)
    if not nessus_path.exists():
        console.print(f"[red]File not found:[/red] {nessus_file}")
        raise typer.Exit(1)

    out_dir = Path(output_dir)
    poc_dir = out_dir / "pocs"
    poe_dir = out_dir / "poe"
    out_dir.mkdir(parents=True, exist_ok=True)

    min_sev_int = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2}.get(min_severity.upper(), 3)

    # ── Phase 1: Parse ────────────────────────────────────────────────
    console.print(f"\n[bold cyan]Phase 1[/bold cyan]  Parsing [yellow]{nessus_path.name}[/yellow]…")
    try:
        scan_name, all_findings = parse_nessus(nessus_path)
    except Exception as exc:
        console.print(f"[red]Parse error:[/red] {exc}")
        raise typer.Exit(1)

    sev_counts_raw = {}
    for f in all_findings:
        sev_counts_raw[f.nessus_severity_str] = sev_counts_raw.get(f.nessus_severity_str, 0) + 1

    console.print(
        f"  Scan: [bold]{scan_name}[/bold]  |  "
        f"Total items: [bold]{len(all_findings)}[/bold]  |  "
        + "  ".join(
            f"[{_sev_colour(s)}]{s}:{n}[/{_sev_colour(s)}]"
            for s, n in sev_counts_raw.items() if n
        )
    )

    # Triage table
    console.print()
    console.print(_triage_table(all_findings))

    # Save triage_table.md
    triage_md_path = out_dir / "triage_table.md"
    triage_md_path.write_text(
        _triage_md(scan_name, all_findings), encoding="utf-8"
    )
    console.print(f"\n[dim]Triage table saved → {triage_md_path}[/dim]")

    # Filter to target severity
    targets = [f for f in all_findings if f.nessus_severity >= min_sev_int]
    if limit > 0:
        targets = targets[:limit]

    if not targets:
        console.print(
            f"\n[yellow]No {min_severity}+ findings to validate. Done.[/yellow]"
        )
        raise typer.Exit(0)

    console.print(
        f"\n[bold cyan]Phase 2[/bold cyan]  "
        f"Validating [bold]{len(targets)}[/bold] "
        f"[{_sev_colour(min_severity)}]{min_severity}+[/{_sev_colour(min_severity)}] "
        f"findings with AI…\n"
    )

    # ── Phase 2 + 3: AI validation + PoC save ────────────────────────
    try:
        validator = VulnValidator()
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    results: list[ValidationResult] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task("Validating…", total=len(targets))

        for idx, finding in enumerate(targets, 1):
            cve_label = finding.cves[0] if finding.cves else finding.plugin_id
            progress.update(
                task_id,
                description=f"[{_sev_colour(finding.nessus_severity_str)}]"
                            f"{finding.nessus_severity_str}[/{_sev_colour(finding.nessus_severity_str)}] "
                            f"{finding.host_ip}:{finding.port} — {finding.plugin_name[:45]}",
            )

            result = validator.validate_finding(finding)
            results.append(result)

            # Save PoC file
            if result.poc_type in ("A", "B") and result.poc_code.strip():
                saved = _save_poc(result, poc_dir)
                if saved:
                    result.poc_filename = result.poc_filename  # already set

            progress.advance(task_id)

    # ── Print validation result panels ────────────────────────────────
    console.print()
    for idx, result in enumerate(results, 1):
        console.print(_result_panel(result, idx, len(results)))
        console.print()

    # ── Phase 3b: Execute PoCs (opt-in) ───────────────────────────────
    exec_results: dict[str, PoCExecutionResult] = {}   # poc_filename → result

    if execute:
        runnable = [
            r for r in results
            if r.poc_type in ("A", "B", "C") and (r.poc_code.strip() or r.poc_type == "C")
        ]
        console.print(
            f"[bold cyan]Phase 3b[/bold cyan]  "
            f"Executing [bold]{len(runnable)}[/bold] PoC(s) "
            f"[dim](timeout: {exec_timeout}s each)[/dim]…\n"
        )

        executor = PoCExecutor(validator=validator)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
            transient=False,
        ) as prog:
            exec_task = prog.add_task("Executing…", total=len(runnable))

            for r in runnable:
                prog.update(
                    exec_task,
                    description=f"{r.finding.host_ip}:{r.finding.port} — {r.finding.plugin_name[:50]}",
                )
                er = executor.execute(r, poc_dir, poe_dir, timeout=exec_timeout)
                exec_results[r.poc_filename] = er
                prog.advance(exec_task)

        # Print execution panels
        console.print()
        for r in runnable:
            er = exec_results.get(r.poc_filename)
            if er:
                console.print(_exec_panel(er, r.finding.plugin_name))
                console.print()

        # ── MSF failure → offer manual PoC fallback ───────────────────
        msf_failed = [
            r for r in runnable
            if r.poc_type == "C"
            and exec_results.get(r.poc_filename) is not None
            and exec_results[r.poc_filename].outcome in ("FAILURE", "PARTIAL", "ERROR")
        ]

        if msf_failed:
            console.print(
                f"\n[yellow]Metasploit was unable to verify "
                f"[bold]{len(msf_failed)}[/bold] finding(s):[/yellow]"
            )
            for r in msf_failed:
                er = exec_results[r.poc_filename]
                cve = r.finding.cves[0] if r.finding.cves else r.finding.plugin_id
                console.print(
                    f"  [{_sev_colour(r.realistic_severity)}]"
                    f"{r.realistic_severity}[/{_sev_colour(r.realistic_severity)}]  "
                    f"[bold]{r.finding.plugin_name}[/bold]  "
                    f"[dim]{r.finding.host_ip}:{r.finding.port}[/dim]  "
                    f"[dim]{cve}[/dim]  → [red]{er.outcome}[/red]"
                )

            console.print()
            retry = typer.confirm(
                "Generate standalone Python/Bash PoC scripts for the failed findings and retry?",
                default=False,
            )

            if retry:
                console.print(
                    f"\n[bold cyan]Phase 3c[/bold cyan]  "
                    f"Generating manual PoCs for [bold]{len(msf_failed)}[/bold] failed finding(s)…\n"
                )
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    MofNCompleteColumn(),
                    console=console,
                    transient=False,
                ) as prog2:
                    t2 = prog2.add_task("Generating…", total=len(msf_failed))

                    for r in msf_failed:
                        prog2.update(
                            t2,
                            description=f"{r.finding.host_ip}:{r.finding.port} — "
                                        f"{r.finding.plugin_name[:50]}",
                        )
                        msf_out = exec_results[r.poc_filename].stdout
                        poc_code, poc_fname, poc_lang = validator.generate_manual_poc(
                            r.finding, msf_out
                        )
                        prog2.advance(t2)

                        if not poc_code.strip():
                            console.print(
                                f"  [dim]Could not generate manual PoC for "
                                f"{r.finding.plugin_name}[/dim]"
                            )
                            continue

                        # Save manual PoC
                        poc_path = poc_dir / poc_fname
                        poc_path.write_text(poc_code, encoding="utf-8")

                        # Execute it — build a minimal ValidationResult-like object
                        # by mutating a copy of r with the new poc info
                        import copy
                        r_manual        = copy.copy(r)
                        r_manual.poc_type     = "A"
                        r_manual.poc_code     = poc_code
                        r_manual.poc_filename = poc_fname
                        r_manual.poc_language = poc_lang

                        er_manual = executor.execute(
                            r_manual, poc_dir, poe_dir, timeout=exec_timeout
                        )
                        exec_results[poc_fname] = er_manual

                        # Also update the original MSF result key so report links correctly
                        exec_results[r.poc_filename + "_manual"] = er_manual

                        console.print(_exec_panel(er_manual, r.finding.plugin_name + " [manual]"))
                        console.print()

    # ── Phase 4a: Chain detection ─────────────────────────────────────
    chains: list[ExploitChain] = []
    if not skip_chains:
        console.print("[bold cyan]Phase 4[/bold cyan]  Detecting exploit chains…")
        chains = validator.detect_chains(results)
        if chains:
            console.print(f"  [yellow]{len(chains)} chain(s) identified:[/yellow]")
            for c in chains:
                console.print(f"    [bold yellow]{c.label}[/bold yellow]")
                console.print(f"    [dim]{c.description[:120]}[/dim]")
        else:
            console.print("  [dim]No significant chains identified.[/dim]")
        console.print()

    # ── Phase 4b: Save report files ───────────────────────────────────
    report_path = out_dir / "findings_report.md"
    chains_path = out_dir / "chains.md"

    report_path.write_text(
        _findings_report_md(
            str(nessus_path),
            scan_name,
            all_findings,
            results,
            chains,
            poc_dir,
            exec_results=exec_results or None,
        ),
        encoding="utf-8",
    )

    chains_path.write_text(_chains_md(chains), encoding="utf-8")

    # ── Summary ───────────────────────────────────────────────────────
    pocs_written = sum(
        1 for r in results if r.poc_type in ("A", "B") and r.poc_code.strip()
    )
    reclassified  = sum(1 for r in results if r.severity_changed)
    exec_success  = sum(1 for er in exec_results.values() if er.outcome == "SUCCESS")
    exec_partial  = sum(1 for er in exec_results.values() if er.outcome == "PARTIAL")
    exec_failure  = sum(1 for er in exec_results.values() if er.outcome == "FAILURE")

    sev_after: dict[str, int] = {}
    for r in results:
        sev_after[r.realistic_severity] = sev_after.get(r.realistic_severity, 0) + 1

    t = Table(title="[bold]Validation Complete[/bold]", show_header=False, box=None)
    t.add_column("Key",   style="bold cyan")
    t.add_column("Value")
    t.add_row("Findings validated",   str(len(results)))
    t.add_row("PoC artefacts written", str(pocs_written))
    t.add_row("Severity reclassified", str(reclassified))
    if execute:
        t.add_row("PoCs executed",    str(len(exec_results)))
        t.add_row("Outcomes",
                  f"[green]SUCCESS:{exec_success}[/green]  "
                  f"[yellow]PARTIAL:{exec_partial}[/yellow]  "
                  f"[red]FAILURE:{exec_failure}[/red]")
    t.add_row("Chains identified",    str(len(chains)))
    t.add_row("After-validation counts",
              "  ".join(
                  f"[{_sev_colour(s)}]{s}:{n}[/{_sev_colour(s)}]"
                  for s, n in sorted(sev_after.items(),
                                     key=lambda x: _SEVERITY_ORDER.get(x[0], 5))
              ))
    t.add_row("Report",        str(report_path))
    t.add_row("PoC directory", str(poc_dir))
    if execute:
        t.add_row("PoE directory", str(poe_dir))
    t.add_row("Chains",        str(chains_path))
    console.print(t)
