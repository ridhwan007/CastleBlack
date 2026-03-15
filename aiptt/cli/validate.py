"""
Exploit validation workflow.

  aiptt validate run <file.nessus>
  aiptt validate run <file.nessus> --execute        # also runs each PoC

Phases:
  1. Parse → triage (actionable findings only, SSL consolidated, per-scan folder)
  2. Per finding: AI analysis → save PoC → execute → auto-retry on error (up to N) → next
  3. Chain analysis
  4. Report — pentest_report.md
"""

from __future__ import annotations

import copy
import gzip
import re
import xml.etree.ElementTree as ET
from datetime import date, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from aiptt.engine.vuln_validator import RawFinding, ValidationResult, ExploitChain, VulnValidator
from aiptt.engine.poc_executor   import PoCExecutor, PoCExecutionResult

app     = typer.Typer(help="Exploit validation workflow.")
console = Console()

_SEV_STR = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
_SEV_INT  = {v: k for k, v in _SEV_STR.items()}

_SEV_COLOUR = {
    "CRITICAL":       "bold red",
    "HIGH":           "red",
    "MEDIUM":         "yellow",
    "LOW":            "cyan",
    "INFO":           "dim",
    "FALSE_POSITIVE": "dim green",
}

_SEVERITY_ORDER = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "FALSE_POSITIVE": 5
}


def _sev_colour(s: str) -> str:
    return _SEV_COLOUR.get(s.upper(), "white")


def _slug(name: str, max_len: int = 60) -> str:
    """Filesystem-safe slug from a finding/scan name."""
    s = re.sub(r"[^\w\s\-]", "", name).strip()
    s = re.sub(r"[\s_]+", "_", s)
    return s[:max_len].rstrip("_")


def _is_ssl_finding(f: RawFinding) -> bool:
    """True if this finding relates to SSL/TLS configuration."""
    keywords = ("ssl", "tls", "certificate", "cipher", "x.509", "poodle",
                "beast", "heartbleed", "drown", "logjam", "freak", "sweet32",
                "rc4", "diffie-hellman")
    combined = (f.plugin_name + " " + f.plugin_family).lower()
    return any(k in combined for k in keywords)


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------

def _load_xml(path: Path) -> ET.ElementTree:
    if path.suffix == ".gz" or path.name.endswith(".nessus.gz"):
        with gzip.open(path, "rb") as fh:
            return ET.parse(fh)
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
    """Parse a .nessus XML file — returns (scan_name, list[RawFinding])."""
    tree  = _load_xml(path)
    root  = tree.getroot()
    reports   = root.findall(".//Report")
    scan_name = reports[0].get("name", "Unknown") if reports else "Unknown"

    findings: list[RawFinding] = []
    seen: set[str] = set()

    for report in reports:
        for rhost in report.findall("ReportHost"):
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

                port       = int(item.get("port", 0))
                protocol   = item.get("protocol", "tcp").lower()
                svc_name   = item.get("svc_name", "").lower()
                nessus_sev = int(item.get("severity", 0))
                pname      = item.get("pluginName", "")
                pfam       = item.get("pluginFamily", "")

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
                    plugin_name=pname,
                    plugin_family=pfam,
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

    findings.sort(key=lambda f: (f.host_ip, -f.cvss))
    return scan_name, findings


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _triage_table(findings: list[RawFinding]) -> Table:
    t = Table(
        title="[bold]Actionable Findings — Triage[/bold]",
        show_lines=False,
        header_style="bold cyan",
    )
    t.add_column("Host",       style="cyan", no_wrap=True)
    t.add_column("Port",       style="dim",  no_wrap=True)
    t.add_column("Service",    style="dim",  no_wrap=True)
    t.add_column("CVSSv3",     no_wrap=True)
    t.add_column("Severity",   no_wrap=True)
    t.add_column("Exploit",    no_wrap=True)
    t.add_column("Finding",    overflow="fold")
    t.add_column("CVE(s)",     overflow="fold")

    for f in findings:
        sev_col  = _sev_colour(f.nessus_severity_str)
        exp_col  = "[green]Yes[/green]" if f.exploit_available else "[dim]No[/dim]"
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
    f    = r.finding
    orig = f.nessus_severity_str
    real = r.realistic_severity
    col  = _sev_colour(real)

    arrow = ""
    if r.severity_changed:
        orig_n = _SEV_INT.get(orig, 2)
        real_n = _SEV_INT.get(real, 2)
        arrow  = " [green]↓[/green]" if real_n < orig_n else " [red]↑[/red]"

    title = (
        f"[{col}]{real}[/{col}]{arrow}  "
        f"[bold]{f.plugin_name}[/bold]  "
        f"[dim]{f.host_ip}:{f.port}[/dim]  "
        f"[dim]({idx}/{total})[/dim]"
    )

    cve_str = ", ".join(f.cves) or "—"
    lines = [
        f"[bold]CVE:[/bold] {cve_str}   [bold]CVSS:[/bold] {f.cvss}   [bold]Service:[/bold] {f.svc_name}/{f.protocol}",
        f"[bold]Evidence Quality:[/bold] {r.evidence_quality}",
        "",
        "[bold cyan]Context:[/bold cyan]",
        r.context_notes,
        "",
        "[bold cyan]Exploit Research:[/bold cyan]",
        r.exploit_research,
        "",
        f"[bold cyan]Exploitation Outcome:[/bold cyan] {r.exploitation_outcome}",
        "",
        f"[bold cyan]PoC Type {r.poc_type}:[/bold cyan] {r.poc_filename or 'N/A'}  "
        f"[dim](reliability: {r.poc_reliability})[/dim]",
    ]
    if r.poc_type == "D":
        lines.append(f"  [dim]{r.poc_no_reason}[/dim]")
    elif r.poc_filename:
        lines.append(f"  [green]Saved → {r.poc_filename}[/green]")
    lines += [
        "",
        f"[bold cyan]Severity:[/bold cyan]  {orig} → [{col}]{real}[/{col}]",
        f"  {r.severity_justification}",
        "",
        "[bold cyan]Remediation:[/bold cyan]",
        r.remediation,
    ]
    if r.chain_hint:
        lines += ["", f"[bold yellow]Chain:[/bold yellow] {r.chain_hint}"]

    return Panel("\n".join(lines), title=title, expand=False)


_OUTCOME_COLOUR = {
    "SUCCESS": "bold green",
    "PARTIAL": "yellow",
    "FAILURE": "red",
    "ERROR":   "dim red",
    "SKIPPED": "dim",
}


def _exec_panel(er: PoCExecutionResult, finding_name: str, attempt: int = 1) -> Panel:
    col   = _OUTCOME_COLOUR.get(er.outcome, "white")
    atag  = f" [dim]attempt {attempt}[/dim]" if attempt > 1 else ""
    title = (
        f"[{col}]{er.outcome}[/{col}]{atag}  "
        f"[bold]{finding_name}[/bold]  "
        f"[dim]{er.target_ip}:{er.target_port}[/dim]  "
        f"[dim]{er.duration_s:.1f}s[/dim]"
    )

    lines = [
        f"[bold]Command:[/bold] {er.command_run}",
        f"[bold]Return code:[/bold] {er.return_code}"
        + (" [yellow][TIMEOUT][/yellow]" if er.timed_out else ""),
    ]
    if er.stdout.strip():
        preview = er.stdout[:600].rstrip()
        if len(er.stdout) > 600:
            preview += "\n... [dim][truncated — see PoE artefact][/dim]"
        lines += ["", "[bold cyan]STDOUT:[/bold cyan]", preview]
    if er.stderr.strip():
        lines += ["", "[bold red]STDERR:[/bold red]", er.stderr[:300].rstrip()]
    if er.captured_data.strip():
        lines += ["", "[bold green]CAPTURED DATA:[/bold green]", er.captured_data]
    lines += ["", "[bold cyan]AI Interpretation:[/bold cyan]", er.ai_interpretation]
    if er.poe_artefact_path:
        lines += ["", f"[dim]PoE → {er.poe_artefact_path}[/dim]"]

    return Panel("\n".join(lines), title=title, expand=False)


# ---------------------------------------------------------------------------
# File writers
# ---------------------------------------------------------------------------

def _save_poc(result: ValidationResult, poc_dir: Path) -> Path | None:
    if result.poc_type == "D" or not result.poc_code.strip():
        return None
    poc_dir.mkdir(parents=True, exist_ok=True)
    out = poc_dir / result.poc_filename
    out.write_text(result.poc_code, encoding="utf-8")
    return out


def _triage_md(scan_name: str, findings: list[RawFinding], ssl_group: list[RawFinding]) -> str:
    lines = [
        f"# Actionable Findings — {scan_name}",
        f"Date: {date.today().isoformat()}",
        f"Identified: {len(findings)} actionable + {len(ssl_group)} SSL/TLS (consolidated)",
        "",
        "| Host | Port | Service | CVSSv3 | Severity | Exploit Available | Finding | CVE(s) |",
        "|------|------|---------|--------|----------|-------------------|---------|--------|",
    ]
    for f in findings:
        cve_str = ", ".join(f.cves[:3]) + ("…" if len(f.cves) > 3 else "") if f.cves else "—"
        exp     = "Yes" if f.exploit_available else "No"
        lines.append(
            f"| {f.host_ip} | {f.port or '—'} | {f.svc_name} | {f.cvss:.1f} | "
            f"{f.nessus_severity_str} | {exp} | {f.plugin_name} | {cve_str} |"
        )
    if ssl_group:
        ssl_hosts = ", ".join(sorted({f.host_ip for f in ssl_group}))
        lines.append(
            f"| {ssl_hosts} | various | ssl/tls | — | MEDIUM | No | "
            f"SSL/TLS Configuration Issues ({len(ssl_group)} consolidated) | — |"
        )
    return "\n".join(lines)


def _findings_report_md(
    scan_name: str,
    all_findings: list[RawFinding],
    results: list[ValidationResult],
    chains: list[ExploitChain],
    poc_dir: Path,
    ssl_group: list[RawFinding],
    exec_results: dict[str, list[PoCExecutionResult]] | None = None,
) -> str:
    today  = date.today().isoformat()
    hosts  = sorted({f.host_ip for f in all_findings})

    sev_counts: dict[str, int] = {}
    for r in results:
        sev_counts[r.realistic_severity] = sev_counts.get(r.realistic_severity, 0) + 1
    if ssl_group:
        sev_counts["MEDIUM"] = sev_counts.get("MEDIUM", 0) + 1

    sorted_results = sorted(results, key=lambda r: _SEVERITY_ORDER.get(r.realistic_severity, 5))
    best           = sorted_results[0] if sorted_results else None
    crits_highs    = [r for r in sorted_results if r.realistic_severity in ("CRITICAL", "HIGH")]

    lines: list[str] = []

    # ── Cover ──────────────────────────────────────────────────────────────
    lines += [
        "# Penetration Test — Findings Report",
        "",
        f"**Target(s):** {', '.join(hosts)}",
        f"**Assessment Date:** {today}",
        f"**Engagement:** {scan_name}",
        "",
        "---",
        "",
    ]

    # ── Executive Summary ──────────────────────────────────────────────────
    total_exploitable = sum(
        1 for r in results if r.realistic_severity in ("CRITICAL", "HIGH", "MEDIUM")
    ) + (1 if ssl_group else 0)

    lines += [
        "## Executive Summary",
        "",
        f"A security assessment was conducted against **{', '.join(hosts)}**. "
        f"The engagement identified **{len(results) + (1 if ssl_group else 0)} findings**, "
        f"of which **{total_exploitable} are considered exploitable** under realistic attack conditions.",
        "",
    ]

    if best:
        cve = best.finding.cves[0] if best.finding.cves else ""
        lines.append(
            f"The highest-risk finding is **{best.finding.plugin_name}**"
            + (f" ({cve})" if cve else "")
            + f" on **{best.finding.host_ip}:{best.finding.port}**,"
            f" presenting a **{best.exploitation_outcome}** risk under exploitation."
        )
        lines.append("")

    lines += [
        "### Risk Distribution",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "FALSE_POSITIVE"):
        n = sev_counts.get(sev, 0)
        if n:
            lines.append(f"| {sev} | {n} |")
    lines.append("")

    if crits_highs:
        lines += ["### Priority Remediation Actions", ""]
        for i, r in enumerate(crits_highs[:5], 1):
            lines.append(
                f"{i}. **{r.finding.plugin_name}** on {r.finding.host_ip}:{r.finding.port} — "
                f"{r.remediation[:130]}"
            )
        lines.append("")

    lines += ["---", ""]

    # ── Vulnerability Summary Table ────────────────────────────────────────
    lines += [
        "## Vulnerability Summary",
        "",
        "| # | Finding | Host | Port | Severity | CVE | Outcome |",
        "|---|---------|------|------|----------|-----|---------|",
    ]
    for i, r in enumerate(sorted_results, 1):
        f   = r.finding
        cve = f.cves[0] if f.cves else "—"
        lines.append(
            f"| {i} | {f.plugin_name} | {f.host_ip} | {f.port or '—'} | "
            f"{r.realistic_severity} | {cve} | {r.exploitation_outcome} |"
        )
    if ssl_group:
        ssl_hosts = ", ".join(sorted({f.host_ip for f in ssl_group}))
        lines.append(
            f"| {len(sorted_results)+1} | SSL/TLS Configuration Issues | "
            f"{ssl_hosts} | various | MEDIUM | — | Downgrade / Info Disclosure |"
        )
    lines += ["", "---", ""]

    # ── Detailed Findings ──────────────────────────────────────────────────
    lines += ["## Detailed Findings", ""]

    for idx, r in enumerate(sorted_results, 1):
        f   = r.finding
        cve = ", ".join(f.cves) or "—"

        poc_ref = (
            (poc_dir / r.poc_filename).as_posix()
            if r.poc_filename and r.poc_type != "D"
            else "No viable PoC"
        )

        lines += [
            f"### {idx}. {f.plugin_name}",
            "",
            "| Field | Detail |",
            "|-------|--------|",
            f"| **Severity** | {r.realistic_severity} |",
            f"| **CVE** | {cve} |",
            f"| **CVSS** | {f.cvss:.1f} |",
            f"| **Target** | {f.host_ip}:{f.port} ({f.svc_name}/{f.protocol}) |",
            f"| **Outcome** | {r.exploitation_outcome} |",
            f"| **Evidence Quality** | {r.evidence_quality} |",
        ]
        if f.metasploit_name:
            lines.append(f"| **Metasploit Module** | {f.metasploit_name} |")
        lines.append("")

        lines += [
            "**Description**",
            "",
            r.context_notes,
            "",
            "**Exploitability**",
            "",
            r.exploit_research,
            "",
            "**Severity Assessment**",
            "",
            r.severity_justification,
            "",
            "**Remediation**",
            "",
            r.remediation,
            "",
        ]

        if r.poc_type != "D" and r.poc_filename:
            lines.append(f"**Proof of Concept:** `{poc_ref}`")
            lines.append("")

        if r.chain_hint:
            lines.append(f"**Exploit Chain:** {r.chain_hint}")
            lines.append("")

        # ── Exploitation attempts ──────────────────────────────────────
        all_exec = (exec_results or {}).get(r.poc_filename, [])
        if all_exec:
            lines += ["**Exploitation Attempts**", ""]
            for attempt_no, er in enumerate(all_exec, 1):
                icon = {
                    "SUCCESS": "✅", "PARTIAL": "⚠️", "FAILURE": "❌",
                    "ERROR": "💥", "SKIPPED": "⏭️",
                }.get(er.outcome, "")
                lines.append(
                    f"*Attempt {attempt_no}:* {icon} **{er.outcome}** — "
                    f"`{er.command_run}` ({er.duration_s:.1f}s"
                    + (" — timed out" if er.timed_out else "") + ")"
                )
                if er.captured_data.strip():
                    lines.append(f"  Captured: `{er.captured_data}`")
                lines.append(f"  {er.ai_interpretation}")
                lines.append("")
            final_er = all_exec[-1]
            if final_er.poe_artefact_path:
                lines.append(f"**PoE Artefact:** `{final_er.poe_artefact_path}`")
                lines.append("")

        lines += ["---", ""]

    # ── SSL consolidated ───────────────────────────────────────────────────
    if ssl_group:
        ssl_hosts = sorted({f.host_ip for f in ssl_group})
        ssl_cves  = sorted({c for f in ssl_group for c in f.cves})
        ssl_names = sorted({f.plugin_name for f in ssl_group})

        lines += [
            f"### {len(sorted_results)+1}. SSL/TLS Configuration Issues",
            "",
            "| Field | Detail |",
            "|-------|--------|",
            "| **Severity** | MEDIUM |",
            f"| **Affected Hosts** | {', '.join(ssl_hosts)} |",
            f"| **Consolidated Checks** | {len(ssl_group)} |",
            "",
            "**Description**",
            "",
            "The assessment identified multiple SSL/TLS configuration weaknesses across the target "
            "environment. These include use of deprecated protocol versions, weak cipher suites, "
            "and certificate-related issues. While individually low-to-medium risk, the combined "
            "exposure represents a cryptographic hardening gap that could facilitate traffic "
            "interception or downgrade attacks in a targeted engagement.",
            "",
            "**Checks Identified**",
            "",
        ]
        for name in ssl_names:
            lines.append(f"- {name}")
        lines.append("")
        if ssl_cves:
            lines.append(f"**Related CVEs:** {', '.join(ssl_cves[:10])}")
            lines.append("")
        lines += [
            "**Remediation**",
            "",
            "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Restrict cipher suites to "
            "ECDHE+AES-GCM or ChaCha20-Poly1305. Ensure certificates are valid, properly "
            "chained, and renewed before expiry. Enforce HSTS where applicable.",
            "",
            "---",
            "",
        ]

    # ── Exploit Chain Analysis ─────────────────────────────────────────────
    if chains:
        lines += ["## Exploit Chain Analysis", ""]
        for c in chains:
            lines += [
                f"### {c.label}",
                "",
                f"**Step 1:** {c.vuln_a}",
                f"**Step 2:** {c.vuln_b}",
                f"**Combined Impact:** {c.impact}",
                "",
                c.description,
                "",
                "---",
                "",
            ]

    # ── Appendix: Reclassifications ────────────────────────────────────────
    reclassified = [r for r in results if r.severity_changed]
    if reclassified:
        lines += [
            "## Appendix A — Severity Reclassifications",
            "",
            "The following findings were re-assessed and reclassified based on "
            "actual exploitability analysis, diverging from the initial automated rating:",
            "",
            "| Finding | Initial Rating | Adjusted Rating | Rationale |",
            "|---------|---------------|-----------------|-----------|",
        ]
        for r in reclassified:
            cve    = r.finding.cves[0] if r.finding.cves else r.finding.plugin_id
            reason = r.severity_justification.replace("|", "\\|")[:120]
            lines.append(
                f"| {r.finding.plugin_name} | {r.finding.nessus_severity_str} | "
                f"{r.realistic_severity} | {reason} |"
            )
        lines.append("")

    return "\n".join(lines)


def _chains_md(chains: list[ExploitChain]) -> str:
    if not chains:
        return "# Exploit Chain Analysis\n\nNo significant exploit chains identified.\n"
    lines = ["# Exploit Chain Analysis", ""]
    for c in chains:
        lines += [
            f"## {c.label}",
            f"**Step 1:** {c.vuln_a}",
            f"**Step 2:** {c.vuln_b}",
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
        help="Base output directory (a per-scan subfolder is created inside)",
    ),
    min_severity: str = typer.Option(
        "HIGH",
        "--severity", "-s",
        help="Minimum severity to include: CRITICAL | HIGH | MEDIUM",
    ),
    limit: int = typer.Option(
        0,
        "--limit", "-n",
        help="Process at most N findings (0 = all)",
    ),
    skip_chains: bool = typer.Option(
        False,
        "--skip-chains",
        help="Skip exploit chain detection",
    ),
    execute: bool = typer.Option(
        False,
        "--execute", "-x",
        help="Execute each PoC and capture proof-of-exploitation output",
    ),
    exec_timeout: int = typer.Option(
        45,
        "--timeout",
        help="Per-PoC execution timeout in seconds",
    ),
    max_retries: int = typer.Option(
        3,
        "--retries",
        help="Max auto-retry attempts per finding when execution fails",
    ),
):
    """
    Parse a scan file, validate every actionable finding, generate PoCs,
    and produce a pentest report. Use --execute / -x to run PoCs live.
    """
    nessus_path = Path(nessus_file)
    if not nessus_path.exists():
        console.print(f"[red]File not found:[/red] {nessus_file}")
        raise typer.Exit(1)

    # ── Phase 1: Parse ──────────────────────────────────────────────────
    console.print(f"\n[bold cyan]Phase 1[/bold cyan]  Parsing [yellow]{nessus_path.name}[/yellow]…")
    try:
        scan_name, all_findings = parse_nessus(nessus_path)
    except Exception as exc:
        console.print(f"[red]Parse error:[/red] {exc}")
        raise typer.Exit(1)

    # Per-scan output folder
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug      = _slug(scan_name, max_len=40) or "scan"
    out_dir   = Path(output_dir) / f"{slug}_{ts}"
    poc_dir   = out_dir / "pocs"
    poe_dir   = out_dir / "poe"
    out_dir.mkdir(parents=True, exist_ok=True)

    sev_counts_raw: dict[str, int] = {}
    for f in all_findings:
        sev_counts_raw[f.nessus_severity_str] = sev_counts_raw.get(f.nessus_severity_str, 0) + 1

    console.print(
        f"  Engagement: [bold]{scan_name}[/bold]  |  "
        f"Total items: [bold]{len(all_findings)}[/bold]  |  "
        + "  ".join(
            f"[{_sev_colour(s)}]{s}:{n}[/{_sev_colour(s)}]"
            for s, n in sev_counts_raw.items() if n
        )
    )
    console.print(f"  Output: [dim]{out_dir}[/dim]")

    # ── Triage ──────────────────────────────────────────────────────────
    min_sev_int = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2}.get(min_severity.upper(), 3)

    ssl_group = [f for f in all_findings if _is_ssl_finding(f)]
    non_ssl   = [f for f in all_findings if not _is_ssl_finding(f)]

    # Actionable: HIGH+ always; MEDIUM/LOW if exploit_available
    targets = [
        f for f in non_ssl
        if f.nessus_severity >= min_sev_int
        or (f.exploit_available and f.nessus_severity >= 2)
    ]
    if limit > 0:
        targets = targets[:limit]

    if ssl_group:
        console.print(
            f"  [dim]SSL/TLS:[/dim] [yellow]{len(ssl_group)}[/yellow] findings "
            f"consolidated → rated MEDIUM"
        )

    console.print()
    console.print(_triage_table(targets))

    triage_md_path = out_dir / "triage_table.md"
    triage_md_path.write_text(_triage_md(scan_name, targets, ssl_group), encoding="utf-8")
    console.print(f"\n[dim]Triage saved → {triage_md_path}[/dim]")

    if not targets:
        console.print("\n[yellow]No actionable findings to validate.[/yellow]")
        raise typer.Exit(0)

    console.print(
        f"\n[bold cyan]Phase 2[/bold cyan]  "
        f"Processing [bold]{len(targets)}[/bold] finding(s) — "
        f"[dim]validate → exploit → next[/dim]\n"
    )

    # ── Initialise AI + executor ────────────────────────────────────────
    try:
        validator = VulnValidator()
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    executor = PoCExecutor(validator=validator)

    results:      list[ValidationResult]                    = []
    exec_results: dict[str, list[PoCExecutionResult]]       = {}

    total = len(targets)

    for idx, finding in enumerate(targets, 1):
        console.print(Rule(
            f"[{_sev_colour(finding.nessus_severity_str)}]"
            f"{finding.nessus_severity_str}[/{_sev_colour(finding.nessus_severity_str)}]  "
            f"[bold]{finding.plugin_name}[/bold]  "
            f"[dim]{finding.host_ip}:{finding.port}[/dim]  "
            f"[dim]({idx}/{total})[/dim]",
            style="dim",
        ))

        # Step 1: AI analysis
        with console.status(f"[cyan]Analysing {finding.plugin_name[:50]}…[/cyan]"):
            result = validator.validate_finding(finding)

        results.append(result)
        console.print(_result_panel(result, idx, total))
        console.print()

        # Step 2: Save PoC
        if result.poc_type in ("A", "B") and result.poc_code.strip():
            saved = _save_poc(result, poc_dir)
            if saved:
                console.print(f"  [green]PoC saved →[/green] {saved}")

        # Step 3: Execute + auto-retry
        if not execute or result.poc_type not in ("A", "B", "C"):
            console.print()
            continue

        attempts:       list[PoCExecutionResult] = []
        current_result                           = result

        for attempt in range(1, max_retries + 1):
            if attempt > 1:
                console.print(
                    f"\n  [yellow]Attempt {attempt}/{max_retries} — "
                    f"analysing error and retrying…[/yellow]"
                )

            with console.status(
                f"[cyan]Executing {current_result.poc_filename} "
                f"(attempt {attempt}/{max_retries})…[/cyan]"
            ):
                er = executor.execute(current_result, poc_dir, poe_dir, timeout=exec_timeout)

            attempts.append(er)
            console.print(_exec_panel(er, finding.plugin_name, attempt))
            console.print()

            if er.outcome in ("SUCCESS", "PARTIAL", "SKIPPED"):
                break

            if attempt < max_retries:
                # Retry even without stderr — syntax errors may leave stderr empty
                error_hint = er.stderr.strip() or er.stdout.strip() or f"outcome={er.outcome}"
                with console.status(
                    f"[yellow]Attempt {attempt} failed ({er.outcome}) — "
                    f"analysing error and generating fix…[/yellow]"
                ):
                    fixed_code, fixed_fname, fixed_lang = validator.fix_poc_for_error(
                        finding,
                        current_result.poc_code,
                        error_hint,
                        attempt,
                    )
                if fixed_code.strip():
                    current_result              = copy.copy(result)
                    current_result.poc_code     = fixed_code
                    current_result.poc_filename = fixed_fname
                    current_result.poc_language = fixed_lang
                    _save_poc(current_result, poc_dir)
                    console.print(f"  [green]Fix generated →[/green] {poc_dir / fixed_fname}")
                else:
                    console.print(
                        "  [dim]AI determined this error is not fixable "
                        "(e.g. host not running the service) — stopping retries.[/dim]"
                    )
                    break

        exec_results[result.poc_filename] = attempts
        console.print()

    # ── MSF failure fallback ────────────────────────────────────────────
    if execute:
        msf_failed = [
            r for r in results
            if r.poc_type == "C"
            and exec_results.get(r.poc_filename)
            and exec_results[r.poc_filename][-1].outcome in ("FAILURE", "PARTIAL", "ERROR")
        ]
        if msf_failed:
            console.print(
                f"\n[yellow]Metasploit was unable to verify "
                f"[bold]{len(msf_failed)}[/bold] finding(s):[/yellow]"
            )
            for r in msf_failed:
                er  = exec_results[r.poc_filename][-1]
                cve = r.finding.cves[0] if r.finding.cves else r.finding.plugin_id
                console.print(
                    f"  [{_sev_colour(r.realistic_severity)}]{r.realistic_severity}"
                    f"[/{_sev_colour(r.realistic_severity)}]  "
                    f"[bold]{r.finding.plugin_name}[/bold]  "
                    f"[dim]{r.finding.host_ip}:{r.finding.port}[/dim]  "
                    f"[dim]{cve}[/dim]  → [red]{er.outcome}[/red]"
                )
            console.print()
            retry = typer.confirm(
                "Generate standalone Python/Bash PoC scripts for failed findings and retry?",
                default=False,
            )
            if retry:
                console.print(
                    f"\n[bold cyan]Phase 3[/bold cyan]  "
                    f"Generating manual PoCs for [bold]{len(msf_failed)}[/bold] finding(s)…\n"
                )
                for r in msf_failed:
                    msf_out = exec_results[r.poc_filename][-1].stdout
                    with console.status(
                        f"[cyan]Generating manual PoC for {r.finding.plugin_name[:50]}…[/cyan]"
                    ):
                        poc_code, poc_fname, poc_lang = validator.generate_manual_poc(
                            r.finding, msf_out
                        )
                    if not poc_code.strip():
                        console.print(f"  [dim]No manual PoC available for {r.finding.plugin_name}[/dim]")
                        continue

                    (poc_dir / poc_fname).write_text(poc_code, encoding="utf-8")

                    r_manual              = copy.copy(r)
                    r_manual.poc_type     = "A"
                    r_manual.poc_code     = poc_code
                    r_manual.poc_filename = poc_fname
                    r_manual.poc_language = poc_lang

                    er_manual = executor.execute(r_manual, poc_dir, poe_dir, timeout=exec_timeout)
                    exec_results.setdefault(r.poc_filename, []).append(er_manual)
                    console.print(_exec_panel(er_manual, r.finding.plugin_name + " [manual]"))
                    console.print()

    # ── Phase 4: Chain detection ────────────────────────────────────────
    chains: list[ExploitChain] = []
    if not skip_chains:
        console.print("[bold cyan]Phase 4[/bold cyan]  Detecting exploit chains…")
        with console.status("[cyan]Analysing chains…[/cyan]"):
            chains = validator.detect_chains(results)
        if chains:
            console.print(f"  [yellow]{len(chains)} chain(s) identified:[/yellow]")
            for c in chains:
                console.print(f"    [bold yellow]{c.label}[/bold yellow]")
        else:
            console.print("  [dim]No significant chains identified.[/dim]")
        console.print()

    # ── Phase 5: Report ─────────────────────────────────────────────────
    report_path = out_dir / "pentest_report.md"
    chains_path = out_dir / "chains.md"

    report_path.write_text(
        _findings_report_md(
            scan_name,
            all_findings,
            results,
            chains,
            poc_dir,
            ssl_group=ssl_group,
            exec_results=exec_results or None,
        ),
        encoding="utf-8",
    )
    chains_path.write_text(_chains_md(chains), encoding="utf-8")

    # ── Summary ─────────────────────────────────────────────────────────
    pocs_written = sum(1 for r in results if r.poc_type in ("A", "B") and r.poc_code.strip())
    reclassified = sum(1 for r in results if r.severity_changed)
    exec_success = sum(
        1 for attempts in exec_results.values()
        if any(e.outcome == "SUCCESS" for e in attempts)
    )
    exec_partial = sum(
        1 for attempts in exec_results.values()
        if not any(e.outcome == "SUCCESS" for e in attempts)
        and any(e.outcome == "PARTIAL" for e in attempts)
    )
    exec_failure = sum(
        1 for attempts in exec_results.values()
        if all(e.outcome in ("FAILURE", "ERROR") for e in attempts)
    )

    sev_after: dict[str, int] = {}
    for r in results:
        sev_after[r.realistic_severity] = sev_after.get(r.realistic_severity, 0) + 1
    if ssl_group:
        sev_after["MEDIUM"] = sev_after.get("MEDIUM", 0) + 1

    t = Table(title="[bold]Assessment Complete[/bold]", show_header=False, box=None)
    t.add_column("Key",   style="bold cyan")
    t.add_column("Value")
    t.add_row("Findings validated",    str(len(results)))
    t.add_row("SSL findings grouped",  str(len(ssl_group)))
    t.add_row("PoC artefacts written", str(pocs_written))
    t.add_row("Severity reclassified", str(reclassified))
    if execute:
        total_attempts = sum(len(v) for v in exec_results.values())
        t.add_row("Total execution attempts", str(total_attempts))
        t.add_row(
            "Final outcomes",
            f"[green]SUCCESS:{exec_success}[/green]  "
            f"[yellow]PARTIAL:{exec_partial}[/yellow]  "
            f"[red]FAILURE:{exec_failure}[/red]",
        )
    t.add_row("Chains identified", str(len(chains)))
    t.add_row(
        "Risk profile",
        "  ".join(
            f"[{_sev_colour(s)}]{s}:{n}[/{_sev_colour(s)}]"
            for s, n in sorted(sev_after.items(), key=lambda x: _SEVERITY_ORDER.get(x[0], 5))
        ),
    )
    t.add_row("Report",        str(report_path))
    t.add_row("PoC directory", str(poc_dir))
    if execute:
        t.add_row("PoE directory", str(poe_dir))
    t.add_row("Chains", str(chains_path))
    console.print(t)
