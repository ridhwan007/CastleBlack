"""
Scan / Discovery commands.

  aiptt scan discover     — host sweep
  aiptt scan fingerprint  — service fingerprinting
  aiptt scan vulnscan     — vulnerability scan
  aiptt scan ad-map       — Active Directory enumeration
"""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

app     = typer.Typer(help="Discovery and scanning commands.")
console = Console()


@app.command("discover")
def discover(
    engagement_id: str = typer.Option(..., "--engagement-id", "-e"),
    cidr:          str = typer.Option(..., "--cidr",          "-c", help="Target CIDR"),
    udp:           bool = typer.Option(False, "--udp",             help="Include UDP sweep"),
):
    """Sweep the target CIDR for live hosts."""
    from aiptt.discovery.host_sweep import HostSweeper
    from aiptt.audit.logger import get_audit_logger

    audit = get_audit_logger()
    audit.log_intent("SCAN_DISCOVER_START", engagement=engagement_id, cidr=cidr)

    console.print(f"[cyan]Sweeping[/cyan] {cidr} (UDP={udp})...")

    sweeper = HostSweeper()
    hosts   = list(sweeper.sweep(cidr, include_udp=udp))

    table = Table(title=f"Discovered Hosts ({len(hosts)})")
    table.add_column("IP",          style="cyan")
    table.add_column("Open Ports",  style="green")
    table.add_column("UDP Ports",   style="yellow")
    table.add_column("Honeypot?",   style="red")

    for h in hosts:
        table.add_row(
            h.ip,
            ", ".join(str(p) for p in h.open_ports[:8]),
            ", ".join(str(p) for p in h.udp_ports[:4]),
            "SUSPECTED" if getattr(h, "suspected_honeypot", False) else "",
        )

    console.print(table)
    audit.log_event("SCAN_DISCOVER_COMPLETE", engagement=engagement_id, hosts=len(hosts))


@app.command("fingerprint")
def fingerprint(
    engagement_id: str  = typer.Option(..., "--engagement-id", "-e"),
    target:        str  = typer.Option(..., "--target",        "-t", help="IP or CIDR"),
):
    """Fingerprint services on the target."""
    from aiptt.discovery.fingerprint import ServiceFingerprinter
    from aiptt.audit.logger import get_audit_logger

    audit = get_audit_logger()
    audit.log_intent("SCAN_FINGERPRINT_START", engagement=engagement_id, target=target)

    fp = ServiceFingerprinter()
    result = fp.fingerprint(target)

    table = Table(title=f"Fingerprint: {target}")
    table.add_column("Port",    style="cyan")
    table.add_column("Service", style="white")
    table.add_column("Version", style="green")
    table.add_column("Banner",  style="dim")

    for svc in result.services:
        table.add_row(
            str(svc.port),
            svc.service_name,
            svc.version or "",
            (svc.banner or "")[:60],
        )

    console.print(table)
    if result.suspected_honeypot:
        console.print("[bold red]WARNING: Suspected honeypot![/bold red]")


@app.command("vulnscan")
def vulnscan(
    engagement_id: str = typer.Option(..., "--engagement-id", "-e"),
    target:        str = typer.Option(..., "--target",        "-t"),
    cve_cache:     str = typer.Option("data/cve_cache", "--cve-cache"),
):
    """Run vulnerability scan against a target."""
    from aiptt.discovery.vuln_scanner import VulnerabilityScanner
    from aiptt.audit.logger import get_audit_logger

    audit = get_audit_logger()
    audit.log_intent("SCAN_VULNSCAN_START", engagement=engagement_id, target=target)

    scanner = VulnerabilityScanner(cve_cache_dir=cve_cache)
    result  = scanner.scan(target)

    table = Table(title=f"Vulnerabilities: {target}")
    table.add_column("CVE",         style="red")
    table.add_column("CVSS",        style="yellow")
    table.add_column("Port",        style="cyan")
    table.add_column("Description", style="white")

    for vuln in result.vulnerabilities:
        table.add_row(
            vuln.cve_id or "N/A",
            str(vuln.cvss_score or ""),
            str(vuln.port or ""),
            (vuln.description or "")[:80],
        )

    console.print(table)
    if not result.scan_complete:
        console.print("[yellow]NOTE: Scan incomplete — host may be unreachable.[/yellow]")


@app.command("ad-map")
def ad_map(
    engagement_id: str = typer.Option(..., "--engagement-id", "-e"),
    dc_ip:         str = typer.Option(..., "--dc-ip"),
    domain:        str = typer.Option(..., "--domain"),
    username:      str = typer.Option(..., "--username"),
    password:      str = typer.Option("",  "--password"),
    nt_hash:       str = typer.Option("",  "--nt-hash"),
):
    """Enumerate Active Directory topology."""
    from aiptt.discovery.ad_mapper import ADMapper
    from aiptt.audit.logger import get_audit_logger

    audit = get_audit_logger()
    audit.log_intent("SCAN_AD_MAP_START", engagement=engagement_id, dc_ip=dc_ip, domain=domain)

    mapper = ADMapper()
    result = mapper.enumerate(
        dc_ip=dc_ip, domain=domain,
        username=username, password=password, nt_hash=nt_hash,
    )

    console.print(f"\n[bold]Domain Controllers:[/bold] {', '.join(result.domain_controllers)}")
    console.print(f"[bold]Computers:[/bold] {len(result.computers)}")
    console.print(f"[bold]Users:[/bold] {len(result.users)}")
    console.print(f"[bold]Kerberoastable SPNs:[/bold] {len(result.kerberoastable_accounts)}")
    console.print(f"[bold]ASREP accounts:[/bold] {len(result.asrep_accounts)}")
    console.print(f"[bold]Domain Trusts:[/bold] {len(result.domain_trusts)}")

    if result.kerberoastable_accounts:
        console.print(f"\n[yellow]Kerberoastable accounts:[/yellow]")
        for acct in result.kerberoastable_accounts[:10]:
            console.print(f"  - {acct}")
