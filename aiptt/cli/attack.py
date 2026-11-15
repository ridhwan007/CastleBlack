"""
Attack execution commands.

  aiptt attack run    — start/stream the OPAV autonomous loop
  aiptt attack plan   — dry-run: show Claude's ranked attack queue
  aiptt attack exec   — execute a single module manually
  aiptt attack lateral — trigger lateral movement from a compromised host
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.spinner import Spinner
from rich.columns import Columns

app     = typer.Typer(help="Attack execution commands.")
console = Console()


def _wire_progress_events(bus, console: Console) -> None:
    """Subscribe to EventBus and print real-time step-by-step progress."""

    def _ts() -> str:
        return datetime.now().strftime("%H:%M:%S")

    def on_observe(cycle, target_count, targets, **_):
        console.print(
            f"[dim]{_ts()}[/dim]  [cyan]◉ OBSERVE[/cyan]  "
            f"Cycle {cycle} — {target_count} target(s): [bold]{', '.join(targets)}[/bold]"
        )

    def on_plan_start(cycle, target_count, **_):
        console.print(
            f"[dim]{_ts()}[/dim]  [yellow]⟳ PLAN[/yellow]    "
            f"Cycle {cycle} — asking Claude to plan attacks against {target_count} target(s)… "
            f"[dim](this takes ~30–60s)[/dim]"
        )

    def on_plan_complete(cycle, task_count, tasks, **_):
        console.print(
            f"[dim]{_ts()}[/dim]  [yellow]✓ PLAN[/yellow]    "
            f"Claude queued {task_count} task(s):"
        )
        for t in tasks:
            console.print(
                f"           [dim]│[/dim]  [{t['id']}] [bold]{t['module']}[/bold] → "
                f"{t['target']}  technique={t['technique']}  priority={t['priority']}"
            )

    def on_task_start(cycle, task_id, module, target, technique, priority, **_):
        console.print(
            f"[dim]{_ts()}[/dim]  [blue]▶ ACT[/blue]     "
            f"[{task_id}] [bold]{module}[/bold] → [bold]{target}[/bold]  "
            f"[dim]({technique}, priority={priority})[/dim]"
        )

    def on_exec_start(cycle, task_id, module, target, **_):
        console.print(
            f"[dim]{_ts()}[/dim]  [blue]  ⚙ EXEC[/blue]   "
            f"[{task_id}] Running {module} against {target}…"
        )

    def on_exec_complete(cycle, task_id, outcome, success, elapsed, **_):
        colour = "green" if success else "red"
        icon   = "✓" if success else "✗"
        console.print(
            f"[dim]{_ts()}[/dim]  [{colour}]  {icon} EXEC[/{colour}]   "
            f"[{task_id}] outcome=[bold]{outcome}[/bold]  [{elapsed}s]"
        )

    def on_validate_start(cycle, task_id, success, **_):
        console.print(
            f"[dim]{_ts()}[/dim]  [magenta]◎ VALIDATE[/magenta] "
            f"[{task_id}] {'capturing PoE artefact…' if success else 'recording failure…'}"
        )

    def on_poe_capture(task_id, **_):
        console.print(
            f"[dim]{_ts()}[/dim]  [magenta]  ⬇ POE[/magenta]    "
            f"[{task_id}] Encrypting artefact → vault…"
        )

    def on_finding(finding_id, severity, **_):
        colour = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                  "LOW": "blue", "INFO": "dim"}.get(severity, "white")
        console.print(
            f"[dim]{_ts()}[/dim]  [{colour}]★ FINDING  {severity}[/{colour}]  "
            f"id={finding_id}"
        )

    def on_zero_subtasks(cycle, **_):
        console.print(
            f"[dim]{_ts()}[/dim]  [red]⚠ HALT[/red]    "
            f"Cycle {cycle}: no tasks generated — scope exhausted or planner error."
        )

    def on_root_no_ad(target, access_level, **_):
        console.print(
            f"[dim]{_ts()}[/dim]  [green bold]✓ ROOT GAINED[/green bold]  "
            f"{target} — access=[bold]{access_level}[/bold]  "
            f"[dim]No AD surface detected — lateral movement not needed. "
            f"Host marked exhausted.[/dim]"
        )

    bus.subscribe("observe_complete",    on_observe)
    bus.subscribe("plan_start",          on_plan_start)
    bus.subscribe("plan_complete",       on_plan_complete)
    bus.subscribe("task_start",          on_task_start)
    bus.subscribe("exec_start",          on_exec_start)
    bus.subscribe("exec_complete",       on_exec_complete)
    bus.subscribe("validate_start",      on_validate_start)
    bus.subscribe("poe_capture_start",   on_poe_capture)
    bus.subscribe("finding_confirmed",   on_finding)
    bus.subscribe("finding_unconfirmed", on_finding)
    bus.subscribe("zero_subtasks",       on_zero_subtasks)
    bus.subscribe("root_gained_no_ad",   on_root_no_ad)

    def on_post_ex_skipped(task_id, module, target, **_):
        console.print(
            f"[dim]{_ts()}[/dim]  [dim]  ⊘ GATE[/dim]     "
            f"[{task_id}] [dim]{module} skipped — no access to {target} yet[/dim]"
        )
    bus.subscribe("post_ex_skipped", on_post_ex_skipped)


def _show_vuln_selector(observations: list[dict]) -> list[dict]:
    """Display all vulnerabilities in a table and let user select which to target.

    `observations` is a list of host dicts, each with a nested `vulnerabilities` list
    (as populated by engage_nessus.py). Returns a filtered host list where each host
    only contains the user-selected vulnerabilities (hosts with no selected vulns are
    dropped entirely).
    """
    from rich.prompt import Prompt

    # ── Flatten host→vuln structure into per-row tuples ───────────────
    # row_num → (host_obs, vuln_dict)
    flat_rows: list[tuple[int, dict, dict]] = []  # (num, host_obs, vuln)
    for host_obs in observations:
        ip      = host_obs.get("ip", "?")
        vulns   = host_obs.get("vulnerabilities", [])
        if vulns:
            for v in vulns:
                num = len(flat_rows) + 1
                flat_rows.append((num, host_obs, v))
        else:
            # Host with no individual vulns — show as a single info row
            num = len(flat_rows) + 1
            flat_rows.append((num, host_obs, {}))

    if not flat_rows:
        console.print("[yellow]No vulnerabilities found in Nessus file.[/yellow]")
        return observations

    # ── Build Rich table ──────────────────────────────────────────────
    table = Table(
        title="[bold cyan]Vulnerabilities discovered (Nessus)[/bold cyan]",
        show_lines=False,
        header_style="bold white on dark_blue",
        border_style="cyan",
    )
    table.add_column("#",            style="dim",    width=5,  justify="right")
    table.add_column("IP",           style="cyan",   width=15)
    table.add_column("Port",         style="white",  width=6,  justify="right")
    table.add_column("Service",      style="yellow", width=12)
    table.add_column("CVE / Plugin", style="green",  width=22)
    table.add_column("CVSS",         style="white",  width=6,  justify="right")
    table.add_column("Severity",     width=10)
    table.add_column("Description",  style="dim",    no_wrap=False)

    for num, host_obs, vuln in flat_rows:
        ip      = host_obs.get("ip", "?")
        port    = str(vuln.get("port", "")) or "—"
        svc     = vuln.get("service", "") or "—"
        cve     = vuln.get("cve", "") or "—"
        cvss_f  = float(vuln.get("cvss", 0.0) or 0.0)
        desc    = (vuln.get("description", "") or host_obs.get("os", "No details"))[:70]
        sev_raw = vuln.get("severity", "")
        if not sev_raw:
            sev_raw = "CRITICAL" if cvss_f >= 9.0 else "HIGH" if cvss_f >= 7.0 else \
                      "MEDIUM" if cvss_f >= 4.0 else "LOW" if cvss_f > 0 else "INFO"

        colour  = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                   "LOW": "blue"}.get(sev_raw.upper(), "dim")
        sev_str = f"[{colour}]{sev_raw}[/{colour}]"

        table.add_row(str(num), ip, port, svc, cve, f"{cvss_f:.1f}", sev_str, desc)

    console.print(table)
    unique_ips = {host_obs.get("ip") for _, host_obs, _ in flat_rows}
    console.print(
        f"\n[bold]{len(flat_rows)} finding(s) across "
        f"{len(unique_ips)} host(s)[/bold]\n"
    )

    # ── Selection prompt loop ─────────────────────────────────────────
    while True:
        raw = Prompt.ask(
            "[cyan]Select targets to exploit[/cyan] "
            "[dim](e.g. 1,3,5-8  |  all  |  host:10.0.0.1)[/dim]",
            default="all",
        ).strip()

        if raw.lower() == "all":
            console.print(f"[green]✓ All {len(flat_rows)} findings selected.[/green]\n")
            return observations

        # host: filter — return all vulns for that IP
        if raw.lower().startswith("host:"):
            target_ip = raw.split(":", 1)[1].strip()
            matched = [h for h in observations if h.get("ip") == target_ip]
            if not matched:
                console.print(f"[red]No host {target_ip} found. Try again.[/red]")
                continue
            count = sum(len(h.get("vulnerabilities", [])) or 1 for h in matched)
            console.print(f"[green]✓ {count} finding(s) for {target_ip} selected.[/green]\n")
            return matched

        # Number / range parsing → select specific vuln rows
        selected_nums: set[int] = set()
        try:
            for part in raw.split(","):
                part = part.strip()
                if "-" in part:
                    lo, hi = part.split("-", 1)
                    selected_nums.update(range(int(lo), int(hi) + 1))
                else:
                    selected_nums.add(int(part))
        except ValueError:
            console.print("[red]Invalid input. Use: 1,3,5-8  or  all  or  host:IP[/red]")
            continue

        valid_nums = {n for n in selected_nums if 1 <= n <= len(flat_rows)}
        if not valid_nums:
            console.print(f"[red]Numbers must be 1–{len(flat_rows)}. Try again.[/red]")
            continue

        # Rebuild host observations keeping only selected vulns
        # Group selected vulns by host IP
        selected_vulns_by_ip: dict[str, list[dict]] = {}
        for num, host_obs, vuln in flat_rows:
            if num in valid_nums:
                ip = host_obs.get("ip", "?")
                selected_vulns_by_ip.setdefault(ip, [])
                if vuln:
                    selected_vulns_by_ip[ip].append(vuln)

        # Rebuild host list with filtered vuln sub-lists
        filtered_hosts: list[dict] = []
        for host_obs in observations:
            ip = host_obs.get("ip", "?")
            if ip in selected_vulns_by_ip:
                filtered_hosts.append({
                    **host_obs,
                    "vulnerabilities": selected_vulns_by_ip[ip],
                })

        total_vulns = sum(len(h.get("vulnerabilities", [])) for h in filtered_hosts)
        console.print(
            f"[green]✓ {total_vulns} finding(s) across "
            f"{len(filtered_hosts)} host(s) selected.[/green]\n"
        )
        return filtered_hosts


@app.command("run")
def run(
    engagement_id: str  = typer.Option(..., "--engagement-id", "-e"),
    max_cycles:    int  = typer.Option(10,  "--max-cycles",    help="Max OPAV cycles"),
    max_pivots:    int  = typer.Option(3,   "--max-pivots"),
    nessus_file:   Optional[str] = typer.Option(None, "--nessus-file", "-f",
                                                help="Override: parse this .nessus file instead of live scanning."),
    no_sandbox:    bool = typer.Option(False, "--no-sandbox",
                                       help="Run generated exploits directly without Docker (dev/test only)."),
    interactive:   bool = typer.Option(False, "--interactive", "-i",
                                       help="Show all vulnerabilities and let you choose which to exploit."),
    save_html:     Optional[str] = typer.Option(None, "--save-html",
                                       help="Save a full-colour HTML transcript of the run to this path."),
    verbose:       bool = typer.Option(False, "--verbose", "-v"),
):
    """Start the autonomous OPAV attack loop."""
    import tomllib
    from pathlib import Path as _Path

    from aiptt.storage.db import init_db, get_session_factory
    from aiptt.storage.models import Engagement
    from aiptt.core.state_manager import SessionState, EngagementConfig
    from aiptt.core.opav_loop import OPAVLoop
    from aiptt.audit.logger import get_audit_logger

    init_db()
    session_factory = get_session_factory()
    audit = get_audit_logger()

    # ── Load engagement record ─────────────────────────────────────────
    with session_factory() as session:
        eng = session.query(Engagement).filter(Engagement.id == engagement_id).first()
        if not eng:
            console.print(f"[red]Engagement not found:[/red] {engagement_id}")
            raise typer.Exit(1)

    # ── Load engagement.toml for full config ──────────────────────────
    toml_path = _Path(f"./engagements/{engagement_id}/engagement.toml")
    toml_cfg: dict = {}
    if toml_path.exists():
        with open(toml_path, "rb") as _f:
            toml_cfg = tomllib.load(_f)

    mode           = toml_cfg.get("mode", "live")
    effective_cidr = toml_cfg.get("cidr", eng.cidr or "")
    blast_radius   = toml_cfg.get("blast_radius", "conservative")
    out_dir        = _Path(toml_cfg.get("output_dir", f"./engagements/{engagement_id}"))

    # CLI --nessus-file overrides toml
    nessus_source: Optional[str] = nessus_file or toml_cfg.get("nessus_file")
    if nessus_source:
        mode = "nessus"

    # ── Build EngagementConfig ─────────────────────────────────────────
    cfg = EngagementConfig(
        engagement_id=engagement_id,
        name=eng.name,
        cidr=effective_cidr,
        roe_path=_Path(toml_cfg.get("roe", "roe.pdf")),
        blast_radius=blast_radius,
        time_limit_hrs=toml_cfg.get("time_limit_hrs", 8),
        output_dir=out_dir,
        nessus_file=_Path(nessus_source) if nessus_source else None,
    )

    state = SessionState(cfg)

    # ── Knowledge graph (optional — skip gracefully if Neo4j not running) ──
    kg = None
    try:
        import os as _os
        from aiptt.graph.knowledge_graph import KnowledgeGraph
        from aiptt.core.config import get_config as _get_cfg
        kgcfg = _get_cfg()
        neo4j_password = _os.environ.get(kgcfg.neo4j.password_env, "")
        if not neo4j_password:
            raise ValueError(f"env var {kgcfg.neo4j.password_env} not set")
        kg = KnowledgeGraph(
            uri=kgcfg.neo4j.uri,
            user=kgcfg.neo4j.user,
            password=neo4j_password,
        )
        state.knowledge_graph = kg
    except Exception as kg_err:
        console.print(f"[yellow]⚠ Neo4j unavailable ({kg_err}) — running without knowledge graph.[/yellow]")

    console.print(Panel(
        f"[bold cyan]Starting OPAV loop[/bold cyan]\n"
        f"Engagement: [cyan]{engagement_id}[/cyan]  |  Mode: [bold]{mode}[/bold]  |  Max cycles: {max_cycles}",
        expand=False,
    ))

    # ── Nessus bootstrap (replaces live scan) ─────────────────────────
    nessus_context: dict = {}
    if mode == "nessus":
        if not nessus_source:
            console.print("[red]ERROR:[/red] Nessus mode but no --nessus-file provided or saved in engagement.toml.")
            raise typer.Exit(1)

        from aiptt.core.engage_nessus import NessusEngagementBootstrap
        bootstrap  = NessusEngagementBootstrap(audit=audit, config=cfg)
        nessus_result = bootstrap.prepare(
            nessus_file=nessus_source,
            state=state,
            kg=kg,
        )
        nessus_context = nessus_result.summary_dict()

    # ── Interactive vuln selection ─────────────────────────────────────
    # Save the COMPLETE Nessus vuln list before any narrowing happens.
    # The remaining-vulns picker always references this full list so the
    # user can pick any of the original 67 (minus already-attempted ones).
    all_nessus_observations: list[dict] = (
        [
            {**h, "vulnerabilities": list(h.get("vulnerabilities", []))}
            for h in state.nessus_observations
        ]
        if interactive and state.nessus_observations
        else []
    )

    if interactive and state.nessus_observations:
        filtered_hosts = _show_vuln_selector(state.nessus_observations)
        state.nessus_observations = filtered_hosts
        # Rebuild the planner context to only include selected hosts/vulns
        total_selected_vulns = sum(
            len(h.get("vulnerabilities", [])) for h in filtered_hosts
        )
        nessus_context["top_targets"] = [
            {
                "ip": h["ip"],
                "hostname": h.get("hostname", ""),
                "os": h.get("os", ""),
                "max_cvss": max(
                    (v.get("cvss", 0.0) or 0.0 for v in h.get("vulnerabilities", [])),
                    default=0.0,
                ),
                "exploit_available": h.get("exploit_available", False),
                "ad_surface": h.get("ad_surface", False),
                "top_vulns": h.get("vulnerabilities", [])[:10],
            }
            for h in filtered_hosts
        ]
        nessus_context["in_scope_hosts"] = len(filtered_hosts)
        nessus_context["vulnerability_count"] = total_selected_vulns
        console.print(
            f"[dim]Proceeding with {total_selected_vulns} selected finding(s) "
            f"across {len(filtered_hosts)} host(s).[/dim]\n"
        )
    elif interactive and not state.nessus_observations:
        console.print(
            "[yellow]⚠  --interactive requires a Nessus file (no vulnerabilities loaded). "
            "Continuing without selection.[/yellow]"
        )

    # ── Build planner + loop ───────────────────────────────────────────
    from aiptt.engine.ai_planner import AIPlannerEngine
    from aiptt.engine.path_scorer import PathScorer
    from aiptt.engine.replan_engine import ReplanEngine
    from aiptt.guardrail.controller import GuardrailController
    from aiptt.guardrail.scope_enforcer import ScopeEnforcer
    from aiptt.guardrail.blast_radius import BlastRadiusGate
    from aiptt.guardrail.rate_limiter import CredentialRateLimiter
    from aiptt.guardrail.circuit_breaker import CircuitBreaker
    from aiptt.poe.capture import PoECapture
    from aiptt.core.event_bus import EventBus
    from aiptt.attacks.registry import AttackRegistry
    from aiptt.engine.exploit_generator import ExploitGenerator

    bus       = EventBus()
    scorer    = PathScorer()
    replanner = ReplanEngine(audit=audit)
    planner   = AIPlannerEngine(audit=audit, scorer=scorer, replanner=replanner)

    # Inject Nessus scan context into the planner so Claude has full picture
    if nessus_context:
        planner.inject_scan_context(nessus_context)

    # In Nessus mode with no explicit CIDR, derive scope from the hosts in the file
    if not effective_cidr and mode == "nessus" and state.nessus_observations:
        effective_cidr = ",".join(
            f"{obs['ip']}/32" for obs in state.nessus_observations
        )
        console.print(f"[dim]  Scope auto-derived from Nessus hosts: {effective_cidr}[/dim]")

    scope_enf  = ScopeEnforcer(
        allowed_cidrs=[c.strip() for c in effective_cidr.split(",") if c.strip()] if effective_cidr else [],
        exclusions=cfg.exclusions,
    )
    blast_gate = BlastRadiusGate(blast_radius=blast_radius)
    rate_lim   = CredentialRateLimiter()
    circuit    = CircuitBreaker(audit=audit, scope_enforcer=scope_enf)

    guardrail  = GuardrailController(
        scope=scope_enf,
        blast=blast_gate,
        rate=rate_lim,
        circuit=circuit,
        audit=audit,
    )

    from aiptt.attacks.sandbox import SandboxExecutor
    from aiptt.core.config import get_config as _get_config
    sandbox     = SandboxExecutor(
        docker_socket=_get_config().sandbox.docker_socket,
        audit=audit,
    )
    if no_sandbox:
        sandbox.allow_direct_exec = True
        console.print("[yellow]⚠  --no-sandbox: exploits will run directly (dev/test mode)[/yellow]")
    exploit_gen = ExploitGenerator()
    registry    = AttackRegistry(sandbox=sandbox, blast_gate=blast_gate, audit=audit)

    from aiptt.storage.vault import ArtifactVault
    vault = ArtifactVault()
    poe   = PoECapture(vault=vault, audit=audit)

    loop = OPAVLoop(
        state=state,
        planner=planner,
        guardrail=guardrail,
        registry=registry,
        poe=poe,
        audit=audit,
        bus=bus,
        max_pivots=max_pivots,
    )

    # ── Recording console for --save-html ─────────────────────────────
    # Capture silently (file=StringIO) so output doesn't print twice.
    rec_console: Console | None = None
    if save_html:
        import io as _io
        from rich.console import Console as _RecConsole
        rec_console = _RecConsole(
            record=True,
            file=_io.StringIO(),
            force_terminal=True,   # preserve colour in the recording
        )
        _wire_progress_events(bus, rec_console)

    # ── Wire real-time progress display ───────────────────────────────
    _wire_progress_events(bus, console)

    # ── Interactive: track planned task count per cycle ────────────────
    # Picker shows AFTER all planned tasks (RCE + privesc + cred harvest)
    # complete, not after every individual task.
    _cycle_plan_sizes: dict[int, int] = {}   # cycle → planned task count
    _cycle_done:        dict[int, int] = {}   # cycle → results seen so far
    _cycle_first_ok:    dict[int, dict] = {}  # cycle → first SUCCESS snapshot

    if interactive:
        def _track_plan_size(cycle, task_count, **_):
            _cycle_plan_sizes[cycle] = task_count
        bus.subscribe("plan_complete", _track_plan_size)

    # ── Interactive vuln picker ────────────────────────────────────────
    # Tracks (ip:port:cve) strings so attempted vulns are hidden next time
    attempted_vuln_keys: set[str] = set()

    def _vuln_key(ip: str, vuln: dict) -> str:
        return f"{ip}:{vuln.get('port', 0)}:{vuln.get('cve', '')}"

    def _pick_next_vuln_interactive(result) -> bool:
        """Show remaining vuln table and prompt for next target. Returns False to stop."""
        from rich.prompt import Prompt

        # ── Build remaining vuln rows (from preserved full list) ─────
        remaining: list[tuple[int, dict, dict]] = []
        for host_obs in all_nessus_observations:
            ip = host_obs.get("ip", "?")
            for v in host_obs.get("vulnerabilities", []):
                if _vuln_key(ip, v) not in attempted_vuln_keys:
                    remaining.append((len(remaining) + 1, host_obs, v))

        if not remaining:
            console.print("[dim]No more vulnerabilities remaining in scope.[/dim]")
            return False  # nothing left → stop

        # ── Table of remaining vulns ──────────────────────────────────
        rem_table = Table(
            title="[bold cyan]Remaining vulnerabilities — pick next target[/bold cyan]",
            show_lines=False,
            header_style="bold white on dark_blue",
            border_style="cyan",
        )
        rem_table.add_column("#",            style="dim",    width=5,  justify="right")
        rem_table.add_column("IP",           style="cyan",   width=15)
        rem_table.add_column("Port",         style="white",  width=6,  justify="right")
        rem_table.add_column("Service",      style="yellow", width=12)
        rem_table.add_column("CVE / Plugin", style="green",  width=22)
        rem_table.add_column("CVSS",         style="white",  width=6,  justify="right")
        rem_table.add_column("Severity",     width=10)
        rem_table.add_column("Description",  style="dim",    no_wrap=False)

        for num, host_obs, v in remaining:
            ip     = host_obs.get("ip", "?")
            port   = str(v.get("port", "")) or "—"
            svc    = v.get("service", "") or "—"
            cve    = v.get("cve", "") or "—"
            cvss_f = float(v.get("cvss", 0.0) or 0.0)
            desc   = (v.get("description", "") or host_obs.get("os", ""))[:70]
            sev    = v.get("severity", "")
            if not sev:
                sev = ("CRITICAL" if cvss_f >= 9.0 else "HIGH" if cvss_f >= 7.0
                       else "MEDIUM" if cvss_f >= 4.0 else "LOW" if cvss_f > 0 else "INFO")
            col    = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                      "LOW": "blue"}.get(sev.upper(), "dim")
            rem_table.add_row(str(num), ip, port, svc, cve,
                              f"{cvss_f:.1f}", f"[{col}]{sev}[/{col}]", desc)

        console.print(rem_table)
        console.print(f"\n[bold]{len(remaining)} vulnerability/ies remaining[/bold]\n")

        # ── User prompt ───────────────────────────────────────────────
        raw = Prompt.ask(
            "[cyan]Select next vulnerability to exploit[/cyan]  "
            "[dim](number  or  'q' to stop)[/dim]",
            default="q",
        ).strip().lower()

        if raw in ("q", "quit", ""):
            console.print("[yellow]Stopping at user request.[/yellow]")
            return False

        try:
            num = int(raw)
            if 1 <= num <= len(remaining):
                _, chosen_host, chosen_vuln = remaining[num - 1]
                chosen_ip = chosen_host.get("ip", "?")
                # Narrow state to only this one vuln for the next OPAV cycle
                state.nessus_observations = [{
                    **chosen_host,
                    "vulnerabilities": [chosen_vuln],
                }]
                # Update planner context to match
                planner.inject_scan_context({
                    **nessus_context,
                    "top_targets": [{
                        "ip": chosen_ip,
                        "hostname": chosen_host.get("hostname", ""),
                        "os": chosen_host.get("os", ""),
                        "max_cvss": float(chosen_vuln.get("cvss", 0.0) or 0.0),
                        "exploit_available": chosen_host.get("exploit_available", False),
                        "ad_surface": chosen_host.get("ad_surface", False),
                        "top_vulns": [chosen_vuln],
                    }],
                    "in_scope_hosts": 1,
                    "vulnerability_count": 1,
                })
                # Reset visit counter so OBSERVE doesn't skip this host.
                # (gaining access increments _visited; hitting 2 would exclude it)
                if hasattr(state, "_visited"):
                    state._visited[chosen_ip] = 0
                console.print(
                    f"[dim]Next target: {chosen_ip}:{chosen_vuln.get('port', '?')} "
                    f"({chosen_vuln.get('cve', '?')}) — asking Claude to plan…[/dim]\n"
                )
                return True
        except ValueError:
            pass

        console.print("[red]Invalid input — stopping.[/red]")
        return False

    # ── Run ────────────────────────────────────────────────────────────
    all_results = []
    cycles_seen = set()
    user_quit   = False

    try:
        for result in loop.run():
            all_results.append(result)
            cycles_seen.add(result.cycle)

            # Print outcome lines for non-event-covered cases
            if result.outcome == "SKIPPED" and result.skip_reason:
                console.print(
                    f"  [yellow]  ⊘ SKIPPED[/yellow] [{result.subtask_id}] "
                    f"[dim]{result.skip_reason}[/dim]"
                )
            elif result.outcome == "FAILURE" and verbose:
                console.print(
                    f"  [red]  ✗ FAILURE[/red] [{result.subtask_id}] "
                    f"[dim]{result.elapsed_seconds:.1f}s[/dim]"
                )

            # Interactive: track results and show picker after FULL cycle completes
            # (i.e., after RCE + cred harvest + privesc tasks all finish).
            if interactive:
                c = result.cycle
                _cycle_done[c] = _cycle_done.get(c, 0) + 1

                # Snapshot first SUCCESS per cycle (the initial-access task)
                if result.outcome == "SUCCESS" and c not in _cycle_first_ok:
                    _snap_obs = state.nessus_observations[0] if state.nessus_observations else {}
                    _snap_v   = (_snap_obs.get("vulnerabilities") or [{}])[0]
                    _cycle_first_ok[c] = {
                        "result": result,
                        "obs":    dict(_snap_obs),
                        "vuln":   dict(_snap_v),
                        "ip":     _snap_obs.get("ip", "?"),
                    }

                # Trigger only when all planned tasks for this cycle have yielded
                _planned = _cycle_plan_sizes.get(c, 0)
                _done    = _cycle_done.get(c, 0)
                if _planned > 0 and _done >= _planned:
                    _snp = _cycle_first_ok.get(c)
                    if _snp:
                        # At least one SUCCESS — show success narrative
                        _sv, _so, _sr, _s_ip = (
                            _snp["vuln"], _snp["obs"], _snp["result"], _snp["ip"]
                        )
                        _ad_str = (
                            "[yellow]Yes — lateral movement may be possible[/yellow]"
                            if _so.get("ad_surface") else
                            "[green]No — host fully compromised, no lateral movement needed[/green]"
                        )
                        console.print(
                            f"\n[bold green]━━ Cycle {c} Summary ━━[/bold green]\n"
                            f"  [bold]Exploited:[/bold] {_sv.get('cve','?')} — "
                            f"{(_sv.get('description') or _sv.get('cve','?'))[:60]}\n"
                            f"  [bold]Target:[/bold]    {_s_ip}:{_sv.get('port','?')}"
                            f"  ({_sv.get('service','') or 'unknown'})\n"
                            f"  [bold]OS:[/bold]        {_so.get('os','Unknown OS')}\n"
                            f"  [bold]AD Surface:[/bold] {_ad_str}\n"
                            f"  [bold]Post-exploitation:[/bold] {_done - 1} follow-up task(s) ran"
                            + (f"  |  finding_id={_sr.finding_id}" if _sr.finding_id else "") + "\n"
                        )
                        attempted_vuln_keys.add(_vuln_key(_s_ip, _sv))
                    else:
                        # No successes — failure summary
                        _cur_obs = state.nessus_observations[0] if state.nessus_observations else {}
                        _cur_v   = (_cur_obs.get("vulnerabilities") or [{}])[0]
                        _cur_ip  = _cur_obs.get("ip", "?")
                        console.print(
                            f"\n[bold yellow]━━ Cycle {c} Summary ━━[/bold yellow]\n"
                            f"  [bold]Attempted:[/bold] {_cur_v.get('cve','?')} on "
                            f"{_cur_ip}:{_cur_v.get('port','?')}\n"
                            f"  [bold]Result:[/bold]    [yellow bold]No access gained[/yellow bold]"
                            f" — {_done} task(s) tried\n"
                        )
                        attempted_vuln_keys.add(_vuln_key(_cur_ip, _cur_v))

                    should_continue = _pick_next_vuln_interactive(result)
                    if not should_continue:
                        user_quit = True
                        break

            # max_cycles limits OPAV cycles, not individual task yields
            if not user_quit and len(cycles_seen) >= max_cycles:
                console.print(f"[dim]Max cycles ({max_cycles}) reached.[/dim]")
                break

    except KeyboardInterrupt:
        console.print("\n[yellow]Loop interrupted by user.[/yellow]")

    success_count = sum(1 for r in all_results if r.outcome == "SUCCESS")
    skipped_count = sum(1 for r in all_results if r.outcome == "SKIPPED")
    console.print(
        f"\n[bold]Run complete.[/bold] {len(all_results)} subtasks executed "
        f"([green]{success_count} success[/green], [red]{skipped_count} skipped[/red]) "
        f"across {len(cycles_seen)} cycle(s)."
    )

    # ── Save HTML transcript ───────────────────────────────────────────
    if save_html and rec_console:
        html_path = _Path(save_html)
        rec_console.save_html(str(html_path))
        console.print(f"[dim]HTML transcript saved → {html_path.resolve()}[/dim]")


@app.command("plan")
def plan(
    engagement_id: str = typer.Option(..., "--engagement-id", "-e"),
    target:        str = typer.Option(..., "--target",         "-t", help="Target IP"),
    vulnerabilities: str = typer.Option("", "--vulns", help="Comma-separated CVE list"),
):
    """Dry-run: ask Claude to generate a ranked attack plan."""
    from aiptt.engine.ai_planner import AIPlannerEngine
    from aiptt.engine.path_scorer import PathScorer
    from aiptt.engine.replan_engine import ReplanEngine
    from aiptt.audit.logger import get_audit_logger
    from aiptt.utils.display import build_attack_queue_table

    audit    = get_audit_logger()
    scorer   = PathScorer()
    replanner = ReplanEngine()
    planner  = AIPlannerEngine(audit=audit, scorer=scorer, replanner=replanner)

    vuln_list = [v.strip() for v in vulnerabilities.split(",") if v.strip()]

    context = {
        "target":          target,
        "engagement_id":   engagement_id,
        "vulnerabilities": vuln_list,
        "compromised":     [],
    }

    console.print(f"[cyan]Asking Claude for attack plan...[/cyan]")

    tasks = planner.score_and_queue(context)

    table = build_attack_queue_table(tasks)
    console.print(table)
    console.print(f"\n[dim](Dry-run — no attacks executed)[/dim]")


@app.command("exec")
def exec_module(
    engagement_id: str = typer.Option(..., "--engagement-id", "-e"),
    module:        str = typer.Option(..., "--module",         "-m", help="Module ID (e.g. AD-KERB-001)"),
    target:        str = typer.Option(..., "--target",         "-t"),
    params:        str = typer.Option("{}","--params",              help="JSON params string"),
):
    """Execute a single attack module manually."""
    import json as _json
    from aiptt.attacks.registry import AttackRegistry
    from aiptt.audit.logger import get_audit_logger
    from aiptt.engine.exploit_generator import ExploitGenerator

    audit    = get_audit_logger()
    gen      = ExploitGenerator()
    registry = AttackRegistry(exploit_generator=gen, audit=audit)

    try:
        parameters = _json.loads(params)
    except _json.JSONDecodeError:
        console.print("[red]ERROR:[/red] --params must be valid JSON")
        raise typer.Exit(1)

    class _ManualTask:
        id          = "MANUAL-001"
        module_id   = module
        target      = target
        technique   = ""
        parameters  = parameters
        destructive = False

    audit.log_intent("MANUAL_EXEC", engagement=engagement_id, module=module, target=target)
    console.print(f"[cyan]Executing[/cyan] {module} → {target}")

    result = registry.execute(_ManualTask())

    if result.success:
        console.print(f"[green]SUCCESS[/green] — CVSS {result.cvss_score}")
    else:
        console.print(f"[red]FAILED[/red] — {result.error or 'no details'}")

    if result.output:
        console.print(Panel(result.output[:1000], title="Output", expand=False))


@app.command("lateral")
def lateral(
    engagement_id:  str = typer.Option(..., "--engagement-id", "-e"),
    source:         str = typer.Option(..., "--source",         help="Source (compromised) host IP"),
    destination:    str = typer.Option(..., "--destination",    help="Target host IP"),
    username:       str = typer.Option(..., "--username"),
    nt_hash:        str = typer.Option("", "--nt-hash"),
    password:       str = typer.Option("", "--password"),
):
    """Attempt lateral movement from a compromised host."""
    from aiptt.attacks.lateral.movement import LateralMovementEngine
    from aiptt.audit.logger import get_audit_logger

    audit = get_audit_logger()
    audit.log_intent("LATERAL_MOVEMENT",
                     engagement=engagement_id, source=source, destination=destination)

    engine = LateralMovementEngine(audit=audit)
    result = engine.move(
        source=source, destination=destination,
        username=username, nt_hash=nt_hash, password=password,
    )

    if result.success:
        console.print(f"[green]Lateral movement succeeded[/green] → {destination}")
    else:
        console.print(f"[red]Lateral movement failed[/red]: {result.error}")
