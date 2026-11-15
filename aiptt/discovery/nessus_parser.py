"""
Nessus .nessus file parser.

Replaces the live subnet scan phase entirely.
Parses a .nessus XML export from Tenable Nessus / Tenable.io / Tenable.sc
and produces the same data structures that HostSweeper + VulnerabilityScanner
+ ServiceFingerprinter would produce, feeding them directly into:
  - The knowledge graph (Neo4j)
  - The AI planner context
  - SessionState

Supports:
  - Plain .nessus (XML)
  - Gzip-compressed .nessus.gz
  - Multiple <Report> blocks in one file
  - Scope enforcement (skips out-of-scope hosts)
  - Honeypot detection on banner/service combos extracted from plugin data
  - Deduplication of duplicate CVE findings per host/port
"""

from __future__ import annotations

import gzip
import hashlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from aiptt.discovery.host_sweep import DiscoveredHost
from aiptt.discovery.vuln_scanner import VulnerabilityFinding
from aiptt.discovery.honeypot_detector import HoneypotDetector
from aiptt.graph.models import HostNode, ServiceNode, VulnerabilityNode

if TYPE_CHECKING:
    from aiptt.audit.logger import AuditLogger
    from aiptt.guardrail.scope_enforcer import ScopeEnforcer
    from aiptt.graph.knowledge_graph import KnowledgeGraph


# ---------------------------------------------------------------------------
# Nessus severity level → CVSS approximation and string
# Nessus uses 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
# ---------------------------------------------------------------------------
_NESSUS_SEVERITY_TO_STR = {
    0: "INFO",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
}

_NESSUS_SEVERITY_TO_CVSS = {
    0: 0.0,
    1: 3.0,
    2: 5.5,
    3: 7.5,
    4: 9.5,
}

# Plugin families that indicate AD / Windows attack surface
_AD_PLUGIN_FAMILIES = frozenset({
    "Windows",
    "Windows : Microsoft Bulletins",
    "Windows : User management",
    "Kerberos",
    "Active Directory",
    "SMB",
})

# Plugin IDs for well-known high-value findings (for prioritisation hints)
_HIGH_VALUE_PLUGIN_IDS = frozenset({
    "10394",   # Microsoft Windows SMB Log In Possible
    "57608",   # SMB Signing Not Required
    "42873",   # SSL Medium Strength Cipher Suites
    "65821",   # SSL RC4 Cipher Suites Supported
    "20007",   # SSL Version 2 and 3 Protocol Detection
    "34477",   # NFS Shares World Readable
    "22964",   # Service Detection (banner grab)
    "10863",   # SSL Certificate Information
    "11936",   # OS Identification
    "25220",   # TCP/IP Timestamps Supported
    "12217",   # DNS Server BIND version
    "10736",   # DCE Services Enumeration
    "10860",   # SMB Use Host SID to Enumerate Local Users
    "10395",   # Microsoft Windows SMB Shares Access
    "35703",   # Kerberos 'Clock Skew'
    "73182",   # Kerberoastable Accounts
    "19506",   # Nessus Scan Information (meta, always ignored)
})


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------

@dataclass
class NessusService:
    """A single open port/service extracted from Nessus plugin data."""
    port: int
    protocol: str
    svc_name: str
    product: str = ""
    version: str = ""
    banner: str = ""
    cpe: str = ""


@dataclass
class NessusHost:
    """All data extracted from a single <ReportHost> block."""
    ip: str
    hostname: str = ""
    fqdn: str = ""
    netbios_name: str = ""
    os_guess: str = ""
    mac_address: str = ""
    domain: str = ""

    # Risk summary
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # Flags
    suspected_honeypot: bool = False
    scope_excluded: bool = False

    # Structured sub-data
    services: list[NessusService] = field(default_factory=list)
    vulnerabilities: list[VulnerabilityFinding] = field(default_factory=list)
    ad_surface: bool = False      # True if any AD/Windows plugins fired
    exploit_available: bool = False  # True if any plugin has exploit_available=true

    @property
    def max_cvss(self) -> float:
        if not self.vulnerabilities:
            return 0.0
        return max(v.cvss_score for v in self.vulnerabilities)

    def to_discovered_host(self) -> DiscoveredHost:
        return DiscoveredHost(
            ip=self.ip,
            status="up",
            mac=self.mac_address,
            hostname=self.fqdn or self.hostname or self.netbios_name,
            suspected_honeypot=self.suspected_honeypot,
            open_ports=[s.port for s in self.services],
        )

    def to_host_node(self) -> HostNode:
        return HostNode(
            ip=self.ip,
            hostname=self.fqdn or self.hostname or self.netbios_name,
            os=self.os_guess,
            suspected_honeypot=self.suspected_honeypot,
            domain=self.domain,
        )

    def to_fingerprint_dict(self) -> dict:
        """Returns same format as ServiceFingerprinter.fingerprint()."""
        return {
            "ip": self.ip,
            "os_guess": self.os_guess,
            "suspected_honeypot": self.suspected_honeypot,
            "services": [
                {
                    "port": s.port,
                    "proto": s.protocol,
                    "state": "open",
                    "name": s.svc_name,
                    "version": s.version,
                    "product": s.product,
                    "extrainfo": s.banner,
                    "cpe": s.cpe,
                }
                for s in self.services
            ],
        }


@dataclass
class NessusScanResult:
    """Complete parsed result from one .nessus file."""
    scan_name: str
    scan_file: str
    file_sha256: str
    hosts: list[NessusHost] = field(default_factory=list)

    @property
    def total_hosts(self) -> int:
        return len(self.hosts)

    @property
    def in_scope_hosts(self) -> list[NessusHost]:
        return [h for h in self.hosts if not h.scope_excluded]

    @property
    def critical_hosts(self) -> list[NessusHost]:
        return [h for h in self.in_scope_hosts if h.critical_count > 0]

    @property
    def total_vulns(self) -> int:
        return sum(len(h.vulnerabilities) for h in self.in_scope_hosts)

    @property
    def exploit_ready_hosts(self) -> list[NessusHost]:
        """Hosts where Nessus flagged at least one public exploit exists."""
        return [h for h in self.in_scope_hosts if h.exploit_available]

    def prioritized_hosts(self) -> list[NessusHost]:
        """
        Returns in-scope hosts sorted for AI planner:
        1. Exploit-available first
        2. Then by highest CVSS
        3. Then by AD surface area
        """
        return sorted(
            self.in_scope_hosts,
            key=lambda h: (
                h.exploit_available,
                h.max_cvss,
                h.ad_surface,
                h.critical_count,
            ),
            reverse=True,
        )

    def summary_dict(self) -> dict:
        """Compact dict for AI planner context injection."""
        return {
            "scan_name": self.scan_name,
            "total_hosts": self.total_hosts,
            "in_scope_hosts": len(self.in_scope_hosts),
            "exploit_ready_hosts": len(self.exploit_ready_hosts),
            "critical_vulns": sum(h.critical_count for h in self.in_scope_hosts),
            "high_vulns": sum(h.high_count for h in self.in_scope_hosts),
            "ad_surface_hosts": sum(
                1 for h in self.in_scope_hosts if h.ad_surface
            ),
            "top_targets": [
                {
                    "ip": h.ip,
                    "hostname": h.fqdn or h.hostname,
                    "os": h.os_guess,
                    "max_cvss": h.max_cvss,
                    "critical": h.critical_count,
                    "high": h.high_count,
                    "exploit_available": h.exploit_available,
                    "ad_surface": h.ad_surface,
                    "top_vulns": [
                        {
                            "cve": v.cve_id,
                            "cvss": v.cvss_score,
                            "severity": v.severity,
                            "port": v.port,
                            "service": v.service,
                            "description": v.description[:120],
                        }
                        for v in sorted(
                            h.vulnerabilities,
                            key=lambda v: v.cvss_score,
                            reverse=True,
                        )[:5]  # top 5 per host
                    ],
                }
                for h in self.prioritized_hosts()[:20]  # top 20 for context
            ],
        }


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

class NessusParser:
    """
    Parses a .nessus XML file into structured data ready for the OPAV pipeline.

    Usage:
        parser = NessusParser(audit, scope_enforcer)
        result = parser.parse("/path/to/scan.nessus")
        parser.load_into_knowledge_graph(result, knowledge_graph)
    """

    def __init__(
        self,
        audit: "AuditLogger",
        scope_enforcer: "ScopeEnforcer | None" = None,
        honeypot_detector: HoneypotDetector | None = None,
    ):
        self.audit             = audit
        self.scope_enforcer    = scope_enforcer
        self.honeypot_detector = honeypot_detector or HoneypotDetector()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, filepath: str | Path) -> NessusScanResult:
        """
        Parse a .nessus or .nessus.gz file.
        Returns NessusScanResult with all hosts and vulnerabilities extracted.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Nessus file not found: {path}")

        self.audit.log_intent(
            "NESSUS_PARSE_START",
            file=str(path),
            size_bytes=path.stat().st_size,
        )

        # Compute file hash for audit trail / integrity
        file_hash = self._sha256_file(path)

        # Parse XML — support plain and gzip
        tree = self._load_xml(path)
        root = tree.getroot()

        # Locate <Report> element (may be direct child or under <Policy>)
        reports = root.findall(".//Report")
        scan_name = reports[0].get("name", "Unknown") if reports else "Unknown"

        result = NessusScanResult(
            scan_name=scan_name,
            scan_file=str(path.resolve()),
            file_sha256=file_hash,
        )

        total_items = 0
        for report in reports:
            for report_host in report.findall("ReportHost"):
                nessus_host = self._parse_report_host(report_host)
                result.hosts.append(nessus_host)
                total_items += len(nessus_host.vulnerabilities)

        self.audit.log_event(
            "NESSUS_PARSE_COMPLETE",
            file=str(path),
            sha256=file_hash,
            total_hosts=result.total_hosts,
            in_scope=len(result.in_scope_hosts),
            excluded=sum(1 for h in result.hosts if h.scope_excluded),
            total_vulns=result.total_vulns,
            critical_hosts=len(result.critical_hosts),
            exploit_ready=len(result.exploit_ready_hosts),
        )

        return result

    def load_into_knowledge_graph(
        self,
        result: NessusScanResult,
        kg: "KnowledgeGraph",
    ) -> None:
        """
        Bulk-load all in-scope hosts, services, and vulnerabilities
        from a parsed NessusScanResult into the Neo4j knowledge graph.

        This replaces the combined HostSweeper + VulnerabilityScanner graph
        population that would happen during a live scan.
        """
        self.audit.log_intent(
            "NESSUS_KG_LOAD_START",
            hosts=len(result.in_scope_hosts),
        )

        loaded_hosts = 0
        loaded_vulns = 0

        for nhost in result.in_scope_hosts:
            if nhost.suspected_honeypot:
                self.audit.log_event(
                    "HONEYPOT_SKIPPED_KG",
                    ip=nhost.ip,
                )
                continue

            # Upsert host node
            kg.upsert_host(nhost.to_host_node())

            # Upsert service nodes
            for svc in nhost.services:
                kg.upsert_service(ServiceNode(
                    ip=nhost.ip,
                    port=svc.port,
                    proto=svc.protocol,
                    name=svc.svc_name,
                    version=svc.version,
                    product=svc.product,
                    extrainfo=svc.banner,
                ))

            # Upsert vulnerability nodes
            for vuln in nhost.vulnerabilities:
                kg.upsert_vulnerability(VulnerabilityNode(
                    ip=nhost.ip,
                    port=vuln.port,
                    cve_id=vuln.cve_id,
                    cvss=vuln.cvss_score,
                    severity=vuln.severity,
                    description=vuln.description,
                    service=vuln.service,
                ))
                loaded_vulns += 1

            loaded_hosts += 1

        self.audit.log_event(
            "NESSUS_KG_LOAD_COMPLETE",
            loaded_hosts=loaded_hosts,
            loaded_vulns=loaded_vulns,
        )

    # ------------------------------------------------------------------
    # Internal: XML parsing
    # ------------------------------------------------------------------

    def _load_xml(self, path: Path) -> ET.ElementTree:
        """Load XML, transparently handling gzip compression."""
        try:
            if path.suffix == ".gz" or path.name.endswith(".nessus.gz"):
                with gzip.open(path, "rb") as f:
                    return ET.parse(f)
            else:
                return ET.parse(path)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid Nessus XML in {path}: {exc}") from exc

    def _parse_report_host(self, report_host: ET.Element) -> NessusHost:
        """Parse a single <ReportHost> element into a NessusHost."""
        raw_name = report_host.get("name", "")

        # Extract HostProperties tags
        props = self._extract_host_properties(report_host)
        ip       = props.get("host-ip", raw_name)
        fqdn     = props.get("host-fqdn", "")
        os_guess = props.get("operating-system", "")
        mac      = props.get("mac-address", "")
        netbios  = props.get("netbios-name", "")
        domain   = self._extract_domain(fqdn, netbios)

        nhost = NessusHost(
            ip=ip,
            hostname=raw_name,
            fqdn=fqdn,
            netbios_name=netbios,
            os_guess=os_guess,
            mac_address=mac,
            domain=domain,
        )

        # Scope check
        if self.scope_enforcer and not self.scope_enforcer.is_in_scope(ip):
            nhost.scope_excluded = True
            return nhost

        # Parse all ReportItem elements
        services_seen: dict[tuple, NessusService] = {}  # (port, proto) → service
        vulns_seen: set[str] = set()  # dedup key

        for item in report_host.findall("ReportItem"):
            self._process_report_item(item, nhost, services_seen, vulns_seen)

        # Populate services list (deduplicated)
        nhost.services = list(services_seen.values())

        # Honeypot detection using extracted fingerprint
        fingerprint = nhost.to_fingerprint_dict()
        hp = self.honeypot_detector.evaluate(fingerprint)
        if hp.suspected:
            nhost.suspected_honeypot = True
            self.audit.log_event(
                "HONEYPOT_SUSPECTED",
                ip=ip,
                confidence=hp.confidence,
                indicators=hp.indicators,
            )

        return nhost

    def _extract_host_properties(self, report_host: ET.Element) -> dict[str, str]:
        """Extract <HostProperties><tag name="..."> → dict."""
        props: dict[str, str] = {}
        hp = report_host.find("HostProperties")
        if hp is not None:
            for tag in hp.findall("tag"):
                name = tag.get("name", "")
                if name:
                    props[name] = (tag.text or "").strip()
        return props

    def _process_report_item(
        self,
        item: ET.Element,
        nhost: NessusHost,
        services_seen: dict,
        vulns_seen: set,
    ) -> None:
        """Process one <ReportItem> — extract service info and vulnerability."""
        port     = int(item.get("port", 0))
        protocol = item.get("protocol", "tcp").lower()
        svc_name = item.get("svc_name", "").lower()
        severity = int(item.get("severity", 0))
        plugin_id    = item.get("pluginID", "")
        plugin_name  = item.get("pluginName", "")
        plugin_family = item.get("pluginFamily", "")

        # Skip meta plugin (Nessus scan info)
        if plugin_id == "19506":
            return

        # ── Service extraction ────────────────────────────────────────
        if port > 0:
            svc_key = (port, protocol)
            if svc_key not in services_seen:
                services_seen[svc_key] = NessusService(
                    port=port,
                    protocol=protocol,
                    svc_name=svc_name,
                    product=self._get_text(item, "plugin_output", "")[:80],
                    version=self._get_text(item, "version", ""),
                    banner=self._get_text(item, "plugin_output", "")[:200],
                    cpe=self._get_text(item, "cpe", ""),
                )

        # ── Vulnerability extraction ──────────────────────────────────
        # Info-level plugins are still parsed but don't become VulnerabilityFindings
        description = self._get_text(item, "description", plugin_name)
        solution    = self._get_text(item, "solution", "")
        synopsis    = self._get_text(item, "synopsis", "")

        # CVSS — prefer cvss3, fall back to cvss2, fall back to severity mapping
        cvss = self._extract_cvss(item, severity)

        # CVEs — a plugin can reference multiple CVEs
        cve_ids = [el.text.strip() for el in item.findall("cve") if el.text]

        # Exploit availability flag
        exploit_avail = self._get_text(item, "exploit_available", "false").lower() == "true"
        exploit_ease  = self._get_text(item, "exploitability_ease", "")
        if exploit_avail:
            nhost.exploit_available = True

        # AD surface detection
        if plugin_family in _AD_PLUGIN_FAMILIES:
            nhost.ad_surface = True

        # Update severity counters
        self._increment_severity_counter(nhost, severity)

        # Build VulnerabilityFinding for each CVE, or one generic entry
        if cve_ids:
            for cve in cve_ids:
                dedup_key = f"{nhost.ip}:{port}:{cve}"
                if dedup_key in vulns_seen:
                    continue
                vulns_seen.add(dedup_key)

                nhost.vulnerabilities.append(VulnerabilityFinding(
                    ip=nhost.ip,
                    port=port,
                    cve_id=cve,
                    cvss_score=cvss,
                    severity=_NESSUS_SEVERITY_TO_STR.get(severity, "INFO"),
                    description=f"{synopsis}\n{description}".strip()[:500],
                    service=svc_name,
                    evidence=(
                        f"Plugin: {plugin_name} (ID: {plugin_id})\n"
                        f"Exploit: {'YES' if exploit_avail else 'No'} — {exploit_ease}\n"
                        f"Solution: {solution[:200]}"
                    ),
                    scan_complete=True,
                ))
        elif severity >= 2:
            # Medium/High/Critical with no CVE — create a plugin-ID entry
            dedup_key = f"{nhost.ip}:{port}:{plugin_id}"
            if dedup_key not in vulns_seen:
                vulns_seen.add(dedup_key)
                nhost.vulnerabilities.append(VulnerabilityFinding(
                    ip=nhost.ip,
                    port=port,
                    cve_id=f"PLUGIN-{plugin_id}",
                    cvss_score=cvss,
                    severity=_NESSUS_SEVERITY_TO_STR.get(severity, "MEDIUM"),
                    description=f"{synopsis}\n{description}".strip()[:500],
                    service=svc_name,
                    evidence=(
                        f"Plugin: {plugin_name} (ID: {plugin_id})\n"
                        f"Exploit: {'YES' if exploit_avail else 'No'} — {exploit_ease}\n"
                        f"Solution: {solution[:200]}"
                    ),
                    scan_complete=True,
                ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_text(element: ET.Element, tag: str, default: str = "") -> str:
        """Safe text extraction from a child element."""
        child = element.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default

    @staticmethod
    def _extract_cvss(item: ET.Element, nessus_severity: int) -> float:
        """Extract the best available CVSS score from a ReportItem."""
        # Prefer CVSSv3
        cvss3_el = item.find("cvss3_base_score")
        if cvss3_el is not None and cvss3_el.text:
            try:
                return float(cvss3_el.text.strip())
            except ValueError:
                pass
        # Fall back to CVSSv2
        cvss2_el = item.find("cvss_base_score")
        if cvss2_el is not None and cvss2_el.text:
            try:
                return float(cvss2_el.text.strip())
            except ValueError:
                pass
        # Fall back to Nessus severity approximation
        return _NESSUS_SEVERITY_TO_CVSS.get(nessus_severity, 0.0)

    @staticmethod
    def _increment_severity_counter(nhost: NessusHost, severity: int) -> None:
        if severity == 4:
            nhost.critical_count += 1
        elif severity == 3:
            nhost.high_count += 1
        elif severity == 2:
            nhost.medium_count += 1
        elif severity == 1:
            nhost.low_count += 1
        else:
            nhost.info_count += 1

    @staticmethod
    def _extract_domain(fqdn: str, netbios: str) -> str:
        """Best-effort domain extraction from FQDN or NetBIOS name."""
        if fqdn and "." in fqdn:
            parts = fqdn.split(".")
            if len(parts) >= 2:
                return ".".join(parts[-2:])
        return ""

    @staticmethod
    def _sha256_file(path: Path) -> str:
        """Compute SHA-256 of file for audit integrity record."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
