"""
CVE-enriched vulnerability scanner.

FR-DISC-03: Nessus-class scan depth using nmap NSE vuln scripts + local CVE cache.
Business Rule: Scan MUST complete before attack planning begins.
Edge case: Hosts unreachable mid-scan → marked scan_complete=False and excluded
           from high-confidence scoring.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from aiptt.core.config import get_config


@dataclass
class VulnerabilityFinding:
    ip: str
    port: int
    cve_id: str
    cvss_score: float
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    description: str
    service: str
    evidence: str
    scan_complete: bool = True   # False = host unreachable mid-scan


class VulnerabilityScanner:
    """
    CVE-enriched scanner.
    Uses nmap NSE scripts + local CVE cache for offline enrichment.

    Scan timeout: if a host scan exceeds 6 hours, emits scan_timeout event.
    """

    CVE_CACHE_PATH = Path("data/cve_cache")
    NMAP_VULN_ARGS = "-sV --script vuln,exploit -T3 --script-timeout 60s"
    SCAN_TIMEOUT_HOURS = 6

    def __init__(self, audit, event_bus=None):
        self.audit     = audit
        self.bus       = event_bus
        self._cve_cache = self._load_cve_cache()
        try:
            import nmap
            self.nm = nmap.PortScanner()
        except ImportError:
            self.nm = None

    def scan_host(
        self,
        ip: str,
        ports: list[int] | None = None,
    ) -> list[VulnerabilityFinding]:
        """
        Scan a single host for vulnerabilities.
        Returns list of VulnerabilityFinding sorted CRITICAL first.
        """
        self.audit.log_intent("VULN_SCAN_START", ip=ip)

        if self.nm is None:
            self.audit.log_event("VULN_SCAN_ERROR",
                                  error="python-nmap not installed", ip=ip)
            return []

        port_arg = f"-p {','.join(map(str, ports))}" if ports else "-p-"
        findings: list[VulnerabilityFinding] = []
        start    = time.time()

        try:
            self.nm.scan(ip, arguments=f"{self.NMAP_VULN_ARGS} {port_arg}")
        except Exception as e:
            self.audit.log_event("SCAN_INCOMPLETE", ip=ip, reason=str(e))
            return [VulnerabilityFinding(
                ip=ip, port=0, cve_id="N/A", cvss_score=0.0,
                severity="INFO", description="Host unreachable during scan",
                service="N/A", evidence="", scan_complete=False,
            )]

        # Check timeout
        elapsed_hrs = (time.time() - start) / 3600
        if elapsed_hrs > self.SCAN_TIMEOUT_HOURS and self.bus:
            self.bus.emit("scan_timeout", ip=ip, elapsed_hrs=elapsed_hrs)

        # Parse NSE script output for CVEs
        try:
            for proto in self.nm[ip].all_protocols():
                for port in self.nm[ip][proto].keys():
                    svc = self.nm[ip][proto][port]
                    for script_id, output in svc.get("script", {}).items():
                        cves = self._extract_cves(output)
                        for cve in cves:
                            enriched = self._enrich_cve(cve)
                            findings.append(VulnerabilityFinding(
                                ip=ip,
                                port=port,
                                cve_id=cve,
                                cvss_score=enriched.get("cvss", 0.0),
                                severity=self._cvss_to_severity(
                                    enriched.get("cvss", 0.0)),
                                description=enriched.get("description",
                                                          output[:200]),
                                service=svc.get("name", ""),
                                evidence=output[:500],
                            ))
        except KeyError:
            pass

        # Sort: CRITICAL first (FR-ATK-01 priority)
        findings.sort(key=lambda f: f.cvss_score, reverse=True)
        self.audit.log_event("VULN_SCAN_COMPLETE", ip=ip, findings=len(findings))
        return findings

    def scan_multiple(
        self,
        hosts: list[str],
        ports: list[int] | None = None,
    ) -> dict[str, list[VulnerabilityFinding]]:
        """Scan multiple hosts; returns dict[ip → findings]."""
        results: dict[str, list[VulnerabilityFinding]] = {}
        for ip in hosts:
            results[ip] = self.scan_host(ip, ports)
        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_cves(self, text: str) -> list[str]:
        return list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))

    def _enrich_cve(self, cve_id: str) -> dict:
        """Look up CVE from local cache (offline-safe)."""
        cache_file = self.CVE_CACHE_PATH / f"{cve_id}.json"
        if cache_file.exists():
            try:
                return json.loads(cache_file.read_text())
            except json.JSONDecodeError:
                pass
        # Fallback: check in-memory manifest
        return self._cve_cache.get(cve_id, {"cvss": 5.0, "description": cve_id})

    @staticmethod
    def _cvss_to_severity(score: float) -> str:
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        if score > 0.0:  return "LOW"
        return "INFO"

    def _load_cve_cache(self) -> dict:
        manifest = self.CVE_CACHE_PATH / "manifest.json"
        if manifest.exists():
            try:
                return json.loads(manifest.read_text())
            except json.JSONDecodeError:
                pass
        return {}
