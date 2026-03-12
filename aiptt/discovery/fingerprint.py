"""
OS and service fingerprinter.

FR-DISC-02: OS detection, service version banners, and honeypot evaluation.
All results pass through HoneypotDetector before being returned.
"""

from __future__ import annotations

from aiptt.discovery.honeypot_detector import HoneypotDetector


class ServiceFingerprinter:
    """
    Fingerprints a single host using nmap -sV -O -sC.
    Returns a dict that is fed into the knowledge graph and AI planner.

    Edge case: If host is suspected honeypot, sets suspected_honeypot=True
    and logs it — the host is then excluded from automatic exploitation.
    """

    def __init__(self, audit, honeypot_detector: HoneypotDetector | None = None):
        self.audit             = audit
        self.honeypot_detector = honeypot_detector or HoneypotDetector()
        try:
            import nmap
            self.nm = nmap.PortScanner()
        except ImportError:
            self.nm = None

    def fingerprint(self, ip: str) -> dict:
        """Run full fingerprint scan and return structured result dict."""
        self.audit.log_intent("FINGERPRINT_START", ip=ip)

        if self.nm is None:
            self.audit.log_event("FINGERPRINT_ERROR",
                                  error="python-nmap not installed", ip=ip)
            return {"ip": ip, "os_guess": "Unknown", "services": [],
                    "suspected_honeypot": False}

        try:
            self.nm.scan(ip, arguments="-sV -O -sC --version-intensity 7 -T3")
        except Exception as e:
            self.audit.log_event("FINGERPRINT_SCAN_ERROR", ip=ip, error=str(e))
            return {"ip": ip, "os_guess": "Unknown", "services": [],
                    "suspected_honeypot": False}

        result = {
            "ip":                ip,
            "os_guess":          self._get_os(ip),
            "services":          self._get_services(ip),
            "suspected_honeypot": False,
        }

        # Honeypot evaluation
        hp = self.honeypot_detector.evaluate(result)
        if hp.suspected:
            result["suspected_honeypot"] = True
            self.audit.log_event(
                "HONEYPOT_SUSPECTED",
                ip=ip,
                confidence=hp.confidence,
                indicators=hp.indicators,
            )

        self.audit.log_event("FINGERPRINT_COMPLETE", ip=ip,
                              services=len(result["services"]),
                              honeypot=result["suspected_honeypot"])
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_os(self, ip: str) -> str:
        try:
            matches = self.nm[ip]["osmatch"]
            return matches[0]["name"] if matches else "Unknown"
        except (KeyError, IndexError):
            return "Unknown"

    def _get_services(self, ip: str) -> list[dict]:
        services = []
        try:
            for proto in self.nm[ip].all_protocols():
                for port in self.nm[ip][proto].keys():
                    svc = self.nm[ip][proto][port]
                    services.append({
                        "port":      port,
                        "proto":     proto,
                        "state":     svc.get("state", ""),
                        "name":      svc.get("name", ""),
                        "version":   svc.get("version", ""),
                        "product":   svc.get("product", ""),
                        "extrainfo": svc.get("extrainfo", ""),
                        "cpe":       svc.get("cpe", ""),
                    })
        except KeyError:
            pass
        return services
