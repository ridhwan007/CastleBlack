"""
Heuristic-based honeypot detector.

FR-DISC-02 edge case: Hosts suspected to be honeypots are flagged,
not exploited, and logged as informational findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HoneypotEvaluation:
    suspected: bool
    confidence: float           # 0.0 – 1.0
    indicators: list[str] = field(default_factory=list)


class HoneypotDetector:
    """
    Heuristic scoring against fingerprint data.

    Checks:
      - Known honeypot strings in service banners
      - Suspicious service combinations (all remote-access protocols open)
      - Abnormally high open port count (>50)
      - OS/service version contradictions

    Threshold: suspected = True when cumulative score >= 0.5
    """

    SUSPICIOUS_SERVICE_COMBOS = [
        frozenset({"ssh", "telnet", "rlogin"}),
        frozenset({"http", "ftp", "smtp", "imap", "pop3"}),
        frozenset({"ssh", "telnet", "ftp", "http", "smtp"}),
    ]

    HONEYPOT_BANNER_STRINGS = [
        "kippo", "cowrie", "honeyd", "opencanary",
        "artillery", "glutton", "dionaea", "honeytrap",
        "glastopf", "conpot", "honeypot",
    ]

    def evaluate(self, fingerprint: dict) -> HoneypotEvaluation:
        """
        Evaluate a host fingerprint dict (from ServiceFingerprinter).

        Expected keys: services (list[dict]), os_guess (str)
        """
        indicators: list[str] = []
        score = 0.0

        services      = fingerprint.get("services", [])
        service_names = {s.get("name", "").lower() for s in services}
        banners = " ".join(
            (s.get("extrainfo", "") + " " + s.get("product", "") +
             " " + s.get("version", ""))
            for s in services
        ).lower()

        # 1. Known honeypot strings in banners
        for hp_str in self.HONEYPOT_BANNER_STRINGS:
            if hp_str in banners:
                indicators.append(f"Known honeypot string in banner: '{hp_str}'")
                score += 0.6

        # 2. Suspicious service combinations
        for combo in self.SUSPICIOUS_SERVICE_COMBOS:
            if combo.issubset(service_names):
                indicators.append(f"Suspicious service combination: {sorted(combo)}")
                score += 0.4

        # 3. Abnormally high open port count
        if len(services) > 50:
            indicators.append(
                f"Abnormally high open port count: {len(services)} (threshold: 50)")
            score += 0.3

        # 4. OS/service contradiction
        os_guess = fingerprint.get("os_guess", "").lower()
        if "windows" in os_guess:
            linux_services = {"rlogin", "rsh", "nfs"}
            if linux_services & service_names:
                indicators.append(
                    f"OS/service contradiction: Windows OS with Linux-only services "
                    f"{linux_services & service_names}"
                )
                score += 0.3

        return HoneypotEvaluation(
            suspected=score >= 0.5,
            confidence=min(score, 1.0),
            indicators=indicators,
        )
