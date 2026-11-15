"""
Attack path scorer.

FR-AI-03: Impact × feasibility scoring.
RCE against CRITICAL CVEs always floats to the top (FR-ATK-01).
"""

from __future__ import annotations


class PathScorer:
    """
    Scores attack tasks by: impact_score × feasibility_score.

    Weights:
        CVSS         40%  — vulnerability severity
        Access level 25%  — domain_admin > local_admin > user > none
        Hop count    20%  — prefer shorter paths
        Reliability  15%  — known exploit vs AI-generated novel path

    RCE override: any module with 'rce' in its ID against a CRITICAL CVE
    gets priority_score = 1.0 (forced to top of queue).
    """

    W_CVSS         = 0.40
    W_ACCESS_LEVEL = 0.25
    W_HOP_COUNT    = 0.20
    W_RELIABILITY  = 0.15

    ACCESS_SCORES = {
        "domain_admin": 1.00,
        "local_admin":  0.75,
        "user":         0.50,
        "none":         0.25,
    }

    def score(self, tasks: list, observations: list[dict]) -> list:
        """
        Score and sort tasks by priority.

        Args:
            tasks:        List of AttackTask objects
            observations: List of target dicts from KnowledgeGraph.get_unexhausted_targets()

        Returns:
            Sorted list of tasks (highest priority first).
        """
        vuln_index = self._build_vuln_index(observations)

        for task in tasks:
            key      = f"{task.target}:{task.parameters.get('port', 0)}"
            vuln     = vuln_index.get(key, {})
            cvss     = vuln.get("cvss", 5.0)
            access   = self.ACCESS_SCORES.get(
                task.parameters.get("grants_access", "none"), 0.25)
            hops     = max(1, task.parameters.get("hop_count", 1))
            reliable = 1.0 if not getattr(task, "is_novel", False) else 0.6

            task.priority_score = (
                self.W_CVSS         * (cvss / 10.0) +
                self.W_ACCESS_LEVEL * access +
                self.W_HOP_COUNT    * (1.0 / hops) +
                self.W_RELIABILITY  * reliable
            )

        # RCE override — CRITICAL CVEs always first (FR-ATK-01)
        for task in tasks:
            key  = f"{task.target}:{task.parameters.get('port', 0)}"
            vuln = vuln_index.get(key, {})
            if (vuln.get("cvss", 0) >= 9.0
                    and "rce" in getattr(task, "module_id", "").lower()):
                task.priority_score = 1.0   # Force to top

        return sorted(tasks, key=lambda t: t.priority_score, reverse=True)

    def _build_vuln_index(self, observations: list[dict]) -> dict:
        """Build {ip:port → vuln_dict} index for fast lookup."""
        index = {}
        for obs in observations:
            ip = obs.get("ip", "")
            for v in obs.get("vulnerabilities", []):
                port = v.get("port", 0)
                key  = f"{ip}:{port}"
                # Keep highest CVSS entry per ip:port
                if key not in index or v.get("cvss", 0) > index[key].get("cvss", 0):
                    index[key] = v
        return index
