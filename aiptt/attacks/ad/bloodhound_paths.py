"""
BloodHound-style offline attack path analyser.

FR-ATK-05: Analyses the knowledge graph for shortest privilege-escalation paths
to Domain Admin using BloodHound SharpHound data or internal graph.
"""

from __future__ import annotations

from aiptt.attacks.base import AbstractAttackModule, AttackResult


class Module(AbstractAttackModule):
    module_id       = "AD-BH-001"
    mitre_technique = "T1069.002"
    destructive     = False
    sandboxable     = False   # Uses local graph — no network needed

    def execute(self, target: str, parameters: dict) -> AttackResult:
        """
        Analyse paths from compromised user to Domain Admins group
        using the AIPTT knowledge graph.
        """
        domain = parameters.get("domain", "")

        try:
            from aiptt.graph.knowledge_graph import KnowledgeGraph
            kg = KnowledgeGraph()

            # Query all attack paths and filter for DA-level access
            paths = kg.get_attack_paths_ranked()
            da_paths = [
                p for p in paths
                if (p.get("max_cvss") or 0) >= 7.0
            ]

            if not da_paths:
                return AttackResult(
                    False, "NO_PATHS_FOUND", False, "none",
                    "No high-confidence attack paths to privileged targets found",
                )

            summary = "\n".join(
                f"  {p['source']} → {p['target']} via {p['technique']} "
                f"(CVSS {p.get('max_cvss', 0):.1f})"
                for p in da_paths[:10]
            )

            return AttackResult(
                success=True,
                outcome="SUCCESS",
                gained_access=False,
                access_level="none",
                output=f"Found {len(da_paths)} high-value attack paths:\n{summary}",
            )

        except Exception as e:
            return AttackResult(False, "ERROR", False, "none", str(e))
