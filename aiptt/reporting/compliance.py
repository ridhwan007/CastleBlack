"""
Compliance Reporter.

Maps findings to control frameworks: PCI-DSS, NIS2, ISO27001, SOC2, HIPAA.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FRAMEWORK_FILES = {
    "pci_dss":  "data/compliance/pci_dss.json",
    "nis2":     "data/compliance/nis2.json",
    "iso27001": "data/compliance/iso27001.json",
    "soc2":     "data/compliance/soc2.json",
    "hipaa":    "data/compliance/hipaa.json",
}

# Fallback built-in mappings (technique → {framework: [control_ids]})
BUILTIN_MAPPINGS: dict[str, dict[str, list[str]]] = {
    "T1110.003": {
        "pci_dss":  ["8.3.6", "8.3.9"],
        "nis2":     ["Article 21(2)(i)"],
        "iso27001": ["A.9.4.3"],
        "soc2":     ["CC6.1"],
        "hipaa":    ["164.312(d)"],
    },
    "T1003.006": {
        "pci_dss":  ["7.2.1", "8.2.1"],
        "nis2":     ["Article 21(2)(e)"],
        "iso27001": ["A.9.2.3"],
        "soc2":     ["CC6.3"],
        "hipaa":    ["164.312(a)(2)(i)"],
    },
    "T1558.003": {
        "pci_dss":  ["8.3.6"],
        "nis2":     ["Article 21(2)(i)"],
        "iso27001": ["A.9.4.3"],
        "soc2":     ["CC6.1"],
        "hipaa":    ["164.312(d)"],
    },
    "T1558.004": {
        "pci_dss":  ["8.3.6"],
        "nis2":     ["Article 21(2)(i)"],
        "iso27001": ["A.9.4.3"],
        "soc2":     ["CC6.1"],
        "hipaa":    ["164.312(d)"],
    },
    "T1190": {
        "pci_dss":  ["6.3.3", "6.4.1"],
        "nis2":     ["Article 21(2)(e)"],
        "iso27001": ["A.12.6.1"],
        "soc2":     ["CC7.1"],
        "hipaa":    ["164.308(a)(5)(ii)(B)"],
    },
    "T1550.002": {
        "pci_dss":  ["8.3.2"],
        "nis2":     ["Article 21(2)(i)"],
        "iso27001": ["A.9.4.2"],
        "soc2":     ["CC6.1"],
        "hipaa":    ["164.312(d)"],
    },
    "T1134": {
        "pci_dss":  ["7.2.1", "7.2.2"],
        "nis2":     ["Article 21(2)(e)"],
        "iso27001": ["A.9.2.3"],
        "soc2":     ["CC6.3"],
        "hipaa":    ["164.312(a)(2)(i)"],
    },
}


@dataclass
class ComplianceMapping:
    framework:    str
    control_id:   str
    control_title: str
    finding_ids:  list[str] = field(default_factory=list)


@dataclass
class ComplianceReport:
    engagement_id: str
    frameworks:    list[str]
    mappings:      list[ComplianceMapping]
    markdown:      str
    generated_at:  str


class ComplianceReporter:
    """
    Maps MITRE ATT&CK techniques found in an engagement to compliance controls.
    """

    def __init__(self, data_root: str | Path = "."):
        self.data_root = Path(data_root)
        self._framework_data: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        findings: list[dict],
        engagement_id: str,
        frameworks: list[str] | None = None,
    ) -> ComplianceReport:
        frameworks = frameworks or list(FRAMEWORK_FILES.keys())
        all_mappings: list[ComplianceMapping] = []

        for finding in findings:
            technique  = finding.get("mitre_technique", "")
            finding_id = finding.get("id", "")
            if not technique:
                continue

            tech_map = BUILTIN_MAPPINGS.get(technique, {})
            for fw in frameworks:
                controls = tech_map.get(fw, [])
                for ctrl_id in controls:
                    ctrl_title = self._lookup_title(fw, ctrl_id)
                    # Merge into existing mapping if same ctrl_id+fw
                    existing = next(
                        (m for m in all_mappings
                         if m.framework == fw and m.control_id == ctrl_id), None
                    )
                    if existing:
                        existing.finding_ids.append(finding_id)
                    else:
                        all_mappings.append(ComplianceMapping(
                            framework=fw,
                            control_id=ctrl_id,
                            control_title=ctrl_title,
                            finding_ids=[finding_id],
                        ))

        markdown = self._render_markdown(
            engagement_id, frameworks, all_mappings, findings
        )

        return ComplianceReport(
            engagement_id=engagement_id,
            frameworks=frameworks,
            mappings=all_mappings,
            markdown=markdown,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def save(self, report: ComplianceReport, output_dir: str | Path) -> Path:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / f"{report.engagement_id}_compliance.md"
        path.write_text(report.markdown, encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _lookup_title(self, framework: str, control_id: str) -> str:
        """Look up a human-readable control title from the JSON data files."""
        data = self._load_framework(framework)
        return data.get(control_id, {}).get("title", control_id)

    def _load_framework(self, framework: str) -> dict:
        if framework in self._framework_data:
            return self._framework_data[framework]
        rel_path = FRAMEWORK_FILES.get(framework, "")
        full_path = self.data_root / rel_path
        if full_path.exists():
            try:
                self._framework_data[framework] = json.loads(
                    full_path.read_text(encoding="utf-8")
                )
                return self._framework_data[framework]
            except Exception:
                pass
        self._framework_data[framework] = {}
        return {}

    @staticmethod
    def _render_markdown(
        engagement_id: str,
        frameworks: list[str],
        mappings: list[ComplianceMapping],
        findings: list[dict],
    ) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            f"# Compliance Mapping Report",
            f"",
            f"**Engagement ID:** `{engagement_id}`",
            f"**Generated:** {ts}",
            f"**Frameworks:** {', '.join(frameworks).upper()}",
            f"",
        ]

        if not mappings:
            lines.append("No compliance control mappings identified.")
            return "\n".join(lines)

        for fw in frameworks:
            fw_mappings = [m for m in mappings if m.framework == fw]
            if not fw_mappings:
                continue
            lines.append(f"## {fw.upper().replace('_', '-')}")
            lines.append("")
            lines.append("| Control ID | Title | Affected Findings |")
            lines.append("|-----------|-------|-------------------|")
            for m in sorted(fw_mappings, key=lambda x: x.control_id):
                findings_str = ", ".join(m.finding_ids)
                lines.append(f"| {m.control_id} | {m.control_title} | {findings_str} |")
            lines.append("")

        lines.append(
            "\n---\n"
            "*This mapping is provided for reference and does not constitute a formal "
            "compliance audit. Engage a qualified assessor for certification purposes.*\n"
            "\n*Generated by AIPTT — Autonomous Internal Penetration Testing Tool*"
        )

        return "\n".join(lines)
