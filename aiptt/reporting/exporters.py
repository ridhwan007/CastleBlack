"""
Report Exporters.

Supports PDF (reportlab), JSON (jsonschema-validated), CSV, and HTML output.
"""

from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# JSON schema for finding export validation
# ---------------------------------------------------------------------------
FINDING_SCHEMA = {
    "type": "object",
    "required": ["id", "title", "severity", "cvss_score", "mitre_technique",
                 "target_host", "classification", "status"],
    "properties": {
        "id":               {"type": "string"},
        "title":            {"type": "string"},
        "severity":         {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "cvss_score":       {"type": "number", "minimum": 0, "maximum": 10},
        "mitre_technique":  {"type": "string"},
        "target_host":      {"type": "string"},
        "classification":   {"type": "string"},
        "status":           {"type": "string"},
    },
}


class ReportExporter:
    """
    Exports engagement findings in multiple formats.
    """

    def __init__(self, output_dir: str | Path = "."):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def export_json(self, findings: list[dict], engagement_id: str) -> Path:
        """Export findings as validated JSON."""
        try:
            import jsonschema
            for f in findings:
                jsonschema.validate(instance=f, schema=FINDING_SCHEMA)
        except ImportError:
            pass  # jsonschema optional; skip validation

        payload = {
            "engagement_id": engagement_id,
            "exported_at":   datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "findings":      findings,
        }
        path = self.output_dir / f"{engagement_id}_findings.json"
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    # CSV
    # ------------------------------------------------------------------

    def export_csv(self, findings: list[dict], engagement_id: str) -> Path:
        """Export findings as CSV."""
        path = self.output_dir / f"{engagement_id}_findings.csv"
        if not findings:
            path.write_text("", encoding="utf-8")
            return path

        fieldnames = [
            "id", "title", "severity", "cvss_score", "mitre_technique",
            "target_host", "classification", "status", "description",
        ]
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(findings)
        return path

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def export_html(self, findings: list[dict], engagement_id: str,
                    title: str = "AIPTT Report") -> Path:
        """Export findings as an HTML report."""
        rows = ""
        for f in findings:
            sev = f.get("severity", "INFO")
            colour = {
                "CRITICAL": "#dc2626", "HIGH": "#ea580c",
                "MEDIUM":   "#d97706", "LOW":  "#16a34a", "INFO": "#6b7280",
            }.get(sev, "#6b7280")
            rows += (
                f"<tr>"
                f"<td>{f.get('id','')}</td>"
                f"<td>{f.get('title','')}</td>"
                f"<td style='color:{colour};font-weight:bold'>{sev}</td>"
                f"<td>{f.get('cvss_score','')}</td>"
                f"<td>{f.get('mitre_technique','')}</td>"
                f"<td>{f.get('target_host','')}</td>"
                f"<td>{f.get('status','')}</td>"
                f"</tr>\n"
            )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{title}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2em; color: #111; }}
    h1   {{ color: #1e3a5f; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 1em; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    th   {{ background: #1e3a5f; color: #fff; }}
    tr:nth-child(even) {{ background: #f5f5f5; }}
  </style>
</head>
<body>
  <h1>{title}</h1>
  <p>Engagement: <strong>{engagement_id}</strong> &mdash;
     Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
  <p>Total findings: <strong>{len(findings)}</strong></p>
  <table>
    <thead>
      <tr><th>ID</th><th>Title</th><th>Severity</th><th>CVSS</th>
          <th>Technique</th><th>Target</th><th>Status</th></tr>
    </thead>
    <tbody>
{rows}
    </tbody>
  </table>
  <p><em>Generated by AIPTT &mdash; Autonomous Internal Penetration Testing Tool</em></p>
</body>
</html>"""
        path = self.output_dir / f"{engagement_id}_report.html"
        path.write_text(html, encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    # PDF (reportlab)
    # ------------------------------------------------------------------

    def export_pdf(self, findings: list[dict], engagement_id: str,
                   title: str = "AIPTT Penetration Test Report") -> Path:
        """Export findings as a PDF report using reportlab."""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import cm
            from reportlab.platypus import (
                Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
            )
        except ImportError:
            # Fall back to HTML if reportlab not installed
            html_path = self.export_html(findings, engagement_id, title)
            return html_path

        path = self.output_dir / f"{engagement_id}_report.pdf"
        doc = SimpleDocTemplate(str(path), pagesize=A4,
                                leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()
        story  = []

        # Title
        story.append(Paragraph(title, styles["Title"]))
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph(
            f"Engagement: <b>{engagement_id}</b> &mdash; "
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            styles["Normal"],
        ))
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph(f"Total Findings: <b>{len(findings)}</b>", styles["Normal"]))
        story.append(Spacer(1, 1*cm))

        if findings:
            headers = ["ID", "Title", "Severity", "CVSS", "Technique", "Target", "Status"]
            data = [headers]
            for f in findings:
                data.append([
                    f.get("id", ""),
                    Paragraph(str(f.get("title", ""))[:60], styles["Normal"]),
                    f.get("severity", ""),
                    str(f.get("cvss_score", "")),
                    f.get("mitre_technique", ""),
                    f.get("target_host", ""),
                    f.get("status", ""),
                ])

            sev_colours = {
                "CRITICAL": colors.HexColor("#dc2626"),
                "HIGH":     colors.HexColor("#ea580c"),
                "MEDIUM":   colors.HexColor("#d97706"),
                "LOW":      colors.HexColor("#16a34a"),
                "INFO":     colors.HexColor("#6b7280"),
            }

            table = Table(data, colWidths=[2.5*cm, 5.5*cm, 2*cm, 1.5*cm, 2.5*cm, 3*cm, 2*cm])
            table_style = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
                ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",   (0, 0), (-1, -1), 8),
                ("GRID",       (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
                ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ]
            # Colour severity column
            for i, f in enumerate(findings, start=1):
                sev = f.get("severity", "INFO")
                c   = sev_colours.get(sev, colors.grey)
                table_style.append(("TEXTCOLOR", (2, i), (2, i), c))
                table_style.append(("FONTNAME",  (2, i), (2, i), "Helvetica-Bold"))

            table.setStyle(TableStyle(table_style))
            story.append(table)

        doc.build(story)
        return path
