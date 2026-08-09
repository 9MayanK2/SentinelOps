"""
report_generator.py

Automated Executive HTML & PDF Security Report Generator.
Reads master_report.json and produces HTML and PDF reports inside:
  compliance/reports/executive_reports/security_report.html
  compliance/reports/executive_reports/security_report.pdf
"""

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

from security.common.logger import logger

# Import ReportLab for native PDF generation (safe fallback if not installed)
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    logger.warning("ReportLab library not found. Installing via 'pip install -r requirements.txt' will enable PDF report generation.")


REPORTS_DIR = Path("compliance/reports/executive_reports")
HTML_REPORT_PATH = REPORTS_DIR / "security_report.html"
PDF_REPORT_PATH = REPORTS_DIR / "security_report.pdf"


class ReportGenerator:
    """
    Generates HTML and PDF reports inside compliance/reports/executive_reports/.
    """

    def __init__(self, reports_dir: str | Path = REPORTS_DIR):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_html(self, master_report: dict) -> Path:
        """
        Generates an executive HTML report inside compliance/reports/executive_reports/security_report.html.
        """
        summary = master_report.get("summary", {})
        risk_summary = master_report.get("risk_summary", {})
        compliance_summary = master_report.get("compliance_summary", {})
        findings = master_report.get("findings", [])

        risk_level = risk_summary.get("risk_level", "UNKNOWN")
        risk_color = "#ef4444" if risk_level in ["CRITICAL", "HIGH"] else "#f59e0b" if risk_level == "MEDIUM" else "#10b981"

        findings_rows = ""
        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            sev_badge = f'<span class="badge badge-{sev.lower()}">{sev}</span>'
            file_loc = f"{f.get('file', 'N/A')}"
            if f.get('line'):
                file_loc += f":{f.get('line')}"

            findings_rows += f"""
            <tr>
                <td>{sev_badge}</td>
                <td><strong>{f.get('tool', 'N/A')}</strong></td>
                <td><code>{f.get('rule_id', 'N/A')}</code></td>
                <td><code>{file_loc}</code></td>
                <td>{f.get('message', 'N/A')}</td>
            </tr>
            """

        framework_bars = ""
        for fw_key, fw_data in compliance_summary.items():
            fw_title = fw_key.replace("_", " ").upper()
            pct = fw_data.get("compliance_percentage", 0.0)
            passed = fw_data.get("controls_passed", 0)
            total = fw_data.get("total_controls_baseline", 0)
            framework_bars += f"""
            <div class="fw-item">
                <div class="fw-header">
                    <span>{fw_title}</span>
                    <span>{pct}% ({passed}/{total} Passed)</span>
                </div>
                <div class="progress-bar"><div class="progress-fill" style="width: {pct}%;"></div></div>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DevSecOps Security & Compliance Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
        .container {{ max-width: 1100px; margin: 0 auto; background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #334155; padding-bottom: 15px; }}
        .title {{ font-size: 24px; font-weight: bold; color: #38bdf8; }}
        .badge {{ padding: 6px 12px; border-radius: 6px; font-weight: bold; font-size: 13px; text-transform: uppercase; }}
        .badge-critical {{ background: #991b1b; color: #fca5a5; }}
        .badge-high {{ background: #c2410c; color: #ffedd5; }}
        .badge-medium {{ background: #854d0e; color: #fef08a; }}
        .badge-low {{ background: #15803d; color: #bbf7d0; }}
        .badge-info {{ background: #1e40af; color: #bfdbfe; }}
        .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 25px 0; }}
        .card {{ background: #0f172a; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #334155; }}
        .card .val {{ font-size: 28px; font-weight: bold; margin-top: 5px; }}
        .fw-item {{ margin-bottom: 15px; }}
        .fw-header {{ display: flex; justify-content: space-between; margin-bottom: 5px; font-size: 14px; }}
        .progress-bar {{ background: #334155; height: 10px; border-radius: 5px; overflow: hidden; }}
        .progress-fill {{ background: #38bdf8; height: 100%; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #94a3b8; }}
        code {{ font-family: monospace; background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #e2e8f0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">🛡️ DevSecOps Master Security Report</div>
            <div class="badge" style="background:{risk_color}; color:#fff;">Risk Level: {risk_level}</div>
        </div>

        <div class="cards">
            <div class="card"><div>Total Findings</div><div class="val">{summary.get('total_findings', 0)}</div></div>
            <div class="card"><div>Risk Score</div><div class="val">{risk_summary.get('total_risk_score', 0)} Pts</div></div>
            <div class="card"><div>Compliance Score</div><div class="val">{summary.get('compliance_score', 0)}%</div></div>
            <div class="card"><div>Critical / High</div><div class="val" style="color:#ef4444;">{summary.get('critical', 0)} / {summary.get('high', 0)}</div></div>
        </div>

        <h3>📜 Compliance Posture by Framework</h3>
        {framework_bars}

        <h3>🔍 Detailed Security Findings</h3>
        <table>
            <thead>
                <tr><th>Severity</th><th>Tool</th><th>Rule ID</th><th>File / Location</th><th>Description</th></tr>
            </thead>
            <tbody>
                {findings_rows}
            </tbody>
        </table>
    </div>
</body>
</html>"""

        with open(HTML_REPORT_PATH, "w", encoding="utf-8") as fp:
            fp.write(html_content)

        logger.info(f"Generated Executive HTML Report at {HTML_REPORT_PATH}")
        return HTML_REPORT_PATH

    def generate_pdf(self, master_report: dict) -> Path:
        """
        Generates an audit-ready executive PDF report using ReportLab.
        """
        if not HAS_REPORTLAB:
            logger.warning("Skipping PDF generation because ReportLab is not installed.")
            return PDF_REPORT_PATH

        summary = master_report.get("summary", {})
        risk_summary = master_report.get("risk_summary", {})
        compliance_summary = master_report.get("compliance_summary", {})
        findings = master_report.get("findings", [])

        doc = SimpleDocTemplate(
            str(PDF_REPORT_PATH),
            pagesize=A4,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        normal_style = styles["Normal"]

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=10
        )

        subtitle_style = ParagraphStyle(
            "SubTitle",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#475569"),
            spaceAfter=15
        )

        h2_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=12,
            spaceAfter=8
        )

        cell_style = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#1e293b")
        )

        cell_header_style = ParagraphStyle(
            "TableHeaderCell",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#ffffff")
        )

        story = []

        # Header Title
        story.append(Paragraph("🛡️ DevSecOps Executive Security & Audit Report", title_style))
        gen_time = master_report.get("generated_at", datetime.utcnow().isoformat())
        story.append(Paragraph(f"Generated: {gen_time} | Scanners: {', '.join(master_report.get('scanners_executed', []))}", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#cbd5e1"), spaceAfter=12))

        # Executive Metrics Table
        risk_level = risk_summary.get("risk_level", "UNKNOWN")
        metrics_data = [
            [
                Paragraph("<b>Total Findings</b>", cell_style),
                Paragraph("<b>Total Risk Score</b>", cell_style),
                Paragraph("<b>Overall Risk Level</b>", cell_style),
                Paragraph("<b>Compliance Score</b>", cell_style)
            ],
            [
                Paragraph(str(summary.get('total_findings', 0)), cell_style),
                Paragraph(f"{risk_summary.get('total_risk_score', 0)} Pts", cell_style),
                Paragraph(f"<b>{risk_level}</b>", cell_style),
                Paragraph(f"<b>{summary.get('compliance_score', 0)}%</b>", cell_style)
            ]
        ]
        t_metrics = Table(metrics_data, colWidths=[1.3 * inch, 1.4 * inch, 1.8 * inch, 1.8 * inch])
        t_metrics.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor("#0f172a")),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 6)
        ]))
        story.append(t_metrics)
        story.append(Spacer(1, 15))

        # Compliance Framework Posture Section
        story.append(Paragraph("📜 Framework Compliance Posture Breakdown", h2_style))
        comp_rows = [
            [
                Paragraph("Framework", cell_header_style),
                Paragraph("Compliance %", cell_header_style),
                Paragraph("Controls Passed", cell_header_style),
                Paragraph("Controls Failed", cell_header_style)
            ]
        ]

        for fw_key, fw_data in compliance_summary.items():
            fw_title = fw_key.replace("_", " ").upper()
            pct = fw_data.get("compliance_percentage", 0.0)
            passed = fw_data.get("controls_passed", 0)
            total = fw_data.get("total_controls_baseline", 0)
            failed = fw_data.get("controls_failed", 0)

            comp_rows.append([
                Paragraph(f"<b>{fw_title}</b>", cell_style),
                Paragraph(f"{pct}%", cell_style),
                Paragraph(f"{passed} / {total}", cell_style),
                Paragraph(str(failed), cell_style)
            ])

        t_comp = Table(comp_rows, colWidths=[2.5 * inch, 1.2 * inch, 1.3 * inch, 1.3 * inch])
        t_comp.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor("#1e293b")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0, 0), (-1, -1), 5)
        ]))
        story.append(t_comp)
        story.append(Spacer(1, 15))

        # Detailed Vulnerabilities Table
        story.append(Paragraph("🔍 Detailed Findings Inventory", h2_style))
        vuln_rows = [
            [
                Paragraph("Severity", cell_header_style),
                Paragraph("Tool", cell_header_style),
                Paragraph("Rule ID", cell_header_style),
                Paragraph("File / Location", cell_header_style),
                Paragraph("Description", cell_header_style)
            ]
        ]

        for f in findings[:25]:  # Limit top 25 for printable summary
            sev = (f.get("severity") or "INFO").upper()
            file_loc = f"{f.get('file', 'N/A')}"
            if f.get('line'):
                file_loc += f":{f.get('line')}"

            vuln_rows.append([
                Paragraph(f"<b>{sev}</b>", cell_style),
                Paragraph(f.get("tool", "N/A"), cell_style),
                Paragraph(f.get("rule_id", "N/A"), cell_style),
                Paragraph(file_loc[:30], cell_style),
                Paragraph(f.get("message", "N/A")[:70], cell_style)
            ])

        t_vuln = Table(vuln_rows, colWidths=[0.8 * inch, 0.8 * inch, 1.2 * inch, 1.5 * inch, 2.0 * inch])
        t_vuln.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor("#1e293b")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 4)
        ]))
        story.append(t_vuln)

        doc.build(story)
        logger.info(f"Generated Executive PDF Report at {PDF_REPORT_PATH}")
        return PDF_REPORT_PATH

    def generate_all(self, master_report: dict) -> Dict[str, Path]:
        """
        Generates both HTML and PDF executive reports.
        """
        html_p = self.generate_html(master_report)
        pdf_p = self.generate_pdf(master_report)
        return {"html": html_p, "pdf": pdf_p}


def main():
    generator = ReportGenerator()
    print("Report Generator initialized.")


if __name__ == "__main__":
    main()
