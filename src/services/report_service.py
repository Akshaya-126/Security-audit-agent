"""
Report generation service.

Handles saving security audit reports as:
  - JSON (structured, machine-readable)
  - PDF (human-readable, formatted with ReportLab)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# ReportLab imports — optional; PDF generation is skipped gracefully if missing
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        HRFlowable,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    _REPORTLAB_AVAILABLE = True
except ImportError:
    _REPORTLAB_AVAILABLE = False
    logger.warning("ReportLab not installed — PDF report generation will be skipped.")


# ─────────────────────────────────────────────────────────────────────────────
# JSON report
# ─────────────────────────────────────────────────────────────────────────────

def save_json_report(report: Dict[str, Any], scan_id: str, reports_dir: str = "reports") -> str:
    """Save the report dict as a JSON file and return the file path."""
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    path = str(Path(reports_dir) / f"{scan_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    return path


# ─────────────────────────────────────────────────────────────────────────────
# PDF report
# ─────────────────────────────────────────────────────────────────────────────

_SEV_COLORS = {
    "critical": colors.HexColor("#DC2626"),
    "high":     colors.HexColor("#EA580C"),
    "medium":   colors.HexColor("#D97706"),
    "low":      colors.HexColor("#2563EB"),
    "info":     colors.HexColor("#6B7280"),
}

_STATUS_COLORS = {
    "confirmed":     colors.HexColor("#15803D"),
    "likely":        colors.HexColor("#B45309"),
    "manual_review": colors.HexColor("#6B7280"),
}


def _get_styles():
    styles = getSampleStyleSheet()
    custom = {
        "Title": ParagraphStyle(
            "Title", fontSize=24, leading=30, textColor=colors.HexColor("#0F172A"),
            spaceAfter=6, fontName="Helvetica-Bold",
        ),
        "Subtitle": ParagraphStyle(
            "Subtitle", fontSize=12, textColor=colors.HexColor("#475569"),
            spaceAfter=20,
        ),
        "SectionHeader": ParagraphStyle(
            "SectionHeader", fontSize=14, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#1E293B"), spaceBefore=16, spaceAfter=8,
        ),
        "Body": ParagraphStyle(
            "Body", fontSize=10, leading=14, textColor=colors.HexColor("#334155"),
            spaceAfter=6,
        ),
        "FindingTitle": ParagraphStyle(
            "FindingTitle", fontSize=11, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#1E293B"), spaceAfter=4,
        ),
        "Meta": ParagraphStyle(
            "Meta", fontSize=9, textColor=colors.HexColor("#64748B"), spaceAfter=4,
        ),
        "Code": ParagraphStyle(
            "Code", fontSize=9, fontName="Courier",
            textColor=colors.HexColor("#1E293B"), backColor=colors.HexColor("#F1F5F9"),
            leftIndent=12, spaceAfter=6,
        ),
    }
    return custom


def _severity_badge(severity: str) -> str:
    """Return HTML-ish coloured text for severity (ReportLab Paragraph markup)."""
    color = _SEV_COLORS.get(severity.lower(), colors.grey)
    hex_color = color.hexval() if hasattr(color, "hexval") else "#6B7280"
    return f'<font color="{hex_color}"><b>[{severity.upper()}]</b></font>'


def save_pdf_report(report: Dict[str, Any], scan_id: str, reports_dir: str = "reports") -> str:
    """
    Generate a formatted PDF report and return the file path.
    Returns an empty string if ReportLab is not installed.
    """
    if not _REPORTLAB_AVAILABLE:
        return ""

    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    path = str(Path(reports_dir) / f"{scan_id}.pdf")

    styles = _get_styles()
    story = []

    # ── Cover page ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph("🛡️ Security Audit Report", styles["Title"]))
    story.append(Paragraph(
        f"Target: {report.get('target', 'Unknown')}",
        styles["Subtitle"],
    ))
    story.append(Paragraph(
        f"Scan ID: {scan_id}  |  Generated: {report.get('generated_at', '')}",
        styles["Meta"],
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))
    story.append(Spacer(1, 0.5 * cm))

    # ── Executive summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", styles["SectionHeader"]))
    summary_text = report.get("executive_summary", "No summary available.")
    for para in summary_text.split("\n\n"):
        if para.strip():
            story.append(Paragraph(para.strip(), styles["Body"]))
    story.append(Spacer(1, 0.5 * cm))

    # ── Severity breakdown table ──────────────────────────────────────────────
    story.append(Paragraph("Severity Breakdown", styles["SectionHeader"]))
    breakdown = report.get("severity_breakdown", {})
    table_data = [["Severity", "Count"]]
    for sev in ("critical", "high", "medium", "low", "info"):
        count = breakdown.get(sev, 0)
        if count > 0:
            table_data.append([sev.upper(), str(count)])

    if len(table_data) > 1:
        t = Table(table_data, colWidths=[8 * cm, 4 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t)

    story.append(Spacer(1, 1 * cm))
    story.append(PageBreak())

    # ── Individual findings ───────────────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", styles["SectionHeader"]))

    findings: List[Dict[str, Any]] = report.get("findings", [])
    if not findings:
        story.append(Paragraph("No significant findings were detected.", styles["Body"]))
    else:
        for i, f in enumerate(findings, 1):
            severity = f.get("severity", "info")
            badge = _severity_badge(severity)
            title = f.get("title", "Untitled Finding")
            story.append(Paragraph(f"{i}. {badge}  {title}", styles["FindingTitle"]))

            meta_parts = []
            if f.get("file"):
                meta_parts.append(f"File: {f['file']}" + (f" (line {f['line']})" if f.get("line") else ""))
            if f.get("source"):
                meta_parts.append(f"Source: {f['source']}")
            if f.get("status"):
                meta_parts.append(f"Status: {f['status'].replace('_', ' ').title()}")
            if meta_parts:
                story.append(Paragraph(" | ".join(meta_parts), styles["Meta"]))

            # AI explanation takes priority, fall back to description
            explanation = f.get("ai_explanation") or f.get("description", "")
            if explanation:
                for para in explanation.split("\n\n")[:3]:
                    if para.strip():
                        story.append(Paragraph(para.strip(), styles["Body"]))

            # Remediation
            remediation = f.get("ai_remediation") or f.get("recommendation", "")
            if remediation:
                story.append(Paragraph("<b>Remediation:</b>", styles["Body"]))
                for para in remediation.split("\n\n")[:3]:
                    if para.strip():
                        story.append(Paragraph(para.strip(), styles["Body"]))

            story.append(HRFlowable(
                width="100%", thickness=0.5,
                color=colors.HexColor("#E2E8F0"), spaceAfter=8,
            ))

    # ── Build PDF ─────────────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )
    doc.build(story)
    return path
