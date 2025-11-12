from __future__ import annotations

from io import BytesIO
from typing import List

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from src.llm.processor import ProcessedViolation
from src.reporting.models import ReportContext


SUMMARY_STYLE = ParagraphStyle(
    "Summary",
    parent=getSampleStyleSheet()["BodyText"],
    fontSize=11,
    leading=14,
)

HEADER_STYLE = ParagraphStyle(
    "Header",
    parent=getSampleStyleSheet()["Heading1"],
    fontSize=16,
    leading=20,
)

SUBHEADER_STYLE = ParagraphStyle(
    "SubHeader",
    parent=getSampleStyleSheet()["Heading2"],
    fontSize=13,
    leading=18,
)


def build_pdf(context: ReportContext) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=LETTER, leftMargin=1 * inch, rightMargin=1 * inch)

    elements = []
    meta = context.metadata

    elements.append(Paragraph(meta.title, HEADER_STYLE))
    elements.append(Spacer(1, 0.2 * inch))

    details = [
        f"Generated: {meta.generated_at.isoformat()} UTC",
        f"Average Risk Score: {context.average_risk():.1f}",
    ]
    if meta.standard:
        details.append(f"Standard: {meta.standard}")
    if meta.account:
        details.append(f"Account: {meta.account}")
    if meta.cloud_provider:
        details.append(f"Cloud: {meta.cloud_provider}")
    if meta.total_violations is not None:
        details.append(f"Violations: {meta.total_violations}")
    for line in details:
        elements.append(Paragraph(line, SUMMARY_STYLE))
    elements.append(Spacer(1, 0.2 * inch))

    elements.append(Paragraph("Risk Overview", SUBHEADER_STYLE))
    elements.append(_build_risk_table(context))
    elements.append(Spacer(1, 0.3 * inch))

    if context.notes:
        elements.append(Paragraph("Notes", SUBHEADER_STYLE))
        elements.append(Paragraph(context.notes, SUMMARY_STYLE))
        elements.append(Spacer(1, 0.3 * inch))

    elements.append(Paragraph("Violations", SUBHEADER_STYLE))
    for violation in context.violations:
        elements.extend(_render_violation_section(violation))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()


def _build_risk_table(context: ReportContext):
    counts = context.severity_breakdown()
    data = [["Risk Level", "Count"]]
    for level, count in counts.items():
        data.append([level.title(), str(count)])
    table = Table(data, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )
    return table


def _render_violation_section(violation: ProcessedViolation) -> List:
    items = []
    header = f"{violation.violation_id} - {violation.summary}"
    items.append(Paragraph(header, SUMMARY_STYLE))
    items.append(Paragraph(f"Risk: {violation.risk_label.title()} ({violation.risk_score:.1f})", SUMMARY_STYLE))
    if violation.remediation_steps:
        items.append(Paragraph("Remediation:", SUMMARY_STYLE))
        for step in violation.remediation_steps:
            items.append(Paragraph(f"- {step}", SUMMARY_STYLE))
    if violation.references:
        items.append(Paragraph("References:", SUMMARY_STYLE))
        for ref in violation.references:
            items.append(Paragraph(f"- {ref}", SUMMARY_STYLE))
    items.append(Spacer(1, 0.2 * inch))
    return items
