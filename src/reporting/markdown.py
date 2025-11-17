from __future__ import annotations

from typing import Iterable

from src.reporting.models import ReportContext


def render_markdown_report(context: ReportContext) -> str:
    metadata = context.metadata
    severity_counts = context.severity_breakdown()
    lines = [f"# {metadata.title}"]
    lines.append("")
    lines.append(f"Generated: {metadata.generated_at.isoformat()} UTC")
    if metadata.standard:
        lines.append(f"Standard: {metadata.standard}")
    if metadata.account:
        lines.append(f"Account: {metadata.account}")
    if metadata.cloud_provider:
        lines.append(f"Cloud: {metadata.cloud_provider}")
    if metadata.total_violations is not None:
        lines.append(f"Violations: {metadata.total_violations}")
    avg_risk = context.average_risk()
    lines.append(f"Average Risk Score: {avg_risk:.1f}")
    lines.append("")

    lines.append("## Risk Overview")
    lines.extend(_render_bullet_counts(severity_counts))
    lines.append("")

    if context.notes:
        lines.append("## Notes")
        lines.append(context.notes)
        lines.append("")

    lines.append("## Violations")
    for violation in context.violations:
        lines.append(f"### {violation.violation_id} - {violation.summary}")
        lines.append(f"- Risk: {violation.risk_label.title()} ({violation.risk_score:.1f})")
        if violation.remediation_steps:
            lines.append("- Remediation:")
            for step in violation.remediation_steps:
                lines.append(f"  - {step}")
        if violation.references:
            lines.append("- References:")
            for ref in violation.references:
                lines.append(f"  - {ref}")
        lines.append("")

    return "\n".join(lines).strip()


def _render_bullet_counts(counts: dict[str, int]) -> Iterable[str]:
    for level, count in counts.items():
        yield f"- {level.title()}: {count}"
