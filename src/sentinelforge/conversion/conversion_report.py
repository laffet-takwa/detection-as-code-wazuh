"""Conversion report rendering."""

from __future__ import annotations

from typing import Any

from ..models import ConversionReport

__all__ = ["render_conversion_report", "render_conversion_summary"]


def render_conversion_report(report: ConversionReport) -> dict[str, Any]:
    """Render a conversion report as a JSON-serialisable dictionary."""

    return {
        "backend": report.backend,
        "output_directory": report.output_directory,
        "generated_at": report.generated_at.isoformat(),
        "tool_versions": report.tool_versions,
        "summary": {
            "total": len(report.outcomes),
            "converted": len(report.converted),
            "rejected": len(report.rejected),
            "warnings": len(report.warnings),
        },
        "outcomes": [
            {
                "rule_path": outcome.rule_path,
                "rule_id": outcome.rule_id,
                "title": outcome.title,
                "status": outcome.status,
                "converted": outcome.converted,
                "wazuh_rule_id": outcome.wazuh_rule_id,
                "output_path": outcome.output_path,
                "feature": outcome.feature,
                "limitation": outcome.limitation,
                "message": outcome.message,
                "warnings": outcome.warnings,
            }
            for outcome in report.outcomes
        ],
    }


def render_conversion_summary(report: ConversionReport) -> str:
    """Render a human-readable summary of the conversion run."""

    lines = [
        "SentinelForge Conversion Summary",
        "=" * 40,
        f"Backend: {report.backend}",
        f"Output directory: {report.output_directory or 'N/A'}",
        f"Generated: {report.generated_at.isoformat()}",
        "",
        f"Total rules processed: {len(report.outcomes)}",
        f"  Converted: {len(report.converted)}",
        f"  Rejected:  {len(report.rejected)}",
        "",
    ]

    if report.converted:
        lines.append("Converted rules:")
        for outcome in report.converted:
            lines.append(f"  ✓ {outcome.title} (ID: {outcome.wazuh_rule_id}) -> {outcome.output_path}")
        lines.append("")

    if report.rejected:
        lines.append("Rejected rules:")
        for outcome in report.rejected:
            lines.append(f"  ✗ {outcome.title}: {outcome.message}")
            if outcome.limitation:
                lines.append(f"      Limitation: {outcome.limitation}")
        lines.append("")

    if report.warnings:
        lines.append("Warnings:")
        for warning in report.warnings:
            lines.append(f"  ! {warning}")

    return "\n".join(lines)
