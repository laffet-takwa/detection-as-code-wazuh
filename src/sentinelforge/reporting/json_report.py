"""JSON report rendering."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..models import ConversionReport, CoverageReport, TestReport, ValidationReport
from .markdown_report import render_markdown_report

__all__ = ["write_json_report", "write_all_reports"]


def _serialize_model(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json")
    return {}


def build_full_report(
    validation: ValidationReport | None = None,
    conversion: ConversionReport | None = None,
    test: TestReport | None = None,
    coverage: CoverageReport | None = None,
) -> dict[str, Any]:
    """Build a combined JSON report from all stages."""

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "validation": _serialize_model(validation) if validation else None,
        "conversion": _serialize_model(conversion) if conversion else None,
        "testing": _serialize_model(test) if test else None,
        "coverage": _serialize_model(coverage) if coverage else None,
    }


def write_json_report(report: dict[str, Any], output_path: Path) -> None:
    """Write *report* as JSON to *output_path*."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)


def write_all_reports(
    output_dir: Path,
    validation: ValidationReport | None = None,
    conversion: ConversionReport | None = None,
    test: TestReport | None = None,
    coverage: CoverageReport | None = None,
) -> tuple[Path, Path]:
    """Write both JSON and Markdown reports to *output_dir*."""

    output_dir.mkdir(parents=True, exist_ok=True)

    full_report = build_full_report(validation, conversion, test, coverage)
    json_path = output_dir / "report.json"
    md_path = output_dir / "report.md"

    write_json_report(full_report, json_path)

    md_content = render_markdown_report(full_report)
    md_path.write_text(md_content, encoding="utf-8")

    return json_path, md_path
