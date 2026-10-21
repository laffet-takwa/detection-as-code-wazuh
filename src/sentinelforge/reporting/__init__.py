"""Reporting layer: JSON and Markdown report rendering."""

from __future__ import annotations

from .json_report import write_all_reports, write_json_report
from .markdown_report import render_markdown_report

__all__ = [
    "write_all_reports",
    "write_json_report",
    "render_markdown_report",
]
