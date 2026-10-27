from __future__ import annotations

from pathlib import Path

from app.exporters.html_exporter import export_html_report
from app.models.report import AddressReport


def export(report: AddressReport, graph: dict, output_dir: Path, language: str = "ru") -> Path:
    return export_html_report(report=report, graph=graph, output_dir=output_dir, filename="report.html", language=language).output_path

