from __future__ import annotations

from pathlib import Path

from app.exporters.pdf_exporter import export_pdf_report_from_html


async def export(html_path: Path, output_dir: Path) -> Path:
    return (await export_pdf_report_from_html(html_path=html_path, output_dir=output_dir, filename="report.pdf")).output_path

