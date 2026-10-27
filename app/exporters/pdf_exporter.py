from __future__ import annotations

import asyncio
from io import BytesIO
from dataclasses import dataclass
from pathlib import Path

from PIL import Image
from playwright.async_api import async_playwright
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas


@dataclass(frozen=True)
class PdfExportResult:
    output_path: Path
    rendered: bool = True
    renderer_status: str = "rendered"
    error: str | None = None


def _write_fallback_pdf(out: Path, html_path: Path, reason: str) -> None:
    c = canvas.Canvas(str(out), pagesize=A4)
    width, height = A4
    lines = [
        "GANSAR report",
        "PDF renderer did not complete.",
        f"Reason: {reason[:120]}",
        f"HTML report: {html_path.resolve()}",
        "Open report.html for the full interactive report.",
    ]
    y = height - 72
    c.setFont("Helvetica-Bold", 14)
    c.drawString(72, y, lines[0])
    c.setFont("Helvetica", 10)
    for line in lines[1:]:
        y -= 22
        c.drawString(72, y, line[:110])
    c.showPage()
    c.save()


def _write_image_pdf(out: Path, image_bytes: bytes) -> None:
    image = Image.open(BytesIO(image_bytes)).convert("RGB")
    width_px, height_px = image.size
    page_width, page_height = A4
    margin = 18
    content_width = page_width - margin * 2
    content_height = page_height - margin * 2
    slice_height = max(1, int(content_height * width_px / content_width))
    c = canvas.Canvas(str(out), pagesize=A4)
    y = 0
    while y < height_px:
        bottom = min(height_px, y + slice_height)
        crop = image.crop((0, y, width_px, bottom))
        draw_height = content_width * crop.height / width_px
        c.drawImage(ImageReader(crop), margin, page_height - margin - draw_height, width=content_width, height=draw_height)
        c.showPage()
        y = bottom
    c.save()


async def _write_screenshot_pdf(page, out: Path) -> None:
    image_bytes = await page.screenshot(full_page=True, type="jpeg", quality=82, animations="disabled")
    _write_image_pdf(out, image_bytes)


async def export_pdf_report_from_html(html_path: Path, output_dir: Path, filename: str = "report.pdf") -> PdfExportResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / filename
    browser = None
    try:
        async with async_playwright() as p:
            try:
                browser = await p.chromium.launch(args=["--disable-dev-shm-usage", "--disable-background-networking"])
                page = await browser.new_page(viewport={"width": 1400, "height": 900})
                # Static dossiers require no provider requests while rendering.
                # Block remote resources and redirects, including private addresses.
                async def local_resources_only(route):
                    if route.request.url.startswith(("file:", "data:", "blob:")):
                        await route.continue_()
                    else:
                        await route.abort("blockedbyclient")
                await page.route("**/*", local_resources_only)
                page.set_default_timeout(30000)
                await page.add_init_script("window.__GANSAR_PDF_EXPORT__ = true;")
                await page.goto(html_path.resolve().as_uri(), wait_until="domcontentloaded", timeout=30000)
                try:
                    await page.wait_for_function("window.__GANSAR_READY_FOR_PDF__ === true", timeout=12000)
                except Exception:
                    await page.wait_for_timeout(1500)
                try:
                    await page.emulate_media(media="print")
                except Exception:
                    pass
                await _write_screenshot_pdf(page, out)
            finally:
                if browser is not None:
                    await browser.close()
    except Exception as exc:
        _write_fallback_pdf(out, html_path, type(exc).__name__)
        return PdfExportResult(output_path=out, rendered=False, renderer_status="fallback_notice", error=type(exc).__name__)
    return PdfExportResult(output_path=out)


def export_pdf_report_from_html_sync(html_path: Path, output_dir: Path, filename: str = "report.pdf") -> PdfExportResult:
    return asyncio.run(export_pdf_report_from_html(html_path=html_path, output_dir=output_dir, filename=filename))

