"""Small offline contracts for the original template's guarded file stream."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from jinja2 import Template

from app.exporters import html_exporter, render_security
from app.graph.builder import build_graph_payload
from app.models.report import AddressReport, Transaction


class StreamedHtmlGuardTests(unittest.TestCase):
    def test_every_split_matches_legacy_guard_with_json_unicode_and_self_closing_tags(self):
        payload = html_exporter._browser_json({"name": "Подарок 💎 中文", "raw": "</script>&",
            "operation_identity": "synthetic:nft:1", "owner": "0:" + "2" * 64})
        source = ('<!DOCTYPE html><!-- Привет 😀 --><html><body>'
            '<a href="javascript:alert(1)">Unsafe</a>'
            '<a href="https://example.com/proof?api_key=private&page=2">Evidence</a>'
            '<img src="http://127.0.0.1/private" data-src="https://cdn.tonapi.io/a.png"/>'
            '<p title="💎 &amp; 中文">Привет &#128512;</p>'
            '<script id="nft-payload" type="application/json">' + payload + '</script>'
            '<script>const message = "Привет 😀"; const limit = 1 < 2;</script>'
            '</body></html>')
        expected = render_security.guard_rendered_html(source)
        for split in range(len(source) + 1):
            with self.subTest(split=split):
                actual = "".join(render_security.guard_rendered_chunks((source[:split], source[split:])))
                self.assertEqual(actual.encode("utf-8"), expected.encode("utf-8"))
        self.assertEqual("".join(render_security.guard_rendered_chunks(iter(source))), expected)
        self.assertIn('<img src="" data-src="https://cdn.tonapi.io/a.png"/>', expected)
        self.assertNotIn("javascript:", expected)
        self.assertNotIn("127.0.0.1", expected)
        self.assertNotIn("private&page", expected)
        json_text = expected.split('<script id="nft-payload" type="application/json">', 1)[1].split('</script>', 1)[0]
        self.assertEqual(json.loads(json_text)["name"], "Подарок 💎 中文")

    def test_guard_emits_completed_prefix_before_requesting_next_fragment(self):
        def fragments():
            yield '<p>Первая часть 😀</p>'
            raise RuntimeError("synthetic later template failure")

        guarded = render_security.guard_rendered_chunks(fragments())
        self.assertEqual(next(guarded), "<p>")
        self.assertEqual(next(guarded), "Первая часть 😀")
        self.assertEqual(next(guarded), "</p>")
        with self.assertRaisesRegex(RuntimeError, "later template failure"):
            next(guarded)


class StreamedOriginalHtmlExportTests(unittest.TestCase):
    def test_original_template_bytes_match_legacy_without_full_document_render(self):
        address = "0:" + "1" * 64
        report = AddressReport(target_address=address, detected_chains=["ton"],
            warnings=["Публичная заметка 😀 中文"], transactions=[Transaction(chain="ton",
                tx_hash="2" * 64, source="synthetic_stream_provider", asset="TON",
                raw={"metadata": "Подарок 💎", "public_proof": {"value": "all fields survive"}})])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            template, context = html_exporter._prepare_html_template(report, build_graph_payload(report), output)
            reference = render_security.guard_rendered_html(template.render(**context))
            expected = output / "legacy.html"
            expected.write_text(reference, encoding="utf-8")
            with patch.object(html_exporter, "_prepare_html_template", return_value=(template, context)), \
                    patch.object(Template, "render", side_effect=AssertionError("Full Jinja render called")), \
                    patch.object(html_exporter, "render_html_report", side_effect=AssertionError("Full report render called")), \
                    patch.object(html_exporter, "guard_rendered_html", side_effect=AssertionError("Full HTML guard called")):
                result = html_exporter.export_html_report(report, {}, output)
            self.assertEqual(result.output_path.read_bytes(), expected.read_bytes())
            self.assertFalse((output / "report.html.tmp").exists())
            self.assertIn("Публичная заметка 😀 中文", reference)

    def test_public_string_render_api_remains_compatible(self):
        template = Template('<p>{{ message }}</p>')
        with patch.object(html_exporter, "_prepare_html_template", return_value=(template, {"message": "Привет 😀"})):
            value = html_exporter.render_html_report(None, {}, Path("unused"))
        self.assertIsInstance(value, str)
        self.assertEqual(value, "<p>Привет 😀</p>")

    def test_partial_template_failure_preserves_previous_report_and_removes_temp(self):
        class FailingTemplate:
            def generate(self, **context):
                yield "<p>Checked prefix</p>"
                raise RuntimeError("synthetic template failure")

        self._check_rollback(FailingTemplate(), "template failure")

    def test_partial_guard_failure_preserves_previous_report_and_removes_temp(self):
        class TemplateChunks:
            def generate(self, **context):
                yield "<p>Checked prefix</p>"
                yield '<img src="https://cdn.tonapi.io/a.png"/>'

        original = render_security._RenderedGuard.handle_starttag

        def fail_on_image(guard, tag, attrs):
            if tag == "img":
                raise RuntimeError("synthetic guard failure")
            return original(guard, tag, attrs)

        with patch.object(render_security._RenderedGuard, "handle_starttag", fail_on_image):
            self._check_rollback(TemplateChunks(), "guard failure")

    def test_partial_write_failure_preserves_previous_report_and_removes_temp(self):
        class TemplateChunks:
            def generate(self, **context):
                yield "<p>Checked prefix</p>"
                yield "<p>Second fragment</p>"

        original_open = Path.open

        class FailingWriter:
            def __init__(self, stream):
                self.stream = stream
                self.calls = 0

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.stream.close()

            def write(self, value):
                self.calls += 1
                if self.calls > 1:
                    raise OSError("synthetic write failure")
                return self.stream.write(value)

        def failing_open(path, *args, **kwargs):
            stream = original_open(path, *args, **kwargs)
            return FailingWriter(stream) if path.name == "report.html.tmp" else stream

        with patch.object(Path, "open", failing_open):
            self._check_rollback(TemplateChunks(), "write failure", OSError)

    def _check_rollback(self, template, message, exception=RuntimeError):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            report_path = output / "report.html"
            report_path.write_bytes(b"previous complete report")
            with patch.object(html_exporter, "_prepare_html_template", return_value=(template, {})):
                with self.assertRaisesRegex(exception, message):
                    html_exporter.export_html_report(None, {}, output)
            self.assertEqual(report_path.read_bytes(), b"previous complete report")
            self.assertFalse((output / "report.html.tmp").exists())


if __name__ == "__main__":
    unittest.main()
