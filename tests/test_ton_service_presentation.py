"""Offline behavioral checks for evidence-based TON service report views."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest

from app.models.report import AddressReport, Transaction
from app.exporters.html_exporter import export_html_report, _ton_service_views, _service_logos
from app.exporters.render_security import safe_image_url
from app.graph.builder import build_graph_payload

A, B, C = ["0:" + str(value) * 64 for value in (1, 2, 3)]
WHEN = "2026-10-16T12:00:00Z"


def fixture(count=1):
    evidence = [{"evidence_id": "official-fixture", "source": "official_fixture", "upstream": "example.com",
        "url": "https://example.com/published-address", "observed_at": WHEN, "relation": "published_service_address",
        "address": A, "facts": {"claim": "fixture only"}}]
    known = {"address": A, "account_type": "wallet", "account_status": "active",
        "contract": {"wallet_version": "v4r2", "code_hash": "fixture-code-hash", "status": "observed", "evidence_ids": ["official-fixture"]},
        "attributions": [{"attribution_id": "claim-fixture", "service_id": "xrocket", "name": "xRocket", "category": "custodial_service",
            "status": "PROBABLE", "method": "fixture registry claim", "reason": "This test fixture is not a real address assertion.",
            "evidence_ids": ["official-fixture"], "source_url": "https://example.com/published-address", "observed_at": WHEN,
            "conflicts": ["alternative operator remains possible"]}],
        "client_attribution": {"status": "UNKNOWN", "reason": "Wallet V4 is shared by multiple signing apps."}, "evidence_ids": ["official-fixture"]}
    unknown = {"address": B, "account_type": "wallet", "account_status": "active",
        "contract": {"wallet_version": "v5r1", "code_hash": "other-code", "status": "observed"}, "attributions": [],
        "client_attribution": {"status": "UNKNOWN", "reason": "No signing application proof."}, "conflicts": []}
    report = AddressReport(target_address=A, detected_chains=["ton"], transactions=[Transaction(chain="ton", tx_hash=f"service-tx-{i}",
        from_address=A, to_address=B, amount_decimal="0.000000001", asset="TON", direction="out", source="tonapi",
        raw={"trace_id": "service-trace"}) for i in range(count)], ton_service_intelligence={"schema_version": "1.0", "target_address": A,
        "addresses": {A: known, B: unknown}, "transactions": [], "evidence": evidence,
        "observations": [{"raw": {"api_key": "secret-service-observation"}}], "coverage": {"status": "PARTIAL", "limits": "fixture-only"}})
    return report


class TonServicePresentationTests(unittest.TestCase):
    def test_sender_recipient_contract_and_client_claims_are_separate(self):
        report = fixture()
        with tempfile.TemporaryDirectory() as directory:
            html = export_html_report(report, build_graph_payload(report), Path(directory), language="en").output_path.read_text(encoding="utf-8")
        self.assertIn("Sender service:", html)
        self.assertIn("Recipient service:", html)
        self.assertIn("xRocket · PROBABLE", html)
        self.assertIn("Signing client", html)
        self.assertIn("v4r2", html)
        self.assertIn("Wallet Application / Signing client", html)
        self.assertIn("Application confidence", html)
        self.assertIn("Wallet V4 is shared", html)
        self.assertIn("alternative operator remains possible", html)
        self.assertIn(WHEN, html)
        self.assertIn('href="https://example.com/published-address"', html)
        self.assertNotIn("secret-service-observation", html)
        payload = json.loads(re.search(r'<script id="nft-payload" type="application/json">(.*?)</script>', html, re.S).group(1))
        self.assertEqual(payload["transaction_views"][0]["sender_service_address"], A)
        self.assertEqual(payload["transaction_views"][0]["recipient_service_address"], B)
        self.assertEqual(payload["transaction_views"][0]["service"], "")
        self.assertNotIn("observations", payload["services"])
        self.assertFalse(payload["services"]["addresses"]["ton:" + B]["attributions"])
        self.assertEqual(payload["services"]["addresses"]["ton:" + A]["attributions"][0]["status"], "PROBABLE")
        self.assertEqual(payload["transaction_views"][0]["sender_service_keys"], ["ton:" + A])

    def test_logo_is_pinned_official_asset_not_an_attribution_or_provider_url(self):
        report = fixture()
        claim = report.ton_service_intelligence["addresses"][A]["attributions"][0]
        claim["logo"] = "javascript:alert(1)"
        claim["image_url"] = "https://attacker.example/tracker.png"
        views = _ton_service_views(report)
        result = views["addresses"][A]["attributions"][0]
        self.assertTrue(result["logo"].startswith("data:image/png;base64,"))
        self.assertEqual(result["status"], "PROBABLE")
        claim["status"] = "UNKNOWN"
        self.assertEqual(_ton_service_views(report)["addresses"][A]["attributions"][0]["logo"], "")
        claim["status"], claim["service_id"] = "CONFIRMED", "invented-service"
        self.assertEqual(_ton_service_views(report)["addresses"][A]["attributions"][0]["logo"], "")
        for asset in _service_logos().values():
            self.assertTrue(asset["source_url"].startswith("https://"))
            self.assertTrue(asset["license"])

    def test_png_guard_rejects_invalid_or_oversized_data(self):
        self.assertTrue(safe_image_url(_service_logos()["xrocket"]["url"]))
        for value in ("data:image/png;base64,!!!!", "data:image/png;base64," + base64.b64encode(b"<svg onload='x'>").decode(),
                      "data:image/png;base64," + "A" * 180001):
            self.assertEqual(safe_image_url(value), "")

    def test_service_evidence_escapes_content_and_rejects_unsafe_links(self):
        report = fixture()
        claim = report.ton_service_intelligence["addresses"][A]["attributions"][0]
        claim.update({"name": '<img src=x onerror="alert(1)">', "source_url": "javascript:alert(1)", "reason": "</script><script>alert(1)</script>"})
        report.ton_service_intelligence["evidence"][0]["url"] = "http://127.0.0.1/private"
        with tempfile.TemporaryDirectory() as directory:
            html = export_html_report(report, build_graph_payload(report), Path(directory)).output_path.read_text(encoding="utf-8")
        self.assertNotIn('<script>alert(1)</script>', html)
        self.assertNotIn('href="javascript:', html)
        self.assertNotIn('href="http://127.', html)
        self.assertIn("&lt;img", html)

    def test_original_css_navigation_and_no_separate_ui(self):
        template = (Path(__file__).resolve().parents[1] / "app/exporters/investigation_template.html").read_text(encoding="utf-8")
        self.assertEqual(hashlib.sha256(re.search(r"<style>(.*?)</style>", template, re.S).group(1).encode()).hexdigest(), "617e933a0973854d1fafb1a2501c9ce3aeae224553e733e742595e293b7801d7")
        navigation=re.search(r'<section class="panel nav">(.*?)</section>', template, re.S).group(1)
        extension=r"(?m)^[ \t]*<!-- GANSAR_INFERENTIAL_BEGIN -->\n.*?^[ \t]*<!-- GANSAR_INFERENTIAL_END -->\n"
        self.assertEqual(len(list(re.finditer(extension,navigation,re.S))),1)
        navigation=re.sub(extension,'',navigation,flags=re.S|re.M)
        self.assertEqual(hashlib.sha256(navigation.encode()).hexdigest(), "fe74b164f088dad4d80a0491f6d7cdebf10027ee8e1039798ffd51a04e9fc959")
        self.assertIn('id="graphCanvas"', template)
        self.assertIn('id="graph3d"', template)


class TonServiceBrowserTests(unittest.IsolatedAsyncioTestCase):
    async def test_offline_paged_rows_and_2d_3d_node_inspector_keep_evidence(self):
        from playwright.async_api import async_playwright
        report = fixture(261)
        with tempfile.TemporaryDirectory() as directory:
            graph = build_graph_payload(report)
            path = export_html_report(report, graph, Path(directory), language="en").output_path
            async with async_playwright() as runtime:
                try:
                    browser = await runtime.chromium.launch(args=["--disable-background-networking", "--enable-unsafe-swiftshader"])
                except Exception as exc:
                    self.skipTest(type(exc).__name__)
                try:
                    page = await browser.new_page(viewport={"width": 1400, "height": 900})
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    async def offline(route):
                        if route.request.url.startswith(("file:", "data:", "blob:")):
                            await route.continue_()
                        else:
                            await route.abort()
                    await page.route("**/*", offline)
                    await page.goto(path.resolve().as_uri())
                    await page.wait_for_function("document.querySelectorAll('#txTimeline .tx-row').length === 260")
                    await page.locator("#txPageNext").click()
                    self.assertEqual(await page.locator("#txTimeline .tx-row").count(), 1)
                    self.assertIn("xRocket · PROBABLE", await page.locator("#txTimeline").inner_text())
                    await page.locator("#txTimeline .tx-expand").click()
                    await page.locator("#txTimeline .ton-service-details > summary").first.click()
                    await page.wait_for_selector('#txTimeline .ton-service-details[open]:not([data-service-lazy])')
                    self.assertIn("fixture-code-hash", await page.locator("#txTimeline .tx-details").inner_text())
                    self.assertIn("alternative operator", await page.locator("#txTimeline .tx-details").inner_text())
                    await page.evaluate("inspectNode(graphData.nodes.find(node=>node.id === graphData.target))")
                    self.assertIn("xRocket · PROBABLE", await page.locator("#inspector").text_content())
                    self.assertIn("Contract version / code hash", await page.locator("#inspector").text_content())
                    await page.locator("#graph3dMode").click()
                    await page.wait_for_function("document.querySelector('#graph3d canvas')")
                    await page.evaluate("inspectNode(graphData.nodes.find(node=>node.id === graphData.target))")
                    self.assertIn("Signing client", await page.locator("#inspector").text_content())
                    for width in (390, 320):
                        await page.set_viewport_size({"width": width, "height": 844})
                        self.assertTrue(await page.evaluate("document.documentElement.scrollWidth <= innerWidth"))
                    self.assertEqual(errors, [])
                finally:
                    await browser.close()


if __name__ == "__main__":
    unittest.main()
