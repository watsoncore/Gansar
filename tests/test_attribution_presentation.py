"""Network-scoped attribution in the existing HTML; fixtures assert no live facts."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest

from app.attribution.normalize import address_id
from app.exporters.html_exporter import _attribution_views, _transaction_views, export_html_report
from app.graph.builder import build_graph_payload
from app.models.report import AddressReport, Transaction

EVM_A, EVM_B = "0x" + "aB" * 20, "0x" + "cD" * 20
BTC_A, BTC_B = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
TON_A, TON_B = "0:" + "1" * 64, "0:" + "2" * 64
WHEN = "2026-10-16T16:00:00Z"


def record(chain, address, label=None):
    key = address_id(chain, address)
    return {"address": address, "blockchain": chain, "account_type": "account", "account_status": "observed",
        "observed_at": WHEN, "contract": {"kind": "unknown", "status": "UNKNOWN"},
        "client_attribution": {"status": "UNKNOWN", "reason": "An account or interaction does not establish a signing application."},
        "attributions": [{"attribution_id": key + ":fixture", "service_id": "fixture:" + label, "name": label,
            "status": "POSSIBLE", "entity_type": "protocol", "relationship": "published_address_label",
            "category": "protocol", "method": "fixture only", "reason": "Synthetic view fixture, not a live address claim.",
            "confidence_rationale": "One fixture source is not independent corroboration.",
            "alternative_explanations": ["The label may be stale."], "coverage_limitations": ["Fixture observations only."],
            "observed_at": WHEN, "source_url": "https://example.com/evidence", "evidence_ids": [key + ":proof"],
            "conflicts": ["Fixture alternative label."]}] if label else [], "evidence_ids": [key + ":proof"], "conflicts": []}


def fixture(chain="eth", count=1):
    addresses = {"ton": (TON_A, TON_B), "btc": (BTC_A, BTC_B),
        "doge": ("D5EQRCnPMXmRvUoZwC7gu7fYspean3PQ9a", "D5KiJ9d8QedaJxRY8oEpFUAVsWZs4jVeBM"),
        "tron": ("TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE", "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7"),
        "solana": ("11111111111111111111111111111111", "Vote111111111111111111111111111111111111111")}
    left, right = addresses.get(chain, (EVM_A, EVM_B))
    rows = {address_id(chain, left): record(chain, left), address_id(chain, right): record(chain, right, "Fixture " + chain)}
    evidence = [{"evidence_id": key + ":proof", "source": "fixture", "upstream": "same-fixture-upstream",
        "url": "https://example.com/evidence", "observed_at": WHEN, "facts": {"fixture": True}} for key in rows]
    return AddressReport(target_address=left, detected_chains=[chain], transactions=[Transaction(chain=chain,
        tx_hash="same-hash-" + str(index), event_id="event-" + str(index), from_address=left, to_address=right,
        inputs=[{"address": left}] if chain in {"btc", "doge"} else [],
        outputs=[{"address": right}] if chain in {"btc", "doge"} else [], amount_decimal="1.000000001", asset=chain.upper(),
        direction="out", source="fixture_provider") for index in range(count)], attribution_intelligence={
        "schema_version": "1.0", "target_address": left, "target_chain": chain, "target_key": address_id(chain, left),
        "addresses": rows, "evidence": evidence, "observations": [{"raw": {"api_key": "do-not-render-observation"}}],
        "relationships": [{"relationship_id": "fixture-route", "blockchain": chain, "from_key": address_id(chain, left),
            "to_key": address_id(chain, right), "type": "direct_transfer", "status": "CONFIRMED",
            "evidence_ids": [address_id(chain, left) + ":proof"], "transaction_hashes": ["same-hash-0"],
            "reason": "Transfer observation only; does not establish a common owner.",
            "alternative_explanations": ["Payment between independent parties."], "limitations": ["One fixture transaction."]}],
        "coverage": {"status": "PARTIAL", "limitations": ["Synthetic fixture."]}, "warnings": [], "errors": []})


def payload(html):
    return json.loads(re.search(r'<script id="nft-payload" type="application/json">(.*?)</script>', html, re.S).group(1))


class AttributionPresentationTests(unittest.TestCase):
    def test_every_supported_chain_uses_scoped_participants_and_unknown_client(self):
        for chain in ("btc", "doge", "eth", "bsc", "polygon", "arbitrum", "optimism", "avalanche", "tron", "solana", "ton"):
            with self.subTest(chain=chain):
                report = fixture(chain)
                views = _attribution_views(report)
                row = _transaction_views(report, "en", views)[0]
                self.assertEqual(len(views["addresses"]), 2)
                self.assertTrue(all(key and key.startswith(chain + ":") for key in views["addresses"]))
                self.assertEqual(row["sender_service_keys"], [address_id(chain, report.transactions[0].from_address)])
                self.assertEqual(row["recipient_service_keys"], [address_id(chain, report.transactions[0].to_address)])
                self.assertIn("published_address_label", row["q"])
                self.assertTrue(all(record["client_attribution"]["status"] == "UNKNOWN" for record in views["addresses"].values()))

    def test_same_hex_address_on_two_chains_never_shares_claims(self):
        report = fixture("eth")
        other = fixture("bsc")
        report.transactions += other.transactions
        report.attribution_intelligence["addresses"].update(other.attribution_intelligence["addresses"])
        report.attribution_intelligence["evidence"] += other.attribution_intelligence["evidence"]
        rows = _transaction_views(report, "en")
        self.assertIn("fixture eth", rows[0]["q"])
        self.assertNotIn("fixture bsc", rows[0]["q"])
        self.assertIn("fixture bsc", rows[1]["q"])
        self.assertNotIn("fixture eth", rows[1]["q"])
        self.assertNotEqual(rows[0]["recipient_service_key"], rows[1]["recipient_service_key"])

    def test_utxo_keeps_all_inputs_outputs_and_no_fabricated_single_sender(self):
        report = fixture("btc")
        tx = report.transactions[0]
        tx.inputs.append({"address": BTC_B})
        tx.outputs.append({"address": BTC_A})
        row = _transaction_views(report, "en")[0]
        self.assertEqual(row["sender_service_keys"], ["btc:" + BTC_A, "btc:" + BTC_B])
        self.assertEqual(row["recipient_service_keys"], ["btc:" + BTC_B, "btc:" + BTC_A])
        self.assertEqual(row["sender_service_key"], "")
        self.assertEqual(row["recipient_service_key"], "")
        self.assertEqual(row["from"], "")
        self.assertEqual(row["to"], "")
        with tempfile.TemporaryDirectory() as directory:
            html = export_html_report(report, build_graph_payload(report), Path(directory), language="en").output_path.read_text(encoding="utf-8")
        self.assertIn("Sender service · ", html)
        self.assertIn("Payment between independent parties.", html)

    def test_full_evidence_limits_relationships_escaping_and_no_input_mutation(self):
        report = fixture()
        snapshot = copy.deepcopy(report.model_dump())
        graph = build_graph_payload(report)
        graph_snapshot = copy.deepcopy(graph)
        with tempfile.TemporaryDirectory() as directory:
            html = export_html_report(report, graph, Path(directory), language="en").output_path.read_text(encoding="utf-8")
        self.assertEqual(report.model_dump(), snapshot)
        self.assertEqual(graph, graph_snapshot)
        data = payload(html)
        self.assertNotIn("observations", data["services"])
        for text in ("Signing client", "Entity / relationship", "Confidence rationale", "The label may be stale.",
                     "Coverage limitations", "Fixture observations only.", "Fixture alternative label.", "common owner", WHEN):
            self.assertIn(text, html)
        self.assertNotIn("do-not-render-observation", html)
        self.assertIn('href="https://example.com/evidence"', html)
        self.assertEqual(data["services"]["relationships"]["fixture-route"]["status"], "CONFIRMED")

    def test_unified_data_takes_priority_over_legacy_ton_labels(self):
        report = fixture("ton")
        report.ton_service_intelligence = {"addresses": {TON_A: record("ton", TON_A, "Legacy conflict not merged")}}
        self.assertNotIn("Legacy conflict not merged", json.dumps(_attribution_views(report)))

    def test_typed_claim_aliases_all_sources_times_and_conflicting_proof_remain_visible(self):
        from app.attribution.models import AttributionClaim
        report = fixture()
        key = address_id("eth", EVM_B)
        typed = AttributionClaim(attribution_id="typed-fixture", blockchain="eth", address=EVM_B,
            entity_name="Typed protocol fixture", entity_type="protocol", relationship="published_address_label",
            status="PROBABLE", method="typed fixture", confidence_rationale="Independent control remains unproved.",
            source_urls=["https://example.com/first", "http://127.0.0.1/private", "https://example.com/second"],
            observation_timestamps=[WHEN, "2026-10-15T16:00:00Z"], evidence_ids=[key + ":proof"],
            conflicting_evidence=["conflicting-proof"], alternative_explanations=["A prior operator."],
            coverage_limitations=["No present controller proof."]).model_dump()
        report.attribution_intelligence["addresses"][key]["attributions"] = [typed,
            {**typed, "attribution_id": "other-typed", "entity_name": "Alternative protocol fixture", "status": "POSSIBLE"}]
        report.attribution_intelligence["evidence"].append({"evidence_id": "conflicting-proof", "source": "fixture_alt",
            "upstream": "example.com", "source_independence": "shared_upstream", "url": "https://example.com/conflict",
            "observed_at": WHEN, "facts": {"label": "Alternative protocol fixture"}})
        views = _attribution_views(report)
        claims = views["addresses"][key]["attributions"]
        self.assertEqual([claim["name"] for claim in claims], ["Typed protocol fixture", "Alternative protocol fixture"])
        self.assertEqual(claims[0]["source_urls"], ["https://example.com/first", "https://example.com/second"])
        self.assertTrue(all(not claim["logo"] for claim in claims))
        with tempfile.TemporaryDirectory() as directory:
            html = export_html_report(report, build_graph_payload(report), Path(directory), language="en").output_path.read_text(encoding="utf-8")
        for value in ("Typed protocol fixture", "Alternative protocol fixture", "PROBABLE", "POSSIBLE",
                      "Conflicting evidence", "Observation times", "shared_upstream", "No present controller proof."):
            self.assertIn(value, html)
        for url in ("https://example.com/first", "https://example.com/second", "https://example.com/conflict"):
            self.assertIn(url, payload(html)["public_urls"])
        self.assertNotIn('href="http://127.', html)

    def test_correlated_evidence_is_complete_without_repeating_it_in_every_transaction(self):
        from app.attribution.engine import correlate_attribution
        report = fixture("eth", 261)
        correlate_attribution(report, dataset_records=[], max_seconds=10)
        expected = copy.deepcopy(report.attribution_intelligence)
        with tempfile.TemporaryDirectory() as directory:
            html = export_html_report(report, build_graph_payload(report), Path(directory), language="en").output_path.read_text(encoding="utf-8")
        self.assertEqual(report.attribution_intelligence, expected)
        self.assertEqual(len(payload(html)["services"]["evidence"]), len(expected["evidence"]))
        self.assertEqual(sum(e.get('relation')=='transaction_participants' for e in expected['evidence']),261)
        proof_ids={e['evidence_id'] for e in expected['evidence']}
        self.assertEqual(len(proof_ids),len(expected['evidence']))
        self.assertTrue(any(e.get('relation')=='inference_operation_observation' for e in expected['evidence']))
        for family in ('hypotheses','clusters','paths'):
            for record in expected['inferential_intelligence'][family]:
                self.assertLessEqual(set(record.get('evidence_ids',[])),proof_ids)
        self.assertLess(len(html.encode("utf-8")), 8_000_000)
        self.assertEqual(html.count('data-service-lazy="1"'), 521)  # 260 rows × 2 roles, plus dynamic-row template.

    def test_official_tether_asset_never_labels_a_token_holder(self):
        report = fixture()
        report.transactions[0].asset = "USDT"
        for item in report.attribution_intelligence["addresses"].values():
            item["attributions"] = []
        views = _attribution_views(report)
        self.assertTrue(all(not item["attributions"] for item in views["addresses"].values()))
        key = address_id("eth", EVM_B)
        report.attribution_intelligence["addresses"][key]["attributions"] = [
            {**record("eth", EVM_B, "Tether")["attributions"][0], "service_id": "tether"}]
        claim = _attribution_views(report)["addresses"][key]["attributions"][0]
        self.assertTrue(claim["logo"].startswith("data:image/svg+xml;base64,"))
        self.assertEqual(claim["status"], "POSSIBLE")
        self.assertEqual(claim["logo_source_url"], "https://tether.to/images/logoCircle.svg")

    def test_original_css_and_navigation_are_unchanged(self):
        root = Path(__file__).resolve().parents[1]
        template = (root / "app/exporters/investigation_template.html").read_text(encoding="utf-8")
        baseline = json.loads((root / "tests/fixtures/attribution/presentation_baseline.json").read_text(encoding="utf-8"))
        for name, pattern in (("css_sha256", r"<style>(.*?)</style>"),
                              ("navigation_sha256", r'<section class="panel nav">(.*?)</section>')):
            content=re.search(pattern,template,re.S).group(1)
            if name=='navigation_sha256':
                extension=r'(?m)^[ \t]*<!-- GANSAR_INFERENTIAL_BEGIN -->\n.*?^[ \t]*<!-- GANSAR_INFERENTIAL_END -->\n'
                self.assertEqual(len(re.findall(extension,content,re.S)),1)
                content=re.sub(extension,'',content,flags=re.S|re.M)
            # Navigation already has this hash in the task's unchanged baseline.
            expected = "fe74b164f088dad4d80a0491f6d7cdebf10027ee8e1039798ffd51a04e9fc959" if name == "navigation_sha256" else baseline[name]
            self.assertEqual(hashlib.sha256(content.encode()).hexdigest(), expected)


class AttributionBrowserTests(unittest.IsolatedAsyncioTestCase):
    async def test_paged_universal_claims_and_2d_3d_inspection_work_offline(self):
        from playwright.async_api import async_playwright
        report = fixture("eth", 261)
        with tempfile.TemporaryDirectory() as directory:
            path = export_html_report(report, build_graph_payload(report), Path(directory), language="en").output_path
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
                    self.assertIn("Fixture eth · POSSIBLE", await page.locator("#txTimeline").inner_text())
                    await page.locator("#txPageNext").click()
                    self.assertEqual(await page.locator("#txTimeline .tx-row").count(), 1)
                    await page.locator("#txTimeline .tx-expand").click()
                    await page.locator("#txTimeline .ton-service-details > summary").last.click()
                    await page.wait_for_selector('#txTimeline .ton-service-details[open]:not([data-service-lazy])')
                    self.assertIn("published_address_label", await page.locator("#txTimeline .tx-details").inner_text())
                    self.assertIn("The label may be stale.", await page.locator("#txTimeline .tx-details").inner_text())
                    self.assertEqual(await page.locator('#txTimeline .ton-service-details[open] a[href="https://example.com/evidence"]').count(), 3)
                    key = address_id("eth", EVM_B)
                    await page.evaluate("key=>inspectNode(graphData.nodes.find(node=>node.service_key === key))", key)
                    self.assertIn("Fixture eth · POSSIBLE", await page.locator("#inspector").text_content())
                    await page.locator("#graph3dMode").click()
                    await page.wait_for_function("document.querySelector('#graph3d canvas')")
                    await page.evaluate("key=>inspectNode(graphData.nodes.find(node=>node.service_key === key))", key)
                    self.assertIn("Signing client", await page.locator("#inspector").text_content())
                    for width in (390, 320):
                        await page.set_viewport_size({"width": width, "height": 844})
                        self.assertTrue(await page.evaluate("document.documentElement.scrollWidth <= innerWidth"))
                    self.assertEqual(errors, [])
                finally:
                    await browser.close()


if __name__ == "__main__":
    unittest.main()
