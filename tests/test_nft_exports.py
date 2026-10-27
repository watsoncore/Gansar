from __future__ import annotations

import asyncio
import csv
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from app.exporters.nft_exporter import export_nft_dossier, export_nft_machine_data, render_nft_dossier, export_nft_pdf
from app.exporters.render_security import safe_href, safe_image_url
from app.graph.builder import build_graph_payload
from app.graph.nft_builder import build_nft_graph
from app.exporters.ton_presentation import friendly_address
from app.models.report import AddressReport, Balance, Transaction, TokenHolding
from app.ton_nft.models import NFTAsset, NFTOwnershipAssertion, NFTEvent, NFTIntelligenceReport, IntelligenceEvidence, Money, NFTListing, TelegramCollectible, VerificationStatus

A = "0:" + "1" * 64
B = "0:" + "2" * 64
C = "0:" + "3" * 64
NFT1 = "0:" + "4" * 64
NFT2 = "0:" + "5" * 64
COLLECTION = "0:" + "6" * 64


def fixture() -> NFTIntelligenceReport:
    evidence = IntelligenceEvidence(evidence_id="proof", source="fixture", upstream="fixture", observation_id="raw-1", relation="ownership", status="verified_onchain", explanation="Mock getter assertion", url="https://tonviewer.com/" + NFT1, confidence="high")
    asset = NFTAsset(asset_id=NFT1, address=NFT1, name="Shared title", collection_address=COLLECTION, collection_status="verified_onchain",
        current_owner=C, current_owner_status="verified_onchain", ownership=[NFTOwnershipAssertion(asset_address=NFT1, owner_address=C, status="verified_onchain", method="get_nft_data", evidence_ids=["proof"])],
        evidence_ids=["proof"], metadata=[{"source": "fixture", "raw": {"unmodelled_trait": [1, 2, 3]}, "normalized": {"name": "Shared title"}}])
    asset2 = NFTAsset(asset_id=NFT2, address=NFT2, name="Shared title", current_owner=A, current_owner_status="provider_reported")
    events = [NFTEvent(event_id="event-1", asset_address=NFT1, event_type="transfer", status="success", verification="verified_onchain", from_address=A, to_address=B, transaction_hash="samehash", logical_time=100, action_index=0,
        money=Money(currency="TON", base_units=1000000001, decimals=9, amount="1.000000001"), evidence_ids=["proof"], observation_ids=["raw-1"]),
        NFTEvent(event_id="event-2", asset_address=NFT1, event_type="sale", status="success", verification="verified_onchain", from_address=B, to_address=C, transaction_hash="samehash", logical_time=100, action_index=1,
        money=Money(currency="TON", amount="2.0000000001"), evidence_ids=["proof"], raw={"NftPurchase": True})]
    return NFTIntelligenceReport(investigation_id="test-investigation", query="example.ton", status="partial", assets=[asset, asset2], events=events, evidence=[evidence], coverage=[{"scope": "history", "source": "fixture", "upstream": "fixture", "status": "partial", "records": 2, "gap_reason": "Fixture sample"}])


class NFTGraphTests(unittest.TestCase):
    def test_nft_contract_owner_not_misclassified_wallet(self):
        report = fixture()
        report.assets[1].current_owner = NFT1
        report.assets[1].ownership = [NFTOwnershipAssertion(asset_address=NFT2, owner_address=NFT1, status="verified_onchain", method="get_nft_data", evidence_ids=["proof"])]
        report.assets[1].current_owner_status = VerificationStatus.VERIFIED_ONCHAIN
        graph = build_nft_graph(report)
        owns = next(e for e in graph["edges"] if e["type"] == "OWNS" and e["to"].endswith(NFT2))
        owner_node = next(n for n in graph["nodes"] if n["id"] == owns["from"])
        self.assertEqual(owner_node["kind"], "nft_item")
        self.assertFalse(any(n["kind"] == "ton_wallet" and n["address"] == NFT1 for n in graph["nodes"]))

    def test_verified_timeline_excludes_provider_observations(self):
        report = fixture()
        report.events[1].verification = VerificationStatus.PROVIDER_REPORTED
        graph = build_nft_graph(report)
        timeline = next(t for t in graph["ownership_timelines"] if t["asset_address"] == NFT1)
        self.assertEqual([e["event_id"] for e in timeline["segments"]], ["event-1"])
        self.assertEqual([e["event_id"] for e in timeline["unverified_transition_observations"]], ["event-2"])
        self.assertTrue(any(e["type"] == "NFT_TRANSITION_OBSERVATION" for e in graph["edges"]))

    def test_same_title_distinct_items_and_directed_transitions(self):
        graph = build_nft_graph(fixture())
        items = [n for n in graph["nodes"] if n["kind"] == "nft_item"]
        self.assertEqual({n["address"] for n in items}, {NFT1, NFT2})
        transitions = [e for e in graph["edges"] if e["type"] == "TRANSFERRED"]
        self.assertEqual(len(transitions), 2)
        self.assertEqual([(e["from"].split(":", 2)[-1], e["to"].split(":", 2)[-1]) for e in transitions], [(A, B), (B, C)])
        self.assertEqual({e["tx_hash"] for e in transitions}, {"samehash"})
        self.assertEqual(len({e["id"] for e in transitions}), 2)
        self.assertTrue(all(e["evidence_ids"] == ["proof"] for e in transitions))

    def test_current_owner_requires_verified_assertion(self):
        graph = build_nft_graph(fixture())
        owns = [e for e in graph["edges"] if e["type"] == "OWNS"]
        self.assertEqual(len(owns), 1)
        self.assertTrue(owns[0]["from"].endswith(C))
        self.assertTrue(any(e["type"] == "ASSOCIATED_WITH" and e["to"].endswith(NFT2) for e in graph["edges"]))

    def test_transfer_amount_not_sale_and_pending_not_transition(self):
        report = fixture()
        report.events[1].event_type = "transfer"
        report.events[1].status = "pending"
        graph = build_nft_graph(report)
        self.assertFalse(any(e["type"] in {"SOLD", "PURCHASED"} for e in graph["edges"]))
        self.assertEqual(sum(e["type"] == "TRANSFERRED" for e in graph["edges"]), 1)

    def test_listing_separate_from_sale(self):
        report = fixture()
        report.assets[0].listings = [NFTListing(asset_address=NFT1, listing_id="listing", status="active", marketplace="Getgems", price=Money(currency="TON", amount="88"), evidence_ids=["proof"])]
        report.events[0].marketplace = "Fragment"
        graph = build_nft_graph(report)
        listings = [e for e in graph["edges"] if e["type"] == "LISTED_ON"]
        self.assertEqual(len(listings), 1)
        self.assertEqual(listings[0]["price"]["amount"], "88")
        self.assertTrue(any(e["type"] == "INTERACTED_WITH" and e["to"].endswith("Fragment") for e in graph["edges"]))

    def test_public_assignment_never_wallet_control(self):
        report = fixture()
        report.assets[0].telegram = TelegramCollectible(asset_address=NFT1, kind="gift", assigned_entity="https://t.me/public_channel", assignment_status="publicly_verified", assignment_evidence_ids=["proof"])
        graph = build_nft_graph(report)
        association = next(e for e in graph["edges"] if e["to"].endswith("https://t.me/public_channel"))
        self.assertEqual(association["type"], "ASSOCIATED_WITH")
        self.assertIn("does not establish", association["explanation"])


class NFTExportTests(unittest.TestCase):
    def test_offline_nft_reexport_restores_matching_owner_wallet_snapshot(self):
        report = fixture()
        resolution = {"original_query": report.query, "object_type": "ton_domain_nft", "discovery_status": "resolved",
            "nft_item_address": NFT1, "collection_address": COLLECTION, "onchain_owner_address": A,
            "ownership_status": "verified_onchain", "evidence_ids": ["proof"], "owner_analysis_address": A,
            "owner_analysis_status": "complete", "owner_account_type": "wallet", "owner_account_evidence": {"status": "provider_reported"}}
        report.input_resolution = resolution
        report.assets[0].current_owner = A
        report.assets[0].ownership[0].owner_address = A
        saved = AddressReport(target_address=A, detected_chains=["ton"], input_resolution=resolution,
            balances=[Balance(chain="ton", address=A, asset="TON", amount=18.25, source="saved-owner-balance")],
            transactions=[Transaction(chain="ton", tx_hash="saved-owner-native-tx", from_address=A, to_address=B,
                amount=3, asset="TON", direction="out", source="saved-owner-analysis")])
        report.owner_analysis_snapshot = saved.model_dump(mode="json")
        with tempfile.TemporaryDirectory() as directory, patch("httpx.AsyncClient.send", new=AsyncMock(side_effect=AssertionError("Offline re-export made an HTTP request"))) as request, patch("app.exporters.html_exporter.AddressReport.model_validate", wraps=AddressReport.model_validate) as render_validation:
            paths = export_nft_dossier(report, Path(directory), language="en")
            html = paths["html"].read_text(encoding="utf-8")
            self.assertEqual(set(paths), {"html"})
            self.assertEqual({item.name for item in Path(directory).iterdir() if item.is_file()}, {"report.html"})
            request.assert_not_called()
            self.assertNotIn("owner_analysis_snapshot", render_validation.call_args.args[0]["nft_intelligence"])
            self.assertNotIn('"owner_analysis_snapshot"', html)
            payload = json.loads(re.search(r'<script id="nft-payload" type="application/json">(.*?)</script>', html, re.S).group(1))
            expected_nft = report.model_dump(mode="json")
            expected_nft.pop("owner_analysis_snapshot")
            expected_nft["owner_analysis_reference"] = {"location":"parent_address_report",
                "investigation_id":report.investigation_id,"exclude":["nft_intelligence"]}
            self.assertEqual(payload["report"], expected_nft)
            self.assertTrue(any(row["hash"] == "saved-owner-native-tx" for row in payload["transaction_views"]))
            machine = export_nft_machine_data(report, Path(directory) / "explicit-machine-export")
            exported = json.loads(machine["json"].read_text(encoding="utf-8"))
            self.assertEqual(exported["owner_analysis_snapshot"]["target_address"], A)
            self.assertEqual(exported["owner_analysis_snapshot"]["transactions"][0]["tx_hash"], "saved-owner-native-tx")
            self.assertEqual(exported["owner_analysis_snapshot"]["balances"][0]["amount"], 18.25)
        self.assertEqual(report.owner_analysis_snapshot, saved.model_dump(mode="json"))
        self.assertIn(f'<div class="target">{friendly_address(A)}</div>', html)
        self.assertIn("Original query: example.ton", html)
        self.assertIn("saved-owner-native-tx", html)
        self.assertIn("saved-owner-balance", html)
        self.assertIn("18.25", html)
        self.assertIn(NFT1, html)
        self.assertIn("unmodelled_trait", html)

    def test_offline_nft_reexport_rejects_mismatched_owner_snapshot_target(self):
        report = fixture()
        report.input_resolution = {"original_query": report.query, "owner_analysis_address": A}
        report.owner_analysis_snapshot = AddressReport(target_address=B, detected_chains=["ton"],
            balances=[Balance(chain="ton", address=B, asset="TON", amount=777, source="mismatched-owner-balance")],
            transactions=[Transaction(chain="ton", tx_hash="mismatched-owner-native-tx", source="mismatched-snapshot")]).model_dump(mode="json")
        from app.exporters.nft_exporter import _address_dossier
        projected = _address_dossier(report)
        self.assertNotEqual(projected.target_address, B)
        self.assertEqual(projected.balances, [])
        self.assertFalse(any(tx.tx_hash == "mismatched-owner-native-tx" for tx in projected.transactions))
        html = render_nft_dossier(report)
        payload = json.loads(re.search(r'<script id="nft-payload" type="application/json">(.*?)</script>', html, re.S).group(1))
        self.assertFalse(any(row["hash"] == "mismatched-owner-native-tx" for row in payload["transaction_views"]))

    def test_machine_only_export_preserves_original_wallet_html(self):
        with tempfile.TemporaryDirectory() as directory:
            html = Path(directory) / "report.html"
            html.write_text("original enriched wallet HTML", encoding="utf-8")
            paths = export_nft_machine_data(fixture(), Path(directory))
            self.assertNotIn("html", paths)
            self.assertEqual(html.read_text(encoding="utf-8"), "original enriched wallet HTML")
            self.assertEqual(set(paths), {"json", "events", "ownership", "transactions", "graph"})

    def test_exact_consideration_is_separate_from_nft_quantity(self):
        from app.exporters.html_exporter import _asset_history_amount, _transaction_views
        from app.ton_nft.service import report_to_address_report
        projected = report_to_address_report(fixture())
        rows = _transaction_views(projected, "en")
        self.assertTrue(all(row["amount"] == "" for row in rows))
        self.assertTrue(all(row["asset"].startswith("NFT:") for row in rows))
        self.assertEqual(rows[1]["consideration"], "2.0000000001 TON · sale consideration")
        self.assertIn("accompanying amount; not a sale price", rows[0]["consideration"])
        displayed, css = _asset_history_amount(projected.ton_assets[0].history_events[1], "out")
        self.assertEqual(displayed, "2.0000000001 TON · sale consideration")
        self.assertEqual(css, "")
        html = render_nft_dossier(fixture(), language="en")
        self.assertIn('class="asset-meta">2.0000000001 TON · sale consideration', html)

    def test_original_components_do_not_invent_current_owner_or_sale_price(self):
        from app.models.report import TelegramIdentity, TonAsset
        from app.exporters.html_exporter import _asset_paths, _username_history
        report = AddressReport(target_address=A, detected_chains=["ton"],
            telegram_identities=[TelegramIdentity(wallet_address=B, username="public", confidence="confirmed", source="fixture")],
            ton_assets=[TonAsset(asset_id=NFT1, type="username", title="observed", owner_address=C,
                floor_price=88, ownership_status="historical", source="fixture")])
        entries = _username_history(report, "en")["entries"]
        self.assertTrue(all(not item["current_owner"] for item in entries))
        self.assertTrue(all(not item["price"] for item in entries))
        self.assertFalse(any(step["kind"] == "current_owner" for path in _asset_paths(report) for step in path["steps"]))

    def test_browser_link_allowlist_rejects_private_and_nonpublic_urls(self):
        report = fixture()
        report.evidence[0].url = "https://[::ffff:127.0.0.1]/private"
        html = render_nft_dossier(report)
        payload = json.loads(re.search(r'<script id="nft-payload" type="application/json">(.*?)</script>', html, re.S).group(1))
        self.assertNotIn(report.evidence[0].url, payload["public_urls"])
        self.assertNotIn('href="https://[::ffff:127.0.0.1]', html)

    def test_default_export_is_only_original_html(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = export_nft_dossier(fixture(), Path(directory))
            self.assertEqual(set(paths), {"html"})
            self.assertEqual({p.name for p in Path(directory).glob("*") if p.is_file()}, {"report.html"})
            html = paths["html"].read_text(encoding="utf-8")
            self.assertIn('id="graphCanvas"', html)
            self.assertIn('id="txTimeline"', html)
            self.assertNotIn("Digital asset investigation", html)
            self.assertNotIn('href="nft/report.html"', html)
            self.assertFalse((Path(directory) / "nft").exists())

    def test_old_ownership_assertions_are_not_labelled_current(self):
        from app.exporters.nft_exporter import ownership_rows
        report = fixture()
        original = report.assets[0].ownership[0]
        report.assets[0].ownership.append(original.model_copy())
        rows = [r for r in ownership_rows(report) if r["asset_address"] == NFT1]
        self.assertEqual(sum(r["role"] == "current_assertion" for r in rows), 1)
        report.assets[0].current_owner_status = VerificationStatus.UNVERIFIED
        self.assertFalse(any(r["role"] == "current_assertion" for r in ownership_rows(report) if r["asset_address"] == NFT1))

    def test_public_gift_observations_have_separate_telegram_rows(self):
        report = fixture()
        report.public_collectibles = [{"identifier": "FixtureGift-1", "public_profile_mentions": ["Fixture Profile"],
            "attributes": {"Model": "Fixture"}, "identity_status": "unverified", "onchain_export_status": "unknown"}]
        html = render_nft_dossier(report)
        self.assertIn("public_collectibles", html)
        self.assertIn("unverified profile display", html)
        self.assertIn("FixtureGift-1", html)

    def test_browser_uint256_string_machine_json_integer(self):
        report = fixture()
        report.assets[0].index = 2 ** 255 + 123456789
        report.events[0].money.base_units = 2 ** 90
        html = render_nft_dossier(report)
        payload = json.loads(re.search(r'<script id="nft-payload" type="application/json">(.*?)</script>', html, re.S).group(1))
        self.assertEqual(payload["report"]["assets"][0]["index"], str(report.assets[0].index))
        self.assertEqual(payload["report"]["events"][0]["money"]["base_units"], str(2 ** 90))
        with tempfile.TemporaryDirectory() as directory:
            paths = export_nft_dossier(report, Path(directory), machine_exports=True)
            self.assertEqual(json.loads(paths["json"].read_text(encoding="utf-8"))["assets"][0]["index"], report.assets[0].index)

    def test_all_exports_preserve_actions_decimal_and_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = export_nft_dossier(fixture(), Path(directory), machine_exports=True)
            self.assertEqual(set(paths), {"html", "json", "events", "ownership", "transactions", "graph"})
            data = json.loads(paths["json"].read_text(encoding="utf-8"))
            self.assertEqual(len(data["events"]), 2)
            self.assertEqual(data["events"][0]["money"]["amount"], "1.000000001")
            self.assertEqual(data["assets"][0]["metadata"][0]["raw"]["unmodelled_trait"], [1, 2, 3])
            events = [json.loads(line) for line in paths["events"].read_text(encoding="utf-8").splitlines()]
            self.assertEqual([e["action_index"] for e in events], [0, 1])
            with paths["transactions"].open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 2)
            self.assertIn("proof", rows[0]["evidence_ids"])
            self.assertIn("1.000000001", rows[0]["money"])

    def test_render_escape_and_redact_secrets_and_unsafe_links(self):
        report = fixture().model_dump(mode="json")
        report["query"] = '</script><script>alert("unsafe")</script>'
        report["assets"][0]["raw"] = {"api_key": "must-not-export", "nested": {"Authorization": "Bearer abcdefgh"}, "url": "https://tonapi.io/path?api_key=must-not-export"}
        report["evidence"][0]["url"] = "javascript:alert(99)"
        html = render_nft_dossier(report)
        self.assertNotIn("must-not-export", html)
        self.assertNotIn("Bearer abcdefgh", html)
        self.assertNotIn('<script>alert("unsafe")</script>', html)
        encoded = re.search(r'<script id="nft-payload" type="application/json">(.*?)</script>', html, re.S).group(1)
        payload = json.loads(encoded)
        self.assertEqual(payload["report"]["events"][0]["evidence_ids"], ["proof"])
        self.assertFalse(any(e.get("evidence_url", "").startswith("javascript:") for e in payload["graph"]["edges"]))
        self.assertIn('id="graphCanvas"', html)
        self.assertIn('id="transactions"', html)
        self.assertNotIn('id="event-table"', html)

    def test_visual_paging_does_not_drop_large_backend_history(self):
        report = fixture()
        base = report.events[0]
        report.events = [base.model_copy(update={"event_id": f"event-{i}", "logical_time": i, "action_index": i}) for i in range(501)]
        with tempfile.TemporaryDirectory() as directory:
            paths = export_nft_dossier(report, Path(directory), machine_exports=True)
            self.assertEqual(len(json.loads(paths["json"].read_text(encoding="utf-8"))["events"]), 501)
            self.assertEqual(len(paths["events"].read_text(encoding="utf-8").splitlines()), 501)

    def test_csv_formula_guard(self):
        report = fixture()
        report.events[0].raw["formula"] = "=HYPERLINK(1)"
        report.events[0].provider_event_ids = ["@malicious"]
        from app.exporters.nft_exporter import _csv_cell
        self.assertEqual(_csv_cell(" =1+2"), "' =1+2")
        self.assertEqual(_csv_cell("ordinary"), "ordinary")

    def test_url_and_image_guards(self):
        for url in ["javascript:alert(1)", "file:///C:/secret", "http://127.0.0.1/x", "http://10.1.1.1/x", "https://localhost/x", "https://user:pass@tonapi.io/x"]:
            self.assertEqual(safe_href(url), "")
        self.assertEqual(safe_image_url("https://unknown-public.example/nft.png"), "")
        self.assertEqual(safe_image_url("https://i.toncdn.org/nft.png"), "https://i.toncdn.org/nft.png")

    def test_pdf_fallback_is_not_claimed_success(self):
        from app.exporters.pdf_exporter import PdfExportResult
        with patch("app.exporters.pdf_exporter.export_pdf_report_from_html", new=AsyncMock(return_value=PdfExportResult(Path("fallback.pdf"), rendered=False, error="Unavailable"))):
            with self.assertRaisesRegex(RuntimeError, "PDF rendering unavailable"):
                asyncio.run(export_nft_pdf(Path("input.html"), Path("output.pdf")))


class LegacyGraphRegressionTests(unittest.TestCase):
    def test_network_namespaces_and_aggregate_count(self):
        target = "0x" + "1" * 40
        receiver = "0x" + "2" * 40
        contract = "0x" + "3" * 40
        report = AddressReport(target_address=target, detected_chains=["eth", "bsc"], transactions=[
            Transaction(tx_hash="samehash", chain="eth", from_address=target, to_address=receiver, amount=1, asset="ETH", direction="out", source="fixture"),
            Transaction(tx_hash="secondhash", chain="eth", from_address=target, to_address=receiver, amount=2, asset="ETH", direction="out", source="fixture"),
            Transaction(tx_hash="samehash", chain="bsc", from_address=target, to_address=receiver, amount=3, asset="BNB", direction="out", source="fixture")],
            tokens=[TokenHolding(chain=chain, address=target, contract=contract, symbol="T", amount=1, source="fixture") for chain in ["eth", "bsc"]])
        graph = build_graph_payload(report)
        ids = {n["id"] for n in graph["nodes"]}
        self.assertIn("tx:eth:samehash", ids)
        self.assertIn("tx:bsc:samehash", ids)
        self.assertIn("asset:eth:" + contract, ids)
        self.assertIn("asset:bsc:" + contract, ids)
        aggregate = next(e for e in graph["edges"] if e["from"] == "wallet:eth:" + target and e["to"] == "wallet:eth:" + receiver)
        self.assertEqual(aggregate["count"], 2)

    def test_legacy_dossier_integrates_nft_in_one_html_and_guards_href(self):
        from app.exporters.html_exporter import export_html_report
        report = AddressReport(target_address=A, detected_chains=["ton"], nft_intelligence=fixture().model_dump(mode="json"))
        with tempfile.TemporaryDirectory() as directory:
            result = export_html_report(report, build_graph_payload(report), Path(directory))
            html = result.output_path.read_text(encoding="utf-8")
            self.assertNotIn('href="nft/report.html"', html)
            self.assertFalse((Path(directory) / "nft").exists())
            self.assertIn('id="nftCoverage"', html)
            self.assertIn('id="nft-payload"', html)
            self.assertFalse(re.search(r'href="(?:javascript:|file:|data:text)', html, re.I))


class BrowserDossierTests(unittest.IsolatedAsyncioTestCase):
    async def test_original_html_resolved_nft_and_owner_wallet_share_one_report(self):
        from app.exporters.html_exporter import export_html_report
        from test_nft_report_bridge import NFTReportBridgeTests, B, ITEM, COLLECTION
        from playwright.async_api import async_playwright
        report = NFTReportBridgeTests().resolved_owner_report()
        with tempfile.TemporaryDirectory() as directory:
            path = export_html_report(report, build_graph_payload(report), Path(directory), language="en").output_path
            async with async_playwright() as runtime:
                try:
                    browser = await runtime.chromium.launch(args=["--disable-background-networking"])
                except Exception as exc:
                    self.skipTest("Existing Chromium unavailable: " + type(exc).__name__)
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
                    await page.wait_for_function("document.getElementById('nftAssetSelect').options.length > 1")
                    self.assertEqual(await page.locator(".target").inner_text(), friendly_address(B))
                    self.assertIn("Original query: example.ton", await page.locator(".hero-copy").inner_text())
                    await page.locator("#inputResolution details > summary").first.click()
                    resolution = await page.locator("#inputResolution").inner_text()
                    for fact in ("example.ton", friendly_address(ITEM), friendly_address(COLLECTION), friendly_address(B), "verified_onchain", "provider_reported", "Source-reported owner account type"):
                        self.assertIn(fact, resolution)
                    self.assertEqual(await page.locator("#txTimeline .tx-row").count(), 2)
                    await page.locator("#txSearch").fill("owner-native")
                    await page.wait_for_function("document.querySelectorAll('#txTimeline .tx-row:not(.hidden)').length === 1")
                    await page.locator("#nftAssetSelect").select_option(ITEM)
                    self.assertIn("Fixture description", await page.locator("#nftAssetDetails").inner_text())
                    self.assertIn(friendly_address(B), await page.locator("#nftAssetDetails").inner_text())
                    await page.locator("#inputResolution").scroll_into_view_if_needed()
                    for width in (390, 320):
                        await page.set_viewport_size({"width": width, "height": 844})
                        self.assertTrue(await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"))
                    self.assertEqual(errors, [])
                finally:
                    await browser.close()

    async def test_original_html_paging_filter_exact_index_graph_and_mobile(self):
        asyncio.get_running_loop().slow_callback_duration = 5
        from playwright.async_api import async_playwright
        report = fixture()
        report.assets[0].index = 2 ** 255 + 99
        base = report.events[0]
        report.events = [base.model_copy(update={"event_id": f"ui-event-{i}", "logical_time": i, "transaction_hash": "unique-final" if i == 500 else "hash-" + str(i)}) for i in range(501)]
        with tempfile.TemporaryDirectory() as directory:
            paths = export_nft_dossier(report, Path(directory))
            self.assertEqual(set(paths), {"html"})
            async with async_playwright() as runtime:
                try:
                    browser = await runtime.chromium.launch(args=["--disable-background-networking"])
                except Exception as exc:
                    self.skipTest("Existing Chromium unavailable: " + type(exc).__name__)
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
                    await page.goto(paths["html"].resolve().as_uri())
                    await page.wait_for_function("document.getElementById('nftAssetSelect').options.length > 1")
                    self.assertEqual(await page.locator("#txTimeline .tx-row").count(), 260)
                    await page.locator("#txPageNext").click()
                    self.assertEqual(await page.locator("#txTimeline .tx-row").count(), 241)
                    await page.locator("#txSearch").fill("unique-final")
                    await page.wait_for_timeout(200)
                    self.assertEqual(await page.locator("#txTimeline .tx-row:not(.hidden)").count(), 1)
                    index = await page.evaluate("JSON.parse(document.getElementById('nft-payload').textContent).report.assets[0].index")
                    self.assertEqual(index, str(report.assets[0].index))
                    await page.locator("#nftOwnershipTimeline > summary").click()
                    await page.wait_for_function("document.querySelectorAll('#nftTraceRows > .item').length === 50")
                    self.assertEqual(await page.locator("#nftTraceRows > .item").count(), 50)
                    await page.locator("#assets").scroll_into_view_if_needed()
                    await page.locator("#nftAssetSelect").select_option(NFT1)
                    await page.wait_for_function("document.getElementById('nftAssetDetails').textContent.includes('Current verified owner')")
                    await page.locator("#nftAssetDetails").scroll_into_view_if_needed()
                    self.assertIn("Current verified owner", await page.locator("#nftAssetDetails").inner_text())
                    self.assertIn(str(report.assets[0].index), await page.locator("#nftAssetDetails").inner_text())
                    self.assertEqual(await page.locator("#graphCanvas").count(), 1)
                    self.assertEqual(await page.locator("#graph3d").count(), 1)
                    self.assertEqual(await page.evaluate("getComputedStyle(document.documentElement).getPropertyValue('--green').trim()"), "#64d47d")
                    for width in (390, 320):
                        await page.set_viewport_size({"width": width, "height": 844})
                        self.assertTrue(await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"))
                    self.assertEqual(errors, [])
                finally:
                    await browser.close()



if __name__ == "__main__":
    unittest.main()
