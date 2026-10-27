"""Offline regressions for the original AddressReport NFT projection."""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import hashlib
from pathlib import Path
import re
import tempfile
import unittest

from app.exporters.ton_presentation import friendly_address
from app.models.report import (ActivityChain, AddressReport, Balance, Counterparty,
                              TonAsset, Transaction, WalletTimeline)
from app.ton_nft.models import (CollectionCoverage, DiscoveryCandidate, DiscoveryResult,
    IntelligenceEvidence, Money, NFTAsset, NFTCollection, NFTEvent, NFTIntelligenceReport,
    NFTMetadataSnapshot, NFTOwnershipAssertion, NFTPortfolio, SourceObservation,
    TelegramCollectible, VerificationStatus)
from app.ton_nft.service import attach_nft_intelligence, report_to_address_report


A, B, ITEM, OTHER, COLLECTION = ["0:" + char * 64 for char in "12345"]
HASH, TRACE = "a" * 64, "b" * 64
WHEN = datetime(2024, 1, 1, tzinfo=timezone.utc)


def fixture_report():
    return NFTIntelligenceReport(investigation_id="bridge-fixture", query="example.ton", status="partial",
        updated_at=WHEN, discovery=DiscoveryResult(normalized_query="example.ton", query_kind="domain",
            status="resolved", candidates=[DiscoveryCandidate(address=ITEM, reason="Exact fixture lookup")]),
        collections=[NFTCollection(address=COLLECTION, name="Fixture Collection")],
        assets=[NFTAsset(asset_id=ITEM, address=ITEM, collection_address=COLLECTION, index=2, kind="domain",
            name="example.ton", description="Fixture description", image_url="https://example.com/nft.png",
            metadata_uri="ipfs://fixture", attributes=[{"trait_type": "Model", "value": "Fixture"}],
            metadata=[NFTMetadataSnapshot(source="fixture_provider", normalized={"name": "example.ton", "description": "Fixture description"})],
            current_owner=B, current_owner_status=VerificationStatus.VERIFIED_ONCHAIN, evidence_ids=["proof"],
            ownership=[NFTOwnershipAssertion(asset_address=ITEM, owner_address=B,
                status=VerificationStatus.VERIFIED_ONCHAIN, method="get_nft_data", observed_at=WHEN,
                logical_time=100, evidence_ids=["proof"])],
            historical_owners=[{"address": A}, {"address": B}],
            ownership_summary={"history_status": "partial", "first_observed_transaction": HASH})],
        events=[NFTEvent(event_id="transfer-action", asset_address=ITEM, event_type="transfer", status="success",
            from_address=A, to_address=B, timestamp=WHEN, transaction_hash=HASH, logical_time=100, action_index=0,
            verification=VerificationStatus.VERIFIED_ONCHAIN, evidence_ids=["proof"], observation_ids=["raw"],
            fee=Money(currency="TON", base_units=2, decimals=9, amount=Decimal("0.000000002")))],
        evidence=[IntelligenceEvidence(evidence_id="proof", source="fixture_provider", upstream="fixture",
            observation_id="raw", relation="nft_contract_state", status=VerificationStatus.VERIFIED_ONCHAIN,
            explanation="Fixture evidence", url="https://example.com/proof", collected_at=WHEN)],
        observations=[SourceObservation(observation_id="raw", source="fixture_provider", upstream="fixture",
            endpoint="https://example.com/item", content_hash="digest", raw_ref="sqlite:fixture:raw", collected_at=WHEN)],
        coverage=[CollectionCoverage(scope="history:" + ITEM, source="fixture_provider", upstream="fixture",
            status="budget_limit", coverage_status="TRUNCATED", records=1, pages=1,
            gap_reason="Fixture page budget", next_cursor="100")])


class NFTReportBridgeTests(unittest.TestCase):
    def resolved_owner_report(self):
        report = AddressReport(target_address=B, detected_chains=["ton"],
            balances=[Balance(chain="ton", address=B, asset="TON", amount=12, source="owner_provider")],
            transactions=[Transaction(chain="ton", tx_hash="owner-native", from_address=B, to_address=A,
                amount=3, asset="TON", direction="out", source="owner_provider")])
        attach_nft_intelligence(report, fixture_report())
        report.input_resolution = {"original_query": "example.ton", "object_type": "ton_domain_nft",
            "discovery_status": "resolved", "nft_item_address": ITEM, "collection_address": COLLECTION,
            "onchain_owner_address": B, "ownership_status": "verified_onchain", "evidence_ids": ["proof"],
            "owner_analysis_address": B, "owner_analysis_status": "complete", "owner_account_type": "wallet",
            "owner_account_evidence": {"source": "fixture_provider", "status": "provider_reported", "is_wallet": True},
            "notes": ["Owner wallet classification is source reported; no personal identity assertion."]}
        return report

    def test_unified_original_html_separates_input_nft_from_owner_analysis(self):
        from app.exporters.html_exporter import export_html_report
        from app.graph.builder import build_graph_payload
        report = self.resolved_owner_report()
        report = AddressReport.model_validate_json(report.model_dump_json())
        with tempfile.TemporaryDirectory() as directory:
            path = export_html_report(report, build_graph_payload(report), Path(directory), language="en").output_path
            html = path.read_text(encoding="utf-8")
            self.assertEqual({item.name for item in Path(directory).iterdir() if item.is_file()}, {"report.html"})
        self.assertIn(f'<div class="target">{friendly_address(B)}</div>', html)
        self.assertIn("Original query: example.ton", html)
        resolution = re.search(r'<div class="list" id="inputResolution">(.*?)<div class="item"><b>TON NFT', html, re.S).group(1)
        for value in [friendly_address(ITEM), friendly_address(COLLECTION), friendly_address(B), "verified_onchain", "provider_reported", "fixture_provider", "proof", "Owner analysis address"]:
            self.assertIn(value, resolution)
        self.assertIn('href="https://example.com/proof"', resolution)
        self.assertIn("Fixture description", html)
        self.assertIn("owner-native", html)
        self.assertIn("owner_provider", html)
        self.assertIn('id="txTimeline"', html)
        self.assertIn('id="graphCanvas"', html)
        self.assertNotIn('href="nft/report.html"', html)

    def test_original_graph_uses_one_owner_node_and_one_supported_ownership_edge(self):
        from app.graph.builder import build_graph_payload, _wallet_node_id, _asset_node_id
        report = self.resolved_owner_report()
        graph = build_graph_payload(report)
        self.assertEqual(graph["target"], _wallet_node_id("ton", B))
        self.assertEqual(sum(node["id"] == _wallet_node_id("ton", B) for node in graph["nodes"]), 1)
        self.assertFalse(any(node["id"] == "ton_address:ton:" + B for node in graph["nodes"]))
        owns = [edge for edge in graph["edges"] if edge["type"] == "owns"
                and edge["from"] == graph["target"] and edge["to"] == _asset_node_id(ITEM)]
        self.assertEqual(len(owns), 1)
        self.assertEqual(owns[0]["count"], 1)
        self.assertEqual(owns[0]["evidence_ids"], ["proof"])
        self.assertEqual(owns[0]["confirmation"], "verified_onchain")
        self.assertIn("https://example.com/proof", owns[0]["evidence_urls"])
        self.assertEqual(graph["input_resolution"], report.input_resolution)
        target = next(node for node in graph["nodes"] if node["id"] == graph["target"])
        self.assertEqual(target["owner_account_evidence"]["status"], "provider_reported")

    def test_resolution_dict_alone_does_not_fabricate_owner_or_identity_edges(self):
        from app.graph.builder import build_graph_payload
        report = AddressReport(target_address=ITEM, detected_chains=["ton"], input_resolution={
            "original_query": "unresolved.ton", "nft_item_address": ITEM,
            "onchain_owner_address": B, "ownership_status": "unverified", "owner_analysis_status": "skipped"})
        graph = build_graph_payload(report)
        self.assertFalse(any(edge["type"] in {"owns", "same_address", "linked_by"} for edge in graph["edges"]))
        self.assertEqual(len(graph["nodes"]), 1)

    def test_unresolved_human_identifier_is_activity_not_wallet_or_owner(self):
        from app.graph.builder import build_graph_payload
        from app.exporters.html_exporter import export_html_report
        for status in ("unresolved", "ambiguous", "unsupported", "not_found"):
            with self.subTest(status=status):
                report = AddressReport(target_address="not-resolved.ton", detected_chains=["ton"],
                    input_resolution={"original_query": "not-resolved.ton", "discovery_status": status,
                        "ownership_status": "unknown", "owner_analysis_status": "skipped"})
                graph = build_graph_payload(report)
                root = next(node for node in graph["nodes"] if node["id"] == graph["target"])
                self.assertEqual(root["kind"], "activity")
                self.assertEqual(root["asset_type"], "input_identifier")
                self.assertIn("no verified account or owner assertion", root["title"])
                self.assertFalse(any(node["kind"] == "wallet" for node in graph["nodes"]))
                self.assertEqual(graph["edges"], [])
                with tempfile.TemporaryDirectory() as directory:
                    html = export_html_report(report, graph, Path(directory), language="en").output_path.read_text(encoding="utf-8")
                self.assertIn('id="graphCanvas"', html)
                self.assertIn('id="inputResolution"', html)
                self.assertIn('"asset_type": "input_identifier"', html)

    def test_valid_ton_address_keeps_legacy_kind_when_discovery_is_unresolved(self):
        from app.graph.builder import build_graph_payload
        report = AddressReport(target_address=A, detected_chains=["ton"],
            input_resolution={"original_query": A, "discovery_status": "unresolved"})
        graph = build_graph_payload(report)
        self.assertEqual(next(node for node in graph["nodes"] if node["id"] == graph["target"])["kind"], "wallet")

    def test_resolution_rendering_redacts_secrets_and_filters_source_links(self):
        from app.exporters.html_exporter import export_html_report
        from app.graph.builder import build_graph_payload
        report = self.resolved_owner_report()
        report.input_resolution["original_query"] = '<script>alert("query")</script>'
        report.input_resolution["owner_account_evidence"]["api_key"] = "resolution_secret"
        report.nft_intelligence["evidence"][0]["url"] = "javascript:alert(1)"
        with tempfile.TemporaryDirectory() as directory:
            html = export_html_report(report, build_graph_payload(report), Path(directory)).output_path.read_text(encoding="utf-8")
        self.assertNotIn("resolution_secret", html)
        self.assertNotIn('<script>alert("query")</script>', html)
        self.assertNotIn('href="javascript:', html)
        self.assertIn("&lt;script&gt;", html)

    def _without_transaction_origin_additions(self, script):
        extension=r"(?m)^[ \t]*// GANSAR_INFERENTIAL_BEGIN\n.*?^[ \t]*// GANSAR_INFERENTIAL_END\n"
        self.assertEqual(len(list(re.finditer(extension,script,re.S))),4)
        script=re.sub(extension,"",script,flags=re.S|re.M)
        call="${transactionOriginMarkup(tx)}"
        self.assertEqual(script.count(call),1)
        script=script.replace(call,"")
        for name in ("", "_INSPECTOR"):
            pattern=r"(?m)^[ \t]*// GANSAR_TRANSACTION_ORIGIN"+name+r"_BEGIN\n.*?^[ \t]*// GANSAR_TRANSACTION_ORIGIN"+name+r"_END\n"
            self.assertEqual(len(list(re.finditer(pattern,script,re.S))),1)
            script=re.sub(pattern,"",script,flags=re.S|re.M)
        return script

    def test_original_css_and_approved_service_javascript_are_preserved(self):
        template = (Path(__file__).resolve().parents[1] / "app/exporters/investigation_template.html").read_text(encoding="utf-8")
        for pattern, expected in [(r"<style>(.*?)</style>", "617e933a0973854d1fafb1a2501c9ce3aeae224553e733e742595e293b7801d7"),
                # Approved 2026-10-23 3D patch; original CSS remains unchanged.
                (r"<script>(.*?)</script>", "20b00dff4ecdd4c40c92bf93173cf362f553ac6665a242c98059f705a7e92d1d")]:
            content=(next(part for part in re.findall(pattern, template, re.S) if "const graphData =" in part) if pattern.startswith(r"<script>") else re.search(pattern, template, re.S).group(1))
            if pattern.startswith(r"<script>"):
                addition="${detail('POSSIBLE / INVESTIGATIVE LEADS · signing client unconfirmed',client.investigative_leads)}"
                self.assertEqual(content.count(addition),1)
                content=content.replace(addition,"")
                content=self._without_transaction_origin_additions(content)
            self.assertEqual(hashlib.sha256(content.encode()).hexdigest(), expected)

    def test_approved_friendly_javascript_outside_explicit_source_transport_is_byte_identical(self):
        template = (Path(__file__).resolve().parents[1] / "app/exporters/investigation_template.html").read_text(encoding="utf-8")
        script = next(part for part in re.findall(r"<script>(.*?)</script>", template, re.S) if "const graphData =" in part)
        addition="${detail('POSSIBLE / INVESTIGATIVE LEADS · signing client unconfirmed',client.investigative_leads)}"
        self.assertEqual(script.count(addition),1)
        script=script.replace(addition,"")
        script=self._without_transaction_origin_additions(script)
        for name in ("", "_DISCLOSURE", "_PROOF_TOGGLE", "_PROOF"):
            pattern = r"(?m)^[ \t]*// GANSAR_SOURCE_TRANSPORT" + name + r"_BEGIN\n.*?^[ \t]*// GANSAR_SOURCE_TRANSPORT" + name + r"_END\n"
            matches = list(re.finditer(pattern, script, re.S))
            self.assertEqual(len(matches), 1)
            replacement = ""
            if name == "_PROOF":
                replacement = matches[0].group().splitlines()[1] + "\n"
                replacement, count = re.subn(r"\$\{serviceSourceTransport \? `<details><summary>Source facts</summary><pre class=\"mono\">\$\{json\(proof.facts\)\}</pre></details>` \+ `.*?` : `<details><summary>Source facts</summary><pre class=\"mono\">\$\{json\(fullServiceFacts\(proof.facts\)\)\}</pre></details>`\}",
                    "${json(fullServiceFacts(proof.facts))}", replacement)
                self.assertEqual(count, 1)
            script = re.sub(pattern, lambda _: replacement, script, flags=re.S | re.M)
        self.assertEqual(hashlib.sha256(script.encode()).hexdigest(),
            "86e659f7fbd409ae88eb93614e067cdd7a401658495544ff8b5dc4a228aabdd1")

    def test_projects_real_asset_ownership_metadata_history_and_provenance(self):
        projected = report_to_address_report(fixture_report())
        self.assertEqual(projected.target_address, ITEM)
        self.assertEqual(projected.balances, [])
        asset = projected.ton_assets[0]
        self.assertEqual((asset.asset_id, asset.collection, asset.image_url), (ITEM, "Fixture Collection", "https://example.com/nft.png"))
        self.assertEqual(asset.owner_address, B)
        self.assertTrue(asset.ownership_verified)
        self.assertEqual(asset.ownership_observed_at, WHEN)
        self.assertEqual(asset.previous_owners, [A])
        self.assertEqual(asset.history_events[0].event_id, "transfer-action")
        self.assertEqual(asset.history_events[0].logical_time, 100)
        self.assertEqual(asset.transfer_history, asset.history_events)
        self.assertEqual(asset.raw["ownership_assertions"][0]["method"], "get_nft_data")
        self.assertEqual(asset.raw["metadata"]["description"], "Fixture description")
        transaction = projected.transactions[0]
        self.assertEqual(transaction.source, "fixture_provider")
        self.assertEqual(Decimal(transaction.raw["fee_money"]["amount"]), Decimal("0.000000002"))
        self.assertEqual(transaction.provenance[-1]["raw_ref"], "sqlite:fixture:raw")
        self.assertEqual(projected.source_health[0].status, "partial")
        self.assertIn("TRUNCATED", projected.source_health[0].details)
        self.assertEqual(projected.coverage["ton_nft"][0]["next_cursor"], "100")
        self.assertEqual(projected.wallet_timeline.first_activity, WHEN)

    def test_preserves_distinct_actions_sale_precision_failed_status_and_trace(self):
        report = fixture_report()
        price = Decimal("123456789012.345678901")
        for index, kind, status in [(1, "sale", "success"), (2, "bid", "failed"), (3, "listing", "pending")]:
            report.events.append(NFTEvent(event_id=f"action-{index}", asset_address=ITEM, event_type=kind,
                status=status, transaction_hash=HASH, action_index=index, logical_time=100, from_address=A, to_address=B,
                money=Money(currency="TON", amount=price, base_units=123456789012345678901, decimals=9), evidence_ids=["proof"]))
        report.events.append(NFTEvent(event_id="trace-action", asset_address=ITEM, event_type="contract_interaction",
            trace_id=TRACE, action_index=4, status="unknown", money=Money(currency="TON", amount=Decimal("0.000000001"), base_units=1, decimals=9)))
        projected = report_to_address_report(report)
        self.assertEqual(len(projected.transactions), 5)
        events = projected.ton_assets[0].history_events
        self.assertEqual(len({item.event_id for item in events}), 5)
        self.assertEqual(events[1].price_decimal, price)
        self.assertIsNone(events[2].price_decimal)
        self.assertFalse(events[2].success)
        self.assertEqual(len(projected.ton_assets[0].sale_history), 1)
        sale = next(item for item in projected.transactions if item.event_id == "action-1")
        self.assertIsNone(sale.amount_decimal)  # consideration is not NFT quantity or money movement
        self.assertEqual(sale.raw["money"]["amount"], str(price))
        self.assertEqual(sale.asset, "NFT:" + ITEM)
        interaction = next(item for item in projected.transactions if item.event_id == "trace-action")
        self.assertEqual(interaction.tx_hash, "")
        self.assertEqual(interaction.raw["trace_id"], TRACE)
        self.assertEqual(interaction.amount_decimal, Decimal("0.000000001"))
        self.assertIsNone(interaction.success)

    def test_unverified_or_failed_transfers_do_not_become_verified_ownership(self):
        report = fixture_report()
        report.assets[0].current_owner_status = VerificationStatus.UNVERIFIED
        report.events[0].verification = VerificationStatus.PROVIDER_REPORTED
        report.events.append(report.events[0].model_copy(update={"event_id": "failed", "status": "failed"}))
        projected = report_to_address_report(report)
        self.assertFalse(projected.ton_assets[0].ownership_verified)
        self.assertEqual(projected.ton_assets[0].ownership_status, "unknown")
        self.assertEqual(projected.ton_assets[0].transfer_history, [])
        self.assertEqual(len(projected.ton_assets[0].history_events), 2)

    def test_unresolved_predicted_candidate_keeps_query_and_no_fabricated_item(self):
        report = fixture_report()
        report.discovery.status = "unresolved"
        report.assets = []
        report.events = []
        projected = report_to_address_report(report)
        self.assertEqual(projected.target_address, "example.ton")
        self.assertEqual(projected.ton_assets, [])
        self.assertEqual(projected.transactions, [])

    def test_public_gift_metadata_stays_separate_from_wallet_person_identity(self):
        report = fixture_report()
        report.assets = []
        report.events = []
        report.discovery.status = "unresolved"
        report.public_collectibles = [{"identifier": "https://t.me/nft/Fixture-1", "url": "https://t.me/nft/Fixture-1",
            "attributes": {"Model": "Fixture"}, "public_profile_mentions": ["Public display profile"], "evidence_ids": ["proof"]}]
        projected = report_to_address_report(report)
        identity = projected.telegram_identities[0]
        self.assertEqual(identity.wallet_address, "")
        self.assertEqual(identity.confidence, "unknown")
        self.assertFalse(identity.identity_verified)
        self.assertIsNone(identity.username)
        self.assertEqual(identity.raw["public_collectible"]["attributes"]["Model"], "Fixture")
        self.assertEqual(projected.ton_assets, [])

    def test_collectible_username_ownership_does_not_confirm_person(self):
        report = fixture_report()
        report.assets[0].kind = "username"
        report.assets[0].telegram = TelegramCollectible(asset_address=ITEM, kind="username", username="fixture",
            ownership_evidence_ids=["proof"], collection_verified=True)
        identity = report_to_address_report(report).telegram_identities[0]
        self.assertEqual(identity.wallet_address, B)
        self.assertEqual(identity.username, "fixture")
        self.assertEqual(identity.confidence, "unknown")
        self.assertFalse(identity.identity_verified)
        self.assertEqual(identity.raw["collectible"]["assignment_status"], "unknown")

    def test_attachment_preserves_wallet_observations_analyses_and_is_idempotent(self):
        native = Transaction(chain="ton", tx_hash="native", from_address=B, to_address=A, amount=3,
                             asset="TON", direction="out", source="legacy")
        balance = Balance(chain="ton", address=B, asset="TON", amount=5, source="legacy")
        chain = ActivityChain(chain_type="asset_path", title="Legacy", summary="Retain", source="legacy")
        timeline = WalletTimeline(first_activity=WHEN)
        legacy_asset = TonAsset(asset_id=ITEM, type="domain", name="Legacy name", owner_address=A, source="legacy")
        other = TonAsset(asset_id=OTHER, type="nft", title="example.ton", source="legacy")
        report = AddressReport(target_address=B, balances=[balance], transactions=[native], ton_assets=[legacy_asset, other],
            activity_chains=[chain], wallet_timeline=timeline, financial_summary={"TON": {"in": Decimal(5)}},
            counterparties=[Counterparty(chain="ton", address=A, tx_count=3, total_out=3)])
        investigation = fixture_report()
        investigation.portfolio = NFTPortfolio(wallet_address=B, counterparties=[{"address": A, "event_count": 1}],
            financial_totals={"TON": {"sale_out": Decimal(10)}})
        self.assertIs(attach_nft_intelligence(report, investigation), report)
        attach_nft_intelligence(report, investigation)
        self.assertEqual(report.target_address, B)
        self.assertIs(report.balances[0], balance)
        self.assertIs(report.transactions[0], native)
        self.assertIs(report.activity_chains[0], chain)
        self.assertIs(report.wallet_timeline, timeline)
        self.assertEqual(report.financial_summary["TON"]["in"], 5)
        self.assertEqual(len(report.transactions), 2)
        self.assertEqual(len(report.ton_assets), 2)
        self.assertEqual(len(report.ton_assets[0].history_events), 1)
        self.assertEqual(report.ton_assets[0].owner_address, B)
        self.assertEqual(report.ton_assets[0].name, "Legacy name")
        self.assertEqual(len(report.ton_assets[0].raw["prior_ownership_observations"]), 1)
        self.assertEqual(report.counterparties[0].tx_count, 3)
        self.assertEqual(report.nft_intelligence["portfolio"]["financial_totals"]["TON"]["sale_out"], "10")

    def test_attachment_matches_exact_provider_action_and_retains_provenance(self):
        report = fixture_report()
        report.events[0].raw["corroborating_observations"] = [{"trace_id": TRACE, "action_index": 2,
            "asset_address": ITEM, "from_address": A, "to_address": B}]
        legacy_action = Transaction(chain="ton", tx_hash=TRACE, from_address=A, to_address=B,
            asset="NFT:" + ITEM, source="tonapi", event_id="legacy-action",
            raw={"provider": "tonapi_events", "event_id": TRACE, "action_index": 2, "legacy": True})
        distinct = legacy_action.model_copy(deep=True, update={"event_id": "distinct"})
        distinct.raw["action_index"] = 3
        existing = AddressReport(target_address=B, transactions=[legacy_action, distinct])
        attach_nft_intelligence(existing, report)
        self.assertEqual(len(existing.transactions), 2)
        self.assertTrue(existing.transactions[0].raw["legacy"])
        self.assertEqual(existing.transactions[0].raw["nft_event_id"], "transfer-action")
        self.assertGreaterEqual(len(existing.transactions[0].provenance), 3)
        self.assertNotIn("nft_event_id", existing.transactions[1].raw)
        attach_nft_intelligence(existing, report)
        self.assertEqual(len(existing.transactions), 2)

    def test_projection_redacts_full_report_extra_fields_and_query_secrets(self):
        report = fixture_report()
        report.query = "https://example.com/nft?apikey=fixture_secret"
        report.assets[0].raw["authorization"] = "Bearer fixture_secret"
        projected = report_to_address_report(report)
        self.assertNotIn("fixture_secret", projected.model_dump_json())

    def test_original_graph_types_verified_nft_root_and_nft_contract_owner(self):
        from app.graph.builder import build_graph_payload, _wallet_node_id
        report = fixture_report()
        report.assets[0].standard_status = VerificationStatus.VERIFIED_ONCHAIN
        report.assets[0].collection_status = VerificationStatus.VERIFIED_ONCHAIN
        report.assets[0].current_owner = OTHER
        report.assets[0].ownership[0].owner_address = OTHER
        report.assets.append(NFTAsset(asset_id=OTHER, address=OTHER, name="Owner contract",
            standard_status=VerificationStatus.VERIFIED_ONCHAIN, current_owner=A,
            current_owner_status=VerificationStatus.PROVIDER_REPORTED))
        graph = build_graph_payload(report_to_address_report(report))
        nodes = {item["id"]: item for item in graph["nodes"]}
        self.assertEqual(nodes[graph["target"]]["kind"], "domain")
        self.assertEqual(nodes[_wallet_node_id("ton", OTHER)]["kind"], "nft")
        self.assertEqual(nodes[_wallet_node_id("ton", A)]["kind"], "wallet")

    def test_original_graph_maps_added_nft_item_to_existing_kind(self):
        from app.graph.builder import build_graph_payload, _asset_node_id
        report = fixture_report()
        unknown_item = "0:" + "6" * 64
        report.events.append(NFTEvent(event_id="other-observation", asset_address=unknown_item,
            event_type="unknown", status="unknown"))
        graph = build_graph_payload(report_to_address_report(report))
        nodes = {item["id"]: item for item in graph["nodes"]}
        self.assertEqual(nodes[_asset_node_id(unknown_item)]["kind"], "nft")
        self.assertNotIn("nft_item", {item["kind"] for item in graph["nodes"]})

    def test_original_graph_keeps_unverified_address_and_non_ton_kinds(self):
        from app.graph.builder import build_graph_payload
        report = fixture_report()  # provider metadata alone does not classify root as NFT
        graph = build_graph_payload(report_to_address_report(report))
        self.assertEqual(next(item for item in graph["nodes"] if item["id"] == graph["target"])["kind"], "wallet")
        graph = build_graph_payload(AddressReport(target_address="0x" + "1" * 40, detected_chains=["eth"]))
        self.assertEqual(next(item for item in graph["nodes"] if item["id"] == graph["target"])["kind"], "ethereum_wallet")


if __name__ == "__main__":
    unittest.main()
