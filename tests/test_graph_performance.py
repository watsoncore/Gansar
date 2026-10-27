"""Semantic parity for graph indexes, redaction, and attribution evidence."""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import unittest
from unittest.mock import patch

from app.graph.builder import build_graph_payload, _wallet_node_id
from app.graph.nft_builder import _sanitize_graph, build_nft_graph
from app.graph import nft_builder
from app.models.report import AddressReport, Transaction
from app.utils.security import sanitize_observation


A, B, C = ["0:" + value * 64 for value in "123"]


class GraphIndexParityTests(unittest.TestCase):
    def test_repeated_public_evidence_url_is_validated_once_per_graph(self):
        data = {"assets": [{"asset_id": A, "address": A}],
            "events": [{"event_id": str(index), "asset_address": A, "status": "unknown", "evidence_ids": ["proof"]}
                       for index in range(100)],
            "evidence": [{"evidence_id": "proof", "source": "fixture", "url": "https://example.com/proof"}]}
        with patch.object(nft_builder, "safe_public_url", wraps=nft_builder.safe_public_url) as validate:
            graph = build_nft_graph(data)
        self.assertEqual(validate.call_count, 1)
        self.assertEqual(graph["stats"]["events"], 100)
        self.assertEqual(sum(edge["type"] == "VERIFIED_BY" for edge in graph["edges"]), 100)

    def test_incident_index_matches_original_scan_counts_including_self_loop(self):
        report = AddressReport(target_address=A, detected_chains=["ton"], transactions=[
            Transaction(chain="ton", tx_hash=str(index), source="fixture", from_address=sender,
                        to_address=receiver, asset="TON", amount=1, direction="out")
            for index, (sender, receiver) in enumerate(((A, B), (A, B), (B, A), (A, A)))])
        graph = build_graph_payload(report)
        for node in graph["nodes"]:
            incident = [edge for edge in graph["edges"] if edge["from"] == node["id"] or edge["to"] == node["id"]]
            self.assertEqual(node["relationship_count"], len(incident))
            self.assertEqual(node["tx_count"], sum(int(edge.get("count") or 1) for edge in incident))

    def test_memoized_graph_redaction_matches_shared_rules_without_container_aliasing(self):
        shared = {"api_key": "fixture_key", "url": "https://user:pass@example.com/a?token=public&apikey=fixture_secret",
                  "text": "Bearer fixture_token authClientToken=fixture_private", "amount": Decimal("1.234"),
                  "at": datetime(2026, 1, 1, tzinfo=timezone.utc)}
        raw = {"first": shared, "second": shared, "items": (shared, "Bearer fixture_token"), 12: "safe"}
        actual = _sanitize_graph(raw)
        self.assertEqual(actual, sanitize_observation(raw))
        actual["first"]["url"] = "changed"
        self.assertNotEqual(actual["second"]["url"], "changed")
        self.assertEqual(shared["api_key"], "fixture_key")

    def test_marketplace_index_preserves_insertion_order_and_collection_proofs(self):
        data = {"collections": [{"address": C, "name": "First", "known_registry_kind": "gift"},
                                {"address": C, "name": "Second"}],
            "assets": [{"asset_id": A, "address": A, "collection_address": C,
                "collection_status": "verified_onchain", "current_owner": B,
                "current_owner_status": "verified_onchain", "ownership": [{"owner_address": B, "status": "verified_onchain"}],
                "listings": [{"listing_id": "listing", "status": "active", "marketplace_address": B, "sale_contract": B}]}],
            "events": [{"event_id": "transfer", "asset_address": A, "event_type": "transfer", "status": "success",
                        "verification": "verified_onchain", "from_address": B, "to_address": C}], "evidence": [], "coverage": []}
        graph = build_nft_graph(data)
        self.assertTrue(any(edge["type"] == "REGISTERED_IN" and edge["registry_kind"] == "gift" for edge in graph["edges"]))
        transition = next(edge for edge in graph["edges"] if edge["type"] == "TRANSFERRED")
        self.assertEqual(transition["from"], "marketplace:ton:" + B)
        self.assertEqual(transition["to"], "nft_collection:ton:" + C)
        self.assertEqual(graph["ownership_timelines"][0]["segments"][0]["event_id"], "transfer")

    def test_service_attribution_is_additive_provenance_with_no_application_inference(self):
        report = AddressReport(target_address=A, detected_chains=["ton"], ton_service_intelligence={
            "addresses": {A: {"contract": {"wallet_version": "v4r2"},
                "client_attribution": {"status": "UNKNOWN", "reason": "Shared wallet code"},
                "attributions": [{"attribution_id": "label", "service_id": "xrocket", "name": "xRocket", "status": "POSSIBLE",
                    "method": "provider_label", "reason": "Public provider label", "evidence_ids": ["label-proof"]}]},
                B: {"contract": {"wallet_version": "v4r2"}, "client_attribution": {"status": "UNKNOWN"},
                    "attributions": [{"service_id": "tonkeeper", "status": "UNKNOWN", "evidence_ids": ["label-proof"]}]}},
            "evidence": [{"evidence_id": "label-proof", "source": "fixture", "url": "https://example.com/label"}]})
        graph = build_graph_payload(report)
        root = next(node for node in graph["nodes"] if node["id"] == _wallet_node_id("ton", A))
        self.assertEqual(root["service_address"], A)
        self.assertEqual(root["ton_service_intelligence"]["client_attribution"]["status"], "UNKNOWN")
        claims = [edge for edge in graph["edges"] if edge["type"] == "service_attribution"]
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["verification_status"], "POSSIBLE")
        self.assertIsNone(claims[0]["confidence"])
        self.assertEqual(claims[0]["evidence_ids"], ["label-proof"])
        self.assertFalse(any(node.get("service_id") == "tonkeeper" for node in graph["nodes"]))


if __name__ == "__main__":
    unittest.main()
