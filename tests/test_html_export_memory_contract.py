"""Small offline contracts for the original HTML's bounded render projection.

These synthetic observations check representation and redaction, not live data.
"""
from __future__ import annotations

import copy
import hashlib
from html import unescape
import json
from pathlib import Path
import re
import tempfile
from typing import get_args
import unittest
from unittest.mock import patch

from app.exporters import html_exporter
from app.graph.builder import build_graph_payload
from app.exporters.ton_presentation import friendly_address
from app.models.report import AddressReport, Chain, Transaction
from app.utils.event_identity import event_identity


A, B = "0:" + "1" * 64, "0:" + "2" * 64


def fixture(count=1):
    """Use the existing presentation-fixture shape, with full source evidence."""
    key = "ton:" + A
    observation = {"source": "synthetic_render_provider", "url": "https://example.com/raw/1",
        "raw": {"unmodelled": {"items": [1, {"public_text": "полное наблюдение 😀"}]},
            "transaction": {"hash": "a" * 64, "in_msg": {"body": "public-boc-body"}}}}
    return AddressReport(target_address=A, detected_chains=["ton"], transactions=[
        Transaction(chain="ton", tx_hash=f"{index:064x}", event_id=f"synthetic:render:{index}",
            from_address=A, to_address=B, direction="out", asset="TON", source="synthetic_render_provider",
            raw={"provider": "synthetic_render_provider", "public_value": index})
        for index in range(count)], attribution_intelligence={
            "target_address": A, "target_chain": "ton", "target_key": key,
            "addresses": {key: {"address": A, "blockchain": "ton", "attributions": [],
                "client_attribution": {"status": "UNKNOWN"}, "evidence_ids": ["synthetic:render:proof"]}},
            "evidence": [{"evidence_id": "synthetic:render:proof", "source": "synthetic_render_provider",
                "url": "https://example.com/proof/1", "facts": {"source_provenance": [observation, observation]}}]})


def render(report, graph=None, language="ru"):
    if graph is None:
        graph = build_graph_payload(report)
    with tempfile.TemporaryDirectory() as directory:
        return html_exporter.render_html_report(report, graph, Path(directory), language=language)


def payload(html):
    match = re.search(r'<script id="nft-payload" type="application/json">(.*?)</script>', html, re.S)
    if match is None:
        raise AssertionError("The original integrated report payload is missing")
    return json.loads(match.group(1))


class HtmlExportMemoryContract(unittest.TestCase):
    def test_non_tron_classification_does_not_serialize_provider_raw(self):
        # A large nested TON provider tail must not become another large string
        # merely to check markers used exclusively by TRON classification.
        chains = [chain for chain in get_args(Chain) if chain != "tron"]
        self.assertEqual(len(chains), 10)
        for chain in chains:
            with self.subTest(chain=chain):
                tx = Transaction(chain=chain, tx_hash="synthetic", source="synthetic_render_provider",
                    direction="in", raw={"type": "transfer", "provider_tail": {
                        "permission": {"nested": "sunpump memecoin meme token"}, "body": "x" * 4096}})
                with patch.object(html_exporter.json, "dumps", side_effect=AssertionError(
                        "Non-TRON classification serialized provider raw")) as dumps:
                    kind = html_exporter._tx_kind(tx)
                self.assertEqual(kind, "doge_received" if chain == "doge" else "transfer")
                dumps.assert_not_called()

    def test_tron_nested_markers_and_classification_precedence_survive(self):
        cases = [
            ({"contract": {"value": {"PermissionUpdateContract": {"owner": []}}}}, "permission_update"),
            ({"nested": [{"description": "memecoin launch"}]}, "meme_token_event"),
            ({"nested": {"market": "SunPump"}}, "meme_token_event"),
            ({"nested": {"description": "meme token"}}, "meme_token_event"),
            ({"status": "FAILED", "nested": {"permission": {}}}, "failed_transfer"),
            ({"contract_type": "46"}, "permission_update"),
            ({"method": "SunSwap exchange"}, "swap"),
            ({"function_name": "JustLend borrow"}, "defi_interaction"),
            ({"contract_type": "57"}, "resource_event"),
            ({"type": "trc20", "contract": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"}, "usdt_transfer"),
            ({"type": "trc20", "contract": "synthetic-other-token"}, "trc20_transfer"),
            ({"status": "SUCCESS"}, "trx_transfer"),
        ]
        for raw, expected in cases:
            with self.subTest(expected=expected, raw=raw):
                tx = Transaction(chain="tron", tx_hash="synthetic", source="synthetic_render_provider",
                    asset="TRX", raw=raw)
                self.assertEqual(html_exporter._tx_kind(tx), expected)

    def _check_validated_template_projection(self, language):
        report = fixture()
        # These mutations deliberately bypass construction-time redaction.
        report.warnings = ["Bearer caller_warning_secret"]
        report.errors = ["password=caller_error_secret"]
        report.transactions[0].raw["api_key"] = "caller_raw_secret"
        report.attribution_intelligence["evidence"][0]["facts"]["access_token"] = "caller_proof_secret"
        graph = build_graph_payload(report)
        graph["nodes"][0]["properties"] = {"authorization": "caller_graph_secret", "public": "graph-public"}
        before_report, before_graph = copy.deepcopy(report.model_dump()), copy.deepcopy(graph)
        validate = AddressReport.model_validate
        validated = []

        def new_validated_report(value, *args, **kwargs):
            result = validate(value, *args, **kwargs)
            # Observable sentinels verify that template summaries use this new
            # validated instance rather than a pre-validation dump or caller.
            result.target_address = B
            result.detected_chains = ["ton", "eth"]
            result.risk_score = 73
            result.warnings.append("Validated-render-warning")
            result.coverage["search_execution"] = {"status": "completed", "phase": "render-contract-final",
                "reason": "Validated-render-session"}
            validated.append(result)
            return result

        with patch.object(AddressReport, "model_validate", side_effect=new_validated_report):
            html = render(report, graph, language)
        self.assertEqual(len(validated), 1)
        self.assertIsNot(validated[0], report)
        self.assertEqual(report.model_dump(), before_report)
        self.assertEqual(graph, before_graph)
        self.assertIn(f'<div class="target">{friendly_address(B)}</div>', html)
        self.assertIn('<span class="chip">ton</span>', html)
        self.assertIn('<span class="chip">ethereum</span>', html)
        risk = html_exporter.I18N[language]["risk"]
        self.assertIn(f'data-i18n="risk">{risk}</span> 73', html)
        transactions = "наблюдений операций" if language == "ru" else "operation observations"
        self.assertIn(f'data-i18n="transactions">{transactions}</span><b>1</b>', html)
        self.assertIn('id="investigationSessionState"><b>completed</b>', html)
        for text in ("render-contract-final", "Validated-render-session", "Validated-render-warning", "graph-public"):
            self.assertIn(text, html)
        for secret in ("caller_warning_secret", "caller_error_secret", "caller_raw_secret",
                "caller_proof_secret", "caller_graph_secret"):
            self.assertNotIn(secret, html)
        self.assertIn("[REDACTED]", html)

    def test_ru_summary_uses_new_validated_report_without_mutating_inputs(self):
        self._check_validated_template_projection("ru")

    def test_en_summary_uses_new_validated_report_without_mutating_inputs(self):
        self._check_validated_template_projection("en")

    def test_projection_keeps_all_operations_and_complete_source_proofs_after_page_one(self):
        report = fixture(267)
        before = copy.deepcopy(report.model_dump())
        data = payload(render(report))
        self.assertEqual(report.model_dump(), before)
        rows = data["transaction_views"]
        self.assertEqual(len(rows), 267)
        self.assertEqual([row["operation_identity"] for row in rows], [event_identity(tx) for tx in report.transactions])
        self.assertEqual(rows[-1]["hash"], report.transactions[-1].tx_hash)
        self.assertEqual(rows[-1]["source"], "synthetic_render_provider")
        services = data["services"]
        proof = next(item for item in services["evidence"] if item["evidence_id"] == "synthetic:render:proof")
        refs = proof["facts"]["source_provenance_refs"]
        original = before["attribution_intelligence"]["evidence"][0]["facts"]["source_provenance"]
        self.assertEqual([services["source_observations"][ref] for ref in refs], original)
        self.assertEqual(len(refs), 2)
        self.assertEqual(len(services["source_observations"]), 1)
        stage = data["collection_audit"]["stages"]["html"]
        self.assertEqual(stage["embedded_operation_rows"], 267)
        self.assertEqual(stage["initial_dom_rows"], 260)
        self.assertFalse(stage["ui_page_limit_is_collection_limit"])

    def test_visible_collection_audit_equals_fresh_payload_audit(self):
        report = fixture(263)
        report.collection_audit = {"stages": {"html": {"records": 1, "stale_fixture": True}},
            "streams": {"synthetic_render_provider": {"history": {
                "pages": 2, "raw_records": 263, "next_cursor": "pending-tail", "exhausted": False}}}}
        before = copy.deepcopy(report.collection_audit)
        html = render(report, language="en")
        data = payload(html)
        match = re.search(r'<pre class="mono" id="collectionAuditData">(.*?)</pre>', html, re.S)
        self.assertIsNotNone(match)
        self.assertEqual(json.loads(unescape(match.group(1))), data["collection_audit"])
        stage = data["collection_audit"]["stages"]["html"]
        self.assertEqual(stage["records"], 263)
        self.assertNotIn("stale_fixture", stage)
        expected_digest = hashlib.sha256("\n".join(sorted(event_identity(tx) for tx in report.transactions)).encode()).hexdigest()
        self.assertEqual(stage["model_event_ids_sha256"], expected_digest)
        self.assertEqual(stage["browser_operation_ids_sha256"], expected_digest)
        self.assertEqual(data["collection_audit"]["streams"]["synthetic_render_provider"]["history"]["next_cursor"], "pending-tail")
        self.assertFalse(stage["history_complete"])
        self.assertEqual(report.collection_audit, before)


if __name__ == "__main__":
    unittest.main()
