"""Regression for the ordinary search graph contract; no provider calls."""
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.aggregator import analyzer
from app.graph.builder import build_graph_payload
from app.models.report import ActivityChain, AddressReport, Transaction
from app.sources.manager import build_default_source_manager


A, B = "0:" + "1" * 64, "0:" + "2" * 64


def recurring_report(source: str = "fixture") -> AddressReport:
    return AddressReport(
        target_address=A, detected_chains=["ton"], sources_used=[source],
        transactions=[Transaction(
            chain="ton", tx_hash="activity-contract-" + str(index), source=source,
            from_address=A, to_address=B, direction="out", asset="TON", amount=1,
            amount_decimal="1", success=True,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=index),
        ) for index in range(3)],
    )


class ActivityChainGraphTests(unittest.TestCase):
    def test_real_activity_chain_uses_existing_raw_network_contract(self):
        report = recurring_report()
        report.counterparties = analyzer._build_counterparties(report)
        report.activity_chains = analyzer._build_activity_chains(report)
        self.assertTrue(all(isinstance(item, ActivityChain) for item in report.activity_chains))
        self.assertTrue(report.activity_chains)
        self.assertFalse(hasattr(report.activity_chains[0], "chain"))
        self.assertEqual(report.activity_chains[0].raw["chain"], "ton")
        graph = build_graph_payload(report)
        activity_assets = [node for node in graph["nodes"] if node["id"] == "asset:ton:TON"]
        self.assertEqual(len(activity_assets), 1)
        self.assertEqual(activity_assets[0]["chain"], "ton")


class ActivityChainPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_collect_normalize_analyze_graph_original_html_ru_en(self):
        """Three TON transfers reach the exact branch missed by one-tx fixtures."""
        async def fixture_fetch(source, address):
            if source.name == "tonapi":
                return recurring_report(source.name)
            return AddressReport(target_address=address, detected_chains=["ton"], sources_used=[source.name])

        with ExitStack() as stack:
            stack.enter_context(patch.object(analyzer, "SOURCE_MANAGER", build_default_source_manager()))
            stack.enter_context(patch.object(analyzer, "_tonconsole_available", return_value=False))
            classes = {value for name, value in vars(analyzer).items()
                       if name.endswith("Source") and isinstance(value, type) and hasattr(value, "fetch")}
            for collector in classes:
                stack.enter_context(patch.object(collector, "fetch", fixture_fetch))
            report, graph = await analyzer.analyze_address(A, selected_chains=["ton"])

        self.assertEqual(len(report.transactions), 3)
        self.assertTrue(report.activity_chains)
        self.assertFalse(report.errors)
        self.assertTrue(graph["nodes"])
        from app.exporters.html_exporter import export_html_report
        with tempfile.TemporaryDirectory() as temporary:
            for language in ["ru", "en"]:
                path = export_html_report(report, graph, Path(temporary), filename=language + ".html", language=language).output_path
                html = path.read_text(encoding="utf-8")
                self.assertIn("activity-contract-", html)
                self.assertIn("GANSAR", html)
                self.assertIn("Recurring counterparty", html)


if __name__ == "__main__":
    unittest.main()
