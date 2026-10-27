"""Offline integration regressions; these fixtures do not validate live APIs."""
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from app.aggregator import analyzer
from app.models.report import AddressReport, Balance, Transaction
from app.nft_cli import analyze_search_input
from app.sources.manager import build_default_source_manager
from app.ton_nft.models import DiscoveryCandidate, DiscoveryResult, NFTIntelligenceReport


class LegacyIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_existing_chains_collect_merge_analyze_and_render(self):
        """Exercise real aggregation and HTML with deterministic source replies."""
        chains = ["btc", "doge", "eth", "bsc", "polygon", "arbitrum", "optimism", "avalanche", "tron", "solana", "ton"]
        for chain in chains:
            with self.subTest(chain=chain):
                address = {"btc": "1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "doge": "D" + "1" * 33,
                           "tron": "T" + "1" * 33, "solana": "1" * 32,
                           "ton": "0:" + "1" * 64}.get(chain, "0x" + "1" * 40)
                recipient = "0:" + "2" * 64 if chain == "ton" else "fixture-recipient"
                asset = {"bsc": "BNB", "polygon": "POL", "arbitrum": "ETH", "optimism": "ETH", "avalanche": "AVAX"}.get(chain, chain.upper())

                async def fixture_fetch(source, target):
                    return AddressReport(target_address=target, detected_chains=[chain], sources_used=[source.name],
                        balances=[Balance(chain=chain, address=target, asset=asset, amount=3, source=source.name)],
                        transactions=[Transaction(chain=chain, tx_hash="fixture-transaction-" + str(index), source=source.name,
                            from_address=target, to_address=recipient, amount=1, amount_decimal="1",
                            asset=asset, direction="out", success=True,
                            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=index))
                            for index in range(3)])

                with ExitStack() as stack:
                    stack.enter_context(patch.object(analyzer, "SOURCE_MANAGER", build_default_source_manager()))
                    stack.enter_context(patch.object(analyzer, "_tonconsole_available", return_value=False))
                    classes = {value for name, value in vars(analyzer).items()
                               if name.endswith("Source") and isinstance(value, type) and hasattr(value, "fetch")}
                    for collector in classes:
                        stack.enter_context(patch.object(collector, "fetch", fixture_fetch))
                    investigation = stack.enter_context(patch("app.ton_nft.service.investigate_ton_nft", AsyncMock(
                        return_value=NFTIntelligenceReport(investigation_id="legacy-wallet-fixture", query=address,
                            scope="wallet", mode="deep", discovery=DiscoveryResult(normalized_query=address,
                                query_kind="address", status="resolved", candidates=[DiscoveryCandidate(
                                    address=address, reason="Fixture normal account")])))))
                    report, graph = await analyze_search_input(address, selected_chains=[chain],
                                                              address_analyzer=analyzer.analyze_address)
                if chain == "ton":
                    investigation.assert_awaited_once()
                else:
                    investigation.assert_not_awaited()
                self.assertIn(chain, report.detected_chains)
                self.assertEqual(len(report.transactions), 3)
                self.assertEqual(report.transactions[0].amount_decimal, 1)
                self.assertTrue(report.transactions[0].provenance)
                self.assertTrue(graph["nodes"])
                self.assertTrue(report.activity_chains)
                self.assertEqual({item.raw["chain"] for item in report.activity_chains}, {chain})
                self.assertFalse(report.errors)
                self.assertEqual(report.coverage["transactions"]["display_limit"], 100000)
                from app.exporters.html_exporter import export_html_report
                with tempfile.TemporaryDirectory() as temporary:
                    for language in ["ru", "en"]:
                        path = export_html_report(report, graph, Path(temporary), filename=language + ".html", language=language).output_path
                        html = path.read_text(encoding="utf-8")
                        self.assertIn("fixture-transaction", html)
                        self.assertIn("GANSAR", html)
                        self.assertIn("Recurring counterparty", html)

    async def test_default_shared_search_preserves_more_than_200_collected_events(self):
        address = "0x" + "1" * 40
        async def fetch(source, target):
            if source.name != "ethereum_rpc":
                return AddressReport(target_address=target, sources_used=[source.name])
            return AddressReport(target_address=target, detected_chains=["eth"], sources_used=[source.name],
                transactions=[Transaction(chain="eth", tx_hash=f"retained-event-{index:03d}", source=source.name,
                    from_address=target, to_address="0x" + "2" * 40, asset="ETH", amount=1,
                    direction="out", success=True, timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc)
                    + timedelta(seconds=index)) for index in range(260)])
        with ExitStack() as stack:
            stack.enter_context(patch.object(analyzer, "SOURCE_MANAGER", build_default_source_manager()))
            classes = {value for name, value in vars(analyzer).items()
                       if name.endswith("Source") and isinstance(value, type) and hasattr(value, "fetch")}
            for collector in classes:
                stack.enter_context(patch.object(collector, "fetch", fetch))
            report, graph = await analyze_search_input(address, selected_chains=["eth"],
                                                      address_analyzer=analyzer.analyze_address)
        self.assertEqual(len(report.transactions), 260)
        self.assertEqual({item.tx_hash for item in report.transactions}, {f"retained-event-{index:03d}" for index in range(260)})
        self.assertTrue(report.activity_chains)
        self.assertEqual(report.counterparties[0].tx_count, 260)
        from app.exporters.html_exporter import export_html_report
        with tempfile.TemporaryDirectory() as directory:
            html = export_html_report(report, graph, Path(directory), language="en").output_path.read_text(encoding="utf-8")
        self.assertIn("retained-event-000", html)
        self.assertIn("retained-event-259", html)

    async def test_address_no_pdf_skips_local_renderer(self):
        from app import main
        report = AddressReport(target_address="0x" + "1" * 40, detected_chains=["eth"])
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(main, "analyze_address", AsyncMock(return_value=(report, {"nodes": [], "edges": []}))), \
             patch.object(main, "export_html", return_value=Path(temporary) / "report.html"), \
             patch.object(main, "export_pdf", AsyncMock()) as renderer:
            actual, html, pdf = await main._analyze_quiet(report.target_address, Path(temporary), pdf=False)
        self.assertIs(actual, report)
        self.assertIsNone(pdf)
        renderer.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
