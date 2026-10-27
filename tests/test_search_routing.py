"""Offline regression evidence for real scheduling and observable stage order.

Collector/service boundaries are fixtures. These tests make no public requests.
"""
from __future__ import annotations

import asyncio
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from unittest.mock import AsyncMock, patch
import unittest

from app.aggregator import analyzer
from app.models.report import AddressReport, Balance, SourceHealth, Transaction
from app.sources.manager import build_default_source_manager
from app.ton_nft.models import (DiscoveryCandidate, DiscoveryResult, IntelligenceEvidence,
    NFTAsset, NFTIntelligenceReport, NFTOwnershipAssertion)
from app.ton_nft.protocol import ton_dns_item_index
from app.ton_nft.service import resolve_verified_nft_owner
from app.utils.ton_normalize import ton_canonical_address


BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
ETH = "0x" + "1" * 40
TON = "0:" + "1" * 64


def patch_collectors(stack, fetch):
    manager = build_default_source_manager()
    for plan in manager._plans.values():
        plan.retries = 0
    stack.enter_context(patch.object(analyzer, "SOURCE_MANAGER", manager))
    stack.enter_context(patch.object(analyzer, "_tonconsole_available", return_value=False))
    for collector in {value for name, value in vars(analyzer).items()
                      if name.endswith("Source") and isinstance(value, type) and hasattr(value, "fetch")}:
        stack.enter_context(patch.object(collector, "fetch", fetch))


class SearchDisplayRoutingTests(unittest.TestCase):
    def test_nft_names_and_unknown_inputs_never_queue_unrelated_chain_rows(self):
        from app.main import _active_source_states
        for query in ("424242.ton", "@fixture_username", "LolPop-1", "unsupported input ???"):
            with self.subTest(query=query):
                states = _active_source_states(query)
                irrelevant = {name for name, state in states.items()
                              if state.chain in {"btc", "doge", "eth", "tron", "solana"}}
                self.assertEqual(irrelevant, set())
                self.assertEqual(states, {})

    def test_recognized_address_display_preserves_only_selected_networks(self):
        from app.main import _active_source_states
        for address, chain in ((BTC, "btc"), (ETH, "eth"), (TON, "ton")):
            with self.subTest(chain=chain):
                states = _active_source_states(address)
                self.assertTrue(states)
                self.assertEqual({state.chain for state in states.values()}, {chain})
        states = _active_source_states(ETH, ["bsc", "polygon"])
        self.assertEqual({state.chain for state in states.values()}, {"bsc", "polygon"})


class SearchActualRoutingTests(unittest.IsolatedAsyncioTestCase):
    async def test_unsupported_direct_analyzer_input_rejects_before_any_collector(self):
        calls = []
        async def fetch(source, address):
            calls.append(source.name)
            return AddressReport(target_address=address)
        for query in ("424242.ton", "unsupported input ???", "https://localhost/nft", "0xINVALID"):
            with self.subTest(query=query), ExitStack() as stack:
                patch_collectors(stack, fetch)
                events = []
                with self.assertRaisesRegex(ValueError, "Unsupported address input"):
                    await analyzer.analyze_address(query, progress=events.append)
                self.assertEqual(calls, [])
                self.assertEqual([event["stage"] for event in events], ["routing.start", "routing.error"])

    async def test_unknown_search_input_rejects_without_any_provider_or_collector(self):
        from app.nft_cli import analyze_search_input
        for query in ("unsupported input ???", "https://localhost/nft", "0xINVALID"):
            with self.subTest(query=query):
                collect, investigate = AsyncMock(), AsyncMock()
                with patch("app.ton_nft.service.investigate_ton_nft", investigate):
                    with self.assertRaisesRegex(ValueError, "Unknown input format"):
                        await analyze_search_input(query, address_analyzer=collect)
                collect.assert_not_awaited()
                investigate.assert_not_awaited()

    async def test_invalid_bitcoin_and_dogecoin_keep_existing_diagnostics_without_collectors(self):
        calls = []
        async def fetch(source, address):
            calls.append(source.name)
            return AddressReport(target_address=address)
        for query, chain in (("1BoatSLRHtKNngkdXEeobR76b53LETtpyU", "btc"), ("D" + "1" * 33, "doge")):
            with self.subTest(chain=chain), ExitStack() as stack:
                patch_collectors(stack, fetch)
                report, graph = await analyzer.analyze_address(query)
                self.assertEqual(report.detected_chains, [chain])
                self.assertTrue(any("invalid" in warning for warning in report.warnings))
                self.assertEqual(calls, [])
                self.assertTrue(graph["nodes"])

    async def test_all_supported_explicit_chains_only_schedule_their_own_collectors(self):
        for chain in ("btc", "doge", "eth", "bsc", "polygon", "arbitrum", "optimism", "avalanche", "tron", "solana", "ton"):
            with self.subTest(chain=chain), ExitStack() as stack:
                calls = []
                async def fetch(source, address):
                    calls.append((source.name, source.chain))
                    return AddressReport(target_address=address, detected_chains=[chain], sources_used=[source.name])
                patch_collectors(stack, fetch)
                report, graph = await analyzer.analyze_address(TON if chain == "ton" else ETH, selected_chains=[chain])
                self.assertTrue(calls)
                self.assertEqual({actual_chain for _, actual_chain in calls}, {chain})
                self.assertEqual(report.detected_chains, [chain])

    async def test_selected_evm_networks_keep_supported_multichain_collection(self):
        calls = []
        async def fetch(source, address):
            calls.append(source.chain)
            return AddressReport(target_address=address, detected_chains=[source.chain])
        with ExitStack() as stack:
            patch_collectors(stack, fetch)
            report, graph = await analyzer.analyze_address(ETH, selected_chains=["bsc", "polygon", "arbitrum"])
        self.assertEqual(set(calls), {"bsc", "polygon", "arbitrum"})
        self.assertEqual(set(report.detected_chains), {"bsc", "polygon", "arbitrum"})

    async def test_nft_resolution_wait_does_not_execute_legacy_collectors(self):
        from app.nft_cli import analyze_search_input
        started, release = asyncio.Event(), asyncio.Event()
        async def investigate(*args, **kwargs):
            started.set()
            await release.wait()
            return NFTIntelligenceReport(investigation_id="routing-unresolved-fixture", query="424242.ton",
                status="unresolved", discovery=DiscoveryResult(normalized_query="424242.ton", query_kind="domain", status="unresolved"))
        collect = AsyncMock()
        with patch("app.ton_nft.service.investigate_ton_nft", investigate):
            task = asyncio.create_task(analyze_search_input("424242.ton", address_analyzer=collect))
            try:
                await asyncio.wait_for(started.wait(), timeout=1)
                self.assertFalse(task.done())
                collect.assert_not_awaited()
            finally:
                release.set()
            report, graph = await asyncio.wait_for(task, timeout=1)
        collect.assert_not_awaited()
        self.assertEqual(report.input_resolution["discovery_status"], "unresolved")

    async def test_timestamped_progress_tracks_actual_fetches_analysis_and_graph(self):
        events, calls = [], []
        async def fetch(source, address):
            calls.append(source.name)
            if source.name == "etherscan_api":
                raise RuntimeError("fixture unavailable API")
            return AddressReport(target_address=address, detected_chains=["eth"], sources_used=[source.name],
                transactions=[Transaction(chain="eth", tx_hash="routing-fixture-transaction", source=source.name,
                    from_address=address, to_address="0x" + "2" * 40, asset="ETH", amount=1)] if source.name == "ethereum_rpc" else [])
        with ExitStack() as stack:
            patch_collectors(stack, fetch)
            report, graph = await analyzer.analyze_address(ETH, progress=events.append)
        stages = [event["stage"] for event in events]
        for first, second in (("routing.start", "routing.complete"), ("routing.complete", "collectors.start"),
                              ("collectors.start", "collectors.complete"), ("collectors.complete", "analysis.start"),
                              ("analysis.start", "analysis.complete"), ("analysis.complete", "graph.start"),
                              ("graph.start", "graph.complete")):
            self.assertLess(stages.index(first), stages.index(second))
        self.assertEqual({event["source"] for event in events if event["stage"] == "source.start"}, set(calls))
        self.assertEqual({event["source"] for event in events if event["stage"] == "source.finish"}, set(calls))
        self.assertTrue(any(event.get("source") == "etherscan_api" and event.get("status") == "error" for event in events))
        final_sources = [event for event in events if event["stage"] == "source.result"]
        self.assertEqual({event["source"] for event in final_sources}, set(calls))
        self.assertTrue(any(event["source"] == "etherscan_api" and event["status"] == "error"
                            and event["errors"] == ["etherscan_api: fixture unavailable API"] for event in final_sources))
        elapsed = [event["elapsed_seconds"] for event in events]
        self.assertEqual(elapsed, sorted(elapsed))
        self.assertTrue(all(datetime.fromisoformat(event["timestamp"]).utcoffset().total_seconds() == 0 for event in events))
        self.assertTrue(all(event["component"] == "legacy_analyzer" for event in events))
        self.assertEqual(len(report.transactions), 1)
        self.assertTrue(any("fixture unavailable API" in error for error in report.errors))
        self.assertTrue(graph["nodes"])

    async def test_source_result_reports_real_rate_limit_and_timeout_status(self):
        events = []
        async def fetch(source, address):
            if source.name == "etherscan_api":
                return AddressReport(target_address=address, errors=["etherscan_api: http 429"],
                    source_health=[SourceHealth(source=source.name, status="rate_limited")])
            if source.name == "ethereum_rpc":
                raise asyncio.TimeoutError()
            return AddressReport(target_address=address)
        with ExitStack() as stack:
            patch_collectors(stack, fetch)
            await analyzer.analyze_address(ETH, progress=events.append)
        results = {event["source"]: event for event in events if event["stage"] == "source.result"}
        self.assertEqual(results["etherscan_api"]["status"], "rate_limited")
        self.assertEqual(results["ethereum_rpc"]["status"], "timeout")

    async def test_verified_owner_analysis_and_partial_html_finish_before_deep_enrichment(self):
        """A blocked deep history must not delay the first useful owner dossier."""
        from app.nft_cli import analyze_search_input
        from app.exporters.html_exporter import export_html_report
        item, owner = "0:" + "2" * 64, "0:" + "3" * 64
        nft = NFTIntelligenceReport(investigation_id="early-owner-routing-fixture", query="424242.ton", mode="deep", scope="item",
            discovery=DiscoveryResult(normalized_query="424242.ton", query_kind="domain", status="resolved",
                candidates=[DiscoveryCandidate(address=item, reason="Exact fixture NFT")]),
            assets=[NFTAsset(asset_id=item, address=item, name="424242.ton", kind="domain", initialized=True,
                standard_status="verified_onchain", collection_status="verified_onchain",
                collection_address=ton_canonical_address("EQC3dNlesgVD8YbAazcauIrXBPfiVhMMr5YYk2in0Mtsz0Bz"),
                index=ton_dns_item_index("424242.ton"), current_owner=owner, current_owner_status="verified_onchain",
                ownership=[NFTOwnershipAssertion(asset_address=item, owner_address=owner, status="verified_onchain",
                    method="get_nft_data", evidence_ids=["early-owner-proof"])])],
            evidence=[IntelligenceEvidence(evidence_id="early-owner-proof", source="fixture", upstream="fixture",
                observation_id="fixture-getter", relation="onchain_current_owner", status="verified_onchain", explanation="Fresh fixture getter")])
        entered, allow_owner, deep_waiting, finish_deep, ready = (asyncio.Event() for _ in range(5))
        timeline, partials = [], []
        async def investigate(query, **kwargs):
            entered.set()
            await allow_owner.wait()
            target = {**resolve_verified_nft_owner(nft), "scope": "item", "analysis_address": owner}
            await kwargs["on_target_resolved"](target, nft)
            timeline.append("deep_waiting")
            deep_waiting.set()
            await finish_deep.wait()
            timeline.append("deep_complete")
            nft.status = "partial"
            return nft
        async def collect(address, **kwargs):
            timeline.append("legacy_analysis_complete")
            return AddressReport(target_address=address, detected_chains=["ton"],
                balances=[Balance(chain="ton", address=address, asset="TON", amount=5, source="fixture_owner")]), {}
        with tempfile.TemporaryDirectory() as directory:
            async def on_ready(report, graph):
                path = export_html_report(report, graph, Path(directory)).output_path
                partials.append((report, path.read_text(encoding="utf-8")))
                timeline.append("partial_html_ready")
                ready.set()
            legacy = AsyncMock(side_effect=collect)
            with patch("app.ton_nft.service.investigate_ton_nft", investigate):
                task = asyncio.create_task(analyze_search_input("424242.ton", address_analyzer=legacy,
                    nft_options={"store_path": Path(directory) / "snapshot.sqlite3"}, on_report_ready=on_ready))
                try:
                    await asyncio.wait_for(entered.wait(), timeout=1)
                    legacy.assert_not_awaited()
                    allow_owner.set()
                    await asyncio.wait_for(deep_waiting.wait(), timeout=1)
                    await asyncio.wait_for(ready.wait(), timeout=5)
                    self.assertFalse(task.done())
                    legacy.assert_awaited_once()
                    self.assertEqual(legacy.await_args.args, (owner,))
                    partial, html = partials[0]
                    self.assertTrue(partial.coverage["search_execution"]["partial_checkpoint"])
                    self.assertEqual(partial.coverage["search_execution"]["status"], "running")
                    # The owner pipeline finished; the surrounding NFT run is
                    # still explicitly running/partial in search_execution.
                    self.assertEqual(partial.input_resolution["owner_analysis_status"], "completed")
                    self.assertEqual(partial.balances[0].amount, 5)
                    self.assertTrue(any("partial checkpoint" in warning for warning in partial.warnings))
                    self.assertIn(owner, html)
                    self.assertIn("424242.ton", html)
                finally:
                    allow_owner.set()
                    finish_deep.set()
                    report, graph = await asyncio.wait_for(task, timeout=5)
            self.assertEqual(report.target_address, owner)
            self.assertLess(timeline.index("legacy_analysis_complete"), timeline.index("partial_html_ready"))
            self.assertLess(timeline.index("partial_html_ready"), timeline.index("deep_complete"))

    async def test_progress_callback_errors_are_not_hidden(self):
        class FixtureProgressError(RuntimeError):
            pass
        def progress(event):
            raise FixtureProgressError("fixture callback failure")
        with self.assertRaisesRegex(FixtureProgressError, "fixture callback failure"):
            await analyzer.analyze_address(BTC, progress=progress)


if __name__ == "__main__":
    unittest.main()
