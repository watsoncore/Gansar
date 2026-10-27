"""Offline owner-search regressions; fixtures never constitute live API evidence.

NFT/provider boundaries are deterministic. Ownership gating, legacy aggregation,
model projection, graph generation and original HTML use production code.
"""
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import asyncio
import base64
import binascii
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

from rich.console import Console

from app.aggregator import analyzer
from app.graph.builder import build_graph_payload
from app.models.report import AddressReport, Balance, Transaction
from app.nft_cli import analyze_search_input
from app.sources.manager import build_default_source_manager
from app.ton_nft.discovery import normalize_nft_query
from app.ton_nft.models import (CollectionCoverage, DiscoveryCandidate, DiscoveryResult,
    IntelligenceEvidence, InvestigationBudget, NFTAsset, NFTEvent, NFTIntelligenceReport,
    NFTOwnershipAssertion, SourceObservation, VerificationStatus)
from app.ton_nft.service import resolve_verified_nft_owner
from app.ton_nft.protocol import ton_dns_item_index
from app.utils.ton_normalize import ton_canonical_address


ITEM, OWNER, OTHER = ["0:" + char * 64 for char in "123"]
# Official DNS collection is a fixed fixture trust anchor, independent of the
# mutable service registry used during the investigation.
COLLECTION = ton_canonical_address("EQC3dNlesgVD8YbAazcauIrXBPfiVhMMr5YYk2in0Mtsz0Bz")
WHEN = datetime(2026, 10, 16, 0, 0, tzinfo=timezone.utc)


def friendly(address):
    payload = b"\x11\x00" + bytes.fromhex(address.split(":")[1])
    return base64.urlsafe_b64encode(payload + binascii.crc_hqx(payload, 0).to_bytes(2, "big")).decode()


def nft_fixture(query="424242.ton"):
    normalized = normalize_nft_query(query)
    return NFTIntelligenceReport(investigation_id="owner-pipeline-fixture", query=query,
        mode="deep", scope="item", status="partial", budget=InvestigationBudget.for_mode("deep"),
        discovery=DiscoveryResult(normalized_query=normalized.value, query_kind=normalized.kind, status="resolved",
            candidates=[DiscoveryCandidate(address=ITEM, reason="Exact NFT fixture record")]),
        assets=[NFTAsset(asset_id=ITEM, address=ITEM, name="424242.ton", kind="domain",
            initialized=True, standard="TEP-62", standard_status=VerificationStatus.VERIFIED_ONCHAIN,
            collection_address=COLLECTION, index=ton_dns_item_index("424242.ton"), collection_status=VerificationStatus.VERIFIED_ONCHAIN,
            current_owner=OWNER, current_owner_status=VerificationStatus.VERIFIED_ONCHAIN,
            ownership=[NFTOwnershipAssertion(asset_address=ITEM, owner_address=OWNER,
                status=VerificationStatus.VERIFIED_ONCHAIN, observed_at=WHEN,
                method="get_nft_data", evidence_ids=["owner-proof"], logical_time=123)],
            evidence_ids=["owner-proof"],
            raw={"dns_resolved_wallet": OTHER, "metadata_owner": OTHER})],
        events=[NFTEvent(event_id="nft-transfer-fixture", asset_address=ITEM, event_type="transfer",
            status="success", from_address=OTHER, to_address=OWNER, transaction_hash="e" * 64,
            timestamp=WHEN, logical_time=123, action_index=0, evidence_ids=["owner-proof"])],
        evidence=[IntelligenceEvidence(evidence_id="owner-proof", source="fixture_provider", upstream="fixture",
            observation_id="getter-observation", relation="onchain_current_owner",
            status=VerificationStatus.VERIFIED_ONCHAIN, explanation="Fixture fresh get_nft_data owner",
            url="https://tonviewer.com/" + ITEM, collected_at=WHEN)],
        observations=[SourceObservation(observation_id="getter-observation", source="fixture_provider", upstream="fixture",
            endpoint="https://toncenter.com/api/v2/runGetMethod", request_method="POST",
            request_body={"address": ITEM, "method": "get_nft_data", "stack": []}, content_hash="fixture-hash",
            status="ok", collected_at=WHEN)],
        coverage=[CollectionCoverage(scope="history:item:" + ITEM, source="fixture_provider", upstream="fixture",
            status="budget_limit", coverage_status="TRUNCATED", records=1, pages=1,
            next_cursor="122", gap_reason="Fixture request budget; checkpoint retained")],
        checkpoints={"fixture:history": {"cursor": 122, "exhausted": False}})


def wallet_fixture(address=OWNER):
    return AddressReport(target_address=address, detected_chains=["ton"],
        balances=[Balance(chain="ton", address=address, asset="TON", amount=12, source="owner_fixture")],
        transactions=[Transaction(chain="ton", tx_hash="owner-transaction-" + str(index), source="owner_fixture",
            from_address=address, to_address=OTHER, asset="TON", amount=1, amount_decimal="1", direction="out", success=True,
            timestamp=WHEN + timedelta(seconds=index)) for index in range(3)])


class NFTOwnerPipelineTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = patch("app.ton_nft.storage.DEFAULT_STORE", Path(directory.name) / "investigations.sqlite3")
        store.start()
        self.addCleanup(store.stop)

    async def test_post_resolution_failure_never_falls_back_to_nft_contract_or_leaks_owner(self):
        for with_checkpoint in (False, True):
            with self.subTest(with_checkpoint=with_checkpoint):
                nft = nft_fixture(friendly(ITEM))
                owner_started, owner_stopped = asyncio.Event(), asyncio.Event()
                calls, owners = [], []
                async def discover(query, **kwargs):
                    await kwargs["on_target_resolved"]({"scope": "item", "owner_address": OWNER}, nft)
                    await owner_started.wait()
                    raise RuntimeError("fixture unexpected post-resolution failure")
                async def analyze(target, **kwargs):
                    calls.append(target)
                    owners.append(asyncio.current_task())
                    owner_started.set()
                    try:
                        await asyncio.Future()
                    finally:
                        await asyncio.sleep(0)
                        owner_stopped.set()
                ready = AsyncMock() if with_checkpoint else None
                with patch("app.ton_nft.service.investigate_ton_nft", discover):
                    with self.assertRaisesRegex(RuntimeError, "unexpected post-resolution failure"):
                        await analyze_search_input(friendly(ITEM), address_analyzer=analyze, on_report_ready=ready)
                self.assertEqual(calls, [OWNER])
                self.assertTrue(owner_stopped.is_set())
                self.assertTrue(all(task.done() for task in owners))
                if ready:
                    ready.assert_not_awaited()

    async def test_finished_enrichment_skips_redundant_running_checkpoint(self):
        nft = nft_fixture()
        owner_started, release_owner, nft_finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def discover(query, **kwargs):
            await kwargs["on_target_resolved"]({"scope": "item", "owner_address": OWNER}, nft)
            nft_finished.set()
            return nft
        async def analyze(target, **kwargs):
            owner_started.set()
            await release_owner.wait()
            return wallet_fixture(target), {}
        ready = AsyncMock()
        with tempfile.TemporaryDirectory() as directory, \
             patch("app.ton_nft.service.investigate_ton_nft", discover):
            task = asyncio.create_task(analyze_search_input("424242.ton", address_analyzer=analyze,
                on_report_ready=ready, nft_options={"store_path": Path(directory) / "snapshots.sqlite3"}))
            await asyncio.wait_for(owner_started.wait(), 2)
            await asyncio.wait_for(nft_finished.wait(), 2)
            release_owner.set()
            report, _ = await asyncio.wait_for(task, 5)
        ready.assert_not_awaited()
        self.assertEqual(report.coverage["search_execution"]["status"], "completed")
        self.assertFalse(report.coverage["search_execution"]["data_complete"])

    async def test_cancelled_resolver_drains_concurrent_owner_and_checkpoint(self):
        nft = nft_fixture()
        owner_started, owner_stopped, enrichment_started = asyncio.Event(), asyncio.Event(), asyncio.Event()
        owners = []
        async def discover(query, **kwargs):
            await kwargs["on_target_resolved"]({"scope": "item", "owner_address": OWNER}, nft)
            enrichment_started.set()
            await asyncio.Future()
        async def analyze(target, **kwargs):
            owners.append(asyncio.current_task())
            owner_started.set()
            try:
                await asyncio.Future()
            finally:
                owner_stopped.set()
        with patch("app.ton_nft.service.investigate_ton_nft", discover):
            task = asyncio.create_task(analyze_search_input("424242.ton", address_analyzer=analyze,
                on_report_ready=AsyncMock()))
            await asyncio.wait_for(owner_started.wait(), 2)
            await asyncio.wait_for(enrichment_started.wait(), 2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertTrue(owner_stopped.is_set())
        self.assertTrue(all(owner.done() for owner in owners))
        self.assertFalse(any("analyze_search_input.<locals>.checkpoint" in t.get_coro().__qualname__
                             for t in asyncio.all_tasks() if not t.done()))

    async def test_exact_input_getter_owner_uses_existing_analyzer_and_original_html(self):
        from app.exporters.html_exporter import export_html_report
        queries = ["424242.ton", friendly(ITEM), "https://gram.org/address/" + friendly(ITEM)]
        for query in queries:
            with self.subTest(query=query):
                nft = nft_fixture(query)
                # A related item must not override the one exact discovery result.
                nft.assets.insert(0, NFTAsset(asset_id=OTHER, address=OTHER, current_owner=COLLECTION))
                calls = []
                async def fetch(source, target):
                    calls.append((source.name, target))
                    return wallet_fixture(target) if source.name == "tonapi" else AddressReport(target_address=target)
                with ExitStack() as stack:
                    stack.enter_context(patch("app.ton_nft.service.investigate_ton_nft", AsyncMock(return_value=nft)))
                    stack.enter_context(patch.object(analyzer, "SOURCE_MANAGER", build_default_source_manager()))
                    stack.enter_context(patch.object(analyzer, "_tonconsole_available", return_value=False))
                    for collector in {value for name, value in vars(analyzer).items()
                                      if name.endswith("Source") and isinstance(value, type) and hasattr(value, "fetch")}:
                        stack.enter_context(patch.object(collector, "fetch", fetch))
                    report, graph = await analyze_search_input(query)
                self.assertTrue(calls)
                self.assertEqual({address for _, address in calls}, {OWNER})
                self.assertEqual(report.target_address, OWNER)
                self.assertEqual(report.balances[0].amount, 12)
                self.assertGreaterEqual(len(report.transactions), 4)
                self.assertTrue(report.counterparties)
                self.assertTrue(report.activity_chains)
                self.assertEqual(report.input_resolution["original_query"], query)
                self.assertEqual(report.input_resolution["nft_item_address"], ITEM)
                self.assertEqual(report.input_resolution["onchain_owner_address"], OWNER)
                self.assertEqual(report.input_resolution["owner_analysis_address"], OWNER)
                self.assertEqual(report.input_resolution["search_mode"], "deep")
                self.assertIn("owner-proof", report.input_resolution["evidence_ids"])
                self.assertTrue(any(asset.asset_id == ITEM for asset in report.ton_assets))
                self.assertIn("owner-transaction-0", str(graph))
                for language in ("ru", "en"):
                    with tempfile.TemporaryDirectory() as directory:
                        path = export_html_report(report, graph, Path(directory), language=language).output_path
                        html = path.read_text(encoding="utf-8")
                        self.assertIn(query, html)
                        self.assertIn(ITEM, html)
                        self.assertIn(OWNER, html)
                        self.assertIn("owner-transaction-0", html)
                        self.assertIn("nft-transfer-fixture", html)
                        self.assertEqual({p.name for p in Path(directory).iterdir() if p.is_file()}, {"report.html"})

    async def test_unresolved_ambiguous_conflict_and_metadata_claims_do_not_start_owner_analysis(self):
        scenarios = ("unresolved", "ambiguous", "multiple_candidates", "missing_owner", "conflict",
                     "unverified_current", "not_initialized", "unverified_standard", "unverified_collection",
                     "no_getter_assertion", "wrong_assertion_owner", "missing_evidence", "metadata_only_evidence")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                nft = nft_fixture()
                asset = nft.assets[0]
                if scenario in {"unresolved", "ambiguous"}:
                    nft.discovery.status = scenario
                elif scenario == "multiple_candidates":
                    nft.discovery.candidates.append(DiscoveryCandidate(address=OTHER, reason="Competing exact candidate"))
                elif scenario == "missing_owner":
                    asset.current_owner = None
                elif scenario == "conflict":
                    asset.current_owner_status = VerificationStatus.CONFLICT
                elif scenario == "unverified_current":
                    asset.current_owner_status = VerificationStatus.UNVERIFIED
                elif scenario == "not_initialized":
                    asset.initialized = False
                elif scenario == "unverified_standard":
                    asset.standard_status = VerificationStatus.PROVIDER_REPORTED
                elif scenario == "unverified_collection":
                    asset.collection_status = VerificationStatus.UNVERIFIED
                elif scenario == "no_getter_assertion":
                    asset.ownership[0].method = "metadata_owner"
                elif scenario == "wrong_assertion_owner":
                    asset.ownership[0].owner_address = OTHER
                elif scenario == "missing_evidence":
                    nft.evidence = []
                else:
                    nft.evidence[0].relation = "public_profile_owner"
                collector = AsyncMock()
                self.assertIsNone(resolve_verified_nft_owner(nft))
                with patch("app.ton_nft.service.investigate_ton_nft", AsyncMock(return_value=nft)):
                    report, graph = await analyze_search_input("424242.ton", address_analyzer=collector)
                collector.assert_not_awaited()
                self.assertIsNone(report.input_resolution["owner_analysis_address"])
                self.assertEqual(report.input_resolution["owner_analysis_status"], "not_started")
                self.assertTrue(report.nft_intelligence)

    async def test_verified_owner_contract_is_analyzed_without_identity_claim(self):
        nft = nft_fixture()
        nft.assets[0].owner_account = {"address": OWNER, "account_type": "sale_or_escrow_contract",
                                      "status": "provider_reported", "is_wallet": False}
        collect = AsyncMock(return_value=(wallet_fixture(), {}))
        with patch("app.ton_nft.service.investigate_ton_nft", AsyncMock(return_value=nft)):
            report, graph = await analyze_search_input("424242.ton", address_analyzer=collect)
        self.assertEqual(collect.await_args.args, (OWNER,))
        self.assertEqual(report.input_resolution["account_type"], "sale_or_escrow_contract")
        self.assertFalse(any(identity.identity_verified for identity in report.telegram_identities))

    async def test_normal_ton_wallet_keeps_legacy_target(self):
        nft = NFTIntelligenceReport(investigation_id="wallet-fixture", query=OWNER, scope="wallet", mode="deep",
            discovery=DiscoveryResult(normalized_query=OWNER, query_kind="address", status="resolved",
                candidates=[DiscoveryCandidate(address=OWNER, reason="Fixture wallet account")]))
        collect = AsyncMock(return_value=(wallet_fixture(), {}))
        with patch("app.ton_nft.service.investigate_ton_nft", AsyncMock(return_value=nft)):
            report, graph = await analyze_search_input(OWNER, address_analyzer=collect)
        self.assertEqual(collect.await_args.args, (OWNER,))
        self.assertEqual(report.target_address, OWNER)
        self.assertIsNone(report.input_resolution["owner_analysis_address"])
        self.assertEqual(report.balances[0].amount, 12)

    async def test_partial_budget_and_resume_checkpoints_preserve_owner_pipeline(self):
        store_directory = tempfile.TemporaryDirectory()
        self.addCleanup(store_directory.cleanup)
        nft = nft_fixture()
        nft.warnings.append("Fixture request budget reached; resume checkpoint retained")
        custom = InvestigationBudget.for_mode("deep").model_copy(update={"max_requests": 5, "max_pages": 2})
        options = {"mode": "standard", "budget": custom, "scope": "auto", "resume": True,
                   "incremental": True, "investigation_id": "owner-pipeline-fixture", "store_path": Path(store_directory.name) / "fixture.sqlite3"}
        original = dict(options)
        investigation = AsyncMock(return_value=nft)
        collect = AsyncMock(return_value=(wallet_fixture(), {}))
        with patch("app.ton_nft.service.investigate_ton_nft", investigation):
            report, graph = await analyze_search_input("424242.ton", nft_options=options, address_analyzer=collect)
        forwarded = investigation.await_args.kwargs
        self.assertEqual(forwarded["mode"], "deep")
        self.assertEqual(forwarded["budget"].max_requests, 5)
        self.assertEqual(forwarded["budget"].max_pages, 2)
        for key in ("resume", "incremental", "investigation_id", "store_path", "scope"):
            self.assertEqual(forwarded[key], options[key])
        self.assertEqual(options, original)
        self.assertEqual(report.nft_intelligence["checkpoints"], nft.checkpoints)
        self.assertEqual(report.nft_intelligence["coverage"][0]["next_cursor"], "122")
        self.assertEqual(report.input_resolution["owner_analysis_status"], "partial")
        self.assertEqual(report.balances[0].amount, 12)

    async def test_default_owner_search_has_maximum_supported_finite_budget(self):
        investigation = AsyncMock(return_value=nft_fixture())
        collect = AsyncMock(return_value=(wallet_fixture(), {}))
        with patch("app.ton_nft.service.investigate_ton_nft", investigation):
            await analyze_search_input("424242.ton", address_analyzer=collect)
        budget = investigation.await_args.kwargs["budget"]
        self.assertEqual(budget, InvestigationBudget.for_mode("deep"))
        self.assertGreater(budget.max_seconds, 0)
        self.assertLessEqual(budget.max_seconds, 3600)
        self.assertEqual(collect.await_args.kwargs["max_txs"], 100000)
        self.assertTrue(collect.await_args.kwargs["include_experimental"])

    async def test_non_ton_chains_keep_explicit_chain_and_maximum_retained_limit(self):
        cases = {"btc": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "doge": "D89DhnsgKncmN12RejxudfU8AwXp3946q1",
                 "tron": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "solana": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"}
        cases.update({chain: "0x" + "1" * 40 for chain in ("eth", "bsc", "polygon", "arbitrum", "optimism", "avalanche")})
        investigation = AsyncMock()
        for chain, query in cases.items():
            with self.subTest(chain=chain):
                expected = AddressReport(target_address=query, detected_chains=[chain])
                collect = AsyncMock(return_value=(expected, {"nodes": []}))
                with patch("app.ton_nft.service.investigate_ton_nft", investigation):
                    report, graph = await analyze_search_input(query, selected_chains=[chain], address_analyzer=collect)
                self.assertIs(report, expected)
                self.assertEqual(collect.await_args.args, (query,))
                self.assertEqual(collect.await_args.kwargs["selected_chains"], [chain])
                self.assertEqual(collect.await_args.kwargs["max_txs"], 100000)
                self.assertTrue(collect.await_args.kwargs["include_experimental"])
        investigation.assert_not_awaited()

    async def test_discovery_outage_keeps_ton_address_and_source_error_visible(self):
        collect = AsyncMock(return_value=(wallet_fixture(), build_graph_payload(wallet_fixture())))
        with patch("app.ton_nft.service.investigate_ton_nft", AsyncMock(side_effect=RuntimeError("fixture discovery unavailable"))):
            report, graph = await analyze_search_input(OWNER, address_analyzer=collect)
        self.assertEqual(report.target_address, OWNER)
        self.assertEqual(report.input_resolution["discovery_status"], "unavailable")
        self.assertTrue(any("fixture discovery unavailable" in warning for warning in report.warnings))
        self.assertEqual(report.balances[0].amount, 12)

    async def test_owner_analysis_failure_retains_exact_nft_evidence(self):
        collect = AsyncMock(side_effect=RuntimeError("fixture owner source failure"))
        with patch("app.ton_nft.service.investigate_ton_nft", AsyncMock(return_value=nft_fixture())):
            report, graph = await analyze_search_input("424242.ton", address_analyzer=collect)
        self.assertEqual(report.target_address, OWNER)
        self.assertTrue(any("fixture owner source failure" in error for error in report.errors))
        self.assertEqual(report.nft_intelligence["assets"][0]["address"], ITEM)
        self.assertEqual(report.input_resolution["owner_analysis_status"], "failed")
        self.assertEqual(report.coverage["search_execution"]["status"], "failed")
        self.assertTrue(graph["nodes"])

    async def test_quiet_and_live_entrypoints_use_same_search_helper(self):
        from app import main
        for entry in (main._analyze_quiet, main._analyze_with_live_console):
            with self.subTest(entry=entry.__name__), tempfile.TemporaryDirectory() as directory:
                expected = wallet_fixture()
                shared = AsyncMock(return_value=(expected, build_graph_payload(expected)))
                with patch.object(main, "analyze_search_input", shared), \
                     patch.object(main, "export_html", return_value=Path(directory) / "report.html"), \
                     patch.object(main, "export_pdf", AsyncMock()) as pdf, \
                     patch.object(main, "console", Console(file=io.StringIO(), width=120)):
                    report, html, pdf_path = await entry("424242.ton", Path(directory))
                self.assertIs(report, expected)
                self.assertEqual(shared.await_args.args, ("424242.ton",))
                self.assertEqual(shared.await_args.kwargs["max_txs"], 100000)
                self.assertIs(shared.await_args.kwargs["address_analyzer"], main.analyze_address)
                self.assertIsNone(pdf_path)
                pdf.assert_not_awaited()

    async def test_batch_uses_shared_search_for_each_input(self):
        from app import main
        with tempfile.TemporaryDirectory() as directory:
            inputs = Path(directory) / "inputs.txt"
            inputs.write_text("424242.ton\n" + OWNER + "\n", encoding="utf-8")
            console = Console(file=io.StringIO(), width=120)
            console.input = Mock(side_effect=[str(inputs), ""])
            shared = AsyncMock(side_effect=lambda query, **kwargs: (wallet_fixture(), build_graph_payload(wallet_fixture())))
            with patch.object(main, "console", console), patch.object(main, "analyze_search_input", shared), \
                 patch.object(main, "export_html", return_value=Path(directory) / "report.html"):
                await main.batch_flow()
            self.assertEqual({call.args[0] for call in shared.await_args_list}, {"424242.ton", OWNER})
            self.assertEqual(shared.await_count, 2)
            self.assertTrue(all(call.kwargs["max_txs"] == 100000 for call in shared.await_args_list))


class OwnerSearchPromptTests(unittest.TestCase):
    def test_interactive_scenario_does_not_ask_for_depth(self):
        from app import main
        result = wallet_fixture()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.html"
            console = Console(file=io.StringIO())
            console.input = Mock(side_effect=["424242.ton"])
            with patch.object(main, "console", console), \
                 patch.object(main, "_analyze_with_live_console", AsyncMock(return_value=(result, output, None))) as run, \
                 patch.object(main, "final_summary"), patch("webbrowser.open"):
                main.analyze_flow()
            self.assertEqual(console.input.call_count, 1)
            run.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
