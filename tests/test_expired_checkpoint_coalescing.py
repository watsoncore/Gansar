"""Synthetic orchestration races using real SQLite, graph and original HTML.

These fixtures never call providers and do not establish live history coverage.
Only nft_cli's clock binding is controlled; asyncio's real scheduler is intact.
"""
import asyncio
from contextlib import closing
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from app import main, nft_cli
from app.models.report import AddressReport, Transaction
from app.ton_nft.models import (DiscoveryCandidate, DiscoveryResult, IntelligenceEvidence,
    NFTAsset, NFTEvent, NFTIntelligenceReport, NFTOwnershipAssertion,
    SourceObservation, VerificationStatus)
from app.ton_nft.storage import InvestigationStore


TARGET = "0:" + "1" * 64
OTHER = "0:" + "2" * 64
ITEM = "0:" + "3" * 64
INVESTIGATION = "expired-checkpoint-coalescing"
RAW = {"public_fixture": "Публичное доказательство 💎", "values": [1, {"kept": True}]}


def wallet(chars="ab", target=TARGET):
    return AddressReport(target_address=target, detected_chains=["ton"], transactions=[
        Transaction(chain="ton", tx_hash=char * 64, source="synthetic_expired_checkpoint",
            raw={"public_proof": {"identity": char, "values": [char, {"kept": True}]}})
        for char in chars])


def native_ids(report):
    return {tx.tx_hash for tx in report.transactions if tx.source == "synthetic_expired_checkpoint"}


class _LocalAsyncioClock:
    """Delegate tasks/threads to asyncio without changing its scheduler clock."""
    def __init__(self, clock):
        self.clock = clock

    def get_running_loop(self):
        return SimpleNamespace(time=lambda: self.clock[0])

    def __getattr__(self, name):
        return getattr(asyncio, name)


class ExpiredCheckpointCoalescingTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, kind):
        clock = [100.0]
        deadline = 120.0
        collector_started, allow_owner, owner_complete = (asyncio.Event() for _ in range(3))
        preview_entered, release_preview = (asyncio.Event() for _ in range(2))
        owner_task = None
        previews, models, writes, trace = [], [], [], []
        inflight = kind == "inflight"
        first_preview = True
        original_save = InvestigationStore.save_snapshot
        baseline = wallet(target=OTHER if kind == "wrong_owner" else TARGET).model_dump(mode="json")

        async def probe(address, **kwargs):
            return {"report_fragment": wallet("c").model_dump(mode="json"),
                "descriptor": {"account_type": "wallet_contract"}, "evidence": [], "observations": []}

        def progress(event):
            if event["stage"] == "address.complete":
                trace.append("owner.complete")
                owner_complete.set()

        def retain(report):
            ids = native_ids(report)
            models.append({"native_ids": ids, "coverage": dict(report.coverage.get("search_execution", {})),
                "nft": report.model_dump(mode="json").get("nft_intelligence"),
                "input_resolution": dict(report.input_resolution)})
            if "d" * 64 in ids:
                trace.append("model.post_analysis")

        def save(store, value):
            owner = value.owner_analysis_snapshot
            if owner is not None:
                writes.append({"target": owner["target_address"],
                    "native_ids": {tx["tx_hash"] for tx in owner["transactions"]
                        if tx["source"] == "synthetic_expired_checkpoint"},
                    "status": owner.get("coverage", {}).get("search_execution", {}).get("status")})
            return original_save(store, value)

        async def ready(report, graph):
            nonlocal first_preview
            if report.coverage.get("search_execution", {}).get("priority") == "P0":
                await main._write_search_html(report, graph, output, checkpoint=True)
                return
            previews.append({"native_ids": native_ids(report), "errors": list(report.errors),
                "status": report.coverage.get("search_execution", {}).get("status")})
            if inflight and first_preview:
                first_preview = False
                trace.append("preview.entered")
                preview_entered.set()
                await release_preview.wait()
                await main._write_search_html(report, graph, output, checkpoint=True)
                trace.append("preview.first_saved")
            else:
                await main._write_search_html(report, graph, output, checkpoint=True)

        async def collect(address, **kwargs):
            nonlocal owner_task
            owner_task = asyncio.current_task()
            initial = kwargs.get("initial_report")
            result = initial.model_copy(deep=True) if initial is not None else wallet("c")
            result.transactions.append(wallet("d").transactions[0])
            if kind == "missing_history":
                result.transactions = [tx for tx in result.transactions if tx.tx_hash != "b" * 64]
            collector_started.set()
            try:
                await allow_owner.wait()
            except asyncio.CancelledError:
                if kind != "cancelled_owner":
                    raise
                result.coverage["search_execution"] = {"status": "stopped", "reason": "user_stop"}
            if kind == "error":
                raise RuntimeError("Synthetic owner failure after collection")
            if kind == "owner_stopped":
                result.coverage["search_execution"] = {"status": "stopped", "reason": "user_stop"}
            return result, {}

        async def investigate(query, **kwargs):
            value = kwargs["_resume_report"]
            with closing(InvestigationStore(path)) as store:
                store.save_observation(INVESTIGATION, SourceObservation(
                    observation_id="synthetic-retained-page", source="synthetic_expired_checkpoint",
                    upstream="synthetic", endpoint="https://example.org/fixture/page",
                    content_hash=hashlib.sha256(json.dumps(RAW, sort_keys=True).encode()).hexdigest(), raw=RAW))
            await kwargs["on_target_resolved"]({"scope": "wallet", "analysis_address": TARGET}, value)
            await asyncio.wait_for(collector_started.wait(), 5)
            preview_task = None
            try:
                if inflight:
                    # This view starts before expiry, then holds the checkpoint
                    # lock while the native owner finishes after expiry.
                    preview_task = asyncio.create_task(kwargs["on_checkpoint"](value))
                    await asyncio.wait_for(preview_entered.wait(), 5)
                if kind != "before_deadline":
                    clock[0] = deadline + 1
                if kind == "expired_nft_callback":
                    # Cadence is eligible, but the common source deadline has
                    # expired. Raw page/cursor persistence remains independent.
                    await kwargs["on_checkpoint"](value)
                if kind == "nft_stopped":
                    value.stats["stopped"] = True
                if kind == "cancelled_owner":
                    owner_task.cancel("synthetic user stop")
                else:
                    allow_owner.set()
                if kind != "error":
                    await asyncio.wait_for(owner_complete.wait(), 5)
                release_preview.set()
                if preview_task is not None:
                    await asyncio.wait_for(preview_task, 5)
                # Waiting here keeps enrichment_finished false until the actual
                # owner-finish publication (or its model-only defer) completes.
                await asyncio.wait_for(asyncio.shield(owner_task), 5)
                if inflight:
                    clock[0] += 1000
                    await kwargs["on_checkpoint"](value)
                with closing(InvestigationStore(path)) as store:
                    store.save_snapshot(value)  # Existing service final snapshot.
                return value
            finally:
                allow_owner.set()
                release_preview.set()
                if preview_task is not None:
                    await asyncio.gather(preview_task, return_exceptions=True)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshots.sqlite3"
            output = Path(directory) / "html"
            output.mkdir()
            seed = NFTIntelligenceReport(investigation_id=INVESTIGATION, query=TARGET, scope="wallet",
                checkpoints={"synthetic:history": {"cursor": 123, "exhausted": False}},
                discovery=DiscoveryResult(normalized_query=TARGET, query_kind="address", status="resolved",
                    candidates=[DiscoveryCandidate(address=ITEM, reason="Exact synthetic NFT fixture")]),
                assets=[NFTAsset(asset_id=ITEM, address=ITEM, initialized=True,
                    standard_status=VerificationStatus.VERIFIED_ONCHAIN, current_owner=TARGET,
                    current_owner_status=VerificationStatus.VERIFIED_ONCHAIN,
                    ownership=[NFTOwnershipAssertion(asset_address=ITEM, owner_address=TARGET,
                        status=VerificationStatus.VERIFIED_ONCHAIN, method="get_nft_data",
                        evidence_ids=["synthetic-owner-proof"])])],
                evidence=[IntelligenceEvidence(evidence_id="synthetic-owner-proof",
                    source="synthetic_expired_checkpoint", upstream="synthetic", observation_id="synthetic-retained-page",
                    relation="onchain_current_owner", status=VerificationStatus.VERIFIED_ONCHAIN,
                    explanation="Synthetic state assertion; never live provider evidence")],
                events=[NFTEvent(event_id="synthetic-retained-nft-event", asset_address=ITEM,
                    event_type="transfer", transaction_hash="e" * 64, from_address=OTHER,
                    to_address=TARGET, status="success", raw=RAW)], owner_analysis_snapshot=baseline)
            with closing(InvestigationStore(path)) as store:
                store.save_snapshot(seed)
            with patch.object(nft_cli, "asyncio", _LocalAsyncioClock(clock)), \
                    patch.object(nft_cli, "time", SimpleNamespace(monotonic=lambda: clock[0])), \
                    patch("app.ton_nft.service.investigate_ton_nft", investigate), \
                    patch("app.ton_attribution.probe_ton_account", probe), \
                    patch("app.ton_attribution.enrich_ton_service_intelligence", new=AsyncMock()), \
                    patch.object(InvestigationStore, "save_snapshot", save), \
                    patch("httpx.AsyncClient.request", new=AsyncMock(side_effect=AssertionError("No provider requests in synthetic regression"))):
                try:
                    report, graph = await asyncio.wait_for(nft_cli.analyze_search_input(TARGET,
                        continuous=True, deadline=deadline, address_analyzer=collect, progress=progress,
                        on_report_ready=ready, on_model_ready=retain,
                        nft_options={"store_path": path, "resume": True, "investigation_id": INVESTIGATION}), 15)
                finally:
                    allow_owner.set()
                    release_preview.set()
                    if owner_task is not None and not owner_task.done():
                        owner_task.cancel()
                        await asyncio.gather(owner_task, return_exceptions=True)
            # Same original atomic writer used by the main final pipeline.
            html = await main._write_search_html(report, graph, output)
            text = html.read_text(encoding="utf-8")
            payload = json.loads(text.split('<script id="nft-payload" type="application/json">', 1)[1].split('</script>', 1)[0])
            with closing(InvestigationStore(path)) as store:
                saved = store.load_snapshot(INVESTIGATION)
                raw = store.observation(INVESTIGATION, "synthetic-retained-page").raw
            self.assertEqual(raw, RAW)
            self.assertEqual(saved.checkpoints["synthetic:history"], {"cursor": 123, "exhausted": False})
            self.assertEqual(saved.events[0].raw, RAW)
            self.assertIn(RAW["public_fixture"], json.dumps(payload, ensure_ascii=False))
            self.assertFalse((output / "report.html.tmp").exists())
            for identity in native_ids(report):
                self.assertIn(identity, text)
            return {"report": report, "saved": saved, "previews": previews, "models": models,
                "writes": writes, "trace": trace, "baseline": baseline}

    def assert_complete_retention(self, result):
        expected = {char * 64 for char in "abcd"}
        self.assertEqual(native_ids(result["report"]), expected)
        self.assertEqual(sum(tx.event_id == "synthetic-retained-nft-event"
            for tx in result["report"].transactions), 1, "Final repeated attach must retain one exact NFT event projection")
        saved = result["saved"].owner_analysis_snapshot
        self.assertEqual({row["tx_hash"] for row in saved["transactions"]
            if row["source"] == "synthetic_expired_checkpoint"}, expected)
        by_id = {row["tx_hash"]: row for row in saved["transactions"]}
        for char in "abcd":
            self.assertEqual(by_id[char * 64]["raw"], wallet(char).transactions[0].raw)

    async def test_expired_owner_finish_coalesces_inflight_preview_and_preserves_final_dossier(self):
        result = await self._run("inflight")
        self.assertEqual(len(result["previews"]), 1, "Owner finish and expired NFT callback must not queue another full preview")
        self.assert_complete_retention(result)
        self.assertLess(result["trace"].index("model.post_analysis"), result["trace"].index("preview.first_saved"))
        post_analysis = next(model for model in result["models"] if "d" * 64 in model["native_ids"])
        self.assertEqual(post_analysis["nft"]["events"][0]["event_id"], "synthetic-retained-nft-event")
        self.assertEqual(post_analysis["nft"]["events"][0]["raw"], RAW)
        self.assertEqual(post_analysis["input_resolution"]["onchain_owner_address"], TARGET)
        self.assertEqual(post_analysis["input_resolution"]["ownership_status"], "verified_onchain")
        self.assertEqual(post_analysis["input_resolution"]["original_query"], TARGET)
        self.assertFalse(post_analysis["coverage"]["data_complete"])
        # One initial eligible preview can persist its current owner; only the
        # final joined write may persist the post-analysis four-native-ID model.
        self.assertEqual(sum(row["native_ids"] == {char * 64 for char in "abcd"} for row in result["writes"]), 1)

    async def test_expired_nft_callback_coalesces_eligible_view_without_losing_raw_or_cursor(self):
        result = await self._run("expired_nft_callback")
        self.assertEqual(result["previews"], [], "Expired ordinary NFT callback and normal owner finish must defer full preview")
        self.assert_complete_retention(result)
        self.assertEqual(len(result["writes"]), 1)

    async def test_before_deadline_owner_finish_keeps_forced_checkpoint(self):
        result = await self._run("before_deadline")
        self.assertEqual(len(result["previews"]), 1)
        self.assert_complete_retention(result)
        self.assertEqual(len(result["writes"]), 2)

    async def test_expired_owner_stop_keeps_forced_checkpoint(self):
        result = await self._run("owner_stopped")
        self.assertEqual(len(result["previews"]), 1)
        self.assertEqual(result["report"].coverage["search_execution"]["status"], "stopped")
        self.assert_complete_retention(result)

    async def test_actual_owner_task_cancellation_keeps_forced_stop_checkpoint(self):
        result = await self._run("cancelled_owner")
        self.assertEqual(len(result["previews"]), 1)
        self.assertEqual(result["report"].coverage["search_execution"]["status"], "stopped")
        self.assert_complete_retention(result)

    async def test_expired_nft_stop_keeps_forced_owner_checkpoint(self):
        result = await self._run("nft_stopped")
        self.assertEqual(len(result["previews"]), 1)
        self.assertEqual(result["report"].coverage["search_execution"]["status"], "stopped")
        self.assert_complete_retention(result)

    async def test_expired_owner_error_keeps_forced_checkpoint_and_durable_history(self):
        result = await self._run("error")
        self.assertEqual(len(result["previews"]), 1)
        self.assertTrue(any("Synthetic owner failure" in message for message in result["report"].errors))
        self.assertEqual(result["report"].coverage["search_execution"]["status"], "failed")
        self.assertEqual(result["saved"].owner_analysis_snapshot, result["baseline"])

    async def test_expired_wrong_owner_cannot_skip_forced_safety_boundary(self):
        result = await self._run("wrong_owner")
        self.assertEqual(len(result["previews"]), 1)
        self.assertEqual(result["saved"].owner_analysis_snapshot, result["baseline"])
        self.assertEqual(result["report"].nft_intelligence["owner_analysis_reference"]["location"], "snapshot_store")

    async def test_expired_missing_history_cannot_skip_forced_safety_boundary(self):
        result = await self._run("missing_history")
        self.assertEqual(len(result["previews"]), 1)
        self.assertEqual(result["saved"].owner_analysis_snapshot, result["baseline"])
        self.assertEqual(result["report"].nft_intelligence["owner_analysis_reference"]["location"], "snapshot_store")


if __name__ == "__main__":
    unittest.main()
