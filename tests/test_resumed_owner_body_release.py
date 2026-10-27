"""Resume drops its detached duplicate only after independent wallet handoff.

Small synthetic lifecycle tests use actual SQLite, without provider requests.
"""
import asyncio
from contextlib import closing
import gc
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
import weakref

from app import nft_cli
from app.models.report import AddressReport, Transaction
from app.ton_nft.models import NFTIntelligenceReport
from app.ton_nft.storage import InvestigationStore


TARGET = "0:" + "1" * 64
OTHER = "0:" + "2" * 64
INVESTIGATION = "resumed-owner-body-release"


def historical(target=TARGET):
    return AddressReport(target_address=target, detected_chains=["ton"], transactions=[
        Transaction(chain="ton", tx_hash=char * 64, source="retained_fixture",
            raw={"public_proof": {"values": [char, {"preserved": True}]}})
        for char in "ab"])


class ResumedOwnerBodyReleaseTests(unittest.IsolatedAsyncioTestCase):
    def create_store(self, directory, target=TARGET):
        path = Path(directory) / "snapshots.sqlite3"
        original = historical(target).model_dump(mode="json")
        with closing(InvestigationStore(path)) as store:
            store.save_snapshot(NFTIntelligenceReport(investigation_id=INVESTIGATION,
                query=TARGET, scope="wallet", owner_analysis_snapshot=original))
        return path, original

    def tracked_loader(self, references):
        original_load = nft_cli._load_resume_state
        def load(*args):
            header, owner = original_load(*args)
            references.append(weakref.ref(owner))
            return header, owner
        return load

    async def investigate(self, query, **kwargs):
        report = kwargs["_resume_report"]
        await kwargs["on_target_resolved"]({"scope": "wallet", "analysis_address": TARGET}, report)
        return report

    async def test_independent_initial_owner_releases_original_and_keeps_stale_checkpoint_guard(self):
        references, observed = [], []
        async def collect(address, **kwargs):
            initial = kwargs["initial_report"]
            # Let asyncio release the just-completed hydration wakeup handle;
            # the real collector also yields while its requests are running.
            await asyncio.sleep(0)
            gc.collect()
            self.assertIsNone(references[0](), "Detached historical owner is still retained by its orchestration closure")
            self.assertEqual([tx.raw for tx in initial.transactions], [tx.raw for tx in historical().transactions])
            # A queued P0 body must still be rejected after its full baseline
            # model is released; the immutable identity guard remains live.
            await kwargs["on_checkpoint"](AddressReport(target_address=TARGET))
            return initial, {}
        async def ready(report, graph):
            observed.append({tx.tx_hash for tx in report.transactions})
        with tempfile.TemporaryDirectory() as directory:
            path, _ = self.create_store(directory)
            with patch.object(nft_cli, "_load_resume_state", self.tracked_loader(references)), \
                    patch("app.ton_nft.service.investigate_ton_nft", self.investigate):
                report, _ = await nft_cli.analyze_search_input(TARGET, continuous=True,
                    address_analyzer=collect, on_report_ready=ready,
                    nft_options={"store_path": path, "resume": True, "investigation_id": INVESTIGATION})
            self.assertEqual({tx.tx_hash for tx in report.transactions}, {char * 64 for char in "ab"})
            self.assertTrue(observed)
            self.assertTrue(all({char * 64 for char in "ab"} <= rows for rows in observed))
            with closing(InvestigationStore(path)) as store:
                saved = store.load_snapshot(INVESTIGATION).owner_analysis_snapshot
            self.assertEqual([tx["raw"] for tx in saved["transactions"]], [tx.raw for tx in report.transactions])

    async def test_wrong_target_keeps_original_durable_owner_and_rejects_replacement(self):
        references = []
        async def collect(address, **kwargs):
            self.assertNotIn("initial_report", kwargs)
            self.assertIsNotNone(references[0]())
            return historical(), {}
        with tempfile.TemporaryDirectory() as directory:
            path, original = self.create_store(directory, OTHER)
            with patch.object(nft_cli, "_load_resume_state", self.tracked_loader(references)), \
                    patch("app.ton_nft.service.investigate_ton_nft", self.investigate):
                report, _ = await nft_cli.analyze_search_input(TARGET, continuous=True,
                    address_analyzer=collect,
                    nft_options={"store_path": path, "resume": True, "investigation_id": INVESTIGATION})
            self.assertEqual(report.nft_intelligence["owner_analysis_reference"]["location"], "snapshot_store")
            with closing(InvestigationStore(path)) as store:
                self.assertEqual(store.load_snapshot(INVESTIGATION).owner_analysis_snapshot, original)

    async def test_failed_independent_copy_keeps_historical_dossier(self):
        references = []
        original_copy = AddressReport.model_copy
        def copy(model, **kwargs):
            if references and model is references[0]():
                raise RuntimeError("Synthetic independent copy failure")
            return original_copy(model, **kwargs)
        collect = AsyncMock(side_effect=AssertionError("Cannot analyze without independent resume handoff"))
        with tempfile.TemporaryDirectory() as directory:
            path, original = self.create_store(directory)
            with patch.object(nft_cli, "_load_resume_state", self.tracked_loader(references)), \
                    patch.object(AddressReport, "model_copy", copy), \
                    patch("app.ton_nft.service.investigate_ton_nft", self.investigate):
                report, _ = await nft_cli.analyze_search_input(TARGET, continuous=True,
                    address_analyzer=collect,
                    nft_options={"store_path": path, "resume": True, "investigation_id": INVESTIGATION})
            collect.assert_not_awaited()
            self.assertTrue(any("Synthetic independent copy failure" in error for error in report.errors))
            self.assertEqual(report.nft_intelligence["owner_analysis_reference"]["location"], "snapshot_store")
            with closing(InvestigationStore(path)) as store:
                self.assertEqual(store.load_snapshot(INVESTIGATION).owner_analysis_snapshot, original)

    async def test_cancellation_after_handoff_preserves_full_sqlite_owner(self):
        references, released, ready, blocked = [], [], asyncio.Event(), asyncio.Event()
        async def collect(address, **kwargs):
            self.assertEqual({tx.tx_hash for tx in kwargs["initial_report"].transactions}, {char * 64 for char in "ab"})
            await asyncio.sleep(0)
            gc.collect()
            released.append(references[0]() is None)
            ready.set()
            await blocked.wait()
        async def investigate(query, **kwargs):
            await self.investigate(query, **kwargs)
            await blocked.wait()
        with tempfile.TemporaryDirectory() as directory:
            path, original = self.create_store(directory)
            with patch.object(nft_cli, "_load_resume_state", self.tracked_loader(references)), \
                    patch("app.ton_nft.service.investigate_ton_nft", investigate):
                task = asyncio.create_task(nft_cli.analyze_search_input(TARGET, continuous=True,
                    address_analyzer=collect,
                    nft_options={"store_path": path, "resume": True, "investigation_id": INVESTIGATION}))
                try:
                    await asyncio.wait_for(ready.wait(), 3)
                    self.assertEqual(released, [True])
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                finally:
                    if not task.done():
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
            with closing(InvestigationStore(path)) as store:
                self.assertEqual(store.load_snapshot(INVESTIGATION).owner_analysis_snapshot, original)


if __name__ == "__main__":
    unittest.main()
