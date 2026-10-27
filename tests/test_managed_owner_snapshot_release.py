"""Managed CLI keeps full owner data in AddressReport/SQLite, not a third live copy.

Synthetic collectors below exercise real aggregation handoff, SQLite and graph.
They are lifecycle regressions, not live provider evidence.
"""
import asyncio
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from app.nft_cli import analyze_search_input
from app.models.report import AddressReport, Transaction
from app.ton_nft.models import DiscoveryCandidate, DiscoveryResult, NFTIntelligenceReport
from app.ton_nft.storage import InvestigationStore

TARGET = "0:" + "1" * 64


def header():
    return NFTIntelligenceReport(investigation_id="managed-owner-release", query=TARGET,
        scope="wallet", mode="deep", discovery=DiscoveryResult(normalized_query=TARGET,
            query_kind="address", status="resolved", candidates=[DiscoveryCandidate(address=TARGET,
                reason="Synthetic lifecycle fixture")]))


def wallet():
    return AddressReport(target_address=TARGET, detected_chains=["ton"], transactions=[
        Transaction(chain="ton", tx_hash=str(index), source="synthetic_owner_release",
            raw={"public_proof": {"record": index, "values": ["retained", index]}})
        for index in range(3)])


class ManagedOwnerSnapshotReleaseTests(unittest.IsolatedAsyncioTestCase):
    async def test_intermediate_commit_releases_copy_and_later_nft_page_uses_only_reference(self):
        nft, collected, release = header(), asyncio.Event(), asyncio.Event()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.sqlite3"
            async def collect(address, **kwargs):
                report = wallet()
                await kwargs["on_checkpoint"](report)
                collected.set()
                await release.wait()
                return report, {}
            async def investigate(query, **kwargs):
                await kwargs["on_target_resolved"]({"scope": "wallet", "analysis_address": TARGET}, nft)
                await asyncio.wait_for(collected.wait(), 5)
                self.assertIsNone(nft.owner_analysis_snapshot)
                with closing(InvestigationStore(path)) as store:
                    saved = store.load_snapshot(nft.investigation_id)
                    self.assertEqual([row["raw"] for row in saved.owner_analysis_snapshot["transactions"]],
                        [row.raw for row in wallet().transactions])
                    reference = dict(nft.owner_snapshot_reference)
                    nft.stats["pages"] = 2
                    with patch.object(store, "_owner_reference", side_effect=AssertionError("Reference-only page reserialized the owner")):
                        store.save_snapshot(nft)
                    self.assertEqual(nft.owner_snapshot_reference, reference)
                    self.assertEqual(len(store.load_snapshot(nft.investigation_id).owner_analysis_snapshot["transactions"]), 3)
                release.set()
                return nft
            with patch("app.ton_nft.service.investigate_ton_nft", investigate):
                try:
                    report, _ = await asyncio.wait_for(analyze_search_input(TARGET, continuous=True,
                        address_analyzer=collect, on_report_ready=AsyncMock(),
                        nft_options={"store_path": path}), 10)
                finally:
                    release.set()
            self.assertIsNone(nft.owner_analysis_snapshot)
            self.assertEqual(len(report.transactions), 3)
            self.assertNotIn("owner_analysis_snapshot", report.nft_intelligence)

    async def test_final_commit_releases_copy_without_losing_default_hydration_or_parent_proofs(self):
        nft = header()
        async def investigate(query, **kwargs):
            await kwargs["on_target_resolved"]({"scope": "wallet", "analysis_address": TARGET}, nft)
            return nft
        async def collect(address, **kwargs):
            return wallet(), {}
        with tempfile.TemporaryDirectory() as directory, patch("app.ton_nft.service.investigate_ton_nft", investigate):
            path = Path(directory) / "snapshot.sqlite3"
            report, _ = await analyze_search_input(TARGET, address_analyzer=collect, nft_options={"store_path": path})
            self.assertIsNone(nft.owner_analysis_snapshot)
            self.assertEqual(report.nft_intelligence["owner_analysis_reference"]["location"], "parent_address_report")
            with closing(InvestigationStore(path)) as store:
                stored = store.load_snapshot(nft.investigation_id)
                self.assertEqual(stored.owner_snapshot_reference, nft.owner_snapshot_reference)
                self.assertEqual([row["raw"] for row in stored.owner_analysis_snapshot["transactions"]],
                    [row.raw for row in report.transactions])

    async def test_failed_atomic_commit_keeps_pending_body_and_previous_durable_owner(self):
        nft = header()
        async def investigate(query, **kwargs):
            await kwargs["on_target_resolved"]({"scope": "wallet", "analysis_address": TARGET}, nft)
            return nft
        async def collect(address, **kwargs):
            return wallet(), {}
        with tempfile.TemporaryDirectory() as directory, patch("app.ton_nft.service.investigate_ton_nft", investigate):
            path = Path(directory) / "snapshot.sqlite3"
            nft.owner_analysis_snapshot = {"target_address": TARGET, "transactions": [], "public_previous": "retained"}
            with closing(InvestigationStore(path)) as store:
                store.save_snapshot(nft)
                previous = store.load_snapshot(nft.investigation_id).owner_analysis_snapshot
                store.db.execute("CREATE TRIGGER fail_managed_report BEFORE INSERT ON investigations BEGIN SELECT RAISE(ABORT,'synthetic commit failure'); END")
                store.db.commit()
            with self.assertRaisesRegex(sqlite3.IntegrityError, "synthetic commit failure"):
                await analyze_search_input(TARGET, address_analyzer=collect, nft_options={"store_path": path})
            self.assertEqual(len(nft.owner_analysis_snapshot["transactions"]), 3)
            with closing(InvestigationStore(path)) as store:
                self.assertEqual(store.load_snapshot(nft.investigation_id).owner_analysis_snapshot, previous)


if __name__ == "__main__":
    unittest.main()
