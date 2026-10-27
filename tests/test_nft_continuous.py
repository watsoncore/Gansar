"""Synthetic scheduler/cancellation regressions; never live provider evidence."""
import asyncio
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.ton_nft.models import InvestigationBudget, NFTIntelligenceReport
from app.ton_nft.providers import Payload
from app.ton_nft.service import NFTInvestigator, investigate_ton_nft
from app.ton_nft.storage import InvestigationStore


class ContinuousNftTests(unittest.IsolatedAsyncioTestCase):
    async def _scheduler(self, maximum):
        calls=[]
        with tempfile.TemporaryDirectory() as directory:
            store=InvestigationStore(Path(directory)/"snapshots.sqlite3")
            try:
                report=NFTIntelligenceReport(investigation_id="scheduler-fixture",query="fixture.ton",
                    budget=InvestigationBudget(max_pages=maximum,page_size=1,max_seconds=10))
                investigator=NFTInvestigator(report,store,priority_scheduling=True,continuous=True)
                provider=SimpleNamespace(name="fixture",upstream="fixture")
                async def fetch(name,cursor,size):
                    calls.append((name,cursor))
                    return Payload({"rows":[{"index":cursor}] if cursor<2 else []},f"{name}:{cursor}","fixture","fixture","https://example.org")
                for name in ("a","b"):
                    async def request(cursor,size,name=name):return await fetch(name,cursor,size)
                    await investigator.page_stream(name,provider,request,"rows",lambda *args:None)
                self.assertEqual(calls,[("a",0),("b",0)])
                await investigator.drain_priority_streams()
                return calls,report
            finally:store.close()

    async def test_first_page_slice_continues_automatically_and_fairly(self):
        calls,report=await self._scheduler(10)
        self.assertEqual(calls,[("a",0),("b",0),("a",1),("b",1),("a",2),("b",2)])
        for stream in ("a","b"):
            self.assertTrue(report.checkpoints[stream]["exhausted"])
            coverage=next(c for c in report.coverage if c.scope==stream)
            self.assertEqual(coverage.records,2)
            self.assertFalse(coverage.complete)

    async def test_scheduler_cannot_reset_the_per_stream_page_ceiling(self):
        calls,report=await self._scheduler(2)
        self.assertEqual(calls,[("a",0),("b",0),("a",1),("b",1)])
        for stream in ("a","b"):
            self.assertFalse(report.checkpoints[stream]["exhausted"])
            coverage=next(c for c in report.coverage if c.scope==stream)
            self.assertEqual(coverage.pages,2)
            self.assertEqual(coverage.coverage_status,"TRUNCATED")
            self.assertEqual(coverage.next_cursor,"2")

    async def test_incremental_refresh_keeps_and_drains_old_unfinished_history_tail(self):
        calls=[]
        with tempfile.TemporaryDirectory() as directory:
            store=InvestigationStore(Path(directory)/"snapshots.sqlite3")
            try:
                stream="history:wallet:fixture:toncenter"
                report=NFTIntelligenceReport(investigation_id="incremental-fixture",query="fixture.ton",
                    checkpoints={stream:{"cursor":3,"exhausted":False}},
                    budget=InvestigationBudget(max_pages=10,page_size=1,max_seconds=10))
                investigator=NFTInvestigator(report,store,priority_scheduling=True,continuous=True,incremental=True)
                self.assertEqual(report.checkpoints["retained_history_tails"][stream]["cursor"],3)
                provider=SimpleNamespace(name="fixture",upstream="fixture")
                async def fetch(cursor,size):
                    calls.append(cursor)
                    return Payload({"rows":[{"index":cursor}] if cursor<5 else []},str(cursor),"fixture","fixture","https://example.org")
                await investigator.page_stream(stream,provider,fetch,"rows",lambda *args:None)
                self.assertEqual(calls,[0])
                await investigator.drain_priority_streams()
                self.assertEqual(calls[:3],[0,3,1])
                self.assertTrue(report.checkpoints[stream+":retained_tail"]["exhausted"])
                self.assertTrue(report.checkpoints[stream]["exhausted"])
                self.assertNotIn(stream,report.checkpoints["retained_history_tails"])
            finally:store.close()

    def test_projection_preserves_complete_raw_once_with_stable_resolvable_references(self):
        from test_nft_report_bridge import fixture_report
        from app.ton_nft.service import report_to_address_report
        original=fixture_report()
        marker="unique_full_provider_evidence_marker"
        original.events[0].raw["unknown_provider_evidence"]={"marker":marker,"body":"publicbody"*4000}
        projected=report_to_address_report(original)
        tx=next(tx for tx in projected.transactions if tx.event_id==original.events[0].event_id)
        ref=tx.raw["nft_intelligence"]["raw_reference"]
        self.assertEqual(ref,{"collection":"events","id":original.events[0].event_id})
        full=next(row for row in projected.nft_intelligence[ref["collection"]] if row["event_id"]==ref["id"])
        encode=lambda value:json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
        self.assertEqual(hashlib.sha256(encode(full["raw"])).hexdigest(),hashlib.sha256(encode(original.events[0].raw)).hexdigest())
        self.assertNotIn(marker,tx.model_dump_json())
        self.assertEqual(projected.model_dump_json().count(marker),1)
        asset=projected.ton_assets[0]
        self.assertEqual(asset.raw["nft_intelligence"]["raw_reference"],{"collection":"assets","id":original.assets[0].address})
        self.assertTrue(all("raw_reference" in event.raw["nft_intelligence"] for event in asset.history_events))

    async def test_inventory_item_ceiling_does_not_abort_history_or_lose_overflow_evidence(self):
        from test_nft_engine import FakeToncenter, FakeTonAPI, FakeTelegram, indexed_item, transfer, ITEM, ITEM2, OWNER
        items=[indexed_item(address=ITEM,index=1),indexed_item(address=ITEM2,index=2)]
        transfers=[transfer(address=ITEM,lt=200,tx="a"*64),transfer(address=ITEM2,lt=100,tx="b"*64)]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"snapshots.sqlite3"
            result=await investigate_ton_nft(OWNER,mode="deep",scope="wallet",store_path=path,
                investigation_id="inventory-cap-fixture",continuous=True,priority_scheduling=False,
                budget=InvestigationBudget(max_items=1,max_events=20,page_size=10,max_pages=10,
                    max_requests=100,max_seconds=20,requests_per_second=20,retries=0,
                    trace_depth=0,max_transaction_details=0),
                providers={"toncenter":FakeToncenter(items=items,transfers=transfers),
                    "tonapi":FakeTonAPI(items=items),"telegram_public":FakeTelegram()})
            self.assertEqual(len(result.assets),1)
            self.assertEqual({event.asset_address for event in result.events},{ITEM,ITEM2})
            self.assertEqual(len(result.events),2)
            self.assertIn(ITEM2,result.stats["asset_enrichment_pending"])
            self.assertFalse(result.stats.get("stopped",False))
            inventories=[c for c in result.coverage if c.scope.startswith("inventory:")]
            self.assertTrue(inventories)
            self.assertTrue(all(c.coverage_status=="TRUNCATED" for c in inventories))
            self.assertTrue(all(not result.checkpoints[c.scope]["exhausted"] for c in inventories))
            partial=next(c for c in inventories if c.records)
            checkpoint=result.checkpoints[partial.scope]
            self.assertEqual(checkpoint["cursor"],0)
            self.assertEqual(checkpoint["resume_row_index"],1)
            store=InvestigationStore(path)
            try:
                original=store.observation(result.investigation_id,checkpoint["raw_page_observation_id"])
                self.assertEqual(len(original.raw["nft_items"]),2)
                self.assertEqual(original.raw["nft_items"][1]["address"],ITEM2)
                saved=store.load_snapshot(result.investigation_id)
                self.assertEqual(len(saved.events),2)
            finally:store.close()
            resumed=await investigate_ton_nft(OWNER,mode="deep",scope="wallet",store_path=path,
                investigation_id="inventory-cap-fixture",resume=True,continuous=True,priority_scheduling=False,
                budget=InvestigationBudget(max_items=2,max_events=20,page_size=10,max_pages=10,
                    max_requests=100,max_seconds=20,requests_per_second=20,retries=0,
                    trace_depth=0,max_transaction_details=0),
                providers={"toncenter":FakeToncenter(items=items,transfers=transfers),
                    "tonapi":FakeTonAPI(items=items),"telegram_public":FakeTelegram()})
            self.assertEqual(len(resumed.assets),2)
            self.assertEqual(len(resumed.events),2)
            self.assertEqual(resumed.stats["asset_enrichment_pending_count"],0)
            self.assertNotIn(ITEM2,resumed.stats["asset_enrichment_pending"])

    async def test_already_loaded_resume_snapshot_is_reused_without_second_sqlite_parse(self):
        from test_nft_engine import ITEM
        snapshot=NFTIntelligenceReport(investigation_id="reuse-fixture",query=ITEM,
            checkpoints={"history:fixture":{"cursor":123,"exhausted":False}})
        seen=[]
        async def running(investigator,*args):
            seen.append(investigator.report)
            investigator.report.status="partial"
        with tempfile.TemporaryDirectory() as directory,patch.object(NFTInvestigator,"run",running), \
             patch.object(InvestigationStore,"load_snapshot",side_effect=AssertionError("Second snapshot load is forbidden")):
            result=await investigate_ton_nft(ITEM,mode="deep",scope="item",resume=True,
                investigation_id="reuse-fixture",store_path=Path(directory)/"snapshots.sqlite3",_resume_report=snapshot)
        self.assertIs(result,snapshot)
        self.assertIs(seen[0],snapshot)
        self.assertEqual(result.checkpoints["history:fixture"]["cursor"],123)

    async def test_loaded_resume_snapshot_still_requires_same_id_and_query(self):
        from test_nft_engine import ITEM, ITEM2
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"snapshots.sqlite3"
            snapshot=NFTIntelligenceReport(investigation_id="reuse-fixture",query=ITEM)
            with self.assertRaisesRegex(ValueError,"query differs"):
                await investigate_ton_nft(ITEM2,mode="deep",resume=True,investigation_id="reuse-fixture",store_path=path,_resume_report=snapshot)
            with self.assertRaisesRegex(ValueError,"investigation ID"):
                await investigate_ton_nft(ITEM,mode="deep",resume=True,investigation_id="another-fixture",store_path=path,_resume_report=snapshot)

    async def test_managed_stop_commits_unfinished_cursor_before_sqlite_closes(self):
        started=asyncio.Event()
        async def running(investigator,*args):
            investigator.report.checkpoints["fixture:history"]={"cursor":123,"exhausted":False}
            investigator.snapshot(force=True)
            started.set()
            await asyncio.Future()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"snapshots.sqlite3"
            with patch.object(NFTInvestigator,"run",running):
                task=asyncio.create_task(investigate_ton_nft("0:"+"1"*64,scope="wallet",mode="deep",
                    continuous=True,store_path=path,investigation_id="stop-fixture"))
                await asyncio.wait_for(started.wait(),timeout=2)
                task.cancel()
                result=await asyncio.wait_for(task,timeout=3)
            self.assertTrue(result.stats["stopped"])
            store=InvestigationStore(path)
            try:
                saved=store.load_snapshot("stop-fixture")
                self.assertEqual(saved.checkpoints["fixture:history"]["cursor"],123)
                self.assertFalse(saved.checkpoints["fixture:history"]["exhausted"])
                self.assertTrue(saved.stats["stopped"])
            finally:store.close()
