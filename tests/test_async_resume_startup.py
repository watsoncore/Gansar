"""Resume startup uses an owned SQLite thread; no live provider requests."""
import asyncio
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from app import nft_cli
from app.ton_nft.models import NFTIntelligenceReport
from app.ton_nft.storage import InvestigationStore
from app.models.report import AddressReport, Balance, Transaction
from app.ton_nft.models import DiscoveryResult, DiscoveryCandidate, NFTEvent


class AsyncResumeStartupTests(unittest.IsolatedAsyncioTestCase):
    async def test_after_hydration_nft_and_stale_p0_callbacks_preserve_full_history_before_collector_result(self):
        target="0:"+"1"*64
        collector_ready,release_collector=(asyncio.Event() for _ in range(2))
        ready_calls=[]
        async def probe(address,**kwargs):
            current=AddressReport(target_address=target,detected_chains=["ton"],transactions=[
                Transaction(chain="ton",tx_hash="c"*64,source="fresh_fixture")],balances=[
                Balance(chain="ton",address=target,asset="TON",amount=7,source="fresh_fixture")])
            return {"report_fragment":current.model_dump(mode="json"),"descriptor":{"account_type":"wallet_contract"},
                "evidence":[],"observations":[]}
        async def collect(address,**kwargs):
            initial=kwargs["initial_report"]
            collector_ready.set()
            # A queued source callback may still carry only the earlier P0
            # body. It cannot restore that body as the durable history base.
            stale=AddressReport(target_address=target,transactions=[Transaction(chain="ton",tx_hash="c"*64,source="fresh_fixture")])
            await kwargs["on_checkpoint"](stale)
            await release_collector.wait()
            return initial,{}
        async def investigate(query,**kwargs):
            report=kwargs["_resume_report"]
            await kwargs["on_target_resolved"]({"scope":"wallet","analysis_address":target},report)
            await asyncio.wait_for(collector_ready.wait(),timeout=3)
            await kwargs["on_checkpoint"](report)
            store=InvestigationStore(path)
            try:
                owner=store.load_snapshot("post-hydration-fixture").owner_analysis_snapshot
                self.assertEqual({row["tx_hash"] for row in owner["transactions"]},{char*64 for char in "abc"})
                self.assertEqual(owner["balances"][0]["amount"],7)
            finally:store.close()
            release_collector.set()
            return report
        async def ready(report,graph):ready_calls.append({tx.tx_hash for tx in report.transactions})
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"snapshots.sqlite3"
            original=AddressReport(target_address=target,detected_chains=["ton"],transactions=[
                Transaction(chain="ton",tx_hash=char*64,source="retained_fixture") for char in "ab"])
            store=InvestigationStore(path)
            store.save_snapshot(NFTIntelligenceReport(investigation_id="post-hydration-fixture",query=target,scope="wallet",
                owner_analysis_snapshot=original.model_dump(mode="json")));store.close()
            with patch("app.ton_nft.service.investigate_ton_nft",investigate), \
                    patch("app.ton_attribution.probe_ton_account",probe), \
                    patch("app.ton_attribution.enrich_ton_service_intelligence",new=AsyncMock()), \
                    patch.object(nft_cli,"SEARCH_CHECKPOINT_SECONDS",0):
                report,_=await nft_cli.analyze_search_input(target,continuous=True,address_analyzer=collect,
                    on_report_ready=ready,deadline=asyncio.get_running_loop().time()+30,
                    nft_options={"store_path":path,"resume":True,"investigation_id":"post-hydration-fixture"})
        self.assertEqual({tx.tx_hash for tx in report.transactions},{char*64 for char in "abc"})
        self.assertTrue(any({char*64 for char in "abc"}<=rows for rows in ready_calls))

    async def test_owner_failure_after_hydration_cannot_replace_historical_dossier_with_partial(self):
        target="0:"+"1"*64
        async def collect(*args,**kwargs):raise RuntimeError("Synthetic post-hydration failure")
        async def investigate(query,**kwargs):
            report=kwargs["_resume_report"]
            await kwargs["on_target_resolved"]({"scope":"wallet","analysis_address":target},report)
            await asyncio.sleep(.01)
            return report
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"snapshot.sqlite3"
            original=AddressReport(target_address=target,transactions=[Transaction(chain="ton",tx_hash="a"*64,source="fixture")]).model_dump(mode="json")
            store=InvestigationStore(path);store.save_snapshot(NFTIntelligenceReport(investigation_id="post-hydration-error",query=target,
                scope="wallet",owner_analysis_snapshot=original));store.close()
            with patch("app.ton_nft.service.investigate_ton_nft",investigate):
                report,_=await nft_cli.analyze_search_input(target,continuous=True,address_analyzer=collect,
                    nft_options={"store_path":path,"resume":True,"investigation_id":"post-hydration-error"})
            self.assertEqual(report.nft_intelligence["owner_analysis_reference"]["location"],"snapshot_store")
            self.assertTrue(any("post-hydration failure" in error for error in report.errors))
            store=InvestigationStore(path)
            try:self.assertEqual(store.load_snapshot("post-hydration-error").owner_analysis_snapshot,original)
            finally:store.close()

    async def test_p0_nft_render_in_flight_when_hydration_finishes_cannot_revert_owner(self):
        from app.graph.builder import build_graph_payload
        target="0:"+"1"*64
        clock=[0.0]
        loading,load_release,graph_entered,graph_release=(threading.Event() for _ in range(4))
        collector_ready=asyncio.Event();collector_release=asyncio.Event()
        original_loader=nft_cli._load_resume_state
        def slow_load(*args):
            loading.set()
            if not load_release.wait(5):raise TimeoutError("Fixture owner release missing")
            return original_loader(*args)
        def graph(report):
            if report.coverage.get("search_execution",{}).get("partial_checkpoint") and len(report.transactions)==1:
                graph_entered.set()
                if not graph_release.wait(5):raise TimeoutError("Fixture graph release missing")
            return build_graph_payload(report)
        async def probe(address,**kwargs):
            value=AddressReport(target_address=target,transactions=[Transaction(chain="ton",tx_hash="c"*64,source="fresh")])
            return {"report_fragment":value.model_dump(mode="json"),"descriptor":{"account_type":"wallet_contract"},"evidence":[],"observations":[]}
        async def collect(address,**kwargs):
            collector_ready.set();await collector_release.wait();return kwargs["initial_report"],{}
        async def investigate(query,**kwargs):
            value=kwargs["_resume_report"]
            await kwargs["on_target_resolved"]({"scope":"wallet","analysis_address":target},value)
            for _ in range(100):
                if loading.is_set():break
                await asyncio.sleep(.01)
            earlier=asyncio.create_task(kwargs["on_checkpoint"](value))
            try:
                for _ in range(100):
                    if graph_entered.is_set():break
                    await asyncio.sleep(.01)
                self.assertTrue(graph_entered.is_set())
                load_release.set();await asyncio.wait_for(collector_ready.wait(),timeout=3)
                graph_release.set();await earlier
                clock[0]=100  # A subsequent preview is eligible after its measured gap.
                await kwargs["on_checkpoint"](value)
                store=InvestigationStore(path)
                try:
                    rows=store.load_snapshot("in-flight-p0").owner_analysis_snapshot["transactions"]
                    self.assertEqual({row["tx_hash"] for row in rows},{char*64 for char in "abc"})
                finally:store.close()
            finally:
                load_release.set();graph_release.set();collector_release.set()
                await earlier
            return value
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"snapshot.sqlite3"
            original=AddressReport(target_address=target,transactions=[Transaction(chain="ton",tx_hash=char*64,source="old") for char in "ab"])
            store=InvestigationStore(path);store.save_snapshot(NFTIntelligenceReport(investigation_id="in-flight-p0",query=target,
                scope="wallet",owner_analysis_snapshot=original.model_dump(mode="json")));store.close()
            with patch.object(nft_cli,"_load_resume_state",slow_load),patch.object(nft_cli,"SEARCH_CHECKPOINT_SECONDS",0), \
                    patch.object(nft_cli,"time",SimpleNamespace(monotonic=lambda:clock[0])), \
                    patch("app.graph.builder.build_graph_payload",graph),patch("app.ton_attribution.probe_ton_account",probe), \
                    patch("app.ton_attribution.enrich_ton_service_intelligence",new=AsyncMock()), \
                    patch("app.ton_nft.service.investigate_ton_nft",investigate):
                result,_=await nft_cli.analyze_search_input(target,continuous=True,address_analyzer=collect,
                    on_report_ready=AsyncMock(),deadline=asyncio.get_running_loop().time()+30,
                    nft_options={"store_path":path,"resume":True,"investigation_id":"in-flight-p0"})
        self.assertEqual({tx.tx_hash for tx in result.transactions},{char*64 for char in "abc"})

    async def test_failed_hydration_preserves_historical_sqlite_owner_and_truthful_reference(self):
        target="0:"+"1"*64
        async def investigate(query,**kwargs):
            report=kwargs["_resume_report"]
            await kwargs["on_target_resolved"]({"scope":"wallet","analysis_address":target},report)
            await asyncio.sleep(.01)
            return report
        collect=AsyncMock(side_effect=AssertionError("No analyzer without retained owner load"))
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"snapshots.sqlite3"
            original=AddressReport(target_address=target,detected_chains=["ton"],transactions=[
                Transaction(chain="ton",tx_hash=char*64,source="retained_fixture") for char in "ab"]).model_dump(mode="json")
            store=InvestigationStore(path)
            store.save_snapshot(NFTIntelligenceReport(investigation_id="failed-hydration",query=target,scope="wallet",
                owner_analysis_snapshot=original));store.close()
            with patch.object(nft_cli,"_load_resume_state_async",new=AsyncMock(side_effect=OSError("Synthetic hydration failure"))), \
                    patch("app.ton_nft.service.investigate_ton_nft",investigate):
                report,_=await nft_cli.analyze_search_input(target,continuous=True,address_analyzer=collect,
                    on_report_ready=AsyncMock(),
                    nft_options={"store_path":path,"resume":True,"investigation_id":"failed-hydration"})
            self.assertTrue(any("Synthetic hydration failure" in error for error in report.errors))
            self.assertEqual(report.coverage["search_execution"]["status"],"failed")
            self.assertEqual(report.nft_intelligence["owner_analysis_reference"]["location"],"snapshot_store")
            self.assertEqual(report.nft_intelligence["owner_analysis_reference"]["investigation_id"],"failed-hydration")
            store=InvestigationStore(path)
            try:self.assertEqual(store.load_snapshot("failed-hydration").owner_analysis_snapshot,original)
            finally:store.close()
            collect.assert_not_awaited()

    async def test_detached_owner_load_follows_p0_and_cannot_be_overwritten_by_nft_checkpoint(self):
        target="0:"+"1"*64;item="0:"+"2"*64
        loading,release=(threading.Event() for _ in range(2))
        p0,checkpoint=(asyncio.Event() for _ in range(2));order=[]
        original=nft_cli._load_resume_state
        def slow_load(*args):
            order.append("owner_load");loading.set()
            if not release.wait(5):raise TimeoutError("Deferred fixture load not released")
            return original(*args)
        async def probe(address,**kwargs):
            fragment=AddressReport(target_address=target,detected_chains=["ton"],
                balances=[Balance(chain="ton",address=target,asset="TON",amount=7,source="fresh_fixture")],
                transactions=[Transaction(chain="ton",tx_hash="c"*64,source="fresh_fixture")])
            return {"report_fragment":fragment.model_dump(mode="json"),
                "descriptor":{"account_type":"wallet_contract"},"evidence":[],"observations":[]}
        async def ready(report,graph):
            if report.coverage.get("search_execution",{}).get("priority")=="P0":
                order.append("p0_html");p0.set()
        async def collect(address,**kwargs):
            initial=kwargs["initial_report"]
            self.assertEqual({tx.tx_hash for tx in initial.transactions},{char*64 for char in "abc"})
            self.assertEqual(initial.balances[0].amount,7)
            return initial,{}
        async def investigate(query,**kwargs):
            report=kwargs["_resume_report"]
            self.assertIsNone(report.owner_analysis_snapshot)
            await kwargs["on_target_resolved"]({"scope":"wallet","analysis_address":target},report)
            for _ in range(100):
                if loading.is_set():break
                await asyncio.sleep(.01)
            self.assertTrue(loading.is_set())
            await kwargs["on_checkpoint"](report)
            checkpoint.set()
            return report
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"snapshots.sqlite3"
            historical=AddressReport(target_address=target,detected_chains=["ton"],
                transactions=[Transaction(chain="ton",tx_hash=char*64,source="retained_fixture") for char in "ab"])
            store=InvestigationStore(path)
            store.save_snapshot(NFTIntelligenceReport(investigation_id="deferred-fixture",query=target,scope="wallet",
                discovery=DiscoveryResult(normalized_query=target,query_kind="address",status="resolved",
                    candidates=[DiscoveryCandidate(address=target,reason="Synthetic wallet")]),
                events=[NFTEvent(event_id="retained-nft-event",asset_address=item,event_type="transfer",
                    transaction_hash="d"*64,from_address=item,to_address=target,status="success")],
                owner_analysis_snapshot=historical.model_dump(mode="json")))
            store.close()
            with patch.object(nft_cli,"_load_resume_state",slow_load), \
                    patch("app.ton_nft.service.investigate_ton_nft",investigate), \
                    patch("app.ton_attribution.probe_ton_account",probe), \
                    patch("app.ton_attribution.enrich_ton_service_intelligence",new=AsyncMock()):
                task=asyncio.create_task(nft_cli.analyze_search_input(target,continuous=True,
                    deadline=asyncio.get_running_loop().time()+30,address_analyzer=collect,on_report_ready=ready,
                    nft_options={"store_path":path,"resume":True,"investigation_id":"deferred-fixture"}))
                try:
                    await asyncio.wait_for(p0.wait(),timeout=3)
                    await asyncio.wait_for(checkpoint.wait(),timeout=3)
                    self.assertEqual(order[:2],["p0_html","owner_load"])
                    # The available P0 model has one fresh row; it must never
                    # replace the still-loading historical two-row owner.
                    store=InvestigationStore(path)
                    try:self.assertEqual(len(store.load_snapshot("deferred-fixture").owner_analysis_snapshot["transactions"]),2)
                    finally:store.close()
                finally:
                    release.set();report,_=await asyncio.wait_for(task,timeout=4)
            self.assertEqual({tx.tx_hash for tx in report.transactions},{char*64 for char in "abcd"})

    async def test_legacy_inline_uses_one_full_loader_after_lightweight_header_detection(self):
        target="0:"+"1"*64
        async def investigate(query,**kwargs):
            report=kwargs["_resume_report"]
            await kwargs["on_target_resolved"]({"scope":"wallet","analysis_address":target},report)
            return report
        async def collect(address,**kwargs):return kwargs["initial_report"],{}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"snapshots.sqlite3"
            old=NFTIntelligenceReport(investigation_id="legacy-once",query=target,scope="wallet",
                owner_analysis_snapshot=AddressReport(target_address=target,transactions=[
                    Transaction(chain="ton",tx_hash="a"*64,source="fixture")]).model_dump(mode="json"))
            store=InvestigationStore(path)
            store.db.execute("INSERT INTO investigations VALUES(?,?,?,?,?)",("legacy-once",target,"1.0","2026-10-17",old.model_dump_json()))
            store.db.commit();store.close()
            with patch.object(nft_cli,"_load_resume_state",wraps=nft_cli._load_resume_state) as full, \
                    patch.object(nft_cli,"_load_resume_header",wraps=nft_cli._load_resume_header) as header, \
                    patch("app.ton_nft.service.investigate_ton_nft",investigate):
                report,_=await nft_cli.analyze_search_input(target,continuous=True,address_analyzer=collect,
                    nft_options={"store_path":path,"resume":True,"investigation_id":"legacy-once"})
            self.assertEqual(full.call_count,1)
            self.assertEqual(header.call_count,1)
            self.assertEqual(len(report.transactions),1)

    async def test_detached_query_mismatch_rejects_before_owner_hydration_or_http(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"snapshots.sqlite3"
            store=InvestigationStore(path)
            store.save_snapshot(NFTIntelligenceReport(investigation_id="wrong-query",query="999999.ton",
                owner_analysis_snapshot={"target_address":"historical-owner"}))
            store.close()
            with patch.object(nft_cli,"_load_resume_state_async",new=AsyncMock()) as full, \
                    patch("httpx.AsyncClient.send",new=AsyncMock(side_effect=AssertionError("Unexpected HTTP"))) as http:
                with self.assertRaisesRegex(ValueError,"query differs"):
                    await nft_cli.analyze_search_input("424242.ton",continuous=True,
                        nft_options={"store_path":path,"resume":True,"investigation_id":"wrong-query"})
            full.assert_not_awaited();http.assert_not_awaited()

    async def test_sqlite_connection_is_created_loaded_and_closed_in_the_same_worker_thread(self):
        main_thread=threading.get_ident();operations=[]
        class TrackingStore(InvestigationStore):
            def __init__(self,*args,**kwargs):
                self.created_on=threading.get_ident();operations.append(("create",self.created_on))
                super().__init__(*args,**kwargs)
            def load_snapshot(self,*args,**kwargs):
                operations.append(("load",threading.get_ident()))
                if threading.get_ident()!=self.created_on:raise AssertionError("SQLite handle crossed threads")
                return super().load_snapshot(*args,**kwargs)
            def close(self):
                operations.append(("close",threading.get_ident()))
                if threading.get_ident()!=self.created_on:raise AssertionError("SQLite handle closed on different thread")
                super().close()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"snapshots.sqlite3"
            store=InvestigationStore(path)
            original={"target_address":"0:"+"1"*64,"detected_chains":["ton"],
                "transactions":[{"chain":"ton","tx_hash":"a"*64,"source":"fixture"}],
                "attribution_intelligence":{"large_legacy_copy":{"preserved_in_sqlite":True}},
                "balances":[{"amount":999}]}
            report=NFTIntelligenceReport(investigation_id="thread-fixture",query="fixture.ton",owner_analysis_snapshot=original)
            store.save_snapshot(report);store.close()
            with patch("app.ton_nft.storage.InvestigationStore",TrackingStore):
                saved,retained=await nft_cli._load_resume_state_async("thread-fixture",path)
            self.assertEqual([op for op,_ in operations],["create","load","close"])
            self.assertEqual(len({tid for _,tid in operations}),1)
            self.assertNotEqual(operations[0][1],main_thread)
            self.assertEqual(len(retained.transactions),1)
            self.assertEqual(retained.balances,[])
            self.assertEqual(retained.attribution_intelligence,{})
            self.assertIsNone(saved.owner_analysis_snapshot)
            store=InvestigationStore(path)
            try:self.assertEqual(store.load_snapshot("thread-fixture").owner_analysis_snapshot,original)
            finally:store.close()

    async def test_slow_legacy_startup_does_not_starve_unrelated_coroutines(self):
        started,release=(threading.Event() for _ in range(2));thread_ids=[]
        def loading(*args):
            thread_ids.append(threading.get_ident());started.set()
            if not release.wait(3):raise TimeoutError("Fixture load release missing")
            return "loaded","retained"
        with patch.object(nft_cli,"_load_resume_state",loading):
            task=asyncio.create_task(nft_cli._load_resume_state_async("fixture",None))
            try:
                for _ in range(100):
                    if started.is_set():break
                    await asyncio.sleep(.01)
                self.assertTrue(started.is_set())
                pulses=[]
                for _ in range(5):
                    pulses.append("independent P0 can progress")
                    await asyncio.sleep(.01)
                self.assertEqual(len(pulses),5)
                self.assertFalse(task.done())
            finally:
                release.set();result=await asyncio.wait_for(task,timeout=2)
            self.assertEqual(result,("loaded","retained"))
            self.assertNotEqual(thread_ids[0],threading.get_ident())

    async def test_cancel_waits_for_load_transaction_and_close_even_after_second_cancel(self):
        started,release,closed=(threading.Event() for _ in range(3))
        def loading(*args):
            started.set()
            try:
                if not release.wait(3):raise TimeoutError("Fixture cancellation release missing")
                return "loaded","retained"
            finally:closed.set()
        with patch.object(nft_cli,"_load_resume_state",loading):
            task=asyncio.create_task(nft_cli._load_resume_state_async("fixture",None))
            for _ in range(100):
                if started.is_set():break
                await asyncio.sleep(.01)
            self.assertTrue(started.is_set());task.cancel();await asyncio.sleep(.02)
            self.assertFalse(task.done());self.assertFalse(closed.is_set())
            task.cancel();await asyncio.sleep(.02)
            self.assertFalse(task.done())
            release.set()
            with self.assertRaises(asyncio.CancelledError):await asyncio.wait_for(task,timeout=2)
            self.assertTrue(closed.is_set())
