"""Lifecycle fault tests, not live-provider coverage or application proof."""
from __future__ import annotations
import asyncio
import contextlib
import io
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.models.report import AddressReport, Transaction

BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


class ContinuousWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def test_first_html_is_intermediate_and_same_file_retains_deeper_records(self):
        from app import main, search_worker
        from app.search_runtime import load_result
        from app.graph.builder import build_graph_payload
        first, release = asyncio.Event(), asyncio.Event()
        async def analysis(query, output, *, checkpoint_callback, continuous, deadline, **kwargs):
            self.assertTrue(continuous)
            self.assertGreater(deadline-asyncio.get_running_loop().time(), 60)
            early = AddressReport(target_address=query, detected_chains=["btc"], transactions=[
                Transaction(chain="btc", tx_hash=f"{number:064x}", source="fixture") for number in range(20)])
            graph = build_graph_payload(early)
            path = await main._write_search_html(early, graph, output, checkpoint=True)
            await checkpoint_callback(early, graph, path)
            first.set()
            await release.wait()
            final = early.model_copy(deep=True)
            final.transactions.extend(Transaction(chain="btc", tx_hash=f"{number:064x}", source="fixture") for number in range(20, 420))
            final.coverage["search_execution"] = {"status": "completed", "data_complete": False}
            path = await main._write_search_html(final, build_graph_payload(final), output)
            return final, path, None
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)/"session";session.mkdir()
            output = Path(directory)/"report"
            request = {"jobs": [{"query": BTC, "output": str(output)}], "language": "en",
                "session": str(session), "collection_seconds": 300, "first_result_seconds": 60}
            with patch.object(main, "_analyze_quiet", analysis), contextlib.redirect_stdout(io.StringIO()) as stdout:
                task = asyncio.create_task(search_worker.execute(request))
                try:
                    await asyncio.wait_for(first.wait(), timeout=12)
                    self.assertFalse(task.done())
                    preliminary = load_result(session/"job_0_first.pickle")
                    self.assertEqual(len(preliminary[0].transactions),20)
                    self.assertTrue((session/"job_0_first.html").exists())
                finally:
                    release.set()
                    await asyncio.wait_for(task,timeout=12)
                final = load_result(session/"job_0.pickle")
                self.assertTrue(final[3])
                self.assertEqual(len(final[0].transactions),420)
                self.assertEqual(final[1],preliminary[1])
                self.assertTrue({tx.tx_hash for tx in preliminary[0].transactions} <= {tx.tx_hash for tx in final[0].transactions})
                events = [json.loads(line)["event"]["stage"] for line in stdout.getvalue().splitlines()]
                self.assertLess(events.index("initial_html.ready"),events.index("investigation.complete"))
                self.assertIn("investigation.deep",events)

    async def test_continuous_nft_enrichment_does_not_wait_for_deep_owner_collector(self):
        from app.nft_cli import analyze_search_input
        from app.models.report import Balance
        from app.ton_nft.models import NFTIntelligenceReport, DiscoveryResult, DiscoveryCandidate
        from app.graph.builder import build_graph_payload
        target="0:"+"1"*64
        owner_started, nft_running, release, first_ready=(asyncio.Event() for _ in range(4))
        observed=[]
        async def collect(address, **kwargs):
            self.assertTrue(kwargs["continuous"])
            partial=AddressReport(target_address=address,detected_chains=["ton"],
                balances=[Balance(chain="ton",address=address,asset="TON",amount=1,source="fixture")])
            await kwargs["on_checkpoint"](partial)
            owner_started.set()
            await release.wait()
            return partial,build_graph_payload(partial)
        async def investigate(query,**kwargs):
            self.assertTrue(kwargs["continuous"])
            report=NFTIntelligenceReport(investigation_id="continuous-fixture",query=query,mode="deep",scope="wallet",
                discovery=DiscoveryResult(normalized_query=target,query_kind="address",status="resolved",
                    candidates=[DiscoveryCandidate(address=target,reason="synthetic wallet fixture")]))
            await kwargs["on_target_resolved"]({"scope":"wallet","analysis_address":target},report)
            nft_running.set()
            await release.wait()
            return report
        async def ready(report,graph):
            observed.append(report)
            first_ready.set()
        with tempfile.TemporaryDirectory() as directory,patch("app.ton_nft.service.investigate_ton_nft",investigate):
            task=asyncio.create_task(analyze_search_input(target,continuous=True,address_analyzer=collect,
                nft_options={"store_path":Path(directory)/"snapshot.sqlite3"},on_report_ready=ready))
            try:
                await asyncio.wait_for(nft_running.wait(),timeout=2)
                await asyncio.wait_for(owner_started.wait(),timeout=2)
                await asyncio.wait_for(first_ready.wait(),timeout=2)
                self.assertFalse(task.done())
                self.assertEqual(observed[0].coverage["search_execution"]["status"],"running")
            finally:
                release.set()
                report,_=await asyncio.wait_for(task,timeout=5)
            self.assertEqual(report.target_address,target)

    async def test_resume_preserves_wallet_history_and_cursors_but_refreshes_mutable_state(self):
        from app.nft_cli import analyze_search_input
        from app.models.report import Balance
        from app.ton_nft.models import NFTIntelligenceReport, DiscoveryResult, DiscoveryCandidate
        from app.ton_nft.storage import InvestigationStore
        target="0:"+"1"*64
        observed=[]
        async def collect(address,**kwargs):
            prior=kwargs["initial_report"]
            observed.append(prior)
            self.assertTrue(kwargs["incremental"])
            self.assertEqual(len(prior.transactions),1)
            self.assertEqual(prior.balances,[])
            self.assertEqual(prior.collection_audit["streams"]["fixture"]["history"]["next_cursor"],123)
            return prior,{"nodes":[],"edges":[]}
        async def investigate(query,**kwargs):
            result=NFTIntelligenceReport(investigation_id="resume-fixture",query=query,mode="deep",scope="wallet",
                discovery=DiscoveryResult(normalized_query=target,query_kind="address",status="resolved",
                    candidates=[DiscoveryCandidate(address=target,reason="synthetic wallet fixture")]))
            await kwargs["on_target_resolved"]({"scope":"wallet","analysis_address":target},result)
            return result
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"snapshot.sqlite3"
            old=AddressReport(target_address=target,detected_chains=["ton"],
                balances=[Balance(chain="ton",address=target,asset="TON",amount=999,source="old_fixture")],
                transactions=[Transaction(chain="ton",tx_hash="a"*64,source="fixture")],
                collection_audit={"streams":{"fixture":{"history":{"next_cursor":123,"exhausted":False}}}})
            store=InvestigationStore(path)
            try:
                store.save_snapshot(NFTIntelligenceReport(investigation_id="resume-fixture",query=target,
                    owner_analysis_snapshot=old.model_dump(mode="json")))
            finally:store.close()
            with patch("app.ton_nft.service.investigate_ton_nft",investigate):
                report,_=await analyze_search_input(target,continuous=True,address_analyzer=collect,
                    nft_options={"store_path":path,"investigation_id":"resume-fixture","resume":True,"incremental":True})
            self.assertEqual(len(observed),1)
            self.assertEqual(len(report.transactions),1)
            self.assertNotIn("owner_analysis_snapshot",report.nft_intelligence)
            self.assertEqual(report.nft_intelligence["owner_analysis_reference"]["location"],"parent_address_report")
            store=InvestigationStore(path)
            try:
                persisted=store.load_snapshot("resume-fixture")
                self.assertEqual(persisted.owner_analysis_snapshot["target_address"],target)
                self.assertEqual(len(persisted.owner_analysis_snapshot["transactions"]),1)
            finally:store.close()

    async def test_owner_pipeline_failure_does_not_stop_later_nft_html_checkpoints(self):
        from app import nft_cli
        from app.ton_nft.models import NFTIntelligenceReport, DiscoveryResult, DiscoveryCandidate, NFTEvent
        target="0:"+"1"*64;item="0:"+"2"*64
        failure_ready=asyncio.Event();counts=[]
        async def collect(*args,**kwargs):raise RuntimeError("Synthetic owner pipeline fault")
        async def ready(report,graph):
            counts.append(len(report.transactions))
            if report.errors:failure_ready.set()
        async def investigate(query,**kwargs):
            result=NFTIntelligenceReport(investigation_id="owner-fault-fixture",query=query,mode="deep",scope="wallet",
                discovery=DiscoveryResult(normalized_query=target,query_kind="address",status="resolved",
                    candidates=[DiscoveryCandidate(address=target,reason="synthetic wallet fixture")]))
            await kwargs["on_target_resolved"]({"scope":"wallet","analysis_address":target},result)
            await asyncio.wait_for(failure_ready.wait(),timeout=3)
            result.events=[NFTEvent(event_id=f"event-{i}",asset_address=item,event_type="transfer",
                from_address=item,to_address=target,transaction_hash=f"{i:064x}",status="success") for i in range(3)]
            await kwargs["on_checkpoint"](result)
            return result
        with tempfile.TemporaryDirectory() as directory,patch("app.ton_nft.service.investigate_ton_nft",investigate),patch.object(nft_cli,"SEARCH_CHECKPOINT_SECONDS",0):
            # This fault-retention test makes both checkpoints eligible. The
            # measured preview backoff itself has a separate clock regression.
            from types import SimpleNamespace
            with patch.object(nft_cli,"time",SimpleNamespace(monotonic=lambda:0.0)):
                result,_=await nft_cli.analyze_search_input(target,continuous=True,address_analyzer=collect,
                    nft_options={"store_path":Path(directory)/"snapshot.sqlite3"},on_report_ready=ready)
        self.assertIn(0,counts)
        self.assertIn(3,counts)
        self.assertEqual(len(result.transactions),3)
        self.assertTrue(any("Synthetic owner pipeline fault" in error for error in result.errors))

    async def test_older_renderer_completion_cannot_replace_newer_durable_model(self):
        from app import main,search_worker
        from app.search_runtime import load_result
        from app.graph.builder import build_graph_payload
        seen=[]
        async def analysis(query,output,*,checkpoint_callback,model_callback,**kwargs):
            old=AddressReport(target_address=query,detected_chains=["btc"],transactions=[
                Transaction(chain="btc",tx_hash="a"*64,source="fixture")])
            newest=old.model_copy(deep=True)
            newest.transactions.append(Transaction(chain="btc",tx_hash="b"*64,source="fixture"))
            model_callback(old)
            # Old renderer started with generation one, but a new provider page
            # completes before it returns. Token order, never row counts, wins.
            model_callback(newest)
            path=await main._write_search_html(old,build_graph_payload(old),output,checkpoint=True)
            await checkpoint_callback(old,build_graph_payload(old),path)
            record=next(Path(output).parent.glob("session/job_0.pickle"))
            saved=load_result(record)[0]
            seen.append({tx.tx_hash for tx in saved.transactions})
            self.assertEqual(saved.coverage["checkpoint_generation"]["sequence"],2)
            path=await main._write_search_html(newest,build_graph_payload(newest),output)
            return newest,path,None
        with tempfile.TemporaryDirectory() as directory:
            session=Path(directory)/"session";session.mkdir()
            output=Path(directory)/"report"
            with patch.object(main,"_analyze_quiet",analysis),contextlib.redirect_stdout(io.StringIO()) as stdout:
                await search_worker.execute({"jobs":[{"query":BTC,"output":str(output)}],"language":"en",
                    "session":str(session),"collection_seconds":300})
            final=load_result(session/"job_0.pickle")[0]
            self.assertEqual(seen,[{"a"*64,"b"*64}])
            self.assertEqual({tx.tx_hash for tx in final.transactions},{"a"*64,"b"*64})
            self.assertIn("checkpoint.render.superseded",stdout.getvalue())

    async def test_intermediate_checkpoint_coalesces_while_previous_renderer_is_busy(self):
        from app import nft_cli
        from app.ton_nft.models import NFTIntelligenceReport,DiscoveryResult,DiscoveryCandidate
        target="0:"+"1"*64
        entered,release=(asyncio.Event() for _ in range(2));calls=[]
        async def ready(report,graph):
            calls.append(len(report.transactions))
            if len(calls)==1:
                entered.set();await release.wait()
        async def collect(address,**kwargs):
            first=AddressReport(target_address=address,detected_chains=["ton"],transactions=[Transaction(chain="ton",tx_hash="a"*64,source="fixture")])
            newest=first.model_copy(deep=True);newest.transactions.append(Transaction(chain="ton",tx_hash="b"*64,source="fixture"))
            task=asyncio.create_task(kwargs["on_checkpoint"](first))
            try:
                await asyncio.wait_for(entered.wait(),timeout=3)
                # A second source checkpoint must return without queuing a
                # second frozen model/graph while the first export is blocked.
                await asyncio.wait_for(kwargs["on_checkpoint"](newest),timeout=.3)
                self.assertEqual(calls,[1])
            finally:
                release.set();await task
            return newest,{}
        async def investigate(query,**kwargs):
            result=NFTIntelligenceReport(investigation_id="coalescing-fixture",query=query,mode="deep",scope="wallet",
                discovery=DiscoveryResult(normalized_query=target,query_kind="address",status="resolved",
                    candidates=[DiscoveryCandidate(address=target,reason="synthetic wallet")]))
            await kwargs["on_target_resolved"]({"scope":"wallet","analysis_address":target},result)
            await release.wait()
            return result
        with tempfile.TemporaryDirectory() as directory,patch("app.ton_nft.service.investigate_ton_nft",investigate),patch.object(nft_cli,"SEARCH_CHECKPOINT_SECONDS",0):
            report,_=await nft_cli.analyze_search_input(target,continuous=True,address_analyzer=collect,
                on_report_ready=ready,nft_options={"store_path":Path(directory)/"snapshots.sqlite3"})
        self.assertEqual(len(report.transactions),2)
        # Enrichment has now finished. The complete model is returned for the
        # final renderer instead of creating a redundant intermediate HTML.
        self.assertEqual(calls,[1])

    async def test_cooperative_stop_returns_saved_html_without_killing_real_child(self):
        from app import search_runtime as runtime
        create = asyncio.create_subprocess_exec
        processes = []
        code = '''import json,sys,time
from pathlib import Path
from app.models.report import AddressReport
from app.graph.builder import build_graph_payload
from app.exporters.html import export
from app.search_runtime import atomic_pickle
r=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"));s=Path(r["session"])
a=AddressReport(target_address=r["jobs"][0]["query"],warnings=["Cooperative lifecycle fault test; no live responses"],coverage={"search_execution":{"status":"running","data_complete":False}})
p=export(a,build_graph_payload(a),Path(r["jobs"][0]["output"]))
atomic_pickle(s/"job_0.pickle",(a,p,None,False))
print(json.dumps({"job":0,"event":{"stage":"initial_html.ready"}}),flush=True)
while not (s/"stop.json").exists():time.sleep(.02)
a.coverage["search_execution"]={"status":"stopped","data_complete":False}
atomic_pickle(s/"job_0.pickle",(a,p,None,True))
'''
        async def start(*args,**kwargs):
            process=await create(args[0],"-B","-c",code,args[-1],**kwargs)
            processes.append(process)
            return process
        stopping=asyncio.Event()
        def progress(index,event):
            if event.get("stage")=="initial_html.ready":stopping.set()
        with tempfile.TemporaryDirectory() as directory, patch.object(runtime.asyncio,"create_subprocess_exec",start), patch.object(runtime,"SHUTDOWN_GRACE_SECONDS",5):
            result=(await runtime.run_bounded_jobs([{"query":BTC,"output":directory}],progress=progress,cancel_event=stopping))[0]
            self.assertEqual(result["status"],"stopped")
            self.assertTrue(result["runtime"]["cooperative_stop"])
            self.assertFalse(result["runtime"]["worker_terminated"])
            self.assertTrue(Path(result["html"]).exists())
            self.assertTrue(all(process.returncode==0 for process in processes))
            self.assertTrue(result["runtime"]["initial_html_seconds"])

    async def test_progress_callback_failure_is_reported_after_worker_is_reaped(self):
        from app import search_runtime as runtime
        create=asyncio.create_subprocess_exec
        processes=[]
        async def start(*args,**kwargs):
            code = "import json,time; print(json.dumps({'job':0,'event':{'stage':'fixture'}}),flush=True); time.sleep(60)"
            process=await create(args[0],"-B","-c",code,**kwargs)
            processes.append(process)
            return process
        def broken(*args):raise RuntimeError("fixture progress callback failure")
        with tempfile.TemporaryDirectory() as directory,patch.object(runtime.asyncio,"create_subprocess_exec",start),patch.object(runtime,"SHUTDOWN_GRACE_SECONDS",.3):
            with self.assertRaisesRegex(RuntimeError,"fixture progress callback failure"):
                await runtime.run_bounded_jobs([{"query":BTC,"output":directory}],progress=broken)
        self.assertTrue(all(process.returncode is not None for process in processes))

    async def test_session_budget_drains_one_final_export_without_cancelling_worker(self):
        from app import search_runtime as runtime
        create=asyncio.create_subprocess_exec;processes=[]
        code='''import json,sys,time
from pathlib import Path
from app.models.report import AddressReport
from app.graph.builder import build_graph_payload
from app.exporters.html import export
from app.search_runtime import atomic_pickle
request=Path(sys.argv[1]);d=json.loads(request.read_text(encoding="utf-8"));session=Path(d["session"])
r=AddressReport(target_address=d["jobs"][0]["query"],warnings=["Synthetic drain checkpoint; no live evidence"],coverage={"search_execution":{"status":"running","data_complete":False}})
p=export(r,build_graph_payload(r),Path(d["jobs"][0]["output"]))
atomic_pickle(session/"job_0.pickle",(r,p,None,False))
print(json.dumps({"job":0,"event":{"stage":"initial_html.ready"}}),flush=True)
while time.time()<request.stat().st_mtime+d["session_seconds"]:time.sleep(.02)
# A normal final export may exceed the short legacy shutdown grace. The
# session boundary must not send stop.json or trigger a second fallback export.
time.sleep(.65)
r.warnings.append("final-drain-completed")
if (session/"stop.json").exists():r.warnings.append("unexpected-cancellation")
r.coverage["search_execution"]={"status":"completed","data_complete":False}
p=export(r,build_graph_payload(r),Path(d["jobs"][0]["output"]))
atomic_pickle(session/"job_0.pickle",(r,p,None,True))
print(json.dumps({"job":0,"event":{"stage":"html.complete"}}),flush=True)
'''
        async def start(*args,**kwargs):
            process=await create(args[0],"-B","-c",code,args[-1],**kwargs)
            processes.append(process);return process
        events=[]
        with tempfile.TemporaryDirectory() as directory,patch.object(runtime.asyncio,"create_subprocess_exec",start), \
             patch.object(runtime,"SEARCH_SECONDS",4),patch.object(runtime,"WORKER_SECONDS",4), \
             patch.object(runtime,"COLLECTION_SECONDS",2),patch.object(runtime,"SHUTDOWN_GRACE_SECONDS",.5),patch.object(runtime,"FINALIZATION_GRACE_SECONDS",3):
            result=(await runtime.run_bounded_jobs([{"query":BTC,"output":directory}],
                progress=lambda index,event:events.append(event)))[0]
            self.assertFalse(result["runtime"]["worker_terminated"])
            self.assertFalse(result["runtime"]["cooperative_stop"])
            self.assertTrue(result["runtime"]["session_budget_reached"])
            self.assertFalse(result["runtime"]["collection_deadline_extended"])
            self.assertEqual(result["runtime"]["worker_exit_code"],0)
            self.assertEqual(result["runtime"]["collection_seconds"],2)
            self.assertGreater(result["runtime"]["total_seconds"],4.5)
            self.assertLess(result["runtime"]["total_seconds"],7)
            self.assertIn("final-drain-completed",Path(result["html"]).read_text(encoding="utf-8"))
            self.assertNotIn("unexpected-cancellation",result["report"].warnings)
            self.assertEqual(sum(event.get("stage")=="html.complete" for event in events),1)
            self.assertTrue(all(process.returncode==0 for process in processes))

    @unittest.skipUnless(os.name=="nt","Windows Job Object ownership guard")
    async def test_abrupt_parent_closure_cannot_orphan_a_blocked_worker(self):
        from app.search_worker import _parent_alive
        code='''import json,subprocess,sys,time
from pathlib import Path
from app.search_runtime import _WindowsWorkerLease
child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"])
lease=_WindowsWorkerLease(child.pid)
Path(sys.argv[1]).write_text(json.dumps({"pid":child.pid,"lease_error":lease.error}),encoding="utf-8")
time.sleep(60)
'''
        parent=None;child_pid=None
        with tempfile.TemporaryDirectory() as directory:
            marker=Path(directory)/"child.json"
            try:
                parent=await asyncio.create_subprocess_exec(sys.executable,"-B","-c",code,str(marker),
                    stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
                for _ in range(100):
                    if marker.exists():break
                    await asyncio.sleep(.05)
                detail=json.loads(marker.read_text(encoding="utf-8"))
                child_pid=detail["pid"]
                self.assertIsNone(detail["lease_error"])
                self.assertTrue(_parent_alive(child_pid))
                parent.kill();await parent.wait()
                for _ in range(60):
                    if not _parent_alive(child_pid):break
                    await asyncio.sleep(.05)
                self.assertFalse(_parent_alive(child_pid))
            finally:
                if parent is not None and parent.returncode is None:
                    parent.kill();await parent.wait()
                if child_pid is not None and _parent_alive(child_pid):
                    import ctypes
                    from ctypes import wintypes
                    kernel=ctypes.WinDLL("kernel32",use_last_error=True)
                    kernel.OpenProcess.restype=wintypes.HANDLE
                    kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
                    kernel.TerminateProcess.argtypes=[wintypes.HANDLE,wintypes.UINT]
                    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
                    handle=kernel.OpenProcess(1,False,child_pid)
                    if handle:
                        kernel.TerminateProcess(handle,1);kernel.CloseHandle(handle)

    def test_first_result_target_is_separate_from_finite_deep_budget(self):
        from app.search_runtime import FIRST_RESULT_SECONDS, COLLECTION_SECONDS, SEARCH_SECONDS
        self.assertEqual(FIRST_RESULT_SECONDS,60)
        self.assertGreater(COLLECTION_SECONDS,FIRST_RESULT_SECONDS)
        self.assertGreater(SEARCH_SECONDS,COLLECTION_SECONDS)
        self.assertLessEqual(SEARCH_SECONDS,3600)
