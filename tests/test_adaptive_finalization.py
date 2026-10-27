"""Measured finite finalization policy; no live sources or performance claims."""
import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app import search_runtime as runtime


class AdaptiveFinalizationMathTests(unittest.TestCase):
    def test_measured_export_controls_only_finite_finalization(self):
        self.assertEqual(runtime._finalization_grace("session_budget"),180)
        self.assertEqual(runtime._finalization_grace("session_budget",86),524)
        self.assertEqual(runtime._finalization_grace("session_budget",10000),900)
        self.assertAlmostEqual(runtime._finalization_grace("session_budget",166.7528071),847.0112284)
        self.assertEqual(runtime._finalization_grace("session_budget",float("nan")),180)
        self.assertEqual(runtime._finalization_grace("user_stop"),30)
        self.assertEqual(runtime._finalization_grace("user_stop",large_model=True),180)
        self.assertEqual(runtime._finalization_grace("user_stop",86),524)
        self.assertEqual(runtime._finalization_grace("user_stop",10000),900)
        self.assertEqual(runtime.COLLECTION_SECONDS,575)
        self.assertEqual(runtime.SEARCH_SECONDS,600)
        with patch.object(runtime,"SHUTDOWN_GRACE_SECONDS",.1):
            self.assertAlmostEqual(runtime._finalization_grace("session_budget"),.6)
            self.assertEqual(runtime._finalization_grace("session_budget",86),3)

    def test_batch_export_measurements_do_not_mix_jobs_or_stage_types(self):
        durations=runtime._ExportDurations()
        durations.observe(0,{"stage":"html.start"},now=0)
        durations.observe(1,{"stage":"checkpoint.html.start"},now=2)
        durations.observe(0,{"stage":"html.complete"},now=10)
        durations.observe(1,{"stage":"checkpoint.html.complete"},now=88)
        durations.observe(2,{"stage":"html.complete"},now=1000)  # no matching start
        durations.observe(1,{"stage":"checkpoint.model.saved","transactions":25009},now=90)
        self.assertEqual(durations.max_completed_seconds,86)
        self.assertEqual(durations.max_model_rows,25009)
        self.assertEqual(durations.started,{})


class AdaptiveFinalizationProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_large_user_stop_drains_and_reaps_one_cooperative_final_save(self):
        create=asyncio.create_subprocess_exec;processes=[];stopping=asyncio.Event()
        code='''import json,sys,time
from pathlib import Path
from app.models.report import AddressReport,Transaction
from app.graph.builder import build_graph_payload
from app.exporters.html import export
from app.search_runtime import atomic_pickle
data=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"));session=Path(data["session"])
report=AddressReport(target_address=data["jobs"][0]["query"],transactions=[Transaction(chain="ton",tx_hash=str(i),source="synthetic") for i in range(1000)],warnings=["Synthetic cooperative large-stop test; no live responses"])
path=export(report,build_graph_payload(report),Path(data["jobs"][0]["output"]))
atomic_pickle(session/"job_0.pickle",(report,path,None,False))
print(json.dumps({"job":0,"event":{"stage":"checkpoint.model.saved","transactions":len(report.transactions)}}),flush=True)
print(json.dumps({"job":0,"event":{"stage":"checkpoint.html.start"}}),flush=True)
time.sleep(.7)
print(json.dumps({"job":0,"event":{"stage":"checkpoint.html.complete"}}),flush=True)
while not (session/"stop.json").exists():time.sleep(.01)
# Healthy single final save exceeds the former two-second clipped drain.
time.sleep(2.15)
report.coverage["search_execution"]={"status":"stopped","data_complete":False}
path=export(report,build_graph_payload(report),Path(data["jobs"][0]["output"]))
atomic_pickle(session/"job_0.pickle",(report,path,None,True))
'''
        async def start(*args,**kwargs):
            process=await create(args[0],"-B","-c",code,args[-1],**kwargs)
            processes.append(process);return process
        def progress(index,event):
            if event.get("stage")=="checkpoint.html.complete":stopping.set()
        with tempfile.TemporaryDirectory() as directory,patch.object(runtime.asyncio,"create_subprocess_exec",start), \
                patch.object(runtime,"SHUTDOWN_GRACE_SECONDS",.1),patch.object(runtime,"FINALIZATION_GRACE_SECONDS",.3):
            result=(await runtime.run_bounded_jobs([{"query":"0:"+"1"*64,"output":directory}],
                progress=progress,cancel_event=stopping))[0]
            self.assertTrue(Path(result["html"]).exists())
        self.assertTrue(result["runtime"]["cooperative_stop"])
        self.assertFalse(result["runtime"]["worker_terminated"])
        self.assertEqual(result["runtime"]["worker_exit_code"],0)
        self.assertEqual(len(result["report"].transactions),1000)
        self.assertEqual(result["runtime"]["max_observed_model_rows"],1000)
        self.assertEqual(result["runtime"]["finalization_grace_seconds"],3)
        self.assertTrue(all(process.returncode==0 for process in processes))

    async def test_observed_slow_checkpoint_allows_one_final_save_with_same_collection_deadline(self):
        create=asyncio.create_subprocess_exec;processes=[]
        code='''import json,sys,time
from pathlib import Path
from app.models.report import AddressReport
from app.graph.builder import build_graph_payload
from app.exporters.html import export
from app.search_runtime import atomic_pickle
request=Path(sys.argv[1]);data=json.loads(request.read_text(encoding="utf-8"));session=Path(data["session"])
report=AddressReport(target_address=data["jobs"][0]["query"],warnings=["Synthetic adaptive finalization; no live evidence"])
path=export(report,build_graph_payload(report),Path(data["jobs"][0]["output"]))
atomic_pickle(session/"job_0.pickle",(report,path,None,False))
print(json.dumps({"job":0,"event":{"stage":"checkpoint.html.start"}}),flush=True)
time.sleep(.4)
print(json.dumps({"job":0,"event":{"stage":"checkpoint.html.complete"}}),flush=True)
while time.time()<request.stat().st_mtime+data["session_seconds"]:time.sleep(.01)
time.sleep(.8)
report.warnings.append("single-adaptive-final-save")
if (session/"stop.json").exists():report.warnings.append("unexpected-stop")
path=export(report,build_graph_payload(report),Path(data["jobs"][0]["output"]))
atomic_pickle(session/"job_0.pickle",(report,path,None,True))
print(json.dumps({"job":0,"event":{"stage":"html.complete"}}),flush=True)
'''
        async def start(*args,**kwargs):
            process=await create(args[0],"-B","-c",code,args[-1],**kwargs)
            processes.append(process);return process
        with tempfile.TemporaryDirectory() as directory,patch.object(runtime.asyncio,"create_subprocess_exec",start), \
                patch.object(runtime,"SEARCH_SECONDS",3),patch.object(runtime,"WORKER_SECONDS",3), \
                patch.object(runtime,"COLLECTION_SECONDS",2),patch.object(runtime,"SHUTDOWN_GRACE_SECONDS",.1), \
                patch.object(runtime,"FINALIZATION_GRACE_SECONDS",.3):
            result=(await runtime.run_bounded_jobs([{"query":"0:"+"1"*64,"output":directory}]))[0]
        self.assertFalse(result["runtime"]["worker_terminated"])
        self.assertEqual(result["runtime"]["worker_exit_code"],0)
        self.assertGreater(result["runtime"]["max_completed_export_seconds"],.35)
        self.assertGreater(result["runtime"]["finalization_grace_seconds"],1.4)
        self.assertLessEqual(result["runtime"]["finalization_grace_seconds"],3)
        self.assertAlmostEqual(result["runtime"]["finalization_grace_seconds"],
            min(3,.3+4*result["runtime"]["max_completed_export_seconds"]))
        self.assertFalse(result["runtime"]["collection_deadline_extended"])
        self.assertEqual(result["runtime"]["collection_seconds"],2)
        self.assertIn("single-adaptive-final-save",result["report"].warnings)
        self.assertNotIn("unexpected-stop",result["report"].warnings)
        self.assertTrue(all(process.returncode==0 for process in processes))


if __name__=="__main__":unittest.main()
