"""One existing finite drain shared by final owner-store, graph, HTML and commit.

The real child workloads below are synthetic; they make no live-source claim.
"""
import asyncio
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from app import search_runtime as runtime


class FinalGraphDrainPolicyTests(unittest.TestCase):
    def test_large_same_job_final_graph_uses_one_existing_absolute_ceiling(self):
        measured = runtime._ExportDurations()
        measured.observe(0, {"stage": "checkpoint.model.saved", "transactions": 32000}, now=1)
        measured.observe(0, {"stage": "checkpoint.html.start"}, now=2)
        measured.observe(0, {"stage": "checkpoint.html.complete"}, now=12)
        measured.observe(0, {"stage": "graph.start"}, now=180)
        measured.observe(0, {"stage": "graph.start"}, now=200)
        self.assertEqual(measured.final_graph_started, {0: 180})
        kwargs = {"finish_started": 100, "initial_deadline": 320}
        self.assertEqual(runtime._late_final_export_deadline("session_budget", measured, **kwargs), 1000)
        self.assertEqual(runtime._late_final_export_deadline("user_stop", measured, **kwargs), 320)
        # Graph and HTML complete before the durable pickle commit. The first
        # reservation survives both; neither can create another 900 seconds.
        measured.observe(0, {"stage": "graph.complete"}, now=400)
        measured.observe(0, {"stage": "html.start"}, now=500)
        measured.observe(0, {"stage": "html.complete"}, now=700)
        self.assertEqual(runtime._late_final_export_deadline("session_budget", measured, **kwargs), 1000)
        measured.observe(0, {"stage": "investigation.complete"}, now=750)
        self.assertEqual(measured.final_graph_started, {})
        self.assertEqual(runtime._late_final_export_deadline("session_budget", measured, **kwargs), 320)

    def test_checkpoint_deferred_small_unmeasured_and_other_job_graph_do_not_qualify(self):
        measured = runtime._ExportDurations()
        kwargs = {"finish_started": 100, "initial_deadline": 320}
        deadline = lambda: runtime._late_final_export_deadline("session_budget", measured, **kwargs)
        measured.observe(0, {"stage": "checkpoint.model.saved", "transactions": 32000}, now=1)
        measured.max_completed_seconds = 10
        measured.observe(0, {"stage": "checkpoint.graph.start"}, now=200)
        measured.observe(0, {"stage": "graph.deferred"}, now=210)
        self.assertEqual(measured.final_graph_started, {})
        self.assertEqual(deadline(), 320)
        measured.observe(1, {"stage": "graph.start", "transactions": 999}, now=220)
        self.assertEqual(deadline(), 320, "A different job's large model cannot qualify this graph")
        measured.observe(0, {"stage": "graph.start"}, now=230)
        measured.max_completed_seconds = 0
        self.assertEqual(deadline(), 320, "An actual completed render measurement is required")
        measured.max_completed_seconds = 10
        self.assertEqual(deadline(), 1000)
        measured.observe(0, {"stage": "search.error"}, now=240)
        self.assertEqual(deadline(), 320)
        measured.observe(2, {"stage": "graph.start", "transactions": 1000}, now=250)
        measured.observe(2, {"stage": "investigation.stopped"}, now=260)
        self.assertEqual(deadline(), 320)
        self.assertEqual(runtime.COLLECTION_SECONDS, 575)
        self.assertEqual(runtime.SEARCH_SECONDS, 600)
        self.assertEqual(runtime.MAX_FINALIZATION_GRACE_SECONDS, 900)


_WORKER = '''import json,sys,time
from pathlib import Path
from app.models.report import AddressReport,Transaction
from app.graph.builder import build_graph_payload
from app.exporters.html import export
from app.search_runtime import atomic_pickle
data=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"));hung=sys.argv[2]=="hung"
session=Path(data["session"])
report=AddressReport(target_address=data["jobs"][0]["query"],warnings=["Synthetic final graph/store drain; no live evidence"])
output=Path(data["jobs"][0]["output"])
path=export(report,build_graph_payload(report),output)
atomic_pickle(session/"job_0.pickle",(report,path,None,False))
def event(stage,**values):print(json.dumps({"job":0,"event":{"stage":stage,**values}}),flush=True)
def until(deadline):
    while time.monotonic()<deadline:time.sleep(.005)
event("initial_html.ready")
event("checkpoint.html.start");time.sleep(.4);event("checkpoint.html.complete")
event("checkpoint.model.saved",transactions=1000)
control=session/"test_final_graph_control.json"
while not control.exists():time.sleep(.005)
boundary=json.loads(control.read_text(encoding="utf-8"));initial=boundary["at"]+boundary["grace"]
until(initial-.25)
event("graph.start")
if hung:
    while True:event("graph.start");event("fixture.progress");time.sleep(.04)
# The phase represents finite final owner-store CPU and graph building, without
# any new source request. HTML begins only after the original drain expired.
time.sleep(.5)
report.transactions=[Transaction(chain="ton",tx_hash=str(i),source="synthetic_final_graph") for i in range(1000)]
graph=build_graph_payload(report);event("graph.complete")
event("html.start")
report.warnings.append("single-final-graph-html-commit")
report.coverage["search_execution"]={"status":"completed","data_complete":False}
path=export(report,graph,output);event("html.complete")
time.sleep(.15)
if (session/"stop.json").exists():report.warnings.append("unexpected-stop-file")
atomic_pickle(session/"job_0.pickle",(report,path,None,True))
event("investigation.complete")
'''


class FinalGraphDrainProcessTests(unittest.IsolatedAsyncioTestCase):
    async def _run_case(self, hung):
        create = asyncio.create_subprocess_exec
        processes, events = [], []

        async def start(*args, **kwargs):
            kwargs["stderr"] = asyncio.subprocess.PIPE
            process = await create(args[0], "-B", "-c", _WORKER, args[-1], "hung" if hung else "healthy", **kwargs)
            processes.append(process)
            return process

        def progress(index, event):
            events.append({**event, "received_at": time.monotonic()})
            if event.get("stage") == "investigation.finalizing":
                session = Path(event["session"])
                temporary = session/"test_final_graph_control.writing"
                temporary.write_text(json.dumps({"at": time.monotonic(),
                    "grace": event["finalization_grace_seconds"]}), encoding="utf-8")
                temporary.replace(session/"test_final_graph_control.json")

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(runtime.asyncio, "create_subprocess_exec", start), \
                patch.object(runtime, "SEARCH_SECONDS", 4), patch.object(runtime, "WORKER_SECONDS", 4), \
                patch.object(runtime, "COLLECTION_SECONDS", 2), patch.object(runtime, "SHUTDOWN_GRACE_SECONDS", .2), \
                patch.object(runtime, "FINALIZATION_GRACE_SECONDS", .2):
            result = (await runtime.run_bounded_jobs([{"query": "0:"+"1"*64, "output": directory}],
                progress=progress))[0]
            result["test_worker_stderr"] = "".join([(await process.stderr.read()).decode("utf-8", errors="replace")
                for process in processes])
            self.assertTrue(Path(result["html"]).exists())
        self.assertTrue(all(process.returncode is not None for process in processes))
        self.assertTrue(result["runtime"]["session_budget_reached"])
        self.assertFalse(result["runtime"]["collection_deadline_extended"])
        self.assertEqual(result["runtime"]["collection_seconds"], 2)
        self.assertEqual(result["runtime"]["finalization_hard_ceiling_seconds"], 6)
        return result, events

    async def test_late_final_owner_store_graph_then_html_and_atomic_commit_finish_once(self):
        result, events = await self._run_case(False)
        self.assertFalse(result["runtime"]["worker_terminated"])
        self.assertEqual(result["runtime"]["worker_exit_code"], 0, result["test_worker_stderr"])
        self.assertEqual(result["runtime"]["late_finalization_reservation_phase"], "final_graph_owner_store")
        self.assertGreater(result["runtime"]["late_final_export_grace_seconds"], 0)
        self.assertEqual(len(result["report"].transactions), 1000)
        self.assertIn("single-final-graph-html-commit", result["report"].warnings)
        self.assertNotIn("unexpected-stop-file", result["report"].warnings)
        initial = next(event for event in events if event["stage"] == "investigation.finalizing")
        original_deadline = initial["received_at"]+initial["finalization_grace_seconds"]
        html_start = next(event for event in events if event["stage"] == "html.start")
        self.assertGreater(html_start["received_at"], original_deadline)
        for stage in ("graph.start", "graph.complete", "html.start", "html.complete", "investigation.complete",
                "investigation.final_export_draining"):
            self.assertEqual(sum(event["stage"] == stage for event in events), 1, stage)
        self.assertLess(result["runtime"]["total_seconds"], 10.8)

    async def test_hung_final_graph_progress_cannot_renew_existing_absolute_ceiling(self):
        result, events = await self._run_case(True)
        self.assertTrue(result["runtime"]["worker_terminated"])
        self.assertNotEqual(result["runtime"]["worker_exit_code"], 0)
        self.assertEqual(result["runtime"]["late_finalization_reservation_phase"], "final_graph_owner_store")
        self.assertGreater(sum(event["stage"] == "graph.start" for event in events), 3)
        self.assertEqual(sum(event["stage"] == "investigation.final_export_draining" for event in events), 1)
        self.assertFalse(any(event["stage"] == "html.start" for event in events))
        self.assertAlmostEqual(result["runtime"]["finalization_grace_seconds"]+
            result["runtime"]["late_final_export_grace_seconds"], 6)
        self.assertLess(result["runtime"]["total_seconds"], 10.8)


if __name__ == "__main__":
    unittest.main()
