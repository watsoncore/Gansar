"""Finite final-render/commit drain regressions with real owned child processes.

Only the clock and worker workload are synthetic; no provider responses or
live-completeness claims are involved.
"""
import asyncio
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from app import search_runtime as runtime


class LateFinalExportPolicyTests(unittest.TestCase):
    def test_reservation_stays_until_durable_job_terminal_and_never_restarts(self):
        measured = runtime._ExportDurations()
        measured.observe(0, {"stage": "checkpoint.html.start"}, now=1)
        measured.observe(0, {"stage": "checkpoint.html.complete"}, now=11)
        measured.observe(0, {"stage": "html.start"}, now=20)
        measured.observe(0, {"stage": "html.start"}, now=25)
        self.assertEqual(measured.started[(0, "html")], 20)
        self.assertEqual(measured.final_started, {0: 20})
        measured.observe(0, {"stage": "html.complete"}, now=30)
        self.assertEqual(measured.started, {})
        self.assertEqual(measured.final_started, {0: 20})
        measured.observe(0, {"stage": "html.start"}, now=35)
        self.assertEqual(measured.final_started, {0: 20})
        measured.observe(1, {"stage": "html.start"}, now=36)
        measured.observe(1, {"stage": "investigation.stopped"}, now=37)
        measured.observe(2, {"stage": "html.start"}, now=38)
        measured.observe(2, {"stage": "search.error"}, now=39)
        measured.observe(0, {"stage": "investigation.complete"}, now=40)
        self.assertEqual(measured.final_started, {})

    def test_late_allowance_is_exactly_anchored_capped_and_requires_final_evidence(self):
        measured = runtime._ExportDurations()
        measured.observe(0, {"stage": "html.start"}, now=100)
        initial = 120
        deadline = lambda reason="session_budget": runtime._late_final_export_deadline(
            reason, measured, finish_started=0, initial_deadline=initial)
        self.assertEqual(deadline(), initial, "No completed measurement must keep the old policy")
        measured.max_completed_seconds = 20
        self.assertEqual(deadline(), 140)
        self.assertEqual(deadline("user_stop"), initial)
        self.assertEqual(deadline("progress_callback_error"), initial)
        measured.observe(0, {"stage": "html.complete"}, now=121)
        self.assertEqual(deadline(), 142, "The pending durable commit retains the first reservation")
        measured.observe(0, {"stage": "html.start"}, now=500)
        self.assertEqual(deadline(), 142, "Repeated starts cannot move the reservation")
        measured.observe(1, {"stage": "html.start"}, now=890)
        self.assertEqual(deadline(), 900, "All jobs share the existing absolute ceiling")
        measured.observe(1, {"stage": "investigation.complete"}, now=891)
        measured.observe(0, {"stage": "investigation.complete"}, now=892)
        measured.observe(2, {"stage": "checkpoint.html.start"}, now=893)
        self.assertEqual(deadline(), initial, "A checkpoint cannot reserve a final-export drain")
        self.assertEqual(runtime.COLLECTION_SECONDS, 575)
        self.assertEqual(runtime.SEARCH_SECONDS, 600)
        self.assertEqual(runtime.MAX_FINALIZATION_GRACE_SECONDS, 900)


_WORKER = '''import json,sys,time
from pathlib import Path
from app.models.report import AddressReport
from app.graph.builder import build_graph_payload
from app.exporters.html import export
from app.search_runtime import atomic_pickle
request=Path(sys.argv[1]);spec=json.loads(sys.argv[2])
data=json.loads(request.read_text(encoding="utf-8"));session=Path(data["session"])
report=AddressReport(target_address=data["jobs"][0]["query"],warnings=["Synthetic finite final drain; no live evidence"])
path=export(report,build_graph_payload(report),Path(data["jobs"][0]["output"]))
atomic_pickle(session/"job_0.pickle",(report,path,None,False))
def event(stage):print(json.dumps({"job":0,"event":{"stage":stage}}),flush=True)
def until(deadline):
    while time.monotonic()<deadline:time.sleep(.005)
event("checkpoint.html.start");time.sleep(spec["observed"]);event("checkpoint.html.complete")
control=session/"test_finalization_control.json"
while not control.exists():time.sleep(.005)
boundary=json.loads(control.read_text(encoding="utf-8"))
initial=boundary["at"]+boundary["grace"]
case=spec["case"]
until(initial-(.45 if case=="commit_race" else .1))
if case=="checkpoint_only":
    while True:event("checkpoint.html.start");time.sleep(.04)
event("html.start")
if case=="hung":
    while True:event("html.start");event("fixture.progress");time.sleep(.04)
if case=="healthy":time.sleep(.3)
report.warnings.append("single-final-durable-save")
report.coverage["search_execution"]={"status":"completed","data_complete":False}
path=export(report,build_graph_payload(report),Path(data["jobs"][0]["output"]))
event("html.complete")
if case=="commit_race":until(initial+.2)
if (session/"stop.json").exists():report.warnings.append("unexpected-stop-file")
atomic_pickle(session/"job_0.pickle",(report,path,None,True))
event("investigation.complete")
'''


class LateFinalExportProcessTests(unittest.IsolatedAsyncioTestCase):
    async def _run_case(self, case, *, observed=.3, base=.2):
        create = asyncio.create_subprocess_exec
        processes, events = [], []
        spec = json.dumps({"case": case, "observed": observed})

        async def start(*args, **kwargs):
            kwargs["stderr"] = asyncio.subprocess.PIPE
            process = await create(args[0], "-B", "-c", _WORKER, args[-1], spec, **kwargs)
            processes.append(process)
            return process

        def progress(index, event):
            events.append({**event, "received_at": time.monotonic()})
            if event.get("stage") == "investigation.finalizing":
                session = Path(event["session"])
                temporary = session/"test_finalization_control.writing"
                temporary.write_text(json.dumps({"at": time.monotonic(),
                    "grace": event["finalization_grace_seconds"]}), encoding="utf-8")
                temporary.replace(session/"test_finalization_control.json")

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(runtime.asyncio, "create_subprocess_exec", start), \
                patch.object(runtime, "SEARCH_SECONDS", 4), patch.object(runtime, "WORKER_SECONDS", 4), \
                patch.object(runtime, "COLLECTION_SECONDS", 2), patch.object(runtime, "SHUTDOWN_GRACE_SECONDS", .1), \
                patch.object(runtime, "FINALIZATION_GRACE_SECONDS", base):
            result = (await runtime.run_bounded_jobs([{"query": "0:"+"1"*64, "output": directory}],
                progress=progress))[0]
            result["test_worker_stderr"] = "".join([(await process.stderr.read()).decode("utf-8", errors="replace")
                for process in processes])
            self.assertTrue(Path(result["html"]).exists())
            timing = json.loads((Path(result["runtime"]["session"])/"timing.json").read_text(encoding="utf-8"))
        self.assertTrue(all(process.returncode is not None for process in processes))
        self.assertEqual(result["runtime"]["collection_seconds"], 2)
        self.assertFalse(result["runtime"]["collection_deadline_extended"])
        self.assertFalse(result["runtime"]["cooperative_stop"])
        self.assertTrue(result["runtime"]["session_budget_reached"])
        self.assertEqual(result["runtime"]["finalization_hard_ceiling_seconds"], 3)
        return result, events, timing

    async def test_late_running_final_export_finishes_once_and_worker_is_reaped(self):
        result, events, timing = await self._run_case("healthy", observed=.5)
        self.assertFalse(result["runtime"]["worker_terminated"])
        self.assertEqual(result["runtime"]["worker_exit_code"], 0, result["test_worker_stderr"])
        self.assertGreater(result["runtime"]["late_final_export_grace_seconds"], 0)
        self.assertIn("single-final-durable-save", result["report"].warnings)
        self.assertNotIn("unexpected-stop-file", result["report"].warnings)
        self.assertEqual(sum(event["stage"] == "html.start" for event in events), 1)
        self.assertEqual(sum(event["stage"] == "html.complete" for event in events), 1)
        self.assertEqual(sum(event["stage"] == "investigation.complete" for event in events), 1)
        self.assertEqual(sum(event["stage"] == "investigation.final_export_draining" for event in events), 1)

    async def test_html_complete_before_initial_expiry_keeps_final_atomic_commit_reservation(self):
        result, events, timing = await self._run_case("commit_race", observed=.5)
        self.assertFalse(result["runtime"]["worker_terminated"])
        self.assertEqual(result["runtime"]["worker_exit_code"], 0, result["test_worker_stderr"])
        finalizing = next(event for event in events if event["stage"] == "investigation.finalizing")
        complete = next(event for event in events if event["stage"] == "html.complete")
        terminal = next(event for event in events if event["stage"] == "investigation.complete")
        original_deadline = finalizing["received_at"]+finalizing["finalization_grace_seconds"]
        self.assertLess(complete["received_at"], original_deadline)
        self.assertGreater(terminal["received_at"], original_deadline)
        self.assertGreater(result["runtime"]["late_final_export_grace_seconds"], 0)
        self.assertEqual(result["report"].coverage["search_execution"]["status"], "completed")
        self.assertIn("single-final-durable-save", result["report"].warnings)
        self.assertEqual(sum(event["stage"] == "html.complete" for event in events), 1)

    async def test_hung_final_repeated_progress_cannot_renew_existing_hard_ceiling(self):
        result, events, timing = await self._run_case("hung", observed=.6, base=.05)
        self.assertTrue(result["runtime"]["worker_terminated"])
        self.assertNotEqual(result["runtime"]["worker_exit_code"], 0)
        self.assertGreater(result["runtime"]["late_final_export_grace_seconds"], 0)
        self.assertGreater(sum(event["stage"] == "html.start" for event in events), 3)
        self.assertEqual(sum(event["stage"] == "investigation.final_export_draining" for event in events), 1)
        self.assertLess(result["runtime"]["total_seconds"], 7.8)
        self.assertLessEqual(result["runtime"]["finalization_grace_seconds"]+
            result["runtime"]["late_final_export_grace_seconds"], 3.001)

    async def test_checkpoint_only_progress_does_not_extend_initial_drain(self):
        result, events, timing = await self._run_case("checkpoint_only")
        self.assertTrue(result["runtime"]["worker_terminated"])
        self.assertEqual(result["runtime"]["late_final_export_grace_seconds"], 0)
        self.assertFalse(any(event["stage"] == "html.start" for event in events))
        self.assertFalse(any(event["stage"] == "investigation.final_export_draining" for event in events))
        self.assertLess(result["runtime"]["total_seconds"], 6.1)


if __name__ == "__main__":
    unittest.main()
