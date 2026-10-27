"""Reproduce the real drain/late-final-stage ordering with owned local children.

No provider responses are mocked as live data. Only stage workloads and clocks
are controlled. The worker still writes a genuine original HTML and checkpoint.
"""
import asyncio
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from app import search_runtime as runtime


WORKER = '''import json,sys,time
from pathlib import Path
from app.models.report import AddressReport,Transaction
from app.graph.builder import build_graph_payload
from app.exporters.html import export
from app.search_runtime import atomic_pickle
data=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"));case=sys.argv[2]
session=Path(data["session"]);output=Path(data["jobs"][0]["output"])
report=AddressReport(target_address=data["jobs"][0]["query"],warnings=["Synthetic final graph ordering; no live source evidence"])
path=export(report,build_graph_payload(report),output)
atomic_pickle(session/"job_0.pickle",(report,path,None,False))
def event(stage,**fields):print(json.dumps({"job":0,"event":{"stage":stage,**fields}}),flush=True)
def until(at):
    while time.monotonic()<at:time.sleep(.005)
def control(name):
    path=session/name
    while not path.exists():time.sleep(.005)
    return json.loads(path.read_text(encoding="utf-8"))
event("checkpoint.html.start",transactions=0);time.sleep(.025);event("checkpoint.html.complete")
event("initial_html.ready")
report.transactions=[Transaction(chain="ton",tx_hash=str(i),source="synthetic_phase_order") for i in range(1000)]
atomic_pickle(session/"job_0.pickle",(report,path,None,False))
event("checkpoint.model.saved",transactions=1000)
boundary=control("test_phase_initial.json")
event("checkpoint.html.start",transactions=1000);time.sleep(.07);event("checkpoint.html.complete")
# The ordinary drain expires before any final graph/HTML has begun.
recalibrated=control("test_phase_recalibrated.json")
until(recalibrated["at"]+.04)
if case=="checkpoint_only":
    while True:event("checkpoint.html.start",transactions=1000);event("fixture.progress");time.sleep(.025)
event("graph.start");graph=build_graph_payload(report);event("graph.complete")
event("html.start",transactions=1000)
if case=="hung":
    while True:event("graph.start");event("html.start",transactions=1000);event("fixture.progress");time.sleep(.025)
report.coverage["search_execution"]={"status":"completed","phase":"finished","html_pending_update":False,"data_complete":False}
path=export(report,graph,output);event("html.complete")
# Even a fast actual HTML write must finish its atomic model commit after the
# measured checkpoint reservation, within the SAME original absolute ceiling.
until(recalibrated["at"]+recalibrated["remaining"]+.3)
report.warnings.append("final-commit-after-render-recalibration")
atomic_pickle(session/"job_0.pickle",(report,path,None,True));event("investigation.complete")
'''


class FinalGraphAfterRecalibration(unittest.IsolatedAsyncioTestCase):
    async def run_case(self, case):
        create = asyncio.create_subprocess_exec
        children, events = [], []

        async def start(*args, **kwargs):
            kwargs["stderr"] = asyncio.subprocess.PIPE
            child = await create(args[0], "-B", "-c", WORKER, args[-1], case, **kwargs)
            children.append(child)
            return child

        session_path = None
        def progress(index, event):
            nonlocal session_path
            now = time.monotonic()
            events.append({**event, "received_at": now})
            if event.get("stage") == "investigation.finalizing":
                session_path = Path(event["session"])
                content = {"at": now, "grace": event["finalization_grace_seconds"]}
                name = "test_phase_initial.json"
            elif event.get("stage") == "investigation.final_export_draining" and event.get("reservation_phase") == "measured_large_render_cost":
                content = {"at": now, "remaining": event["remaining_seconds"]}
                name = "test_phase_recalibrated.json"
            else:
                return
            temporary = session_path / (name + ".writing")
            temporary.write_text(json.dumps(content), encoding="utf-8")
            temporary.replace(session_path / name)

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(runtime.asyncio, "create_subprocess_exec", start), \
                patch.object(runtime, "SEARCH_SECONDS", 2), patch.object(runtime, "WORKER_SECONDS", 2), \
                patch.object(runtime, "COLLECTION_SECONDS", .5), patch.object(runtime, "SHUTDOWN_GRACE_SECONDS", .1), \
                patch.object(runtime, "FINALIZATION_GRACE_SECONDS", .12):
            result = (await runtime.run_bounded_jobs([{"query": "0:" + "1" * 64, "output": directory}], progress=progress))[0]
            stderr = "".join([(await child.stderr.read()).decode("utf-8", errors="replace") for child in children])
            self.assertTrue(Path(result["html"]).exists())
        self.assertTrue(all(child.returncode is not None for child in children), stderr)
        self.assertFalse(result["runtime"]["collection_deadline_extended"])
        self.assertEqual(result["runtime"]["collection_seconds"], .5)
        self.assertEqual(result["runtime"]["finalization_hard_ceiling_seconds"], 3)
        self.assertLessEqual(result["runtime"]["finalization_grace_seconds"] + result["runtime"]["late_final_export_grace_seconds"], 3.01)
        self.assertLess(result["runtime"]["total_seconds"], 5.9)
        self.assertEqual(sum(e["stage"] == "investigation.final_export_draining" and e.get("reservation_phase") == "measured_large_render_cost" for e in events), 1)
        return result, events, stderr

    async def test_late_graph_then_html_and_commit_finish_inside_original_ceiling(self):
        result, events, stderr = await self.run_case("healthy")
        self.assertEqual(result["runtime"]["worker_exit_code"], 0, stderr)
        self.assertFalse(result["runtime"]["worker_terminated"], stderr)
        self.assertIn("final-commit-after-render-recalibration", result["report"].warnings)
        reservation = [e for e in events if e["stage"] == "investigation.final_export_draining"]
        self.assertEqual(len(reservation), 2)
        recalibration = reservation[0]
        final_graph = next(e for e in events if e["stage"] == "graph.start")
        terminal = next(e for e in events if e["stage"] == "investigation.complete")
        self.assertGreater(final_graph["received_at"], recalibration["received_at"])
        self.assertGreater(terminal["received_at"], recalibration["received_at"] + recalibration["remaining_seconds"])

    async def test_repeated_final_progress_cannot_move_original_absolute_ceiling(self):
        result, events, stderr = await self.run_case("hung")
        self.assertTrue(result["runtime"]["worker_terminated"], stderr + json.dumps(result["runtime"]))
        self.assertNotEqual(result["runtime"]["worker_exit_code"], 0)
        self.assertEqual(sum(e["stage"] == "investigation.final_export_draining" for e in events), 2)
        self.assertGreater(sum(e["stage"] == "graph.start" for e in events), 5)

    async def test_checkpoint_only_progress_does_not_qualify_for_final_phase_remainder(self):
        result, events, stderr = await self.run_case("checkpoint_only")
        self.assertTrue(result["runtime"]["worker_terminated"],stderr+json.dumps(result['runtime'])+json.dumps(events[-12:]))
        self.assertEqual(sum(e["stage"] == "investigation.final_export_draining" for e in events), 1)
        self.assertFalse(any(e["stage"] in {"graph.start", "html.start"} for e in events))


if __name__ == "__main__":
    unittest.main()
