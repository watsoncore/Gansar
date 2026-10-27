"""Late actual renderer measurements calibrate one existing finite drain."""
import asyncio
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from app import search_runtime as runtime


class RenderCostPolicyTests(unittest.TestCase):
    def test_late_completed_large_frame_updates_cost_inside_original_absolute_cap(self):
        measured = runtime._ExportDurations()
        measured.observe(0, {"stage": "checkpoint.html.start", "transactions": 20}, now=1)
        measured.observe(0, {"stage": "checkpoint.html.complete"}, now=11)
        initial = 100+runtime._finalization_grace("session_budget", measured.max_completed_seconds)
        measured.observe(0, {"stage": "checkpoint.html.start", "transactions": 2000}, now=20)
        measured.observe(0, {"stage": "checkpoint.html.complete", "cancelled_after_save": True}, now=220)
        self.assertEqual(measured.large_completed_seconds, {0: 200})
        self.assertEqual(runtime._late_render_cost_deadline("session_budget", measured,
            finish_started=100, initial_deadline=initial, now=initial), 1000)
        self.assertEqual(runtime._late_render_cost_deadline("user_stop", measured,
            finish_started=100, initial_deadline=initial, now=initial), initial)
        measured.observe(0, {"stage": "investigation.complete"}, now=221)
        self.assertEqual(measured.large_completed_seconds, {})
        self.assertEqual(runtime._late_render_cost_deadline("session_budget", measured,
            finish_started=100, initial_deadline=initial, now=initial), initial)

    def test_active_large_elapsed_is_lower_bound_with_first_start_and_frozen_own_size(self):
        measured = runtime._ExportDurations()
        measured.observe(0, {"stage": "checkpoint.html.start", "transactions": 1000}, now=200)
        measured.observe(0, {"stage": "checkpoint.html.start", "transactions": 5}, now=500)
        self.assertEqual(measured.started[(0, "checkpoint.html")], 200)
        self.assertEqual(measured.started_rows[(0, "checkpoint.html")], 1000)
        self.assertEqual(runtime._late_render_cost_deadline("session_budget", measured,
            finish_started=100, initial_deadline=280, now=300), 680)
        self.assertEqual(runtime._late_render_cost_deadline("session_budget", measured,
            finish_started=100, initial_deadline=280, now=800), 1000)

    def test_no_size_small_other_job_and_terminal_frames_cannot_borrow_large_model(self):
        for rows, index in ((rows, index) for rows in (None, 20, "1000", float("nan")) for index in (0, 1)):
            with self.subTest(rows=rows, index=index):
                measured = runtime._ExportDurations()
                measured.observe(0, {"stage": "checkpoint.model.saved", "transactions": 32000}, now=1)
                event = {"stage": "checkpoint.html.start"}
                if rows is not None:
                    event["transactions"] = rows
                measured.observe(index, event, now=2)
                measured.observe(index, {"stage": "checkpoint.model.saved", "transactions": 32000}, now=3)
                self.assertEqual(runtime._late_render_cost_deadline("session_budget", measured,
                    finish_started=100, initial_deadline=280, now=700), 280)
                measured.observe(index, {"stage": "checkpoint.html.complete"}, now=710)
                self.assertEqual(measured.large_completed_seconds, {})
        measured = runtime._ExportDurations()
        measured.observe(0, {"stage": "html.start", "transactions": 2000}, now=1)
        measured.observe(1, {"stage": "html.start", "transactions": 3000}, now=2)
        measured.observe(0, {"stage": "search.error"}, now=3)
        self.assertEqual(set(measured.started), {(1, "html")})
        measured.observe(1, {"stage": "investigation.stopped"}, now=4)
        self.assertEqual(measured.started, {})
        self.assertEqual(measured.started_rows, {})


_WORKER = '''import json,sys,time
from pathlib import Path
from app.models.report import AddressReport,Transaction
from app.graph.builder import build_graph_payload
from app.exporters.html import export
from app.search_runtime import atomic_pickle
data=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"));case=sys.argv[2];session=Path(data["session"])
report=AddressReport(target_address=data["jobs"][0]["query"],warnings=["Synthetic late render measurement; no live evidence"])
output=Path(data["jobs"][0]["output"])
def event(stage,**fields):print(json.dumps({"job":0,"event":{"stage":stage,**fields}}),flush=True)
def until(deadline):
    while time.monotonic()<deadline:time.sleep(.005)
event("checkpoint.html.start",transactions=0)
path=export(report,build_graph_payload(report),output);event("checkpoint.html.complete")
atomic_pickle(session/"job_0.pickle",(report,path,None,False));event("initial_html.ready")
report.transactions=[Transaction(chain="ton",tx_hash=str(i),source="synthetic_late_render") for i in range(1000)]
graph=build_graph_payload(report);event("checkpoint.model.saved",transactions=1000)
event("checkpoint.html.start",transactions=1000)
control=session/"test_render_cost_control.json"
while not control.exists():time.sleep(.005)
boundary=json.loads(control.read_text(encoding="utf-8"));initial=boundary["at"]+boundary["grace"]
if case=="hung":
    while True:event("checkpoint.html.start",transactions=1000);event("fixture.progress");time.sleep(.04)
if case=="completed":
    # Save real HTML first, then publish its completion before the controlled
    # boundary. Renderer speed must not decide which policy case is exercised.
    path=export(report,graph,output)
    until(initial-.15)
else:
    until(initial+.3)
    path=export(report,graph,output)
event("checkpoint.html.complete",cancelled_after_save=True)
# No final phase event is available at initial expiry: actual completed or
# still-active render cost must be enough to make the one bounded decision.
until(initial+.65)
event("html.start",transactions=1000)
report.warnings.append("single-final-after-late-render-measurement")
report.coverage["search_execution"]={"status":"completed","data_complete":False}
path=export(report,graph,output);event("html.complete")
atomic_pickle(session/"job_0.pickle",(report,path,None,True));event("investigation.complete")
'''


class RenderCostProcessTests(unittest.IsolatedAsyncioTestCase):
    async def _run_case(self, case):
        create = asyncio.create_subprocess_exec
        processes, events = [], []

        async def start(*args, **kwargs):
            child = await create(args[0], "-B", "-c", _WORKER, args[-1], case, **kwargs)
            processes.append(child)
            return child

        def progress(index, event):
            events.append({**event, "received_at": time.monotonic()})
            if event.get("stage") == "investigation.finalizing":
                session = Path(event["session"])
                temporary = session/"test_render_cost_control.writing"
                temporary.write_text(json.dumps({"at": time.monotonic(),
                    "grace": event["finalization_grace_seconds"]}), encoding="utf-8")
                temporary.replace(session/"test_render_cost_control.json")

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(runtime.asyncio, "create_subprocess_exec", start), \
                patch.object(runtime, "SEARCH_SECONDS", 4), patch.object(runtime, "WORKER_SECONDS", 4), \
                patch.object(runtime, "COLLECTION_SECONDS", 2), patch.object(runtime, "SHUTDOWN_GRACE_SECONDS", .2), \
                patch.object(runtime, "FINALIZATION_GRACE_SECONDS", 1):
            result = (await runtime.run_bounded_jobs([{"query": "0:"+"1"*64, "output": directory}],
                progress=progress))[0]
            self.assertTrue(Path(result["html"]).exists())
        self.assertTrue(all(child.returncode is not None for child in processes))
        self.assertEqual(result["runtime"]["collection_seconds"], 2)
        self.assertFalse(result["runtime"]["collection_deadline_extended"])
        self.assertEqual(result["runtime"]["finalization_hard_ceiling_seconds"], 6)
        self.assertEqual(result["runtime"]["late_finalization_reservation_phase"], "measured_large_render_cost")
        self.assertEqual(sum(event["stage"] == "investigation.final_export_draining" for event in events), 1)
        self.assertLess(result["runtime"]["total_seconds"], 10.9)
        return result, events

    async def _healthy(self, case):
        result, events = await self._run_case(case)
        self.assertFalse(result["runtime"]["worker_terminated"])
        self.assertEqual(result["runtime"]["worker_exit_code"], 0)
        self.assertEqual(len(result["report"].transactions), 1000)
        self.assertIn("single-final-after-late-render-measurement", result["report"].warnings)
        boundary = next(event for event in events if event["stage"] == "investigation.finalizing")
        deadline = boundary["received_at"]+boundary["finalization_grace_seconds"]
        completed = [event for event in events if event["stage"] == "checkpoint.html.complete"][-1]
        if case == "completed":
            self.assertGreater(completed["received_at"], boundary["received_at"])
            self.assertLess(completed["received_at"], deadline)
        else:
            self.assertGreater(completed["received_at"], deadline)
        self.assertEqual(sum(event["stage"] == "html.complete" for event in events), 1)
        self.assertFalse(any(event["stage"] == "graph.start" for event in events))

    async def test_large_checkpoint_completed_after_initial_calculation_recalibrates_once(self):
        await self._healthy("completed")

    async def test_still_active_large_checkpoint_lower_bound_allows_one_final_commit(self):
        await self._healthy("active")

    async def test_hung_large_checkpoint_duplicate_starts_cannot_reset_original_hard_ceiling(self):
        result, events = await self._run_case("hung")
        self.assertTrue(result["runtime"]["worker_terminated"])
        self.assertNotEqual(result["runtime"]["worker_exit_code"], 0)
        self.assertGreater(sum(event["stage"] == "checkpoint.html.start" for event in events), 4)
        self.assertFalse(any(event["stage"] == "html.complete" for event in events))
        self.assertAlmostEqual(result["runtime"]["finalization_grace_seconds"]+
            result["runtime"]["late_final_export_grace_seconds"], 6)


if __name__ == "__main__":
    unittest.main()
