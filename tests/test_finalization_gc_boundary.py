"""A completed large pipeline releases unreachable cycles before final export."""
import gc
from pathlib import Path
import tempfile
import unittest
import weakref
from unittest.mock import patch

from app import main
from app.models.report import AddressReport, Transaction


class FinalizationMemoryBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, rows):
        class FinishedPipelineState:
            pass
        report = AddressReport(target_address="0:" + "1" * 64, detected_chains=["ton"],
            transactions=[Transaction(chain="ton", tx_hash=str(index), source="synthetic_gc_lifecycle") for index in range(rows)])
        reachable = FinishedPipelineState()
        reachable.self = reachable
        dead, events = [], []
        async def analyze(*args, **kwargs):
            completed = FinishedPipelineState()
            completed.self = completed
            completed.report = report
            dead.append(weakref.ref(completed))
            return report, {"nodes": [], "edges": []}
        async def export(current, graph, output, progress, **kwargs):
            self.assertIs(current, report)
            self.assertEqual(len(current.transactions), rows)
            self.assertIs(reachable.self, reachable, "Reachable state from another job must remain live")
            self.assertEqual(dead[0]() is None, rows >= 1000)
            return Path(output) / "report.html"
        enabled = gc.isenabled()
        gc.disable()
        try:
            with tempfile.TemporaryDirectory() as directory, patch.object(main, "analyze_search_input", analyze), \
                    patch.object(main, "_write_search_html", export):
                result = await main._analyze_quiet("0:" + "1" * 64, Path(directory), continuous=True,
                    progress=events.append, close_clients=False)
                self.assertIs(result[0], report)
            reclamations = [event for event in events if event.get("stage") == "final.memory_reclaimed"]
            self.assertEqual(len(reclamations), int(rows >= 1000))
            if reclamations:
                self.assertGreater(reclamations[0]["collected_objects"], 0)
        finally:
            reachable.self = None
            gc.collect()
            if enabled:
                gc.enable()

    async def test_large_finished_pipeline_reclaims_unreachable_cycles_before_export(self):
        await self._run(1000)

    async def test_small_pipeline_avoids_forced_global_collection(self):
        await self._run(3)


if __name__ == "__main__":
    unittest.main()
