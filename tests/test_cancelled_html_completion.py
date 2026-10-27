"""Successful atomic HTML writes remain measured when their caller is cancelled."""
import asyncio
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from app import main
from app.exporters.html import export as original_export
from app.graph.builder import build_graph_payload
from app.models.report import AddressReport, Transaction


class CancelledHtmlCompletionTests(unittest.IsolatedAsyncioTestCase):
    async def _write(self, *, cancel_count=1, fail=False, checkpoint=True):
        report = AddressReport(target_address="0:"+"1"*64, detected_chains=["ton"], transactions=[
            Transaction(chain="ton", tx_hash=str(index), event_id=f"synthetic:{index}", source="synthetic_cancelled_render")
            for index in range(3)])
        graph = build_graph_payload(report)
        events = []
        entered, release = asyncio.Event(), threading.Event()
        loop = asyncio.get_running_loop()

        def blocked_export(*args, **kwargs):
            loop.call_soon_threadsafe(entered.set)
            if not release.wait(10):
                raise TimeoutError("Test did not release the owned writer")
            if fail:
                raise OSError("Synthetic atomic write failure")
            return original_export(*args, **kwargs)

        with tempfile.TemporaryDirectory() as directory, patch.object(main, "export_html", blocked_export):
            task = asyncio.create_task(main._write_search_html(report, graph, Path(directory), events.append,
                checkpoint=checkpoint))
            try:
                await asyncio.wait_for(entered.wait(), 5)
                for index in range(cancel_count):
                    task.cancel("first-cancellation" if index == 0 else "second-cancellation")
                    await asyncio.sleep(0)
                    self.assertFalse(task.done(), "Cancellation must drain the same owned atomic writer")
                self.assertFalse(any(event["stage"].endswith(".complete") for event in events))
                release.set()
                if fail:
                    with self.assertRaisesRegex(OSError, "Synthetic atomic write failure"):
                        await asyncio.wait_for(task, 5)
                elif cancel_count:
                    with self.assertRaises(asyncio.CancelledError) as cancelled:
                        await asyncio.wait_for(task, 5)
                    self.assertEqual(cancelled.exception.args, ("first-cancellation",))
                else:
                    await asyncio.wait_for(task, 5)
                prefix = "checkpoint.html" if checkpoint else "html"
                self.assertEqual([event["stage"] for event in events],
                    [prefix+".start"] if fail else [prefix+".start", prefix+".complete"])
                self.assertEqual(events[0]["transactions"], 3)
                path = Path(directory)/"report.html"
                if fail:
                    self.assertFalse(path.exists())
                else:
                    self.assertTrue(path.exists())
                    self.assertIn('id="nft-payload"', path.read_text(encoding="utf-8"))
                    self.assertEqual(events[-1]["path"], str(path))
                    self.assertEqual(events[-1]["status"], "partial" if checkpoint else "saved")
                    self.assertEqual(events[-1]["cancelled_after_save"], bool(cancel_count))
                    self.assertFalse(path.with_name("report.html.tmp").exists())
            finally:
                release.set()
                await asyncio.gather(task, return_exceptions=True)

    async def test_cancelled_checkpoint_emits_one_completion_after_actual_atomic_html_then_propagates(self):
        await self._write()

    async def test_second_cancellation_does_not_orphan_writer_or_replace_first_cancellation(self):
        await self._write(cancel_count=2, checkpoint=False)

    async def test_cancelled_failed_writer_propagates_write_error_without_success_event(self):
        await self._write(fail=True)

    async def test_normal_final_write_keeps_one_start_one_complete(self):
        await self._write(cancel_count=0, checkpoint=False)


if __name__ == "__main__":
    unittest.main()
