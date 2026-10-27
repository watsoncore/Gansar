"""Local UI/lifecycle regressions with blocked work and real HTTP lease handling."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import io
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import AsyncMock, Mock, patch

import httpx
from rich.console import Console
from rich.text import Text

from app import main
from app.models.report import AddressReport
from app.utils import http


STAMP = "2026-10-16T10:00:00+00:00"


class RecordingLive:
    def __init__(self, *args, **kwargs):
        self.updates = []
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def update(self, renderable):
        self.updates.append(renderable)


class SearchUiLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_live_view_keeps_refreshing_during_blocked_threaded_html_export(self):
        started, release = threading.Event(), threading.Event()
        live = RecordingLive()
        report = AddressReport(target_address="fixture-address")
        def export(*args, **kwargs):
            started.set()
            if not release.wait(timeout=5):
                raise TimeoutError("fixture exporter not released")
            return Path("fixture-report.html")
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(main, "analyze_search_input", AsyncMock(return_value=(report, {}))), \
             patch.object(main, "export_html", export), patch.object(main, "Live", return_value=live), \
             patch.object(main, "_analysis_view", side_effect=lambda state: state.stage), \
             patch.object(http, "close_shared_clients", AsyncMock()):
            task = asyncio.create_task(main._analyze_with_live_console("fixture-address", Path(directory)))
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 2))
                before = len(live.updates)
                await asyncio.sleep(0.35)
                self.assertGreater(len(live.updates), before)
                self.assertIn("html.start", live.updates)
                self.assertFalse(task.done())
            finally:
                release.set()
                await asyncio.wait_for(task, timeout=3)

    async def test_cancelled_live_search_drains_search_task_before_http_cleanup(self):
        started, stopped = asyncio.Event(), asyncio.Event()
        child = []
        async def search(*args, **kwargs):
            child.append(asyncio.current_task())
            started.set()
            try:
                await asyncio.Future()
            finally:
                await asyncio.sleep(0)
                stopped.set()
        async def close():
            self.assertTrue(stopped.is_set())
            self.assertTrue(child[0].done())
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(main, "analyze_search_input", search), \
             patch.object(main, "Live", RecordingLive), \
             patch.object(http, "close_shared_clients", AsyncMock(side_effect=close)) as cleanup:
            task = asyncio.create_task(main._analyze_with_live_console("fixture-address", Path(directory)))
            await asyncio.wait_for(started.wait(), timeout=1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            cleanup.assert_awaited_once()

    async def test_managed_live_ctrl_c_returns_saved_report_to_normal_summary(self):
        started,stopped=asyncio.Event(),asyncio.Event()
        report=AddressReport(target_address="fixture-address",
            coverage={"search_execution":{"status":"stopped","data_complete":False}})
        async def managed(*args,**kwargs):
            started.set()
            try:await asyncio.Future()
            except asyncio.CancelledError:
                stopped.set()
                return report,Path("saved-report.html"),None
        with tempfile.TemporaryDirectory() as directory,patch("app.search_runtime.run_bounded_search",managed), \
             patch.object(main,"Live",RecordingLive),patch.object(http,"close_shared_clients",AsyncMock()):
            task=asyncio.create_task(main._analyze_with_live_console("fixture-address",Path(directory),supervised=True))
            await asyncio.wait_for(started.wait(),timeout=2)
            task.cancel()
            result=await asyncio.wait_for(task,timeout=2)
            self.assertTrue(stopped.is_set())
            self.assertIs(result[0],report)
            self.assertEqual(result[0].coverage["search_execution"]["status"],"stopped")

    async def test_batch_tracks_each_running_query_and_owns_final_client_cleanup(self):
        first_started, second_finished, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        snapshots, calls = [], []
        def view(state, addresses):
            snapshots.append({index: {"status": item.status, "stage": item.stage,
                "timestamp": item.timestamp, "last_progress": item.last_progress} for index, item in state.items.items()})
            return Text("batch fixture")
        async def analyze(query, output, *, progress, close_clients):
            calls.append((query, close_clients))
            if query == "first.ton":
                progress({"stage": "nft.owner_history", "timestamp": STAMP, "requests": 9, "assets": 1, "events": 2})
                first_started.set()
                await release.wait()
            else:
                progress({"stage": "html.complete", "timestamp": STAMP, "status": "saved"})
                second_finished.set()
        with tempfile.TemporaryDirectory() as directory:
            inputs = Path(directory) / "inputs.txt"
            inputs.write_text("first.ton\nsecond.ton\n", encoding="utf-8")
            console = Console(file=io.StringIO())
            console.input = Mock(side_effect=[str(inputs), ""])
            with patch.object(main, "console", console), patch.object(main, "Live", RecordingLive), \
                 patch.object(main, "_batch_view", view), patch.object(main, "_analyze_quiet", analyze), \
                 patch.object(http, "close_shared_clients", AsyncMock()) as cleanup:
                task = asyncio.create_task(main.batch_flow())
                try:
                    await asyncio.wait_for(first_started.wait(), timeout=1)
                    await asyncio.wait_for(second_finished.wait(), timeout=1)
                    await asyncio.sleep(0.25)
                    self.assertTrue(any(state[0]["status"] == "running" and state[0]["stage"] == "nft.owner_history"
                                        and state[1]["status"] == "saved" for state in snapshots))
                    cleanup.assert_not_awaited()
                finally:
                    release.set()
                    await asyncio.wait_for(task, timeout=2)
                cleanup.assert_awaited_once()
            self.assertEqual(calls, [("first.ton", False), ("second.ton", False)])
            self.assertEqual(snapshots[-1][0]["timestamp"], STAMP)
            self.assertIsNotNone(snapshots[-1][0]["last_progress"])

    async def test_batch_cancellation_drains_all_workers_before_http_cleanup(self):
        entered, stopped = [], []
        all_started = asyncio.Event()
        async def analyze(query, output, **kwargs):
            entered.append(query)
            if len(entered) == 2:
                all_started.set()
            try:
                await asyncio.Future()
            finally:
                await asyncio.sleep(0)
                stopped.append(query)
        async def close():
            self.assertCountEqual(stopped, ["first.ton", "second.ton"])
        with tempfile.TemporaryDirectory() as directory:
            inputs = Path(directory) / "inputs.txt"
            inputs.write_text("first.ton\nsecond.ton\n", encoding="utf-8")
            console = Console(file=io.StringIO())
            console.input = Mock(return_value=str(inputs))
            with patch.object(main, "console", console), patch.object(main, "Live", RecordingLive), \
                 patch.object(main, "_analyze_quiet", analyze), \
                 patch.object(http, "close_shared_clients", AsyncMock(side_effect=close)) as cleanup:
                task = asyncio.create_task(main.batch_flow())
                await asyncio.wait_for(all_started.wait(), timeout=1)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                cleanup.assert_awaited_once()

    async def test_quiet_cleanup_does_not_interrupt_concurrent_active_shared_client(self):
        slow_started, release = asyncio.Event(), asyncio.Event()
        async def handler(request):
            if request.url.path == "/slow":
                slow_started.set()
                await release.wait()
            return httpx.Response(200, json={"observed": request.url.path})
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async def search(query, **kwargs):
            async with http.shared_async_client(11) as leased:
                await http.request_json(leased, "GET", "https://example.org/" + query, retries=0)
            return AddressReport(target_address=query), {}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(main, "analyze_search_input", search), \
             patch.object(main, "export_html", return_value=Path(directory) / "report.html"), \
             patch.object(http, "create_async_client", return_value=client):
            slow = asyncio.create_task(main._analyze_quiet("slow", Path(directory) / "slow"))
            try:
                await asyncio.wait_for(slow_started.wait(), timeout=1)
                await main._analyze_quiet("fast", Path(directory) / "fast")
                self.assertFalse(client.is_closed)
                self.assertFalse(slow.done())
            finally:
                release.set()
                result = await asyncio.wait_for(slow, timeout=2)
            self.assertEqual(result[0].target_address, "slow")
            self.assertTrue(client.is_closed)

    async def test_quiet_forwards_real_progress_and_optional_cleanup_ownership(self):
        events = []
        async def search(query, *, progress, **kwargs):
            progress({"stage": "nft.owner_history", "timestamp": STAMP})
            return AddressReport(target_address=query), {}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(main, "analyze_search_input", search), \
             patch.object(main, "export_html", return_value=Path(directory) / "report.html"), \
             patch.object(http, "close_shared_clients", AsyncMock()) as cleanup:
            await main._analyze_quiet("fixture.ton", Path(directory), progress=events.append, close_clients=False)
            cleanup.assert_not_awaited()
        self.assertEqual([event["stage"] for event in events], ["nft.owner_history", "html.start", "html.complete"])
        self.assertTrue(all(datetime.fromisoformat(event["timestamp"]).utcoffset().total_seconds() == 0 for event in events))


class SearchProgressRenderingTests(unittest.TestCase):
    def test_actual_nft_retry_and_rate_wait_seconds_are_visible(self):
        state = main.InvestigationState(address="fixture.ton", source_states={})
        main._search_progress(state, {"stage": "nft.request_retry", "source": "tonapi_nft",
            "status": "rate_limited", "retry_after_seconds": 3.5, "timestamp": STAMP})
        self.assertIn("3.5s", state.source_states["tonapi_nft"].details)
        main._search_progress(state, {"stage": "nft.rate_wait", "source": "tonapi_nft",
            "wait_seconds": 0.7, "timestamp": STAMP})
        self.assertIn("0.7s", state.source_states["tonapi_nft"].details)

    def test_batch_renders_real_stage_utc_and_event_age_for_each_duplicate_query(self):
        first = main.BatchItemState("same.ton", status="running", stage="nft.owner_history", started=90, last_progress=95, timestamp=STAMP)
        second = main.BatchItemState("same.ton", status="running", stage="html.start", started=88, last_progress=99, timestamp=STAMP)
        state = main.BatchState(total=2, items={0: first, 1: second})
        console = Console(file=io.StringIO(), width=240)
        with patch.object(main.time, "monotonic", return_value=100):
            console.print(main._batch_view(state, ["same.ton", "same.ton"]))
        output = console.file.getvalue()
        self.assertIn("01 same.ton", output)
        self.assertIn("02 same.ton", output)
        self.assertIn("nft.owner_history", output)
        self.assertIn("elapsed 10.0s", output)
        self.assertIn("last event 5.0s ago", output)
        self.assertIn(STAMP, output)
        self.assertNotIn("%", output)

    def test_noninteractive_progress_throttles_requests_but_reports_real_stage_and_error(self):
        console = Mock()
        with patch.object(main, "console", console), patch.object(main.time, "monotonic", return_value=100):
            progress = main._command_progress()
            for index in range(20):
                progress({"stage": "nft.request_completed", "timestamp": STAMP, "requests": index})
            progress({"stage": "target.resolved", "timestamp": STAMP})
            progress({"stage": "source.result", "source": "fixture_source", "status": "rate_limited", "timestamp": STAMP})
        self.assertEqual(console.print.call_count, 3)
        output = "\n".join(call.args[0].plain for call in console.print.call_args_list)
        self.assertIn(STAMP, output)
        self.assertIn("target.resolved", output)
        self.assertIn("fixture_source", output)
        self.assertIn("rate_limited", output)
        self.assertNotIn("%", output)


if __name__ == "__main__":
    unittest.main()
