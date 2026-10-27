"""Local source deadlines retain P0 observations before analytics/graph work."""
from __future__ import annotations
import asyncio
from contextlib import ExitStack
import unittest
from unittest.mock import patch

from app.aggregator import analyzer
from app.models.report import AddressReport, Balance, Transaction
from app.sources.manager import build_default_source_manager


A, B = ["0:" + char * 64 for char in "12"]


def sources(stack, fetch):
    manager = build_default_source_manager()
    stack.enter_context(patch.object(analyzer, "SOURCE_MANAGER", manager))
    stack.enter_context(patch.object(analyzer, "_tonconsole_available", return_value=False))
    for cls in {value for name, value in vars(analyzer).items() if name.endswith("Source") and isinstance(value, type) and hasattr(value, "fetch")}:
        stack.enter_context(patch.object(cls, "fetch", fetch))
    return manager


def p0():
    return AddressReport(target_address=A, detected_chains=["ton"],
        balances=[Balance(chain="ton", address=A, asset="TON", amount=7, source="fresh_probe")],
        transactions=[Transaction(chain="ton", tx_hash="p0-transfer", from_address=A, to_address=B,
            amount=1, asset="TON", source="fresh_probe", direction="out")])


class AnalyzerDeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def test_expired_deadline_skips_sources_and_retains_initial_p0_and_checkpoint(self):
        calls, collected = [], []
        async def fetch(source, address):
            calls.append(source.name)
            return AddressReport(target_address=address)
        initial = p0()
        with ExitStack() as stack:
            sources(stack, fetch)
            report, graph = await analyzer.analyze_address(A, selected_chains=["ton"], include_experimental=True,
                deadline=asyncio.get_running_loop().time()-1, initial_report=initial,
                on_collected=lambda row: collected.append(row.model_copy(deep=True)))
        self.assertEqual(calls, [])
        self.assertEqual(len(collected), 1)
        self.assertEqual(collected[0].transactions[0].tx_hash, "p0-transfer")
        self.assertEqual(collected[0].counterparties, [])
        self.assertEqual(report.balances[0].amount, 7)
        self.assertEqual(report.counterparties[0].address, B)
        self.assertTrue(graph["nodes"])
        self.assertEqual(initial.counterparties, [])
        self.assertTrue(any(item.status == "skipped" and "deadline" in item.details for item in report.source_health))
        self.assertTrue(any(isinstance(value, dict) and value.get("status") == "truncated" for value in report.coverage.values()))

    async def test_deadline_cancels_fetches_and_queued_sources_without_losing_partial(self):
        calls, stopped, checkpoints = [], [], []
        async def fetch(source, address):
            calls.append(source.name)
            if source.name == "tonapi":
                source._partial_report = p0()
            try:
                await asyncio.Future()
            finally:
                stopped.append(source.name)
        with ExitStack() as stack:
            manager = sources(stack, fetch)
            started = asyncio.get_running_loop().time()
            report, graph = await asyncio.wait_for(analyzer.analyze_address(A, selected_chains=["ton"],
                # Leave time for model/source setup under concurrent Chromium
                # load; the blocked fetches still have to be cancelled, queued
                # sources skipped, and the entire call bounded by two seconds.
                include_experimental=True, deadline=started+0.5,
                on_collected=lambda row: checkpoints.append(row.model_copy(deep=True))), timeout=2)
        self.assertEqual(calls[:2], ["tonapi", "toncenter_v3"])
        self.assertCountEqual(calls, stopped)
        self.assertLessEqual(len(calls), analyzer.SOURCE_CONCURRENCY)
        self.assertEqual(report.transactions[0].tx_hash, "p0-transfer")
        self.assertEqual(checkpoints[0].transactions[0].tx_hash, "p0-transfer")
        self.assertTrue(any(item.status == "partial" and item.source == "tonapi" for item in report.source_health))
        self.assertTrue(any(item.status == "skipped" for item in report.source_health))
        self.assertEqual(manager.plan("tonapi", 1).fail_count, 0)

    async def test_retry_backoff_is_bounded_by_global_deadline(self):
        calls = []
        async def fetch(source, address):
            calls.append(source.name)
            raise RuntimeError("fixture unavailable")
        with ExitStack() as stack:
            manager = sources(stack, fetch)
            for plan in manager._plans.values():
                plan.retries = 5
            report, graph = await asyncio.wait_for(analyzer.analyze_address(A, selected_chains=["ton"],
                deadline=asyncio.get_running_loop().time()+0.03, initial_report=p0()), timeout=2)
        self.assertEqual(report.balances[0].amount, 7)
        self.assertEqual(len(report.transactions), 1)
        self.assertTrue(graph["nodes"])

    async def test_initial_report_target_must_match_before_collectors_start(self):
        calls = []
        async def fetch(source, address):
            calls.append(source.name)
        with ExitStack() as stack:
            sources(stack, fetch)
            with self.assertRaisesRegex(ValueError, "Initial report target differs"):
                await analyzer.analyze_address(B, selected_chains=["ton"], initial_report=p0())
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
