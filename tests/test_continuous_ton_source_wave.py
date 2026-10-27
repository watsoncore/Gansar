"""Offline scheduling regressions; synthetic collectors are not live proof."""
from __future__ import annotations

import asyncio
from collections import Counter
from contextlib import ExitStack
from decimal import Decimal
import unittest
from unittest.mock import AsyncMock, patch

from app.aggregator import analyzer
from app.models.report import AddressReport, Transaction
from app.sources.manager import build_default_source_manager

TARGET = "0:" + "1" * 64
PEER = "0:" + "2" * 64


def partial(source: str, number: int) -> AddressReport:
    return AddressReport(
        target_address=TARGET, detected_chains=["ton"], sources_used=[source],
        transactions=[Transaction(chain="ton", tx_hash=f"{number:064x}",
            from_address=TARGET, to_address=PEER, asset="TON", amount=number,
            direction="out", source=source,
            raw={"public_marker": f"retained-{number}"})],
        collection_audit={"streams": {source: {"account_transactions": {
            "next_cursor": {"lt": number}, "exhausted": False}}}},
    )


class ContinuousTonSourceWaveTests(unittest.IsolatedAsyncioTestCase):
    def configured(self, fetch, *, authenticated=False):
        stack = ExitStack()
        manager = build_default_source_manager()
        for plan in manager._plans.values():
            plan.retries = 0
        stack.enter_context(patch.object(analyzer, "SOURCE_MANAGER", manager))
        stack.enter_context(patch.object(analyzer, "_source_disabled", return_value=False))
        stack.enter_context(patch.object(analyzer, "_record_source_result"))
        stack.enter_context(patch.object(analyzer, "_tonconsole_available", return_value=authenticated))
        stack.enter_context(patch.object(analyzer, "close_shared_clients", new=AsyncMock()))
        for source_type in {value for name, value in vars(analyzer).items()
                if name.endswith("Source") and isinstance(value, type) and hasattr(value, "fetch")}:
            stack.enter_context(patch.object(source_type, "fetch", fetch))
        return stack

    async def deadline_wave(self, authenticated):
        calls = []
        events = []
        native_finished = asyncio.Event()
        console_finished = asyncio.Event()
        v3_cancelled = asyncio.Event()
        native_budget = []

        async def fetch(source, address):
            calls.append(source.name)
            if source.name == "toncenter_v3":
                source._partial_report = partial(source.name, 3)
                try:
                    # This primary consumes its actual shared absolute deadline.
                    await asyncio.Event().wait()
                finally:
                    v3_cancelled.set()
            if source.name == "toncenter":
                self.assertFalse(v3_cancelled.is_set(), "V2 was deferred until V3 ended")
                native_budget.append(source._timeout)
                native_finished.set()
                return partial(source.name, 2)
            if source.name == "tonconsole":
                self.assertFalse(v3_cancelled.is_set(), "Configured console was starved behind V3")
                console_finished.set()
            if source.name == "tonapi":
                raise RuntimeError("synthetic unavailable API")
            return AddressReport(target_address=address, sources_used=[source.name])

        initial = partial("retained_fixture", 1)
        with self.configured(fetch, authenticated=authenticated):
            deadline = asyncio.get_running_loop().time() + 2.0
            report, graph = await analyzer.analyze_address(
                TARGET, selected_chains=["ton"], include_experimental=True,
                continuous=True, initial_report=initial, deadline=deadline,
                progress=events.append,
            )
        self.assertTrue(native_finished.is_set())
        self.assertTrue(v3_cancelled.is_set())
        self.assertEqual(console_finished.is_set(), authenticated)
        self.assertTrue(native_budget and native_budget[0] > 1.0)
        self.assertTrue(all(count == 1 for count in Counter(calls).values()), calls)
        self.assertEqual(Counter(calls)["toncenter"], 1)
        self.assertEqual(Counter(calls)["toncenter_v3"], 1)
        self.assertEqual(Counter(calls)["tonconsole"], int(authenticated))
        self.assertEqual({tx.tx_hash for tx in report.transactions}, {f"{n:064x}" for n in (1, 2, 3)})
        self.assertEqual([tx.tx_hash for tx in initial.transactions], [f"{1:064x}"])
        self.assertTrue(any("tonapi:" in error for error in report.errors))
        self.assertIn("toncenter", report.collection_audit["streams"])
        self.assertIn("toncenter_v3", report.collection_audit["streams"])
        self.assertFalse(report.coverage["transactions"]["collection_limit_applied"])
        self.assertEqual(report.coverage["transactions"]["discarded_by_display_limit"], 0)
        self.assertEqual(sum(value["out"] for value in report.financial_summary.values()), Decimal(6))
        self.assertTrue(report.counterparties)
        self.assertTrue(report.wallet_timeline)
        self.assertIsNotNone(report.behavioral_fingerprint)
        self.assertTrue(graph["nodes"])
        stages = [event["stage"] for event in events]
        self.assertIn("analysis.complete", stages)
        self.assertIn("graph.complete", stages)
        return report, events

    async def test_native_v2_collects_before_v3_absolute_deadline_and_retains_full_analysis(self):
        await self.deadline_wave(False)

    async def test_configured_console_and_v2_run_once_in_continuous_primary_wave(self):
        await self.deadline_wave(True)

    async def test_noncontinuous_ton_retains_sequential_fallback_behavior(self):
        calls = []
        v3_finished = False

        async def fetch(source, address):
            nonlocal v3_finished
            calls.append(source.name)
            if source.name == "toncenter_v3":
                v3_finished = True
                return partial(source.name, 3)
            if source.name == "toncenter":
                self.assertTrue(v3_finished)
                return partial(source.name, 2)
            if source.name == "tonapi":
                raise RuntimeError("synthetic unavailable API")
            return AddressReport(target_address=address, sources_used=[source.name])

        with self.configured(fetch):
            report, _ = await analyzer.analyze_address(
                TARGET, selected_chains=["ton"], include_experimental=True,
                continuous=False, deadline=asyncio.get_running_loop().time() + 5,
            )
        self.assertEqual(Counter(calls)["toncenter"], 1)
        self.assertGreater(calls.index("toncenter"), calls.index("toncenter_v3"))
        self.assertEqual({tx.tx_hash for tx in report.transactions}, {f"{n:064x}" for n in (2, 3)})

    async def test_cooperative_stop_drains_both_streams_and_preserves_partial_rows_and_cursors(self):
        started = {name: asyncio.Event() for name in ("toncenter", "toncenter_v3")}
        closed = set()

        async def fetch(source, address):
            if source.name in started:
                source._partial_report = partial(source.name, 2 if source.name == "toncenter" else 3)
                started[source.name].set()
                try:
                    await asyncio.Event().wait()
                finally:
                    closed.add(source.name)
            return AddressReport(target_address=address, sources_used=[source.name])

        with self.configured(fetch):
            task = asyncio.create_task(analyzer.analyze_address(
                TARGET, selected_chains=["ton"], include_experimental=True,
                continuous=True, initial_report=partial("retained_fixture", 1),
                deadline=asyncio.get_running_loop().time() + 10,
            ))
            try:
                await asyncio.wait_for(asyncio.gather(*(event.wait() for event in started.values())), timeout=3)
                task.cancel()
                report, graph = await asyncio.wait_for(task, timeout=3)
            finally:
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
        self.assertEqual(closed, set(started))
        self.assertEqual({tx.tx_hash for tx in report.transactions}, {f"{n:064x}" for n in (1, 2, 3)})
        for source in started:
            self.assertEqual(report.collection_audit["streams"][source]["account_transactions"]["next_cursor"],
                {"lt": 2 if source == "toncenter" else 3})
        self.assertTrue(graph["nodes"])


if __name__ == "__main__":
    unittest.main()
