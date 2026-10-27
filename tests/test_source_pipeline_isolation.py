"""Source failures remain visible without breaking usable search results."""
from __future__ import annotations

from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.aggregator import analyzer
from app.exporters.html_exporter import export_html_report
from app.models.report import AddressReport, SourceHealth, Transaction
from app.sources.manager import build_default_source_manager


TON = "0:" + "1" * 64
ETH = "0x" + "1" * 40


def usable_report(source, address, chain):
    recipient = "0:" + "2" * 64 if chain == "ton" else "0x" + "2" * 40
    return AddressReport(target_address=address, detected_chains=[chain], sources_used=[source.name],
        transactions=[Transaction(chain=chain, tx_hash=f"isolation-{index}", source=source.name,
            from_address=address, to_address=recipient, asset=chain.upper(), amount=1,
            amount_decimal="1", direction="out", success=True,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc)) for index in range(3)])


class SourcePipelineIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def run_fixture(self, chain, callback, manager, *, include_experimental=False):
        address = TON if chain == "ton" else ETH
        with ExitStack() as stack:
            stack.enter_context(patch.object(analyzer, "SOURCE_MANAGER", manager))
            stack.enter_context(patch.object(analyzer, "_tonconsole_available", return_value=False))
            classes = {value for name, value in vars(analyzer).items()
                       if name.endswith("Source") and isinstance(value, type) and hasattr(value, "fetch")}
            for collector in classes:
                stack.enter_context(patch.object(collector, "fetch", callback))
            return await analyzer.analyze_address(address, selected_chains=[chain], include_experimental=include_experimental)

    async def test_experimental_ton_sources_do_not_repeat_in_fallback(self):
        """A failing/partial first-wave collector has its own bounded retry policy."""
        for outcome in ("partial", "exception"):
            with self.subTest(outcome=outcome):
                calls = Counter()
                manager = build_default_source_manager()
                for plan in manager._plans.values():
                    plan.retries = 0

                async def fetch(source, address):
                    calls[source.name] += 1
                    if source.name == "tonapi":
                        return usable_report(source, address, "ton")
                    if source.name == "toncenter_v3":
                        if outcome == "exception":
                            raise RuntimeError("deterministic v3 failure")
                        partial = usable_report(source, address, "ton")
                        partial.errors.append("toncenter_v3: deterministic partial response")
                        return partial
                    return AddressReport(target_address=address, sources_used=[source.name])

                report, graph = await self.run_fixture("ton", fetch, manager, include_experimental=True)
                expected = {"tonapi", "tonviewer_public", "toncenter_v3", "telegram_identity",
                            "fragment_public", "getgems_public", "tonscan_public", "dton_public",
                            "cryptoscamdb", "toncenter"}
                self.assertEqual(set(calls), expected)
                self.assertEqual(dict(calls), {name: 1 for name in expected})
                self.assertEqual(len(report.transactions), 3)
                self.assertTrue(graph["nodes"])
                self.assertTrue(any("deterministic" in error for error in report.errors))
                self.assertTrue(any(item.source == "toncenter_v3" and item.status in {"error", "partial"}
                                    for item in report.source_health))

    async def test_source_exception_retains_other_source_and_renders(self):
        async def fetch(source, address):
            if source.name == "etherscan_api":
                raise RuntimeError("deterministic provider failure")
            if source.name == "ethereum_rpc":
                return usable_report(source, address, "eth")
            return AddressReport(target_address=address, sources_used=[source.name])

        report, graph = await self.run_fixture("eth", fetch, build_default_source_manager())
        self.assertEqual(len(report.transactions), 3)
        self.assertTrue(report.activity_chains)
        self.assertTrue(any(error == "etherscan_api: deterministic provider failure" for error in report.errors))
        self.assertTrue(any(health.source == "etherscan_api" and health.status == "error" for health in report.source_health))
        self.assertTrue(graph["nodes"])
        with tempfile.TemporaryDirectory() as temporary:
            html = export_html_report(report, graph, Path(temporary)).output_path.read_text(encoding="utf-8")
            self.assertIn("isolation-", html)
            self.assertIn("deterministic provider failure", html)

    async def test_recovered_429_warning_does_not_trip_circuit(self):
        manager = build_default_source_manager()
        calls = 0
        async def fetch(source, address):
            nonlocal calls
            if source.name == "tonapi":
                calls += 1
                report = usable_report(source, address, "ton")
                report.warnings.append("tonapi: events: http 429 retry")
                return report
            return AddressReport(target_address=address, sources_used=[source.name])

        for _ in range(4):
            report, graph = await self.run_fixture("ton", fetch, manager)
            self.assertTrue(any(health.source == "tonapi" and health.status == "ok" for health in report.source_health))
            self.assertIn("tonapi: events: http 429 retry", report.warnings)
            self.assertEqual(manager.plan("tonapi", 1).fail_count, 0)
            self.assertTrue(graph["nodes"])
        self.assertEqual(calls, 4)

    async def test_terminal_429_is_failure_even_with_partial_data(self):
        manager = build_default_source_manager()
        async def fetch(source, address):
            if source.name == "tonapi":
                report = usable_report(source, address, "ton")
                report.errors.append("tonapi: events: http 429 after retry; fallback")
                return report
            return AddressReport(target_address=address, sources_used=[source.name])

        report, graph = await self.run_fixture("ton", fetch, manager)
        self.assertEqual(len(report.transactions), 3)
        self.assertTrue(any(health.source == "tonapi" and health.status == "rate_limited" for health in report.source_health))
        self.assertEqual(manager.plan("tonapi", 1).fail_count, 1)
        self.assertTrue(graph["nodes"])

    async def test_explicit_unavailable_does_not_record_empty_success(self):
        manager = build_default_source_manager()
        async def fetch(source, address):
            if source.name == "etherscan_api":
                return AddressReport(target_address=address, sources_used=[source.name], source_health=[
                    SourceHealth(source=source.name, status="unavailable", details="provider unavailable")])
            if source.name == "ethereum_rpc":
                return usable_report(source, address, "eth")
            return AddressReport(target_address=address, sources_used=[source.name])

        report, graph = await self.run_fixture("eth", fetch, manager)
        self.assertTrue(any(health.source == "etherscan_api" and health.status == "unavailable" for health in report.source_health))
        self.assertEqual(manager.plan("etherscan_api", 1).fail_count, 1)
        self.assertIsNone(manager.plan("etherscan_api", 1).last_success)
        self.assertEqual(len(report.transactions), 3)
        self.assertTrue(graph["nodes"])


if __name__ == "__main__":
    unittest.main()
