"""Public-context lifecycle and main-pipeline replay, never fresh live evidence.

Financial controls reuse genuine retained ETH rows. External I/O is explicitly
isolated; this suite never generates HTML or reports replay as a new source hit.
"""
import asyncio
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from functools import lru_cache
import gzip
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

import app.aggregator.analyzer as analyzer
from app.models.report import AddressReport, SourceHealth, Transaction
from app.utils.public_context import merge_public_context, scoped_public_context, failed_public_context
from test_ens_pipeline import EmptySource, StatusEnsSource, isolated_eth_collectors

ROOT = Path(__file__).resolve().parents[1]
TARGET = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
LIVE = ROOT / "validation/typography_osint_20261026/sources/adapter_vitalik.json.gz"


def live_context():
    if not LIVE.exists():
        raise unittest.SkipTest("Actual EAS adapter capture is unavailable")
    return json.loads(gzip.decompress(LIVE.read_bytes()))["public_address_context"]


@lru_cache(maxsize=1)
def real_financial_rows():
    path = ROOT / "validation/web3_context_20261025/ethereum/report.json.gz"
    if not path.exists():
        raise unittest.SkipTest("Actual ETH transaction capture is unavailable")
    with gzip.open(path, "rt", encoding="utf8") as stream:
        report = json.load(stream)
    return report["transactions"][:3]


def seed():
    return AddressReport(target_address=TARGET, detected_chains=["eth"],
        transactions=[Transaction.model_validate(deepcopy(row)) for row in real_financial_rows()],
        public_address_context=live_context())


class PublicSource:
    name = "eas_eth"
    chain = "eth"
    public_context_only = True

    def __init__(self, behavior="ok"):
        self.behavior, self.calls = behavior, 0

    async def fetch(self, address):
        self.calls += 1
        if self.behavior == "timeout":
            await asyncio.sleep(3600)
        report = AddressReport(target_address=address, sources_used=[self.name],
            public_address_context=live_context(),
            source_health=[SourceHealth(source=self.name, status=self.behavior)])
        report.public_address_context["outcomes"][0]["status"] = self.behavior
        if self.behavior == "wrong_scope":
            report.public_address_context["outcomes"][0]["input"] = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        return report


@contextmanager
def replay(source):
    with isolated_eth_collectors(StatusEnsSource("empty")):
        with patch("app.sources.eas_public.EasAttestationSource", return_value=source), \
             patch.object(analyzer, "_source_budget", side_effect=lambda name, timeout: 0.04 if name == "eas_eth" else 1):
            yield


class PublicContextMergeTests(unittest.TestCase):
    def test_fresh_failure_replaces_old_claims_and_keeps_exact_financials(self):
        report = seed()
        before = [tx.model_dump(mode="python") for tx in report.transactions]
        fresh = AddressReport(target_address=TARGET,
            public_address_context=failed_public_context("eas_eth", "eth", TARGET, "timeout"))
        analyzer._merge(report, fresh)
        self.assertEqual(report.public_address_context["outcomes"][0]["claims"], [])
        self.assertEqual([tx.model_dump(mode="python") for tx in report.transactions], before)
        restored = AddressReport.model_validate_json(report.model_dump_json())
        self.assertEqual(restored.public_address_context, report.public_address_context)

    def test_scope_rejects_wrong_provider_network_target_and_malformed_claims(self):
        actual = live_context()["outcomes"][0]
        rows = [deepcopy(actual)]
        for field, value in (("source", "unit-wrong-provider"), ("chain", "optimism"),
                             ("input", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), ("claims", {})):
            row = deepcopy(actual);row[field] = value;rows.append(row)
        result = scoped_public_context({"version": 1, "outcomes": rows}, "eas_eth", "eth", TARGET)
        self.assertEqual(result["outcomes"], [actual])
        result["outcomes"][0]["claims"].clear()
        self.assertTrue(actual["claims"])

    def test_other_provider_claims_remain_separate_without_winner_or_alias(self):
        previous = live_context()
        other = deepcopy(previous);other["outcomes"][0]["source"] = "unit-other-public-provider"
        merged = merge_public_context(previous, other)
        self.assertEqual(len(merged["outcomes"]), 2)
        self.assertEqual({row["source"] for row in merged["outcomes"]}, {"eas_eth", "unit-other-public-provider"})
        merged["outcomes"][0]["claims"].clear()
        self.assertTrue(previous["outcomes"][0]["claims"])


class PublicContextPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_expired_global_deadline_clears_stale_claims_without_fetch(self):
        source = PublicSource()
        with replay(source):
            report, _ = await analyzer.analyze_address(TARGET, selected_chains=["eth"],
                initial_report=seed(), defer_graph=True,
                deadline=asyncio.get_running_loop().time() - 1)
        outcome = next(row for row in report.public_address_context["outcomes"] if row["source"] == "eas_eth")
        self.assertEqual(source.calls, 0)
        self.assertEqual(outcome["claims"], [])
        self.assertEqual(outcome["status"], "skipped")

    async def test_outer_timeout_clears_old_claims_without_http(self):
        source = PublicSource("timeout")
        with replay(source):
            report, _ = await analyzer.analyze_address(TARGET, selected_chains=["eth"],
                initial_report=seed(), defer_graph=True)
        outcome = next(row for row in report.public_address_context["outcomes"] if row["source"] == "eas_eth")
        self.assertEqual(source.calls, 1)
        self.assertEqual(outcome["claims"], [])
        self.assertIn(outcome["status"], {"timeout", "partial"})

    async def test_wrong_scope_result_cannot_leave_old_target_claims_current(self):
        source = PublicSource("wrong_scope")
        # SourceHealth's schema accepts known statuses only; the scope mutation
        # is a control, with an otherwise successful source result.
        source.behavior = "ok"
        original = source.fetch
        async def wrong(address):
            result = await original(address)
            result.public_address_context["outcomes"][0]["input"] = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            return result
        source.fetch = wrong
        with replay(source):
            report, _ = await analyzer.analyze_address(TARGET, selected_chains=["eth"],
                initial_report=seed(), defer_graph=True)
        outcome = next(row for row in report.public_address_context["outcomes"] if row["source"] == "eas_eth")
        self.assertEqual(outcome["claims"], [])

    async def test_public_partial_stays_partial_and_never_reaches_neighbor_planner(self):
        source = PublicSource("partial")
        planner = AsyncMock()
        events = []
        with replay(source), patch("app.attribution.investigation_planner.run_investigation_planner", planner):
            report, _ = await analyzer.analyze_address(TARGET, selected_chains=["eth"],
                initial_report=seed(), defer_graph=True, progress=events.append)
        self.assertEqual(source.calls, 1)
        outcome = next(row for row in report.public_address_context["outcomes"] if row["source"] == "eas_eth")
        self.assertTrue(outcome["claims"])
        self.assertTrue(any(row.get("stage") == "source.result" and row.get("source") == "eas_eth"
                            and row.get("status") == "partial" for row in events))
        self.assertTrue(planner.await_count)
        for call in planner.await_args_list:
            self.assertTrue(all(not getattr(item, "public_context_only", False) for item in call.args[1]))
            self.assertFalse({item.name for item in call.args[1]} & {"eas_eth", "lens_public", "basenames"})

    async def test_public_context_uses_separate_capacity_from_four_core_collectors(self):
        release = asyncio.Event()
        public_started = asyncio.Event()
        blocked = set()
        class BlockingCore(EmptySource):
            async def fetch(self, address):
                blocked.add(self.name)
                await release.wait()
                return await super().fetch(address)
        source = PublicSource()
        original = source.fetch
        async def observed(address):
            public_started.set()
            return await original(address)
        source.fetch = observed
        with replay(source), ExitStack() as stack:
            for factory, name in (("EthereumEtherscanApiSource", "etherscan_api"),
                                  ("EthereumRpcSource", "ethereum_rpc"),
                                  ("EthereumBlockchairSource", "blockchair_ethereum"),
                                  ("EthereumEthplorerSource", "ethplorer")):
                stack.enter_context(patch.object(analyzer, factory,
                    side_effect=lambda *args, _name=name, **kwargs: BlockingCore(_name)))
            stack.enter_context(patch.object(analyzer, "_source_budget", return_value=10))
            task = asyncio.create_task(analyzer.analyze_address(TARGET, selected_chains=["eth"], defer_graph=True))
            try:
                await asyncio.wait_for(public_started.wait(), timeout=2)
                self.assertEqual(len(blocked), 4)
            finally:
                release.set()
                await task


if __name__ == "__main__":
    unittest.main()
