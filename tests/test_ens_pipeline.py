"""ENS integration replay; captures retain their original live provenance.

No network requests or HTML export happen here. Synthetic boundary transaction
observations below exist only to detect accidental financial mutations.
"""
import asyncio
from contextlib import ExitStack, contextmanager
from decimal import Decimal
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

import app.aggregator.analyzer as analyzer
from app.models.report import AddressReport, SourceHealth, Transaction
from app.nft_cli import analyze_search_input
from app.sources.manager import build_default_source_manager


CAPTURE = Path(__file__).resolve().parents[1] / "validation/web3_context_20261025/ens/vitalik_name.json"


def captured_seed():
    if not CAPTURE.is_file():
        raise unittest.SkipTest("Saved live ENS capture is unavailable")
    return AddressReport.model_validate(json.loads(CAPTURE.read_text(encoding="utf-8")))


class EmptySource:
    def __init__(self, name):
        self.name = name

    async def fetch(self, address):
        return AddressReport(target_address=address, sources_used=[self.name])


class EmptyPublicSource(EmptySource):
    public_context_only = True

    def __init__(self, name, context_chain):
        super().__init__(name)
        self.chain = "multi"
        self.context_chain = context_chain


class StatusEnsSource:
    name = "ethereum_ens"

    def __init__(self, status):
        self.status = status
        self.calls = 0

    async def fetch(self, address):
        self.calls += 1
        if self.status == "timeout":
            await asyncio.sleep(3600)
        if self.status == "exception":
            raise RuntimeError("test-only provider failure")
        return AddressReport(target_address=address, sources_used=[self.name],
            ens_profile={"lookup_status": self.status, "source": self.name, "coverage": {"rpc_calls": 1}},
            source_health=[SourceHealth(source=self.name, status="empty" if self.status == "empty" else self.status)])


@contextmanager
def isolated_eth_collectors(ens_source=None, *, forbid_ens=False):
    """Keep the actual orchestration/merge; replace external I/O only."""
    names = {"EthereumEtherscanApiSource": "etherscan_api", "EthereumRpcSource": "ethereum_rpc",
        "EthereumBlockchairSource": "blockchair_ethereum", "EthereumEthplorerSource": "ethplorer",
        "EthereumLabelsSource": "ethereum_labels", "EthereumEtherscanHtmlSource": "etherscan_html",
        "EvmBlockscoutSource": "blockscout_eth", "VerifiedContractSource": "sourcify_eth",
        "CryptoScamDbSource": "cryptoscamdb"}
    with ExitStack() as stack:
        for class_name, source_name in names.items():
            stack.enter_context(patch.object(analyzer, class_name,
                side_effect=lambda *args, _name=source_name, **kwargs: EmptySource(_name)))
        stack.enter_context(patch("app.attribution.bridge_execution_evidence.WormholeExecutionEvidenceSource",
            side_effect=lambda *args, **kwargs: EmptySource("wormholescan")))
        # These public context sources belong to separate live validation.
        # Replay must not reach their streamed transport or real DNS/API.
        for module, name, source_name, context_chain in (
            ("app.sources.web3_identity", "LensPublicSource", "lens_public", "lens"),
            ("app.sources.eas_public", "EasAttestationSource", "eas_eth", "eth"),
            ("app.sources.basenames", "BaseNamesSource", "basenames", "base"),
        ):
            stack.enter_context(patch(module + "." + name,
                side_effect=lambda *args, _name=source_name, _chain=context_chain, **kwargs: EmptyPublicSource(_name, _chain)))
        ens_factory = stack.enter_context(patch.object(analyzer, "EthereumEnsSource",
            side_effect=AssertionError("ENS must not run a second time") if forbid_ens else lambda *args, **kwargs: ens_source))
        stack.enter_context(patch.object(analyzer, "SOURCE_MANAGER", build_default_source_manager()))
        stack.enter_context(patch.object(analyzer, "_source_budget", side_effect=lambda name, timeout: .04 if name == "ethereum_ens" else 1))
        stack.enter_context(patch.object(analyzer, "_record_source_result"))
        stack.enter_context(patch("app.attribution.evm_receipt_enrichment.enrich_evm_receipts", AsyncMock()))
        stack.enter_context(patch("app.attribution.engine.correlate_attribution", lambda report: {}))
        stack.enter_context(patch("httpx.AsyncClient.request", side_effect=AssertionError("Replay must not issue network requests")))
        stack.enter_context(patch("httpx.AsyncClient.send", side_effect=AssertionError("Replay must not stream network requests")))
        yield ens_factory


class EnsMergeBoundary(unittest.TestCase):
    def test_fresh_empty_and_unavailable_clear_identity_without_financial_mutation(self):
        for status in ("empty", "unavailable"):
            with self.subTest(status=status):
                base = captured_seed()
                transaction = Transaction(chain="eth", tx_hash="test-only-boundary-observation",
                    from_address=base.target_address, to_address="0x" + "1" * 40,
                    amount_decimal=Decimal("1.234500000000000001"), direction="out", asset="ETH",
                    source="synthetic_boundary_only", raw={"boundary_test": True},
                    provenance=[{"source": "synthetic_boundary_only", "test": True}])
                base.transactions = [transaction]
                base.financial_summary = {"eth:native:ETH": {"in": Decimal(0), "out": transaction.amount_decimal}}
                before = [tx.model_dump(mode="python") for tx in base.transactions]
                summary_before = dict(base.financial_summary)
                fresh = AddressReport(target_address=base.target_address,
                    ens_profile={"source": "ethereum_ens", "lookup_status": status, "coverage": {"rpc_calls": 1}},
                    sources_used=["ethereum_ens"])
                analyzer._merge(base, fresh)
                self.assertEqual(base.ens_profile["lookup_status"], status)
                for field in ("ens_name", "reverse_ens", "resolver", "ens_reverse_resolver", "ens_owner", "ens_resolved_address", "ens_reverse_valid", "avatar"):
                    self.assertIsNone(getattr(base, field), field)
                self.assertEqual(base.text_records, {})
                self.assertEqual([tx.model_dump(mode="python") for tx in base.transactions], before)
                self.assertEqual(base.financial_summary, summary_before)


class EnsRoutingReplay(unittest.IsolatedAsyncioTestCase):
    async def test_saved_live_name_seed_runs_once_and_survives_real_analyzer(self):
        seed = captured_seed()
        saved_thumbnail = seed.ens_profile["avatar"]["thumbnail"]
        resolver = AsyncMock(return_value=seed)
        with isolated_eth_collectors(forbid_ens=True) as constructor, patch("app.sources.ethereum_ens.EthereumEnsSource.resolve_name", resolver):
            report, graph = await analyze_search_input("vitalik.eth", timeout=1,
                address_analyzer=analyzer.analyze_address)
        resolver.assert_awaited_once_with("vitalik.eth")
        constructor.assert_not_called()
        self.assertEqual(report.target_address.lower(), seed.target_address.lower())
        self.assertEqual(report.ens_profile["name"], "vitalik.eth")
        self.assertEqual(report.input_resolution["input_kind"], "ens_name")
        self.assertEqual(report.ens_profile["avatar"]["thumbnail"], saved_thumbnail)
        self.assertFalse(report.transactions)
        self.assertFalse(report.financial_summary)
        self.assertTrue(any(node["id"] == "ens:vitalik.eth" for node in graph["nodes"]))

    async def test_distinct_primary_boundary_keeps_queried_name_and_does_not_recollect(self):
        # Deliberate boundary mutation of replay data, never a live identity claim.
        seed = captured_seed()
        seed.reverse_ens = "boundary-primary.eth"
        seed.ens_profile["primary_name"] = "boundary-primary.eth"
        seed.ens_profile["primary_verified"] = False
        seed.input_resolution = {"input_kind": "ens_name", "normalized_query": "vitalik.eth"}
        with isolated_eth_collectors(forbid_ens=True) as constructor:
            report, _ = await analyzer.analyze_address(seed.target_address,
                selected_chains=["eth"], ens_seed=seed, defer_graph=True)
        constructor.assert_not_called()
        self.assertEqual(report.ens_name, "vitalik.eth")
        self.assertEqual(report.ens_profile["name"], "vitalik.eth")
        self.assertEqual(report.ens_profile["input_name"], "vitalik.eth")
        self.assertEqual(report.reverse_ens, "boundary-primary.eth")
        self.assertFalse(report.ens_profile["primary_verified"])
        graph = analyzer.build_graph_payload(report)
        relations = [edge for edge in graph["edges"] if "primary_name_verified" in edge]
        self.assertTrue(relations)
        self.assertTrue(all(edge["primary_name_verified"] is False for edge in relations))
        self.assertTrue(all(edge.get("monetary") is False for edge in relations))

    async def test_external_source_timeout_replaces_stale_verified_snapshot(self):
        base = captured_seed()
        source = StatusEnsSource("timeout")
        with isolated_eth_collectors(source):
            report, _ = await analyzer.analyze_address(base.target_address,
                selected_chains=["eth"], initial_report=base, defer_graph=True)
        self.assertEqual(source.calls, 1)
        self.assertEqual(report.ens_profile.get("lookup_status"), "timeout")
        self.assertIsNone(report.ens_name)
        self.assertFalse(report.text_records)

    async def test_provider_exception_replaces_stale_verified_snapshot(self):
        base = captured_seed()
        source = StatusEnsSource("exception")
        with isolated_eth_collectors(source):
            report, _ = await analyzer.analyze_address(base.target_address,
                selected_chains=["eth"], initial_report=base, defer_graph=True)
        self.assertEqual(source.calls, 1)
        self.assertIn(report.ens_profile.get("lookup_status"), {"error", "unavailable"})
        self.assertIsNone(report.ens_name)
        self.assertFalse(report.text_records)


if __name__ == "__main__":
    unittest.main()
