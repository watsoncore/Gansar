"""Offline lifecycle regressions for a single fully enriched final pass."""
from __future__ import annotations
import asyncio
import json
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.models.report import AddressReport, Balance, Transaction
from app.ton_nft.models import (DiscoveryCandidate, DiscoveryResult, NFTAsset,
    NFTCollection, NFTEvent, NFTIntelligenceReport)

TARGET = "0:" + "1" * 64
ITEM = "0:" + "2" * 64
COLLECTION = "0:" + "3" * 64


def wallet():
    return AddressReport(target_address=TARGET, detected_chains=["ton"],
        balances=[Balance(chain="ton", address=TARGET, asset="TON", amount=7, source="synthetic")],
        transactions=[Transaction(chain="ton", tx_hash="a" * 64, source="synthetic",
            from_address=TARGET, to_address=ITEM, asset="TON", amount=2)],
        collection_audit={"streams": {"synthetic": {"history": {"next_cursor": "tail", "exhausted": False}}}})


def nft():
    return NFTIntelligenceReport(investigation_id="single-final-pass", query=TARGET, mode="deep", scope="wallet",
        discovery=DiscoveryResult(normalized_query=TARGET, query_kind="address", status="resolved",
            candidates=[DiscoveryCandidate(address=TARGET, reason="Synthetic wallet fixture")]),
        assets=[NFTAsset(asset_id=ITEM, address=ITEM, collection_address=COLLECTION, name="Exact synthetic item")],
        collections=[NFTCollection(address=COLLECTION, name="Synthetic collection")],
        events=[NFTEvent(event_id="synthetic-nft-transfer", asset_address=ITEM, event_type="transfer",
            transaction_hash="b" * 64, from_address=ITEM, to_address=TARGET, status="success")])


class ContinuousFinalizationTests(unittest.IsolatedAsyncioTestCase):
    async def test_finished_nft_then_owner_has_one_final_attach_correlation_and_graph(self):
        from app import nft_cli
        from app.attribution.engine import correlate_attribution
        from app.graph.builder import build_graph_payload
        from app.ton_nft.service import attach_nft_intelligence
        from app.ton_nft.storage import InvestigationStore
        callbacks=[]; models=[]
        async def collect(address, **kwargs):
            self.assertTrue(kwargs["defer_graph"])
            # NFT returns before this owner analysis completes, matching the
            # actual large resumed investigation that previously rendered twice.
            await asyncio.sleep(.01)
            return wallet(), {}
        async def investigate(query, **kwargs):
            result=nft()
            await kwargs["on_target_resolved"]({"scope":"wallet","analysis_address":TARGET},result)
            return result
        async def ready(report,graph): callbacks.append(report)
        with tempfile.TemporaryDirectory() as directory, \
                patch("app.ton_nft.service.investigate_ton_nft",investigate), \
                patch("app.ton_nft.service.attach_nft_intelligence",wraps=attach_nft_intelligence) as attach, \
                patch("app.attribution.engine.correlate_attribution",wraps=correlate_attribution) as correlate, \
                patch("app.graph.builder.build_graph_payload",wraps=build_graph_payload) as graph_builder:
            path=Path(directory)/"snapshot.sqlite3"
            report,graph=await nft_cli.analyze_search_input(TARGET,continuous=True,address_analyzer=collect,
                on_report_ready=ready,on_model_ready=lambda model:models.append(model),nft_options={"store_path":path})
            self.assertEqual(callbacks, [], "Completed enrichment must go directly to the final renderer")
            self.assertEqual(attach.call_count,1)
            self.assertEqual(correlate.call_count,1)
            self.assertEqual(graph_builder.call_count,1)
            self.assertEqual(len(report.transactions),2)
            self.assertEqual(report.balances[0].amount,7)
            self.assertEqual(report.collection_audit["streams"]["synthetic"]["history"]["next_cursor"],"tail")
            self.assertEqual(report.nft_intelligence["collections"][0]["address"],COLLECTION)
            self.assertEqual(report.nft_intelligence["events"][0]["event_id"],"synthetic-nft-transfer")
            self.assertEqual(models[-1].nft_intelligence["assets"][0]["address"],ITEM)
            expected=build_graph_payload(report)
            self.assertEqual(graph,expected)
            store=InvestigationStore(path)
            try:
                stored=store.load_snapshot("single-final-pass")
                self.assertEqual(len(stored.owner_analysis_snapshot["transactions"]),2)
                self.assertEqual(stored.events[0].event_id,"synthetic-nft-transfer")
            finally: store.close()

    async def test_owner_finishes_first_has_one_checkpoint_without_legacy_waiter(self):
        from app.nft_cli import analyze_search_input
        rendered=asyncio.Event();callbacks=[]
        async def collect(address,**kwargs): return wallet(),{}
        async def ready(report,graph):
            callbacks.append(len(report.transactions));rendered.set()
        async def investigate(query,**kwargs):
            result=nft()
            await kwargs["on_target_resolved"]({"scope":"wallet","analysis_address":TARGET},result)
            await asyncio.wait_for(rendered.wait(),timeout=2)
            # Let any extra owner waiter run; continuous has exactly one owner
            # finish checkpoint, followed by the ordinary full final return.
            await asyncio.sleep(.02)
            self.assertEqual(callbacks,[2])
            return result
        with tempfile.TemporaryDirectory() as directory,patch("app.ton_nft.service.investigate_ton_nft",investigate):
            report,graph=await analyze_search_input(TARGET,continuous=True,address_analyzer=collect,
                on_report_ready=ready,nft_options={"store_path":Path(directory)/"snapshot.sqlite3"})
        self.assertEqual(callbacks,[2])
        self.assertEqual(len(report.transactions),2)
        self.assertTrue(graph["nodes"])

    async def test_owner_storage_and_public_html_redact_mutated_raw_once_at_their_boundaries(self):
        from app.nft_cli import analyze_search_input
        from app.ton_nft.storage import InvestigationStore
        from app.exporters.html_exporter import export_html_report
        async def collect(address,**kwargs):
            result=wallet()
            # Deliberate mutation after model validation exercises the storage
            # and render boundaries rather than relying on constructor cleanup.
            result.transactions[0].raw={"authorization":"Bearer synthetic_private_marker",
                "public":{"unknown_field":"public_marker_preserved", "value":12345}}
            return result,{}
        async def investigate(query,**kwargs):
            result=nft()
            await kwargs["on_target_resolved"]({"scope":"wallet","analysis_address":TARGET},result)
            return result
        with tempfile.TemporaryDirectory() as directory,patch("app.ton_nft.service.investigate_ton_nft",investigate):
            path=Path(directory)/"snapshot.sqlite3"
            report,graph=await analyze_search_input(TARGET,continuous=True,address_analyzer=collect,
                nft_options={"store_path":path})
            store=InvestigationStore(path)
            try:
                owner=store.load_snapshot("single-final-pass").owner_analysis_snapshot
                stored=json.dumps(owner)
                self.assertNotIn("synthetic_private_marker",stored)
                self.assertIn("public_marker_preserved",stored)
                self.assertEqual(owner["transactions"][0]["raw"]["public"]["value"],12345)
            finally:store.close()
            report.attribution_intelligence={"evidence":[{"evidence_id":"synthetic:public-raw-proof",
                "source":"synthetic", "facts":{"authorization":"Bearer synthetic_private_marker",
                    "public":"public_marker_preserved"}}],"addresses":{},"transactions":[]}
            html=export_html_report(report,graph,Path(directory)/"html").output_path.read_text(encoding="utf-8")
            self.assertFalse("synthetic_private_marker" in html,"Public HTML exposed a secret")
            self.assertTrue("public_marker_preserved" in html,"Public proof raw was lost")

    async def test_analyzer_graph_deferral_preserves_all_analysis_and_final_graph(self):
        from app.aggregator import analyzer
        from app.graph.builder import build_graph_payload
        from app.sources.manager import build_default_source_manager
        async def fetch(source,address):
            value=wallet();value.sources_used=[source.name]
            return value
        with ExitStack() as stack:
            stack.enter_context(patch("app.attribution.engine._now",return_value="2026-10-17T00:00:00+00:00"))
            manager=build_default_source_manager()
            for plan in manager._plans.values():plan.retries=0
            stack.enter_context(patch.object(analyzer,"SOURCE_MANAGER",manager))
            stack.enter_context(patch.object(analyzer,"_tonconsole_available",return_value=False))
            for source in {value for name,value in vars(analyzer).items()
                    if name.endswith("Source") and isinstance(value,type) and hasattr(value,"fetch")}:
                stack.enter_context(patch.object(source,"fetch",fetch))
            normal,expected=await analyzer.analyze_address(TARGET,selected_chains=["ton"])
            events=[]
            with patch.object(analyzer,"build_graph_payload",side_effect=AssertionError("Unused graph must be deferred")):
                deferred,unused=await analyzer.analyze_address(TARGET,selected_chains=["ton"],defer_graph=True,progress=events.append)
        self.assertEqual(unused,{})
        self.assertEqual(deferred.transactions,normal.transactions)
        self.assertEqual(deferred.balances,normal.balances)
        self.assertEqual(deferred.ton_activity_intelligence,normal.ton_activity_intelligence)
        # Local timing diagnostics naturally differ between the two calls.
        def facts(value):
            if isinstance(value,dict):return {key:facts(item) for key,item in value.items() if key!="elapsed_seconds"}
            if isinstance(value,list):return [facts(item) for item in value]
            return value
        self.assertEqual(facts(deferred.attribution_intelligence),facts(normal.attribution_intelligence))
        self.assertEqual(facts(build_graph_payload(deferred)),facts(expected))
        self.assertIn("graph.deferred",[event["stage"] for event in events])


if __name__=="__main__": unittest.main()
