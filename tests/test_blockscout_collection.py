"""Bounded transport and cursor replay; synthetic data are test-only."""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch
import httpx
from app.models.report import AddressReport
from app.sources.evm_blockscout import EvmBlockscoutSource
from app.aggregator.collection_audit import merge_audit
from app.utils.http import close_shared_clients, request_diagnostics, request_json

A,B=("0x"+c*40 for c in "12")
def row(index):
    return {"hash":"0x"+f"{index:064x}","from":{"hash":A},"to":{"hash":B},"value":"1000000000000000000","status":"ok","raw_input":"0x","timestamp":"2026-10-27T00:00:00Z"}

class BlockscoutTransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):await close_shared_clients()

    async def test_independent_requests_overlap_but_remain_bounded(self):
        active=peak=0
        async def handler(request):
            nonlocal active,peak
            active+=1;peak=max(peak,active)
            try:
                await asyncio.sleep(.45)
                return httpx.Response(200,json={"items":[],"next_page_params":None})
            finally:active-=1
        source=EvmBlockscoutSource(2);report=AddressReport(target_address=A)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await asyncio.gather(*(source._get(client,"/api/v2/test/"+str(i),report) for i in range(4)))
        self.assertEqual(peak,2)
        metrics=report.collection_audit["http"][source.name]
        self.assertEqual(metrics["transport_attempts"],4)
        self.assertEqual(metrics["statuses"],{"200":4})
        self.assertEqual(len(metrics["requests"]),4)

    async def test_500_retries_exact_cursor_and_preserves_success(self):
        seen=[]
        def handler(request):
            seen.append(str(request.url))
            return httpx.Response(500 if len(seen)==1 else 200,json={"items":[row(7)],"next_page_params":None})
        source=EvmBlockscoutSource(2);report=AddressReport(target_address=A)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            data=await source._get(client,"/api/v2/test/retry",report,{"index":40})
        self.assertEqual(data["items"],[row(7)]);self.assertEqual(seen,[seen[0],seen[0]])
        metrics=report.collection_audit["http"][source.name]
        self.assertEqual(metrics["retries"],1);self.assertEqual(metrics["transport_attempts"],2)
        self.assertEqual(metrics["statuses"],{"500":1,"200":1})

    async def test_retry_after_is_not_shortened_and_other_sources_not_needed(self):
        source=EvmBlockscoutSource(.1);report=AddressReport(target_address=A)
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r:httpx.Response(429,headers={"Retry-After":"20"},json={}))) as client:
            self.assertIsNone(await source._get(client,"/api/v2/test/limited",report))
        self.assertTrue(source._blocked)
        self.assertEqual(report.collection_audit["http"][source.name]["transport_attempts"],1)
        self.assertTrue(any("Retry-After" in s for s in report.errors))

    async def test_cache_diagnostics_do_not_count_a_hit_as_network(self):
        calls=[];ledger={}
        def handler(request):calls.append(request);return httpx.Response(200,json={"public":True})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with request_diagnostics(ledger):
                for _ in range(2):await request_json(client,"GET","https://example.com/unique-diagnostic",retries=0)
        self.assertEqual(len(calls),1);self.assertEqual(ledger["transport_attempts"],1)
        self.assertEqual(ledger["logical_requests"],2);self.assertEqual(ledger["cache_hits"],1)

class BlockscoutCursorTests(unittest.IsolatedAsyncioTestCase):
    async def test_more_than_old_page_ceiling_retains_every_unique_record(self):
        source=EvmBlockscoutSource(2);source._continuous=True;report=AddressReport(target_address=A)
        async def page(client,endpoint,out,params):
            i=int(params.get("index",0));return {"items":[row(i+1)],"next_page_params":{"index":i+1} if i<1001 else None}
        with patch.object(source,"_get",side_effect=page) as get:
            await source._history(None,A,report,"transactions")
        self.assertEqual(get.call_count,1002);self.assertEqual(len(report.transactions),1002)
        state=report.collection_audit["streams"][source.name]["transactions"]
        self.assertTrue(state["exhausted"]);self.assertFalse(state["history_complete"])

    async def test_cancelled_page_resumes_cursor_without_restarting_head(self):
        source=EvmBlockscoutSource(2);source._continuous=True;report=AddressReport(target_address=A)
        async def page(client,endpoint,out,params):
            if params:raise asyncio.CancelledError()
            return {"items":[row(1)],"next_page_params":{"index":1}}
        with patch.object(source,"_get",side_effect=page):
            with self.assertRaises(asyncio.CancelledError):await source._history(None,A,report,"transactions")
        self.assertEqual(len(report.transactions),1)
        resumed=EvmBlockscoutSource(2);resumed._continuous=True;resumed._resume_state=report.collection_audit["streams"][source.name]
        result=AddressReport(target_address=A)
        with patch.object(resumed,"_get",AsyncMock(return_value={"items":[row(2)],"next_page_params":None})) as get:
            await resumed._history(None,A,result,"transactions")
        self.assertEqual(get.await_args.args[-1],{"index":1});self.assertEqual(len(result.transactions),1)
        self.assertEqual(result.transactions[0].tx_hash,row(2)["hash"])

    async def test_repeated_cursor_stops_with_partial_status_and_retains_rows(self):
        source=EvmBlockscoutSource(2);source._continuous=True;report=AddressReport(target_address=A)
        with patch.object(source,"_get",AsyncMock(return_value={"items":[row(1)],"next_page_params":{"index":1}})) as get:
            await source._history(None,A,report,"transactions")
        self.assertEqual(get.await_count,2);self.assertEqual(len(report.transactions),1)
        state=report.collection_audit["streams"][source.name]["transactions"]
        self.assertFalse(state["exhausted"]);self.assertEqual(state["stop_reason"],"repeated_page")

    async def test_internal_context_retains_all_pages_and_never_creates_money(self):
        source=EvmBlockscoutSource(2);source._continuous=True;report=AddressReport(target_address=A)
        replies=[{"items":[{"transaction_hash":row(1)["hash"],"index":0}],"next_page_params":{"index":1}},
                 {"items":[{"transaction_hash":row(1)["hash"],"index":1}],"next_page_params":None}]
        with patch.object(source,"_get",AsyncMock(side_effect=replies)) as get:
            await source._internal_context(None,A,report)
        self.assertEqual(get.await_count,2);self.assertEqual(report.transactions,[])
        state=report.collection_audit["streams"][source.name]["internal_call_observations"]
        self.assertEqual(len(state["records"]),2);self.assertEqual(state["raw_records"],2)
        self.assertFalse(state["transaction_edge"]);self.assertTrue(state["exhausted"])
        self.assertFalse(state["history_complete"])

    async def test_internal_incremental_head_does_not_erase_unfinished_tail_cursor(self):
        source=EvmBlockscoutSource(2);source._continuous=True;source._incremental=True
        old={"transaction_hash":row(1)["hash"],"index":1}
        source._resume_state={"internal_call_observations":{"next_cursor":{"index":9},"records":[old],"exhausted":False}}
        report=AddressReport(target_address=A)
        async def page(client,endpoint,out,params):
            if params=={}:return {"items":[old],"next_page_params":{"index":2}}
            self.assertEqual(params,{"index":9})
            return {"items":[{"transaction_hash":row(2)["hash"],"index":9}],"next_page_params":None}
        with patch.object(source,"_get",side_effect=page) as get:
            await source._internal_context(None,A,report)
        state=report.collection_audit["streams"][source.name]["internal_call_observations"]
        self.assertEqual(get.call_count,2);self.assertEqual(len(state["records"]),2);self.assertTrue(state["exhausted"])

    async def test_known_internal_tail_page_is_not_a_proof_of_exhaustion(self):
        source=EvmBlockscoutSource(2);source._continuous=True
        old={"transaction_hash":row(1)["hash"],"index":1}
        source._resume_state={"internal_call_observations":{"next_cursor":{"index":9},"records":[old],"exhausted":False}}
        report=AddressReport(target_address=A)
        replies=[{"items":[old],"next_page_params":{"index":10}},
                 {"items":[{"transaction_hash":row(2)["hash"],"index":10}],"next_page_params":None}]
        with patch.object(source,"_get",AsyncMock(side_effect=replies)) as get:
            await source._internal_context(None,A,report)
        state=report.collection_audit["streams"][source.name]["internal_call_observations"]
        self.assertEqual(get.await_count,2);self.assertEqual(len(state['records']),2)
        self.assertEqual(state['stop_reason'],'endpoint_exhausted')

    def test_transport_metrics_survive_report_merge_without_counting_twice(self):
        ledger={"http":{"blockscout_eth":{"transport_attempts":3}}};merged={}
        merge_audit(merged,ledger);merge_audit(merged,ledger)
        self.assertEqual(merged, {"schema":"collection_audit",**ledger})

if __name__=="__main__":unittest.main()
