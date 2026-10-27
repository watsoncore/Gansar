"""Clock-boundary fault tests; these are not live source/performance evidence."""
import asyncio
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import httpx

from app.models.report import AddressReport, Transaction
from app.utils import http
from app.utils.public_history_cache import history_cache


class PublicHistoryCacheTests(unittest.IsolatedAsyncioTestCase):
    async def test_query_auth_cookies_and_get_bodies_cannot_enter_public_disk_cache(self):
        from app.utils import public_history_cache as cache
        calls=[]
        async def handler(request):
            calls.append(str(request.url))
            return httpx.Response(200,json={'sequence':len(calls)})
        with tempfile.TemporaryDirectory() as directory, history_cache(Path(directory)/'cache.sqlite3'):
            url='https://tonapi.io/v2/a/events'
            for params,headers,body in (({'api_key':'fixture'},None,None),(None,{'X-API-Key':'fixture'},None),
                    (None,None,{'field':'value'})):
                self.assertIsNone(cache.key_for('GET',url,params,body,headers))
            self.assertIsNone(cache.key_for('GET',url+'?access_token=fixture',None,None,None))
            for _ in range(2):
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler),cookies={'session':'fixture'}) as client:
                    await http.request_json(client,'GET',url,retries=0)
        self.assertEqual(len(calls),2)

    async def test_history_is_reused_across_clients_but_current_state_is_fresh(self):
        calls=[]; events=[]
        async def handler(request):
            calls.append(request.url.path)
            return httpx.Response(200,json={"sequence":len(calls),"nested":{"value":1}})
        with tempfile.TemporaryDirectory() as directory, history_cache(Path(directory)/"cache.sqlite3",events.append):
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                first=await http.request_json(client,"GET","https://tonapi.io/v2/accounts/a/events",retries=0)
                first['nested']['value']=999
                await http.request_json(client,"GET","https://tonapi.io/v2/accounts/a",retries=0)
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                second=await http.request_json(client,"GET","https://tonapi.io/v2/accounts/a/events",retries=0)
                await http.request_json(client,"GET","https://tonapi.io/v2/accounts/a",retries=0)
                await http.request_json(client,"GET","https://tonapi.io/v2/accounts/a/events",retries=0,cache_ttl=0)
        self.assertEqual(second['nested']['value'],1)
        self.assertEqual(calls.count('/v2/accounts/a'),2)
        self.assertEqual(calls.count('/v2/accounts/a/events'),2)
        self.assertTrue(events)
        self.assertFalse(events[0]['current_balance_or_ownership'])

    async def test_expired_or_authenticated_history_is_not_reused(self):
        from app.utils import public_history_cache as cache
        calls=[]
        async def handler(request):
            calls.append(request.headers.get('authorization'))
            return httpx.Response(200,json={'seq':len(calls)})
        with tempfile.TemporaryDirectory() as directory, history_cache(Path(directory)/'cache.sqlite3'):
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                await http.request_json(client,'GET','https://tonapi.io/v2/a/events',retries=0)
            with patch.object(cache.time,'time',return_value=time.time()+46):
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    await http.request_json(client,'GET','https://tonapi.io/v2/a/events',retries=0)
            for key in ('fixture_a','fixture_b'):
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler),headers={'Authorization':key}) as client:
                    await http.request_json(client,'GET','https://tonapi.io/v2/a/events',retries=0)
        self.assertEqual(calls,[None,None,'fixture_a','fixture_b'])


class DeepEvidenceSerializationTests(unittest.TestCase):
    def test_deep_decoded_tvm_cells_round_trip_without_losing_fields(self):
        raw={'opcode':'transfer','secret':'fixture_private_value','address':'public_account'}
        for number in range(300):
            raw={'prev':raw,'index':number}
        tx=Transaction(chain='ton',tx_hash='a'*64,source='fixture',raw={'decoded':raw})
        report=AddressReport(target_address='0:'+'1'*64,transactions=[tx])
        dumped=json.loads(report.model_dump_json())
        current=dumped['transactions'][0]['raw']['decoded']
        for number in range(299,-1,-1):
            if current.get('_gansar_encoding')=='json_deep_provider_tail':
                current=json.loads(current['json'])
            self.assertEqual(current['index'],number)
            current=current['prev']
        self.assertEqual(current['opcode'],'transfer')
        self.assertEqual(current['secret'],'[REDACTED]')
        self.assertEqual(raw['prev']['index'],298)
        self.assertNotIn('fixture_private_value',report.model_dump_json())


class SearchProcessBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_blocked_export_process_is_stopped_with_original_partial_html(self):
        from app import search_runtime as runtime
        create=asyncio.create_subprocess_exec
        processes=[]
        # Genuine child/CPU sleep and genuine original exporter. Source data is
        # deliberately absent; no fixture response constitutes a live result.
        code='''import json,sys,time
from pathlib import Path
from app.models.report import AddressReport
from app.graph.builder import build_graph_payload
from app.exporters.html import export
from app.search_runtime import atomic_pickle
d=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
r=AddressReport(target_address=d["jobs"][0]["query"],warnings=["Fault-test partial checkpoint; no live observations"],coverage={"search_execution":{"status":"partial","data_complete":False}})
p=export(r,build_graph_payload(r),Path(d["jobs"][0]["output"]))
atomic_pickle(Path(d["session"])/"job_0.pickle",(r,p,None,False))
print(json.dumps({"job":0,"event":{"stage":"checkpoint.ready"}}),flush=True)
time.sleep(120)
'''
        async def start(*args,**kwargs):
            process=await create(args[0],'-B','-c',code,args[-1],**kwargs)
            processes.append(process)
            return process
        # This deliberately unresponsive fault child ignores cooperative stop.
        # Emergency termination is tested only after an explicit short grace;
        # production searches continue after first HTML for up to ten minutes.
        events=[]
        with tempfile.TemporaryDirectory() as directory, patch.object(runtime,'SEARCH_SECONDS',10), \
             patch.object(runtime,'WORKER_SECONDS',5), patch.object(runtime,'SHUTDOWN_GRACE_SECONDS',.3), patch.object(runtime.asyncio,'create_subprocess_exec',start):
            began=time.monotonic()
            result=(await runtime.run_bounded_jobs([{'query':'0:'+'1'*64,'output':directory}],
                progress=lambda index,event:events.append((index,event))))[0]
            self.assertLess(time.monotonic()-began,10)
            self.assertTrue(any(index==0 and event.get('stage')=='checkpoint.ready' for index,event in events))
            self.assertEqual(result['status'],'partial')
            self.assertTrue(Path(result['html']).exists())
            self.assertIn('Fault-test partial checkpoint',Path(result['html']).read_text(encoding='utf-8'))
            self.assertTrue(result['runtime']['worker_terminated'])
            self.assertTrue(all(p.returncode is not None for p in processes))

    async def test_cancelled_parent_reaps_the_blocked_worker(self):
        from app import search_runtime as runtime
        create=asyncio.create_subprocess_exec; processes=[]; started=asyncio.Event()
        async def start(*args,**kwargs):
            process=await create(args[0],'-c','import time; time.sleep(120)',**kwargs)
            processes.append(process);started.set();return process
        with tempfile.TemporaryDirectory() as directory, patch.object(runtime,'SHUTDOWN_GRACE_SECONDS',.3), patch.object(runtime.asyncio,'create_subprocess_exec',start):
            task=asyncio.create_task(runtime.run_bounded_jobs([{'query':'fixture','output':directory}]))
            await started.wait();task.cancel()
            with self.assertRaises(asyncio.CancelledError):await task
        self.assertTrue(all(p.returncode is not None for p in processes))
