"""Scoped transport budgets preserve main collection policy and real attempts."""
import asyncio
import unittest
import httpx
from app.utils.http import bounded_request_scope,RequestBudgetExceeded,_ensure_ton_transport_hooks

class RequestBudgetTests(unittest.IsolatedAsyncioTestCase):
    async def test_parallel_children_share_transport_attempt_limit(self):
        attempts=[]
        async def handler(request):
            attempts.append(str(request.url));return httpx.Response(200,json={'ok':True})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            _ensure_ton_transport_hooks(client)
            with bounded_request_scope(3) as ledger:
                results=await asyncio.gather(*(client.get('https://example.org/'+str(i)) for i in range(8)),return_exceptions=True)
            self.assertEqual(len(attempts),3)
            self.assertEqual(ledger['attempts'],3)
            self.assertEqual(ledger['statuses'],{'200':3})
            self.assertEqual(sum(isinstance(r,RequestBudgetExceeded) for r in results),5)
            await client.get('https://example.org/main')
            self.assertEqual(len(attempts),4)

    async def test_redirects_consume_attempts_and_scope_resets_after_error(self):
        async def handler(request):return httpx.Response(302,headers={'location':'/next'})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler),follow_redirects=True) as client:
            _ensure_ton_transport_hooks(client)
            with self.assertRaises(RequestBudgetExceeded):
                with bounded_request_scope(2) as ledger:await client.get('https://example.org/start')
            self.assertEqual(ledger['attempts'],2)
            self.assertEqual(ledger['statuses'],{'302':2})
            with bounded_request_scope(0) as empty:
                with self.assertRaises(RequestBudgetExceeded):await client.get('https://example.org/no')
            self.assertEqual(empty['attempts'],0)

    async def test_concurrent_unscoped_main_task_has_independent_policy(self):
        async def handler(request):return httpx.Response(429)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            _ensure_ton_transport_hooks(client)
            async def optional():
                with bounded_request_scope(1) as ledger:
                    await client.get('https://example.org/optional')
                    with self.assertRaises(RequestBudgetExceeded):await client.get('https://example.org/blocked')
                return ledger
            ledger,_=await asyncio.gather(optional(),client.get('https://example.org/main'))
            self.assertEqual(ledger['attempts'],1)
            self.assertEqual(ledger['statuses'],{'429':1})

if __name__=='__main__':unittest.main()
