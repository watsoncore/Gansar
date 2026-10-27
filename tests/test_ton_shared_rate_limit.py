"""Actual HTTPX transport timing with synthetic responses, never live evidence."""
import asyncio
from datetime import datetime,timedelta,timezone
from email.utils import format_datetime
import time
import unittest
from unittest.mock import patch
import httpx

from app.utils import http


class TonSharedRateLimitTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await http.close_shared_clients()

    async def test_native_and_nft_and_batch_clients_share_host_attempt_spacing(self):
        attempts=[];measurement=[]
        async def transport(request):
            attempts.append((request.url.path,time.monotonic()))
            return httpx.Response(200,json={"ok":True})
        async def observed(request):measurement.append(time.monotonic())
        with patch.object(http,"_TON_PUBLIC_INTERVAL_SECONDS",.04):
            clients=[httpx.AsyncClient(transport=httpx.MockTransport(transport),event_hooks={"request":[observed]}) for _ in range(3)]
            try:
                for client in clients:http._ensure_ton_transport_hooks(client)
                await asyncio.gather(clients[0].get("https://tonapi.io/v2/native"),
                    http.request_json(clients[1],"GET","https://tonapi.io/v2/nft",retries=0,cache_ttl=0),
                    http.request_json(clients[2],"GET","https://tonapi.io/v2/batch",retries=0,cache_ttl=0))
                self.assertEqual(len(attempts),3)
                self.assertTrue(all(second[1]-first[1] >= .035 for first,second in zip(attempts,attempts[1:])))
                self.assertTrue(all(b-a >= .035 for a,b in zip(measurement,measurement[1:])))
                metrics=http.ton_public_rate_metrics()["tonapi.io"]
                self.assertEqual(metrics["attempts"],3)
            finally:
                await asyncio.gather(*(client.aclose() for client in clients))

    async def test_rate_limit_cooldown_from_one_client_holds_other_clients(self):
        attempts=[]
        async def transport(request):
            attempts.append(time.monotonic())
            return httpx.Response(429 if len(attempts)==1 else 200,
                headers={"Retry-After":".16"},json={"sequence":len(attempts)})
        with patch.object(http,"_TON_PUBLIC_INTERVAL_SECONDS",.02):
            async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as native, httpx.AsyncClient(transport=httpx.MockTransport(transport)) as nft:
                http._ensure_ton_transport_hooks(native)
                response=await native.get("https://toncenter.com/api/v3/native")
                self.assertEqual(response.status_code,429)
                await http.request_json(nft,"GET","https://toncenter.com/api/v3/nft",retries=0,cache_ttl=0)
                self.assertGreaterEqual(attempts[1]-attempts[0],.15)
                metrics=http.ton_public_rate_metrics()["toncenter.com"]
                self.assertEqual(metrics["rate_limited_responses"],1)
                self.assertEqual(metrics["attempts"],2)

    async def test_cached_result_never_reserves_a_transport_slot(self):
        calls=[]
        async def transport(request):
            calls.append(time.monotonic())
            return httpx.Response(200,json={"sequence":len(calls)})
        with patch.object(http,"_TON_PUBLIC_INTERVAL_SECONDS",.02):
            async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
                first=await http.request_json(client,"GET","https://tonapi.io/v2/nfts/cache-fixture",retries=0)
                second=await http.request_json(client,"GET","https://tonapi.io/v2/nfts/cache-fixture",retries=0)
                self.assertEqual(first,second)
                self.assertEqual(len(calls),1)
                self.assertEqual(http.ton_public_rate_metrics()["tonapi.io"]["attempts"],1)

    async def test_cancelled_waiter_consumes_no_slot_and_other_host_can_progress(self):
        attempts=[]
        async def transport(request):
            attempts.append((request.url.host,time.monotonic()))
            return httpx.Response(200,json={})
        with patch.object(http,"_TON_PUBLIC_INTERVAL_SECONDS",.2):
            async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
                http._ensure_ton_transport_hooks(client)
                await client.get("https://tonapi.io/v2/first")
                pending=asyncio.create_task(client.get("https://tonapi.io/v2/cancel"))
                await asyncio.sleep(.025)
                pending.cancel()
                with self.assertRaises(asyncio.CancelledError):await pending
                before=time.monotonic()
                await client.get("https://toncenter.com/api/v3/other")
                self.assertLess(time.monotonic()-before,.15)
                self.assertEqual(http.ton_public_rate_metrics()["tonapi.io"]["attempts"],1)
                self.assertEqual(len(attempts),2)

    async def test_http_date_retry_after_and_unconfigured_host_preserve_scope(self):
        request=httpx.Request("GET","https://tonapi.io/v2/a")
        date=format_datetime(datetime.now(timezone.utc)+timedelta(seconds=10),usegmt=True)
        await http._ton_response_hook(httpx.Response(429,request=request,headers={"Retry-After":date}))
        self.assertGreater(http.ton_public_rate_metrics()["tonapi.io"]["cooldown_remaining_seconds"],8)
        await http._ton_request_hook(httpx.Request("GET","https://example.org/not-a-ton-api"))
        self.assertNotIn("example.org",http.ton_public_rate_metrics())
        with patch.object(http,"_TON_PUBLIC_INTERVAL_SECONDS",.01):
            self.assertEqual(http.retry_delay(httpx.Response(429,headers={"Retry-After":"100"}),0,.1,cap=5)//1,5)
        # Generic retry backoff may remain capped; the shared transport cooldown
        # keeps the complete Retry-After independently and is never truncated.
