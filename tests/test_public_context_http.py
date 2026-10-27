"""Bounded public-context transport controls, separate from live captures."""
import asyncio
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock,patch
import socket

import httpx
from app.sources import public_context_http as http

class PublicContextTransportTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        http._CACHE.clear();http._GATES.clear()
        self.dns=patch.object(asyncio.get_running_loop(),'getaddrinfo',new=AsyncMock(return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443))]))
        self.public=patch.object(http,'validate_public_url',new=AsyncMock(side_effect=lambda url:url))
        self.dns.start();self.public.start();self.addCleanup(self.dns.stop);self.addCleanup(self.public.stop)

    async def test_success_is_copied_cached_and_preserves_observation_time(self):
        seen=[]
        def respond(request):
            seen.append(request);return httpx.Response(200,json={'data':{'items':[1,2]}})
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond))as client:
            first,a=await http.public_json(client,'GET','https://example.com/api',with_metadata=True,user_agent='Gansar-test')
            first['data']['items'].append(3)
            second,b=await http.public_json(client,'GET','https://example.com/api',with_metadata=True,user_agent='Gansar-test')
        self.assertEqual(len(seen),1);self.assertEqual(second['data']['items'],[1,2]);self.assertTrue(b['cache_hit'])
        self.assertEqual(a['retrieved_at'],b['retrieved_at']);self.assertEqual(b['transport_requests'],0)
        self.assertEqual(seen[0].url.host,'8.8.8.8');self.assertEqual(seen[0].headers['Host'],'example.com')
        self.assertEqual(seen[0].headers['User-Agent'],'Gansar-test')

    async def test_429_respects_long_retry_after_without_second_request(self):
        calls=[]
        def respond(request):calls.append(request);return httpx.Response(429,headers={'Retry-After':'3600'})
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond))as client:
            with self.assertRaises(httpx.HTTPStatusError):await http.public_json(client,'GET','https://example.com/api')
            with self.assertRaises(httpx.HTTPStatusError):await http.public_json(client,'GET','https://example.com/other')
        self.assertEqual(len(calls),1)
        state=http._GATES[asyncio.get_running_loop()]['example.com']
        self.assertGreater(state['until']-http.time.monotonic(),3500)

    async def test_graphql_errors_are_not_cached(self):
        calls=[]
        def respond(request):calls.append(request);return httpx.Response(200,json={'data':None,'errors':[{'message':'unit error'}]})
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond))as client:
            await http.public_json(client,'POST','https://example.com/graphql',json={'query':'unit'})
            await http.public_json(client,'POST','https://example.com/graphql',json={'query':'unit'})
        self.assertEqual(len(calls),2);self.assertFalse(http._CACHE)

    async def test_oversized_decoded_body_and_redirect_are_rejected(self):
        for code,kwargs in [(200,{'content':b'x'*500}),(302,{'headers':{'Location':'https://other.example.com'}})]:
            http._GATES.clear()
            async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request:httpx.Response(code,**kwargs)))as client:
                with self.assertRaises(ValueError):await http.public_json(client,'GET','https://example.com/api',max_bytes=100)

    async def test_unsafe_url_and_private_dns_never_reach_transport(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _:self.fail('network attempted')))as client:
            with self.assertRaises(ValueError):await http.public_json(client,'GET','http://example.com/api')
            with self.assertRaises(ValueError):await http.public_json(client,'GET','https://127.0.0.1/api')
            with patch.object(asyncio.get_running_loop(),'getaddrinfo',new=AsyncMock(return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))])):
                with self.assertRaises(ValueError):await http.public_json(client,'GET','https://example.com/api')
