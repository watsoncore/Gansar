from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch
import httpx

from app.utils import http
from app.utils.security import validate_public_url


class HttpIntegrityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        http._JSON_CACHE.clear()
        http._TEXT_CACHE.clear()

    async def test_tls_default_enabled(self):
        self.assertTrue(http._TLS_VERIFY)

    async def test_auth_cache_isolation_and_defensive_copy(self):
        calls = []
        async def handler(request):
            calls.append(request.headers.get("authorization"))
            return httpx.Response(200, json={"auth": calls[-1], "nested": {"value": 1}})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            first = await http.request_json(client, "GET", "https://example.org/a", headers={"Authorization": "fixture_a"})
            first["nested"]["value"] = 999
            again = await http.request_json(client, "GET", "https://example.org/a", headers={"Authorization": "fixture_a"})
            second = await http.request_json(client, "GET", "https://example.org/a", headers={"Authorization": "fixture_b"})
        self.assertEqual(again["nested"]["value"], 1)
        self.assertEqual(second["auth"], "fixture_b")
        self.assertEqual(len(calls), 2)
        self.assertNotIn("fixture_a", str(list(http._JSON_CACHE)))

    async def test_cancelled_waiter_does_not_cancel_shared_request(self):
        started, release = asyncio.Event(), asyncio.Event()
        count = 0
        async def handler(request):
            nonlocal count
            count += 1
            started.set()
            await release.wait()
            return httpx.Response(200, json={"ok": True})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            first = asyncio.create_task(http.request_json(client, "GET", "https://example.org/a"))
            await started.wait()
            second = asyncio.create_task(http.request_json(client, "GET", "https://example.org/a"))
            await asyncio.sleep(0)
            first.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await first
            release.set()
            self.assertEqual(await second, {"ok": True})
        self.assertEqual(count, 1)

    async def test_detached_http_failure_after_caller_cancellation_has_no_loop_traceback(self):
        started, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
        contexts = []
        loop = asyncio.get_running_loop()
        previous_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda _loop, context: contexts.append(context))

        async def handler(request):
            started.set()
            await release.wait()
            raise httpx.ConnectTimeout("fixture detached timeout", request=request)

        try:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                caller = asyncio.create_task(http.request_json(client, "GET", "https://example.org/detached", retries=0))
                await started.wait()
                loader = next(task for task in http._INFLIGHT.values() if task.get_loop() is loop)
                loader.add_done_callback(lambda _task: finished.set())
                caller.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await caller
                self.assertFalse(loader.cancelled())
                release.set()
                await finished.wait()
                await asyncio.sleep(0)
                self.assertEqual(contexts, [])
                self.assertNotIn(loader, http._INFLIGHT.values())
                self.assertNotIn(id(client), http._LEASES)
        finally:
            loop.set_exception_handler(previous_handler)

    async def test_remaining_waiter_receives_shared_http_error_after_other_cancellation(self):
        started, release = asyncio.Event(), asyncio.Event()
        count = 0
        contexts = []
        failure = httpx.ConnectTimeout("fixture active timeout")
        loop = asyncio.get_running_loop()
        previous_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda _loop, context: contexts.append(context))

        async def handler(request):
            nonlocal count
            count += 1
            started.set()
            await release.wait()
            raise failure

        try:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                first = asyncio.create_task(http.request_json(client, "GET", "https://example.org/shared-error", retries=0))
                await started.wait()
                second = asyncio.create_task(http.request_json(client, "GET", "https://example.org/shared-error", retries=0))
                await asyncio.sleep(0)
                first.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await first
                # Finalizing another investigation must preserve this waiter
                # and the exact transport error it will receive.
                await http.close_shared_clients()
                release.set()
                with self.assertRaises(httpx.ConnectTimeout) as caught:
                    await second
                self.assertIs(caught.exception, failure)
                await asyncio.sleep(0)
                self.assertEqual(contexts, [])
                self.assertEqual(count, 1)
        finally:
            loop.set_exception_handler(previous_handler)

    async def test_finalization_drains_orphan_loader_then_closes_its_client(self):
        started, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def handler(request):
            started.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                # Transports may translate cancellation during connect while
                # unwinding their native timeout scope.
                raise httpx.ConnectTimeout("fixture detached lease timeout", request=request)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

        async def caller_request():
            async with http.shared_async_client(11) as leased:
                return await http.request_json(leased, "GET", "https://example.org/lease-error", retries=0)

        with patch.object(http, "create_async_client", return_value=client):
            caller = asyncio.create_task(caller_request())
            await started.wait()
            loop = asyncio.get_running_loop()
            loader = next(task for task in http._INFLIGHT.values() if task.get_loop() is loop)
            loader.add_done_callback(lambda _task: finished.set())
            caller.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await caller
            self.assertFalse(client.is_closed)
            self.assertEqual(http._LEASES[id(client)], 1)
            await http.close_shared_clients()
            await finished.wait()
            self.assertTrue(loader.done())
            self.assertIsInstance(loader.exception(), httpx.ConnectTimeout)
            self.assertTrue(client.is_closed)
            self.assertNotIn(id(client), http._LEASES)
            self.assertNotIn(id(client), http._PENDING_CLOSE)

    async def test_parallel_client_lease_prevents_close(self):
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
        with patch.object(http, "create_async_client", return_value=client):
            async with http.shared_async_client(9):
                await http.close_shared_clients()
                self.assertFalse(client.is_closed)
        self.assertTrue(client.is_closed)

    async def test_orphan_cancellation_does_not_retry_translated_transport_timeout(self):
        for request_method in (http.request_json, http.request_text):
            with self.subTest(request_method=request_method.__name__):
                started = asyncio.Event()
                calls = 0
                async def handler(request):
                    nonlocal calls
                    calls += 1
                    started.set()
                    try:
                        await asyncio.Future()
                    except asyncio.CancelledError:
                        raise httpx.ConnectTimeout("fixture translated cancellation", request=request)

                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    with patch.object(http, "retry_delay", return_value=60):
                        waiter = asyncio.create_task(request_method(client, "GET", "https://example.org/cancel-retry", retries=2))
                        await started.wait()
                        waiter.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await waiter
                        await asyncio.wait_for(http.close_shared_clients(), timeout=1)
                self.assertEqual(calls, 1)

    async def test_active_request_still_retries_transport_timeout(self):
        for request_method in (http.request_json, http.request_text):
            with self.subTest(request_method=request_method.__name__):
                calls = 0
                async def handler(request):
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        raise httpx.ConnectTimeout("fixture genuine transient timeout", request=request)
                    return httpx.Response(200, json={"ok": True})

                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    with patch.object(http, "retry_delay", return_value=0):
                        result = await request_method(client, "GET", "https://example.org/active-retry", retries=1)
                self.assertTrue(result)
                self.assertEqual(calls, 2)

    async def test_no_cache_refreshes_state(self):
        count = 0
        def handler(request):
            nonlocal count
            count += 1
            return httpx.Response(200, json={"revision": count})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await http.request_json(client, "GET", "https://example.org/a")
            refresh = await http.request_json(client, "GET", "https://example.org/a", cache_ttl=0)
            header_refresh = await http.request_json(client, "GET", "https://example.org/a", headers={"Cache-Control": "no-cache"})
        self.assertEqual(refresh["revision"], 2)
        self.assertEqual(header_refresh["revision"], 3)

    async def test_private_dns_rejected(self):
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", AsyncMock(return_value=[(2, 1, 6, "", ("127.0.0.1", 443))])):
            with self.assertRaises(ValueError):
                await validate_public_url("https://example.org/metadata")

    async def test_redirect_to_private_host_rejected(self):
        calls = []
        def handler(request):
            calls.append(str(request.url))
            return httpx.Response(302, headers={"Location": "http://127.0.0.1/private"})
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", AsyncMock(return_value=[(2, 1, 6, "", ("8.8.8.8", 443))])):
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                with self.assertRaises(ValueError):
                    await http.request_public_json(client, "https://example.org/metadata")
        self.assertEqual(len(calls), 1)

    async def test_metadata_size_limit(self):
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", AsyncMock(return_value=[(2, 1, 6, "", ("8.8.8.8", 443))])):
            async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 100))) as client:
                with self.assertRaises(ValueError):
                    await http.request_public_json(client, "https://example.org/metadata", max_bytes=10)


class HttpRunnerShutdownTests(unittest.TestCase):
    def test_cancel_to_timeout_orphan_is_finished_before_real_runner_shutdown(self):
        """A retrieved exception alone cannot silence Runner's explicit report."""
        contexts = []
        state = {}

        async def operation():
            loop = asyncio.get_running_loop()
            loop.set_exception_handler(lambda _loop, context: contexts.append(context))
            started = asyncio.Event()

            async def handler(request):
                started.set()
                try:
                    await asyncio.Future()
                except asyncio.CancelledError:
                    raise httpx.ConnectTimeout("fixture shutdown connect timeout", request=request)

            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            state["client"] = client

            async def request():
                async with http.shared_async_client(11) as leased:
                    return await http.request_json(leased, "GET", "https://example.org/runner-close", retries=0)

            with patch.object(http, "create_async_client", return_value=client):
                waiter = asyncio.create_task(request())
                await started.wait()
                state["loader"] = next(task for task in http._INFLIGHT.values() if task.get_loop() is loop)
                waiter.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await waiter
                await http.close_shared_clients()
                state["finished_before_shutdown"] = state["loader"].done()

        # This calls the real asyncio.Runner shutdown, not a simulated callback.
        with asyncio.Runner() as runner:
            runner.run(operation())
        self.assertEqual(contexts, [])
        self.assertTrue(state["finished_before_shutdown"])
        self.assertTrue(state["client"].is_closed)
        self.assertIsInstance(state["loader"].exception(), httpx.ConnectTimeout)
        self.assertNotIn(state["loader"], http._INFLIGHT.values())


if __name__ == "__main__":
    unittest.main()
