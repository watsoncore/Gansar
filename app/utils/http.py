from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from collections import OrderedDict
from copy import deepcopy
import hashlib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json as jsonlib
import os
import random
import time
from typing import Any
import ipaddress
import socket
from urllib.parse import urlsplit, urljoin
from weakref import WeakKeyDictionary
from uuid import uuid4

import httpx
from app.utils.security import sanitize_observation, safe_public_url, validate_public_url

_JSON_CACHE: dict[str, tuple[float, Any]] = OrderedDict()
_TEXT_CACHE: dict[str, tuple[float, str]] = OrderedDict()
_INFLIGHT: dict[str, asyncio.Task] = {}
_WAITERS: WeakKeyDictionary = WeakKeyDictionary()
_CLIENTS: WeakKeyDictionary = WeakKeyDictionary()
_CLIENT_CONTEXTS: WeakKeyDictionary = WeakKeyDictionary()
_CACHE_TTL_SECONDS = 45.0
_TLS_VERIFY = os.getenv("GANSAR_VERIFY_TLS", "1").lower() not in {"0", "false", "no", "off"}
_TRUST_ENV = os.getenv("GANSAR_TRUST_ENV", "1").lower() not in {"0", "false", "no", "off"}
_RETRY_STATUS_CODES = {429, 500, 502, 503, 504}
_CACHE_MAX_ITEMS = 512
_LEASES: dict[int, int] = {}
_PENDING_CLOSE: set[int] = set()
# All native collectors, NFT requests, attribution probes and batch jobs share
# the same public-provider gate in this owned event loop. Cache hits and joined
# in-flight consumers never reach these transport hooks and consume no slot.
_TON_PUBLIC_HOSTS = frozenset({"tonapi.io", "toncenter.com"})
_TON_PUBLIC_INTERVAL_SECONDS = 1.0
_TON_RATE_LIMIT_DEFAULT_COOLDOWN = 5.0
_TON_HOST_GATES: WeakKeyDictionary = WeakKeyDictionary()
_REQUEST_SCOPE = ContextVar('gansar_optional_request_scope', default=None)
_REQUEST_DIAGNOSTICS = ContextVar('gansar_request_diagnostics', default=None)


@contextmanager
def request_diagnostics(ledger):
    """Transport counters scoped to one collector; never store URLs/credentials."""
    token = _REQUEST_DIAGNOSTICS.set(ledger)
    try:
        yield ledger
    finally:
        _REQUEST_DIAGNOSTICS.reset(token)


async def _diagnostic_request_hook(request):
    ledger = _REQUEST_DIAGNOSTICS.get()
    if ledger is not None:
        ledger['transport_attempts'] = ledger.get('transport_attempts', 0) + 1
        request.extensions['_gansar_diagnostic_started'] = time.monotonic()


async def _diagnostic_response_hook(response):
    ledger = _REQUEST_DIAGNOSTICS.get()
    if ledger is not None:
        status = str(response.status_code)
        statuses = ledger.setdefault('statuses', {})
        statuses[status] = statuses.get(status, 0) + 1
        elapsed = time.monotonic() - response.request.extensions.get('_gansar_diagnostic_started', time.monotonic())
        ledger['response_wait_seconds'] = ledger.get('response_wait_seconds', 0.0) + elapsed


class RequestBudgetExceeded(RuntimeError):
    """A scoped optional investigation has consumed its transport budget."""


@contextmanager
def bounded_request_scope(max_requests: int):
    """Count actual transport attempts, including retries/redirects; cache hits free.

    Context-local to the optional planner. Other investigations and main target
    collectors retain their existing transport policy. Children share one ledger.
    """
    ledger={'limit':max(0,int(max_requests)), 'attempts':0, 'hosts':{}, 'statuses':{}}
    token=_REQUEST_SCOPE.set(ledger)
    try:yield ledger
    finally:_REQUEST_SCOPE.reset(token)


async def _scoped_request_hook(request):
    ledger=_REQUEST_SCOPE.get()
    if ledger is None:return
    if ledger['attempts']>=ledger['limit']:raise RequestBudgetExceeded('Optional investigation request budget reached')
    ledger['attempts']+=1
    host=request.url.host
    ledger['hosts'][host]=ledger['hosts'].get(host,0)+1


async def _scoped_response_hook(response):
    ledger=_REQUEST_SCOPE.get()
    if ledger is not None:
        status=str(response.status_code)
        ledger['statuses'][status]=ledger['statuses'].get(status,0)+1


def _ton_host_state(url):
    host = (url.host if isinstance(url, httpx.URL) else urlsplit(str(url)).hostname or "").lower().rstrip(".")
    if host not in _TON_PUBLIC_HOSTS:
        return None
    gates = _TON_HOST_GATES.setdefault(asyncio.get_running_loop(), {})
    return gates.setdefault(host, {"lock": asyncio.Lock(), "last_started": float("-inf"),
        "cooldown_until": float("-inf"), "attempts": 0, "rate_limited_responses": 0,
        "wait_seconds": 0.0})


async def _ton_request_hook(request: httpx.Request) -> None:
    state = _ton_host_state(request.url)
    if state is None:
        return
    # asyncio.Lock is FIFO. Waiting remains cancellation-aware. Response hooks
    # update cooldown synchronously, including while this lock's owner sleeps,
    # so the wait is rechecked before reserving an actual transport attempt.
    async with state["lock"]:
        while True:
            now = time.monotonic()
            ready = max(state["last_started"] + _TON_PUBLIC_INTERVAL_SECONDS, state["cooldown_until"])
            delay = ready-now
            if delay <= 0:
                break
            before = time.monotonic()
            await asyncio.sleep(delay)
            state["wait_seconds"] += time.monotonic()-before
        state["last_started"] = time.monotonic()
        state["attempts"] += 1


async def _ton_response_hook(response: httpx.Response) -> None:
    state = _ton_host_state(response.request.url)
    if state is None or response.status_code != 429:
        return
    delay = _retry_after_seconds(response)
    if delay is None:
        delay = _TON_RATE_LIMIT_DEFAULT_COOLDOWN
    # A provider Retry-After is not shortened to the generic retry cap. The
    # owning collection/session deadline can cancel a long wait and save cursors.
    state["cooldown_until"] = max(state["cooldown_until"], time.monotonic()+delay)
    state["rate_limited_responses"] += 1


def _ensure_ton_transport_hooks(client: httpx.AsyncClient) -> httpx.AsyncClient:
    for kind, hook in (("request", _ton_request_hook), ("response", _ton_response_hook),
                       ("request", _scoped_request_hook), ("response", _scoped_response_hook),
                       ("request", _diagnostic_request_hook), ("response", _diagnostic_response_hook)):
        hooks = client.event_hooks.setdefault(kind, [])
        if hook not in hooks:
            if hook is _scoped_request_hook:hooks.append(hook)
            else:hooks.insert(0, hook)
    return client


def ton_public_rate_metrics() -> dict:
    """Public aggregate counters only: never addresses, headers or API keys."""
    gates = _TON_HOST_GATES.get(asyncio.get_running_loop(), {})
    now = time.monotonic()
    return {host: {"attempts": state["attempts"], "rate_limited_responses": state["rate_limited_responses"],
        "wait_seconds": round(state["wait_seconds"], 3),
        "cooldown_remaining_seconds": max(0.0, state["cooldown_until"]-now),
        "minimum_attempt_interval_seconds": _TON_PUBLIC_INTERVAL_SECONDS} for host, state in gates.items()}


def _retry_after_seconds(response: httpx.Response | None) -> float | None:
    if response is None:
        return None
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    raw = raw.strip()
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(raw)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
    except Exception:
        return None


def retry_delay(response: httpx.Response | None, attempt: int, retry_backoff: float, cap: float = 5.0) -> float:
    retry_after = _retry_after_seconds(response)
    if retry_after is not None:
        base = min(cap, retry_after)
    else:
        base = min(cap, retry_backoff * (2**attempt))
    return base + random.uniform(0.05, 0.25)


def http_error_message(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"http {exc.response.status_code}"
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    return sanitize_observation(str(exc) or type(exc).__name__)


def build_headers() -> dict[str, str]:
    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    ]
    return {
        "User-Agent": random.choice(uas),
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }


def create_async_client(timeout_seconds: float) -> httpx.AsyncClient:
    timeout = httpx.Timeout(
        timeout_seconds,
        connect=min(6.0, max(2.5, timeout_seconds)),
        read=timeout_seconds,
        write=min(4.0, max(2.0, timeout_seconds)),
        pool=min(2.0, max(1.0, timeout_seconds)),
    )
    return _ensure_ton_transport_hooks(httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers=build_headers(),
        limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
        trust_env=_TRUST_ENV,
        verify=_TLS_VERIFY,
    ))


def get_shared_client(timeout_seconds: float) -> httpx.AsyncClient:
    loop = asyncio.get_running_loop()
    clients = _CLIENTS.setdefault(loop, {})
    key = round(float(timeout_seconds), 2)
    client = clients.get(key)
    if client is None or client.is_closed:
        client = _ensure_ton_transport_hooks(create_async_client(timeout_seconds))
        clients[key] = client
    return client


@asynccontextmanager
async def shared_async_client(timeout_seconds: float):
    client = get_shared_client(timeout_seconds)
    _LEASES[id(client)] = _LEASES.get(id(client), 0) + 1
    try:
        yield client
    finally:
        await _release_client(client)


async def _release_client(client: httpx.AsyncClient) -> None:
    key = id(client)
    _LEASES[key] = max(0, _LEASES.get(key, 1) - 1)
    if _LEASES[key] == 0:
        _LEASES.pop(key, None)
        if key in _PENDING_CLOSE:
            _PENDING_CLOSE.discard(key)
            if not client.is_closed:
                await client.aclose()


async def close_shared_clients() -> None:
    """Finish abandoned loaders without interrupting other investigations.

    A cancelled source detaches from a coalesced request. Its loader owns a
    client lease until it finishes, so simply closing idle clients leaves that
    task for asyncio.run shutdown. Explicitly cancel and await only loaders
    with no remaining waiters before releasing the clients.
    """
    loop = asyncio.get_running_loop()
    orphaned = [(key, task) for key, task in list(_INFLIGHT.items())
                if task.get_loop() is loop and not task.done() and not _WAITERS.get(task, 0)]
    for key, task in orphaned:
        # A later request must start a new loader rather than join one that is
        # being cancelled. No await separates this check from cancellation.
        if _INFLIGHT.get(key) is task:
            _INFLIGHT.pop(key, None)
        task.cancel()
    if orphaned:
        # These tasks have no consumer. Active waiters still receive their
        # original result/error through _coalesced; cleanup retrieves only
        # abandoned transport/cancellation failures before loop shutdown.
        await asyncio.gather(*(task for _, task in orphaned), return_exceptions=True)
    clients = _CLIENTS.get(loop, {})
    for client in list(clients.values()):
        if _LEASES.get(id(client), 0):
            _PENDING_CLOSE.add(id(client))
            continue
        if not client.is_closed:
            await client.aclose()
    # Active leases remain visible to other investigations until they finish.
    for key, client in list(clients.items()):
        if client.is_closed:
            clients.pop(key, None)


def _request_key(method: str, url: str, params: dict | None, json: Any | None, data: Any | None, *, client: httpx.AsyncClient | None = None, headers: dict | None = None) -> str:
    effective_headers = dict(client.headers) if client is not None else {}
    effective_headers.update({str(k).lower(): v for k, v in (headers or {}).items()})
    encoded = jsonlib.dumps(
        {"loop": id(asyncio.get_running_loop()), "context": _CLIENT_CONTEXTS.setdefault(client, uuid4().hex) if client is not None else None, "method": method.upper(), "url": url, "params": params, "json": json, "data": data, "headers": effective_headers, "cookies": str(client.cookies) if client is not None else None},
        sort_keys=True,
        default=str,
    )
    # Never retain authentication values or URL API keys in cache identifiers.
    return hashlib.sha256(encoded.encode()).hexdigest()


def _cache_get(cache: dict, key: str, ttl: float = _CACHE_TTL_SECONDS) -> Any:
    now = time.monotonic()
    for expired in [k for k, (created, _) in cache.items() if now - created > _CACHE_TTL_SECONDS]:
        cache.pop(expired, None)
    cached = cache.get(key)
    return deepcopy(cached[1]) if cached is not None and now - cached[0] <= ttl else None


def _cache_put(cache: dict, key: str, payload: Any) -> None:
    cache[key] = (time.monotonic(), deepcopy(payload))
    while len(cache) > _CACHE_MAX_ITEMS:
        cache.pop(next(iter(cache)))


async def _coalesced(key: str, client: httpx.AsyncClient, loader) -> Any:
    task = _INFLIGHT.get(key)
    if task is None:
        _LEASES[id(client)] = _LEASES.get(id(client), 0) + 1
        async def run():
            try:
                return await loader()
            finally:
                await _release_client(client)
        task = asyncio.create_task(run())
        _INFLIGHT[key] = task
        def finished(done):
            if _INFLIGHT.get(key) is done:
                _INFLIGHT.pop(key, None)
            _WAITERS.pop(done, None)
            if not done.cancelled():
                done.exception()  # Retrieve detached failures after caller cancellation.
        task.add_done_callback(finished)
    # wait() detaches a cancelled caller without cancelling the shared loader.
    # Python 3.14 shield() explicitly logs later failures of cancelled waiters,
    # even though finished() has already retrieved that detached exception.
    _WAITERS[task] = _WAITERS.get(task, 0) + 1
    try:
        await asyncio.wait({task})
        return deepcopy(task.result())
    finally:
        remaining = _WAITERS.get(task, 1) - 1
        if remaining > 0:
            _WAITERS[task] = remaining
        else:
            _WAITERS.pop(task, None)


async def request_json(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    params: dict | None = None,
    json: Any | None = None,
    data: Any | None = None,
    headers: dict[str, str] | None = None,
    retries: int = 2,
    retry_backoff: float = 0.7,
    cache_ttl: float | None = None,
) -> Any:
    _ensure_ton_transport_hooks(client)
    diagnostics = _REQUEST_DIAGNOSTICS.get()
    if diagnostics is not None:
        diagnostics['logical_requests'] = diagnostics.get('logical_requests', 0) + 1
    cache_key = _request_key(method, url, params, json, data, client=client, headers=headers)
    bypass_cache = cache_ttl == 0 or any(str(k).lower() == "cache-control" and "no-cache" in str(v).lower() for k, v in (headers or {}).items())
    from app.utils import public_history_cache
    public_key = None if bypass_cache or data is not None or client.cookies else public_history_cache.key_for(method, url, params, json,
        {**dict(client.headers), **(headers or {})})
    public_cached = public_history_cache.get(public_key, _CACHE_TTL_SECONDS if cache_ttl is None else cache_ttl)
    if public_cached is not None:
        if diagnostics is not None:
            diagnostics['cache_hits'] = diagnostics.get('cache_hits', 0) + 1
        return public_cached
    cached = None if bypass_cache else _cache_get(_JSON_CACHE, cache_key, _CACHE_TTL_SECONDS if cache_ttl is None else cache_ttl)
    if cached is not None:
        if diagnostics is not None:
            diagnostics['cache_hits'] = diagnostics.get('cache_hits', 0) + 1
        return cached
    inflight_key = f"json:{cache_key}"
    if bypass_cache:
        inflight_key += f":refresh:{time.monotonic_ns()}"

    async def load() -> Any:
        for i in range(retries + 1):
            try:
                r = await client.request(method, url, params=params, json=json, data=data, headers=headers)
                if r.status_code in _RETRY_STATUS_CODES and i < retries and not asyncio.current_task().cancelling():
                    await asyncio.sleep(retry_delay(r, i, retry_backoff))
                    continue
                r.raise_for_status()
                payload = r.json()
                if not bypass_cache:
                    _cache_put(_JSON_CACHE, cache_key, payload)
                    public_history_cache.put(public_key, payload)
                return payload
            except Exception:
                # A transport may translate CancelledError into ConnectTimeout.
                # Finalizing an orphan must not restart its abandoned request.
                if i < retries and not asyncio.current_task().cancelling():
                    await asyncio.sleep(retry_delay(None, i, retry_backoff))
                    continue
                raise

    if bypass_cache:
        # A fresh request has a unique key and cannot have shared consumers.
        # Keep its existing client lease, but own its transport in this caller
        # so a request deadline cancels it before any retry starts.
        _LEASES[id(client)] = _LEASES.get(id(client), 0) + 1
        try:
            return deepcopy(await load())
        finally:
            await _release_client(client)
    return await _coalesced(inflight_key, client, load)


async def request_text(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    params: dict | None = None,
    data: Any | None = None,
    headers: dict[str, str] | None = None,
    retries: int = 1,
    retry_backoff: float = 0.5,
    cache_ttl: float | None = None,
) -> str:
    _ensure_ton_transport_hooks(client)
    cache_key = _request_key(method, url, params, None, data, client=client, headers=headers)
    bypass_cache = cache_ttl == 0 or any(str(k).lower() == "cache-control" and "no-cache" in str(v).lower() for k, v in (headers or {}).items())
    cached = None if bypass_cache else _cache_get(_TEXT_CACHE, cache_key, _CACHE_TTL_SECONDS if cache_ttl is None else cache_ttl)
    if cached is not None:
        return cached
    inflight_key = f"text:{cache_key}"
    if bypass_cache:
        inflight_key += f":refresh:{time.monotonic_ns()}"

    async def load() -> str:
        for i in range(retries + 1):
            try:
                r = await client.request(method, url, params=params, data=data, headers=headers)
                if r.status_code in _RETRY_STATUS_CODES and i < retries and not asyncio.current_task().cancelling():
                    await asyncio.sleep(retry_delay(r, i, retry_backoff))
                    continue
                r.raise_for_status()
                payload = r.text
                if not bypass_cache:
                    _cache_put(_TEXT_CACHE, cache_key, payload)
                return payload
            except Exception:
                if i < retries and not asyncio.current_task().cancelling():
                    await asyncio.sleep(retry_delay(None, i, retry_backoff))
                    continue
                raise

    if bypass_cache:
        # A fresh request has a unique key and cannot have shared consumers.
        # Keep its existing client lease, but own its transport in this caller
        # so a request deadline cancels it before any retry starts.
        _LEASES[id(client)] = _LEASES.get(id(client), 0) + 1
        try:
            return deepcopy(await load())
        finally:
            await _release_client(client)
    return await _coalesced(inflight_key, client, load)


async def request_public_json(client: httpx.AsyncClient, url: str, *, max_bytes: int = 2_000_000, max_redirects: int = 4, https_only: bool = False) -> Any:
    """Bounded external metadata fetch; validate every redirect and DNS answer."""
    for _ in range(max_redirects + 1):
        url = await validate_public_url(url)
        parts = urlsplit(url)
        if https_only and parts.scheme.lower() != "https":
            raise ValueError("metadata URL and redirects must use HTTPS")
        resolved = await asyncio.get_running_loop().getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM)
        if not resolved or any(not ipaddress.ip_address(item[4][0]).is_global for item in resolved):
            raise ValueError("metadata host resolved to a non-public address")
        # Pin the checked IP for this connection to prevent DNS rebinding between
        # validation and transport resolution. Keep original HTTP Host and TLS SNI.
        pinned_url = httpx.URL(url).copy_with(host=resolved[0][4][0])
        host_header = parts.netloc
        async with client.stream("GET", pinned_url, headers={"Host": host_header}, extensions={"sni_hostname": parts.hostname}, follow_redirects=False) as response:
            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    raise ValueError("metadata redirect missing Location")
                url = urljoin(url, location)
                continue
            response.raise_for_status()
            chunks = bytearray()
            async for chunk in response.aiter_bytes():
                chunks.extend(chunk)
                if len(chunks) > max_bytes:
                    raise ValueError("metadata exceeds response size limit")
            return jsonlib.loads(chunks)
    raise ValueError("metadata redirect limit exceeded")


async def fetch_json(timeout_seconds: float, url: str, *, params: dict | None = None, retries: int = 1) -> Any:
    return await request_json(get_shared_client(timeout_seconds), "GET", url, params=params, retries=retries)


async def fetch_text(timeout_seconds: float, url: str, *, params: dict | None = None, retries: int = 1) -> str:
    return await request_text(get_shared_client(timeout_seconds), "GET", url, params=params, retries=retries)


def json_object(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def json_list(value: Any) -> list:
    return value if isinstance(value, list) else []


