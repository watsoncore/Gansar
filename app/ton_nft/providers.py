"""Public, read-only provider adapters. No metadata URI is dereferenced here.

Schemas: TonAPI OpenAPI (tonkeeper/opentonapi/api/openapi.yml), Toncenter v3
NFT items/transfers/DNS APIs, Toncenter v2 runGetMethod. API keys are opt-in.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os
import time
from typing import Any, Callable
from urllib.parse import quote
from weakref import WeakKeyDictionary

import httpx

from app.utils.http import request_json, shared_async_client, http_error_message, request_text, ton_public_rate_metrics
from app.utils.security import sanitize_observation

from .models import InvestigationBudget, SourceObservation, utcnow
from .storage import content_hash


SECRET_KEYS = {"authorization", "x-api-key", "apikey", "api_key", "access_token", "token",
               "private_key", "secret", "seed", "mnemonic", "password", "authclienttoken"}
_LOOP_LIMITERS: WeakKeyDictionary = WeakKeyDictionary()


def redact(value: Any) -> Any:
    return sanitize_observation(value)


class BudgetExceeded(RuntimeError):
    pass


class ProviderError(RuntimeError):
    def __init__(self, source: str, message: str, *, status: str = "error", observation_id: str | None = None,
                 retry_after: float | None = None):
        super().__init__(f"{source}: {message}")
        self.source, self.status, self.observation_id = source, status, observation_id
        self.retry_after = retry_after


@dataclass
class Payload:
    data: dict[str, Any]
    observation_id: str
    source: str
    upstream: str
    endpoint: str


class RequestController:
    def __init__(self, budget: InvestigationBudget, observe: Callable[[SourceObservation], None],
                 *, progress: Callable[[dict[str, Any]], None] | None = None):
        self.budget, self.observe = budget, observe
        self.progress = progress
        self.started = time.monotonic()
        self.requests = 0
        self.semaphore = asyncio.Semaphore(budget.concurrency)
        self.failures: dict[str, int] = {}
        self.circuit_until: dict[str, float] = {}

    def remaining(self) -> float:
        return self.budget.max_seconds - (time.monotonic() - self.started)

    def emit_progress(self, stage: str, **details: Any) -> None:
        if self.progress:
            self.progress(redact({"stage": "nft." + stage, "timestamp": utcnow().isoformat(),
                "elapsed_seconds": time.monotonic() - self.started, "requests": self.requests,
                "remaining_seconds": max(0.0, self.remaining()), **details}))

    async def call(self, provider: "NFTProvider", path: str, params: dict | None = None,
                   body: dict | None = None, *, fresh: bool = False) -> Payload:
        for attempt in range(self.budget.retries + 1):
            try:
                async with asyncio.timeout(max(.001, self.remaining())):
                    return await self._call_once(provider, path, params, body, fresh=fresh)
            except TimeoutError as exc:
                self.emit_progress("request_deadline", source=provider.name, status="deadline")
                raise BudgetExceeded("investigation deadline reached during source wait/request") from exc
            except ProviderError as exc:
                if exc.status not in {"error", "timeout", "rate_limited"} or attempt >= self.budget.retries:
                    raise
                delay = max(min(5, 0.5 * (2 ** attempt)), exc.retry_after or 0)
                if delay >= self.remaining():
                    raise BudgetExceeded("deadline reached before provider retry") from exc
                self.emit_progress("request_retry", source=provider.name, status=exc.status,
                                   attempt=attempt + 1, retry_after_seconds=delay)
                await asyncio.sleep(delay)
        raise RuntimeError("unreachable retry state")

    async def _call_once(self, provider: "NFTProvider", path: str, params: dict | None = None,
                         body: dict | None = None, *, fresh: bool = False) -> Payload:
        if self.requests >= self.budget.max_requests or self.remaining() <= 0:
            raise BudgetExceeded("investigation request/deadline budget reached")
        endpoint = provider.base_url + path
        upstream = provider.upstream
        now = time.monotonic()
        if self.circuit_until.get(upstream, 0) > now:
            raise ProviderError(provider.name, "circuit cooling down; retry on resume", status="unavailable")
        async with self.semaphore:
            loop_state = _LOOP_LIMITERS.setdefault(asyncio.get_running_loop(), {"locks": {}, "last": {}})
            lock = loop_state["locks"].setdefault(upstream, asyncio.Lock())
            async with lock:
                rate = min(self.budget.requests_per_second, getattr(provider, "public_rate_limit", 1.0))
                while True:
                    # Wait for the already active shared host cooldown before
                    # starting the unchanged bounded request window. Transport
                    # hooks still enforce every actual attempt and any new 429.
                    cooldown = ton_public_rate_metrics().get(upstream, {}).get("cooldown_remaining_seconds", 0.0)
                    wait = max(0.0, loop_state["last"].get(upstream, 0) + 1/rate - time.monotonic(), cooldown)
                    if wait >= self.remaining():
                        raise BudgetExceeded("deadline reached while rate limiting")
                    if not wait:
                        break
                    self.emit_progress("rate_wait", source=provider.name, wait_seconds=wait)
                    await asyncio.sleep(wait)
                # Reservation happens after the wait, inside the source lock.
                if self.requests >= self.budget.max_requests or self.remaining() <= 0:
                    raise BudgetExceeded("investigation request/deadline budget reached")
                self.requests += 1
                loop_state["last"][upstream] = time.monotonic()
            collected = utcnow()
            self.emit_progress("request_started", source=provider.name, upstream=upstream,
                method="POST" if body is not None else "GET", endpoint=endpoint,
                method_name=(body or {}).get("method"), parameters=params or {})
            status, error, data, retry_after = "ok", None, None, None
            try:
                async with asyncio.timeout(min(self.remaining(), self.budget.request_timeout)):
                    data = await provider.request(path, params=params, body=body,
                                                  timeout=self.budget.request_timeout,
                                                  retries=0, fresh=fresh)
                if not isinstance(data, dict):
                    raise ValueError("unexpected non-object response")
                if data.get("ok") is False or data.get("error") or data.get("code") and "error" in data:
                    # Provider response text can contain credentials; never interpolate it.
                    raise ValueError("provider returned an error object")
                self.failures[upstream] = 0
                self.circuit_until.pop(upstream, None)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                status = "timeout" if isinstance(exc, (TimeoutError, httpx.TimeoutException)) else "error"
                if isinstance(exc, httpx.HTTPStatusError):
                    status = "not_found" if exc.response.status_code == 404 else "rate_limited" if exc.response.status_code == 429 else "error"
                    try:
                        retry_after = max(0, float(exc.response.headers.get("Retry-After", "0")))
                    except ValueError:
                        from email.utils import parsedate_to_datetime
                        try:
                            retry_after = max(0, (parsedate_to_datetime(exc.response.headers["Retry-After"])-utcnow()).total_seconds())
                        except (ValueError, KeyError, TypeError):
                            retry_after = None
                error = http_error_message(exc) if isinstance(exc, httpx.HTTPError) else type(exc).__name__
                self.failures[upstream] = self.failures.get(upstream, 0) + 1
                if self.failures[upstream] >= 3:
                    self.circuit_until[upstream] = time.monotonic() + 20
            clean_data = redact(data)
            digest = content_hash(clean_data)
            oid = "obs:" + content_hash({"source": provider.name, "endpoint": endpoint,
                                       "parameters": params or {}, "body": body or {},
                                       "at": collected.isoformat(), "hash": digest})
            observation = SourceObservation(observation_id=oid, source=provider.name, upstream=upstream,
                                            endpoint=endpoint, request_parameters=redact(params or {}),
                                            request_method="POST" if body is not None else "GET",
                                            request_body=redact(body), requested_at=collected,
                                            collected_at=utcnow(), content_hash=digest, status=status,
                                            raw=clean_data, error=error)
            self.observe(observation)
            self.emit_progress("request_completed", source=provider.name, upstream=upstream,
                endpoint=endpoint, status=status, observation_id=oid,
                duration_seconds=(observation.collected_at-collected).total_seconds())
            if status != "ok":
                raise ProviderError(provider.name, error or status, status=status, observation_id=oid, retry_after=retry_after)
            return Payload(clean_data, oid, provider.name, upstream, endpoint)


class NFTProvider:
    name: str
    upstream: str
    base_url: str
    public_rate_limit: float = 1.0

    def __init__(self, controller: RequestController | None = None, *, use_api_keys: bool = False):
        self.controller = controller
        self.use_api_keys = use_api_keys

    async def request(self, path: str, *, params: dict | None, body: dict | None,
                      timeout: float, retries: int, fresh: bool) -> dict:
        headers = self.headers()
        if fresh:
            headers["Cache-Control"] = "no-cache"
        async with shared_async_client(timeout) as client:
            return await request_json(client, "POST" if body is not None else "GET", self.base_url + path,
                                      params=params, json=body, headers=headers, retries=retries,
                                      cache_ttl=0 if fresh else None)

    def headers(self) -> dict[str, str]:
        return {}

    async def call(self, path: str, params: dict | None = None, body: dict | None = None,
                   *, fresh: bool = False) -> Payload:
        if self.controller is None:
            raise RuntimeError("provider request controller not configured")
        return await self.controller.call(self, path, params, body, fresh=fresh)


class TonAPIProvider(NFTProvider):
    name = "tonapi_nft"
    upstream = "tonapi.io"
    base_url = "https://tonapi.io/v2"

    def headers(self) -> dict[str, str]:
        if not self.use_api_keys:
            return {}
        key = os.getenv("TONAPI_API_KEY") or os.getenv("TONAPI_KEY")
        return {"Authorization": f"Bearer {key}"} if key else {}

    async def item(self, address: str, *, fresh: bool = False) -> Payload:
        return await self.call(f"/nfts/{quote(address, safe=':')}", fresh=fresh)

    async def account(self, address: str, *, fresh: bool = True) -> Payload:
        """Public account classification; labels/is_wallet are provider reports."""
        return await self.call(f"/accounts/{quote(address, safe=':')}", fresh=fresh)

    async def get_method(self, address: str, method: str, stack: list | None = None) -> Payload:
        """Documented read-only fallback, never message submission or emulation."""
        if method not in {"get_nft_data", "get_collection_data", "get_nft_address_by_index", "get_nft_content"}:
            raise ValueError("unsupported NFT get method")
        args = []
        for kind, value in stack or []:
            if kind == "num":
                args.append(hex(int(str(value), 16 if "0x" in str(value).lower() else 10)))
            elif kind == "cell" and isinstance(value, dict) and isinstance(value.get("bytes"), str):
                args.append(value["bytes"])
            else:
                raise ValueError("unsupported NFT get method argument")
        payload = await self.call(f"/blockchain/accounts/{quote(address, safe=':')}/methods/{method}",
                                  {"args": args} if args else None, fresh=True)
        if payload.data.get("success") is not True or payload.data.get("exit_code") not in (0, 1):
            raise ProviderError(self.name, "NFT get method unsupported or failed", observation_id=payload.observation_id)
        return payload

    async def collection(self, address: str) -> Payload:
        return await self.call(f"/nfts/collections/{quote(address, safe=':')}")

    async def domain(self, domain: str) -> Payload:
        return await self.call(f"/dns/{quote(domain, safe='')}", fresh=True)

    async def resolve_domain(self, domain: str) -> Payload:
        return await self.call(f"/dns/{quote(domain, safe='')}/resolve", fresh=True)

    async def items(self, address: str, *, scope: str, offset: int, limit: int) -> Payload:
        path = f"/accounts/{quote(address, safe=':')}/nfts" if scope == "wallet" else f"/nfts/collections/{quote(address, safe=':')}/items"
        return await self.call(path, {"limit": limit, "offset": offset}, fresh=True)

    async def operations(self, address: str, *, before_lt: int | None, limit: int) -> Payload:
        params = {"limit": limit}
        if before_lt is not None:
            params["before_lt"] = before_lt
        return await self.call(f"/accounts/{quote(address, safe=':')}/nfts/history", params)

    async def events(self, address: str, *, before_lt: int | None, limit: int) -> Payload:
        params = {"limit": limit}
        if before_lt is not None:
            params["before_lt"] = before_lt
        return await self.call(f"/accounts/{quote(address, safe=':')}/events", params)


class ToncenterProvider(NFTProvider):
    name = "toncenter_nft"
    upstream = "toncenter.com"
    base_url = "https://toncenter.com"

    def headers(self) -> dict[str, str]:
        if not self.use_api_keys:
            return {}
        key = os.getenv("TONCENTER_API_KEY") or os.getenv("TONCENTER_KEY")
        return {"X-API-Key": key} if key else {}

    async def domain(self, domain: str) -> Payload:
        return await self.call("/api/v3/dns/records", {"domain": domain, "limit": 100}, fresh=True)

    async def item(self, address: str, *, fresh: bool = False) -> Payload:
        return await self.call("/api/v3/nft/items", {"address": address, "limit": 1}, fresh=fresh)

    async def collection(self, address: str) -> Payload:
        return await self.call("/api/v3/nft/collections", {"collection_address": address, "limit": 1})

    async def items(self, address: str, *, scope: str, offset: int, limit: int) -> Payload:
        key = "owner_address" if scope == "wallet" else "collection_address"
        return await self.call("/api/v3/nft/items", {key: address, "limit": limit, "offset": offset,
                                                  "include_on_sale": "true" if scope == "wallet" else "false"}, fresh=True)

    async def transfers(self, address: str, *, scope: str, offset: int, limit: int) -> Payload:
        key = {"item": "item_address", "collection": "collection_address", "wallet": "owner_address"}[scope]
        return await self.call("/api/v3/nft/transfers", {key: address, "limit": limit, "offset": offset, "sort": "desc"})

    async def transaction(self, transaction_hash: str) -> Payload:
        return await self.call("/api/v3/transactions", {"hash": transaction_hash, "limit": 1})

    async def sale_contract(self, address: str) -> Payload:
        return await self.call("/api/v3/nft/sales", {"address": address})

    async def get_method(self, address: str, method: str, stack: list | None = None) -> Payload:
        allowed = {"get_nft_data", "get_collection_data", "get_nft_address_by_index", "get_nft_content"}
        if method not in allowed:
            raise ValueError("unsupported NFT get method")
        payload = await self.call("/api/v2/runGetMethod", body={"address": address, "method": method,
                                                              "stack": stack or []}, fresh=True)
        result = payload.data.get("result", payload.data)
        if result.get("exit_code") not in (0, 1):
            raise ProviderError(self.name, "NFT get method unsupported or failed",
                                observation_id=payload.observation_id)
        return Payload(result, payload.observation_id, payload.source, payload.upstream, payload.endpoint)


class TelegramPublicProvider(NFTProvider):
    name = "telegram_public_collectible"
    upstream = "telegram.org"
    base_url = "https://t.me"

    async def request(self, path: str, *, params: dict | None, body: dict | None,
                      timeout: float, retries: int, fresh: bool) -> dict:
        # User input never supplies a host or arbitrary path. This is a fixed
        # public Telegram gift page, without account authorization or contacts.
        async with shared_async_client(timeout) as client:
            # Telegram's public pages declare UTF-8 while some intermediary
            # headers mislabel the charset. Decode the actual bytes explicitly.
            async with client.stream("GET", self.base_url + path, follow_redirects=False) as response:
                response.raise_for_status()
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > 2_000_000:
                        raise ValueError("public collectible page too large")
                    chunks.append(chunk)
                html = b"".join(chunks).decode("utf-8", errors="replace")
        return {"html": html}

    async def gift(self, slug: str, number: str) -> Payload:
        import re
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", slug) or not re.fullmatch(r"\d+", number):
            raise ValueError("invalid collectible gift identifier")
        return await self.call("/nft/" + slug + "-" + number)
