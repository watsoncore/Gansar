"""Bounded target-only public identity/attestation transport.

The normal blockchain transport, collection timeouts and rate gates are
unchanged. This layer shares its HTTP client/hooks but keeps a small public
context cache and conservative per-host cooldown without background retries.
"""
from __future__ import annotations

import asyncio
from collections import OrderedDict
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json as jsonlib
import math
import time
import ipaddress
import socket
from urllib.parse import urlsplit
from weakref import WeakKeyDictionary

import httpx

from app.utils.http import _retry_after_seconds
from app.utils.security import safe_public_url, validate_public_url

_CACHE = OrderedDict()
_GATES = WeakKeyDictionary()
_CACHE_MAX_ITEMS = 128


def _key(method, url, params, body, user_agent=None):
    return hashlib.sha256(jsonlib.dumps([method,url,params,body,user_agent],sort_keys=True,separators=(',',':')).encode()).hexdigest()


async def public_json(client: httpx.AsyncClient, method: str, url: str, *, json=None,
                      params=None, max_bytes: int = 1_000_000,
                      cache_ttl: float = 300.0, with_metadata: bool = False,
                      allow_list: bool = False, user_agent: str | None = None):
    """Read one fixed public endpoint, with bounded decoded bytes and no retry.

    A source can opt into transport metadata to retain the actual observation
    time when a subsequent investigation reuses a cached public response.
    Redirects are rejected; callers never pass provider-supplied request URLs.
    """
    method=method.upper()
    if method not in {'GET','POST'} or not safe_public_url(url) or urlsplit(url).scheme!='https':
        raise ValueError('Public context endpoint must be a public HTTPS URL')
    if user_agent is not None and(not isinstance(user_agent,str)or len(user_agent)>200 or any(ord(c)<32 for c in user_agent)):
        raise ValueError('Invalid public context User-Agent')
    key=_key(method,url,params,json,user_agent); now=time.monotonic()
    cached=_CACHE.get(key)
    if cached and now-cached[0]<cache_ttl:
        _CACHE.move_to_end(key)
        value=deepcopy(cached[1]);meta={**cached[2],'cache_hit':True,'transport_requests':0}
        return (value,meta)if with_metadata else value
    host=urlsplit(url).hostname
    gates=_GATES.setdefault(asyncio.get_running_loop(),{})
    state=gates.setdefault(host,{'lock':asyncio.Lock(),'last':float('-inf'),'until':float('-inf')})
    async with state['lock']:
        now=time.monotonic()
        cached=_CACHE.get(key)
        if cached and now-cached[0]<cache_ttl:
            _CACHE.move_to_end(key)
            value=deepcopy(cached[1]);meta={**cached[2],'cache_hit':True,'transport_requests':0}
            return (value,meta)if with_metadata else value
        if state['until']>now:
            raise httpx.HTTPStatusError('Public context provider cooldown',request=httpx.Request(method,url),
                response=httpx.Response(429,request=httpx.Request(method,url)))
        delay=state['last']+1.0-now
        if delay>0:await asyncio.sleep(delay)
        state['last']=time.monotonic()
        try:
            await validate_public_url(url)
            parts=urlsplit(url)
            resolved=await asyncio.get_running_loop().getaddrinfo(parts.hostname,parts.port or 443,type=socket.SOCK_STREAM)
            if not resolved or any(not ipaddress.ip_address(item[4][0]).is_global for item in resolved):
                raise ValueError('Public context endpoint resolved to a private address')
            pinned=httpx.URL(url).copy_with(host=resolved[0][4][0])
            headers={'Host':parts.netloc}
            if user_agent:headers['User-Agent']=user_agent
            async with client.stream(method,pinned,params=params,json=json,headers=headers,
                extensions={'sni_hostname':parts.hostname},follow_redirects=False)as response:
                if response.is_redirect:raise ValueError('Public context redirects are not accepted')
                if response.status_code==429 or response.status_code>=500:
                    delay=_retry_after_seconds(response)
                    if delay is None or not math.isfinite(delay):delay=30.0
                    state['until']=time.monotonic()+max(30.0,delay)
                response.raise_for_status()
                chunks=bytearray()
                async for chunk in response.aiter_bytes():
                    chunks.extend(chunk)
                    if len(chunks)>max_bytes:raise ValueError('Public context response exceeds byte limit')
                value=jsonlib.loads(chunks)
                if not isinstance(value,dict) and not(allow_list and isinstance(value,list)):
                    raise ValueError('Public context response has an unexpected JSON root')
        except httpx.RequestError:
            state['until']=time.monotonic()+5.0
            raise
    meta={'retrieved_at':datetime.now(timezone.utc).isoformat(),'cache_hit':False,'transport_requests':1,
          'response_bytes':len(chunks),'response_sha256':hashlib.sha256(chunks).hexdigest()}
    if cache_ttl>0 and not(isinstance(value,dict)and value.get('errors')):
        _CACHE[key]=(time.monotonic(),deepcopy(value),dict(meta));_CACHE.move_to_end(key)
        while len(_CACHE)>_CACHE_MAX_ITEMS:_CACHE.popitem(last=False)
    return (value,meta)if with_metadata else value
