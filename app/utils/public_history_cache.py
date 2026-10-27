"""Optional TTL cache for public historical responses, never current state."""
from contextvars import ContextVar
from contextlib import contextmanager, closing
import hashlib
import json
from pathlib import Path
import sqlite3
import time
from urllib.parse import urlsplit, parse_qsl

_PATH = ContextVar("gansar_public_history_cache", default=None)
_EVENT = ContextVar("gansar_public_history_cache_event", default=None)

@contextmanager
def history_cache(path, progress=None):
    token = _PATH.set(Path(path))
    callback = _EVENT.set(progress)
    try:
        yield
    finally:
        _PATH.reset(token)
        _EVENT.reset(callback)

def key_for(method, url, params, body, headers):
    parsed = urlsplit(url)
    history = any(part in parsed.path for part in ("/transactions", "/transfers", "/events", "/history"))
    if method.upper() != "GET" or parsed.hostname not in {"tonapi.io", "toncenter.com"} or not history or body is not None or parsed.username:
        return None
    names = [*(headers or {}), *(params or {}), *(key for key, _ in parse_qsl(parsed.query))]
    keys = " ".join(str(key).lower().replace("-", "").replace("_", "") for key in names)
    if any(secret in keys for secret in ("authorization", "apikey", "token", "cookie", "password", "secret")):
        return None
    if _PATH.get() is None:
        return None
    return hashlib.sha256(json.dumps([url, params, body], sort_keys=True, default=str).encode()).hexdigest()

def connection():
    path = _PATH.get()
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=.1)
    db.execute("CREATE TABLE IF NOT EXISTS public_history (key TEXT PRIMARY KEY, observed REAL, payload TEXT)")
    return db

def get(key, ttl=45):
    if not key:
        return None
    try:
        with closing(connection()) as db:
            row = db.execute("SELECT observed,payload FROM public_history WHERE key=?", (key,)).fetchone()
        if not row or time.time()-row[0] > min(45, ttl):
            return None
        callback = _EVENT.get()
        if callback:
            callback({"stage": "cache.history_hit", "cached_at_epoch": row[0], "age_seconds": time.time()-row[0],
                      "current_balance_or_ownership": False})
        return json.loads(row[1])
    except (OSError, sqlite3.Error, ValueError):
        return None

def put(key, payload):
    if not key:
        return
    try:
        encoded = json.dumps(payload, ensure_ascii=False)
        if len(encoded) > 4_000_000:
            return
        with closing(connection()) as db, db:
            db.execute("DELETE FROM public_history WHERE observed<?", (time.time()-45,))
            db.execute("INSERT OR REPLACE INTO public_history VALUES(?,?,?)", (key, time.time(), encoded))
            db.execute("DELETE FROM public_history WHERE key NOT IN (SELECT key FROM public_history ORDER BY observed DESC LIMIT 256)")
    except (OSError, sqlite3.Error, TypeError):
        pass  # Cache availability is not a provider health claim.
