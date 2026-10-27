"""Versioned public address datasets: offline lookup, explicit bounded refresh.

Downloaded text is data only: JSON, safe YAML, or CSV. No JavaScript, imports,
shell commands, arbitrary URLs, or provider metadata code is ever executed.
"""
from __future__ import annotations

import asyncio
import copy
import csv
from datetime import date, datetime, timezone
from functools import lru_cache
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urljoin, urlsplit

import httpx

from app.attribution.normalize import CHAIN_IDS, canonical_address, normalize_chain
from app.utils.http import shared_async_client
from app.utils.security import safe_public_url, sanitize_observation, validate_public_url

ASSETS = Path(__file__).resolve().parent / "assets"
DEFAULT_SOURCES = ASSETS / "sources.json"
DEFAULT_SNAPSHOT = ASSETS / "snapshot.json"
DEFAULT_LOCAL_SNAPSHOT = Path(__file__).resolve().parents[2] / "output" / "attribution_catalogue.json"
MAX_RECORDS = 100_000
_LICENSES = {"MIT", "Apache-2.0", "CC0-1.0", "CC-BY-4.0", "public-domain"}
_CURRENCIES = {"BTC": "btc", "DOGE": "doge", "ETH": "eth", "TRX": "tron", "TRON": "tron",
    "SOL": "solana", "BEP20": "bsc", "BSC": "bsc", "MATIC": "polygon", "POL": "polygon",
    "AVAX": "avalanche", "ARB": "arbitrum", "ARBITRUM": "arbitrum", "OP": "optimism"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _pack(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _hash(value: object) -> str:
    return hashlib.sha256(_pack(value)).hexdigest()


def _slug(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").casefold()).strip("_")[:100]


def _date(value: object) -> str | None:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return str(value)[:80] if value else None


def _upstream(url: str, fallback: str) -> str:
    host = (urlsplit(url).hostname or "").casefold().removeprefix("www.")
    return host or fallback


def _decode(body: bytes, format_name: str) -> object:
    text = body.decode("utf-8-sig")
    if format_name == "json":
        return json.loads(text)
    if format_name == "csv":
        return list(csv.DictReader(io.StringIO(text)))[:MAX_RECORDS + 1]
    if format_name == "yaml":
        import yaml
        loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
        # Refuse recursive/expanding aliases as well as executable YAML tags.
        for count, event in enumerate(yaml.parse(text, Loader=loader)):
            if count > 1_000_000:
                raise ValueError("YAML event limit exceeded")
            if isinstance(event, yaml.AliasEvent):
                raise ValueError("YAML aliases are not accepted in attribution datasets")
        return yaml.load(text, Loader=loader)
    raise ValueError("Only JSON, safe YAML, and CSV dataset formats are supported")


def normalize_dataset(body: bytes, source: dict, *, observed_at: str | None = None) -> dict:
    """Import a configured data-only source; preserve all conflicting labels."""
    if len(body) > 8_000_000:
        raise ValueError("Dataset exceeds 8 MB")
    observed_at = observed_at or _now()
    dataset_id = str(source["id"])
    digest = hashlib.sha256(body).hexdigest()
    raw = _decode(body, source.get("format", "json"))
    adapter = source.get("adapter", "records")
    shared = raw if isinstance(raw, dict) else {}
    if adapter == "graphsense":
        rows = shared.get("tags", [])
    elif adapter == "solana_markets":
        rows = raw if isinstance(raw, list) else []
    elif adapter == "ton_accounts":
        rows = raw if isinstance(raw, list) else shared.get("accounts", [])
    elif adapter == "safe_deployments":
        rows = []
        networks = shared.get("networkAddresses", {})
        deployments = shared.get("deployments", {})
        for chain, chain_id in CHAIN_IDS.items():
            names = networks.get(str(chain_id), [])
            if isinstance(names, str): names = [names]
            if not isinstance(names, list): continue
            for name in names:
                deployment = deployments.get(name, {})
                if not isinstance(deployment, dict): continue
                rows.append({"blockchain": chain, "address": deployment.get("address"),
                    "entity_name": source.get("entity_name", shared.get("contractName")),
                    "contract_metadata": {"contract_name": shared.get("contractName"), "version": shared.get("version"),
                        "published_code_hash": deployment.get("codeHash"), "deployment_name": name}})
    elif adapter == "records":
        rows = raw if isinstance(raw, list) else shared.get("records", [])
    else:
        raise ValueError("Unknown data-only dataset adapter")
    if not isinstance(rows, list):
        raise ValueError("Dataset rows must be a list")
    records = []; rejected = 0; unsupported = 0; seen = set()
    for row in rows[:MAX_RECORDS]:
        if not isinstance(row, dict):
            rejected += 1; continue
        currency = str(row.get("currency", shared.get("currency", ""))).upper()
        chain = source.get("blockchain") or row.get("blockchain") or row.get("chain") or _CURRENCIES.get(currency)
        chain = normalize_chain(chain)
        address_value = row.get("programId") if adapter == "solana_markets" else row.get("address")
        address = canonical_address(chain, address_value)
        if not address:
            if currency and currency not in _CURRENCIES: unsupported += 1
            else: rejected += 1
            continue
        label = str(row.get("entity_name") or row.get("name") or row.get("label") or shared.get("label") or source.get("entity_name") or "").strip()[:240]
        entity_id = str(source.get("entity_id") or row.get("entity_id") or row.get("actor") or shared.get("actor") or _slug(label))[:140]
        if adapter == "solana_markets":
            label = str(source.get("entity_name") or "Serum published program")
        if not label or not entity_id:
            rejected += 1; continue
        row_url = row.get("source") or shared.get("source") or source.get("source_url") or source.get("url")
        source_url = safe_public_url(row_url)
        if not source_url:
            rejected += 1; continue
        source_date = _date(row.get("lastmod") or shared.get("lastmod"))
        limitations = list(source.get("coverage_limitations", []))
        if source_date:
            limitations.append("Historical dataset publication; current control or continued service use is not independently verified.")
        record = {"blockchain": chain, "address": address, "entity_id": entity_id,
            "entity_name": label, "entity_type": str(source.get("entity_type") or row.get("category") or shared.get("category") or "public_address_label"),
            "source": dataset_id, "dataset_id": dataset_id, "source_url": source_url,
            "dataset_url": source.get("url"), "observed_at": observed_at, "source_published_at": source_date,
            "upstream": str(source.get("upstream") or _upstream(source_url, dataset_id)),
            "method": source.get("method", "exact_public_dataset_address"),
            "status": "PROBABLE", "relationship": source.get("relationship", "publicly_labeled_address"),
            "authority": source.get("authority", "community_maintained_registry"),
            "license": source.get("license", "unresolved"), "license_url": source.get("license_url"),
            "license_sha256": source.get("license_sha256"),
            "version": digest, "content_hash": digest, "coverage_limitations": list(dict.fromkeys(limitations))}
        if adapter == "safe_deployments":
            record["contract_metadata"] = row["contract_metadata"]
        if source.get("original_source_sha256"):
            record["upstream_content_hash"] = source["original_source_sha256"]
        record = sanitize_observation(record)
        # Same address/different label/upstream stays separate conflict evidence.
        marker = (chain, address, entity_id, label, record["upstream"], source_url)
        if marker not in seen:
            seen.add(marker); records.append(record)
    # Shared defaults keep 50k-address snapshots small without dropping evidence.
    defaults = {}
    if records:
        for key, value in records[0].items():
            if all(record.get(key) == value for record in records): defaults[key] = value
    return {"id": dataset_id, "version": digest, "content_hash": digest, "observed_at": observed_at,
        "source": sanitize_observation(source), "defaults": defaults,
        "records": [{k: v for k, v in row.items() if k not in defaults} for row in records],
        "coverage": {"input_rows": len(rows), "retained_records": len(records), "invalid_rows": rejected,
            "unsupported_network_rows": unsupported, "record_limit": MAX_RECORDS,
            "truncated": len(rows) > MAX_RECORDS}}


@lru_cache(maxsize=4)
def _load_cached(path: str, mtime_ns: int, size: int) -> list[dict]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    datasets = payload.get("datasets", [])
    if payload.get("version") != _hash(datasets):
        raise ValueError("Attribution snapshot content hash mismatch")
    records = []
    for dataset in datasets:
        defaults = dataset.get("defaults", {})
        records.extend({**defaults, **row} for row in dataset.get("records", []))
    return records


def _snapshot_path(path: str | Path | None) -> Path:
    configured = path if path is not None else os.getenv("GANSAR_ATTRIBUTION_DATASET")
    if configured is not None and "://" in str(configured):
        raise ValueError("Attribution dataset store must be a local filesystem path")
    target = Path(configured) if configured else DEFAULT_LOCAL_SNAPSHOT if DEFAULT_LOCAL_SNAPSHOT.exists() else DEFAULT_SNAPSHOT
    if target.is_dir(): target = target / "snapshot.json"
    return target


def load_dataset_records(path: str | Path | None = None) -> list[dict]:
    """Offline only. Return an independent copy of verified snapshot contents."""
    target = _snapshot_path(path)
    if not target.exists(): return []
    stat = target.stat()
    return copy.deepcopy(_load_cached(str(target.resolve()), stat.st_mtime_ns, stat.st_size))


@lru_cache(maxsize=4)
def _lookup_index(path: str, mtime_ns: int, size: int) -> dict[str, list[tuple[int, dict]]]:
    index = {}
    for position, row in enumerate(_load_cached(path, mtime_ns, size)):
        # Imports already validated and canonicalized these addresses. Rechecking
        # every unrelated Bitcoin checksum on every EVM lookup wastes the budget.
        key = f"{row['blockchain']}:{row['address']}"
        index.setdefault(key, []).append((position, row))
    return index


def lookup_dataset_records(keys, path: str | Path | None = None) -> list[dict]:
    """Copy only matching chain:canonical-address rows, in original source order."""
    keys = set(keys)
    if not keys: return []
    target = _snapshot_path(path)
    if not target.exists(): return []
    stat = target.stat()
    index = _lookup_index(str(target.resolve()), stat.st_mtime_ns, stat.st_size)
    matched = [item for key in keys for item in index.get(key, [])]
    matched.sort(key=lambda item: item[0])
    return copy.deepcopy([row for _, row in matched])


def write_snapshot(datasets: list[dict], store_path: str | Path) -> dict:
    """Atomically publish a content-addressed snapshot; never rewrite history."""
    if sum(len(item.get("records", [])) for item in datasets) > MAX_RECORDS:
        raise ValueError("Attribution snapshot total record limit exceeded")
    target = Path(store_path)
    if target.is_dir(): target = target / "snapshot.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {"schema_version": "1.0", "version": _hash(datasets), "retrieved_at": _now(), "datasets": datasets}
    packed = _pack(payload)
    versions = target.parent / "versions"
    versions.mkdir(exist_ok=True)
    archived = versions / (payload["version"] + ".json")
    try:
        with archived.open("xb") as archive: archive.write(packed)
    except FileExistsError:
        # Content-addressed identity excludes retrieved_at; existing history wins.
        existing = json.loads(archived.read_text(encoding="utf-8"))
        if existing.get("datasets") != datasets:
            raise ValueError("Immutable attribution snapshot conflict")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name); stream.write(packed)
        os.replace(temporary, target)
    finally:
        if temporary is not None and temporary.exists(): temporary.unlink()
    _load_cached.cache_clear()
    _lookup_index.cache_clear()
    return payload


async def _download(client: httpx.AsyncClient, url: str, *, max_bytes: int) -> bytes:
    for _ in range(4):
        await validate_public_url(url)
        async with client.stream("GET", url, follow_redirects=False, headers={"Accept": "application/json, text/yaml, text/csv, text/plain"}) as response:
            if response.is_redirect:
                location = response.headers.get("location")
                if not location: raise ValueError("Dataset redirect lacks a location")
                url = urljoin(url, location); continue
            response.raise_for_status()
            if int(response.headers.get("content-length") or 0) > max_bytes:
                raise ValueError("Dataset response exceeds byte limit")
            chunks = []; size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > max_bytes: raise ValueError("Dataset response exceeds byte limit")
                chunks.append(chunk)
            return b"".join(chunks)
    raise ValueError("Dataset redirect limit exceeded")


async def update_datasets(*, store_path: str | Path, sources_path: str | Path | None = None,
                          deadline: float | None = None, max_response_bytes: int = 8_000_000,
                          client: httpx.AsyncClient | None = None, force: bool = False) -> dict:
    """Explicit bounded refresh; failed sources retain their prior observations.

    deadline is absolute asyncio loop.time(); default total budget is 30 seconds.
    Search never calls this operation implicitly. The caller chooses the store.
    """
    loop = asyncio.get_running_loop()
    deadline = min(deadline, loop.time() + 30) if deadline is not None else loop.time() + 30
    max_response_bytes = min(max(1, max_response_bytes), 8_000_000)
    if client is not None and (client.auth is not None or client.cookies or any(
            sanitize_observation({key: "credential_probe"})[key] == "[REDACTED]" for key in client.headers)):
        raise ValueError("Public dataset updates require a client without credentials or cookies")
    registry = json.loads(Path(sources_path or DEFAULT_SOURCES).read_text(encoding="utf-8"))
    sources = registry.get("sources", [])
    if len(sources) > 64: raise ValueError("Dataset source limit exceeded")
    target = Path(store_path)
    if target.is_dir(): target /= "snapshot.json"
    previous = json.loads(target.read_text(encoding="utf-8")) if target.exists() else {"datasets": []}
    if target.exists() and (not isinstance(previous.get("datasets"), list)
            or previous.get("version") != _hash(previous["datasets"])):
        raise ValueError("Existing attribution snapshot content hash mismatch")
    datasets = {str(row["id"]): row for row in previous["datasets"]}
    # A first explicit refresh must not erase the pre-existing TON catalogue
    # just because its upstream licence has disabled new downloads. Preserve
    # the packaged observation verbatim, including its original retrieval time;
    # this is retained historical evidence, never a successful fresh response.
    bundled_priors = set()
    missing_disabled = {str(source.get("id")) for source in sources
        if not source.get("update_enabled", True) and str(source.get("id")) not in datasets}
    if missing_disabled and DEFAULT_SNAPSHOT.exists():
        bundled = json.loads(DEFAULT_SNAPSHOT.read_text(encoding="utf-8"))
        if not isinstance(bundled.get("datasets"), list) or bundled.get("version") != _hash(bundled["datasets"]):
            raise ValueError("Packaged attribution snapshot content hash mismatch")
        for dataset in bundled["datasets"]:
            name = str(dataset["id"])
            if name in missing_disabled:
                datasets[name] = copy.deepcopy(dataset)
                bundled_priors.add(name)
    errors = []; states = []; semaphore = asyncio.Semaphore(2)
    license_checks = {}; license_lock = asyncio.Lock()

    async def refresh(source, active_client):
        name = str(source.get("id", "unnamed"))
        prior = datasets.get(name)
        if not source.get("update_enabled", True):
            state = {"id": name, "status": "disabled", "retained_previous": bool(prior)}
            if name in bundled_priors:
                state.update(retained_from="bundled_snapshot", retained_observed_at=prior.get("observed_at"))
            states.append(state); return
        if source.get("license") not in _LICENSES or not safe_public_url(source.get("license_url")):
            states.append({"id": name, "status": "license_unresolved", "retained_previous": bool(prior)}); return
        if prior and not force:
            at = datetime.fromisoformat(prior["observed_at"])
            if (datetime.now(timezone.utc) - at).total_seconds() < float(source.get("refresh_ttl_seconds", 86400)):
                states.append({"id": name, "status": "cached", "version": prior["version"]}); return
        try:
            async with asyncio.timeout_at(deadline):
                async with semaphore:
                    if source.get("license_sha256"):
                        license_url = source.get("license_download_url") or source["license_url"]
                        async with license_lock:
                            if license_url not in license_checks:
                                license_body = await _download(active_client, license_url, max_bytes=100_000)
                                license_checks[license_url] = hashlib.sha256(license_body).hexdigest()
                        if license_checks[license_url] != source["license_sha256"]:
                            raise ValueError("Dataset license content changed; retain prior snapshot until source terms are reviewed")
                    body = await _download(active_client, source["url"], max_bytes=max_response_bytes)
                    dataset = normalize_dataset(body, source)
                    if not dataset["coverage"]["retained_records"]:
                        raise ValueError("Dataset returned no supported valid addresses")
                    datasets[name] = dataset
                    states.append({"id": name, "status": "updated", "version": dataset["version"], "coverage": dataset["coverage"]})
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            errors.append({"id": name, "error": str(sanitize_observation(str(exc))), "retained_previous": bool(prior)})

    async def run_all(active):
        # TaskGroup awaits cancellation cleanup before returning to a caller.
        async with asyncio.TaskGroup() as group:
            for source in sources:
                group.create_task(refresh(source, active))

    if client is None:
        async with shared_async_client(max(0.1, min(10, deadline - loop.time()))) as active:
            await run_all(active)
    else:
        await run_all(client)
    payload = write_snapshot([datasets[key] for key in sorted(datasets)], target)
    return {"path": str(target), "version": payload["version"], "sources": states, "errors": errors,
        "records": sum(len(row.get("records", [])) for row in payload["datasets"]),
        "status": "partial" if errors else "ok"}
