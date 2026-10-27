from __future__ import annotations

import hashlib
import base64
import json
import math
from pathlib import Path
import re
import sqlite3
import zlib
from typing import Any

from pydantic_core import from_json

from app.utils.security import sanitize_observation

from .models import NFTIntelligenceReport, SourceObservation, utcnow


DEFAULT_STORE = Path("output") / "investigations.sqlite3"
OWNER_COMPRESSION_THRESHOLD = 32 * 1024 * 1024
MAX_OWNER_SNAPSHOT_BYTES = 4 * 1024 * 1024 * 1024


def _is_native_json_tree(value: Any) -> bool:
    """Conservative no-normalization check; subclasses use the legacy path."""
    kind = type(value)
    if kind is dict:
        return all(type(key) is str and _is_native_json_tree(child) for key, child in value.items())
    if kind is list:
        return all(_is_native_json_tree(child) for child in value)
    if kind is float:
        return math.isfinite(value)
    return kind in (str, int, bool, type(None))


def _encode_owner_snapshot(owner: dict) -> tuple[str, str]:
    """Hash exact legacy JSON bytes and encode large bodies below SQL limits."""
    encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"))
    compressor = zlib.compressobj(level=6)
    digest = hashlib.sha256()
    pieces, piece_chars, raw_small, compressed_parts = [], 0, bytearray(), []
    total = 0
    def consume():
        nonlocal piece_chars, total, raw_small
        chunk = "".join(pieces).encode("utf-8")
        pieces.clear(); piece_chars = 0
        total += len(chunk)
        if total > MAX_OWNER_SNAPSHOT_BYTES:
            raise ValueError("Owner snapshot exceeds the bounded storage size; previous snapshot retained")
        digest.update(chunk)
        if total <= OWNER_COMPRESSION_THRESHOLD:
            raw_small.extend(chunk)
        else:
            raw_small.clear()
        compressed = compressor.compress(chunk)
        if compressed:
            compressed_parts.append(compressed)
    for piece in encoder.iterencode(owner):
        pieces.append(piece); piece_chars += len(piece)
        if piece_chars >= 65536:
            consume()
    if pieces:
        consume()
    compressed_parts.append(compressor.flush())
    content_digest = digest.hexdigest()
    if total <= OWNER_COMPRESSION_THRESHOLD:
        return raw_small.decode("utf-8"), content_digest
    compressed = b"".join(compressed_parts)
    transactions = owner.get("transactions")
    wrapper = {"_gansar_encoding": "zlib_json", "version": 1,
        "uncompressed_bytes": total, "sha256": content_digest,
        "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
        "transaction_count": len(transactions) if isinstance(transactions, list) else 0,
        "data": base64.b64encode(compressed).decode("ascii")}
    return json.dumps(wrapper, ensure_ascii=False, separators=(",", ":")), content_digest


def decode_owner_snapshot(owner_json: str, expected_sha256: str, *, include_owner: bool = True) -> dict | None:
    """Verify legacy text or a bounded lossless codec, hydrating only on demand."""
    if not owner_json.startswith('{"_gansar_encoding":'):
        if hashlib.sha256(owner_json.encode()).hexdigest() != expected_sha256:
            raise ValueError("Owner snapshot missing or content checksum mismatch")
        if not include_owner:
            return None
        owner = json.loads(owner_json)
        if not isinstance(owner, dict):
            raise ValueError("Owner snapshot must decode to a dossier object")
        return owner
    wrapper = json.loads(owner_json)
    if wrapper.get("_gansar_encoding") != "zlib_json" or type(wrapper.get("version")) is not int or wrapper["version"] != 1:
        raise ValueError("Unsupported owner snapshot encoding")
    expected_bytes, count = wrapper.get("uncompressed_bytes"), wrapper.get("transaction_count")
    if (type(expected_bytes) is not int or not 0 <= expected_bytes <= MAX_OWNER_SNAPSHOT_BYTES
            or type(count) is not int or count < 0 or wrapper.get("sha256") != expected_sha256
            or not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}",expected_sha256)):
        raise ValueError("Owner snapshot codec metadata or checksum mismatch")
    try:
        compressed = base64.b64decode(wrapper["data"], validate=True)
    except (ValueError, TypeError, KeyError) as exc:
        raise ValueError("Owner snapshot codec payload is invalid") from exc
    if hashlib.sha256(compressed).hexdigest() != wrapper.get("compressed_sha256"):
        raise ValueError("Owner snapshot compressed checksum mismatch")
    if not include_owner:
        return None
    try:
        inflater = zlib.decompressobj()
        decoded = inflater.decompress(compressed, expected_bytes + 1)
    except zlib.error as exc:
        raise ValueError("Owner snapshot compressed payload is invalid") from exc
    if (len(decoded) != expected_bytes or not inflater.eof or inflater.unconsumed_tail or inflater.unused_data
            or hashlib.sha256(decoded).hexdigest() != expected_sha256):
        raise ValueError("Owner snapshot decompression length or checksum mismatch")
    try:
        # Parse verified UTF-8 bytes directly. A whole Unicode intermediate can
        # multiply the memory cost of a large dossier containing NFT emoji.
        owner = from_json(decoded, allow_inf_nan=True, allow_partial=False, cache_strings=False)
    except ValueError:
        # Preserve stdlib compatibility for legacy JSON details that the fast
        # parser rejects (for example deep trees, BOM or surrogate escapes).
        owner = json.loads(decoded)
    if not isinstance(owner, dict):
        raise ValueError("Owner snapshot must decode to a dossier object")
    transactions = owner.get("transactions")
    if (len(transactions) if isinstance(transactions, list) else 0) != count:
        raise ValueError("Owner snapshot transaction count mismatch")
    return owner


def validate_investigation_id(value: str) -> str:
    stem = value.split(".", 1)[0].upper()
    if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", value) or value in {".", ".."}
            or value.endswith((".", " ")) or stem in {"CON", "PRN", "AUX", "NUL"}
            or re.fullmatch(r"(?:COM|LPT)[1-9]", stem)):
        raise ValueError("invalid investigation ID")
    return value


class InvestigationStore:
    """Local append-only observations and atomically replaced versioned snapshots.

    Raw responses live in separate rows, not duplicated into every snapshot. The
    SQLite reference is resolvable with observation(), without network access.
    """

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else DEFAULT_STORE
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=15)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS investigations(
                id TEXT PRIMARY KEY, query TEXT NOT NULL, schema_version TEXT NOT NULL,
                updated_at TEXT NOT NULL, report_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS observations(
                investigation_id TEXT NOT NULL, id TEXT NOT NULL, content_hash TEXT NOT NULL,
                observed_at TEXT NOT NULL, observation_json TEXT NOT NULL,
                PRIMARY KEY(investigation_id,id));
            CREATE INDEX IF NOT EXISTS observations_hash ON observations(content_hash);
            CREATE TABLE IF NOT EXISTS events(
                investigation_id TEXT NOT NULL, id TEXT NOT NULL, event_json TEXT NOT NULL,
                PRIMARY KEY(investigation_id,id));
            CREATE TABLE IF NOT EXISTS owner_snapshots(
                investigation_id TEXT PRIMARY KEY, input_sha256 TEXT NOT NULL,
                content_sha256 TEXT NOT NULL, owner_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS checkpoints(
                investigation_id TEXT NOT NULL, stream TEXT NOT NULL, checkpoint_json TEXT NOT NULL,
                PRIMARY KEY(investigation_id,stream));
        """)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def save_observation(self, investigation_id: str, observation: SourceObservation) -> str:
        validate_investigation_id(investigation_id)
        self.db.execute("INSERT OR IGNORE INTO observations VALUES(?,?,?,?,?)",
                        (investigation_id, observation.observation_id, observation.content_hash,
                         observation.collected_at.isoformat(), json.dumps(sanitize_observation(observation.model_dump(mode="json")), ensure_ascii=False)))
        self.db.commit()
        return f"sqlite:observations/{investigation_id}/{observation.observation_id}"

    def observation(self, investigation_id: str, observation_id: str) -> SourceObservation:
        row = self.db.execute("SELECT observation_json FROM observations WHERE investigation_id=? AND id=?",
                              (investigation_id, observation_id)).fetchone()
        if row is None:
            raise KeyError(observation_id)
        return SourceObservation.model_validate_json(row[0])

    def _owner_reference(self, investigation_id: str, owner: dict) -> dict:
        """Persist changed owner data once; nested mutation always changes the digest.

        The fast C JSON pass detects changes without an identity-only cache.
        Complete sanitization and replacement occur only for changed content.
        The caller owns the surrounding SQLite transaction.
        """
        from pydantic_core import to_json
        encoded = to_json(owner)
        input_digest = hashlib.sha256(encoded).hexdigest()
        # The durable digest is also the cache key across store instances.
        # Reading it avoids trusting an in-memory entry after SQL rollback.
        stored = self.db.execute("SELECT input_sha256,content_sha256 FROM owner_snapshots WHERE investigation_id=?",
            (investigation_id,)).fetchone()
        if stored and stored[0] == input_digest:
            content_digest = stored[1]
        else:
            if _is_native_json_tree(owner):
                # Native JSON values survive to_json/json.loads unchanged.
                # Drop the cache-digest bytes before making the one mandatory
                # detached sanitized tree; avoid a second full normalized clone.
                del encoded
                clean_owner = sanitize_observation(owner)
            else:
                normalized_owner = json.loads(encoded)
                del encoded
                clean_owner = sanitize_observation(normalized_owner)
                del normalized_owner
            owner_json, content_digest = _encode_owner_snapshot(clean_owner)
            if len(owner_json.encode()) + 1024 >= self.db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH):
                raise ValueError("Encoded owner snapshot exceeds this SQLite storage boundary; previous snapshot retained")
            self.db.execute("INSERT OR REPLACE INTO owner_snapshots VALUES(?,?,?,?)",
                (investigation_id, input_digest, content_digest, owner_json))
        return {"kind": "sqlite_owner_snapshot", "investigation_id": investigation_id,
            "sha256": content_digest}

    def save_snapshot(self, report: NFTIntelligenceReport) -> None:
        validate_investigation_id(report.investigation_id)
        report.updated_at = utcnow()
        # Owner history is one atomic sibling record, not hundreds of MB
        # re-redacted and rewritten with every inventory/history page.
        data = report.model_dump(mode="json", exclude={"owner_analysis_snapshot"})
        with self.db:
            owner = getattr(report, "owner_analysis_snapshot", None)
            if owner is not None:
                reference = self._owner_reference(report.investigation_id, owner)
                data["owner_snapshot_reference"] = reference
            elif data.get("owner_snapshot_reference"):
                reference = data["owner_snapshot_reference"]
                if reference.get("investigation_id") != report.investigation_id or reference.get("kind") != "sqlite_owner_snapshot":
                    raise ValueError("Owner snapshot reference does not match investigation")
            else:
                reference = None
            clean_json = json.dumps(sanitize_observation(data), ensure_ascii=False)
            self.db.execute("INSERT OR REPLACE INTO investigations VALUES(?,?,?,?,?)",
                            (report.investigation_id, sanitize_observation(report.query), report.schema_version,
                             report.updated_at.isoformat(), clean_json))
            self.db.executemany("INSERT OR REPLACE INTO events VALUES(?,?,?)",
                                [(report.investigation_id, e.event_id, json.dumps(sanitize_observation(e.model_dump(mode="json")), ensure_ascii=False)) for e in report.events])
            self.db.executemany("INSERT OR REPLACE INTO checkpoints VALUES(?,?,?)",
                                [(report.investigation_id, key, json.dumps(sanitize_observation(value), default=str))
                                 for key, value in report.checkpoints.items()])
        # Do not publish a reference until its transaction successfully commits.
        if reference:
            report.owner_snapshot_reference = reference

    def load_snapshot(self, investigation_id: str, *, include_owner: bool = True,
                      owner_exclude: set[str] | None = None, detach_owner: bool = False) -> NFTIntelligenceReport:
        validate_investigation_id(investigation_id)
        row = self.db.execute("SELECT report_json FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if row is None:
            raise KeyError(f"investigation not found: {investigation_id}")
        data = json.loads(row[0])
        owner = data.pop("owner_analysis_snapshot", None)
        reference = data.get("owner_snapshot_reference")
        if reference:
            if reference.get("kind") != "sqlite_owner_snapshot" or reference.get("investigation_id") != investigation_id:
                raise ValueError("Owner snapshot reference does not match investigation")
            stored = self.db.execute("SELECT content_sha256,owner_json FROM owner_snapshots WHERE investigation_id=?",
                (investigation_id,)).fetchone()
            if stored is None or stored[0] != reference.get("sha256"):
                raise ValueError("Owner snapshot missing or content checksum mismatch")
            owner = decode_owner_snapshot(stored[1], stored[0], include_owner=include_owner)
        elif owner is not None and detach_owner:
            # Explicit managed resume upgrades legacy inline storage once.
            # Default load remains read-only and supports all old snapshots.
            with self.db:
                reference = self._owner_reference(investigation_id, owner)
            data["owner_snapshot_reference"] = reference
        if include_owner and owner is not None:
            if owner_exclude:
                owner = {key: value for key, value in owner.items() if key not in owner_exclude}
            data["owner_analysis_snapshot"] = owner
        data.setdefault("owner_analysis_snapshot", None)
        report = NFTIntelligenceReport.model_validate(sanitize_observation(data))
        if report.schema_version.split(".")[0] != "1":
            raise ValueError("unsupported investigation schema version")
        return report

    def find_intersections(self, wallet: str, asset_addresses: list[str], *, exclude_id: str) -> list[dict[str, Any]]:
        addresses = set(asset_addresses)
        matches = []
        for inv_id, data in self.db.execute("SELECT id,report_json FROM investigations WHERE id!=?", (exclude_id,)):
            parsed = json.loads(data)
            portfolio = parsed.get("portfolio") or {}
            other_wallet = portfolio.get("wallet_address")
            if other_wallet and other_wallet != wallet:
                shared = sorted(addresses.intersection(portfolio.get("historical_holdings", []) +
                                                       portfolio.get("current_holdings", [])))
                if shared:
                    matches.append({"investigation_id": inv_id, "wallet_address": other_wallet,
                                    "asset_addresses": shared, "meaning": "observed shared NFT; not shared control"})
        return matches


def load_investigation(investigation_id: str, store_path: str | Path | None = None) -> NFTIntelligenceReport:
    store = InvestigationStore(store_path)
    try:
        return store.load_snapshot(investigation_id)
    finally:
        store.close()


def content_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
