"""Lossless inline chunks for large service source-observation maps.

Keep ordinary reports in their original format. Chunk containers own only
references to already guarded values; serialization happens one chunk at a
time while the original HTML template streams to its atomic destination.
"""
from __future__ import annotations

from typing import Any


SOURCE_POOL_INLINE_BYTES = 8 * 1024 * 1024
SOURCE_CHUNK_BYTES = 8 * 1024 * 1024
SOURCE_CHUNK_RECORDS = 128


def _size_hint(value: Any, stop_at: int) -> int:
    """Conservative ASCII JSON size, stopping once a soft bound is exceeded.

    Twelve bytes per Python character cover an escaped supplementary Unicode
    character. No complete encoded copy, decoded codec or UTF-8 copy is built.
    An oversized individual observation remains a lossless singleton chunk.
    """
    size, pending = 0, [value]
    while pending and size <= stop_at:
        item = pending.pop()
        if isinstance(item, str):
            size += 2 + 12 * len(item)
        elif isinstance(item, dict):
            size += 2 + sum(4 + 12 * len(str(key)) for key in item)
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            size += 2 + len(item)
            pending.extend(item)
        else:
            size += 4 + 12 * len(str(item))
    return size


def prepare_source_observations(pool: dict) -> tuple[dict, dict | None, list[dict]]:
    """Return the original small pool or a descriptor and shallow chunks.

    The descriptor is created by the exporter at a controlled payload root,
    outside provider metadata. Observation keys remain exact, including names
    such as ``__proto__``; the browser uses own properties rather than assignment.
    """
    if not pool or _size_hint(pool, SOURCE_POOL_INLINE_BYTES) <= SOURCE_POOL_INLINE_BYTES:
        return pool, None, []
    chunks, descriptors = [], []
    current, current_size = {}, 2

    def finish():
        nonlocal current, current_size
        if not current:
            return
        script_id = "gansar-source-chunk-" + str(len(chunks))
        descriptors.append({"id": script_id, "keys": list(current)})
        chunks.append({"id": script_id, "records": current})
        current, current_size = {}, 2

    for key, value in pool.items():
        record_size = 4 + 12 * len(str(key)) + _size_hint(value, SOURCE_CHUNK_BYTES)
        if current and (len(current) >= SOURCE_CHUNK_RECORDS or current_size + record_size > SOURCE_CHUNK_BYTES):
            finish()
        current[key] = value
        current_size += record_size
    finish()
    descriptor = {"version": 1, "records": len(pool), "chunks": descriptors}
    return {}, descriptor, chunks
