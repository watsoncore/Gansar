"""Lossless, self-contained JSON storage for large investigation HTML.

This is a presentation codec only. It runs after render redaction/number
guards, and never changes the report, graph, source facts or proof identities.
"""
from __future__ import annotations

import base64
import gzip
import json
import zlib
from collections import Counter
from functools import lru_cache
from pathlib import Path

PACK_THRESHOLD = 8 * 1024 * 1024
TAG = "__gansar_json_storage__"


def _string_table(value):
    """Intern repeated immutable values only; dictionary keys stay literal.

    A doubled NUL escapes provider strings. References are interpreted only
    inside the codec-owned packet, never in ordinary provider JSON.
    """
    counts, pending = Counter(), [value]
    while pending:
        node = pending.pop()
        if isinstance(node, str) and len(node) >= 48:
            if node in counts or len(counts) < 200000:
                counts[node] += 1
        elif isinstance(node, dict):
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    strings = [text for text, count in counts.items() if count >= 3]
    if not strings:
        return None
    # Decimal indexes have no parsing ambiguity and avoid numeric precision.
    refs = {text: '\0' + str(i) for i, text in enumerate(strings)}
    def rewrite(node):
        if isinstance(node, str):
            return refs.get(node, '\0' + node if node.startswith('\0') else node)
        if isinstance(node, list):
            return [rewrite(item) for item in node]
        if isinstance(node, dict):
            return {key: rewrite(item) for key, item in node.items()}
        return node
    return {"strings": strings, "value": rewrite(value)}


def pack_json(serialized: str, *, threshold: int = PACK_THRESHOLD) -> str:
    """Keep small JSON compatible; large blocks are exact UTF-8 gzip members."""
    # A provider may legitimately use our reserved property at its own root.
    # Wrap that literal regardless of size/savings, so decoding exactly once
    # returns provider data instead of interpreting it as a storage command.
    literal_root = json.loads(serialized) if '"' + TAG + '"' in serialized else None
    escaped_literal = isinstance(literal_root, dict) and TAG in literal_root
    if len(serialized) < threshold and not escaped_literal:
        return serialized
    raw = serialized.encode("utf-8")
    byte_length, checksum = len(raw), zlib.crc32(raw)
    compressed = gzip.compress(raw, compresslevel=6, mtime=0)
    del raw
    encoding, version = "gzip-base64", 1
    if len(serialized) >= PACK_THRESHOLD:
        packet = _string_table(literal_root if literal_root is not None else json.loads(serialized))
        literal_root = None
        if packet is not None:
            table_raw = json.dumps(packet, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            del packet
            table_compressed = gzip.compress(table_raw, compresslevel=6, mtime=0)
            if len(table_compressed) + 1024 < len(compressed):
                compressed = table_compressed
                byte_length, checksum = len(table_raw), zlib.crc32(table_raw)
                encoding, version = "gzip-base64-string-table", 2
            del table_raw, table_compressed
    encoded = base64.b64encode(compressed).decode("ascii")
    if len(encoded) + 220 >= len(serialized) and not escaped_literal:
        return serialized
    return json.dumps({TAG: {"version": version, "encoding": encoding,
        "bytes": byte_length, "crc32": checksum, "data": encoded}}, separators=(",", ":"))


@lru_cache(maxsize=1)
def decoder_script() -> str:
    vendor = Path(__file__).with_name("assets") / "vendor"
    code = (vendor / "fflate-0.8.3.min.js").read_text(encoding="utf-8")
    license_text = (vendor / "FFLATE-LICENSE.txt").read_text(encoding="utf-8")
    return "/* fflate 0.8.3\n" + license_text + "*/\n" + code
