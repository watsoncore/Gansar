"""Bounded decoding of ordinary TON cells used by NFT get methods.

This deliberately does not execute TVM or interpret exotic cells/dictionaries.
Unsupported cell layouts remain available as raw BOCs in the report.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from typing import Any

from app.utils.ton_normalize import ton_canonical_address


@dataclass
class Cell:
    data: bytes
    bit_length: int
    refs: list["Cell"] = field(default_factory=list)


def decode_boc(value: str) -> Cell:
    value = value.strip()
    try:
        blob = bytes.fromhex(value) if value.startswith("b5ee9c72") else base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("invalid BOC encoding") from exc
    if len(blob) > 2_000_000 or blob[:4] != bytes.fromhex("b5ee9c72"):
        raise ValueError("unsupported BOC header")
    flags, offset_size = blob[4], blob[5]
    size = flags & 7
    if not 1 <= size <= 4 or not 1 <= offset_size <= 8 or flags & 0x20:
        raise ValueError("unsupported BOC flags")
    pos = 6
    def uint(n: int) -> int:
        nonlocal pos
        if pos + n > len(blob):
            raise ValueError("truncated BOC")
        out = int.from_bytes(blob[pos:pos+n], "big")
        pos += n
        return out
    cells, roots, absent, total = uint(size), uint(size), uint(size), uint(offset_size)
    if not 0 < cells <= 10000 or roots != 1 or absent:
        raise ValueError("unsupported BOC roots")
    root = uint(size)
    if flags & 0x80:
        pos += cells * offset_size
    end = pos + total
    if end > len(blob) or root >= cells:
        raise ValueError("truncated BOC cells")
    parsed: list[Cell] = []
    references: list[list[int]] = []
    for _ in range(cells):
        d1, d2 = uint(1), uint(1)
        refs = d1 & 7
        if refs > 4 or d1 & 0xF8:
            raise ValueError("exotic or hashed BOC cells unsupported")
        byte_len = (d2 + 1) // 2
        if pos + byte_len > end:
            raise ValueError("truncated cell payload")
        data = blob[pos:pos+byte_len]
        pos += byte_len
        bits = byte_len * 8
        if d2 & 1:
            if not data or not data[-1]:
                raise ValueError("invalid cell top-up bits")
            bits -= (data[-1] & -data[-1]).bit_length()
        parsed.append(Cell(data, bits))
        references.append([uint(size) for _ in range(refs)])
    if pos != end:
        raise ValueError("BOC cell size mismatch")
    for i, ids in enumerate(references):
        if any(j <= i or j >= cells for j in ids):
            raise ValueError("invalid or cyclic BOC references")
        parsed[i].refs = [parsed[j] for j in ids]
    return parsed[root]


def stack_int(entry: Any) -> int:
    value = entry.get("num", entry.get("value")) if isinstance(entry, dict) else entry[1]
    if isinstance(value, dict):
        value = value.get("number", value.get("value"))
    text = str(value)
    return int(text, 16 if "0x" in text.lower() else 10)


def stack_boc(entry: Any) -> str:
    value = (entry.get("cell") or entry.get("slice") or entry.get("value")) if isinstance(entry, dict) else entry[1]
    if isinstance(value, dict):
        value = value.get("bytes") or value.get("boc") or value.get("data", {}).get("b64")
    if not isinstance(value, str):
        raise ValueError("stack cell BOC unavailable")
    # TonAPI's typed stack uses hex cells; Toncenter cell arguments require
    # base64 BoCs. Normalize only the representation, preserving raw responses.
    if value.startswith("b5ee9c72"):
        try:
            return base64.b64encode(bytes.fromhex(value)).decode("ascii")
        except ValueError as exc:
            raise ValueError("invalid hex stack BOC") from exc
    return value


def stack_address(entry: Any) -> str | None:
    if isinstance(entry, dict) and entry.get("address"):
        return ton_canonical_address(entry["address"])
    cell = decode_boc(stack_boc(entry))
    bits = "".join(f"{byte:08b}" for byte in cell.data)[:cell.bit_length]
    if bits[:2] == "00":
        return None
    if len(bits) < 267 or bits[:3] != "100":
        raise ValueError("only addr_std without anycast is supported")
    wc = int(bits[3:11], 2)
    if wc >= 128:
        wc -= 256
    return ton_canonical_address(f"{wc}:{int(bits[11:267], 2):064x}")


def content_uri(boc: str) -> str | None:
    cell = decode_boc(boc)
    chunks: list[bytes] = []
    count = 0
    while True:
        count += 1
        if count > 1000 or cell.bit_length % 8:
            raise ValueError("unsupported snake content")
        chunks.append(cell.data[:cell.bit_length//8])
        if not cell.refs:
            break
        if len(cell.refs) != 1:
            return None
        cell = cell.refs[0]
    raw = b"".join(chunks)
    if not raw or raw[0] != 1:
        return None
    return raw[1:].decode("utf-8")


def nft_data(result: dict[str, Any]) -> dict[str, Any]:
    stack = result.get("stack") or []
    if len(stack) < 5:
        raise ValueError("get_nft_data returned fewer than five stack entries")
    return {"initialized": stack_int(stack[0]) != 0, "index": stack_int(stack[1]),
            "collection_address": stack_address(stack[2]), "owner_address": stack_address(stack[3]),
            "individual_content_boc": stack_boc(stack[4])}


def collection_data(result: dict[str, Any]) -> dict[str, Any]:
    stack = result.get("stack") or []
    if len(stack) < 3:
        raise ValueError("get_collection_data returned fewer than three stack entries")
    return {"next_item_index": stack_int(stack[0]), "content_boc": stack_boc(stack[1]),
            "owner_address": stack_address(stack[2])}


def ton_dns_item_index(domain: str) -> int:
    """Official dns-contract item_index = slice_hash(label), not SHA256(text).

    This adapter applies only to a single ASCII label in the deployed .ton
    collection. It computes the ordinary no-reference cell representation hash.
    Specialized subdomain collections require a different resolver adapter.
    """
    import re
    if not re.fullmatch(r"[a-z0-9_-]{1,126}\.ton", domain):
        raise ValueError("specialized DNS fallback supports one ASCII .ton label")
    label = domain[:-4].encode("ascii")
    return int.from_bytes(hashlib.sha256(bytes([0, len(label)*2]) + label).digest(), "big")
