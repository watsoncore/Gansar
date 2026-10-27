from __future__ import annotations

import base64
import binascii
import re
from decimal import Decimal, InvalidOperation, localcontext
from datetime import datetime, timezone
from typing import Any

RAW_TON_RE = re.compile(r"^-?\d+:[0-9a-fA-F]{64}$")
FRIENDLY_TON_RE = re.compile(r"^[A-Za-z0-9_+/=-]{48}$")


def parse_ton_address(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, str):
        return None
    address = value.strip()
    if RAW_TON_RE.fullmatch(address):
        wc, body = address.split(":", 1)
        if not -(2**31) <= int(wc) < 2**31:
            return None
        return {"raw": f"{int(wc)}:{body.lower()}", "workchain": int(wc), "hash": body.lower(), "bounceable": None, "test_only": None}
    if not FRIENDLY_TON_RE.fullmatch(address):
        return None
    try:
        payload = base64.b64decode(address.replace("-", "+").replace("_", "/"), validate=True)
    except (ValueError, binascii.Error):
        return None
    if len(payload) != 36 or (payload[0] & 0x7f) not in {0x11, 0x51}:
        return None
    if binascii.crc_hqx(payload[:34], 0).to_bytes(2, "big") != payload[34:]:
        return None
    wc = int.from_bytes(payload[1:2], "big", signed=True)
    return {"raw": f"{wc}:{payload[2:34].hex()}", "workchain": wc, "hash": payload[2:34].hex(), "bounceable": (payload[0] & 0x7f) == 0x11, "test_only": bool(payload[0] & 0x80)}


def ton_address(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        return value if parse_ton_address(value) else None
    if isinstance(value, dict):
        for key in (
            "address",
            "account_address",
            "account",
            "wallet_address",
            "user_friendly",
            "friendly_address",
            "raw",
            "base64",
            "base64url",
        ):
            nested = value.get(key)
            resolved = ton_address(nested)
            if resolved:
                return resolved
    return None


def ton_address_text(value: Any) -> str:
    return ton_address(value) or ""


def ton_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        for key in ("name", "title", "symbol", "address", "domain"):
            nested = value.get(key)
            if isinstance(nested, str) and nested:
                return nested
    return str(value)


def ton_canonical_address(value: Any) -> str | None:
    address = ton_address(value)
    if not address:
        return None
    parsed = parse_ton_address(address)
    return parsed["raw"] if parsed else None


def ton_amount_decimal(value: Any, decimals: int = 9) -> Decimal | None:
    if isinstance(value, dict):
        for key in ("value", "amount", "balance", "quantity"):
            parsed = ton_amount_decimal(value.get(key), decimals)
            if parsed is not None:
                return parsed
        return None
    try:
        if value is None or not 0 <= decimals <= 255:
            return None
        raw = Decimal(str(value))
        with localcontext() as context:
            context.prec = max(80, len(raw.as_tuple().digits) + decimals + 2)
            amount = raw.scaleb(-decimals)
        return amount if amount.is_finite() else None
    except (ValueError, TypeError, InvalidOperation):
        return None


def ton_amount(value: Any, decimals: int = 9) -> float | None:
    if value is None:
        return None
    if isinstance(value, dict):
        for key in ("value", "amount", "balance", "quantity"):
            parsed = ton_amount(value.get(key), decimals)
            if parsed is not None:
                return parsed
        return None
    parsed = ton_amount_decimal(value, decimals)
    return float(parsed) if parsed is not None else None


def ton_datetime(value: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc) if value is not None else None
    except Exception:
        return None


def ton_direction(source: str | None, destination: str | None, target: str) -> str:
    src = ton_canonical_address(source)
    dst = ton_canonical_address(destination)
    tgt = ton_canonical_address(target)
    if src and dst and tgt and src == tgt and dst == tgt:
        return "self"
    if src and tgt and src == tgt:
        return "out"
    if dst and tgt and dst == tgt:
        return "in"
    return "unknown"
