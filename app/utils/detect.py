from __future__ import annotations

import hashlib
import re

from app.models.report import Chain
from app.utils.ton_normalize import parse_ton_address


ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
BTC_BECH32_RE = re.compile(r"^(bc1)[0-9a-z]{20,90}$", re.IGNORECASE)
BTC_BASE58_RE = re.compile(r"^[13][1-9A-HJ-NP-Za-km-z]{25,34}$")
DOGE_BASE58_RE = re.compile(r"^[D9A][1-9A-HJ-NP-Za-km-z]{25,34}$")
TON_RE = re.compile(r"^(EQ|UQ)[0-9A-Za-z_-]{46,60}$")
TON_RAW_RE = re.compile(r"^-?\d:[0-9a-fA-F]{64}$")
SOL_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {char: index for index, char in enumerate(BASE58_ALPHABET)}
BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_INDEX = {char: index for index, char in enumerate(BECH32_ALPHABET)}
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3


def _base58check_version(value: str) -> int | None:
    num = 0
    for char in value:
        index = BASE58_INDEX.get(char)
        if index is None:
            return None
        num = num * 58 + index
    data = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(value) - len(value.lstrip("1"))
    decoded = (b"\0" * pad) + data
    if len(decoded) < 5:
        return None
    payload, checksum = decoded[:-4], decoded[-4:]
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != digest or not payload:
        return None
    return payload[0]


def _base58_decode(value: str) -> bytes | None:
    num = 0
    for char in value:
        index = BASE58_INDEX.get(char)
        if index is None:
            return None
        num = num * 58 + index
    data = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(value) - len(value.lstrip("1"))
    return (b"\0" * pad) + data


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def _bech32_polymod(values: list[int]) -> int:
    chk = 1
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                chk ^= generator
    return chk


def _bech32_decode(value: str) -> tuple[str, list[int], int] | None:
    if value.lower() != value and value.upper() != value:
        return None
    value = value.lower()
    pos = value.rfind("1")
    if pos < 1 or pos + 7 > len(value):
        return None
    hrp = value[:pos]
    data = []
    for char in value[pos + 1:]:
        index = BECH32_INDEX.get(char)
        if index is None:
            return None
        data.append(index)
    spec = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if spec not in {BECH32_CONST, BECH32M_CONST}:
        return None
    return hrp, data, spec


def _convertbits(data: list[int], from_bits: int, to_bits: int, pad: bool) -> list[int] | None:
    acc = 0
    bits = 0
    out = []
    maxv = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            return None
        acc = ((acc << from_bits) | value) & max_acc
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        return None
    return out


def is_bitcoin_address(address: str) -> bool:
    value = address.strip()
    if BTC_BASE58_RE.match(value):
        return _base58check_version(value) in {0, 5}
    if not BTC_BECH32_RE.match(value):
        return False
    decoded = _bech32_decode(value)
    if decoded is None:
        return False
    hrp, data, spec = decoded
    if hrp != "bc" or len(data) < 7:
        return False
    version = data[0]
    if version > 16:
        return False
    program = _convertbits(data[1:-6], 5, 8, False)
    if program is None or not 2 <= len(program) <= 40:
        return False
    if version == 0:
        return spec == BECH32_CONST and len(program) in {20, 32}
    return spec == BECH32M_CONST


def looks_like_bitcoin_address(address: str) -> bool:
    value = address.strip()
    return bool(value.startswith(("1", "3")) or value.lower().startswith("bc1"))


def looks_like_dogecoin_address(address: str) -> bool:
    return bool(DOGE_BASE58_RE.match(address.strip()))


def is_dogecoin_address(address: str) -> bool:
    value = address.strip()
    return looks_like_dogecoin_address(value) and _base58check_version(value) in {0x1E, 0x16}


def looks_like_tron_address(address: str) -> bool:
    return bool(TRON_RE.match(address.strip()))


def is_tron_address(address: str) -> bool:
    return looks_like_tron_address(address) and _base58check_version(address.strip()) == 0x41


def looks_like_solana_address(address: str) -> bool:
    value = address.strip()
    if not SOL_RE.match(value):
        return False
    # A Solana public key can start with 1 or 3. Prefix-only Bitcoin
    # heuristics must not discard a valid 32-byte key before decoding it.
    if is_tron_address(value) or is_bitcoin_address(value) or parse_ton_address(value):
        return False
    return True


def is_solana_address(address: str) -> bool:
    value = address.strip()
    decoded = _base58_decode(value) if looks_like_solana_address(value) else None
    return decoded is not None and len(decoded) == 32


def detect_candidates(address: str) -> list[Chain]:
    a = address.strip()
    out: list[Chain] = []
    if is_bitcoin_address(a):
        out.append("btc")
    if is_dogecoin_address(a):
        out.append("doge")
    if looks_like_tron_address(a):
        out.append("tron")
    if parse_ton_address(a):
        out.append("ton")
    if ETH_RE.match(a):
        out.append("eth")
    if is_solana_address(a) and "ton" not in out and "btc" not in out and "tron" not in out:
        out.append("solana")
    return list(dict.fromkeys(out))

