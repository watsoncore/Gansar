"""Published TON wallet code fingerprints, never a wallet-application classifier.

Source: https://docs.ton.org/contracts/standard/wallets/history (2026-10-16).
V5 is a shared standard, even though initially proposed by the Tonkeeper team.
"""
from __future__ import annotations

import hashlib

from app.ton_nft.protocol import decode_boc

WALLET_SOURCE = "https://docs.ton.org/contracts/standard/wallets/history"
WALLET_HASHES = {
    "a0cfc2c48aee16a271f2cfc0b7382d81756cecb1017d077faaab3bb602f6868c": "V1R1",
    "d4902fcc9fad74698fa8e353220a68da0dcf72e32bcb2eb9ee04217c17d3062c": "V1R2",
    "587cc789eff1c84f46ec3797e45fc809a14ff5ae24f1e0c7a6a99cc9dc9061ff": "V1R3",
    "5c9a5e68c108e18721a07c42f9956bfb39ad77ec6d624b60c576ec88eee65329": "V2R1",
    "fe9530d3243853083ef2ef0b4c2908c0abf6fa1c31ea243aacaa5bf8c7d753f1": "V2R2",
    "b61041a58a7980b946e8fb9e198e3c904d24799ffa36574ea4251c41a566f581": "V3R1",
    "84dafa449f98a6987789ba232358072bc0f76dc4524002a5d0918b9a75d2d599": "V3R2",
    "64dd54805522c5be8a9db59cea0105ccf0d08786ca79beb8cb79e880a8d7322d": "V4R1",
    "feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0": "V4R2",
    "20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f": "V5R1",
    "9149ae51c1e4689710cebf7830297b16acfbadb363a920a537893e7ffeeca768": "WalletTg",
}


def ordinary_code_hash(boc: str) -> str:
    """TON ordinary level-zero cell hash, not the hash of serialized BOC bytes.

    The shared decoder rejects exotic/leveled/oversized cells. An iterative,
    memoized walk handles shared references without recursive DAG expansion.
    """
    root = decode_boc(boc)
    work = [(root, False)]
    hashes: dict[int, tuple[bytes, int]] = {}
    while work:
        cell, ready = work.pop()
        if id(cell) in hashes:
            continue
        if not ready:
            work.append((cell, True))
            work.extend((ref, False) for ref in reversed(cell.refs) if id(ref) not in hashes)
            continue
        pairs = [hashes[id(ref)] for ref in cell.refs]
        representation = bytes([len(cell.refs), cell.bit_length // 8 + (cell.bit_length + 7) // 8]) + cell.data
        representation += b"".join(depth.to_bytes(2, "big") for _, depth in pairs)
        representation += b"".join(digest for digest, _ in pairs)
        hashes[id(cell)] = hashlib.sha256(representation).digest(), max((depth for _, depth in pairs), default=-1) + 1
    return hashes[id(root)][0].hex()
