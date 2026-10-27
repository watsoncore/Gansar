"""Exact-address lookup in a packaged public registry; no remote lookup or fuzzy search."""
from __future__ import annotations

import re
from functools import lru_cache

from app.utils.ton_normalize import ton_canonical_address
from .registry_snapshot import ACCOUNTS, OBSERVED_AT, SOURCE_SHA256, SOURCE_URL


def service_identity(name: str) -> tuple[str, str]:
    """Classify the published label text, never infer a service from contract code."""
    value = name.strip().casefold()
    exact = {"crypto bot": ("cryptobot", "custodial_service"), "cryptobot": ("cryptobot", "custodial_service"),
             "wallet in telegram": ("wallet_telegram", "custodial_service"),
             "tonkeeper": ("tonkeeper", "wallet_service"), "mytonwallet": ("mytonwallet", "wallet_service"),
             "tonhub": ("tonhub", "wallet_service"), "ton space": ("ton_space", "wallet_service"),
             "portals marketplace": ("portals", "marketplace")}
    if value in exact:
        return exact[value]
    # Prefixes classify only complete labels already present in the published
    # snapshot. An arbitrary provider title such as "Tonkeeper support scam"
    # never becomes a known service merely because it contains that name.
    if value in _published_names():
        for prefix, service, category in (("tonkeeper ", "tonkeeper", "wallet_infrastructure"),
                                          ("xrocket bot", "xrocket", "custodial_service"),
                                          ("wallet bot ", "wallet_telegram", "custodial_service"),
                                          ("bybit ", "bybit", "exchange_infrastructure"),
                                          ("getgems ", "getgems", "marketplace"),
                                          ("ston.fi ", "stonfi", "dex"), ("dedust ", "dedust", "dex")):
            if value.startswith(prefix):
                return service, category
    # An arbitrary indexer/account title is a public label, not a wallet client.
    return "registry:" + re.sub(r"[^a-z0-9]+", "_", value).strip("_")[:80], "public_address_label"


@lru_cache(maxsize=1)
def _published_names() -> frozenset[str]:
    return frozenset(row["name"].strip().casefold() for row in ACCOUNTS)


@lru_cache(maxsize=1)
def registry_by_address() -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = {}
    for row in ACCOUNTS:
        address = ton_canonical_address(row["address"])
        if address:
            out.setdefault(address, []).append({"address": address, "name": row["name"]})
    return out


def exact_registry_labels(address: str) -> list[dict[str, str]]:
    return [dict(row) for row in registry_by_address().get(address, [])]
