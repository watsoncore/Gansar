from __future__ import annotations

from collections import defaultdict
from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone
import hashlib
import re
from typing import Any
from urllib.parse import urlparse

import networkx as nx

from app.models.report import AddressReport
from app.utils.event_identity import transaction_success
from app.utils.ton_assets import image_url_from
from app.utils.ton_normalize import ton_canonical_address
from app.utils.security import safe_public_url, sanitize_observation
from app.attribution.program_transaction_fingerprints import is_tron_non_monetary


NODE_LABELS = {
    "bitcoin_wallet": "Bitcoin wallet",
    "bitcoin_tx": "Bitcoin tx",
    "doge_wallet": "Dogecoin wallet",
    "doge_transaction": "Dogecoin tx",
    "doge_utxo": "Dogecoin UTXO",
    "doge_counterparty": "Dogecoin counterparty",
    "doge_exchange_label": "Dogecoin exchange label",
    "ethereum_wallet": "Ethereum wallet",
    "bsc_wallet": "BNB Chain wallet",
    "bsc_contract": "BNB Chain contract",
    "bsc_tx": "BNB Chain tx",
    "bep20_token": "BEP20 token",
    "bsc_nft": "BSC NFT",
    "dex_pair": "DEX pair",
    "dex_router": "DEX router",
    "bridge": "Bridge",
    "risk_source": "Risk source",
    "trx_wallet": "TRX wallet",
    "tron_wallet": "Tron wallet",
    "tron_tx": "Tron tx",
    "tron_contract": "TRON contract",
    "tron_exchange": "TRON exchange",
    "tron_defi": "TRON DeFi",
    "tron_resource": "TRON resource",
    "tron_permission": "TRON permission",
    "usdt_trc20": "USDT TRC20",
    "sunpump_token": "SunPump token",
    "sunswap_pool": "SunSwap pool",
    "solana_wallet": "Solana wallet",
    "solana_tx": "Solana tx",
    "solana_program": "Solana program",
    "ens_identity": "ENS identity",
    "ens_record": "ENS record",
    "eth_contract": "ETH contract",
    "trc20_token": "TRC20 token",
    "spl_token": "SPL token",
    "solana_nft": "Solana NFT",
    "token": "Token",
    "wallet": "кошелёк",
    "transaction": "транзакция",
    "nft": "NFT",
    "username": "имя",
    "telegram_username": "Telegram username",
    "username_owner": "username owner",
    "username_transfer": "username transfer",
    "gift": "подарок",
    "domain": "домен",
    "jetton": "жетон",
    "jetton_transfer": "jetton transfer",
    "jetton_counterparty": "jetton counterparty",
    "exchange": "биржа",
    "marketplace": "маркетплейс",
    "contract": "контракт",
    "service": "сервис",
    "cluster": "кластер",
    "inference_cluster": "кандидатный кластер",
    "collectible": "коллекционный актив",
    "telegram_id": "Telegram ID",
    "activity": "цепочка",
    "migration_target": "Migration target",
}

NODE_ICONS = {
    "bitcoin_wallet": "counterparty",
    "bitcoin_tx": "contract",
    "doge_wallet": "dogecoin",
    "doge_transaction": "contract",
    "doge_utxo": "contract",
    "doge_counterparty": "dogecoin",
    "doge_exchange_label": "service",
    "ethereum_wallet": "counterparty",
    "bsc_wallet": "counterparty",
    "bsc_contract": "contract",
    "bsc_tx": "contract",
    "bep20_token": "contract",
    "bsc_nft": "nft",
    "dex_pair": "service",
    "dex_router": "service",
    "bridge": "service",
    "risk_source": "service",
    "trx_wallet": "counterparty",
    "tron_wallet": "counterparty",
    "tron_tx": "contract",
    "tron_contract": "contract",
    "tron_exchange": "service",
    "tron_defi": "service",
    "tron_resource": "service",
    "tron_permission": "service",
    "usdt_trc20": "contract",
    "sunpump_token": "contract",
    "sunswap_pool": "service",
    "solana_wallet": "counterparty",
    "solana_tx": "contract",
    "solana_program": "contract",
    "ens_identity": "service",
    "ens_record": "service",
    "eth_contract": "contract",
    "trc20_token": "contract",
    "spl_token": "contract",
    "solana_nft": "nft",
    "token": "contract",
    "wallet": "ton_wallet",
    "transaction": "contract",
    "nft": "nft",
    "username": "telegram",
    "telegram_username": "telegram",
    "username_owner": "counterparty",
    "username_transfer": "contract",
    "gift": "gift",
    "domain": "nft",
    "jetton": "contract",
    "jetton_transfer": "contract",
    "jetton_counterparty": "counterparty",
    "exchange": "service",
    "marketplace": "service",
    "contract": "contract",
    "service": "service",
    "cluster": "counterparty",
    "inference_cluster": "counterparty",
    "collectible": "nft",
    "telegram_id": "telegram",
    "activity": "service",
    "migration_target": "counterparty",
}

EDGE_LABELS = {
    "btc_input": "input",
    "btc_output": "output",
    "doge_input": "input",
    "doge_output": "output",
    "sent": "отправлено",
    "received": "получено",
    "owns": "владеет",
    "owned_before": "владел раньше",
    "linked_by": "связано через",
    "confirmed_by": "подтверждено",
    "bought": "куплено",
    "sold": "продано",
    "listed_on": "листинг",
    "interacted_with": "взаимодействие",
    "transfer": "перевод",
    "transferred": "передано",
    "received_asset": "актив получен",
    "mint": "минт",
    "first_owner": "первый владелец",
    "sale": "продажа",
    "listing": "листинг",
    "owner_change": "смена владельца",
    "current_owner": "текущий владелец",
    "interaction": "связь",
    "activity_path": "цепочка связи",
    "same_address": "тот же адрес",
    "resolves": "resolves",
    "ens_resolution": "ENS resolution",
    "ens_reverse_record": "unverified ENS reverse record",
    "marketplace_interaction": "связь с маркетплейсом",
    "username_owner": "владелец username",
    "username_transfer": "перевод username",
    "gift_sender": "отправитель подарка",
    "gift_receiver": "получатель подарка",
    "jetton_flow": "jetton поток",
    "migration_flow": "признаки миграции",
    "inference_association": "кандидатная связь",
    "inference_membership": "участник кандидатного кластера",
    "inference_protocol": "общая протокольная инфраструктура",
    "inference_observed_transfer": "наблюдаемый перевод в контексте",
    "inference_route_step": "возможный шаг маршрута",
    "inference_utxo_spend": "расходование outpoint",
}

BROKEN_GRAPH_IMAGE_HOSTS = {"dns-cdn.gramcoin.org"}
MARKETPLACE_IMAGE_URLS = {
    "fragment": "https://fragment.com/favicon.ico",
}

SERVICE_MARKERS = {
    "tonkeeper",
    "fragment",
    "getgems",
    "ston",
    "dedust",
    "telegram",
    "wallet",
    "bridge",
    "router",
    "swap",
}

EXCHANGE_MARKERS = {
    "binance",
    "okx",
    "bybit",
    "kucoin",
    "mexc",
    "gate",
    "htx",
    "bitget",
    "coinbase",
    "kraken",
    "exchange",
}


def _short(value: str) -> str:
    value = str(value or "")
    return (value[:10] + "..." + value[-6:]) if len(value) > 22 else value


def _dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def _graph_image_url(*values: Any) -> str:
    for value in values:
        candidate = image_url_from(value) if isinstance(value, dict) else value
        text = str(candidate or "").strip()
        if not text:
            continue
        low = text.lower()
        if low.startswith(("https://", "http://")):
            try:
                host = urlparse(text).netloc.lower().split("@")[-1].split(":")[0]
            except ValueError:
                host = ""
            if host in BROKEN_GRAPH_IMAGE_HOSTS:
                continue
            return text
        if low.startswith("//"):
            return f"https:{text}"
        if low.startswith("ipfs://"):
            payload = text[7:].lstrip("/")
            if payload.startswith("ipfs/"):
                payload = payload[5:]
            if payload:
                return f"https://ipfs.io/ipfs/{payload}"
        if low.startswith("data:image/"):
            return text
    return ""


def _marketplace_image_url(name: str | None) -> str:
    key = str(name or "").strip().lower()
    return MARKETPLACE_IMAGE_URLS.get(key, "")


def _wallet_node_id(chain: str, address: str) -> str:
    if chain == "ton":
        return f"wallet:ton:{ton_canonical_address(address) or address.lower()}"
    return f"wallet:{chain}:{_address_key(chain, address)}"


def _address_key(chain: str, address: str) -> str:
    if chain == "ton":
        return ton_canonical_address(address) or address.lower()
    return address.lower() if chain in {"eth", "bsc", "polygon", "arbitrum", "optimism", "avalanche"} else address


def _asset_node_id(asset_id: str, chain: str = "ton") -> str:
    ton_id = asset_id.removeprefix("JETTON:") if chain == "ton" else asset_id
    canonical = ton_canonical_address(ton_id) if chain == "ton" else _address_key(chain, asset_id)
    return f"asset:{chain}:{canonical or asset_id}"


def _tx_node_id(tx_hash: str, chain: str = "ton") -> str:
    return f"tx:{chain}:{tx_hash}"


def _market_node_id(value: str) -> str:
    return f"market:{value.lower().strip()}"


def _confidence(value: str) -> float:
    return {"confirmed": 0.95, "likely": 0.72, "weak": 0.42, "unknown": 0.15}.get(value, 0.5)


def _primary_chain(report: AddressReport) -> str:
    tx_chains = [tx.chain for tx in report.transactions if tx.from_address or tx.to_address]
    if "ton" in report.detected_chains:
        return "ton"
    if tx_chains:
        counts = defaultdict(int)
        for chain in tx_chains:
            counts[chain] += 1
        return sorted(counts, key=counts.get, reverse=True)[0]
    if report.detected_chains:
        return report.detected_chains[0]
    return "multi"


def _kind_from_labels(labels: list[str], fallback: str = "wallet") -> str:
    value = " ".join(labels).lower()
    if any(marker in value for marker in EXCHANGE_MARKERS):
        return "exchange"
    if any(marker in value for marker in SERVICE_MARKERS):
        return "service"
    if "contract" in value:
        return "eth_contract" if fallback == "ethereum_wallet" else "bsc_contract" if fallback == "bsc_wallet" else "contract"
    return fallback


def _wallet_kind(chain: str, labels: list[str] | None = None) -> str:
    fallback = "bitcoin_wallet" if chain == "btc" else "doge_wallet" if chain == "doge" else "ethereum_wallet" if chain == "eth" else "bsc_wallet" if chain == "bsc" else "trx_wallet" if chain == "tron" else "solana_wallet" if chain == "solana" else "wallet"
    return _kind_from_labels(labels or [], fallback)


def _token_kind(token) -> str:
    asset_type = str((getattr(token, "raw", {}) or {}).get("asset_type") or "")
    if asset_type in {"erc721", "erc1155"}:
        return "nft"
    if asset_type == "contract":
        return "eth_contract"
    if asset_type == "bsc_contract":
        return "bsc_contract"
    if asset_type == "dex_pair":
        return "dex_pair"
    if asset_type in {"bep721", "bep1155"}:
        return "bsc_nft"
    if token.chain == "bsc" or asset_type == "bep20":
        return "bep20_token"
    if token.chain == "tron" or asset_type == "trc20":
        raw = getattr(token, "raw", {}) or {}
        contract = str(getattr(token, "contract", "") or raw.get("contract") or "").strip()
        if contract == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t" or str(getattr(token, "symbol", "") or "").upper() == "USDT":
            return "usdt_trc20"
        return "trc20_token"
    if token.chain == "solana" or asset_type == "spl_token":
        return "solana_nft" if asset_type == "solana_nft" else "spl_token"
    if token.chain == "eth":
        return "token"
    if token.chain == "ton" or asset_type == "jetton":
        return "jetton"
    return "contract"


def _is_ton_jetton_tx(tx) -> bool:
    if getattr(tx, "chain", None) != "ton":
        return False
    asset = str(getattr(tx, "asset", "") or "").lower()
    raw = getattr(tx, "raw", {}) or {}
    action = str(raw.get("action_type") or raw.get("asset_type") or raw.get("provider") or raw.get("type") or "").lower()
    return asset.startswith("jetton:") or "jetton" in asset or "jetton" in action


def _btc_io_address(item: dict) -> str:
    return str((item or {}).get("address") or "").strip()


def _btc_io_value(item: dict) -> float:
    try:
        return float((item or {}).get("value") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _asset_kind(asset_type: str | None) -> str:
    if asset_type in NODE_LABELS:
        return asset_type
    return "nft"


def build_graph_payload(report: AddressReport) -> dict:
    primary_chain = _primary_chain(report)
    target = _wallet_node_id(primary_chain, report.target_address)
    graph_transactions = report.transactions
    financial_projection = None
    if any(tx.chain == "ton" for tx in report.transactions):
        from app.aggregator.financial_operations import project_financial_operations
        financial_projection = project_financial_operations(report)
        # Related real movements remain context in the graph. They never enter
        # the target's financial totals. Raw observations remain in the report.
        graph_transactions = financial_projection["transactions"] + financial_projection["related_transactions"]
    nft_data = getattr(report, "nft_intelligence", None)
    input_resolution = getattr(report, "input_resolution", None) or {}
    verified_nft_kinds = {}
    for asset in (nft_data or {}).get("assets", []):
        address = ton_canonical_address(asset.get("address"))
        if address and asset.get("standard_status") == "verified_onchain":
            specialized = {"domain": "domain", "username": "telegram_username", "gift": "gift"}
            kind = specialized.get(asset.get("kind"), "nft") if asset.get("collection_status") == "verified_onchain" else "nft"
            verified_nft_kinds[_wallet_node_id("ton", address)] = kind
            verified_nft_kinds[_asset_node_id(address)] = kind
    g = nx.DiGraph()
    node_data: dict[str, dict[str, Any]] = {}
    edge_data: list[dict[str, Any]] = []

    def node(
        node_id: str,
        label: str,
        kind: str,
        title: str | None = None,
        chain: str = "ton",
        asset_type: str | None = None,
        weight: float = 1.0,
        source: str | None = None,
        evidence_url: str | None = None,
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
        labels: list[str] | None = None,
        image_url: str | None = None,
        image_source: str | None = None,
    ) -> None:
        if not node_id:
            return
        node_id = str(node_id)
        label = str(label or node_id)
        title = str(title or label)
        kind = kind if kind in NODE_LABELS else "wallet"
        # A verified NFT contract can be a root, counterparty or another NFT's
        # owner. Retain its address/IDs while avoiding a wallet classification.
        if chain == "ton" and node_id in verified_nft_kinds:
            kind = verified_nft_kinds[node_id]
        current = node_data.get(node_id, {})
        merged_labels = list(dict.fromkeys((current.get("labels") or []) + (labels or [])))
        sources = list(dict.fromkeys((current.get("sources") or []) + ([source] if source else [])))
        evidence = list(dict.fromkeys((current.get("evidence") or []) + ([evidence_url] if evidence_url else [])))
        seen_values = [item for item in (current.get("first_seen"), _dt(first_seen)) if item]
        last_values = [item for item in (current.get("last_seen"), _dt(last_seen)) if item]
        image = current.get("image_url") or _graph_image_url(image_url)
        g.add_node(node_id)
        node_data[node_id] = {
            "id": node_id,
            "label": label,
            "kind": kind,
            "kind_label": NODE_LABELS.get(kind, kind),
            "icon": NODE_ICONS.get(kind, "?"),
            "title": title,
            "chain": chain,
            "asset_type": asset_type or "",
            "weight": max(float(current.get("weight", 0.0)), float(weight)),
            "sources": sources,
            "evidence": evidence,
            "labels": merged_labels,
            "image_url": image,
            "image_source": current.get("image_source") or (image_source if image else ""),
            "first_seen": min(seen_values) if seen_values else None,
            "last_seen": max(last_values) if last_values else None,
        }

    def edge(
        src: str,
        dst: str,
        edge_type: str,
        *,
        chain: str = "ton",
        asset: str | None = None,
        tx_hash: str | None = None,
        source: str | None = None,
        amount: float | None = None,
        title: str | None = None,
        weight: float = 1.0,
        evidence_url: str | None = None,
        confidence: float | None = None,
        timestamp: datetime | None = None,
        count: int = 1,
        token_contract: str = "",
        sources: list[str] | None = None,
        evidence_urls: list[str] | None = None,
        event_ids: list[str] | None = None,
    ) -> None:
        if not src or not dst:
            return
        src = str(src)
        dst = str(dst)
        if src == dst and edge_type not in {"owns", "same_address"}:
            return
        g.add_edge(src, dst)
        edge_data.append(
            {
                "from": src,
                "to": dst,
                "type": edge_type,
                "label": EDGE_LABELS.get(edge_type, edge_type),
                "chain": chain,
                "asset": asset or "",
                "tx_hash": tx_hash or "",
                "source": source or "",
                "evidence_url": evidence_url or "",
                "confidence": confidence if confidence is not None else 0.62,
                "total": float(amount) if amount is not None else None,
                "amount_decimal": str(amount) if amount is not None else None,
                "transaction_hashes": list(dict.fromkeys(value.strip() for value in (tx_hash or "").split(",") if value.strip())),
                "sources": sources or ([source] if source else []),
                "evidence_urls": evidence_urls or ([evidence_url] if evidence_url else []),
                "event_ids": event_ids or [],
                "count": max(1, count),
                "token_contract": token_contract,
                "weight": max(1.0, min(14.0, float(weight))),
                "title": title or EDGE_LABELS.get(edge_type, edge_type),
                "first_seen": _dt(timestamp),
                "last_seen": _dt(timestamp),
                "timestamps": [_dt(timestamp)] if timestamp else [],
            }
        )

    labels = defaultdict(list)
    for label in report.labels:
        labels[(label.chain, label.address.lower())].append(label.label)

    risky = {
        _wallet_node_id(rf.chain, rf.address)
        for rf in report.risk_flags
        if rf.chain != "multi" and rf.severity in {"high", "medium"} and rf.address
    }

    node(
        target,
        _short(report.target_address),
        _wallet_kind(primary_chain, labels.get((primary_chain, report.target_address.lower()), [])),
        report.target_address,
        primary_chain,
        weight=14,
        labels=labels.get((primary_chain, report.target_address.lower()), []),
    )

    for chain in report.detected_chains:
        chain_target = _wallet_node_id(chain, report.target_address)
        if chain_target == target:
            continue
        node(chain_target, f"{chain}:{_short(report.target_address)}", _wallet_kind(chain), report.target_address, chain, weight=8)
        edge(target, chain_target, "same_address", chain=chain, source="detector", title=f"same address on {chain}", weight=2, confidence=0.86)

    ens_display = report.ens_name or report.reverse_ens
    if ens_display and "eth" in report.detected_chains:
        eth_wallet = _wallet_node_id("eth", report.target_address)
        records_count = len(report.text_records or {})
        resolver = report.resolver or report.ens_reverse_resolver or ""
        profile = getattr(report, "ens_profile", {}) or {}
        verified = bool(report.ens_name and report.ens_resolved_address and report.ens_resolved_address.lower() == report.target_address.lower())
        resolver_short = _short(resolver) if resolver else "unavailable"
        ens_node = f"ens:{ens_display.lower()}"
        node(eth_wallet, _short(report.target_address), _wallet_kind("eth", labels.get(("eth", report.target_address.lower()), [])), report.target_address, "eth", weight=9, labels=labels.get(("eth", report.target_address.lower()), []))
        node(
            ens_node,
            ens_display,
            "ens_identity",
            f"{ens_display} | resolver {resolver_short} | records {records_count}",
            "eth",
            "ens",
            weight=6,
            source="ethereum_ens",
            labels=[f"resolver: {resolver_short}", f"records: {records_count}", "verified" if verified else "unverified"],
        )
        edge(
            eth_wallet,
            ens_node,
            "ens_resolution" if verified else "ens_reverse_record",
            chain="eth",
            asset="ENS",
            source="ethereum_ens",
            title=f"{'verified forward resolution; not registration ownership' if verified else 'unverified reverse publication'} | {ens_display}",
            weight=5 if verified else 2,
            confidence=0.94 if verified else 0.38,
            evidence_url=profile.get("source_url"),
        )
        edge_data[-1].update({"transaction_edge": False, "monetary": False,
            "relationship": "ens_resolution" if verified else "ens_reverse_record",
            "verification": "forward_verified" if verified else "unverified",
            "primary_name_verified": bool(profile.get("primary_verified")) if profile else bool(report.ens_reverse_valid and report.reverse_ens == ens_display),
            "directed": False,
            "provenance": profile.get("provenance", {})})
        if report.ens_resolved_address:
            resolved_wallet = _wallet_node_id("eth", report.ens_resolved_address)
            node(resolved_wallet, _short(report.ens_resolved_address), _wallet_kind("eth", labels.get(("eth", report.ens_resolved_address.lower()), [])), report.ens_resolved_address, "eth", weight=3, source="ethereum_ens", labels=labels.get(("eth", report.ens_resolved_address.lower()), []))
            edge(
                ens_node,
                resolved_wallet,
                "resolves",
                chain="eth",
                asset="ENS",
                source="ethereum_ens",
                title=f"resolves | {ens_display}",
                weight=4 if verified else 2,
                confidence=0.92 if verified else 0.36,
                evidence_url=profile.get("source_url"),
            )
            edge_data[-1].update({"transaction_edge": False, "monetary": False, "directed": False,
                "relationship": "ens_resolution", "verification": "forward_verified" if verified else "provider_reported",
                "provenance": profile.get("provenance", {})})

    tx_edges = defaultdict(lambda: {"count": 0, "total": Decimal(0), "asset": "", "chain": "", "source": "", "evidence_url": "", "first_seen": None, "last_seen": None, "tx_hashes": [], "sources": [], "evidence_urls": [], "event_ids": []})
    tx_detail_count = 0
    for tx in graph_transactions:
        chain_target = _wallet_node_id(tx.chain, report.target_address)
        if tx.chain in {"btc", "doge"} and tx.tx_hash and (tx.inputs or tx.outputs) and tx_detail_count < 80:
            tx_detail_count += 1
            tx_node = _tx_node_id(tx.tx_hash, tx.chain)
            tx_kind = "doge_transaction" if tx.chain == "doge" else "bitcoin_tx"
            input_edge = "doge_input" if tx.chain == "doge" else "btc_input"
            output_edge = "doge_output" if tx.chain == "doge" else "btc_output"
            asset_name = "DOGE" if tx.chain == "doge" else "BTC"
            tx_labels = []
            if tx.fee is not None:
                tx_labels.append(f"fee: {tx.fee}")
            if tx.confirmations is not None:
                tx_labels.append(f"confirmations: {tx.confirmations}")
            node(tx_node, _short(tx.tx_hash), tx_kind, tx.tx_hash, tx.chain, tx_kind, weight=1.7, source=tx.source, evidence_url=tx.url, first_seen=tx.timestamp, last_seen=tx.timestamp, labels=tx_labels)
            for item in tx.inputs[:24]:
                address = _btc_io_address(item)
                if not address:
                    continue
                wallet = _wallet_node_id(tx.chain, address)
                wallet_labels = labels.get((tx.chain, address.lower()), [])
                wallet_kind = _wallet_kind(tx.chain, wallet_labels)
                if tx.chain == "doge" and wallet != target and not wallet_labels:
                    wallet_kind = "doge_counterparty"
                node(wallet, _short(address), wallet_kind, "; ".join(wallet_labels) or address, tx.chain, weight=3 if wallet == target else 2, source=tx.source, evidence_url=tx.url, first_seen=tx.timestamp, last_seen=tx.timestamp, labels=wallet_labels)
                edge(wallet, tx_node, input_edge, chain=tx.chain, asset=asset_name, tx_hash=tx.tx_hash, source=tx.source, amount=_btc_io_value(item), title=f"input | {asset_name} | {_btc_io_value(item):.8f}", weight=1.6 if wallet == target else 1.1, evidence_url=tx.url, confidence=0.72, timestamp=tx.timestamp)
            for item in tx.outputs[:32]:
                address = _btc_io_address(item)
                if not address:
                    continue
                wallet = _wallet_node_id(tx.chain, address)
                wallet_labels = labels.get((tx.chain, address.lower()), [])
                wallet_kind = _wallet_kind(tx.chain, wallet_labels)
                if tx.chain == "doge" and wallet != target and not wallet_labels:
                    wallet_kind = "doge_counterparty"
                node(wallet, _short(address), wallet_kind, "; ".join(wallet_labels) or address, tx.chain, weight=3 if wallet == target else 2, source=tx.source, evidence_url=tx.url, first_seen=tx.timestamp, last_seen=tx.timestamp, labels=wallet_labels)
                edge(tx_node, wallet, output_edge, chain=tx.chain, asset=asset_name, tx_hash=tx.tx_hash, source=tx.source, amount=_btc_io_value(item), title=f"output | {asset_name} | {_btc_io_value(item):.8f}", weight=1.6 if wallet == target else 1.1, evidence_url=tx.url, confidence=0.72, timestamp=tx.timestamp)
            continue
        if tx.chain == "solana" and tx.tx_hash and tx_detail_count < 80:
            tx_detail_count += 1
            tx_node = _tx_node_id(tx.tx_hash, tx.chain)
            raw = tx.raw or {}
            tx_labels = []
            if tx.fee is not None:
                tx_labels.append(f"fee: {tx.fee}")
            if raw.get("slot") is not None:
                tx_labels.append(f"slot: {raw.get('slot')}")
            status = str(raw.get("status") or "")
            if status:
                tx_labels.append(status)
            node(tx_node, _short(tx.tx_hash), "solana_tx", tx.tx_hash, "solana", "solana_tx", weight=1.6, source=tx.source, evidence_url=tx.url, first_seen=tx.timestamp, last_seen=tx.timestamp, labels=tx_labels)
            solana_target = _wallet_node_id("solana", report.target_address)
            accounts = [str(item) for item in raw.get("account_keys") or [] if item]
            signers = [str(item) for item in raw.get("signers") or [] if item]
            if report.target_address in accounts or report.target_address in signers or (not tx.from_address and not tx.to_address):
                node(solana_target, _short(report.target_address), _wallet_kind("solana", labels.get(("solana", report.target_address.lower()), [])), report.target_address, "solana", weight=3, source=tx.source, evidence_url=tx.url, first_seen=tx.timestamp, last_seen=tx.timestamp, labels=labels.get(("solana", report.target_address.lower()), []))
                edge(solana_target, tx_node, "interacted_with", chain="solana", asset=tx.asset, tx_hash=tx.tx_hash, source=tx.source, amount=tx.amount, title=f"solana tx | {tx.asset or ''}", weight=1.4, evidence_url=tx.url, confidence=0.7, timestamp=tx.timestamp)
            for program_id in [str(item) for item in raw.get("program_ids") or [] if item][:8]:
                program_node = f"program:solana:{program_id}"
                node(program_node, _short(program_id), "solana_program", program_id, "solana", "program", weight=2.4, source=tx.source, evidence_url=tx.url, first_seen=tx.timestamp, last_seen=tx.timestamp)
                edge(tx_node, program_node, "interacted_with", chain="solana", asset="program", tx_hash=tx.tx_hash, source=tx.source, title=f"program | {_short(program_id)}", weight=1.2, evidence_url=tx.url, confidence=0.68, timestamp=tx.timestamp)
        if not tx.from_address or not tx.to_address:
            continue
        src_id = _wallet_node_id(tx.chain, tx.from_address)
        dst_id = _wallet_node_id(tx.chain, tx.to_address)
        src_labels = labels.get((tx.chain, tx.from_address.lower()), [])
        dst_labels = labels.get((tx.chain, tx.to_address.lower()), [])
        src_kind = "cluster" if src_id in risky else _wallet_kind(tx.chain, src_labels)
        dst_kind = "cluster" if dst_id in risky else _wallet_kind(tx.chain, dst_labels)
        node(src_id, _short(tx.from_address), src_kind, "; ".join(src_labels) or tx.from_address, tx.chain, weight=2, source=tx.source, evidence_url=tx.url, first_seen=tx.timestamp, last_seen=tx.timestamp, labels=src_labels)
        node(dst_id, _short(tx.to_address), dst_kind, "; ".join(dst_labels) or tx.to_address, tx.chain, weight=2, source=tx.source, evidence_url=tx.url, first_seen=tx.timestamp, last_seen=tx.timestamp, labels=dst_labels)
        # Provider action records interpret transactions/messages; they are
        # retained in the report, not counted again as independent payments.
        raw = tx.raw or {}
        if tx.chain == "ton" and (raw.get("provider") == "tonapi_events" or raw.get("asset_type") == "action" or raw.get("action_index") is not None):
            continue

        token_contract = str((tx.raw or {}).get("token_contract") or (tx.raw or {}).get("contract") or "")
        if tx.chain == "tron" and ((tx.raw or {}).get("type") in {"resource", "permission_update"} or is_tron_non_monetary(tx)):
            edge(src_id, dst_id, "interacted_with", chain=tx.chain, asset="resource / permission",
                tx_hash=tx.tx_hash, source=tx.source, evidence_url=tx.url, timestamp=tx.timestamp,
                title="Resource / permission operation; no payment inferred", confidence=0)
            if src_id != dst_id:
                edge_data[-1].update(relationship_type="resource_or_permission_observation",
                    verification_status="POSSIBLE" if transaction_success(tx) is False else "PROBABLE")
            continue
        if (tx.raw or {}).get("type") == "approval":
            edge(src_id, dst_id, "interacted_with", chain=tx.chain, asset=tx.asset,
                tx_hash=tx.tx_hash, source=tx.source, evidence_url=tx.url, timestamp=tx.timestamp,
                token_contract=token_contract, title="Token approval / allowance observation; no asset transfer", confidence=0)
            if src_id != dst_id:
                edge_data[-1].update(relationship_type="token_allowance_observation",
                    verification_status="POSSIBLE" if transaction_success(tx) is False else "PROBABLE",
                    allowance_decimal=str(getattr(tx,"amount_decimal",None)) if getattr(tx,"amount_decimal",None) is not None else None)
            continue
        # Incomplete or failed source operations cannot assert a monetary edge.
        # The original Transaction remains available in tables and evidence.
        exact_amount = getattr(tx, "amount_decimal", None)
        if exact_amount is None:
            exact_amount = tx.amount
        if (exact_amount is None or not all(str(value or "").strip() for value in (tx.asset, tx.source, tx.tx_hash))
                or transaction_success(tx) is False):
            continue
        try:
            exact_amount = Decimal(str(exact_amount))
        except (InvalidOperation, ValueError, TypeError):
            continue
        if not exact_amount.is_finite() or exact_amount < 0:
            continue
        key = (tx.chain, src_id, dst_id, tx.asset, token_contract)
        item = tx_edges[key]
        item["count"] += 1
        item["total"] += exact_amount
        item["sources"] = list(dict.fromkeys(item["sources"] + [tx.source]))
        item["evidence_urls"] = list(dict.fromkeys(item["evidence_urls"] + ([tx.url] if tx.url else [])))
        if getattr(tx, "event_id", None):
            item["event_ids"].append(tx.event_id)
        item["asset"] = tx.asset or ""
        item["chain"] = tx.chain
        item["source"] = tx.source
        item["evidence_url"] = item["evidence_url"] or tx.url or ""
        item["first_seen"] = min([value for value in (item["first_seen"], tx.timestamp) if value], default=None)
        item["last_seen"] = max([value for value in (item["last_seen"], tx.timestamp) if value], default=None)
        if tx.tx_hash:
            item["tx_hashes"].append(tx.tx_hash)
        if tx.tx_hash and tx_detail_count < 80 and (src_id == chain_target or dst_id == chain_target):
            tx_detail_count += 1
            tx_node = _tx_node_id(tx.tx_hash, tx.chain)
            tx_kind = "tron_tx" if tx.chain == "tron" else "solana_tx" if tx.chain == "solana" else "bsc_tx" if tx.chain == "bsc" else "transaction"
            node(tx_node, _short(tx.tx_hash), tx_kind, tx.tx_hash, tx.chain, weight=1.5, source=tx.source, evidence_url=tx.url, first_seen=tx.timestamp, last_seen=tx.timestamp)
            is_contract_call = (tx.raw or {}).get("type") == "contract_call"
            relation = "interacted_with" if is_contract_call else "sent" if src_id == chain_target else "received" if dst_id == chain_target else "interacted_with"
            edge(src_id, tx_node, relation, chain=tx.chain, asset=tx.asset, tx_hash=tx.tx_hash, source=tx.source, amount=exact_amount, title=f"{EDGE_LABELS.get(relation, relation)} {tx.asset or ''} {exact_amount}", weight=1.5, evidence_url=tx.url, confidence=0.72, timestamp=tx.timestamp)
            edge(tx_node, dst_id, relation, chain=tx.chain, asset=tx.asset, tx_hash=tx.tx_hash, source=tx.source, amount=exact_amount, title=f"{EDGE_LABELS.get(relation, relation)} {tx.asset or ''} {exact_amount}", weight=1.5, evidence_url=tx.url, confidence=0.72, timestamp=tx.timestamp)
            token_contract = str((tx.raw or {}).get("token_contract") or (tx.raw or {}).get("contract") or "")
            if tx.chain == "bsc" and token_contract:
                asset_type = str((tx.raw or {}).get("asset_type") or "")
                token_kind = "bsc_nft" if asset_type in {"bep721", "bep1155"} else "bep20_token"
                token_label = str((tx.raw or {}).get("token_symbol") or tx.asset or _short(token_contract))
                token_node = _asset_node_id(token_contract, tx.chain)
                node(token_node, _short(token_label), token_kind, str((tx.raw or {}).get("token_name") or token_label), tx.chain, asset_type or token_kind, weight=2.5, source=tx.source, evidence_url=tx.url, image_url=_graph_image_url(tx.raw or {}), image_source=tx.source)
                edge(tx_node, token_node, "transfer", chain=tx.chain, asset=tx.asset, tx_hash=tx.tx_hash, source=tx.source, amount=tx.amount, title=f"token event | {token_label}", weight=1.4, evidence_url=tx.url, confidence=0.72, timestamp=tx.timestamp)
            if tx.chain == "tron" and token_contract:
                token_label = str((tx.raw or {}).get("token_symbol") or tx.asset or _short(token_contract))
                token_kind = "usdt_trc20" if token_contract == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t" or token_label.upper() == "USDT" else "trc20_token"
                token_node = _asset_node_id(token_contract, tx.chain)
                node(token_node, _short(token_label), token_kind, str((tx.raw or {}).get("token_name") or token_label), tx.chain, token_kind, weight=2.5, source=tx.source, evidence_url=tx.url, image_url=_graph_image_url(tx.raw or {}), image_source=tx.source)
                edge(tx_node, token_node, "transfer", chain=tx.chain, asset=tx.asset, tx_hash=tx.tx_hash, source=tx.source, amount=tx.amount, title=f"TRC20 event | {token_label}", weight=1.4, evidence_url=tx.url, confidence=0.72, timestamp=tx.timestamp)

    for (chain, src, dst, asset, token_contract), data in tx_edges.items():
        chain_target = _wallet_node_id(chain, report.target_address)
        relation = "sent" if src == chain_target else "received" if dst == chain_target else "interacted_with"
        title = f"{EDGE_LABELS.get(relation, relation)} | {chain} | {asset} | tx={data['count']} | total={data['total']}"
        edge(src, dst, relation, chain=chain, asset=asset, tx_hash=", ".join(dict.fromkeys(data["tx_hashes"])), source=data["source"], amount=data["total"], title=title, weight=min(14, data["count"] * 1.2 + (float(data["total"]) ** 0.5 if data["total"] > 0 else 0)), evidence_url=data["evidence_url"], confidence=0.7, timestamp=data["last_seen"], count=data["count"], token_contract=token_contract, sources=data["sources"], evidence_urls=data["evidence_urls"], event_ids=data["event_ids"])

    for token in report.tokens:
        contract = token.contract or token.symbol or token.name
        if not contract:
            continue
        kind = _token_kind(token)
        token_node = _asset_node_id(contract, token.chain)
        owner = _wallet_node_id(token.chain, token.address)
        title = token.name or token.symbol or contract
        node(owner, _short(token.address), _wallet_kind(token.chain), token.address, token.chain, weight=2, source=token.source, evidence_url=token.url)
        node(token_node, _short(title), kind, title, token.chain, kind, weight=3, source=token.source, evidence_url=token.url, image_url=_graph_image_url(token.raw or {}), image_source=token.source)
        holding_relation = "owns" if getattr(token, "holding_status", "unknown") == "current" else "owned_before" if getattr(token, "holding_status", "unknown") == "historical" else "linked_by"
        edge(owner, token_node, holding_relation, chain=token.chain, asset=token.symbol or token.name or kind, source=token.source, amount=token.amount, title=f"owns | {title}", weight=3, evidence_url=token.url, confidence=0.74)

    if report.dogecoin:
        doge_wallet = _wallet_node_id("doge", report.target_address)
        node(doge_wallet, _short(report.target_address), _wallet_kind("doge", labels.get(("doge", report.target_address.lower()), [])), report.target_address, "doge", "doge_wallet", weight=7, source="dogecoin")
        for item in list((report.dogecoin or {}).get("utxos") or [])[:32]:
            txid = str(item.get("tx_hash") or item.get("txid") or "")
            vout = str(item.get("vout") if item.get("vout") is not None else "")
            if not txid:
                continue
            value = _btc_io_value(item)
            utxo_node = f"doge_utxo:{txid.lower()}:{vout}"
            node(utxo_node, f"{value:.4f} DOGE", "doge_utxo", f"{txid}:{vout}", "doge", "doge_utxo", weight=1.8, source=item.get("source") or "blockchair_dogecoin", evidence_url=item.get("url") or "", labels=[str(item.get("status") or "unspent")])
            edge(doge_wallet, utxo_node, "owns", chain="doge", asset="DOGE", tx_hash=txid, source=item.get("source") or "blockchair_dogecoin", amount=value, title=f"unspent DOGE | {value:.8f}", weight=1.5, evidence_url=item.get("url") or "", confidence=0.72)
        for label in report.labels:
            if label.chain != "doge":
                continue
            if not any(marker in label.label.lower() for marker in EXCHANGE_MARKERS):
                continue
            label_node = f"doge_exchange:{label.address.lower()}:{label.label.lower()}"
            wallet = _wallet_node_id("doge", label.address)
            node(wallet, _short(label.address), "doge_counterparty", label.address, "doge", "doge_counterparty", weight=3, source=label.source, labels=[label.label])
            node(label_node, label.label[:32], "doge_exchange_label", label.label, "doge", "doge_exchange_label", weight=3, source=label.source, labels=[label.label])
            edge(wallet, label_node, "confirmed_by", chain="doge", source=label.source, title=label.label, weight=2, confidence=label.confidence)

    jetton_lookup: dict[str, dict[str, str]] = {}
    for token in report.tokens:
        if token.chain != "ton" or (token.raw or {}).get("asset_type") != "jetton":
            continue
        title = token.symbol or token.name or token.contract or "JETTON"
        data = {"id": token.contract or title, "title": title, "source": token.source, "url": token.url or "", "image": _graph_image_url(token.raw or {})}
        for key in (token.contract, token.symbol, token.name):
            if key:
                jetton_lookup[str(key).strip().lower()] = data
    for asset in report.ton_assets:
        if asset.type != "jetton":
            continue
        title = asset.title or asset.name or asset.asset_id
        data = {"id": asset.asset_id or title, "title": title, "source": asset.source, "url": asset.evidence_url or asset.external_url or "", "image": _graph_image_url(asset.image_url, asset.raw or {})}
        for key in (asset.asset_id, asset.title, asset.name):
            if key:
                jetton_lookup[str(key).strip().lower()] = data
    jetton_detail_count = 0
    jetton_edge_count = 0
    ton_target = _wallet_node_id("ton", report.target_address)
    for tx in graph_transactions:
        if not _is_ton_jetton_tx(tx) or jetton_edge_count >= 80:
            continue
        label = str(tx.asset or "JETTON").removeprefix("JETTON:") or "JETTON"
        raw = tx.raw or {}
        master = str(raw.get("jetton_master") or raw.get("contract") or raw.get("token_contract") or "")
        data = jetton_lookup.get(master.lower()) or jetton_lookup.get(label.lower()) or {"id": master or label, "title": label, "source": tx.source, "url": tx.url or "", "image": _graph_image_url(tx.raw or {})}
        jetton_node = _asset_node_id(data["id"])
        node(jetton_node, _short(data["title"]), "jetton", data["title"], "ton", "jetton", weight=3, source=data.get("source") or tx.source, evidence_url=data.get("url") or tx.url, image_url=data.get("image"), image_source=data.get("source") or tx.source)
        principal = tx.amount_decimal if tx.amount_decimal is not None else tx.amount
        operation_ids = [tx.event_id] if tx.event_id else []
        if ton_target in node_data and tx.direction in {"in", "out"}:
            src, dst = (jetton_node, ton_target) if tx.direction == "in" else (ton_target, jetton_node)
            edge(src, dst, "jetton_flow", chain="ton", asset=tx.asset, tx_hash=tx.tx_hash, source=tx.source,
                amount=principal, title=f"jetton participation | {label} | {tx.direction}", weight=2,
                evidence_url=tx.url, confidence=0.7, timestamp=tx.timestamp, event_ids=operation_ids)
            edge_data[-1].update(transaction_edge=False, monetary=False,
                relationship_type="asset_participation", direction=tx.direction,
                explanation="Asset participation in the referenced real transfer; the asset node is not an account or an additional payment.")
        counterparty = tx.from_address if tx.direction == "in" else tx.to_address if tx.direction == "out" else ""
        if counterparty:
            cp_id = _wallet_node_id("ton", counterparty)
            if cp_id not in node_data:
                node(cp_id, _short(counterparty), "jetton_counterparty", counterparty, "ton", "jetton_counterparty", weight=2, source=tx.source, evidence_url=tx.url, last_seen=tx.timestamp)
            src, dst = (cp_id, jetton_node) if tx.direction == "in" else (jetton_node, cp_id)
            edge(src, dst, "jetton_flow", chain="ton", asset=tx.asset, tx_hash=tx.tx_hash, source=tx.source,
                amount=principal, title=f"jetton participation | {label} | {tx.direction}", weight=2,
                evidence_url=tx.url, confidence=0.7, timestamp=tx.timestamp, event_ids=operation_ids)
            edge_data[-1].update(transaction_edge=False, monetary=False,
                relationship_type="asset_participation", direction=tx.direction,
                explanation="Asset participation in the referenced real transfer; the asset node is not an account or an additional payment.")
        if tx.tx_hash and jetton_detail_count < 24:
            jetton_detail_count += 1
            tx_node = f"jetton_transfer:{tx.tx_hash}:{label.lower()}"
            node(tx_node, _short(tx.tx_hash), "jetton_transfer", tx.tx_hash, "ton", "jetton_transfer", weight=1.5, source=tx.source, evidence_url=tx.url, first_seen=tx.timestamp, last_seen=tx.timestamp)
            edge(tx_node, jetton_node, "jetton_flow", chain="ton", asset=tx.asset, tx_hash=tx.tx_hash, source=tx.source,
                title=f"jetton transfer record | {label}", weight=1.5, evidence_url=tx.url,
                confidence=0.7, timestamp=tx.timestamp, event_ids=operation_ids)
            edge_data[-1].update(transaction_edge=False, monetary=False,
                relationship_type="asset_participation",
                explanation="Transfer record references this asset; no additional monetary movement is asserted.")
        jetton_edge_count += 1

    for asset in report.ton_assets:
        asset_node = _asset_node_id(asset.asset_id)
        kind = "telegram_username" if asset.type == "username" else _asset_kind(asset.type)
        title = asset.title or asset.name or asset.asset_id
        node(asset_node, title[:32], kind, title, "ton", asset.type, weight=5, source=asset.source, evidence_url=asset.evidence_url, first_seen=asset.first_seen, last_seen=asset.last_seen, image_url=_graph_image_url(asset.image_url, asset.raw or {}), image_source=asset.source)
        if asset.owner_address:
            owner_id = _wallet_node_id("ton", asset.owner_address)
            node(owner_id, _short(asset.owner_address), "wallet", asset.owner_address, "ton", weight=3, source=asset.source, evidence_url=asset.evidence_url, last_seen=asset.last_seen)
            relation = "owns" if getattr(asset, "ownership_status", "unknown") == "current" and getattr(asset, "ownership_verified", False) else "owned_before" if getattr(asset, "ownership_status", "unknown") == "historical" else "linked_by"
            edge(owner_id, asset_node, relation, asset=asset.type, source=asset.source, title=f"{relation} | {title}", weight=5, evidence_url=asset.evidence_url, confidence=asset.confidence, timestamp=asset.last_seen)
        if asset.marketplace:
            market_id = _market_node_id(asset.marketplace)
            node(market_id, asset.marketplace, "marketplace", asset.marketplace, "ton", "marketplace", weight=4, source=asset.source, evidence_url=asset.evidence_url, image_url=_marketplace_image_url(asset.marketplace), image_source=asset.marketplace)
            listing_active = str((asset.raw or {}).get("listing_status") or "").lower() == "active"
            edge(asset_node, market_id, "listed_on" if listing_active else "marketplace_interaction", asset=asset.type, source=asset.source, amount=asset.floor_price, title=f"listed on | {asset.marketplace}", weight=3, evidence_url=asset.evidence_url, confidence=asset.confidence, timestamp=asset.last_seen)
        for previous in asset.previous_owners:
            if not previous:
                continue
            previous_id = _wallet_node_id("ton", previous)
            if previous_id not in node_data:
                node(previous_id, _short(previous), "username_owner" if asset.type == "username" else "wallet", previous, "ton", weight=2, source=asset.source, evidence_url=asset.evidence_url)
            edge(previous_id, asset_node, "owned_before", asset=asset.type, source=asset.source, title=f"owned before | {title}", weight=2, evidence_url=asset.evidence_url, confidence=asset.confidence, timestamp=asset.first_seen)
            if asset.type == "username":
                edge(asset_node, previous_id, "username_owner", asset=asset.type, source=asset.source, title=f"username previous owner | {title}", weight=2, evidence_url=asset.evidence_url, confidence=asset.confidence, timestamp=asset.first_seen)
        for event_item in asset.transfer_history + asset.sale_history:
            event_type = event_item.event_type
            if event_item.marketplace:
                market_id = _market_node_id(event_item.marketplace)
                node(market_id, event_item.marketplace, "marketplace", event_item.marketplace, "ton", "marketplace", weight=4, source=event_item.source, evidence_url=event_item.evidence_url, image_url=_marketplace_image_url(event_item.marketplace), image_source=event_item.marketplace)
                edge(asset_node, market_id, "marketplace_interaction", asset=asset.type, tx_hash=event_item.tx_hash, source=event_item.source, amount=event_item.price, title=f"marketplace interaction | {event_item.marketplace}", weight=3, evidence_url=event_item.evidence_url, confidence=event_item.confidence, timestamp=event_item.timestamp)
            if event_item.tx_hash:
                tx_node = _tx_node_id(event_item.tx_hash)
                node(tx_node, _short(event_item.tx_hash), "username_transfer" if asset.type == "username" else "transaction", event_item.tx_hash, "ton", weight=1.5, source=event_item.source, evidence_url=event_item.evidence_url, first_seen=event_item.timestamp, last_seen=event_item.timestamp)
                edge(tx_node, asset_node, event_type, asset=asset.type, tx_hash=event_item.tx_hash, source=event_item.source, title=f"{EDGE_LABELS.get(event_type, event_type)} | {title}", weight=2.5, evidence_url=event_item.evidence_url, confidence=event_item.confidence, timestamp=event_item.timestamp)
                if asset.type == "username":
                    edge(asset_node, tx_node, "username_transfer", asset=asset.type, tx_hash=event_item.tx_hash, source=event_item.source, title=f"username transfer | {title}", weight=2.5, evidence_url=event_item.evidence_url, confidence=event_item.confidence, timestamp=event_item.timestamp)
            if event_item.from_address:
                from_id = _wallet_node_id("ton", event_item.from_address)
                node(from_id, _short(event_item.from_address), "wallet", event_item.from_address, "ton", weight=2, source=event_item.source, evidence_url=event_item.evidence_url, last_seen=event_item.timestamp)
                edge(from_id, asset_node, "sold" if event_type == "sale" else "transferred", asset=asset.type, tx_hash=event_item.tx_hash, source=event_item.source, amount=event_item.price, title=f"{EDGE_LABELS.get(event_type, event_type)} | {title}", weight=3, evidence_url=event_item.evidence_url, confidence=event_item.confidence, timestamp=event_item.timestamp)
                if asset.type == "gift":
                    edge(asset_node, from_id, "gift_sender", asset=asset.type, tx_hash=event_item.tx_hash, source=event_item.source, title=f"gift sender | {title}", weight=2, evidence_url=event_item.evidence_url, confidence=event_item.confidence, timestamp=event_item.timestamp)
            if event_item.to_address:
                to_id = _wallet_node_id("ton", event_item.to_address)
                node(to_id, _short(event_item.to_address), "wallet", event_item.to_address, "ton", weight=2, source=event_item.source, evidence_url=event_item.evidence_url, last_seen=event_item.timestamp)
                edge(to_id if event_type == "sale" else asset_node, asset_node if event_type == "sale" else to_id, "bought" if event_type == "sale" else "received_asset", asset=asset.type, tx_hash=event_item.tx_hash, source=event_item.source, amount=event_item.price, title=f"{EDGE_LABELS.get(event_type, event_type)} | {title}", weight=3, evidence_url=event_item.evidence_url, confidence=event_item.confidence, timestamp=event_item.timestamp)
                if asset.type == "gift":
                    edge(asset_node, to_id, "gift_receiver", asset=asset.type, tx_hash=event_item.tx_hash, source=event_item.source, title=f"gift receiver | {title}", weight=2, evidence_url=event_item.evidence_url, confidence=event_item.confidence, timestamp=event_item.timestamp)

    for identity in report.telegram_identities:
        if identity.confidence == "unknown":
            continue
        relation = "confirmed_by" if identity.confidence == "confirmed" else "linked_by"
        weight = 5 if identity.confidence == "confirmed" else 3
        confidence = _confidence(identity.confidence)
        identity_avatar = _graph_image_url((identity.raw or {}).get("avatar"), (identity.raw or {}).get("image"), identity.raw or {})
        wallet_id = _wallet_node_id("ton", identity.wallet_address or report.target_address)
        node(wallet_id, _short(identity.wallet_address or report.target_address), "wallet", identity.wallet_address or report.target_address, "ton", weight=3, source=identity.source, evidence_url=identity.evidence_url)
        if identity.username:
            identity_node = f"telegram:username:{identity.username.lower()}"
            node(identity_node, f"@{identity.username}", "telegram_username", f"Telegram username @{identity.username}", "ton", "username", weight=5, source=identity.source, evidence_url=identity.evidence_url, image_url=identity_avatar, image_source=identity.source)
            edge(wallet_id, identity_node, relation, source=identity.source, title=f"{EDGE_LABELS.get(relation, relation)} | {identity.confidence}", weight=weight, evidence_url=identity.evidence_url, confidence=confidence)
        if identity.telegram_user_id:
            identity_node = f"telegram:id:{identity.telegram_user_id}"
            node(identity_node, identity.telegram_user_id, "telegram_id", f"Telegram ID {identity.telegram_user_id}", "ton", "telegram_id", weight=5, source=identity.source, evidence_url=identity.evidence_url, image_url=identity_avatar, image_source=identity.source)
            edge(wallet_id, identity_node, relation, source=identity.source, title=f"{EDGE_LABELS.get(relation, relation)} | {identity.confidence}", weight=weight, evidence_url=identity.evidence_url, confidence=confidence)
        for domain in identity.domains:
            domain_node = f"domain:{domain.lower()}"
            node(domain_node, domain, "domain", domain, "ton", "domain", weight=4, source=identity.source, evidence_url=identity.evidence_url)
            edge(wallet_id, domain_node, relation, source=identity.source, title=f"{EDGE_LABELS.get(relation, relation)} | {domain}", weight=weight, evidence_url=identity.evidence_url, confidence=confidence)
        for gift in identity.gifts:
            gift_node = f"gift:{gift.lower()}"
            node(gift_node, gift[:32], "gift", gift, "ton", "gift", weight=4, source=identity.source, evidence_url=identity.evidence_url)
            edge(wallet_id, gift_node, relation, source=identity.source, title=f"{EDGE_LABELS.get(relation, relation)} | {gift}", weight=weight, evidence_url=identity.evidence_url, confidence=confidence)
        for asset_id in identity.asset_ids:
            asset_node = _asset_node_id(asset_id)
            if asset_node in node_data:
                edge(wallet_id, asset_node, relation, asset="identity_asset", source=identity.source, title="linked through NFT metadata", weight=3, evidence_url=identity.evidence_url, confidence=confidence)

    # Structured evidence replaces legacy text-marker branding in this graph;
    # the existing analytic detections remain in the report as separate hints.
    for detection in (report.service_detections if not report.attribution_intelligence else []):
        service_id = f"service:{detection.category}:{detection.name.lower()}:{detection.address.lower()}"
        kind = "exchange" if detection.category == "exchange" else "marketplace" if detection.category == "marketplace" else "service"
        wallet_id = _wallet_node_id(detection.chain if detection.chain != "multi" else primary_chain, report.target_address)
        node(service_id, detection.name, kind, detection.evidence or detection.name, detection.chain if detection.chain != "multi" else primary_chain, kind, weight=4, source=detection.source)
        edge(wallet_id, service_id, "interacted_with", chain=detection.chain if detection.chain != "multi" else primary_chain, source=detection.source, title=detection.evidence or detection.name, weight=3, confidence=detection.confidence)

    migration = report.wallet_migration
    if migration and migration.activity in {"high", "medium"}:
        for item in (migration.raw or {}).get("target_candidates", [])[:3]:
            address = str(item.get("address") or "").strip()
            chain = str(item.get("chain") or primary_chain)
            if not address:
                continue
            wallet_id = _wallet_node_id(chain, report.target_address)
            target_id = f"migration_target:{chain}:{_address_key(chain, address)}"
            source = ", ".join(migration.source[:3]) or "migration_detector"
            node(target_id, _short(address), "migration_target", address, chain, "migration_target", weight=5, source=source, labels=[migration.activity])
            edge(wallet_id, target_id, "migration_flow", chain=chain, asset="asset transfer", source=source, title=migration.observation, weight=4, confidence=0.74 if migration.confidence == "medium" else 0.86)

    tron_intel_kinds = {
        "USDT TRC20 Flow Activity": "usdt_trc20",
        "P2P / Exchange Flow Activity": "tron_exchange",
        "Resource Usage Activity": "tron_resource",
        "Permission Control Activity": "tron_permission",
        "TRON DeFi Activity": "tron_defi",
        "TRON Memecoin Activity": "sunpump_token",
        "Counterparty Intelligence": "trx_wallet",
        "Stablecoin Status": "usdt_trc20",
    }
    if report.tron_activity_intelligence:
        wallet_id = _wallet_node_id("tron", report.target_address)
        node(wallet_id, _short(report.target_address), _wallet_kind("tron", labels.get(("tron", report.target_address.lower()), [])), report.target_address, "tron", weight=3, source="tron_intelligence")
        for signal in report.tron_activity_intelligence:
            if signal.activity not in {"high", "medium", "low"}:
                continue
            kind = tron_intel_kinds.get(signal.title, "service")
            signal_id = f"tron-intel:{signal.title.lower().replace(' ', '-').replace('/', '-')}"
            node(signal_id, signal.title[:32], kind, signal.title, "tron", kind, weight=4 if signal.activity in {"high", "medium"} else 2.5, source=", ".join(signal.source[:3]) or "tron_intelligence", labels=[signal.activity, signal.confidence])
            edge(wallet_id, signal_id, "interacted_with", chain="tron", asset=signal.title, source=", ".join(signal.source[:3]) or "tron_intelligence", title=signal.observation, weight=3 if signal.activity in {"high", "medium"} else 1.8, confidence=0.72)
            facts = signal.facts or {}
            if signal.title == "P2P / Exchange Flow Activity":
                for address in facts.get("top_exchange_like_addresses") or []:
                    if not address:
                        continue
                    exchange_id = _wallet_node_id("tron", str(address))
                    node(exchange_id, _short(str(address)), "tron_exchange", str(address), "tron", "tron_exchange", weight=3, source=", ".join(signal.source[:3]) or "tron_intelligence")
                    edge(signal_id, exchange_id, "interacted_with", chain="tron", asset="exchange-like", source=", ".join(signal.source[:3]) or "tron_intelligence", title="exchange-like counterparty", weight=2, confidence=0.64)
            if signal.title == "TRON DeFi Activity":
                for address in facts.get("defi_contracts") or []:
                    if not address:
                        continue
                    contract_id = _wallet_node_id("tron", str(address))
                    node(contract_id, _short(str(address)), "tron_defi", str(address), "tron", "tron_defi", weight=3, source=", ".join(signal.source[:3]) or "tron_intelligence")
                    edge(signal_id, contract_id, "interacted_with", chain="tron", asset="defi", source=", ".join(signal.source[:3]) or "tron_intelligence", title="DeFi interaction", weight=2, confidence=0.64)

    for flag in report.risk_flags:
        if flag.chain != "bsc":
            continue
        risk_id = f"risk:bsc:{flag.source}:{flag.flag}:{flag.address.lower()}"
        wallet_id = _wallet_node_id("bsc", report.target_address)
        node(risk_id, flag.flag[:32], "risk_source", flag.details or flag.flag, "bsc", "risk", weight=3 if flag.severity == "high" else 2, source=flag.source, labels=[flag.severity])
        edge(wallet_id, risk_id, "linked_by", chain="bsc", asset=flag.severity, source=flag.source, title=flag.details or flag.flag, weight=3 if flag.severity == "high" else 2, confidence=0.68)

    for index, chain in enumerate(report.activity_chains[:32]):
        activity_chain = str((chain.raw or {}).get("chain") or primary_chain)
        chain_node = f"activity:{index}:{chain.chain_type}"
        node(chain_node, chain.title[:32], "activity", chain.summary, "multi", chain.chain_type, weight=4, source=chain.source, evidence_url=chain.evidence_url, first_seen=chain.first_seen, last_seen=chain.last_seen)
        if chain.asset:
            asset_node = _asset_node_id(chain.asset, activity_chain)
            asset_kind = "jetton" if chain.asset.startswith("JETTON:") else "nft" if chain.asset.startswith("NFT:") else "token" if activity_chain == "eth" else "contract"
            node(asset_node, _short(chain.asset), asset_kind, chain.asset, activity_chain, chain.chain_type, weight=2, source=chain.source, evidence_url=chain.evidence_url)
            edge(chain_node, asset_node, "activity_path", asset=chain.asset, source=chain.source, title=chain.summary, weight=3, evidence_url=chain.evidence_url, confidence=chain.confidence, timestamp=chain.last_seen)
        for address in chain.addresses[:10]:
            if not address:
                continue
            wallet = _wallet_node_id(activity_chain, address)
            node(wallet, _short(address), _wallet_kind(activity_chain), address, activity_chain, weight=2, source=chain.source, evidence_url=chain.evidence_url, first_seen=chain.first_seen, last_seen=chain.last_seen)
            edge(wallet, chain_node, "activity_path", asset=chain.asset, source=chain.source, title=chain.summary, weight=2, evidence_url=chain.evidence_url, confidence=chain.confidence, timestamp=chain.last_seen)

    unified = getattr(report, "attribution_intelligence", None) or {}
    service_data = {} if unified else getattr(report, "ton_service_intelligence", None) or {}
    service_records = service_data.get("addresses", {})
    service_evidence = {row.get("evidence_id"): row for row in service_data.get("evidence", [])}
    attribution_edges = defaultdict(list)
    for address, record in service_records.items():
        canonical = ton_canonical_address(address)
        if not canonical:
            continue
        account = _wallet_node_id("ton", canonical)
        if account not in node_data:
            node(account, _short(canonical), "wallet", canonical, "ton", weight=2, source="ton_service_intelligence")
        node_data[account]["address"] = canonical
        node_data[account]["service_address"] = canonical
        node_data[account]["ton_service_intelligence"] = sanitize_observation(record)
        for claim in record.get("attributions", []):
            status = str(claim.get("status") or "UNKNOWN").upper()
            refs = list(dict.fromkeys(claim.get("evidence_ids") or []))
            proofs = [service_evidence[ref] for ref in refs if ref in service_evidence]
            service_id = str(claim.get("service_id") or "")
            # No service relation is manufactured from UNKNOWN, a wallet
            # version or an attribution that has no retained supporting proof.
            if status not in {"CONFIRMED", "PROBABLE", "POSSIBLE"} or not service_id or not proofs:
                continue
            service_node = "service:ton:" + service_id
            node(service_node, str(claim.get("name") or service_id), "service", str(claim.get("reason") or "Service attribution observation"),
                 "ton", weight=3, source="ton_service_intelligence")
            service = node_data[service_node]
            service["service_id"] = service_id
            service["service_address"] = service.get("service_address") or canonical
            service["service_addresses"] = list(dict.fromkeys(service.get("service_addresses", []) + [canonical]))
            urls = [url for proof in proofs if (url := safe_public_url(proof.get("url")))]
            edge(account, service_node, "service_attribution", source="ton_service_intelligence",
                 title=str(claim.get("reason") or "Service attribution observation"), evidence_urls=urls,
                 evidence_url=urls[0] if urls else None, confidence=0, weight=3, event_ids=[str(claim.get("attribution_id") or "")])
            edge_data[-1].update({"verification_status": status, "confirmation": status,
                "confidence_status": status, "confidence": None, "label": "Service attribution", "service_id": service_id,
                "attribution_id": claim.get("attribution_id"), "attribution_method": claim.get("method"),
                "evidence_ids": refs, "evidence": proofs, "conflicts": claim.get("conflicts") or [],
                "attribution_note": "Service address relationship; not signing application or personal identity"})
            attribution_edges[(account, service_node)].append(edge_data[-1])

    if unified:
        from app.attribution.normalize import address_id
        facts = {row.get("evidence_id"): row for row in unified.get("evidence", [])}
        for key, record in unified.get("addresses", {}).items():
            chain, address = record.get("blockchain"), record.get("address")
            if not chain or not address or address_id(chain, address) != key:
                continue
            account = _wallet_node_id(chain, address)
            if account not in node_data:
                node(account, _short(address), _wallet_kind(chain), address, chain, weight=2, source="attribution_intelligence")
            node_data[account].update(service_key=key, service_address=address,
                attribution_intelligence=sanitize_observation(record))
            # Provider titles cannot promote an ordinary address to an exchange
            # or wallet application. Typed claims are shown separately as badges.
            base_kind=_wallet_kind(chain)
            if record.get("account_type") in {"smart_contract","eip1167_minimal_proxy","executable_program"}:
                base_kind="solana_program" if chain=="solana" else "contract"
            node_data[account].update(kind=base_kind,kind_label=NODE_LABELS.get(base_kind,base_kind))
            for claim in record.get("attributions", []):
                refs=claim.get("evidence_ids") or []
                proofs=[facts[ref] for ref in refs if ref in facts]
                status=claim.get("status")
                identity=claim.get("service_id")
                if not identity or not proofs or status not in {"CONFIRMED","PROBABLE","POSSIBLE"}:
                    continue
                service="service:"+chain+":"+str(identity)
                urls=list(dict.fromkeys(row.get("url") for row in proofs if row.get("url")))
                node(service, str(claim.get("name") or claim.get("entity_name") or identity), "service",
                    str(claim.get("reason") or "Published attribution"),chain,weight=3,source="attribution_intelligence")
                node_data[service].update(service_id=identity,service_key=key,service_address=address,
                    attribution_type=claim.get("entity_type") or claim.get("category"))
                edge(account,service,"service_attribution",chain=chain,source="attribution_intelligence",title=claim.get("reason"),
                    evidence_urls=urls,evidence_url=urls[0] if urls else None,confidence=0,weight=3,
                    event_ids=[str(claim.get("attribution_id") or "")])
                edge_data[-1].update(verification_status=status,confirmation=status,confidence_status=status,
                    confidence=None,label="Service attribution",service_id=identity,attribution_id=claim.get("attribution_id"),
                    attribution_method=claim.get("method"),evidence_ids=refs,evidence=proofs,conflicts=claim.get("conflicts") or [],
                    attribution_note="Published address relation; no automatic target ownership or signing client inference")
                attribution_edges[(account,service)].append(edge_data[-1])
        # Technical relations use the existing graph; no new ownership edge.
        for relation in unified.get("relationships", []):
            if relation.get("type") not in {"proxy_implementation","delegation_target","contract_deployer","program_owned_by","authority","protocol_interaction"}:
                continue
            from_record=unified.get("addresses",{}).get(relation.get("from_key"))
            to_record=unified.get("addresses",{}).get(relation.get("to_key"))
            if not from_record or not to_record:
                continue
            frm=_wallet_node_id(from_record["blockchain"],from_record["address"])
            to=_wallet_node_id(to_record["blockchain"],to_record["address"])
            refs=relation.get("evidence_ids",[])
            proofs=[facts[ref] for ref in refs if ref in facts]
            urls=[f["url"] for f in proofs if f.get("url")]
            edge(frm,to,"interaction",chain=from_record["blockchain"],source="attribution_intelligence",
                title=relation.get("reason") or relation["type"],evidence_urls=urls,confidence=0,weight=2)
            edge_data[-1].update(verification_status=relation.get("status"),relationship_type=relation["type"],
                evidence_ids=refs,evidence=proofs,attribution_note="Technical relation only; no common control inferred")

    compacted: dict[tuple, dict[str, Any]] = {}
    for item in edge_data:
        key = (item["from"], item["to"], item["type"], item.get("asset"), item.get("token_contract"))
        current = compacted.get(key)
        if current is None:
            compacted[key] = dict(item)
            continue
        current["count"] = int(current.get("count") or 0) + int(item.get("count") or 0)
        # Unknown components cannot become a known zero or a complete total.
        values = (current.get("amount_decimal"), item.get("amount_decimal"))
        current["amount_decimal"] = str(sum((Decimal(value) for value in values), Decimal(0))) if all(value is not None for value in values) else None
        current["total"] = float(current["amount_decimal"]) if current["amount_decimal"] is not None else None
        for field in ("sources", "evidence_urls", "event_ids"):
            current[field] = list(dict.fromkeys((current.get(field) or []) + (item.get(field) or [])))
        current["weight"] = max(float(current.get("weight") or 1.0), float(item.get("weight") or 1.0))
        current["confidence"] = max(float(current.get("confidence") or 0.0), float(item.get("confidence") or 0.0))
        current["transaction_hashes"] = list(dict.fromkeys((current.get("transaction_hashes") or []) + (item.get("transaction_hashes") or [])))
        current["tx_hash"] = ", ".join(current["transaction_hashes"])
        current["source"] = current.get("source") or item.get("source") or ""
        current["evidence_url"] = current.get("evidence_url") or item.get("evidence_url") or ""
        dates = [value for value in (current.get("first_seen"), item.get("first_seen")) if value]
        current["first_seen"] = min(dates) if dates else None
        dates = [value for value in (current.get("last_seen"), item.get("last_seen")) if value]
        current["last_seen"] = max(dates) if dates else None
        current["timestamps"] = list(dict.fromkeys((current.get("timestamps") or []) + (item.get("timestamps") or [])))[:12]
    edge_data = list(compacted.values())
    # Preserve separate proof/status records if several methods support the
    # same displayed association; topology compaction never votes them certain.
    for item in edge_data:
        if item.get("type") == "service_attribution":
            matches = attribution_edges[(item["from"], item["to"])]
            item["confidence"] = None
            item["attributions"] = [{key: row.get(key) for key in ("attribution_id", "attribution_method", "verification_status", "evidence_ids", "evidence", "conflicts")}
                                    for row in matches]

    discovery_status = str(input_resolution.get("discovery_status") or "").lower()
    if (primary_chain == "ton" and input_resolution
            and discovery_status in {"unresolved", "ambiguous", "unsupported", "not_found"}
            and not ton_canonical_address(report.target_address)):
        # A failed name search has an input string, not an identified account.
        # Reuse the original activity style while retaining the stable root ID.
        node_data[target].update({"kind": "activity", "kind_label": NODE_LABELS["activity"],
            "icon": NODE_ICONS.get("activity", "?"), "asset_type": "input_identifier",
            "title": f"{report.target_address} | {discovery_status} search identifier; no verified account or owner assertion",
            "discovery_status": discovery_status})

    centrality = nx.degree_centrality(g.to_undirected()) if g.number_of_nodes() else {}
    weighted_degree = defaultdict(float)
    incident_counts = defaultdict(int)
    incident_transactions = defaultdict(int)
    for item in edge_data:
        weighted_degree[item["from"]] += float(item.get("weight") or 1.0)
        weighted_degree[item["to"]] += float(item.get("weight") or 1.0)
        # The previous node-by-edge scan counted self-loops once for incidence
        # while weighted degree counted both endpoints. Preserve both contracts.
        for endpoint in dict.fromkeys((item["from"], item["to"])):
            incident_counts[endpoint] += 1
            incident_transactions[endpoint] += int(item.get("count") or 1)

    for node_id, data in node_data.items():
        data["centrality"] = float(centrality.get(node_id, 0.0))
        data["tx_count"] = incident_transactions[node_id]
        data["relationship_count"] = incident_counts[node_id]
        data["strength"] = float(weighted_degree.get(node_id, 0.0))
        data["size"] = max(10, min(34, 10 + data["weight"] * 1.4 + data["relationship_count"] * 0.35))
        data["cluster"] = data.get("chain") or "multi"

    node_limit = 180
    rank = {"wallet": 8, "bitcoin_wallet": 8, "doge_wallet": 8, "ethereum_wallet": 8, "bsc_wallet": 8, "trx_wallet": 8, "tron_wallet": 8, "solana_wallet": 8, "exchange": 8, "service": 7, "marketplace": 7, "migration_target": 7, "doge_exchange_label": 7, "tron_exchange": 7, "tron_defi": 7, "sunswap_pool": 7, "ens_identity": 7, "username": 7, "telegram_username": 7, "gift": 6, "domain": 6, "nft": 6, "bsc_nft": 6, "solana_nft": 6, "solana_program": 6, "tron_resource": 6, "tron_permission": 6, "collectible": 5, "jetton": 5, "jetton_counterparty": 5, "token": 5, "bep20_token": 5, "trc20_token": 5, "usdt_trc20": 5, "sunpump_token": 5, "spl_token": 5, "doge_counterparty": 5, "doge_utxo": 5, "dex_pair": 5, "dex_router": 5, "bridge": 5, "risk_source": 5, "cluster": 5, "activity": 4, "contract": 4, "eth_contract": 4, "bsc_contract": 4, "tron_contract": 4, "telegram_id": 4, "username_owner": 4, "ens_record": 4, "transaction": 1, "username_transfer": 1, "jetton_transfer": 1, "bitcoin_tx": 1, "doge_transaction": 1, "bsc_tx": 1, "tron_tx": 1, "solana_tx": 1}
    strongest = sorted(node_data.values(), key=lambda x: (x["id"] == target, rank.get(x.get("kind"), 3), x.get("strength", 0), x.get("weight", 0), x.get("centrality", 0)), reverse=True)[:node_limit]
    kept = {item["id"] for item in strongest}
    edges = [item for item in edge_data if item["from"] in kept and item["to"] in kept]
    node_by_id = {item["id"]: item for item in strongest}
    for item in edges:
        a = node_by_id.get(item["from"], {})
        b = node_by_id.get(item["to"], {})
        item["importance"] = (
            float(item.get("weight") or 1.0)
            + min(8, int(item.get("count") or 1)) * 0.5
            + rank.get(a.get("kind"), 2) * 0.35
            + rank.get(b.get("kind"), 2) * 0.35
            + (6 if target in {item["from"], item["to"]} else 0)
        )
        item["aggregated"] = int(item.get("count") or 1) > 1 or "," in str(item.get("tx_hash") or "")
        item["relationship_rank"] = round(item["importance"] + min(12, float(item.get("total") or 0) ** 0.5 if float(item.get("total") or 0) > 0 else 0), 4)
        item["noise_score"] = round((1 if node_by_id.get(item["from"], {}).get("kind") in {"transaction", "bitcoin_tx", "doge_transaction", "bsc_tx", "tron_tx", "solana_tx"} else 0) + (1 if node_by_id.get(item["to"], {}).get("kind") in {"transaction", "bitcoin_tx", "doge_transaction", "bsc_tx", "tron_tx", "solana_tx"} else 0) + (0.6 if int(item.get("count") or 1) <= 1 else 0), 4)
    for item in strongest:
        item["importance_score"] = round(
            rank.get(item.get("kind"), 2) * 1.25
            + float(item.get("strength") or 0) * 0.28
            + float(item.get("centrality") or 0) * 18
            + min(12, int(item.get("relationship_count") or 0)) * 0.45
            + (8 if item["id"] == target else 0),
            4,
        )
        item["noise_score"] = round((2.2 if item.get("kind") in {"transaction", "bitcoin_tx", "doge_transaction", "bsc_tx", "tron_tx", "solana_tx"} else 0) + (0.8 if int(item.get("relationship_count") or 0) <= 1 else 0), 4)
    default_edges = sorted(
        [
            item for item in edges
            if (
                node_by_id.get(item["from"], {}).get("kind") not in {"transaction", "bitcoin_tx", "doge_transaction", "bsc_tx", "tron_tx", "solana_tx"}
                and node_by_id.get(item["to"], {}).get("kind") not in {"transaction", "bitcoin_tx", "doge_transaction", "bsc_tx", "tron_tx", "solana_tx"}
                and (
                    item["from"] == target
                    or item["to"] == target
                    or int(item.get("count") or 1) >= 2
                    or item.get("type") in {"owns", "linked_by", "confirmed_by", "listed_on", "marketplace_interaction", "activity_path", "same_address", "resolves"}
                )
            )
        ],
        key=lambda item: item.get("importance", 0),
        reverse=True,
    )[:80]
    default_ids = {target}
    for item in default_edges:
        default_ids.add(item["from"])
        default_ids.add(item["to"])
    for item in sorted(strongest, key=lambda x: (rank.get(x.get("kind"), 2), x.get("strength", 0)), reverse=True):
        if len(default_ids) >= 72:
            break
        if item.get("kind") not in {"transaction", "bsc_tx", "tron_tx", "solana_tx"}:
            default_ids.add(item["id"])
    default_edges = [item for item in edges if item["from"] in default_ids and item["to"] in default_ids and (item in default_edges or item["from"] == target or item["to"] == target)]
    top_nodes = sorted(strongest, key=lambda x: (x["centrality"], x["relationship_count"], x["strength"]), reverse=True)[:24]
    edge_types = sorted({item["type"] for item in edges if item.get("type")})
    asset_types = sorted({item["asset_type"] for item in strongest if item.get("asset_type")})
    node_types = sorted({item["kind"] for item in strongest if item.get("kind")})
    clusters = {
        chain: sum(1 for item in strongest if item.get("chain") == chain)
        for chain in sorted({item.get("chain") for item in strongest if item.get("chain")})
    }
    node_groups = {
        kind: sum(1 for item in strongest if item.get("kind") == kind)
        for kind in sorted({item.get("kind") for item in strongest if item.get("kind")})
    }
    meaningful_node_count = sum(1 for item in strongest if item.get("importance_score", 0) >= 5 or item["id"] == target)
    meaningful_edge_count = sum(1 for item in edges if item.get("relationship_rank", 0) >= 5)

    payload = {
        "target": target,
        "nodes": strongest,
        "edges": edges,
        "top_nodes": top_nodes,
        "top_by_tx": [{"address": c.address, "chain": c.chain, "tx_count": c.tx_count} for c in report.counterparties[:30]],
        "top_by_amount": [{"address": c.address, "chain": c.chain, "amount": c.total_in + c.total_out} for c in sorted(report.counterparties, key=lambda c: c.total_in + c.total_out, reverse=True)[:10]],
        "filters": {"node_types": node_types, "asset_types": asset_types, "edge_types": edge_types, "clusters": sorted(clusters)},
        "views": {"default_nodes": sorted(default_ids), "default_edges": [item["from"] + "\u001f" + item["to"] + "\u001f" + item["type"] + "\u001f" + item.get("asset", "") for item in default_edges]},
        "reduction": {"default_nodes": len(default_ids), "default_edges": len(default_edges), "full_nodes": len(strongest), "full_edges": len(edges), "aggregated_edges": sum(1 for item in edges if item.get("aggregated"))},
        "stats": {"nodes": len(strongest), "edges": len(edges), "clusters": clusters, "node_groups": node_groups, "meaningful_nodes": meaningful_node_count, "meaningful_edges": meaningful_edge_count, "total_nodes": len(node_data), "total_edges": len(edge_data)},
        "labels": {"nodes": NODE_LABELS, "edges": EDGE_LABELS},
    }
    if financial_projection is not None:
        payload["financial_operation_counts"] = financial_projection["counts"]
    if input_resolution:
        # Resolution describes which object was entered and which account was
        # analysed. It does not establish another ownership or identity edge.
        payload["input_resolution"] = input_resolution
        resolution_owner = ton_canonical_address(input_resolution.get("onchain_owner_address"))
        if (primary_chain == "ton" and resolution_owner
                and resolution_owner == ton_canonical_address(report.target_address)):
            node_data[target].update({"owner_account_type": input_resolution.get("owner_account_type") or "unknown",
                "owner_account_evidence": input_resolution.get("owner_account_evidence") or {},
                "owner_analysis_status": input_resolution.get("owner_analysis_status") or "unknown",
                "ownership_status": input_resolution.get("ownership_status") or "unknown"})

    if nft_data:
        from app.graph.nft_builder import build_nft_graph
        nft_graph = build_nft_graph(nft_data)
        payload["nft_intelligence_graph"] = nft_graph
        # Keep the original force layout bounded; the embedded NFT graph retains
        # every relationship and its verified ownership timeline.
        mapping = {}
        known_ids = {item["id"] for item in payload["nodes"]}
        displayed = []
        for item in nft_graph["nodes"]:
            node_id = item["id"]
            if item["kind"] in {"ton_wallet", "ton_address"}:
                node_id = _wallet_node_id("ton", item["address"])
            elif item["kind"] in {"nft_item", "ton_domain_nft", "telegram_collectible_username", "telegram_gift"}:
                node_id = _asset_node_id(item["address"])
            mapping[item["id"]] = node_id
            if node_id in known_ids or len(displayed) >= 100:
                continue
            kind = {"ton_wallet": "wallet", "nft_item": "nft", "telegram_collectible_username": "telegram_username", "telegram_gift": "gift", "ton_domain_nft": "domain"}.get(item["kind"], item["kind"])
            display = {**item, "id": node_id, "kind": kind, "title": item["label"], "asset_type": item["kind"], "weight": 3, "importance_score": 5, "centrality": 0, "strength": 1, "tx_count": 0, "relationship_count": 0, "source": "ton_nft_intelligence", "cluster": "ton"}
            payload["nodes"].append(display)
            displayed.append(node_id)
            known_ids.add(node_id)
        def address_identity(node_id):
            return ton_canonical_address(str(node_id).split(":", 2)[-1]) or node_id
        ownership_edges = {}
        for row in payload["edges"]:
            if row["type"] == "owns":
                ownership_edges.setdefault((address_identity(row["from"]), address_identity(row["to"])), row)
        for item in nft_graph["edges"]:
            src = mapping.get(item["from"], item["from"])
            dst = mapping.get(item["to"], item["to"])
            if src not in known_ids or dst not in known_ids:
                continue
            if item["type"] == "OWNS":
                existing = ownership_edges.get((address_identity(src), address_identity(dst)))
                if existing is not None:
                    # Both projections describe the same current assertion,
                    # rather than two independently confirmed ownership facts.
                    for field in ("evidence_ids", "observation_ids"):
                        existing[field] = list(dict.fromkeys((existing.get(field) or []) + (item.get(field) or [])))
                    existing["nft_relationship_ids"] = list(dict.fromkeys((existing.get("nft_relationship_ids") or []) + [item["id"]]))
                    existing["confirmation"] = item.get("confirmation")
                    existing["explanation"] = item.get("explanation")
                    existing["evidence_url"] = existing.get("evidence_url") or item.get("evidence_url") or ""
                    existing["evidence_urls"] = list(dict.fromkeys((existing.get("evidence_urls") or []) + ([item["evidence_url"]] if item.get("evidence_url") else [])))
                    existing["sources"] = list(dict.fromkeys((existing.get("sources") or []) + ([item["source"]] if item.get("source") else [])))
                    continue
            projected = {**item, "from": src, "to": dst, "type": item["type"].lower(), "label": item["type"], "chain": "ton", "asset": "NFT", "total": 0, "count": 1, "weight": 3, "title": item["explanation"], "confidence": {"high": .9, "medium": .6, "low": .3}.get(item.get("confidence"), .4), "relationship_rank": 5}
            payload["edges"].append(projected)
            if projected["type"] == "owns":
                ownership_edges.setdefault((address_identity(src), address_identity(dst)), projected)
        payload["filters"]["node_types"] = sorted({item["kind"] for item in payload["nodes"]})
        payload["filters"]["edge_types"] = sorted({item["type"] for item in payload["edges"]})
        payload["stats"]["nodes"] = len(payload["nodes"])
        payload["stats"]["edges"] = len(payload["edges"])
        payload["reduction"]["nft_nodes_displayed"] = len(displayed)
        payload["reduction"]["nft_nodes_available"] = len(nft_graph["nodes"])
        payload["reduction"]["nft_full_graph_key"] = "nft_intelligence_graph"
    _attach_inferential_graph(payload, report)
    return payload


def _attach_inferential_graph(payload: dict, report: AddressReport) -> None:
    """Append a bounded analytic layer after the existing financial reduction.

    This deliberately bypasses monetary compaction: an analytic edge carries no
    amount/total, cannot displace an existing financial node, and never adds to
    financial tx_count. Address keys remain chain-qualified and canonical.
    """
    from app.attribution.normalize import address_id, normalize_chain

    unified = report.attribution_intelligence or {}
    inference = unified.get('inferential_intelligence') or {}
    if not isinstance(inference, dict) or not any(inference.get(k) for k in ('clusters', 'relationships', 'paths')):
        return
    limits = {'additional_nodes': 100, 'additional_edges': 300, 'clusters': 30, 'members_per_cluster': 20,
              'relationships_checked': 1000, 'paths': 40, 'evidence_refs_per_edge': 256}
    nodes = {row['id']: row for row in payload['nodes']}
    original_nodes = set(nodes)
    original_edge_count = len(payload['edges'])
    original_node_count = len(nodes)
    facts = {r.get('evidence_id'): r for r in unified.get('evidence', []) if isinstance(r, dict) and r.get('evidence_id')}
    records = unified.get('addresses') or {}
    overlays = {}; refs_to_nodes = {}; path_records = []
    counts = defaultdict(int)
    evidence_url_cache = {}
    hypothesis_refs = defaultdict(list)
    for hypothesis in (inference.get('hypotheses') or [])[:250]:
        if isinstance(hypothesis, dict) and isinstance(hypothesis.get('subject'), str) and hypothesis.get('id'):
            hypothesis_refs[hypothesis['subject']].append(hypothesis['id'])

    def timestamp(value):
        if isinstance(value, datetime): return value.isoformat()
        if not isinstance(value, str) or len(value) > 80: return None
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return parsed.astimezone(timezone.utc).isoformat() if parsed.tzinfo else None
        except ValueError:
            return None

    def references(row):
        return list(dict.fromkeys(v for v in row.get('evidence_ids', []) if isinstance(v, str) and v))

    def new_node(row):
        if row['id'] in nodes: return row['id']
        if len(nodes) - original_node_count >= limits['additional_nodes']:
            counts['nodes_omitted_by_limit'] += 1; return None
        nodes[row['id']] = row
        payload['nodes'].append(row)
        return row['id']

    def base_node(node_id, label, kind, chain, title):
        return {'id': node_id, 'label': label, 'kind': kind, 'kind_label': NODE_LABELS.get(kind, kind),
                'icon': NODE_ICONS.get(kind, 'counterparty'), 'title': title, 'chain': chain, 'cluster': chain,
                'asset_type': 'inference_context', 'weight': 2, 'sources': ['inferential_intelligence'],
                'evidence': [], 'labels': [], 'image_url': '', 'image_source': '',
                'first_seen': None, 'last_seen': None, 'tx_count': 0, 'relationship_count': 0,
                'inference_relationship_count': 0, 'centrality': 0, 'strength': 0, 'size': 14,
                'importance_score': 5, 'noise_score': 0, 'inference_context': True,
                'ownership': 'UNKNOWN', 'monetary': False}

    def account(raw_key):
        if not isinstance(raw_key, str) or ':' not in raw_key: return None
        chain, address = raw_key.split(':', 1)
        chain = normalize_chain(chain)
        canonical_key = address_id(chain, address)
        if not canonical_key:
            counts['invalid_network_keys_omitted'] += 1; return None
        address = canonical_key.split(':', 1)[1]
        node_id = _wallet_node_id(chain, address)
        if node_id not in nodes:
            row = base_node(node_id, _short(address), _wallet_kind(chain), chain, address)
            row.update(address=address, address_key=canonical_key, service_key=canonical_key, service_address=address)
            # Keep the original account dossier on its own address only. A
            # candidate relation never copies its label onto another account.
            if isinstance(records.get(canonical_key), dict):
                row['attribution_intelligence'] = sanitize_observation(records[canonical_key])
            if not new_node(row): return None
        refs_to_nodes[canonical_key] = node_id
        return node_id, chain

    def tx_node(raw_key, chain):
        if not isinstance(raw_key, str) or chain not in {'btc', 'doge'}: return None
        parts = raw_key.split(':', 2)
        if len(parts) != 3 or parts[0] != chain or parts[1] not in {'tx', 'transaction'} or not re.fullmatch(r'[a-fA-F0-9]{64}', parts[2]):
            counts['invalid_transaction_keys_omitted'] += 1; return None
        node_id = _tx_node_id(parts[2].lower(), chain)
        if node_id not in nodes:
            kind = 'bitcoin_tx' if chain == 'btc' else 'doge_transaction'
            if not new_node(base_node(node_id, _short(parts[2]), kind, chain, parts[2])): return None
        return node_id, chain

    def analytic_edge(frm, to, edge_type, chain, row, *, record_id=None, scope=None, path_id=None):
        if not frm or not to or frm == to: return None
        if frm not in nodes or to not in nodes: return None
        # Separate source/claim scope survives topology compaction, while all
        # per-record references remain available in observations below.
        identity = (frm, to, edge_type, scope or row.get('scope'), row.get('asset_key'))
        edge = overlays.get(identity)
        if edge is None:
            if len(overlays) >= limits['additional_edges']:
                counts['edges_omitted_by_limit'] += 1; return None
            rid = 'inference-edge:' + hashlib.sha256(repr(identity).encode()).hexdigest()
            edge = {'id': rid, 'from': frm, 'to': to, 'type': edge_type, 'label': EDGE_LABELS[edge_type],
                    'chain': chain, 'blockchain': chain, 'asset': '', 'token_contract': '', 'source': 'inferential_intelligence',
                    'sources': ['inferential_intelligence'], 'evidence_url': '', 'evidence_urls': [],
                    'evidence_ids': [], 'dependency_groups': [], 'relationship_ids': [], 'path_ids': [],
                    'observations': [], 'count': 1, 'weight': 2, 'confidence': None,
                    'confidence_status': str(row.get('status') or 'UNKNOWN'),
                    'verification_status': str(row.get('status') or 'UNKNOWN'),
                    'status': str(row.get('status') or 'UNKNOWN'), 'relationship_type': scope or row.get('scope') or row.get('type'),
                    'inference_scope': scope or row.get('scope') or row.get('type'),
                    'inference': True, 'analytic': True, 'monetary': False, 'financial_totals_included': False,
                    'ownership': 'UNKNOWN', 'signing_application': 'UNKNOWN', 'exact_funds_traced': False,
                    'directed': row.get('directed', True), 'dashes': True, 'first_seen': None, 'last_seen': None,
                    'timestamps': [], 'event_ids': [], 'importance': 5, 'relationship_rank': 5,
                    'noise_score': 0, 'aggregated': False,
                    'title': EDGE_LABELS[edge_type] + ' | ' + str(scope or row.get('scope') or row.get('method') or 'context'),
                    'attribution_note': 'Analytic context only; no common owner, allocation of funds or signing application is established.'}
            overlays[identity] = edge
        refs = references(row)
        combined_refs = list(dict.fromkeys(edge['evidence_ids'] + refs))
        edge['evidence_ids'] = combined_refs[:limits['evidence_refs_per_edge']]
        edge['evidence_ids_omitted'] = max(0, len(combined_refs) - len(edge['evidence_ids']))
        edge['dependency_groups'] = list(dict.fromkeys(edge['dependency_groups'] + list(row.get('dependency_groups') or [])))
        if record_id and record_id not in edge['relationship_ids']: edge['relationship_ids'].append(record_id)
        edge['relationship_id'] = edge.get('relationship_id') or record_id or edge['id']
        cid = row.get('cluster_id') or (row.get('id') if edge_type == 'inference_membership' else None)
        if cid:
            edge['cluster_id'] = edge.get('cluster_id') or cid
            edge['cluster_ids'] = list(dict.fromkeys(edge.get('cluster_ids', []) + [cid]))
        related_hypotheses = list(row.get('hypothesis_ids') or []) + hypothesis_refs.get(cid, [])
        edge['hypothesis_ids'] = list(dict.fromkeys(edge.get('hypothesis_ids', []) + related_hypotheses))
        if path_id and path_id not in edge['path_ids']: edge['path_ids'].append(path_id)
        statuses = edge.setdefault('confidence_statuses', [])
        status = str(row.get('status') or 'UNKNOWN')
        if status not in statuses: statuses.append(status)
        # Several weak records never vote a displayed edge into certainty.
        edge['confidence'] = None
        if len(statuses) > 1:
            edge['confidence_status'] = edge['verification_status'] = edge['status'] = 'MIXED'
        edge['confirmation'] = edge['status']
        first_last = row.get('first_last') or {}
        first = timestamp(row.get('first_observed') or first_last.get('first_observed'))
        last = timestamp(row.get('last_observed') or first_last.get('last_observed'))
        for field, value, choose in [('first_seen', first, min), ('last_seen', last, max)]:
            candidates = [v for v in (edge[field], value) if v]
            edge[field] = choose(candidates) if candidates else None
        edge['timestamps'] = list(dict.fromkeys(edge['timestamps'] + [v for v in (first, last) if v]))[:12]
        for ref in refs:
            if ref not in evidence_url_cache:
                fact = facts.get(ref) or {}
                evidence_url_cache[ref] = safe_public_url(fact.get('url') or fact.get('source_url')) or ''
            url = evidence_url_cache[ref]
            if url and url not in edge['evidence_urls']: edge['evidence_urls'].append(url)
        edge['evidence_url'] = edge['evidence_url'] or next(iter(edge['evidence_urls']), '')
        observation = {k: row.get(k) for k in ('method', 'status', 'role', 'graph_scope', 'alternatives', 'claim_scope') if row.get(k) is not None}
        observation.update(record_id=record_id, evidence_ids=refs, dependency_groups=row.get('dependency_groups') or [])
        if observation not in edge['observations']: edge['observations'].append(observation)
        return edge['id']

    # Exact redemption receipts reserve their existing analytic nodes/edge
    # before broad motifs consume the same unchanged overlay limits.
    def exact_bridge(row):
        return (row.get('type')=='verified_cross_chain_message_execution'
                and row.get('claim_scope')=='exact_protocol_message_execution'
                and row.get('status')=='CONFIRMED' and row.get('transaction_edge') is False
                and len(references(row))>=2)

    for relation in (inference.get('relationships') or []):
        if not isinstance(relation,dict) or not exact_bridge(relation):continue
        frm,to=account(relation.get('from_key')),account(relation.get('to_key'))
        if frm and to:
            analytic_edge(frm[0],to[0],'inference_protocol',frm[1],relation,
                          record_id=relation.get('relationship_id'),scope='verified_cross_chain_message_execution')

    # Reserve route topology before broad motifs/interaction batches can spend
    # the entire overlay budget. The financial layer above remains untouched.
    paths = inference.get('paths') or []
    for path in paths[:limits['paths']]:
        if not isinstance(path, dict): continue
        pid = path.get('path_id') or path.get('id')
        chain = normalize_chain(path.get('blockchain'))
        raw_nodes = path.get('nodes') or []
        if not isinstance(raw_nodes, list) or not 2 <= len(raw_nodes) <= 4: continue
        utxo = path.get('type') == 'utxo_transaction_spend_path'
        members = [tx_node(k, chain) if utxo else account(k) for k in raw_nodes]
        if any(r is None or r[1] != chain for r in members): continue
        eids = []
        for a, b in zip(members, members[1:]):
            eid = analytic_edge(a[0], b[0], 'inference_utxo_spend' if utxo else 'inference_route_step', chain,
                                path, path_id=pid, scope='captured_outpoint_spend' if utxo else 'possible_temporal_asset_route')
            if eid: eids.append(eid)
        if eids:
            path_records.append({'path_id': pid, 'nodes': [r[0] for r in members], 'edge_ids': eids,
                'hop_count': path.get('hop_count'), 'status': path.get('status'), 'monetary': False,
                'exact_funds_traced': False, 'amount_compatibility': path.get('amount_compatibility'),
                'transaction_hashes': path.get('transaction_hashes') or [], 'evidence_ids': references(path)})

    clusters = inference.get('clusters') or []
    for cluster in clusters[:limits['clusters']]:
        if not isinstance(cluster, dict): continue
        cid = cluster.get('cluster_id') or cluster.get('id')
        if not isinstance(cid, str): continue
        members = []
        for value in (cluster.get('members') or [])[:limits['members_per_cluster']]:
            result = account(value)
            if result: members.append(result)
        if len(members) < 2: continue
        chain = members[0][1] if len({c for _, c in members}) == 1 else 'multi'
        node_id = 'inference-cluster:' + hashlib.sha256(cid.encode()).hexdigest()
        row = base_node(node_id, str(cluster.get('type') or 'CANDIDATE_CLUSTER'), 'inference_cluster', chain,
                        'Candidate infrastructure pattern; common ownership remains UNKNOWN')
        row.update(inference_cluster_id=cid, cluster_id=cid, inference_status=cluster.get('status') or 'UNKNOWN',
                   inference_scope=cluster.get('scope') or 'similar_behavior', inference_members=[m for m, _ in members],
                   evidence_ids=references(cluster), dependency_groups=cluster.get('dependency_groups') or [],
                   first_seen=timestamp(cluster.get('first_observed')), last_seen=timestamp(cluster.get('last_observed')))
        if not new_node(row): continue
        counts['clusters_displayed'] += 1
        for member, member_chain in members:
            analytic_edge(member, node_id, 'inference_membership', member_chain, {**cluster, 'directed': False},
                          record_id=cid, scope=cluster.get('scope') or 'similar_behavior')

    relationships = inference.get('relationships') or []
    # Prefer target/context links and candidate/protocol associations over an
    # arbitrary provider's ordering of a large observed transfer batch.
    targets = set((unified.get('investigation_context') or {}).get('target_keys') or [])
    targets.update(k for c in report.detected_chains if (k := address_id(c, report.target_address)))
    candidates = [r for r in relationships[:limits['relationships_checked']] if isinstance(r, dict)]
    candidates.sort(key=lambda r: (not bool(targets & {r.get('from_key'), r.get('to_key')}),
                                   r.get('scope') == 'interacts_with'))
    for relation in candidates:
        scope = relation.get('scope') or relation.get('type')
        if scope == 'interacts_with' and relation.get('graph_scope') == 'economic':
            edge_type = 'inference_observed_transfer'
        elif scope in {'shared_protocol', 'protocol_message_emission', 'verified_cross_chain_message_execution'}:
            edge_type = 'inference_protocol'
        elif scope in {'similar_behavior', 'shared_infrastructure_supported'}:
            edge_type = 'inference_association'
        else:
            counts['unsupported_relationship_scopes_omitted'] += 1; continue
        frm, to = account(relation.get('from_key')), account(relation.get('to_key'))
        if not frm or not to: continue
        if frm[1] != to[1] and not exact_bridge(relation):
            counts['cross_network_relationships_omitted'] += 1; continue
        if analytic_edge(frm[0], to[0], edge_type, frm[1], relation,
                         record_id=relation.get('relationship_id'), scope=scope):
            counts['relationship_records_displayed'] += 1

    payload['edges'].extend(overlays.values())
    for edge in overlays.values():
        for endpoint in {edge['from'], edge['to']}:
            row = nodes[endpoint]
            row['inference_relationship_count'] = row.get('inference_relationship_count', 0) + 1
            if endpoint not in original_nodes: row['relationship_count'] += 1
    # Preserve financial selection and counters. A small additive default overlay
    # makes target-connected hypotheses discoverable in the original graph view.
    default_nodes = set(payload['views']['default_nodes'])
    default_edges = list(payload['views']['default_edges'])
    for edge in overlays.values():
        if len(default_nodes) >= len(payload['views']['default_nodes']) + 40: break
        if payload['target'] not in {edge['from'], edge['to']}: continue
        default_nodes.update((edge['from'], edge['to']))
        default_edges.append(edge['from'] + '\x1f' + edge['to'] + '\x1f' + edge['type'] + '\x1f')
    payload['views']['default_nodes'] = sorted(default_nodes)
    payload['views']['default_edges'] = list(dict.fromkeys(default_edges))
    payload['views']['inference_nodes'] = sorted({n for e in overlays.values() for n in (e['from'], e['to'])})
    payload['views']['inference_edges'] = [e['id'] for e in overlays.values()]
    payload['filters']['node_types'] = sorted({r['kind'] for r in payload['nodes']})
    payload['filters']['edge_types'] = sorted({r['type'] for r in payload['edges']})
    payload['filters']['clusters'] = sorted({r.get('chain') for r in payload['nodes'] if r.get('chain')})
    payload['stats']['nodes'] = len(payload['nodes']); payload['stats']['edges'] = len(payload['edges'])
    payload['stats']['total_nodes'] += len(nodes) - original_node_count
    payload['stats']['total_edges'] += len(overlays)
    payload['reduction'].update(full_nodes=len(payload['nodes']), full_edges=len(payload['edges']),
        default_nodes=len(default_nodes), default_edges=len(payload['views']['default_edges']))
    payload['inferential_graph'] = {'schema_version': '1.0', 'status': 'PARTIAL',
        'clusters_available': len(clusters), 'relationships_available': len(relationships), 'paths_available': len(paths),
        'paths': path_records, 'nodes_added': len(nodes) - original_node_count,
        'edges_added': len(payload['edges']) - original_edge_count, 'limits': limits, 'diagnostics': dict(counts),
        'ownership': 'UNKNOWN', 'financial_totals_modified': False,
        'coverage_note': 'Bounded analytic overlay. Complete records remain in inferential_intelligence; edge amounts are intentionally absent.'}
