from __future__ import annotations

from decimal import Decimal, localcontext
from app.utils.event_identity import address_key, event_identity, merge_provenance, decimal_amount, transaction_success
from app.utils.ton_assets import merge_asset
from app.utils.security import sanitize_observation
from app.utils.public_context import merge_public_context, failed_public_context, has_public_claims, scoped_public_context

import asyncio
import hashlib
import logging
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Callable, Awaitable
import inspect
from app.aggregator.collection_audit import refresh_audit, merge_audit, record_kind, provider_record_key, provider_record_order

from app.graph.builder import build_graph_payload
from app.models.report import (
    ActivityBurst,
    ActivityChain,
    AddressReport,
    AssetPath,
    BehavioralFingerprint,
    Chain,
    Counterparty,
    CounterpartyRanking,
    CounterpartyRankingEntry,
    DogecoinActivitySignal,
    InactivityPeriod,
    Label,
    RiskFlag,
    ServiceDetection,
    SourceHealth,
    Transaction,
    TonAsset,
    TonActivitySignal,
    TronActivitySignal,
    WalletMigrationSignal,
    WalletTimeline,
)
from app.risk.scoring import score_risk
from app.sources.btc import BitcoinBlockstreamSource, BitcoinMempoolSource
from app.sources.blockcypher import BitcoinBlockCypherSource, DogecoinBlockCypherSource
from app.sources.evm_blockscout import EvmBlockscoutSource, reconcile_blockscout_observations
from app.sources.bsc import BscIntelSource, BscScanApiSource
from app.sources.dogecoin import DogecoinBitquerySource, DogecoinBlockchairSource, DogecoinCoreRpcSource, DogecoinGetBlockSource, DogecoinOklinkSource, DogecoinSoChainSource, DogechainExplorerSource
from app.sources.eth import EthereumBlockchairSource, EthereumEnsSource, EthereumEtherscanApiSource, EthereumEtherscanHtmlSource, EthereumEthplorerSource, EthereumLabelsSource
from app.sources.evm_rpc import AvalancheRpcSource, BscRpcSource, EthereumRpcSource, PolygonRpcSource, ArbitrumRpcSource, OptimismRpcSource
from app.sources.evm_scans_html import (
    ArbiscanHtmlSource,
    BscScanHtmlSource,
    OptimisticEtherscanHtmlSource,
    PolygonScanHtmlSource,
)
from app.sources.manager import build_default_source_manager
from app.sources.risk_cryptoscamdb import CryptoScamDbSource
from app.sources.solana import SolanaRpcSource, SolscanPublicApiSource
from app.sources.ton import DtonPublicSource, FragmentPublicSource, GetgemsPublicSource, TelegramIdentitySource, TonApiSource, TonCenterSource, TonCenterV3Source, TonConsoleSource, TonscanPublicSource, TonviewerPublicSource
from app.sources.tron import TronGridSource, TronScanSource
from app.utils.detect import detect_candidates, looks_like_bitcoin_address, looks_like_dogecoin_address
from app.utils.http import close_shared_clients
from app.utils.ton_normalize import ton_address, ton_canonical_address
from app.attribution.network import VerifiedContractSource,TronContractEvidenceSource

logger = logging.getLogger(__name__)

MIN_DT = datetime.min.replace(tzinfo=timezone.utc)


def _address_key(chain: str, address: str | None) -> str:
    return address_key(chain, address)


SOURCE_PRIORITY = {
    "tonapi": 0,
    "tonconsole": 1,
    "toncenter": 1,
    "toncenter_v3": 6,
    "blockstream_esplora": 0,
    "mempool_space": 1,
    "blockchair_dogecoin": 0,
    "sochain_dogecoin": 1,
    "oklink_dogecoin": 2,
    "dogechain_explorer": 3,
    "dogecoin_core_rpc": 4,
    "bitquery_dogecoin": 5,
    "getblock_dogecoin": 6,
    "solscan_public_api": 0,
    "solana_rpc": 1,
    "etherscan_api": 0,
    "tronscan": 0,
    "trongrid": 1,
    "blockchair_ethereum": 1,
    "ethplorer": 2,
    "ethereum_ens": 1,
    "ethereum_labels": 4,
    "ethereum_rpc": 0,
    "bscscan_api": 0,
    "bsc_intel": 0,
    "bsc_rpc": 1,
    "polygon_rpc": 1,
    "arbitrum_rpc": 1,
    "optimism_rpc": 1,
    "avalanche_rpc": 1,
    "tonviewer_public": 2,
    "tonscan_public": 2,
    "dton_public": 2,
    "telegram_identity": 6,
    "fragment_public": 7,
    "getgems_public": 7,
    "cryptoscamdb": 8,
}

EXPERIMENTAL_SOURCES = {
    "tonconsole",
    "toncenter_v3",
    "telegram_identity",
    "fragment_public",
    "getgems_public",
    "tonscan_public",
    "dton_public",
    "cryptoscamdb",
}

FAIL_COUNTS: dict[str, int] = defaultdict(int)
DISABLED_SOURCES: set[str] = set()
SOURCE_CONCURRENCY = 4
SOURCE_MANAGER = build_default_source_manager()
ESSENTIAL_TON_SOURCES = {"tonapi", "tonviewer_public", "toncenter", "toncenter_v3", "telegram_identity"}
USDT_TRC20_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
TRON_ACTIVITY_SLUGS = {
    "USDT TRC20 Flow Activity": "usdt_trc20_flow",
    "P2P / Exchange Flow Activity": "p2p_exchange_flow",
    "Resource Usage Activity": "resource_usage",
    "Permission Control Activity": "permission_control",
    "TRON DeFi Activity": "tron_defi",
    "TRON Memecoin Activity": "tron_memecoin",
    "Counterparty Intelligence": "counterparty_intelligence",
    "Stablecoin Status": "stablecoin_status",
}
TRON_DEFI_MARKERS = ("sunswap", "justlend", "sun.io", "sun swap", "just lend", "swap", "lending", "borrow", "staking", "vote")
TRON_MEME_MARKERS = ("sunpump", "sun pump", "memecoin", "meme token")
TRON_EXCHANGE_MARKERS = ("binance", "okx", "bybit", "kucoin", "mexc", "gate", "htx", "bitget", "coinbase", "kraken", "exchange", "p2p")
DOGE_ACTIVITY_SLUGS = {
    "DOGE Balance Summary": "doge_balance_summary",
    "UTXO Activity": "utxo_activity",
    "Dust Activity": "dust_activity",
    "Consolidation Activity": "consolidation_activity",
    "Exchange / Deposit Flow": "exchange_deposit_flow",
    "Whale Transfer Activity": "whale_transfer_activity",
    "Counterparty Diversity": "counterparty_diversity",
    "Transfer Frequency": "transfer_frequency",
}
DOGE_SOURCE_NAMES = {"blockchair_dogecoin", "sochain_dogecoin", "oklink_dogecoin", "dogechain_explorer", "dogecoin_core_rpc", "bitquery_dogecoin", "getblock_dogecoin"}
DOGE_DUST_THRESHOLD = 1.0


def _source_budget(source_name: str, base_timeout: float) -> float:
    managed = SOURCE_MANAGER.timeout(source_name, base_timeout)
    if managed:
        return managed
    base_timeout = max(float(base_timeout), 4.0)
    if source_name == "tonapi":
        return min(max(base_timeout, 18.0), 18.0)
    if source_name == "tonconsole":
        return min(max(base_timeout, 12.0), 12.0)
    if source_name == "toncenter_v3":
        return min(base_timeout, 10.0)
    if source_name == "toncenter":
        return min(base_timeout, 7.0)
    if source_name == "blockchair_dogecoin":
        return min(max(base_timeout, 6.0), 6.0)
    if source_name in {"sochain_dogecoin", "oklink_dogecoin", "dogechain_explorer", "dogecoin_core_rpc"}:
        return min(base_timeout, 4.0)
    if source_name in {"bitquery_dogecoin", "getblock_dogecoin"}:
        return min(base_timeout, 3.0)
    if source_name == "ethereum_ens":
        return min(base_timeout, 24.0)
    if source_name in {"mempool_space", "blockstream_esplora", "tronscan", "trongrid", "solana_rpc", "blockchair_ethereum", "etherscan_api", "ethplorer", "ethereum_labels"}:
        return min(base_timeout, 4.0)
    if source_name.endswith("_rpc"):
        return min(base_timeout, 4.0)
    if source_name in {"telegram_identity"}:
        return min(base_timeout, 5.0)
    if source_name in {"cryptoscamdb"}:
        return min(base_timeout, 3.0)
    if source_name in {"fragment_public", "getgems_public"}:
        return min(base_timeout, 5.0)
    if source_name in {"tonviewer_public", "tonscan_public", "dton_public"}:
        return min(base_timeout, 2.5)
    return min(base_timeout, 3.0)


def _source_disabled(source_name: str) -> bool:
    # SourceManager owns the recoverable circuit breaker. Legacy counters are diagnostic.
    return False


def _tonconsole_available() -> bool:
    return bool((os.getenv("TONCONSOLE_API_KEY") or os.getenv("TON_CONSOLE_API_KEY") or "").strip())


def _record_source_result(source_name: str, ok: bool) -> None:
    if ok:
        FAIL_COUNTS[source_name] = 0
        DISABLED_SOURCES.discard(source_name)
        SOURCE_MANAGER.record_success(source_name)
        return
    FAIL_COUNTS[source_name] += 1
    SOURCE_MANAGER.record_fail(source_name)
    if source_name in ESSENTIAL_TON_SOURCES:
        SOURCE_MANAGER.plan(source_name, 5.0).enabled = True
        return
    if FAIL_COUNTS[source_name] >= 3:
        DISABLED_SOURCES.add(source_name)


def _safe_address(chain: str, value) -> str:
    if value is None:
        return ""
    if chain == "ton":
        return ton_address(value) or ""
    if isinstance(value, dict):
        for key in ("address", "account", "account_address", "wallet_address", "from", "to", "owner"):
            found = _safe_address(chain, value.get(key))
            if found:
                return found
        return ""
    return str(value).strip()


def _ton_asset_title_key(asset: TonAsset) -> str:
    title = (asset.title or "").strip().lower()
    name = (asset.name or "").strip().lower()
    value = title or name
    if asset.type != "username":
        return value
    if "@" in name:
        value = name
    marker = value.replace("buy @", "@")
    if "@" not in marker:
        return value
    candidate = marker.split("@", 1)[1]
    out = []
    for char in candidate:
        if char.isalnum() or char == "_":
            out.append(char)
        else:
            break
    return f"@{''.join(out)}" if out else value


def _has_btc_io(tx: Transaction) -> bool:
    return tx.chain == "btc" and bool(tx.inputs or tx.outputs)


def _has_doge_io(tx: Transaction) -> bool:
    return tx.chain == "doge" and bool(tx.inputs or tx.outputs)


def _has_utxo_io(tx: Transaction) -> bool:
    return _has_btc_io(tx) or _has_doge_io(tx)


def _merge_bitcoin(left: dict, right: dict) -> dict:
    if not left:
        return dict(right or {})
    if not right:
        return left
    out = dict(left)
    for key in ("address", "chain"):
        out[key] = out.get(key) or right.get(key)
    for key in ("balance", "balance_sats", "total_received", "total_received_sats", "total_sent", "total_sent_sats", "tx_count", "unspent_outputs"):
        current = out.get(key)
        incoming = right.get(key)
        if current in (None, "", 0) and incoming not in (None, ""):
            out[key] = incoming
        elif key in {"tx_count", "unspent_outputs", "total_received", "total_received_sats", "total_sent", "total_sent_sats"} and incoming not in (None, ""):
            out[key] = max(current or 0, incoming or 0)
    first_values = [value for value in (out.get("first_seen"), right.get("first_seen")) if value]
    last_values = [value for value in (out.get("last_seen"), right.get("last_seen")) if value]
    out["first_seen"] = min(first_values) if first_values else None
    out["last_seen"] = max(last_values) if last_values else None
    links = dict(out.get("explorer_links") or {})
    links.update({key: value for key, value in (right.get("explorer_links") or {}).items() if value})
    out["explorer_links"] = links
    seen_utxos = {}
    for item in list(out.get("utxos") or []) + list(right.get("utxos") or []):
        key = (str(item.get("txid") or item.get("tx_hash") or ""), str(item.get("vout") or ""))
        if key[0]:
            seen_utxos[key] = item
    out["utxos"] = list(seen_utxos.values())
    out["unspent_outputs"] = max(int(out.get("unspent_outputs") or 0), len(out["utxos"]))
    out["sources"] = list(dict.fromkeys(list(out.get("sources") or []) + list(right.get("sources") or [])))
    out["warnings"] = list(dict.fromkeys(list(out.get("warnings") or []) + list(right.get("warnings") or [])))
    out["partial"] = bool(out.get("partial") or right.get("partial") or out["warnings"])
    return out


def _merge_dogecoin(left: dict, right: dict) -> dict:
    if not left:
        return dict(right or {})
    if not right:
        return left
    out = dict(left)
    for key in ("address", "chain"):
        out[key] = out.get(key) or right.get(key)
    for key in ("balance", "balance_sats", "total_received", "total_received_sats", "total_sent", "total_sent_sats", "tx_count", "output_count", "spent_outputs", "unspent_outputs", "tx_details_count", "active_days", "dust_outputs"):
        current = out.get(key)
        incoming = right.get(key)
        if current in (None, "", 0) and incoming not in (None, ""):
            out[key] = incoming
        elif key in {"tx_count", "output_count", "spent_outputs", "unspent_outputs", "tx_details_count", "active_days", "dust_outputs", "total_received", "total_received_sats", "total_sent", "total_sent_sats"} and incoming not in (None, ""):
            out[key] = max(current or 0, incoming or 0)
    for key in ("largest_incoming", "largest_outgoing"):
        incoming = right.get(key)
        if incoming not in (None, ""):
            out[key] = max(float(out.get(key) or 0), float(incoming or 0))
    first_values = [value for value in (out.get("first_seen"), right.get("first_seen")) if value]
    last_values = [value for value in (out.get("last_seen"), right.get("last_seen")) if value]
    out["first_seen"] = min(first_values) if first_values else out.get("first_seen")
    out["last_seen"] = max(last_values) if last_values else out.get("last_seen")
    links = dict(out.get("explorer_links") or {})
    links.update({key: value for key, value in (right.get("explorer_links") or {}).items() if value})
    out["explorer_links"] = links
    seen_utxos = {}
    for item in list(out.get("utxos") or []) + list(right.get("utxos") or []):
        key = (str(item.get("txid") or item.get("tx_hash") or ""), str(item.get("vout") or ""))
        if key[0]:
            seen_utxos[key] = item
    out["utxos"] = list(seen_utxos.values())
    out["unspent_outputs"] = max(int(out.get("unspent_outputs") or 0), len(out["utxos"]))
    for key in ("repeated_dust_amounts", "warnings", "sources"):
        out[key] = list(dict.fromkeys(list(out.get(key) or []) + list(right.get(key) or [])))
    out["partial"] = bool(out.get("partial") or right.get("partial") or out.get("warnings"))
    return out


def _merge_tron(left: dict, right: dict) -> dict:
    if not left:
        return dict(right or {})
    if not right:
        return left
    out = dict(left)
    for key in ("address", "tx_count", "first_seen", "last_seen"):
        if out.get(key) in (None, "", 0) and right.get(key) not in (None, ""):
            out[key] = right.get(key)
    first_values = [value for value in (out.get("first_seen"), right.get("first_seen")) if value]
    last_values = [value for value in (out.get("last_seen"), right.get("last_seen")) if value]
    out["first_seen"] = min(first_values) if first_values else out.get("first_seen")
    out["last_seen"] = max(last_values) if last_values else out.get("last_seen")
    resources = dict(out.get("resources") or {})
    resources.update({key: value for key, value in (right.get("resources") or {}).items() if value not in (None, "", [], {})})
    out["resources"] = resources
    permissions = dict(out.get("permissions") or {})
    permissions.update({key: value for key, value in (right.get("permissions") or {}).items() if value not in (None, "", [], {})})
    if permissions:
        out["permissions"] = permissions
    links = dict(out.get("explorer_links") or {})
    links.update({key: value for key, value in (right.get("explorer_links") or {}).items() if value})
    out["explorer_links"] = links
    out["sources"] = list(dict.fromkeys(list(out.get("sources") or []) + list(right.get("sources") or [])))
    out["warnings"] = list(dict.fromkeys(list(out.get("warnings") or []) + list(right.get("warnings") or [])))
    out["partial"] = bool(out.get("partial") or right.get("partial") or out["warnings"])
    return out


def _merge_solana(left: dict, right: dict) -> dict:
    if not left:
        return dict(right or {})
    if not right:
        return left
    out = dict(left)
    for key in ("address", "lamports", "balance", "tx_count", "signature_count", "token_accounts", "spl_token_count", "nft_count"):
        if out.get(key) in (None, "", 0) and right.get(key) not in (None, ""):
            out[key] = right.get(key)
    account = dict(out.get("account") or {})
    account.update({key: value for key, value in (right.get("account") or {}).items() if value not in (None, "", [], {}) and key not in account})
    out["account"] = account
    first_values = [value for value in (out.get("first_seen"), right.get("first_seen")) if value]
    last_values = [value for value in (out.get("last_seen"), right.get("last_seen")) if value]
    out["first_seen"] = min(first_values) if first_values else out.get("first_seen")
    out["last_seen"] = max(last_values) if last_values else out.get("last_seen")
    links = dict(out.get("explorer_links") or {})
    links.update({key: value for key, value in (right.get("explorer_links") or {}).items() if value})
    out["explorer_links"] = links
    out["sources"] = list(dict.fromkeys(list(out.get("sources") or []) + list(right.get("sources") or [])))
    out["warnings"] = list(dict.fromkeys(list(out.get("warnings") or []) + list(right.get("warnings") or [])))
    out["partial"] = bool(out.get("partial") or right.get("partial") or out["warnings"])
    out["tx_count_sample"] = bool(out.get("tx_count_sample") or right.get("tx_count_sample"))
    return out


def _merge_bsc(left: dict, right: dict) -> dict:
    if not left:
        return dict(right or {})
    if not right:
        return left
    out = dict(left)
    for key in ("address", "balance", "balance_wei", "tx_count", "is_contract", "code_size", "contract_name", "token_symbol", "verified", "creator", "owner", "holder_count"):
        if out.get(key) in (None, "", 0, [], {}) and right.get(key) not in (None, "", [], {}):
            out[key] = right.get(key)
    for key in ("bep20_transfers_count", "nft_transfers_count", "approvals_count", "transactions_sample_count", "tokens_count", "risk_count"):
        incoming = right.get(key)
        current = out.get(key)
        if incoming not in (None, ""):
            out[key] = max(int(current or 0), int(incoming or 0))
    first_values = [value for value in (out.get("first_seen"), right.get("first_seen")) if value]
    last_values = [value for value in (out.get("last_seen"), right.get("last_seen")) if value]
    out["first_seen"] = min(first_values) if first_values else out.get("first_seen")
    out["last_seen"] = max(last_values) if last_values else out.get("last_seen")
    links = dict(out.get("explorer_links") or {})
    links.update({key: value for key, value in (right.get("explorer_links") or {}).items() if value})
    out["explorer_links"] = links
    source_status = dict(out.get("source_status") or {})
    source_status.update({key: value for key, value in (right.get("source_status") or {}).items() if value})
    out["source_status"] = source_status
    for key in ("security", "dex_pairs", "approvals", "stablecoins", "warnings"):
        items = list(out.get(key) or []) + list(right.get(key) or [])
        seen = {}
        for item in items:
            marker = repr(item)
            seen[marker] = item
        out[key] = list(seen.values())
    out["partial"] = bool(out.get("partial") or right.get("partial") or out.get("warnings"))
    return out


def _parser_contract(report: AddressReport | None, address: str, source_name: str) -> AddressReport:
    if report is None:
        return AddressReport(target_address=address, sources_used=[source_name], errors=[f"{source_name}: parser returned empty result"])
    if not isinstance(report, AddressReport):
        return AddressReport(target_address=address, sources_used=[source_name], errors=[f"{source_name}: parser returned invalid result"])
    report.target_address = report.target_address or address
    report.sources_used = list(dict.fromkeys([item for item in report.sources_used if item] + [source_name]))
    for field in ("balances", "transactions", "tokens", "ton_assets", "ton_activity_intelligence", "tron_activity_intelligence", "dogecoin_activity_intelligence", "telegram_identities", "labels", "risk_flags", "source_health", "activity_chains", "contract_observations"):
        values = getattr(report, field, [])
        setattr(report, field, [item for item in values if item is not None])
    for tx in report.transactions:
        tx.from_address = _safe_address(tx.chain, tx.from_address)
        tx.to_address = _safe_address(tx.chain, tx.to_address)
        if tx.raw is None:
            tx.raw = {}
        tx_type = str((tx.raw or {}).get("type") or "").lower()
        if not tx.from_address and not tx.to_address and not _has_utxo_io(tx) and not (tx.chain == "solana" and tx_type == "solana_signature") and not (tx.chain == "ton" and tx.raw.get("action_index") is not None):
            report.warnings.append(f"{source_name}: transaction_without_parties")
    for asset in report.ton_assets:
        asset.owner_address = _safe_address("ton", asset.owner_address)
        asset.previous_owners = list(dict.fromkeys(_safe_address("ton", item) for item in asset.previous_owners if _safe_address("ton", item)))
        asset.related_addresses = list(dict.fromkeys(_safe_address("ton", item) for item in asset.related_addresses if _safe_address("ton", item)))
        if asset.raw is None:
            asset.raw = {}
    for label in report.labels:
        label.address = _safe_address(label.chain, label.address)
        if label.raw is None:
            label.raw = {}
        label.raw.setdefault("observed_at",datetime.now(timezone.utc).isoformat())
    report.warnings = list(dict.fromkeys(str(item) for item in report.warnings if item))
    report.errors = list(dict.fromkeys(str(item) for item in report.errors if item))
    return report


def _merge(base: AddressReport, other: AddressReport) -> AddressReport:
    base.detected_chains = sorted(set(base.detected_chains + other.detected_chains))
    base.balances.extend(other.balances)
    base.transactions.extend(other.transactions)
    merge_audit(base.collection_audit, other.collection_audit)
    base.tokens.extend(other.tokens)
    base.ton_assets.extend(other.ton_assets)
    base.ton_activity_intelligence.extend(other.ton_activity_intelligence)
    base.tron_activity_intelligence.extend(other.tron_activity_intelligence)
    base.dogecoin_activity_intelligence.extend(other.dogecoin_activity_intelligence)
    base.telegram_identities.extend(other.telegram_identities)
    base.labels.extend(other.labels)
    base.activity_chains.extend(other.activity_chains)
    base.source_health.extend(other.source_health)
    base.risk_flags.extend(other.risk_flags)
    base.contract_observations.extend(other.contract_observations)
    base.coverage.update({key:value for key,value in other.coverage.items() if key.startswith("sourcify_")})
    base.bitcoin = _merge_bitcoin(base.bitcoin, other.bitcoin)
    base.dogecoin = _merge_dogecoin(base.dogecoin, other.dogecoin)
    base.bsc = _merge_bsc(base.bsc, other.bsc)
    base.tron = _merge_tron(base.tron, other.tron)
    base.solana = _merge_solana(base.solana, other.solana)
    ens_fields = ("ens_name", "reverse_ens", "resolver", "ens_reverse_resolver", "ens_owner", "ens_resolved_address", "ens_reverse_valid", "avatar")
    fresh_ens = getattr(other, "ens_profile", None)
    base.public_address_context = merge_public_context(getattr(base, "public_address_context", {}), getattr(other, "public_address_context", {}))
    if fresh_ens:
        # A fresh lookup, including an explicit unavailable/empty outcome,
        # supersedes an older snapshot's current identity assertions.
        base.ens_profile = dict(fresh_ens)
        for field in ens_fields:
            setattr(base, field, getattr(other, field))
        base.text_records = dict(other.text_records)
    else:
        for field in ens_fields:
            if getattr(base, field) in (None, "") and getattr(other, field) not in (None, ""):
                setattr(base, field, getattr(other, field))
        base.text_records.update({key: value for key, value in other.text_records.items() if value and key not in base.text_records})
    base.ens_warnings.extend(other.ens_warnings)
    base.sources_used = sorted(set(base.sources_used + other.sources_used))
    base.warnings.extend(other.warnings)
    base.errors.extend(other.errors)
    return base


def _dedupe_report(report: AddressReport) -> AddressReport:
    reconcile_blockscout_observations(report)
    txs = {}
    duplicate_groups = {}
    before_records = len(report.transactions)
    for tx in report.transactions:
        tx_type = str((tx.raw or {}).get("type") or "").lower()
        # Missing decoded parties are uncertainty, not grounds to discard an
        # observed transaction/action. Graph and flow analysis already guard them.
        tx.event_id = event_identity(tx)
        tx.success = transaction_success(tx)
        if tx.amount_decimal is None:
            tx.amount_decimal = decimal_amount(tx)
        key = (tx.chain, tx.event_id)
        if key not in txs:
            merge_provenance(tx)
            txs[key] = tx
        else:
            current = txs[key]
            duplicate = duplicate_groups.setdefault(tx.event_id, {"identity": tx.event_id, "kind": record_kind(tx), "observations": 1, "sources": [current.source], "tx_hash": tx.tx_hash, "message_index": (tx.raw or {}).get("message_index"), "lt": (tx.raw or {}).get("lt")})
            duplicate["observations"] += 1
            duplicate["sources"] = sorted(set(duplicate["sources"] + [tx.source]))
            merge_provenance(current, tx)
            for field in ("timestamp", "amount_decimal", "amount_base_units", "decimals", "success", "fee", "confirmations", "url"):
                if getattr(current, field) is None and getattr(tx, field) is not None:
                    setattr(current, field, getattr(tx, field))
    report.transactions = list(txs.values())
    prior_duplicates = {item["identity"]: item for item in report.collection_audit.get("duplicates", [])}
    for key, item in duplicate_groups.items():
        old = prior_duplicates.get(key)
        if old and old.get("observations", 0) > item["observations"]:
            item["observations"] = old["observations"]
        prior_duplicates[key] = item
    report.collection_audit["duplicates"] = list(prior_duplicates.values())
    refresh_audit(report, "deduplication", input_records=before_records, excluded_this_pass=before_records-len(report.transactions), key_policy="physical TON message hash when available; otherwise chain + stable operation identity, asset and action/message indices; all source observations retained")

    labels = {}
    for label in report.labels:
        key = (label.chain, _address_key(label.chain, label.address), label.label.lower())
        current = labels.get(key)
        if current is None or label.confidence > current.confidence or (label.confidence == current.confidence and SOURCE_PRIORITY.get(label.source, 99) < SOURCE_PRIORITY.get(current.source, 99)):
            labels[key] = label
    report.labels = list(labels.values())

    tokens = {}
    for token in report.tokens:
        key = (token.chain, _address_key(token.chain, token.address), _address_key(token.chain, token.contract), (token.symbol or "").lower(), token.holding_status, str(token.raw.get("token_account") or token.raw.get("token_account_address") or ""))
        current = tokens.get(key)
        if current is None:
            merge_provenance(token)
            tokens[key] = token
            continue
        for field in ("contract", "symbol", "name", "amount", "url"):
            if getattr(current, field) in (None, "") and getattr(token, field) not in (None, ""):
                setattr(current, field, getattr(token, field))
        merge_provenance(current, token)
    report.tokens = list(tokens.values())

    risks = {}
    for risk in report.risk_flags:
        key = (risk.chain, _address_key(risk.chain, risk.address), risk.flag, risk.source)
        if key not in risks:
            risks[key] = risk
    report.risk_flags = list(risks.values())

    chains = {}
    for item in report.activity_chains:
        key = (item.chain_type, item.asset or "", tuple(item.addresses), tuple(item.tx_hashes[:4]), item.source)
        current = chains.get(key)
        if current is None or item.confidence > current.confidence:
            chains[key] = item
    report.activity_chains = list(chains.values())

    ton_activity_rank = {"high": 4, "medium": 3, "low": 2, "not_detected": 1, "insufficient_data": 0}
    ton_activity = {}
    for item in report.ton_activity_intelligence:
        key = item.title
        current = ton_activity.get(key)
        if current is None or ton_activity_rank.get(item.activity, 0) > ton_activity_rank.get(current.activity, 0):
            ton_activity[key] = item
    report.ton_activity_intelligence = list(ton_activity.values())

    tron_activity_rank = {"high": 4, "medium": 3, "low": 2, "not_detected": 1, "insufficient_data": 0}
    tron_activity = {}
    for item in report.tron_activity_intelligence:
        key = item.title
        current = tron_activity.get(key)
        if current is None or tron_activity_rank.get(item.activity, 0) > tron_activity_rank.get(current.activity, 0):
            tron_activity[key] = item
    report.tron_activity_intelligence = list(tron_activity.values())

    dogecoin_activity_rank = {"high": 4, "medium": 3, "low": 2, "not_detected": 1, "insufficient_data": 0}
    dogecoin_activity = {}
    for item in report.dogecoin_activity_intelligence:
        key = item.title
        current = dogecoin_activity.get(key)
        if current is None or dogecoin_activity_rank.get(item.activity, 0) > dogecoin_activity_rank.get(current.activity, 0):
            dogecoin_activity[key] = item
    report.dogecoin_activity_intelligence = list(dogecoin_activity.values())

    health = {}
    rank = {"ok": 7, "partial": 6, "empty": 5, "experimental": 4, "skipped": 3, "unavailable": 3, "rate_limited": 2, "timeout": 1, "error": 0}
    for item in report.source_health:
        current = health.get(item.source)
        if current is not None:
            history = current.details or ""
            item.details = f"{item.details or ''}; prior observation: {current.status}: {history}".strip("; ")
            if current.status in {"ok", "partial"} and item.status in {"error", "timeout", "rate_limited"} or item.status in {"ok", "partial"} and current.status in {"error", "timeout", "rate_limited"}:
                item.status = "partial"
                item.partial = True
        if current is None or rank[item.status] <= rank[current.status] or item.status == "partial":
            health[item.source] = item
    report.source_health = list(health.values())

    assets_to_merge = list(report.ton_assets)
    report.ton_assets = []
    for asset in assets_to_merge:
        # Contract identity only: names and titles are untrusted metadata.
        if not asset.asset_id:
            report.ton_assets.append(asset)
        else:
            merge_asset(report, asset)

    identity_rank = {"unknown": 0, "weak": 1, "likely": 2, "confirmed": 3}
    identities = {}
    for identity in report.telegram_identities:
        key = (identity.wallet_address, identity.username or "", identity.telegram_user_id or "")
        current = identities.get(key)
        if current is None:
            identities[key] = identity
            continue
        if identity_rank[identity.confidence] > identity_rank[current.confidence]:
            current.confidence = identity.confidence
        if current.evidence_url is None and identity.evidence_url:
            current.evidence_url = identity.evidence_url
        if current.collected_at is None and identity.collected_at:
            current.collected_at = identity.collected_at
        current.domains = list(dict.fromkeys(current.domains + identity.domains))
        current.asset_ids = list(dict.fromkeys(current.asset_ids + identity.asset_ids))
        current.gifts = list(dict.fromkeys(current.gifts + identity.gifts))
        current.evidence = list({(e.source, e.evidence_url, e.evidence_tx, e.nft_contract, e.details): e for e in current.evidence + identity.evidence}.values())
        current.raw.update({k: v for k, v in identity.raw.items() if k not in current.raw})
    for identity in identities.values():
        if not identity.identity_verified and identity.confidence == "confirmed":
            identity.confidence = "weak"
    report.telegram_identities = list(identities.values())
    report.warnings = list(dict.fromkeys(report.warnings))
    report.errors = list(dict.fromkeys(report.errors))
    report.ens_warnings = list(dict.fromkeys(str(item) for item in report.ens_warnings if item))
    report.text_records = {str(key): str(value) for key, value in report.text_records.items() if key and value}
    return report


def _recover_ton_assets_from_identities(report: AddressReport) -> int:
    recovered = 0
    existing = {
        (asset.type, (ton_canonical_address(asset.asset_id) or asset.asset_id or "").lower())
        for asset in report.ton_assets
    }
    for identity in report.telegram_identities:
        if identity.confidence == "unknown":
            continue
        for asset_id in identity.asset_ids:
            asset_key = (ton_canonical_address(asset_id) or asset_id or "").lower()
            if not asset_key:
                continue
            if identity.username and ("username", asset_key) not in existing:
                report.ton_assets.append(
                    TonAsset(
                        asset_id=asset_id,
                        type="username",
                        title=f"@{identity.username}",
                        name=identity.username,
                        owner_address=identity.wallet_address or report.target_address,
                        source=identity.source,
                        evidence_url=identity.evidence_url,
                        collected_at=identity.collected_at,
                        confidence=0.82 if identity.confidence == "confirmed" else 0.62,
                        raw={"asset_type": "username", "recovered_from_identity": True},
                    )
                )
                existing.add(("username", asset_key))
                recovered += 1
            for domain in identity.domains:
                if ("domain", asset_key) in existing:
                    continue
                report.ton_assets.append(
                    TonAsset(
                        asset_id=asset_id,
                        type="domain",
                        title=domain,
                        name=domain,
                        owner_address=identity.wallet_address or report.target_address,
                        source=identity.source,
                        evidence_url=identity.evidence_url,
                        collected_at=identity.collected_at,
                        confidence=0.78 if identity.confidence == "confirmed" else 0.58,
                        raw={"asset_type": "domain", "recovered_from_identity": True},
                    )
                )
                existing.add(("domain", asset_key))
                recovered += 1
            for gift in identity.gifts:
                if ("gift", asset_key) in existing:
                    continue
                report.ton_assets.append(
                    TonAsset(
                        asset_id=asset_id,
                        type="gift",
                        title=gift,
                        name=gift,
                        owner_address=identity.wallet_address or report.target_address,
                        source=identity.source,
                        evidence_url=identity.evidence_url,
                        collected_at=identity.collected_at,
                        confidence=0.78 if identity.confidence == "confirmed" else 0.58,
                        raw={"asset_type": "gift", "recovered_from_identity": True},
                    )
                )
                existing.add(("gift", asset_key))
                recovered += 1
    return recovered


def _append_ton_intelligence_health(report: AddressReport) -> None:
    if "ton" not in report.detected_chains:
        return
    username_assets = [asset for asset in report.ton_assets if asset.type == "username"]
    gifts = [asset for asset in report.ton_assets if asset.type == "gift"]
    jetton_assets = [asset for asset in report.ton_assets if asset.type == "jetton"] + [token for token in report.tokens if token.chain == "ton" and (token.raw or {}).get("asset_type") == "jetton"]
    jetton_txs = [tx for tx in report.transactions if _is_ton_jetton_transaction(tx)]
    username_history = [asset for asset in username_assets if asset.previous_owners or getattr(asset, "history_events", []) or asset.transfer_history or asset.sale_history]
    username_sources = sorted({event.source for asset in username_assets for event in (getattr(asset, "history_events", []) + asset.transfer_history + asset.sale_history)} | {asset.source for asset in username_history})
    gift_sources = sorted({asset.source for asset in gifts})
    jetton_sources = sorted({tx.source for tx in jetton_txs})
    active_signals = sum(1 for item in report.ton_activity_intelligence if item.activity in {"high", "medium", "low"})
    parts = [
        f"signals={len(report.ton_activity_intelligence)}",
        f"active={active_signals}",
        f"username_history={len(username_history)}/{len(username_assets)}",
        f"gifts={len(gifts)}",
        f"jetton_flows={len(jetton_txs)}",
    ]
    if (username_assets and not username_history) or (jetton_assets and not jetton_txs):
        parts.append("partial_data")
    source_parts = []
    if username_sources:
        source_parts.append("username:" + ",".join(username_sources[:3]))
    if gift_sources:
        source_parts.append("gifts:" + ",".join(gift_sources[:3]))
    if jetton_sources:
        source_parts.append("jettons:" + ",".join(jetton_sources[:3]))
    details = "; ".join(parts + source_parts)
    has_data = bool(username_assets or gifts or jetton_assets or jetton_txs)
    partial = (username_assets and not username_history) or (jetton_assets and not jetton_txs)
    report.source_health.append(
        SourceHealth(
            source="ton_intelligence",
            status="partial" if partial or not has_data else "ok",
            timeout_seconds=0,
            retry_strategy="derived from TON assets and transactions",
            details=details or "unavailable",
        )
    )


def _is_ton_jetton_transaction(tx: Transaction) -> bool:
    if tx.chain != "ton":
        return False
    asset = str(tx.asset or "").lower()
    raw = tx.raw or {}
    action = str(raw.get("action_type") or raw.get("asset_type") or raw.get("provider") or raw.get("type") or "").lower()
    return asset.startswith("jetton:") or "jetton" in asset or "jetton" in action


TON_ACTIVITY_SLUGS = {
    "NFT Username Activity": "nft_username",
    "NFT Rental Activity": "nft_rental",
    "Username Trading Activity": "username_trading",
    "Telegram Gifts Activity": "telegram_gifts",
    "Gift Distribution Activity": "gift_distribution",
    "Jetton Activity": "jetton",
    "Marketplace Activity": "marketplace",
    "Counterparty Diversity": "counterparty_diversity",
    "Transfer Frequency": "transfer_frequency",
    "Asset Diversity": "asset_diversity",
}

TON_ACTIVITY_SOURCE_NAMES = {
    "tonapi",
    "tonviewer",
    "tonviewer_public",
    "tonviewer_tonapi",
    "tonviewer_username_history",
    "toncenter",
    "toncenter_v3",
    "tonconsole",
    "telegram_identity",
    "fragment_public",
    "getgems_public",
    "tonscan_public",
    "dton_public",
    "ton_assets_fallback",
}

TON_MARKETPLACE_MARKERS = (
    ("fragment", "Fragment"),
    ("getgems", "Getgems"),
    ("get gems", "Getgems"),
    ("portals marketplace", "Portals"),
    ("portals", "Portals"),
    ("ton diamonds", "TON Diamonds"),
    ("ton.diamonds", "TON Diamonds"),
)

USERNAME_SHORT_HOLD_DAYS = 14.0
GIFT_SHORT_HOLD_DAYS = 7.0


def _ton_source_health_items(report: AddressReport) -> list[SourceHealth]:
    return [
        item
        for item in report.source_health
        if item.source in TON_ACTIVITY_SOURCE_NAMES or item.source.startswith("ton") or item.source in {"fragment_public", "getgems_public", "telegram_identity"}
    ]


def _ton_source_issue(report: AddressReport) -> bool:
    return any(item.status in {"timeout", "error", "rate_limited"} for item in _ton_source_health_items(report))


def _ton_data_sources(report: AddressReport) -> list[str]:
    sources = set()
    for balance in report.balances:
        if balance.chain == "ton" and balance.source:
            sources.add(balance.source)
    for tx in report.transactions:
        if tx.chain == "ton" and tx.source:
            sources.add(tx.source)
    for token in report.tokens:
        if token.chain == "ton" and token.source:
            sources.add(token.source)
    for asset in report.ton_assets:
        if asset.source:
            sources.add(asset.source)
        for event in _ton_asset_events(asset):
            if event.source:
                sources.add(event.source)
    for identity in report.telegram_identities:
        if identity.source:
            sources.add(identity.source)
        for evidence in identity.evidence:
            if evidence.source:
                sources.add(evidence.source)
    for label in report.labels:
        if label.chain == "ton" and label.source:
            sources.add(label.source)
    return sorted(sources)


def _ton_signal(
    title: str,
    activity: str,
    facts: dict[str, object],
    evidence: list[str],
    sources: list[str],
    confidence: str = "low",
    raw: dict | None = None,
) -> TonActivitySignal:
    status = "insufficient_data" if activity == "insufficient_data" else "not_detected" if activity == "not_detected" else "ok"
    state = "insufficient" if activity == "insufficient_data" else "not_detected" if activity == "not_detected" else "detected"
    slug = TON_ACTIVITY_SLUGS.get(title, title.lower().replace(" ", "_"))
    payload = dict(raw or {})
    payload.setdefault("observation_key", f"{slug}_{state}")
    return TonActivitySignal(
        title=title,
        activity=activity,
        observation=payload["observation_key"],
        facts={key: value for key, value in facts.items() if value not in (None, "", [], {})},
        evidence=list(dict.fromkeys(item for item in evidence if item)),
        confidence=confidence,
        source=list(dict.fromkeys(item for item in sources if item)),
        status=status,
        raw=payload,
    )


def _activity_by_counts(value: int, high: int, medium: int, low: int = 1) -> str:
    if value >= high:
        return "high"
    if value >= medium:
        return "medium"
    if value >= low:
        return "low"
    return "not_detected"


def _normalize_dt(value: datetime | None) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def _round_days(value: float | None) -> float | None:
    return round(value, 2) if value is not None else None


def _ton_asset_events(asset: TonAsset) -> list:
    events = []
    seen = set()
    for event in list(getattr(asset, "history_events", []) or []) + list(asset.transfer_history or []) + list(asset.sale_history or []):
        key = (event.event_type, event.tx_hash, event.from_address, event.to_address, event.timestamp, event.price)
        if key in seen:
            continue
        seen.add(key)
        events.append(event)
    return events


def _ton_event_direction(event, target_key: str) -> str:
    direction = str(getattr(event, "direction", "") or "").lower()
    if direction in {"in", "out", "self"}:
        return direction
    from_key = _address_key("ton", getattr(event, "from_address", ""))
    to_key = _address_key("ton", getattr(event, "to_address", ""))
    if target_key and to_key == target_key:
        return "in"
    if target_key and from_key == target_key:
        return "out"
    return "unknown"


def _ton_event_counterparty(event, direction: str, target_key: str) -> str:
    direct = ton_address(getattr(event, "counterparty", None))
    if direct:
        return direct
    from_address = ton_address(getattr(event, "from_address", None)) or ""
    to_address = ton_address(getattr(event, "to_address", None)) or ""
    if direction == "in":
        return from_address
    if direction == "out":
        return to_address
    for address in (from_address, to_address):
        if address and _address_key("ton", address) != target_key:
            return address
    return ""


def _ton_marketplace_from_text(value: object) -> str:
    lowered = str(value or "").lower()
    for marker, name in TON_MARKETPLACE_MARKERS:
        if marker in lowered:
            return name
    return ""


def _ton_marketplaces_from_event(event) -> list[str]:
    raw = getattr(event, "raw", None) or {}
    candidates = [
        getattr(event, "marketplace", None),
        getattr(event, "counterparty_label", None),
        getattr(event, "title", None),
        raw.get("marketplace"),
        raw.get("platform"),
        raw.get("source"),
        raw.get("event_label"),
        raw.get("action_type"),
        raw.get("counterparty_label"),
    ]
    return list(dict.fromkeys(name for name in (_ton_marketplace_from_text(item) for item in candidates) if name))


def _ton_marketplaces_from_tx(tx: Transaction) -> list[str]:
    raw = tx.raw or {}
    candidates = [
        tx.source,
        tx.asset,
        raw.get("marketplace"),
        raw.get("platform"),
        raw.get("service"),
        raw.get("action_type"),
        raw.get("comment"),
    ]
    return list(dict.fromkeys(name for name in (_ton_marketplace_from_text(item) for item in candidates) if name))


def _ton_asset_key(asset: TonAsset) -> str:
    return (ton_canonical_address(asset.asset_id) or asset.asset_id or asset.title or asset.name or "").strip().lower()


def _ton_username_value(asset: TonAsset) -> str:
    title = str(asset.title or asset.name or asset.asset_id or "").strip()
    if "@" in title:
        return title.split("@", 1)[1].split()[0].strip(".,;:/").lower()
    return title.strip("@").lower()


def _ton_asset_event_rows(report: AddressReport, asset_type: str | None = None) -> list[dict]:
    target_key = _address_key("ton", report.target_address)
    rows = []
    for asset in report.ton_assets:
        if asset_type and asset.type != asset_type:
            continue
        for event in _ton_asset_events(asset):
            direction = _ton_event_direction(event, target_key)
            counterparty = _ton_event_counterparty(event, direction, target_key)
            rows.append({"asset": asset, "event": event, "direction": direction, "counterparty": counterparty, "timestamp": _normalize_dt(event.timestamp)})
    return rows


def _ton_short_holds(rows: list[dict], max_days: float) -> list[dict]:
    by_asset: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        if row["timestamp"] and row["direction"] in {"in", "out"}:
            by_asset[_ton_asset_key(row["asset"])].append(row)
    holds = []
    for asset_rows in by_asset.values():
        received = []
        for row in sorted(asset_rows, key=lambda item: item["timestamp"] or MIN_DT):
            if row["direction"] == "in":
                received.append(row)
                continue
            if row["direction"] != "out" or not received:
                continue
            start = received.pop(0)
            days = ((row["timestamp"] - start["timestamp"]).total_seconds() / 86400) if row["timestamp"] and start["timestamp"] else None
            if days is not None and 0 <= days <= max_days:
                holds.append({"asset": row["asset"], "received": start, "sent": row, "days": days})
    return holds


def _top_counterparty_values(counter: Counter, display: dict[str, str], limit: int = 5) -> list[str]:
    return [display.get(key, key) for key, _ in counter.most_common(limit)]


def _build_ton_activity_intelligence(report: AddressReport) -> list[TonActivitySignal]:
    if "ton" not in report.detected_chains:
        return []
    target_key = _address_key("ton", report.target_address)
    all_sources = _ton_data_sources(report)
    source_issue = _ton_source_issue(report)
    ton_txs = [tx for tx in report.transactions if tx.chain == "ton"]
    ton_tx_sources = sorted({tx.source for tx in ton_txs if tx.source})
    ton_events = _ton_asset_event_rows(report)
    event_sources = sorted({row["event"].source for row in ton_events if row["event"].source})
    username_assets = [asset for asset in report.ton_assets if asset.type == "username"]
    username_rows = _ton_asset_event_rows(report, "username")
    username_transfer_rows = [row for row in username_rows if row["direction"] in {"in", "out"} or row["event"].event_type in {"transfer", "received_nft", "sent_nft", "owner_change"}]
    username_in = [row for row in username_transfer_rows if row["direction"] == "in"]
    username_out = [row for row in username_transfer_rows if row["direction"] == "out"]
    unique_usernames = sorted({value for value in (_ton_username_value(asset) for asset in username_assets) if value})
    username_counterparties = sorted({row["counterparty"] for row in username_transfer_rows if row["counterparty"]})
    username_marketplace_rows = [
        row
        for row in username_rows
        if row["event"].event_type in {"sale", "listing", "marketplace_sale", "marketplace_purchase"} or _ton_marketplaces_from_event(row["event"])
    ]
    username_sources = sorted({asset.source for asset in username_assets if asset.source} | {row["event"].source for row in username_rows if row["event"].source})
    signals: list[TonActivitySignal] = []

    if not username_assets and source_issue and not all_sources:
        username_activity = "insufficient_data"
    elif not username_assets:
        username_activity = "not_detected"
    elif len(username_assets) >= 10 and len(username_transfer_rows) >= 10:
        username_activity = "high"
    elif len(username_assets) >= 3 or len(username_transfer_rows) >= 3:
        username_activity = "medium"
    else:
        username_activity = "low"
    signals.append(
        _ton_signal(
            "NFT Username Activity",
            username_activity,
            {
                "username_nfts": len(username_assets),
                "username_assets": len(unique_usernames) or len(username_assets),
                "incoming_username_nft_transfers": len(username_in),
                "outgoing_username_nft_transfers": len(username_out),
                "unique_usernames": len(unique_usernames) or len(username_assets),
                "transfer_events": len(username_transfer_rows),
                "marketplace_events": len(username_marketplace_rows),
            },
            ["TonAPI account assets" if any(source == "tonapi" for source in username_sources) else "", "Tonviewer history" if any("tonviewer" in source for source in username_sources) else "", "NFT transfer events" if username_transfer_rows else ""],
            username_sources or all_sources,
            "high" if len(username_transfer_rows) >= 5 else "medium" if username_assets else "low",
        )
    )

    username_holds = _ton_short_holds(username_transfer_rows, USERNAME_SHORT_HOLD_DAYS)
    username_hold_days = [item["days"] for item in username_holds if item.get("days") is not None]
    if not username_assets:
        rental_activity = "not_detected"
    elif not username_transfer_rows:
        rental_activity = "insufficient_data"
    elif len(username_holds) >= 6 and len(username_counterparties) >= 6 and len(username_transfer_rows) >= 12:
        rental_activity = "high"
    elif len(username_holds) >= 3 and len(username_counterparties) >= 3:
        rental_activity = "medium"
    elif len(username_holds) >= 2 and len(username_transfer_rows) >= 4:
        rental_activity = "low"
    else:
        rental_activity = "not_detected"
    signals.append(
        _ton_signal(
            "NFT Rental Activity",
            rental_activity,
            {
                "short_holds": len(username_holds),
                "average_holding_days": _round_days(sum(username_hold_days) / len(username_hold_days)) if username_hold_days else None,
                "median_holding_days": _round_days(_median(username_hold_days)),
                "received_username_nfts": len(username_in),
                "sent_username_nfts": len(username_out),
                "unique_counterparties": len(username_counterparties),
                "short_hold_threshold_days": USERNAME_SHORT_HOLD_DAYS,
            },
            ["Tonviewer history" if username_transfer_rows else "", "NFT transfer events" if username_transfer_rows else ""],
            sorted({row["event"].source for row in username_transfer_rows if row["event"].source}) or username_sources,
            "high" if len(username_holds) >= 3 else "medium" if username_holds else "low",
        )
    )

    marketplace_names = Counter()
    for row in username_marketplace_rows:
        for name in _ton_marketplaces_from_event(row["event"]):
            marketplace_names[name] += 1
    purchase_events = [row for row in username_marketplace_rows if row["event"].event_type == "marketplace_purchase" or row["direction"] == "in"]
    sale_events = [row for row in username_marketplace_rows if row["event"].event_type in {"marketplace_sale", "sale"} or row["direction"] == "out"]
    priced_events = [row for row in username_marketplace_rows if row["event"].price is not None or row["event"].amount is not None]
    if not username_assets:
        trading_activity = "not_detected"
    elif not username_rows:
        trading_activity = "insufficient_data"
    elif len(username_marketplace_rows) >= 10 and len(unique_usernames) >= 8 and (len(purchase_events) + len(sale_events)) >= 6:
        trading_activity = "high"
    elif len(username_marketplace_rows) >= 3 and (len(purchase_events) + len(sale_events)) >= 2:
        trading_activity = "medium"
    elif len(username_marketplace_rows) >= 1:
        trading_activity = "low"
    else:
        trading_activity = "not_detected"
    signals.append(
        _ton_signal(
            "Username Trading Activity",
            trading_activity,
            {
                "marketplace_events": len(username_marketplace_rows),
                "purchase_events": len(purchase_events),
                "sale_events": len(sale_events),
                "outgoing_username_nft_transfers": len(username_out),
                "marketplaces": list(marketplace_names.keys())[:6],
                "priced_events": len(priced_events),
            },
            ["Marketplace events" if username_marketplace_rows else "", "NFT transfer events" if username_transfer_rows else ""],
            sorted({row["event"].source for row in username_marketplace_rows if row["event"].source}) or username_sources,
            "high" if len(username_marketplace_rows) >= 4 else "medium" if username_marketplace_rows else "low",
        )
    )

    gift_assets = [asset for asset in report.ton_assets if asset.type == "gift"]
    gift_rows = _ton_asset_event_rows(report, "gift")
    gift_in = [row for row in gift_rows if row["direction"] == "in"]
    gift_out = [row for row in gift_rows if row["direction"] == "out"]
    identity_gifts = sorted({gift for identity in report.telegram_identities if identity.confidence != "unknown" for gift in identity.gifts if gift})
    asset_gift_names = {str(asset.title or asset.name or asset.asset_id).lower() for asset in gift_assets}
    regular_gifts = [gift for gift in identity_gifts if gift.lower() not in asset_gift_names]
    gift_senders = sorted({row["counterparty"] for row in gift_in if row["counterparty"]})
    gift_receivers = sorted({row["counterparty"] for row in gift_out if row["counterparty"]})
    total_gifts = len(gift_assets) + len(regular_gifts)
    if not total_gifts and source_issue and not all_sources:
        gift_activity = "insufficient_data"
    elif not total_gifts:
        gift_activity = "not_detected"
    elif total_gifts >= 20 or len(gift_rows) >= 20:
        gift_activity = "high"
    elif total_gifts >= 5 or len(gift_rows) >= 3:
        gift_activity = "medium"
    else:
        gift_activity = "low"
    gift_sources = sorted({asset.source for asset in gift_assets if asset.source} | {row["event"].source for row in gift_rows if row["event"].source} | {identity.source for identity in report.telegram_identities if identity.gifts})
    signals.append(
        _ton_signal(
            "Telegram Gifts Activity",
            gift_activity,
            {
                "total_gifts": total_gifts,
                "nft_gifts": len(gift_assets),
                "regular_gifts": len(regular_gifts),
                "incoming": len(gift_in),
                "outgoing": len(gift_out),
                "unique_senders": len(gift_senders),
                "unique_receivers": len(gift_receivers),
            },
            ["Telegram gift assets" if gift_assets else "", "Gift transfer events" if gift_rows else ""],
            gift_sources or all_sources,
            "high" if len(gift_rows) >= 8 or total_gifts >= 10 else "medium" if total_gifts else "low",
        )
    )

    gift_holds = _ton_short_holds(gift_rows, GIFT_SHORT_HOLD_DAYS)
    if not total_gifts:
        distribution_activity = "not_detected"
    elif not gift_rows and total_gifts >= 10:
        distribution_activity = "insufficient_data"
    elif len(gift_rows) >= 20 or len(gift_receivers) >= 15 or len(gift_senders) >= 15:
        distribution_activity = "high"
    elif len(gift_rows) >= 8 or len(gift_receivers) >= 6 or len(gift_senders) >= 6 or len(gift_holds) >= 4:
        distribution_activity = "medium"
    elif len(gift_rows) >= 4 or len(gift_receivers) >= 3 or len(gift_senders) >= 3 or len(gift_holds) >= 2:
        distribution_activity = "low"
    else:
        distribution_activity = "not_detected"
    signals.append(
        _ton_signal(
            "Gift Distribution Activity",
            distribution_activity,
            {
                "total_gifts": total_gifts,
                "incoming": len(gift_in),
                "outgoing": len(gift_out),
                "unique_senders": len(gift_senders),
                "unique_receivers": len(gift_receivers),
                "short_holds": len(gift_holds),
                "short_hold_threshold_days": GIFT_SHORT_HOLD_DAYS,
            },
            ["Gift transfer events" if gift_rows else "", "Telegram gift assets" if gift_assets else ""],
            gift_sources or all_sources,
            "high" if distribution_activity == "high" else "medium" if distribution_activity in {"medium", "low"} else "low",
        )
    )

    jetton_tokens = [token for token in report.tokens if token.chain == "ton" and (token.raw or {}).get("asset_type") == "jetton"]
    jetton_assets = [asset for asset in report.ton_assets if asset.type == "jetton"]
    jetton_keys = {
        str(token.contract or token.symbol or token.name or "").strip().lower()
        for token in jetton_tokens
        if str(token.contract or token.symbol or token.name or "").strip()
    } | {
        str(asset.asset_id or asset.title or asset.name or "").strip().lower()
        for asset in jetton_assets
        if str(asset.asset_id or asset.title or asset.name or "").strip()
    }
    jetton_txs = [tx for tx in ton_txs if _is_ton_jetton_transaction(tx)]
    jetton_in = [tx for tx in jetton_txs if tx.direction == "in"]
    jetton_out = [tx for tx in jetton_txs if tx.direction == "out"]
    jetton_counter = Counter()
    jetton_display = {}
    for tx in jetton_txs:
        cp = tx.from_address if tx.direction == "in" else tx.to_address if tx.direction == "out" else tx.to_address or tx.from_address or ""
        cp_key = _address_key("ton", cp)
        if cp and cp_key and cp_key != target_key:
            jetton_counter[cp_key] += 1
            jetton_display[cp_key] = cp
    largest_jetton = max([tx for tx in jetton_txs if tx.amount is not None], key=lambda item: item.amount or 0, default=None)
    weak_metadata_jettons = sum(1 for token in jetton_tokens if not (token.symbol or token.name))
    stablecoins = sum(1 for token in jetton_tokens if str(token.symbol or token.name or "").upper() in {"USDT", "USDC", "USDв‚®"})
    if not jetton_keys and source_issue and not all_sources:
        jetton_activity = "insufficient_data"
    elif len(jetton_keys) >= 10 or len(jetton_txs) >= 20:
        jetton_activity = "high"
    elif len(jetton_keys) >= 3 or len(jetton_txs) >= 5:
        jetton_activity = "medium"
    elif jetton_keys or jetton_txs:
        jetton_activity = "low"
    else:
        jetton_activity = "not_detected"
    jetton_sources = sorted({token.source for token in jetton_tokens if token.source} | {asset.source for asset in jetton_assets if asset.source} | {tx.source for tx in jetton_txs if tx.source})
    signals.append(
        _ton_signal(
            "Jetton Activity",
            jetton_activity,
            {
                "jettons": len(jetton_keys),
                "jetton_transfers": len(jetton_txs),
                "incoming": len(jetton_in),
                "outgoing": len(jetton_out),
                "largest_transfer": f"{largest_jetton.amount} {largest_jetton.asset}" if largest_jetton and largest_jetton.amount is not None else "",
                "top_counterparties": _top_counterparty_values(jetton_counter, jetton_display),
                "weak_metadata_jettons": weak_metadata_jettons,
                "stablecoin_hints": stablecoins,
            },
            ["TonAPI jettons" if any(source == "tonapi" for source in jetton_sources) else "", "Toncenter jetton transfers" if any(source == "toncenter_v3" for source in jetton_sources) else "", "Jetton transfers" if jetton_txs else ""],
            jetton_sources or all_sources,
            "high" if len(jetton_txs) >= 10 else "medium" if jetton_keys or jetton_txs else "low",
        )
    )

    marketplace_counter = Counter()
    marketplace_sources = set()
    marketplace_event_count = 0
    for row in ton_events:
        names = _ton_marketplaces_from_event(row["event"])
        if not names:
            continue
        marketplace_event_count += 1
        marketplace_sources.add(row["event"].source)
        for name in names:
            marketplace_counter[name] += 1
    for tx in ton_txs:
        names = _ton_marketplaces_from_tx(tx)
        if not names:
            continue
        marketplace_event_count += 1
        marketplace_sources.add(tx.source)
        for name in names:
            marketplace_counter[name] += 1
    for label in report.labels:
        if label.chain != "ton":
            continue
        name = _ton_marketplace_from_text(label.label)
        if name:
            marketplace_counter[name] += 1
            marketplace_sources.add(label.source)
    if marketplace_event_count >= 12 or (marketplace_event_count >= 8 and len(marketplace_counter) >= 2):
        marketplace_activity = "high"
    elif marketplace_event_count >= 3:
        marketplace_activity = "medium"
    elif marketplace_event_count >= 1 or marketplace_counter:
        marketplace_activity = "low"
    else:
        marketplace_activity = "not_detected"
    signals.append(
        _ton_signal(
            "Marketplace Activity",
            marketplace_activity,
            {
                "marketplace_events": marketplace_event_count,
                "marketplaces": list(marketplace_counter.keys())[:8],
                "top_marketplace": marketplace_counter.most_common(1)[0][0] if marketplace_counter else "",
                "source_labels": sum(1 for label in report.labels if label.chain == "ton" and _ton_marketplace_from_text(label.label)),
            },
            ["Marketplace events" if marketplace_event_count else "", "Marketplace labels" if marketplace_counter else ""],
            sorted(marketplace_sources) or all_sources,
            "high" if marketplace_event_count >= 5 else "medium" if marketplace_event_count or marketplace_counter else "low",
        )
    )

    cp_counter = Counter()
    cp_in = Counter()
    cp_out = Counter()
    cp_display = {}
    for tx in ton_txs:
        cp = tx.from_address if tx.direction == "in" else tx.to_address if tx.direction == "out" else tx.to_address or tx.from_address or ""
        cp_key = _address_key("ton", cp)
        if not cp_key or cp_key == target_key:
            continue
        cp_counter[cp_key] += 1
        cp_display[cp_key] = cp
        if tx.direction == "in":
            cp_in[cp_key] += 1
        elif tx.direction == "out":
            cp_out[cp_key] += 1
    for row in ton_events:
        cp = row["counterparty"]
        cp_key = _address_key("ton", cp)
        if not cp_key or cp_key == target_key:
            continue
        cp_counter[cp_key] += 1
        cp_display[cp_key] = cp
        if row["direction"] == "in":
            cp_in[cp_key] += 1
        elif row["direction"] == "out":
            cp_out[cp_key] += 1
    unique_counterparties = len(cp_counter)
    if not ton_txs and not ton_events and source_issue:
        counterparty_activity = "insufficient_data"
    else:
        counterparty_activity = _activity_by_counts(unique_counterparties, 20, 6, 1)
    signals.append(
        _ton_signal(
            "Counterparty Diversity",
            counterparty_activity,
            {
                "unique_counterparties": unique_counterparties,
                "incoming_counterparties": len(cp_in),
                "outgoing_counterparties": len(cp_out),
                "repeated_counterparties": sum(1 for count in cp_counter.values() if count >= 2),
                "top_counterparties": _top_counterparty_values(cp_counter, cp_display),
            },
            ["TON transactions" if ton_txs else "", "NFT transfer events" if ton_events else ""],
            sorted(set(ton_tx_sources) | set(event_sources)) or all_sources,
            "high" if unique_counterparties >= 12 else "medium" if unique_counterparties else "low",
        )
    )

    transfer_rows = [row for row in ton_events if row["event"].event_type in {"transfer", "received_nft", "sent_nft", "received_ton", "sent_ton", "marketplace_sale", "marketplace_purchase", "sale", "owner_change"}]
    stamps = [_normalize_dt(tx.timestamp) for tx in ton_txs if _normalize_dt(tx.timestamp)] + [row["timestamp"] for row in transfer_rows if row["timestamp"]]
    total_events = len(ton_txs) + len(transfer_rows)
    if total_events and not stamps:
        frequency_activity = "insufficient_data"
    elif not total_events:
        frequency_activity = "insufficient_data" if source_issue and not all_sources else "not_detected"
    else:
        day_counts = Counter(stamp.date().isoformat() for stamp in stamps if stamp)
        active_days = len(day_counts)
        tx_per_day = total_events / active_days if active_days else 0
        peak_count = max(day_counts.values()) if day_counts else 0
        now = datetime.now(timezone.utc)
        last_7 = sum(1 for stamp in stamps if stamp and (now - stamp).days <= 7)
        last_30 = sum(1 for stamp in stamps if stamp and (now - stamp).days <= 30)
        if total_events >= 100 or tx_per_day >= 5 or peak_count >= 20 or last_7 >= 20:
            frequency_activity = "high"
        elif total_events >= 20 or tx_per_day >= 1 or peak_count >= 5 or last_30 >= 10:
            frequency_activity = "medium"
        else:
            frequency_activity = "low"
    day_counts = Counter(stamp.date().isoformat() for stamp in stamps if stamp)
    active_days = len(day_counts)
    tx_per_day = round(total_events / active_days, 2) if active_days else None
    peak = day_counts.most_common(1)[0] if day_counts else ("", 0)
    now = datetime.now(timezone.utc)
    signals.append(
        _ton_signal(
            "Transfer Frequency",
            frequency_activity,
            {
                "total_events": total_events,
                "tx_per_day": tx_per_day,
                "active_days": active_days,
                "peak_day": f"{peak[0]} ({peak[1]})" if peak[0] else "",
                "last_7_days": sum(1 for stamp in stamps if stamp and (now - stamp).days <= 7),
                "last_30_days": sum(1 for stamp in stamps if stamp and (now - stamp).days <= 30),
                "first_activity": min(stamps) if stamps else None,
                "last_activity": max(stamps) if stamps else None,
                "most_active_days": [f"{day} ({count})" for day, count in day_counts.most_common(3)],
            },
            ["TON transactions" if ton_txs else "", "TonAPI events" if any(source == "tonapi" for source in ton_tx_sources) else "", "NFT transfer events" if transfer_rows else ""],
            sorted(set(ton_tx_sources) | set(event_sources)) or all_sources,
            "high" if total_events >= 50 else "medium" if total_events else "low",
        )
    )

    nft_count = sum(1 for asset in report.ton_assets if asset.type in {"nft", "collectible", "domain", "username", "gift"})
    username_count = len(username_assets)
    gift_count = len(gift_assets)
    jetton_count = len(jetton_keys)
    collections = sorted({asset.collection for asset in report.ton_assets if asset.collection})
    token_types = sorted({asset.type for asset in report.ton_assets} | {str((token.raw or {}).get("asset_type") or "token") for token in report.tokens if token.chain == "ton"})
    asset_total = len(report.ton_assets) + len([token for token in report.tokens if token.chain == "ton" and (token.raw or {}).get("asset_type") != "nft"])
    if not asset_total and source_issue:
        asset_activity = "insufficient_data"
    elif asset_total >= 20 and len(token_types) >= 4:
        asset_activity = "high"
    elif asset_total >= 5 or len(token_types) >= 2:
        asset_activity = "medium"
    elif asset_total:
        asset_activity = "low"
    else:
        asset_activity = "not_detected"
    signals.append(
        _ton_signal(
            "Asset Diversity",
            asset_activity,
            {
                "nft_count": nft_count,
                "username_nft_count": username_count,
                "gifts_count": gift_count,
                "jettons_count": jetton_count,
                "unique_collections": len(collections),
                "unique_token_types": len(token_types),
            },
            ["TonAPI account assets" if any(source == "tonapi" for source in all_sources) else "", "Asset metadata" if report.ton_assets or jetton_tokens else ""],
            all_sources,
            "high" if asset_total >= 10 else "medium" if asset_total else "low",
        )
    )
    return signals


def _tron_source_health_items(report: AddressReport) -> list[SourceHealth]:
    return [item for item in report.source_health if item.source in {"tronscan", "trongrid", "tronscan_public_page", "tron_token_metadata", "tron_defi_context"} or item.source.startswith("tron")]


def _tron_source_issue(report: AddressReport) -> bool:
    return any(item.status in {"timeout", "error", "rate_limited", "unavailable"} for item in _tron_source_health_items(report))


def _tron_data_sources(report: AddressReport) -> list[str]:
    sources = set()
    for balance in report.balances:
        if balance.chain == "tron" and balance.source:
            sources.add(balance.source)
    for tx in report.transactions:
        if tx.chain == "tron" and tx.source:
            sources.add(tx.source)
    for token in report.tokens:
        if token.chain == "tron" and token.source:
            sources.add(token.source)
    for label in report.labels:
        if label.chain == "tron" and label.source:
            sources.add(label.source)
    for source in (report.tron or {}).get("sources") or []:
        if source:
            sources.add(str(source))
    return sorted(sources)


def _tron_signal(
    title: str,
    activity: str,
    facts: dict[str, object],
    evidence: list[str],
    sources: list[str],
    confidence: str = "low",
    raw: dict | None = None,
) -> TronActivitySignal:
    status = "insufficient_data" if activity == "insufficient_data" else "not_detected" if activity == "not_detected" else "ok"
    state = "insufficient" if activity == "insufficient_data" else "not_detected" if activity == "not_detected" else "detected"
    slug = TRON_ACTIVITY_SLUGS.get(title, title.lower().replace(" ", "_"))
    payload = dict(raw or {})
    if not payload.get("observation_key"):
        payload["observation_key"] = f"{slug}_{state}"
    return TronActivitySignal(
        title=title,
        activity=activity,
        observation=payload["observation_key"],
        facts={key: value for key, value in facts.items() if value not in (None, "", [], {})},
        evidence=list(dict.fromkeys(item for item in evidence if item)),
        confidence=confidence,
        source=list(dict.fromkeys(item for item in sources if item)),
        status=status,
        raw=payload,
    )


def _tron_tx_type(tx: Transaction) -> str:
    return str((tx.raw or {}).get("type") or "").lower()


def _tron_raw_text(*values: object) -> str:
    parts = []
    for value in values:
        if value in (None, "", [], {}):
            continue
        try:
            parts.append(str(value).lower())
        except Exception:
            continue
    return " ".join(parts)


def _is_usdt_trc20_tx(tx: Transaction) -> bool:
    if tx.chain != "tron" or _tron_tx_type(tx) != "trc20_transfer":
        return False
    raw = tx.raw or {}
    token_info = raw.get("token_info") or {}
    contract = str(raw.get("contract") or token_info.get("tokenId") or token_info.get("address") or "").strip()
    symbol = str(tx.asset or token_info.get("tokenAbbr") or token_info.get("symbol") or "").upper()
    return contract == USDT_TRC20_CONTRACT or symbol == "USDT"


def _tron_counterparty(tx: Transaction, target_key: str) -> str:
    from_key = _address_key("tron", tx.from_address)
    to_key = _address_key("tron", tx.to_address)
    if from_key == target_key and tx.to_address:
        return tx.to_address
    if to_key == target_key and tx.from_address:
        return tx.from_address
    for value in (tx.to_address, tx.from_address):
        if value and _address_key("tron", value) != target_key:
            return value
    return ""


def _tron_amount_counter(items: list[Transaction]) -> list[str]:
    counts = Counter(round(float(tx.amount or 0), 2) for tx in items if tx.amount and float(tx.amount or 0) > 0)
    return [f"{amount:g} x{count}" for amount, count in counts.most_common(6) if count >= 2]


def _tron_same_day_flow(usdt_txs: list[Transaction]) -> tuple[int, float | None]:
    incoming = sorted([tx for tx in usdt_txs if tx.direction == "in" and tx.timestamp], key=lambda tx: tx.timestamp or MIN_DT)
    outgoing = sorted([tx for tx in usdt_txs if tx.direction == "out" and tx.timestamp], key=lambda tx: tx.timestamp or MIN_DT)
    holds = []
    used = set()
    for out_tx in outgoing:
        for index, in_tx in enumerate(incoming):
            if index in used or not in_tx.timestamp or not out_tx.timestamp:
                continue
            seconds = (out_tx.timestamp - in_tx.timestamp).total_seconds()
            if 0 <= seconds <= 86400:
                used.add(index)
                holds.append(seconds / 3600)
                break
    return len(holds), round(sum(holds) / len(holds), 2) if holds else None


def _tron_resource_metric(resources: dict, *markers: str) -> float | None:
    values = []

    def walk(prefix: str, value: object) -> None:
        key = prefix.lower()
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                walk(f"{prefix}.{child_key}" if prefix else str(child_key), child_value)
            return
        if isinstance(value, list):
            for index, child_value in enumerate(value[:20]):
                walk(f"{prefix}.{index}", child_value)
            return
        if any(marker in key for marker in markers):
            try:
                values.append(float(value))
            except (TypeError, ValueError):
                return

    walk("", resources or {})
    return max(values) if values else None


def _tron_permissions(report: AddressReport) -> dict:
    data = dict((report.tron or {}).get("permissions") or {})
    owner = data.get("owner_permission") or data.get("ownerPermission") or {}
    active = data.get("active_permission") or data.get("activePermission") or data.get("active_permissions") or data.get("activePermissions") or []
    if isinstance(active, dict):
        active = [active]
    if not isinstance(active, list):
        active = []
    owner_key_items = owner.get("keys") or owner.get("key") or [] if isinstance(owner, dict) else []
    owner_keys = len(owner_key_items) if isinstance(owner_key_items, list) else 0
    owner_threshold = owner.get("threshold") if isinstance(owner, dict) else None
    active_key_count = 0
    active_thresholds = []
    active_key_items = []
    for item in active:
        if not isinstance(item, dict):
            continue
        keys = item.get("keys") or item.get("key") or []
        if isinstance(keys, list):
            active_key_items.extend(keys)
            active_key_count += len(keys)
        if item.get("threshold") is not None:
            active_thresholds.append(item.get("threshold"))

    def numeric(value: object) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    def key_addresses(values: list) -> set[str]:
        out = set()
        for item in values:
            if isinstance(item, dict):
                value = item.get("address") or item.get("key") or item.get("permission_address")
            else:
                value = item
            if value:
                out.add(str(value).lower())
        return out

    owner_active_diff = bool(key_addresses(owner_key_items if isinstance(owner_key_items, list) else []) and key_addresses(active_key_items) and key_addresses(owner_key_items if isinstance(owner_key_items, list) else []) != key_addresses(active_key_items))
    multisig = bool((owner_threshold and numeric(owner_threshold) > 1) or owner_keys > 1 or any(numeric(value) > 1 for value in active_thresholds) or active_key_count > len(active))
    custom_active = bool(len(active) > 1 or owner_active_diff or any(numeric(value) != 1 for value in active_thresholds if value is not None) or active_key_count > max(len(active), 1))
    return {
        "available": bool(owner or active),
        "owner_threshold": owner_threshold,
        "owner_key_count": owner_keys,
        "active_permissions": len(active),
        "active_key_count": active_key_count,
        "owner_active_diff": owner_active_diff,
        "multisig": multisig,
        "custom_active": custom_active,
    }


def _tron_marker_matches(report: AddressReport, markers: tuple[str, ...], *, include_tokens: bool = False, strict_tx: bool = True) -> list[dict]:
    label_by_address = defaultdict(list)
    for label in report.labels:
        if label.chain == "tron":
            label_by_address[_address_key("tron", label.address)].append(label.label)
    matches = []
    for tx in report.transactions:
        if tx.chain != "tron":
            continue
        counterparty = tx.to_address or tx.from_address or ""
        labels = label_by_address.get(_address_key("tron", counterparty), [])
        raw = tx.raw or {}
        if strict_tx:
            text = _tron_raw_text(raw.get("method"), raw.get("function_name"), raw.get("event_type"), raw.get("contract_type"), raw.get("provider"), raw.get("type"), raw.get("status"), labels)
        else:
            text = _tron_raw_text(tx.asset, tx.source, tx.raw, labels)
        found = [marker for marker in markers if marker in text]
        if found:
            matches.append({"tx": tx, "markers": found, "counterparty": counterparty, "labels": labels})
    if not include_tokens:
        return matches
    for token in report.tokens:
        if token.chain != "tron":
            continue
        text = _tron_raw_text(token.symbol, token.name, token.contract, token.raw)
        found = [marker for marker in markers if marker in text]
        if found:
            matches.append({"token": token, "markers": found, "counterparty": token.contract or "", "labels": []})
    return matches


def _build_tron_activity_intelligence(report: AddressReport) -> list[TronActivitySignal]:
    if "tron" not in report.detected_chains:
        return []
    target_key = _address_key("tron", report.target_address)
    all_sources = _tron_data_sources(report)
    source_issue = _tron_source_issue(report)
    tron_txs = [tx for tx in report.transactions if tx.chain == "tron"]
    trc20_txs = [tx for tx in tron_txs if _tron_tx_type(tx) == "trc20_transfer"]
    usdt_txs = [tx for tx in trc20_txs if _is_usdt_trc20_tx(tx)]
    usdt_in = [tx for tx in usdt_txs if tx.direction == "in"]
    usdt_out = [tx for tx in usdt_txs if tx.direction == "out"]
    usdt_received = sum(float(tx.amount or 0) for tx in usdt_in)
    usdt_sent = sum(float(tx.amount or 0) for tx in usdt_out)
    usdt_counter = Counter()
    usdt_volume = defaultdict(float)
    for tx in usdt_txs:
        cp = _tron_counterparty(tx, target_key)
        if cp:
            key = _address_key("tron", cp)
            usdt_counter[key] += 1
            usdt_volume[key] += float(tx.amount or 0)
    repeated_usdt_counterparties = [key for key, count in usdt_counter.items() if count >= 2]
    active_days = sorted({tx.timestamp.date() for tx in usdt_txs if tx.timestamp})
    same_day_flows, average_holding_hours = _tron_same_day_flow(usdt_txs)
    largest_in = max([tx.amount or 0 for tx in usdt_in], default=0)
    largest_out = max([tx.amount or 0 for tx in usdt_out], default=0)
    average_usdt = (usdt_received + usdt_sent) / len(usdt_txs) if usdt_txs else 0
    signals: list[TronActivitySignal] = []

    if not usdt_txs and source_issue and not trc20_txs:
        usdt_activity = "insufficient_data"
    elif len(usdt_txs) >= 25 or (len(usdt_txs) >= 10 and (usdt_received + usdt_sent) >= 100000):
        usdt_activity = "high"
    elif len(usdt_txs) >= 5 or (usdt_received + usdt_sent) >= 1000:
        usdt_activity = "medium"
    elif usdt_txs:
        usdt_activity = "low"
    else:
        usdt_activity = "not_detected"
    signals.append(
        _tron_signal(
            "USDT TRC20 Flow Activity",
            usdt_activity,
            {
                "total_received_usdt": round(usdt_received, 6),
                "total_sent_usdt": round(usdt_sent, 6),
                "net_usdt_flow": round(usdt_received - usdt_sent, 6),
                "transfer_count": len(usdt_txs),
                "incoming_count": len(usdt_in),
                "outgoing_count": len(usdt_out),
                "largest_incoming": round(largest_in, 6),
                "largest_outgoing": round(largest_out, 6),
                "top_usdt_counterparties": [key for key, _ in usdt_counter.most_common(5)],
                "first_usdt_activity": min([tx.timestamp for tx in usdt_txs if tx.timestamp], default=None),
                "last_usdt_activity": max([tx.timestamp for tx in usdt_txs if tx.timestamp], default=None),
                "active_days": len(active_days),
                "average_transfer_amount": round(average_usdt, 6) if usdt_txs else None,
                "repeated_amounts": _tron_amount_counter(usdt_txs),
                "repeated_counterparties": len(repeated_usdt_counterparties),
            },
            ["TRC20 transfers" if trc20_txs else "", "USDT TRC20 contract" if usdt_txs else ""],
            sorted({tx.source for tx in usdt_txs if tx.source}) or all_sources,
            "high" if len(usdt_txs) >= 10 else "medium" if usdt_txs else "low",
        )
    )

    exchange_matches = _tron_marker_matches(report, TRON_EXCHANGE_MARKERS)
    exchange_counterparties = sorted({_address_key("tron", item.get("counterparty")) for item in exchange_matches if item.get("counterparty")})
    usdt_velocity = round(len(usdt_txs) / max(len(active_days), 1), 4) if usdt_txs else 0
    if not tron_txs and source_issue:
        p2p_activity = "insufficient_data"
    elif len(usdt_txs) >= 30 and len(usdt_counter) >= 15 and same_day_flows >= 5:
        p2p_activity = "high"
    elif (len(usdt_txs) >= 10 and len(usdt_counter) >= 5 and same_day_flows >= 2) or (exchange_matches and len(usdt_txs) >= 3):
        p2p_activity = "medium"
    elif len(usdt_txs) >= 5 and len(usdt_counter) >= 3 and (same_day_flows or repeated_usdt_counterparties):
        p2p_activity = "low"
    else:
        p2p_activity = "not_detected"
    signals.append(
        _tron_signal(
            "P2P / Exchange Flow Activity",
            p2p_activity,
            {
                "unique_counterparties": len(usdt_counter),
                "repeated_counterparties": len(repeated_usdt_counterparties),
                "average_holding_hours": average_holding_hours,
                "same_day_in_out": same_day_flows,
                "top_exchange_like_addresses": exchange_counterparties[:5],
                "transfer_velocity": usdt_velocity,
                "repeated_amounts": _tron_amount_counter(usdt_txs),
            },
            ["USDT TRC20 transfers" if usdt_txs else "", "Explorer labels" if exchange_matches else ""],
            sorted({tx.source for tx in usdt_txs if tx.source} | {item["tx"].source for item in exchange_matches if item.get("tx")}) or all_sources,
            "high" if p2p_activity in {"high", "medium"} else "medium" if p2p_activity == "low" else "low",
        )
    )

    resources = dict((report.tron or {}).get("resources") or {})
    energy_usage = _tron_resource_metric(resources, "energyused", "energy_used", "energy.usage", "energy_usage")
    bandwidth_usage = _tron_resource_metric(resources, "netused", "net_usage", "freenetused", "free_net_usage", "bandwidth")
    trx_fee_burn = round(sum(float(tx.fee or 0) for tx in tron_txs if tx.fee), 8)
    resource_events = [tx for tx in tron_txs if _tron_tx_type(tx) == "resource" or str((tx.raw or {}).get("contract_type") or "") in {"57", "58"}]
    delegated_keys = [key for key, value in resources.items() if "delegat" in str(key).lower() and value not in (None, "", [], {}, 0)]
    possible_fee_optimization = bool(len(usdt_txs) >= 10 and trx_fee_burn <= max(1.0, len(usdt_txs) * 0.15) and (energy_usage or delegated_keys))
    if not resources and not tron_txs and source_issue:
        resource_activity = "insufficient_data"
    elif len(resource_events) >= 5 or (energy_usage and energy_usage >= 100000) or possible_fee_optimization:
        resource_activity = "high"
    elif resources or resource_events or trx_fee_burn:
        resource_activity = "medium"
    elif tron_txs:
        resource_activity = "low"
    else:
        resource_activity = "not_detected"
    signals.append(
        _tron_signal(
            "Resource Usage Activity",
            resource_activity,
            {
                "energy_usage": energy_usage,
                "bandwidth_usage": bandwidth_usage,
                "trx_fee_burn": trx_fee_burn,
                "resource_events": len(resource_events),
                "resource_delegation_fields": delegated_keys[:6],
                "possible_fee_optimization": possible_fee_optimization,
                "usdt_transfers": len(usdt_txs),
            },
            ["TRON account resources" if resources else "", "TRON transaction fees" if tron_txs else ""],
            sorted({tx.source for tx in resource_events if tx.source} | set(all_sources)),
            "high" if resources else "medium" if tron_txs else "low",
            {"observation_key": "resource_usage_optimized" if possible_fee_optimization else None},
        )
    )

    permission = _tron_permissions(report)
    permission_update_txs = [tx for tx in tron_txs if "permission" in _tron_raw_text(tx.raw) or str((tx.raw or {}).get("contract_type") or "") == "46"]
    if not permission["available"]:
        permission_activity = "insufficient_data"
    elif permission["multisig"]:
        permission_activity = "high"
    elif permission["custom_active"] or permission_update_txs:
        permission_activity = "medium"
    else:
        permission_activity = "low"
    signals.append(
        _tron_signal(
            "Permission Control Activity",
            permission_activity,
            {
                "owner_threshold": permission["owner_threshold"],
                "owner_key_count": permission["owner_key_count"],
                "active_permissions": permission["active_permissions"],
                "active_key_count": permission["active_key_count"],
                "owner_active_diff": permission["owner_active_diff"],
                "multisig": permission["multisig"],
                "custom_active_permissions": permission["custom_active"],
                "permission_update_transactions": len(permission_update_txs),
            },
            ["TRON account permissions" if permission["available"] else "", "Permission update transactions" if permission_update_txs else ""],
            sorted(set(all_sources) | {tx.source for tx in permission_update_txs if tx.source}),
            "high" if permission["available"] else "low",
            {"observation_key": "permission_control_normal" if permission_activity == "low" else None},
        )
    )

    defi_matches = _tron_marker_matches(report, TRON_DEFI_MARKERS)
    defi_contracts = sorted({_address_key("tron", item.get("counterparty")) for item in defi_matches if item.get("counterparty")})[:8]
    swaps = sum(1 for item in defi_matches if "swap" in " ".join(item.get("markers") or []))
    lending_events = sum(1 for item in defi_matches if any(marker in {"justlend", "just lend", "lending", "borrow"} for marker in item.get("markers") or []))
    if not tron_txs and source_issue:
        defi_activity = "insufficient_data"
    elif len(defi_matches) >= 10:
        defi_activity = "high"
    elif len(defi_matches) >= 3:
        defi_activity = "medium"
    elif defi_matches:
        defi_activity = "low"
    else:
        defi_activity = "not_detected"
    signals.append(
        _tron_signal(
            "TRON DeFi Activity",
            defi_activity,
            {
                "defi_contracts": defi_contracts,
                "swaps": swaps,
                "lending_events": lending_events,
                "interaction_count": len(defi_matches),
                "first_interaction": min([item["tx"].timestamp for item in defi_matches if item.get("tx") and item["tx"].timestamp], default=None),
                "last_interaction": max([item["tx"].timestamp for item in defi_matches if item.get("tx") and item["tx"].timestamp], default=None),
            },
            ["Explorer labels" if defi_matches else "", "TRON transactions" if defi_matches else ""],
            sorted({item["tx"].source for item in defi_matches if item.get("tx")}) or all_sources,
            "high" if defi_activity in {"high", "medium"} else "medium" if defi_activity == "low" else "low",
        )
    )

    meme_matches = _tron_marker_matches(report, TRON_MEME_MARKERS, include_tokens=True, strict_tx=False)
    created = [item for item in meme_matches if "create" in _tron_raw_text(getattr(item.get("tx") or item.get("token"), "raw", {}))]
    migrations = [item for item in meme_matches if "migration" in _tron_raw_text(getattr(item.get("tx") or item.get("token"), "raw", {}))]
    bought = [item for item in meme_matches if item.get("tx") and item["tx"].direction == "in"]
    if not tron_txs and not report.tokens and source_issue:
        meme_activity = "insufficient_data"
    elif len(meme_matches) >= 10:
        meme_activity = "high"
    elif len(meme_matches) >= 3:
        meme_activity = "medium"
    elif meme_matches:
        meme_activity = "low"
    else:
        meme_activity = "not_detected"
    signals.append(
        _tron_signal(
            "TRON Memecoin Activity",
            meme_activity,
            {
                "token_created": len(created),
                "token_bought": len(bought),
                "early_holder": 0,
                "liquidity_event": 0,
                "migration_event": len(migrations),
                "holder_concentration": 0,
                "sunpump_matches": len([item for item in meme_matches if any("sunpump" in marker or "sun pump" in marker for marker in item.get("markers") or [])]),
            },
            ["Explorer labels" if meme_matches else "", "Token metadata" if any(item.get("token") for item in meme_matches) else ""],
            sorted({item["tx"].source for item in meme_matches if item.get("tx")} | {item["token"].source for item in meme_matches if item.get("token")}) or all_sources,
            "high" if meme_activity in {"high", "medium"} else "medium" if meme_activity == "low" else "low",
        )
    )

    tron_counterparties = [item for item in report.counterparties if item.chain == "tron"]
    incoming_counterparties = sorted({_address_key("tron", tx.from_address) for tx in tron_txs if tx.direction == "in" and tx.from_address})
    outgoing_counterparties = sorted({_address_key("tron", tx.to_address) for tx in tron_txs if tx.direction == "out" and tx.to_address})
    trx_volume = defaultdict(float)
    trc20_tokens_by_cp = defaultdict(set)
    for tx in tron_txs:
        cp = _tron_counterparty(tx, target_key)
        if not cp:
            continue
        key = _address_key("tron", cp)
        if (tx.asset or "").upper() == "TRX":
            trx_volume[key] += float(tx.amount or 0)
        if _tron_tx_type(tx) == "trc20_transfer":
            trc20_tokens_by_cp[key].add(tx.asset or str((tx.raw or {}).get("contract") or "TRC20"))
    top_by_count = [item.address for item in sorted(tron_counterparties, key=lambda cp: cp.tx_count, reverse=True)[:5]]
    top_by_usdt_volume = [key for key, _ in sorted(usdt_volume.items(), key=lambda item: item[1], reverse=True)[:5]]
    top_by_trx_volume = [key for key, _ in sorted(trx_volume.items(), key=lambda item: item[1], reverse=True)[:5]]
    unique_cp_count = len({_address_key("tron", item.address) for item in tron_counterparties})
    if not tron_txs and source_issue:
        counterparty_activity = "insufficient_data"
    elif unique_cp_count >= 30 or len(tron_txs) >= 80:
        counterparty_activity = "high"
    elif unique_cp_count >= 10 or len(tron_txs) >= 20:
        counterparty_activity = "medium"
    elif unique_cp_count:
        counterparty_activity = "low"
    else:
        counterparty_activity = "not_detected"
    signals.append(
        _tron_signal(
            "Counterparty Intelligence",
            counterparty_activity,
            {
                "unique_counterparties": unique_cp_count,
                "incoming_counterparties": len(incoming_counterparties),
                "outgoing_counterparties": len(outgoing_counterparties),
                "repeated_counterparties": len([item for item in tron_counterparties if item.tx_count >= 2]),
                "top_by_transfer_count": top_by_count,
                "top_by_usdt_volume": top_by_usdt_volume,
                "top_by_trx_volume": top_by_trx_volume,
                "top_by_trc20_tokens": [key for key, values in sorted(trc20_tokens_by_cp.items(), key=lambda item: len(item[1]), reverse=True)[:5]],
            },
            ["TRON transactions" if tron_txs else "", "TRC20 transfers" if trc20_txs else ""],
            sorted({tx.source for tx in tron_txs if tx.source}) or all_sources,
            "high" if unique_cp_count >= 10 else "medium" if unique_cp_count else "low",
        )
    )

    failed_trc20 = [tx for tx in trc20_txs if str((tx.raw or {}).get("status") or "").upper() not in {"", "SUCCESS", "CONFIRMED"}]
    stablecoin_text_matches = [tx for tx in usdt_txs if any(marker in _tron_raw_text(tx.raw) for marker in ("blacklist", "frozen", "freeze"))]
    blacklist_labels = [label for label in report.labels if label.chain == "tron" and any(marker in label.label.lower() for marker in ("blacklist", "frozen", "freeze"))]
    if not trc20_txs and source_issue:
        stablecoin_activity = "insufficient_data"
    elif stablecoin_text_matches or blacklist_labels:
        stablecoin_activity = "medium"
    elif failed_trc20:
        stablecoin_activity = "low"
    else:
        stablecoin_activity = "not_detected"
    signals.append(
        _tron_signal(
            "Stablecoin Status",
            stablecoin_activity,
            {
                "failed_trc20_transfers": len(failed_trc20),
                "freeze_blacklist_events": len(stablecoin_text_matches),
                "known_blacklist_labels": len(blacklist_labels),
                "checked_usdt_transfers": len(usdt_txs),
            },
            ["TRC20 transfer status" if trc20_txs else "", "Explorer labels" if blacklist_labels else ""],
            sorted({tx.source for tx in failed_trc20 + stablecoin_text_matches if tx.source} | {label.source for label in blacklist_labels}) or all_sources,
            "high" if stablecoin_text_matches or blacklist_labels else "medium" if failed_trc20 else "low",
        )
    )
    return signals


def _append_tron_intelligence_health(report: AddressReport) -> None:
    if "tron" not in report.detected_chains:
        return
    existing = {item.source for item in report.source_health}
    if "tronscan" not in existing:
        report.source_health.append(SourceHealth(source="tronscan", status="unavailable", timeout_seconds=0, retry_strategy="public API", details="not executed or no response"))
    if "trongrid" not in existing:
        report.source_health.append(SourceHealth(source="trongrid", status="unavailable", timeout_seconds=0, retry_strategy="public API", details="not executed or no response"))
    if "tronscan_public_page" not in existing:
        links = (report.tron or {}).get("explorer_links") or {}
        status = "ok" if links.get("tronscan") else "unavailable"
        details = "explorer link fallback available" if status == "ok" else "explorer link fallback unavailable"
        report.source_health.append(SourceHealth(source="tronscan_public_page", status=status, timeout_seconds=0, retry_strategy="public explorer link", details=details))
    if "tron_token_metadata" not in existing:
        tokens = [token for token in report.tokens if token.chain == "tron"]
        with_metadata = [token for token in tokens if token.symbol or token.name or (token.raw or {}).get("token_info")]
        status = "ok" if with_metadata else "empty" if tokens else "empty"
        report.source_health.append(SourceHealth(source="tron_token_metadata", status=status, timeout_seconds=0, retry_strategy="Tronscan/TronGrid token fields", details=f"tokens={len(tokens)}, metadata={len(with_metadata)}"))
    if "tron_defi_context" not in existing:
        defi = next((item for item in report.tron_activity_intelligence if item.title == "TRON DeFi Activity"), None)
        status = "ok" if defi and defi.activity in {"high", "medium", "low"} else "empty"
        report.source_health.append(SourceHealth(source="tron_defi_context", status=status, timeout_seconds=0, retry_strategy="labels and transaction text", details="DeFi evidence found" if status == "ok" else "no DeFi evidence in collected data"))


def _doge_source_health_items(report: AddressReport) -> list[SourceHealth]:
    return [item for item in report.source_health if item.source in DOGE_SOURCE_NAMES]


def _doge_source_issue(report: AddressReport) -> bool:
    health = _doge_source_health_items(report)
    useful = any(item.status in {"ok", "partial", "empty"} for item in health if item.source == "blockchair_dogecoin")
    hard_fail = any(item.status in {"error", "timeout", "rate_limited", "unavailable"} for item in health if item.source == "blockchair_dogecoin")
    doge_data = bool(report.dogecoin or any(balance.chain == "doge" for balance in report.balances) or any(tx.chain == "doge" for tx in report.transactions))
    return hard_fail and not useful and not doge_data


def _doge_data_sources(report: AddressReport) -> list[str]:
    sources = set()
    for item in report.source_health:
        if item.source in DOGE_SOURCE_NAMES and item.status in {"ok", "partial", "empty"}:
            sources.add(item.source)
    for tx in report.transactions:
        if tx.chain == "doge" and tx.source:
            sources.add(tx.source)
    for balance in report.balances:
        if balance.chain == "doge" and balance.source:
            sources.add(balance.source)
    return sorted(sources)


def _doge_signal(title: str, activity: str, facts: dict[str, object], evidence: list[str], source: list[str], confidence: str = "low") -> DogecoinActivitySignal:
    status = "insufficient_data" if activity == "insufficient_data" else "not_detected" if activity == "not_detected" else "ok"
    state = "insufficient" if activity == "insufficient_data" else "not_detected" if activity == "not_detected" else "detected"
    slug = DOGE_ACTIVITY_SLUGS.get(title, title.lower().replace(" ", "_"))
    observation_key = f"{slug}_{state}"
    return DogecoinActivitySignal(
        title=title,
        activity=activity,
        observation=observation_key,
        facts={key: value for key, value in facts.items() if value not in (None, "", [], {})},
        evidence=[item for item in evidence if item],
        confidence=confidence,
        source=list(dict.fromkeys([item for item in source if item]))[:8],
        status=status,
        raw={"observation_key": observation_key, "state": state},
    )


def _doge_io_address(item: dict) -> str:
    return str((item or {}).get("address") or "").strip()


def _doge_io_value(item: dict) -> float:
    try:
        return float((item or {}).get("value") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _doge_counterparty(tx: Transaction, target_key: str) -> str:
    chain = "doge"
    if tx.direction == "in" and tx.from_address:
        return tx.from_address
    if tx.direction == "out" and tx.to_address:
        return tx.to_address
    for item in list(tx.inputs or []) + list(tx.outputs or []):
        address = _doge_io_address(item)
        if address and _address_key(chain, address) != target_key:
            return address
    return ""


def _doge_day_counts(txs: list[Transaction]) -> tuple[int, str, int, int, int]:
    days = Counter(tx.timestamp.date().isoformat() for tx in txs if tx.timestamp)
    active_days = len(days)
    peak_day, peak_count = days.most_common(1)[0] if days else ("", 0)
    now = datetime.now(timezone.utc)
    last_7 = sum(1 for tx in txs if tx.timestamp and (now - tx.timestamp).days <= 7)
    last_30 = sum(1 for tx in txs if tx.timestamp and (now - tx.timestamp).days <= 30)
    return active_days, peak_day, peak_count, last_7, last_30


def _doge_quick_outgoing(incoming: list[Transaction], outgoing: list[Transaction], hours: int = 24) -> int:
    outgoing_times = sorted(tx.timestamp for tx in outgoing if tx.timestamp)
    count = 0
    for tx in incoming:
        if not tx.timestamp:
            continue
        if any(0 <= (out_time - tx.timestamp).total_seconds() <= hours * 3600 for out_time in outgoing_times):
            count += 1
    return count


def _build_dogecoin_activity_intelligence(report: AddressReport) -> list[DogecoinActivitySignal]:
    if "doge" not in report.detected_chains:
        return []
    data = dict(report.dogecoin or {})
    doge_txs = [tx for tx in report.transactions if tx.chain == "doge"]
    balances = [balance for balance in report.balances if balance.chain == "doge"]
    all_sources = _doge_data_sources(report)
    source_issue = _doge_source_issue(report)
    balance = data.get("balance")
    if balance is None and balances:
        balance = balances[0].amount
    total_received = float(data.get("total_received") or 0)
    total_sent = float(data.get("total_sent") or 0)
    tx_count = int(data.get("tx_count") or len(doge_txs) or 0)
    unspent_outputs = int(data.get("unspent_outputs") or len(data.get("utxos") or []) or 0)
    spent_outputs = int(data.get("spent_outputs") or 0)
    output_count = int(data.get("output_count") or 0)
    details_count = int(data.get("tx_details_count") or len(doge_txs) or 0)
    volume = total_received + total_sent
    signals: list[DogecoinActivitySignal] = []

    if not balances and not data and source_issue:
        balance_activity = "insufficient_data"
    elif tx_count == 0 and not float(balance or 0):
        balance_activity = "not_detected"
    elif tx_count >= 200 or volume >= 500_000 or float(balance or 0) >= 100_000:
        balance_activity = "high"
    elif tx_count >= 20 or volume >= 10_000 or float(balance or 0) >= 1_000:
        balance_activity = "medium"
    else:
        balance_activity = "low"
    signals.append(
        _doge_signal(
            "DOGE Balance Summary",
            balance_activity,
            {
                "balance_doge": balance,
                "total_received": total_received,
                "total_sent": total_sent,
                "tx_count": tx_count,
                "first_activity": data.get("first_seen"),
                "last_activity": data.get("last_seen"),
                "unspent_outputs": unspent_outputs,
            },
            ["Blockchair address dashboard" if data else "", "DOGE balance source" if balances else ""],
            all_sources,
            "high" if balance_activity in {"high", "medium"} else "medium" if balance_activity == "low" else "low",
        )
    )

    consolidation_txs = [tx for tx in doge_txs if tx.direction in {"out", "self"} and int((tx.raw or {}).get("input_count") or len(tx.inputs or [])) >= 10 and float((tx.raw or {}).get("target_input") or 0) > 0]
    sweep_txs = [tx for tx in doge_txs if tx.direction in {"out", "self"} and int((tx.raw or {}).get("input_count") or len(tx.inputs or [])) >= 5 and int((tx.raw or {}).get("output_count") or len(tx.outputs or [])) <= 2 and float((tx.raw or {}).get("target_input") or 0) > 0]
    target_dust_outputs = [
        output
        for tx in doge_txs
        for output in tx.outputs
        if _address_key("doge", _doge_io_address(output)) == _address_key("doge", report.target_address) and 0 < _doge_io_value(output) < DOGE_DUST_THRESHOLD
    ]
    sent_dust_outputs = [
        output
        for tx in doge_txs
        if tx.direction == "out"
        for output in tx.outputs
        if _address_key("doge", _doge_io_address(output)) != _address_key("doge", report.target_address) and 0 < _doge_io_value(output) < DOGE_DUST_THRESHOLD
    ]
    dust_outputs = target_dust_outputs + sent_dust_outputs
    if not doge_txs and not data and source_issue:
        utxo_activity = "insufficient_data"
    elif output_count >= 100 or unspent_outputs >= 50 or len(consolidation_txs) >= 3:
        utxo_activity = "high"
    elif output_count >= 20 or unspent_outputs >= 10 or spent_outputs >= 10 or consolidation_txs:
        utxo_activity = "medium"
    elif output_count or unspent_outputs or doge_txs:
        utxo_activity = "low"
    else:
        utxo_activity = "not_detected"
    signals.append(
        _doge_signal(
            "UTXO Activity",
            utxo_activity,
            {
                "utxo_count": unspent_outputs,
                "spent_outputs": spent_outputs,
                "unspent_outputs": unspent_outputs,
                "dust_outputs": len(dust_outputs),
                "consolidation_tx_count": len(consolidation_txs),
            },
            ["Blockchair UTXO list" if data.get("utxos") else "", "DOGE transaction inputs/outputs" if doge_txs else ""],
            all_sources,
            "high" if data or doge_txs else "low",
        )
    )

    repeated_small = Counter(round(_doge_io_value(item), 8) for item in dust_outputs if _doge_io_value(item) > 0)
    repeated_small_facts = [f"{amount:g} x{count}" for amount, count in repeated_small.most_common(5) if count >= 2]
    if not doge_txs and source_issue:
        dust_activity = "insufficient_data"
    elif len(dust_outputs) >= 20 or sum(count for _, count in repeated_small.items() if count >= 2) >= 10:
        dust_activity = "high"
    elif len(dust_outputs) >= 5 or repeated_small_facts:
        dust_activity = "medium"
    elif dust_outputs:
        dust_activity = "low"
    else:
        dust_activity = "not_detected"
    signals.append(
        _doge_signal(
            "Dust Activity",
            dust_activity,
            {
                "dust_threshold_doge": DOGE_DUST_THRESHOLD,
                "dust_outputs": len(dust_outputs),
                "incoming_dust_outputs": len(target_dust_outputs),
                "outgoing_dust_outputs": len(sent_dust_outputs),
                "repeated_small_amounts": repeated_small_facts,
            },
            ["DOGE transaction outputs" if doge_txs else "", "Blockchair transaction dashboard" if doge_txs else ""],
            all_sources,
            "high" if dust_activity in {"high", "medium"} else "medium" if dust_activity == "low" else "low",
        )
    )

    max_input_count = max([int((tx.raw or {}).get("input_count") or len(tx.inputs or [])) for tx in doge_txs], default=0)
    if not doge_txs and source_issue:
        consolidation_activity = "insufficient_data"
    elif len(consolidation_txs) >= 3 or max_input_count >= 25:
        consolidation_activity = "high"
    elif consolidation_txs or sweep_txs:
        consolidation_activity = "medium"
    elif max_input_count >= 5:
        consolidation_activity = "low"
    else:
        consolidation_activity = "not_detected"
    signals.append(
        _doge_signal(
            "Consolidation Activity",
            consolidation_activity,
            {
                "consolidation_tx_count": len(consolidation_txs),
                "sweep_pattern_count": len(sweep_txs),
                "max_inputs_in_tx": max_input_count,
                "spent_outputs": spent_outputs,
            },
            ["DOGE transaction inputs" if doge_txs else "", "UTXO spend pattern" if consolidation_txs or sweep_txs else ""],
            all_sources,
            "high" if consolidation_activity in {"high", "medium"} else "medium" if consolidation_activity == "low" else "low",
        )
    )

    target_key = _address_key("doge", report.target_address)
    incoming = [tx for tx in doge_txs if tx.direction == "in"]
    outgoing = [tx for tx in doge_txs if tx.direction == "out"]
    incoming_counterparties = sorted({_address_key("doge", _doge_counterparty(tx, target_key)) for tx in incoming if _doge_counterparty(tx, target_key)})
    outgoing_counterparties = sorted({_address_key("doge", _doge_counterparty(tx, target_key)) for tx in outgoing if _doge_counterparty(tx, target_key)})
    quick_outgoing = _doge_quick_outgoing(incoming, outgoing)
    fan_in_out = [tx for tx in doge_txs if int((tx.raw or {}).get("input_count") or len(tx.inputs or [])) >= 10 or int((tx.raw or {}).get("output_count") or len(tx.outputs or [])) >= 20]
    exchange_labels = [label for label in report.labels if label.chain == "doge" and any(marker in label.label.lower() for marker in ("exchange", "deposit", "binance", "okx", "bybit", "kraken", "coinbase"))]
    if not doge_txs and source_issue:
        exchange_activity = "insufficient_data"
    elif exchange_labels and tx_count >= 10:
        exchange_activity = "high"
    elif len(incoming_counterparties) >= 25 and quick_outgoing >= 5 and len(fan_in_out) >= 3:
        exchange_activity = "high"
    elif exchange_labels or (len(incoming_counterparties) >= 10 and (quick_outgoing >= 2 or fan_in_out)):
        exchange_activity = "medium"
    elif len(incoming_counterparties) >= 25 or quick_outgoing or fan_in_out:
        exchange_activity = "low"
    else:
        exchange_activity = "not_detected"
    signals.append(
        _doge_signal(
            "Exchange / Deposit Flow",
            exchange_activity,
            {
                "incoming_counterparties": len(incoming_counterparties),
                "outgoing_counterparties": len(outgoing_counterparties),
                "quick_outgoing_count": quick_outgoing,
                "fan_in_fan_out_tx_count": len(fan_in_out),
                "source_exchange_labels": len(exchange_labels),
            },
            ["DOGE transfer timing" if doge_txs else "", "Source labels" if exchange_labels else "", "Fan-in/fan-out transaction facts" if fan_in_out else ""],
            sorted({tx.source for tx in doge_txs if tx.source} | {label.source for label in exchange_labels}) or all_sources,
            "high" if exchange_labels or exchange_activity in {"high", "medium"} else "medium" if exchange_activity == "low" else "low",
        )
    )

    largest_incoming = float(data.get("largest_incoming") or max([float(tx.amount or 0) for tx in incoming], default=0))
    largest_outgoing = float(data.get("largest_outgoing") or max([float(tx.amount or 0) for tx in outgoing], default=0))
    largest_transfer = max(largest_incoming, largest_outgoing)
    volume_share = largest_transfer / volume if volume else 0
    top_tx = next((tx.tx_hash for tx in doge_txs if float(tx.amount or 0) == largest_transfer), "")
    if not doge_txs and not data and source_issue:
        whale_activity = "insufficient_data"
    elif largest_transfer >= 100_000 or (largest_transfer >= 10_000 and volume_share >= 0.5):
        whale_activity = "high"
    elif largest_transfer >= 10_000 or volume_share >= 0.5 and largest_transfer >= 1_000:
        whale_activity = "medium"
    elif largest_transfer >= 1_000:
        whale_activity = "low"
    else:
        whale_activity = "not_detected"
    signals.append(
        _doge_signal(
            "Whale Transfer Activity",
            whale_activity,
            {
                "largest_incoming": largest_incoming,
                "largest_outgoing": largest_outgoing,
                "largest_transfer": largest_transfer,
                "largest_transfer_share": round(volume_share, 4) if volume_share else 0,
                "top_tx": top_tx,
            },
            ["DOGE transfer amounts" if doge_txs else "", "Blockchair address totals" if data else ""],
            all_sources,
            "high" if whale_activity in {"high", "medium"} else "medium" if whale_activity == "low" else "low",
        )
    )

    doge_counterparties = [item for item in report.counterparties if item.chain == "doge"]
    unique_cp_count = len({_address_key("doge", item.address) for item in doge_counterparties})
    repeated = [item for item in doge_counterparties if item.tx_count >= 2]
    top_counterparties = [item.address for item in sorted(doge_counterparties, key=lambda cp: cp.tx_count, reverse=True)[:5]]
    if not doge_txs and source_issue:
        diversity_activity = "insufficient_data"
    elif unique_cp_count >= 30:
        diversity_activity = "high"
    elif unique_cp_count >= 10:
        diversity_activity = "medium"
    elif unique_cp_count:
        diversity_activity = "low"
    else:
        diversity_activity = "not_detected"
    signals.append(
        _doge_signal(
            "Counterparty Diversity",
            diversity_activity,
            {
                "unique_counterparties": unique_cp_count,
                "incoming_counterparties": len(incoming_counterparties),
                "outgoing_counterparties": len(outgoing_counterparties),
                "repeated_counterparties": len(repeated),
                "top_counterparties": top_counterparties,
            },
            ["DOGE transaction counterparties" if doge_txs else "", "UTXO inputs/outputs" if doge_txs else ""],
            sorted({tx.source for tx in doge_txs if tx.source}) or all_sources,
            "high" if unique_cp_count >= 10 else "medium" if unique_cp_count else "low",
        )
    )

    active_days, peak_day, peak_count, last_7, last_30 = _doge_day_counts(doge_txs)
    tx_per_day = (len(doge_txs) / active_days) if active_days else 0
    first_activity = data.get("first_seen") or min([tx.timestamp for tx in doge_txs if tx.timestamp], default=None)
    last_activity = data.get("last_seen") or max([tx.timestamp for tx in doge_txs if tx.timestamp], default=None)
    if not doge_txs and source_issue:
        frequency_activity = "insufficient_data"
    elif tx_count >= 100 or tx_per_day >= 10 or last_30 >= 50:
        frequency_activity = "high"
    elif tx_count >= 20 or tx_per_day >= 2 or last_30 >= 10:
        frequency_activity = "medium"
    elif tx_count or doge_txs:
        frequency_activity = "low"
    else:
        frequency_activity = "not_detected"
    signals.append(
        _doge_signal(
            "Transfer Frequency",
            frequency_activity,
            {
                "total_tx": tx_count,
                "fetched_tx_details": details_count,
                "tx_per_day": round(tx_per_day, 4) if tx_per_day else 0,
                "active_days": active_days or int(data.get("active_days") or 0),
                "peak_day": peak_day,
                "peak_day_tx": peak_count,
                "last_7_days": last_7,
                "last_30_days": last_30,
                "first_activity": first_activity,
                "last_activity": last_activity,
            },
            ["DOGE transaction timestamps" if doge_txs else "", "Blockchair address dashboard" if data else ""],
            all_sources,
            "high" if frequency_activity in {"high", "medium"} else "medium" if frequency_activity == "low" else "low",
        )
    )
    return signals


def _append_dogecoin_intelligence_health(report: AddressReport) -> None:
    if "doge" not in report.detected_chains:
        return
    existing = {item.source for item in report.source_health}
    expected = {
        "blockchair_dogecoin": ("public dashboard API", "not executed or no response"),
        "sochain_dogecoin": ("key_required", "SoChain API key is not configured"),
        "oklink_dogecoin": ("key_required", "OKLink API key is not configured"),
        "dogechain_explorer": ("public explorer page", "not executed or unavailable"),
        "dogecoin_core_rpc": ("optional local RPC", "DOGE RPC is not configured"),
    }
    for source, (strategy, details) in expected.items():
        if source not in existing:
            status = "skipped" if "key" in strategy or "RPC" in strategy else "unavailable"
            report.source_health.append(SourceHealth(source=source, status=status, timeout_seconds=0, retry_strategy=strategy, details=details))
    if "dogecoin_utxo_context" not in existing:
        data = report.dogecoin or {}
        txs = [tx for tx in report.transactions if tx.chain == "doge"]
        status = "ok" if data.get("utxos") or txs else "empty"
        details = f"utxos={len(data.get('utxos') or [])}, tx_details={len(txs)}"
        report.source_health.append(SourceHealth(source="dogecoin_utxo_context", status=status, timeout_seconds=0, retry_strategy="Blockchair UTXO and transaction facts", details=details))


def _btc_io_address(item: dict) -> str:
    return str((item or {}).get("address") or "").strip()


def _btc_io_value(item: dict) -> float:
    try:
        return float((item or {}).get("value") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _transaction_sort_key(tx: Transaction) -> tuple:
    timestamp = tx.timestamp
    if timestamp is not None:
        timestamp = timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None else timestamp.astimezone(timezone.utc)
    raw = tx.raw or {}
    try:
        lt = int(raw.get("lt") or raw.get("logical_time") or 0)
    except (ValueError, TypeError):
        lt = 0
    return (timestamp is not None, timestamp or MIN_DT, lt, str(tx.event_id or tx.tx_hash))


def _financial_asset_key(tx: Transaction) -> str:
    raw = tx.raw or {}
    contract = raw.get("contract") or raw.get("token_contract") or raw.get("jetton_master") or raw.get("mint")
    return f"{tx.chain}|{_address_key(tx.chain, str(contract)) if contract else 'native' if (tx.asset or '').upper() in {'TON', 'ETH', 'BNB', 'BTC', 'DOGE', 'TRX', 'SOL', 'POL', 'AVAX'} else 'unverified-symbol'}|{tx.asset or 'UNKNOWN'}"


def _counterparty_amount(bucket: Counterparty, tx: Transaction, direction: str, amount: Decimal | None = None) -> None:
    amount = decimal_amount(tx) if amount is None else amount
    if amount is None:
        return
    totals = bucket.amounts_by_asset.setdefault(_financial_asset_key(tx), {"in": Decimal(0), "out": Decimal(0)})
    totals[direction] += amount


def _build_counterparties(report: AddressReport) -> list[Counterparty]:
    buckets: dict[tuple[str, str], Counterparty] = {}
    label_map = defaultdict(list)
    for l in report.labels:
        label_map[(l.chain, _address_key(l.chain, l.address))].append(l.label)
    risk_map = defaultdict(list)
    for rf in report.risk_flags:
        if rf.chain == "multi":
            continue
        risk_map[(rf.chain, _address_key(rf.chain, rf.address))].append(rf.flag)

    for t in report.transactions:
        if transaction_success(t) is False or str((t.raw or {}).get("type") or "").lower() in {"approval", "approval_for_all"}:
            continue
        if t.chain in {"btc", "doge"} and _has_utxo_io(t):
            chain = t.chain
            target = _address_key(chain, report.target_address)
            inputs = [item for item in t.inputs if _btc_io_address(item)]
            outputs = [item for item in t.outputs if _btc_io_address(item)]
            target_input = sum(_btc_io_value(item) for item in inputs if _address_key(chain, _btc_io_address(item)) == target)
            target_output = sum(_btc_io_value(item) for item in outputs if _address_key(chain, _btc_io_address(item)) == target)
            outgoing = t.direction == "out" or target_input > target_output
            incoming = t.direction == "in" or target_output > target_input
            if outgoing:
                seen = set()
                for item in outputs:
                    cp = _btc_io_address(item)
                    key_addr = _address_key(chain, cp)
                    if not cp or key_addr == target:
                        continue
                    key = (chain, key_addr)
                    if key not in buckets:
                        buckets[key] = Counterparty(address=cp, chain=chain)
                    b = buckets[key]
                    if key_addr not in seen:
                        b.tx_count += 1
                        seen.add(key_addr)
                    _counterparty_amount(b, t, "out", Decimal(str(_btc_io_value(item))))
                    if t.timestamp:
                        b.first_seen = min(b.first_seen, t.timestamp) if b.first_seen else t.timestamp
                        b.last_seen = max(b.last_seen, t.timestamp) if b.last_seen else t.timestamp
            if incoming:
                seen = set()
                for item in inputs:
                    cp = _btc_io_address(item)
                    key_addr = _address_key(chain, cp)
                    if not cp or key_addr == target:
                        continue
                    key = (chain, key_addr)
                    if key not in buckets:
                        buckets[key] = Counterparty(address=cp, chain=chain)
                    b = buckets[key]
                    if key_addr not in seen:
                        b.tx_count += 1
                        seen.add(key_addr)
                    _counterparty_amount(b, t, "in", Decimal(str(_btc_io_value(item))))
                    if t.timestamp:
                        b.first_seen = min(b.first_seen, t.timestamp) if b.first_seen else t.timestamp
                        b.last_seen = max(b.last_seen, t.timestamp) if b.last_seen else t.timestamp
            continue
        if not t.from_address or not t.to_address:
            continue
        chain = t.chain
        target = _address_key(chain, report.target_address)
        from_key = _address_key(chain, t.from_address)
        to_key = _address_key(chain, t.to_address)
        if from_key == target:
            cp = t.to_address
            key = (chain, _address_key(chain, cp))
            if key not in buckets:
                buckets[key] = Counterparty(address=cp, chain=chain)
            b = buckets[key]
            b.tx_count += 1
            _counterparty_amount(b, t, "out")
            if t.timestamp:
                b.first_seen = min(b.first_seen, t.timestamp) if b.first_seen else t.timestamp
                b.last_seen = max(b.last_seen, t.timestamp) if b.last_seen else t.timestamp
        elif to_key == target:
            cp = t.from_address
            key = (chain, _address_key(chain, cp))
            if key not in buckets:
                buckets[key] = Counterparty(address=cp, chain=chain)
            b = buckets[key]
            b.tx_count += 1
            _counterparty_amount(b, t, "in")
            if t.timestamp:
                b.first_seen = min(b.first_seen, t.timestamp) if b.first_seen else t.timestamp
                b.last_seen = max(b.last_seen, t.timestamp) if b.last_seen else t.timestamp

    out = list(buckets.values())
    for c in out:
        c.aggregate_amount_valid = len(c.amounts_by_asset) <= 1
        if c.aggregate_amount_valid and c.amounts_by_asset:
            totals = next(iter(c.amounts_by_asset.values()))
            c.total_in, c.total_out = float(totals["in"]), float(totals["out"])
        else:
            # No meaningful scalar sum exists for heterogeneous token units.
            c.total_in = c.total_out = 0.0
        c.labels = label_map.get((c.chain, _address_key(c.chain, c.address)), [])
        c.risk_flags = risk_map.get((c.chain, _address_key(c.chain, c.address)), [])
    out.sort(key=lambda x: (x.tx_count, x.total_in + x.total_out), reverse=True)
    return out


def _build_activity_chains(report: AddressReport) -> list[ActivityChain]:
    target_by_chain = {chain: _address_key(chain, report.target_address) for chain in report.detected_chains or ["ton"]}
    chains: list[ActivityChain] = []
    by_counterparty = defaultdict(list)
    by_asset = defaultdict(list)
    for tx in report.transactions:
        if (tx.raw or {}).get("_activity_projection", {}).get("recurrence_eligible") is False:
            continue
        if not tx.from_address or not tx.to_address:
            continue
        target = target_by_chain.get(tx.chain) or _address_key(tx.chain, report.target_address)
        from_key = _address_key(tx.chain, tx.from_address)
        to_key = _address_key(tx.chain, tx.to_address)
        if from_key == target:
            by_counterparty[(tx.chain, _address_key(tx.chain, tx.to_address))].append(tx)
        elif to_key == target:
            by_counterparty[(tx.chain, _address_key(tx.chain, tx.from_address))].append(tx)
        if tx.asset:
            by_asset[(tx.chain, tx.asset)].append(tx)
    for (chain, cp), items in by_counterparty.items():
        if len(items) < 3 or not cp:
            continue
        ordered = sorted(items, key=lambda item: item.timestamp or MIN_DT)
        sample = ordered[-1]
        address = sample.to_address if _address_key(chain, sample.to_address) == cp else sample.from_address
        tx_hashes = [item.tx_hash for item in ordered if item.tx_hash][:8]
        chains.append(
            ActivityChain(
                chain_type="recurring_counterparty",
                title="Recurring counterparty",
                summary=f"{len(items)} interactions with one address",
                addresses=[report.target_address, address or cp],
                asset=sample.asset,
                tx_hashes=tx_hashes,
                first_seen=ordered[0].timestamp,
                last_seen=ordered[-1].timestamp,
                source=sample.source,
                evidence_url=sample.url,
                confidence=min(0.95, 0.55 + len(items) * 0.05),
                raw={"chain": chain, "count": len(items)},
            )
        )
    for (chain, asset), items in by_asset.items():
        if not asset or len(items) < (1 if asset.startswith("NFT:") else 2):
            continue
        ordered = sorted(items, key=lambda item: item.timestamp or MIN_DT)
        addresses = []
        for item in ordered[:12]:
            for value in (item.from_address, item.to_address):
                if value and value not in addresses:
                    addresses.append(value)
        chain_type = "nft_path" if asset.startswith("NFT:") else "jetton_path" if asset.startswith("JETTON:") else "asset_path"
        chains.append(
            ActivityChain(
                chain_type=chain_type,
                title="Asset movement path",
                summary=f"{len(items)} operations for {asset}",
                addresses=addresses[:10],
                asset=asset,
                tx_hashes=[item.tx_hash for item in ordered if item.tx_hash][:8],
                first_seen=ordered[0].timestamp,
                last_seen=ordered[-1].timestamp,
                source=ordered[-1].source,
                evidence_url=ordered[-1].url,
                confidence=0.68,
                raw={"chain": chain, "count": len(items)},
            )
        )
    routing = [c for c in report.counterparties if c.total_in > 0 and c.total_out > 0 and c.tx_count >= 2]
    for c in routing[:12]:
        chains.append(
            ActivityChain(
                chain_type="routing_loop",
                title="Two-way route",
                summary=f"incoming and outgoing operations with one address: {c.tx_count}",
                addresses=[report.target_address, c.address],
                first_seen=c.first_seen,
                last_seen=c.last_seen,
                source="aggregator",
                confidence=0.72,
                raw={"chain": c.chain, "total_in": c.total_in, "total_out": c.total_out},
            )
        )
    chains.sort(key=lambda item: (item.confidence, item.last_seen or MIN_DT), reverse=True)
    return chains[:40]


def _build_wallet_timeline(report: AddressReport) -> WalletTimeline:
    stamps = sorted(tx.timestamp for tx in report.transactions if tx.timestamp)
    if not stamps:
        return WalletTimeline()
    active_days = len({stamp.date() for stamp in stamps})
    gaps = []
    for left, right in zip(stamps, stamps[1:]):
        days = (right - left).days
        if days >= 14:
            gaps.append(InactivityPeriod(from_time=left, to_time=right, days=days))
    bursts = []
    for chain in sorted({tx.chain for tx in report.transactions if tx.timestamp}):
        chain_stamps = sorted(tx.timestamp for tx in report.transactions if tx.chain == chain and tx.timestamp
            and (tx.raw or {}).get("_activity_projection", {}).get("recurrence_eligible") is not False)
        window = []
        for stamp in chain_stamps:
            window = [item for item in window if (stamp - item).total_seconds() <= 3600]
            window.append(stamp)
            if len(window) >= 5:
                bursts.append(ActivityBurst(chain=chain, start_time=window[0], end_time=window[-1], tx_count=len(window)))
                break
    return WalletTimeline(
        first_activity=stamps[0],
        last_activity=stamps[-1],
        active_days=active_days,
        inactivity_periods=gaps[:12],
        bursts=bursts[:12],
    )


def _target_in_tx(report: AddressReport, tx: Transaction) -> bool:
    target = _address_key(tx.chain, report.target_address)
    if tx.chain in {"btc", "doge"} and _has_utxo_io(tx):
        return any(_address_key(tx.chain, _btc_io_address(item)) == target for item in tx.inputs + tx.outputs)
    return _address_key(tx.chain, tx.from_address) == target or _address_key(tx.chain, tx.to_address) == target


def _tx_direction_for_target(report: AddressReport, tx: Transaction) -> str:
    target = _address_key(tx.chain, report.target_address)
    if tx.chain in {"btc", "doge"} and _has_utxo_io(tx):
        target_input = sum(_btc_io_value(item) for item in tx.inputs if _address_key(tx.chain, _btc_io_address(item)) == target)
        target_output = sum(_btc_io_value(item) for item in tx.outputs if _address_key(tx.chain, _btc_io_address(item)) == target)
        if target_input > target_output:
            return "out"
        if target_output > target_input:
            return "in"
        return tx.direction
    from_target = _address_key(tx.chain, tx.from_address) == target
    to_target = _address_key(tx.chain, tx.to_address) == target
    if from_target and not to_target:
        return "out"
    if to_target and not from_target:
        return "in"
    return tx.direction


def _tx_counterparty_for_target(report: AddressReport, tx: Transaction, direction: str) -> str:
    target = _address_key(tx.chain, report.target_address)
    if tx.chain in {"btc", "doge"} and _has_utxo_io(tx):
        items = tx.outputs if direction == "out" else tx.inputs
        ranked = sorted(
            [
                (_btc_io_value(item), _btc_io_address(item))
                for item in items
                if _btc_io_address(item) and _address_key(tx.chain, _btc_io_address(item)) != target
            ],
            reverse=True,
        )
        return ranked[0][1] if ranked else ""
    return tx.to_address if direction == "out" else tx.from_address if direction == "in" else ""


def _tx_amount_value(tx: Transaction) -> float:
    try:
        return float(tx.amount or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _event_address_key(chain: str, value: str | None) -> str:
    return _address_key(chain, value or "")


def _asset_outgoing_events(report: AddressReport) -> list[tuple[TonAsset, object]]:
    target = _address_key("ton", report.target_address)
    out = []
    seen = set()
    for asset in report.ton_assets:
        for event in asset.history_events + asset.transfer_history + asset.sale_history:
            key = (asset.asset_id, event_identity(event))
            if key in seen or event.success is False or event.event_type in {"listing", "interaction", "unknown_activity"}:
                continue
            seen.add(key)
            from_target = _event_address_key("ton", getattr(event, "from_address", "")) == target
            to_target = _event_address_key("ton", getattr(event, "to_address", "")) == target
            if getattr(event, "direction", "") == "out" or (from_target and not to_target):
                out.append((asset, event))
    return out


def _build_wallet_migration(report: AddressReport) -> WalletMigrationSignal:
    total_events = len(report.transactions) + sum(len(asset.history_events) + len(asset.transfer_history) + len(asset.sale_history) for asset in report.ton_assets)
    stamps = [tx.timestamp for tx in report.transactions if tx.timestamp]
    if total_events < 5 or len(stamps) < 3:
        return WalletMigrationSignal(
            activity="insufficient_data",
            observation="Недостаточно временных данных для оценки миграции активов.",
            facts={"transactions": len(report.transactions), "asset_events": total_events - len(report.transactions)},
            evidence=[],
            confidence="low",
            source=sorted(set(report.sources_used))[:8],
            status="insufficient_data",
        )

    outgoing_txs = [tx for tx in report.transactions if _tx_direction_for_target(report, tx) == "out" and transaction_success(tx) is not False and str((tx.raw or {}).get("type") or "").lower() not in {"approval", "approval_for_all"}]
    amount_groups = defaultdict(list)
    for tx in outgoing_txs:
        amount = decimal_amount(tx)
        if amount is not None and amount > 0:
            amount_groups[_financial_asset_key(tx)].append(amount)
    # Share is comparable within one asset only; heterogeneous token units are
    # deliberately never summed into a purported value of the wallet.
    native_by_asset = {}
    for key, values in amount_groups.items():
        # Token quantities can exceed Decimal's default 28 significant digits.
        # Keep the full integer/fractional span and carry digits while summing.
        with localcontext() as amount_context:
            amount_context.prec = max(amount_context.prec,
                max(value.adjusted() for value in values)
                - min(value.as_tuple().exponent for value in values)
                + len(str(len(values))) + 2)
            native_by_asset[key] = sum(values, Decimal(0))
    largest_by_asset = {key: max(values) for key, values in amount_groups.items()}
    largest_outgoing = None
    tx_destinations = Counter()
    destination_times = defaultdict(list)
    for tx in outgoing_txs:
        cp = _tx_counterparty_for_target(report, tx, "out")
        if cp:
            key = _address_key(tx.chain, cp)
            tx_destinations[(tx.chain, key, cp)] += 1
            if tx.timestamp:
                destination_times[(tx.chain, key, cp)].append(tx.timestamp)

    asset_events = _asset_outgoing_events(report)
    nft_types = {"username", "nft", "domain", "collectible"}
    nft_out = [item for item in asset_events if item[0].type in nft_types]
    gift_out = [item for item in asset_events if item[0].type == "gift"]
    asset_destinations = Counter()
    asset_times = defaultdict(list)
    for asset, event in asset_events:
        destination = getattr(event, "to_address", "") or getattr(event, "counterparty", "") or ""
        if destination:
            key = _address_key("ton", destination)
            asset_destinations[("ton", key, destination)] += 1
            if getattr(event, "timestamp", None):
                asset_times[("ton", key, destination)].append(event.timestamp)

    jetton_out = [
        tx for tx in outgoing_txs
        if "jetton" in str(tx.asset or "").lower()
        or "trc20" in str((tx.raw or {}).get("type") or "").lower()
        or str(tx.asset or "").upper() in {"USDT", "USDC", "WETH", "BUSD"}
    ]
    combined_destinations = Counter()
    combined_destinations.update(tx_destinations)
    combined_destinations.update(asset_destinations)
    top_destination, top_destination_count = ("", "", ""), 0
    if combined_destinations:
        top_destination, top_destination_count = combined_destinations.most_common(1)[0]
    migration_times = []
    for key in combined_destinations:
        migration_times.extend(destination_times.get(key, []))
        migration_times.extend(asset_times.get(key, []))
    migration_start = min(migration_times) if migration_times else (min((tx.timestamp for tx in outgoing_txs if tx.timestamp), default=None))
    migration_end = max(migration_times) if migration_times else (max((tx.timestamp for tx in outgoing_txs if tx.timestamp), default=None))
    later_activity = 0
    if migration_end:
        later_activity = sum(1 for tx in report.transactions if tx.timestamp and tx.timestamp > migration_end and _target_in_tx(report, tx))
    moved_assets = len({asset.asset_id for asset, _ in asset_events})
    unique_counterparties = len({item[1] for item in combined_destinations if item[1]})
    largest_share = max((float(largest_by_asset[key] / total) for key, total in native_by_asset.items() if total > 0), default=0.0)
    mass_asset_move = moved_assets >= 5 or len(nft_out) >= 5 or len(gift_out) >= 5
    repeated_destination = top_destination_count >= 3
    post_inactive = migration_end is not None and later_activity <= 2
    large_transfer_pattern = bool(amount_groups) and largest_share >= 0.65

    if mass_asset_move and repeated_destination and post_inactive:
        activity = "high"
    elif (mass_asset_move and repeated_destination) or (large_transfer_pattern and repeated_destination) or (moved_assets >= 3 and len(jetton_out) >= 2 and post_inactive):
        activity = "medium"
    elif outgoing_txs or asset_events:
        activity = "low"
    else:
        activity = "not_detected"

    if activity == "high":
        observation = "Зафиксированы признаки миграции активов: массовый вывод активов связан с повторяющимся адресом назначения и низкой активностью после вывода."
        status = "ok"
        confidence = "high"
    elif activity == "medium":
        observation = "Зафиксированы отдельные признаки миграции активов по исходящим переводам и повторяющемуся адресу назначения."
        status = "ok"
        confidence = "medium"
    elif activity == "low":
        observation = "Есть исходящие переводы или transfer events, но признаков массового переноса активов недостаточно."
        status = "ok"
        confidence = "low"
    else:
        observation = "Признаки миграции активов не обнаружены по собранным данным."
        status = "not_detected"
        confidence = "low"

    # Decimal formatting does not quantize through the active arithmetic
    # context. round(large_decimal, 6) raises InvalidOperation for valid uint256
    # token quantities even though their fixed-point display is representable.
    top_assets = [f"{asset}: {value:.6f}" for asset, value in sorted(native_by_asset.items(), key=lambda item: item[1], reverse=True)[:4]]
    target_candidates = []
    if top_destination_count >= 3 and activity in {"high", "medium"}:
        chain, _, address = top_destination
        target_candidates.append({"chain": chain, "address": address, "count": top_destination_count})
    evidence = sorted({tx.source for tx in outgoing_txs} | {event.source for _, event in asset_events})[:8]
    facts = {
        "transferred_nft": len(nft_out),
        "transferred_gifts": len(gift_out),
        "transferred_jettons": len(jetton_out),
        "transferred_value": top_assets,
        "asset_count": moved_assets,
        "counterparties": unique_counterparties,
        "migration_start": migration_start,
        "last_activity": report.wallet_timeline.last_activity,
        "activity_after_output": later_activity,
    }
    if target_candidates:
        facts["destination_candidate"] = target_candidates[0]["address"]
    return WalletMigrationSignal(
        activity=activity,
        observation=observation,
        facts=facts,
        evidence=evidence,
        confidence=confidence,
        source=sorted(set(evidence or report.sources_used))[:8],
        status=status,
        raw={"target_candidates": target_candidates, "largest_outgoing_by_asset": {key: str(value) for key, value in largest_by_asset.items()}, "largest_share_within_asset": round(largest_share, 4), "top_destination_count": top_destination_count},
    )


def _peak_window(hours: list[int]) -> str | None:
    if not hours:
        return None
    counts = Counter(hours)
    best_start = 0
    best_score = -1
    for start in range(24):
        score = sum(counts[(start + offset) % 24] for offset in range(4))
        if score > best_score:
            best_score = score
            best_start = start
    end = (best_start + 4) % 24
    return f"{best_start:02d}:00-{end:02d}:00 UTC"


def _build_behavioral_fingerprint(report: AddressReport, *, financial_transactions=None) -> BehavioralFingerprint:
    # One TON contract is one asset across inventory and holding projections.
    ton_asset_ids = {
        ("contract", key) if (key := ton_canonical_address(asset.asset_id))
        else ("asset_id", asset.asset_id) if asset.asset_id else ("asset_observation", index)
        for index, asset in enumerate(report.ton_assets)
    }
    ton_asset_ids.update(
        ("contract", key) if (key := ton_canonical_address(token.contract))
        else ("token_contract", token.contract) if token.contract else ("token_observation", index)
        for index, token in enumerate(report.tokens) if token.chain == "ton"
    )
    asset_count = len(ton_asset_ids) + sum(token.chain != "ton" for token in report.tokens)
    txs = [tx for tx in report.transactions if tx.timestamp and transaction_success(tx) is not False
        and (_target_in_tx(report, tx) or (tx.chain == "ton" and ton_canonical_address(report.target_address)
            and ton_canonical_address((tx.raw or {}).get("_activity_projection", {}).get("account_context")) == ton_canonical_address(report.target_address)))
        and (tx.raw or {}).get("_activity_projection", {}).get("recurrence_eligible") is not False]
    monetary_txs = txs if financial_transactions is None else [tx for tx in financial_transactions
        if tx.timestamp and _target_in_tx(report, tx) and transaction_success(tx) is not False]
    if len(txs) < 3:
        return BehavioralFingerprint(
            status="insufficient_data",
            first_activity=report.wallet_timeline.first_activity,
            last_activity=report.wallet_timeline.last_activity,
            active_days=report.wallet_timeline.active_days,
            unique_counterparties=len(report.counterparties),
            asset_count=asset_count,
            nft_count=sum(1 for asset in report.ton_assets if asset.type in {"username", "nft", "domain", "collectible"}),
            gift_count=sum(1 for asset in report.ton_assets if asset.type == "gift"),
            source=sorted(set(report.sources_used))[:8],
        )
    stamps = [tx.timestamp for tx in txs if tx.timestamp]
    active_days = len({stamp.date() for stamp in stamps})
    hours = [stamp.hour for stamp in stamps]
    weekdays = [stamp.weekday() for stamp in stamps]
    amount_groups = defaultdict(list)
    for tx in monetary_txs:
        value = decimal_amount(tx)
        if value is not None and value > 0:
            amount_groups[_financial_asset_key(tx)].append(value)
    amount_asset = max(amount_groups, key=lambda key: len(amount_groups[key])) if amount_groups else None
    amount_values = amount_groups.get(amount_asset, [])
    amount_values_sorted = sorted(amount_values)
    average = sum(amount_values) / len(amount_values) if amount_values else None
    median = None
    if amount_values_sorted:
        mid = len(amount_values_sorted) // 2
        median = amount_values_sorted[mid] if len(amount_values_sorted) % 2 else (amount_values_sorted[mid - 1] + amount_values_sorted[mid]) / 2
    asset_counts = Counter(tx.asset or tx.chain.upper() for tx in monetary_txs)
    heatmap_counts = Counter((stamp.weekday(), stamp.hour) for stamp in stamps)
    heatmap = [{"weekday": day, "hour": hour, "count": heatmap_counts.get((day, hour), 0)} for day in range(7) for hour in range(24)]
    marketplace_markers = ("fragment", "getgems", "portals", "opensea", "marketplace", "sale", "listing")
    defi_markers = ("swap", "router", "dex", "defi", "liquidity", "sunswap", "ston", "dedust", "bridge")
    marketplace_interactions = sum(1 for asset in report.ton_assets if asset.marketplace) + sum(1 for asset in report.ton_assets for event in asset.history_events + asset.transfer_history + asset.sale_history if event.marketplace)
    defi_interactions = 0
    for tx in txs:
        blob = " ".join([str(tx.asset or ""), str(tx.source or ""), str(tx.raw or {})]).lower()
        if any(marker in blob for marker in marketplace_markers):
            marketplace_interactions += 1
        if any(marker in blob for marker in defi_markers):
            defi_interactions += 1
    nft_count = sum(1 for asset in report.ton_assets if asset.type in {"username", "nft", "domain", "collectible"})
    gift_count = sum(1 for asset in report.ton_assets if asset.type == "gift")
    hash_basis = {
        "chains": sorted(set(tx.chain for tx in txs)),
        "weekday_top": [item for item, _ in Counter(weekdays).most_common(4)],
        "hour_top": [item for item, _ in Counter(hours).most_common(6)],
        "tx_per_day_bucket": round(len(txs) / max(active_days, 1), 1),
        "average_bucket": round((average or 0) / 10) * 10,
        "median_bucket": round((median or 0) / 10) * 10,
        "nft_count": min(nft_count, 50),
        "gift_count": min(gift_count, 50),
        "marketplace": min(marketplace_interactions, 50),
        "defi": min(defi_interactions, 50),
    }
    fingerprint_hash = hashlib.sha256(str(sorted(hash_basis.items())).encode("utf-8")).hexdigest()[:24]
    return BehavioralFingerprint(
        status="ok",
        first_activity=min(stamps),
        last_activity=max(stamps),
        active_weekdays=[item for item, _ in Counter(weekdays).most_common(5)],
        active_hours=[item for item, _ in Counter(hours).most_common(8)],
        peak_activity_window=_peak_window(hours),
        average_transfer_amount=float(average) if average is not None else None,
        median_transfer_amount=float(median) if median is not None else None,
        dominant_asset=amount_asset or (asset_counts.most_common(1)[0][0] if asset_counts else None),
        tx_per_day=len(txs) / max(active_days, 1),
        active_days=active_days,
        unique_counterparties=len(report.counterparties),
        asset_count=asset_count,
        nft_count=nft_count,
        gift_count=gift_count,
        marketplace_interactions=marketplace_interactions,
        defi_interactions=defi_interactions,
        heatmap=heatmap,
        fingerprint_hash=fingerprint_hash,
        source=sorted(set(report.sources_used))[:8],
        raw={"hash_basis_version": 1},
    )


def _build_asset_paths(report: AddressReport) -> list[AssetPath]:
    paths = []
    for asset in report.ton_assets:
        events = sorted(asset.transfer_history + asset.sale_history, key=lambda item: item.timestamp or MIN_DT)
        links = []
        for value in (asset.external_url, asset.evidence_url):
            if value and value not in links:
                links.append(value)
        for event in events:
            if event.evidence_url and event.evidence_url not in links:
                links.append(event.evidence_url)
        paths.append(
            AssetPath(
                asset_id=asset.asset_id,
                asset_type=asset.type,
                title=asset.title or asset.name,
                current_owner=asset.owner_address,
                previous_owners=asset.previous_owners[:20],
                tx_chain=[item.tx_hash for item in events if item.tx_hash][:30],
                marketplace_links=links[:10],
                source=asset.source,
            )
        )
    paths.sort(key=lambda item: (len(item.tx_chain), len(item.previous_owners), item.title or ""), reverse=True)
    return paths[:80]


def _ranking_entry(counterparty: Counterparty) -> CounterpartyRankingEntry:
    return CounterpartyRankingEntry(
        address=counterparty.address,
        chain=counterparty.chain,
        tx_count=counterparty.tx_count,
        total_in=counterparty.total_in,
        total_out=counterparty.total_out,
        last_seen=counterparty.last_seen,
        labels=counterparty.labels,
    )


def _build_counterparty_ranking(report: AddressReport) -> CounterpartyRanking:
    return CounterpartyRanking(
        most_frequent=[_ranking_entry(item) for item in sorted(report.counterparties, key=lambda c: (c.tx_count, c.total_in + c.total_out), reverse=True)[:20]],
        biggest_transfers=[_ranking_entry(item) for item in sorted(report.counterparties, key=lambda c: c.total_in + c.total_out, reverse=True)[:20]],
        latest_interactions=[_ranking_entry(item) for item in sorted(report.counterparties, key=lambda c: c.last_seen or MIN_DT, reverse=True)[:20]],
    )


def _build_service_detections(report: AddressReport) -> list[ServiceDetection]:
    detections = {}
    exchange_markers = ("binance", "okx", "bybit", "kucoin", "mexc", "gate", "htx", "bitget", "coinbase", "kraken", "exchange")
    marketplace_markers = ("fragment", "getgems", "tonscan", "tonviewer", "opensea")
    service_markers = ("tonkeeper", "ston", "dedust", "telegram", "wallet", "bridge", "router", "swap")
    for label in report.labels:
        low = label.label.lower()
        category = None
        name = None
        for marker in exchange_markers:
            if marker in low:
                category, name = "exchange", marker
                break
        if category is None:
            for marker in marketplace_markers:
                if marker in low:
                    category, name = "marketplace", marker
                    break
        if category is None:
            for marker in service_markers:
                if marker in low:
                    category, name = "service", marker
                    break
        if category and label.address:
            key = (label.chain, label.address, category, name)
            current = detections.get(key)
            confidence = max(label.confidence, 0.55 if category != "service" else 0.42)
            if current is None or confidence > current.confidence:
                detections[key] = ServiceDetection(address=label.address, chain=label.chain, category=category, name=name or category, confidence=confidence, source=label.source, evidence=label.label)
    for asset in report.ton_assets:
        if asset.marketplace:
            key = ("ton", asset.marketplace, "marketplace", asset.marketplace.lower())
            detections[key] = ServiceDetection(address=asset.marketplace, chain="ton", category="marketplace", name=asset.marketplace, confidence=max(asset.confidence, 0.65), source=asset.source, evidence=asset.evidence_url)
    return sorted(detections.values(), key=lambda item: item.confidence, reverse=True)[:60]


def _has_ens_data(report: AddressReport) -> bool:
    profile = getattr(report, "ens_profile", {}) or {}
    return bool(report.ens_name or report.reverse_ens or report.resolver or report.ens_owner or report.avatar or report.text_records or report.ens_resolved_address or profile.get("name") or profile.get("records"))


async def analyze_address(address: str, *, timeout_seconds: float = 18.0, max_txs: int = 1000, include_experimental: bool = False, selected_chains: list[Chain] | None = None, progress: Callable[[dict], None] | None = None, deadline: float | None = None, on_collected: Callable[[AddressReport], None] | None = None, initial_report: AddressReport | None = None, continuous: bool = False, incremental: bool = False, on_checkpoint: Callable[[AddressReport], Awaitable[None] | None] | None = None, checkpoint_interval: float = 15.0, defer_graph: bool = False, ens_seed: AddressReport | None = None, public_context_seed: AddressReport | None = None) -> tuple[AddressReport, dict]:
    started = asyncio.get_running_loop().time()
    def emit(stage: str, **details) -> None:
        if progress is not None:
            progress({"stage": stage, "timestamp": datetime.now(timezone.utc).isoformat(),
                      "elapsed_seconds": asyncio.get_running_loop().time() - started,
                      "component": "legacy_analyzer", **details})

    emit("routing.start", address=address)
    candidates = list(dict.fromkeys(selected_chains or detect_candidates(address)))
    if not candidates:
        if looks_like_bitcoin_address(address):
            report = AddressReport(
                target_address=address,
                detected_chains=["btc"],
                warnings=["bitcoin: invalid mainnet address"],
                source_health=[SourceHealth(source="bitcoin_detector", status="error", timeout_seconds=0, retry_strategy="checksum validation", details="invalid mainnet address")],
            )
            return report, {} if defer_graph else build_graph_payload(report)
        if looks_like_dogecoin_address(address):
            report = AddressReport(
                target_address=address,
                detected_chains=["doge"],
                warnings=["dogecoin: invalid mainnet address"],
                source_health=[SourceHealth(source="dogecoin_detector", status="error", timeout_seconds=0, retry_strategy="checksum validation", details="invalid dogecoin address")],
            )
            return report, {} if defer_graph else build_graph_payload(report)
        emit("routing.error", status="unsupported_input")
        raise ValueError("Unsupported address input; provide a supported blockchain address or NFT identifier through the main search.")

    emit("routing.complete", chains=candidates)
    if initial_report is not None and not any(
            _address_key(chain, initial_report.target_address) == _address_key(chain, address) for chain in candidates):
        raise ValueError("Initial report target differs from the requested address")

    if ens_seed is not None:
        profile = getattr(ens_seed, "ens_profile", {}) or {}
        resolved = ens_seed.ens_resolved_address or profile.get("resolved_address")
        if "eth" not in candidates or not profile.get("forward_verified") or not resolved or resolved.lower() != address.lower() or ens_seed.target_address.lower() != address.lower():
            raise ValueError("ENS input seed does not verify the requested Ethereum address")
        initial_report = _merge(initial_report.model_copy(deep=True) if initial_report is not None else AddressReport(target_address=address, detected_chains=["eth"]), ens_seed)
        initial_report.input_resolution = dict(ens_seed.input_resolution)

    public_seed_sources = set()
    if public_context_seed is not None:
        valid = public_context_seed.target_address.lower() == address.lower() and any(
            row.get("source") == "basenames" and row.get("chain") == "base" and row.get("status") in {"ok", "partial"}
            and any(claim.get("value", {}).get("forward_verified") is True
                and claim.get("value", {}).get("chain_id") == 8453
                and str(claim.get("value", {}).get("resolved_address") or "").lower() == address.lower()
                for claim in row.get("claims", []))
            for row in public_context_seed.public_address_context.get("outcomes", []))
        if not valid:
            raise ValueError("Public identity input seed does not verify the requested EVM address")
        initial_report = _merge(initial_report.model_copy(deep=True) if initial_report is not None else AddressReport(target_address=address), public_context_seed)
        initial_report.input_resolution = dict(public_context_seed.input_resolution)
        public_seed_sources.add("basenames")

    sources = []
    if "btc" in candidates:
        sources.extend([BitcoinBlockstreamSource(timeout_seconds), BitcoinMempoolSource(timeout_seconds)])
    if "doge" in candidates:
        sources.extend([
            DogecoinBlockchairSource(timeout_seconds),
            DogecoinSoChainSource(timeout_seconds),
            DogecoinOklinkSource(timeout_seconds),
            DogechainExplorerSource(timeout_seconds),
            DogecoinCoreRpcSource(timeout_seconds),
            DogecoinBitquerySource(timeout_seconds),
            DogecoinGetBlockSource(timeout_seconds),
        ])
    if "eth" in candidates:
        sources.extend([
            EthereumEtherscanApiSource(timeout_seconds),
            EthereumRpcSource(timeout_seconds),
            *([] if ens_seed is not None else [EthereumEnsSource(timeout_seconds)]),
            EthereumBlockchairSource(timeout_seconds),
            EthereumEthplorerSource(timeout_seconds),
            EthereumLabelsSource(timeout_seconds),
            EthereumEtherscanHtmlSource(timeout_seconds),
        ])
    evm_candidates = [chain for chain in candidates if chain in {"eth", "bsc", "polygon", "arbitrum", "optimism", "avalanche"}]
    if evm_candidates:
        from app.attribution.bridge_execution_evidence import WormholeExecutionEvidenceSource
        sources.append(WormholeExecutionEvidenceSource(timeout_seconds, chain=evm_candidates[0], source_manager=SOURCE_MANAGER))
    for chain in ("eth", "optimism"):
        if chain in candidates:
            sources.append(EvmBlockscoutSource(timeout_seconds, chain=chain))
    if "bsc" in candidates:
        sources.extend([BscScanApiSource(timeout_seconds), BscIntelSource(timeout_seconds), BscRpcSource(timeout_seconds), BscScanHtmlSource(timeout_seconds)])
    if "polygon" in candidates:
        sources.extend([PolygonRpcSource(timeout_seconds), PolygonScanHtmlSource(timeout_seconds)])
    if "arbitrum" in candidates:
        sources.extend([ArbitrumRpcSource(timeout_seconds), ArbiscanHtmlSource(timeout_seconds)])
    if "optimism" in candidates:
        sources.extend([OptimismRpcSource(timeout_seconds), OptimisticEtherscanHtmlSource(timeout_seconds)])
    if "avalanche" in candidates:
        sources.append(AvalancheRpcSource(timeout_seconds))
    if "tron" in candidates:
        sources.extend([TronScanSource(timeout_seconds), TronGridSource(timeout_seconds)])
        sources.append(TronContractEvidenceSource(min(timeout_seconds,5)))
    if "ton" in candidates:
        sources.extend([
            TonApiSource(timeout_seconds),
            TonviewerPublicSource(timeout_seconds),
        ])
        if include_experimental:
            sources.extend([
                TonCenterV3Source(timeout_seconds),
                TelegramIdentitySource(timeout_seconds),
                FragmentPublicSource(timeout_seconds),
                GetgemsPublicSource(timeout_seconds),
                TonscanPublicSource(timeout_seconds),
                DtonPublicSource(timeout_seconds),
            ])
    if "solana" in candidates:
        sources.extend([SolscanPublicApiSource(timeout_seconds), SolanaRpcSource(timeout_seconds)])
    from app.attribution.normalize import EVM_CHAINS
    for chain in candidates:
        if chain in EVM_CHAINS:
            sources.append(VerifiedContractSource(chain, min(timeout_seconds, 5)))
            if chain not in {"eth", "bsc"}:
                sources.append(EthereumEtherscanApiSource(timeout_seconds, chain=chain))
    if include_experimental:
        sources.append(CryptoScamDbSource(timeout_seconds))

    if evm_candidates:
        # Public address context is target-only. Its separate small semaphore
        # leaves the established blockchain collector order/capacity intact.
        from app.sources.web3_identity import LensPublicSource
        from app.sources.basenames import BaseNamesSource
        from app.sources.eas_public import EasAttestationSource
        sources.append(LensPublicSource(min(timeout_seconds, 10.0)))
        if "basenames" not in public_seed_sources:
            sources.append(BaseNamesSource(min(timeout_seconds, 14.0)))
        if "eth" in candidates:
            sources.append(EasAttestationSource(min(timeout_seconds, 6.0), chain="eth"))

    fallback_sources = []
    if "ton" in candidates:
        if _tonconsole_available():
            fallback_sources.append(TonConsoleSource(timeout_seconds))
        fallback_sources.append(TonCenterSource(timeout_seconds))
        fallback_sources.append(TonCenterV3Source(timeout_seconds))
        fallback_sources.append(TonscanPublicSource(timeout_seconds))
        fallback_sources.append(DtonPublicSource(timeout_seconds))
        fallback_sources.append(TelegramIdentitySource(timeout_seconds))
        fallback_sources.append(FragmentPublicSource(timeout_seconds))
        fallback_sources.append(GetgemsPublicSource(timeout_seconds))

    # Experimental collectors already ran in the first wave. Their retry policy
    # belongs to run_source; a partial/failing response must not schedule another
    # instance of the same provider as a fallback.
    primary_source_names = {source.name for source in sources}
    fallback_sources = [source for source in fallback_sources if source.name not in primary_source_names]

    if continuous and "ton" in candidates:
        # Continuous history collectors can consume the entire absolute source
        # deadline. Waiting for their whole first wave starves complementary
        # TON providers, so schedule each remaining enabled provider once now.
        # The same semaphore, host gate, health checks and deadline still apply.
        sources.extend(fallback_sources)
        fallback_sources = []

    sources.sort(key=lambda item: SOURCE_MANAGER.priority(getattr(item, "name", "")))
    if deadline is not None:
        # Priority state/history before optional evidence, under the same wall
        # clock deadline. The ordinary scheduling order remains compatible.
        history_sources = {"tonapi", "toncenter_v3", "toncenter", "tonconsole"} if continuous else {"tonapi", "toncenter_v3"}
        sources.sort(key=lambda item: item.name not in history_sources)
    fallback_sources.sort(key=lambda item: SOURCE_MANAGER.priority(getattr(item, "name", "")))
    for source in sources:
        if hasattr(source, "_timeout"):
            source._timeout = _source_budget(getattr(source, "name", ""), timeout_seconds)
    for source in fallback_sources:
        if hasattr(source, "_timeout"):
            source._timeout = _source_budget(getattr(source, "name", ""), timeout_seconds)

    if continuous:
        for source in sources + fallback_sources:
            source._continuous = True
            source._incremental = incremental
            source._known_hashes = set()
            source._known_transaction_hashes = {tx.tx_hash for tx in initial_report.transactions if tx.source == source.name} if initial_report is not None else set()
            source._known_records = defaultdict(set)
            source._known_boundaries = defaultdict(int)
            def remember(raw):
                for kind, value in (("account_transactions", raw.get("transaction")), ("action_events", raw.get("action")), ("jetton_transfers" if raw.get("asset_type") == "jetton" else "nft_transfers", raw.get("transfer")), ("account_events", {"event_id": raw.get("event_id"), "lt": raw.get("lt")} if raw.get("event_id") else None)):
                    if not isinstance(value, dict):
                        continue
                    key = provider_record_key(kind, value)
                    if key:
                        source._known_records[kind].add(key)
                        source._known_boundaries[kind] = max(source._known_boundaries[kind], provider_record_order(kind, value))
            if initial_report is not None:
                from app.utils.event_identity import canonical_hash
                for tx in initial_report.transactions:
                    if tx.source == source.name:
                        remember(tx.raw or {})
                    if tx.source == source.name and record_kind(tx) == "physical_message_observations":
                        digest = canonical_hash(tx.tx_hash)
                        if digest:
                            source._known_hashes.add(digest)
                    for observed in tx.provenance:
                        if observed.get("source") != source.name:
                            continue
                        raw = observed.get("raw") or {}
                        remember(raw)
                        account = raw.get("transaction") or {}
                        digest = canonical_hash(account.get("hash") or (account.get("transaction_id") or {}).get("hash") or raw.get("parent_hash"))
                        if digest:
                            source._known_hashes.add(digest)
            source._resume_state = (initial_report.collection_audit.get("streams", {}).get(source.name, {}) if initial_report is not None else {})

    semaphore = asyncio.Semaphore(SOURCE_CONCURRENCY)
    public_context_semaphore = asyncio.Semaphore(2)
    completed_reports: dict[int, AddressReport] = {}
    checkpoint_task = None
    planner_task = None
    planner_last_transactions = -1
    from app.attribution.inference import context_for, journal as inference_journal
    context_seed = initial_report if initial_report is not None else AddressReport(target_address=address, detected_chains=candidates)
    investigation_context = context_for(context_seed)

    def attach_context(value):
        value.attribution_intelligence = {**(value.attribution_intelligence or {}),
            "investigation_context": investigation_context}

    async def investigate_neighbors(value):
        from app.attribution.investigation_planner import run_investigation_planner
        try:
            emit("inference.frontier.start")
            available_sources=[source for source in sources + fallback_sources if not _source_disabled(source.name)
                and not getattr(source, "public_context_only", False)]
            await run_investigation_planner(value, available_sources, SOURCE_MANAGER,
                semaphore=semaphore, deadline=deadline, context=investigation_context, incremental=incremental)
            emit("inference.frontier.complete", histories=len(investigation_context.get("histories", {})),
                http_requests=investigation_context.get("total_http_requests", 0))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Optional context failure cannot discard a usable main dossier.
            detail=f"{type(exc).__name__}: {exc}"
            inference_journal(investigation_context, "frontier.error", decision="Retain main dossier and scoped partial context",
                result={"error": detail}, missing_data=["Remaining neighbor histories"])
            emit("inference.frontier.error", error=detail)

    def start_neighbor_plan(value, *, force=False):
        nonlocal planner_task, planner_last_transactions
        size=len({(t.chain,t.tx_hash) for t in value.transactions})
        if size<3 or (size==planner_last_transactions and not force):return
        if planner_task is not None:
            if not planner_task.done():return
            # An early provider may supply participants without usable native
            # history. Re-evaluate later data, without repeating an HTTP pass.
            if investigation_context.get("coverage",{}).get("last_session_neighbors_attempted",0):return
        planner_last_transactions=size
        planner_task=asyncio.create_task(investigate_neighbors(value))

    async def publish_collections() -> None:
        nonlocal planner_task
        if on_checkpoint is None:
            return
        # Copy models before dedupe/provenance mutations; provider raw structures
        # are immutable after parsing and can be shared with the snapshot exporter.
        checkpoint = initial_report.model_copy(deep=True) if initial_report is not None else AddressReport(target_address=address, detected_chains=candidates)
        for source in sources + fallback_sources:
            partial = completed_reports.get(id(source)) or getattr(source, "_partial_report", None)
            if not isinstance(partial, AddressReport):
                continue
            safe_copy = partial.model_copy()
            for field in ("ton_assets", "tokens", "labels", "source_health", "telegram_identities", "activity_chains"):
                setattr(safe_copy, field, [item.model_copy(deep=True) for item in getattr(partial, field)])
            safe_copy.transactions = [item.model_copy(update={"raw": dict(item.raw or {}), "provenance": list(item.provenance)}) for item in partial.transactions]
            import copy
            safe_copy.collection_audit = copy.deepcopy(partial.collection_audit)
            _merge(checkpoint, safe_copy)
        _dedupe_report(checkpoint)
        attach_context(checkpoint)
        refresh_audit(checkpoint, "model", preliminary=True)
        callback = on_checkpoint(checkpoint)
        if inspect.isawaitable(callback):
            await callback
        # Main results reach the existing renderer first. Bounded optional
        # history expansion shares provider gates while main collection runs.
        # TON's typed history must arrive before spending the optional neighbor
        # budget on an incomplete native-only frontier. Final planning still
        # runs when this source is unavailable; checkpoints publish as before.
        ton_history_ready='ton' not in candidates or any(
            source.name=='toncenter_v3' and id(source) in completed_reports for source in sources)
        if continuous and ton_history_ready:start_neighbor_plan(checkpoint)

    async def checkpoint_loop() -> None:
        while True:
            await asyncio.sleep(max(0.05, checkpoint_interval))
            try:
                await publish_collections()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                emit("checkpoint.error", error=f"{type(exc).__name__}: {exc}")

    async def run_source(s):
        source_name = getattr(s, "name", "source")
        budget = _source_budget(source_name, timeout_seconds)
        if continuous and (source_name in {"tonapi", "toncenter", "toncenter_v3", "blockstream_esplora", "mempool_space", "etherscan_api", "bscscan_api", "trongrid", "tronscan", "solana_rpc", "blockchair_dogecoin"} or source_name.startswith(("etherscan_api_", "blockscout_"))):
            budget = max(budget, (deadline - asyncio.get_running_loop().time()) if deadline is not None else 540.0)
        source_started = False
        def source_result(result: AddressReport, status: str) -> AddressReport:
            if getattr(s, "public_context_only", False):
                context_chain = getattr(s, "context_chain", getattr(s, "chain", "multi"))
                result.public_address_context = scoped_public_context(result.public_address_context, source_name, context_chain, address)
                if not result.public_address_context:
                    result.public_address_context = failed_public_context(source_name, context_chain, address, status)
                elif status in {"partial", "timeout", "error"}:
                    for outcome in result.public_address_context["outcomes"]:
                        outcome["status"] = "partial" if outcome.get("claims") else status
            if source_name == "ethereum_ens" and not getattr(result, "ens_profile", None) and (status in {"timeout", "error", "unavailable", "skipped", "rate_limited"} or not _has_ens_data(result)):
                # Outer source cancellation/circuit breakers also produce a
                # fresh identity outcome. An older snapshot must not remain a
                # current verified ENS profile after this lookup failed.
                result.ens_profile = {"lookup_status": "empty" if status in {"ok", "empty"} else status,
                    "retrieved_at": datetime.now(timezone.utc).isoformat(), "source": source_name,
                    "forward_verified": False, "primary_verified": False, "records": {}, "addresses": [],
                    "coverage": {"status": status, "complete": False, "reason": "source lifecycle outcome"},
                    "provenance": {"source": source_name, "method": "source lifecycle outcome", "target_address": address}}
            refresh_audit(result, "normalization", source=source_name)
            completed_reports[id(s)] = result
            emit("source.result", source=source_name, status=status,
                 transactions=len(result.transactions), assets=len(result.ton_assets),
                 errors=[str(error) for error in result.errors if str(error).startswith(f"{source_name}:")])
            return result

        if deadline is not None and asyncio.get_running_loop().time() >= deadline:
            return source_result(AddressReport(target_address=address, sources_used=[source_name],
                source_health=[SourceHealth(source=source_name, status="skipped", timeout_seconds=0,
                    retry_strategy="resume within a new deadline", details="Global collection deadline reached before source start")],
                coverage={source_name: {"status": "truncated", "gap_reason": "Global collection deadline reached before source start"}}), "skipped")

        if _source_disabled(source_name) or not SOURCE_MANAGER.should_run(source_name, budget):
            return source_result(AddressReport(
                target_address=address,
                sources_used=[source_name],
                warnings=[f"{source_name}: disabled_by_fail_counter"],
                source_health=[SourceHealth(source=source_name, status="error", timeout_seconds=budget, retry_strategy="source temporarily disabled", details=SOURCE_MANAGER.details(source_name, budget))],
            ), "error")
        try:
            result = None
            last_error: Exception | None = None
            for attempt in range(SOURCE_MANAGER.retries(source_name, budget) + 1):
                try:
                    async with asyncio.timeout_at(deadline):
                        async with (public_context_semaphore if getattr(s, "public_context_only", False) else semaphore):
                            remaining = deadline - asyncio.get_running_loop().time() if deadline is not None else budget
                            if remaining <= 0:
                                raise asyncio.TimeoutError()
                            effective_budget = min(budget, remaining)
                            if hasattr(s, "_timeout"):
                                s._timeout = effective_budget
                            source_started = True
                            emit("source.start", source=source_name, attempt=attempt + 1, timeout_seconds=effective_budget)
                            try:
                                result = await asyncio.wait_for(s.fetch(address), timeout=effective_budget)
                            except asyncio.CancelledError:
                                emit("source.finish", source=source_name, attempt=attempt + 1, status="cancelled")
                                raise
                            except Exception:
                                emit("source.finish", source=source_name, attempt=attempt + 1, status="error")
                                raise
                            else:
                                emit("source.finish", source=source_name, attempt=attempt + 1, status="returned",
                                     transactions=len(result.transactions) if isinstance(result, AddressReport) else 0)
                    last_error = None
                    break
                except Exception as exc:
                    last_error = exc
                    if attempt >= SOURCE_MANAGER.retries(source_name, budget) or (deadline is not None and asyncio.get_running_loop().time() >= deadline):
                        raise
                    delay = 0.25 * (attempt + 1)
                    if deadline is not None:
                        delay = min(delay, max(0, deadline - asyncio.get_running_loop().time()))
                    await asyncio.sleep(delay)
            if last_error:
                raise last_error
            result = _parser_contract(result, address, source_name)
            if getattr(s, "public_context_only", False):
                context_chain = getattr(s, "context_chain", getattr(s, "chain", "multi"))
                scoped = scoped_public_context(result.public_address_context, source_name, context_chain, address)
                if not scoped:
                    rejected = result.public_address_context
                    scoped = failed_public_context(source_name, context_chain, address, "error")
                    scoped["outcomes"][0]["evidence"] = {"rejected_scope": rejected}
                    result.errors.append(source_name + ": invalid public source/chain/target scope")
                    for health in result.source_health:
                        if health.source == source_name:
                            health.status = "error"
                result.public_address_context = scoped
            has_errors = any(str(error).startswith(f"{source_name}:") for error in result.errors)
            explicit_health = [item for item in result.source_health if item.source == source_name]
            explicit_statuses = {item.status for item in explicit_health}
            # A retry warning records a transient response, not its final result.
            # Exhausted retries and explicit provider health still report failure.
            source_messages = [str(message).lower() for message in result.errors + result.warnings if str(message).startswith(f"{source_name}:")]
            rate_limited = "rate_limited" in explicit_statuses or any(
                "rate_limited" in message or ("http 429" in message and "http 429 retry" not in message)
                for message in source_messages
            )
            produced = any(
                getattr(item, "source", None) == source_name
                for group in (result.balances, result.transactions, result.tokens, result.ton_assets, result.telegram_identities, result.labels, result.risk_flags)
                for item in group
            ) or (source_name == "ethereum_ens" and _has_ens_data(result)) or has_public_claims(result, source_name)
            if "skipped" in explicit_statuses:
                status = "skipped"
            elif rate_limited:
                status = "rate_limited"
            elif "timeout" in explicit_statuses:
                status = "timeout"
            elif "unavailable" in explicit_statuses:
                status = "unavailable"
            elif "error" in explicit_statuses:
                status = "partial" if produced else "error"
            elif getattr(s, "public_context_only", False) and "partial" in explicit_statuses:
                status = "partial"
            elif source_name in EXPERIMENTAL_SOURCES and not has_errors:
                status = "experimental"
            else:
                status = "partial" if has_errors and produced else "error" if has_errors else "ok" if produced else "empty"
            if status != "skipped":
                _record_source_result(source_name, status in {"ok", "partial", "experimental", "empty"})
            if status in {"ok", "partial", "experimental", "empty"}:
                SOURCE_MANAGER.plan(source_name, budget).parsing_confidence = 0.8 if produced else 0.35
            if explicit_health:
                for item in explicit_health:
                    if item.timeout_seconds is None:
                        item.timeout_seconds = budget
                    if not item.details:
                        item.details = SOURCE_MANAGER.details(source_name, budget)
            else:
                result.source_health.append(
                    SourceHealth(
                        source=source_name,
                        status=status,
                        timeout_seconds=budget,
                        retry_strategy="429 retry/backoff, fallback source" if rate_limited else "timeout, HTTP retry, partial result",
                        details="rate limited; fallback active" if rate_limited else "partial data returned" if status == "partial" else SOURCE_MANAGER.details(source_name, budget),
                    )
                )
            return source_result(result, status)
        except asyncio.TimeoutError:
            deadline_reached = deadline is not None and asyncio.get_running_loop().time() >= deadline
            if deadline_reached and not source_started:
                return source_result(AddressReport(target_address=address, sources_used=[source_name],
                    source_health=[SourceHealth(source=source_name, status="skipped", timeout_seconds=0,
                        retry_strategy="resume within a new deadline", details="Global collection deadline reached while queued")],
                    coverage={source_name: {"status": "truncated", "gap_reason": "Global collection deadline reached while queued"}}), "skipped")
            if not deadline_reached:
                _record_source_result(source_name, False)
            partial = getattr(s, "_partial_report", None)
            if isinstance(partial, AddressReport):
                partial.errors.append(f"{source_name}: deadline reached; collected observations retained")
                partial.source_health.append(SourceHealth(source=source_name, status="partial", timeout_seconds=budget, retry_strategy="retained partial observations"))
                return source_result(partial, "partial")
            return source_result(AddressReport(
                target_address=address,
                sources_used=[source_name],
                errors=[f"{source_name}: timeout"],
                source_health=[SourceHealth(source=source_name, status="timeout", timeout_seconds=budget, retry_strategy="bounded source timeout")],
            ), "timeout")
        except asyncio.CancelledError:
            if not continuous:
                raise
            partial = getattr(s, "_partial_report", None)
            if not isinstance(partial, AddressReport):
                partial = AddressReport(target_address=address, sources_used=[source_name])
            partial.warnings.append(f"{source_name}: collection stopped; observations and cursors retained")
            partial.source_health.append(SourceHealth(source=source_name, status="partial", retry_strategy="resume retained cursor", details="Cooperative session stop"))
            return source_result(partial, "partial")
        except Exception as e:
            logger.error("Source failed: %s (%s)", source_name, type(e).__name__)
            _record_source_result(source_name, False)
            r = getattr(s, "_partial_report", None)
            if not isinstance(r, AddressReport):
                r = AddressReport(target_address=address, sources_used=[source_name])
            r.errors.append(sanitize_observation(f"{source_name}: {e}"))
            retained = bool(r.transactions or r.ton_assets or r.balances)
            status = "partial" if retained else "error"
            r.source_health.append(SourceHealth(source=source_name, status=status, timeout_seconds=budget, retry_strategy="partial observations and cursor retained"))
            return source_result(r, status)

    try:
        emit("collectors.start", sources=[source.name for source in sources])
        if on_checkpoint is not None:
            checkpoint_task = asyncio.create_task(checkpoint_loop())
        collection_stopped = False
        source_tasks = [asyncio.create_task(run_source(source)) for source in sources]
        try:
            results = await asyncio.gather(*source_tasks)
        except asyncio.CancelledError:
            if not continuous:
                raise
            collection_stopped = True
            for task in source_tasks:
                task.cancel()
            results = [item for item in await asyncio.gather(*source_tasks, return_exceptions=True) if isinstance(item, AddressReport)]
            emit("collectors.stopped", retained_reports=len(results))
        # A third UTXO provider is useful when primary history is unavailable,
        # not as an unconditional second download of the same full history.
        for chain, source_type in (("btc", BitcoinBlockCypherSource), ("doge", DogecoinBlockCypherSource)):
            if chain not in candidates or collection_stopped:
                continue
            if any(tx.chain == chain for result in results for tx in result.transactions):
                continue
            source = source_type(timeout_seconds)
            sources.append(source)
            source._continuous = continuous
            source._incremental = incremental
            source._resume_state = initial_report.collection_audit.get("streams", {}).get(source.name, {}) if initial_report is not None else {}
            results.append(await run_source(source))
        ton_tx_count = sum(1 for result in results for tx in result.transactions if tx.chain == "ton")
        ton_asset_count = sum(len(result.ton_assets) for result in results)
        ton_identity_count = sum(len(result.telegram_identities) for result in results)
        ton_has_error = any(any(error.startswith("tonapi:") for error in result.errors) for result in results)
        need_assets_fallback = ton_asset_count == 0 or ton_has_error
        if not collection_stopped and fallback_sources and (ton_tx_count < 20 or ton_has_error or ton_asset_count == 0 or ton_identity_count == 0):
            selected_fallbacks = []
            for source in fallback_sources:
                name = getattr(source, "name", "")
                if name == "tonconsole" and not ton_has_error and ton_tx_count >= 20 and ton_asset_count > 0:
                    continue
                if name == "toncenter" and ton_tx_count >= 20 and not ton_has_error:
                    continue
                if name == "toncenter_v3" and ton_asset_count > 0:
                    continue
                if name == "telegram_identity" and ton_identity_count > 0 and ton_asset_count > 0:
                    continue
                if name in {"tonscan_public", "dton_public"} and not ton_has_error and ton_asset_count > 0 and ton_identity_count > 0:
                    continue
                if name in {"fragment_public", "getgems_public"} and not need_assets_fallback:
                    continue
                selected_fallbacks.append(source)
            fallback_results = await asyncio.gather(*(run_source(source) for source in selected_fallbacks))
            fallback_asset_count = sum(len(result.ton_assets) for result in fallback_results)
            results.extend(fallback_results)
            if ton_asset_count == 0 and fallback_asset_count > 0:
                results.append(
                    AddressReport(
                        target_address=address,
                        detected_chains=["ton"],
                        sources_used=["ton_assets_fallback"],
                        source_health=[
                            SourceHealth(
                                source="ton_assets_fallback",
                                status="partial",
                                timeout_seconds=0,
                                retry_strategy="toncenter_v3, tonviewer_public, telegram_identity, fragment_public, getgems_public",
                                details=f"assets recovered from fallback: {fallback_asset_count}",
                            )
                        ],
                    )
                )
        elif fallback_sources:
            for source in fallback_sources:
                source_name = getattr(source, "name", "source")
                results.append(
                    AddressReport(
                        target_address=address,
                        detected_chains=["ton"],
                        sources_used=[source_name],
                        source_health=[SourceHealth(source=source_name, status="partial", timeout_seconds=_source_budget(source_name, timeout_seconds), retry_strategy="fallback source", details="primary TON sources already returned usable data")],
                    )
                )
        emit("collectors.complete", reports=len(results))
        merged = initial_report.model_copy(deep=True) if initial_report is not None else AddressReport(target_address=address)
        for r in results:
            merged = _merge(merged, r)
            if deadline is not None:
                merged.coverage.update(r.coverage)
        for chain in candidates:
            if chain not in merged.detected_chains:
                merged.detected_chains.append(chain)
        if "eth" in candidates:
            eth_data = any(
                getattr(item, "chain", None) == "eth"
                for group in (merged.balances, merged.transactions, merged.tokens, merged.labels, merged.risk_flags)
                for item in group
            )
            if not eth_data:
                merged.warnings.append("ethereum: no source returned data")
        if "btc" in candidates:
            btc_data = any(
                getattr(item, "chain", None) == "btc"
                for group in (merged.balances, merged.transactions)
                for item in group
            ) or bool(merged.bitcoin)
            if not btc_data:
                merged.warnings.append("bitcoin: no source returned data")
        if "doge" in candidates:
            doge_data = any(
                getattr(item, "chain", None) == "doge"
                for group in (merged.balances, merged.transactions)
                for item in group
            ) or bool(merged.dogecoin)
            if not doge_data:
                merged.warnings.append("dogecoin: no source returned data")
        if "bsc" in candidates:
            bsc_data = any(
                getattr(item, "chain", None) == "bsc"
                for group in (merged.balances, merged.transactions, merged.tokens, merged.labels, merged.risk_flags)
                for item in group
            ) or bool(merged.bsc)
            if not bsc_data:
                merged.warnings.append("bsc: no source returned data")
        if "tron" in candidates:
            tron_data = any(
                getattr(item, "chain", None) == "tron"
                for group in (merged.balances, merged.transactions, merged.tokens, merged.labels, merged.risk_flags)
                for item in group
            ) or bool(merged.tron)
            if not tron_data:
                merged.warnings.append("tron: no source returned data")
        if "solana" in candidates:
            solana_data = any(
                getattr(item, "chain", None) == "solana"
                for group in (merged.balances, merged.transactions, merged.tokens, merged.labels, merged.risk_flags)
                for item in group
            ) or bool((merged.solana or {}).get("account"))
            if not solana_data:
                merged.warnings.append("solana: no source returned data")
        from app.attribution.evm_receipt_enrichment import enrich_evm_receipts
        await enrich_evm_receipts(merged, sources, SOURCE_MANAGER, deadline=deadline)
        if on_collected is not None:
            on_collected(merged)
        attach_context(merged)
        start_neighbor_plan(merged,force=True)
        if planner_task is not None:
            await planner_task
    finally:
        if checkpoint_task is not None:
            checkpoint_task.cancel()
            await asyncio.gather(checkpoint_task, return_exceptions=True)
        if planner_task is not None and not planner_task.done():
            planner_task.cancel()
            await asyncio.gather(planner_task, return_exceptions=True)
        try:
            await asyncio.wait_for(close_shared_clients(), timeout=0.6)
        except Exception:
            logger.debug("Shared client close skipped", exc_info=True)

    emit("analysis.start")
    merged = _dedupe_report(merged)
    recovered_from_identity = _recover_ton_assets_from_identities(merged)
    if recovered_from_identity:
        merged.source_health.append(
            SourceHealth(
                source="ton_assets_fallback",
                status="partial",
                timeout_seconds=0,
                retry_strategy="telegram identity evidence",
                details=f"assets recovered from identity evidence: {recovered_from_identity}",
            )
        )
        merged = _dedupe_report(merged)
    merged.transactions.sort(key=_transaction_sort_key, reverse=True)
    before_cap = len(merged.transactions)
    merged.coverage["transactions"] = {"collected_events": before_cap, "display_hint": max_txs, "display_limit": max_txs, "collection_limit_applied": False, "ui_page_size": 260, "retained_records": before_cap, "discarded_by_display_limit": 0, "status": "partial", "note": "All collected operations retained; UI pagination is independent of collection."}
    refresh_audit(merged, "model", display_hint=max_txs, discarded_by_display_limit=0)
    from app.aggregator.financial_operations import project_financial_operations
    financial_projection = project_financial_operations(merged)
    merged.collection_audit["financial_operations"] = {
        "counts": financial_projection["counts"], "history_complete": False,
        "classification": financial_projection["classification"],
        "scope": financial_projection["scope"], "source_observations_modified": False,
    }
    financial_view = merged.model_copy(update={"transactions": financial_projection["transactions"]})
    from app.aggregator.financial_operations import project_activity_operations
    activity_projection = project_activity_operations(merged, financial_projection)
    activity_view = merged.model_copy(update={"transactions": activity_projection["transactions"]})
    merged.counterparties = _build_counterparties(financial_view)
    financial_view.counterparties = merged.counterparties
    activity_view.counterparties = merged.counterparties
    merged.financial_summary = {}
    for tx in financial_view.transactions:
        if transaction_success(tx) is False or tx.direction not in {"in", "out"}:
            continue
        if str((tx.raw or {}).get("type") or "").lower() in {"approval", "approval_for_all"}:
            continue
        amount = decimal_amount(tx)
        if amount is not None:
            totals = merged.financial_summary.setdefault(_financial_asset_key(tx), {"in": Decimal(0), "out": Decimal(0)})
            totals[tx.direction] += amount
    merged.activity_chains = _build_activity_chains(activity_view)
    merged.wallet_timeline = _build_wallet_timeline(activity_view)
    financial_view.wallet_timeline = merged.wallet_timeline
    activity_view.wallet_timeline = merged.wallet_timeline
    merged.asset_paths = _build_asset_paths(merged)
    merged.counterparty_ranking = _build_counterparty_ranking(merged)
    merged.service_detections = _build_service_detections(merged)
    merged.wallet_migration = _build_wallet_migration(financial_view)
    merged.behavioral_fingerprint = _build_behavioral_fingerprint(activity_view, financial_transactions=financial_view.transactions)

    risk_score, heur_flags = score_risk(financial_view)
    merged.risk_score = risk_score
    merged.risk_flags.extend(heur_flags)
    merged = _dedupe_report(merged)
    merged.service_detections = _build_service_detections(merged)
    merged.tron_activity_intelligence = _build_tron_activity_intelligence(merged)
    _append_tron_intelligence_health(merged)
    merged.dogecoin_activity_intelligence = _build_dogecoin_activity_intelligence(merged)
    _append_dogecoin_intelligence_health(merged)
    merged.ton_activity_intelligence = _build_ton_activity_intelligence(merged)
    _append_ton_intelligence_health(merged)
    merged = _dedupe_report(merged)

    from app.utils.async_tasks import owned_thread_call
    merged = await owned_thread_call(lambda: AddressReport.model_validate(merged.model_dump(mode="python")))
    from app.attribution.engine import correlate_attribution
    await owned_thread_call(correlate_attribution, merged)
    refresh_audit(merged, "model", final_analysis=True)
    emit("analysis.complete", transactions=len(merged.transactions), assets=len(merged.ton_assets))
    if defer_graph:
        # The caller attaches verified NFT/P1 facts before constructing the
        # same final graph. All collected data and analytics above are retained.
        emit("graph.deferred", reason="caller_final_graph_after_enrichment")
        return merged, {}
    emit("graph.start")
    graph = build_graph_payload(merged)
    emit("graph.complete", nodes=len(graph.get("nodes", [])), edges=len(graph.get("edges", [])))
    return merged, graph
