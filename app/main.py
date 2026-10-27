from __future__ import annotations

import asyncio
import re
import site
import sys
import time
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

user_site = site.getusersitepackages()
if user_site and user_site not in sys.path:
    sys.path.append(user_site)

from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.text import Text

if __package__ is None and (Path(__file__).parent.parent / "app").exists():
    sys.path.insert(0, str(Path(__file__).parent.parent))

from app.aggregator.analyzer import analyze_address
from app.exporters.html import export as export_html
from app.exporters.pdf import export as export_pdf
from app.sources.bitcoin_blockstream import BitcoinBlockstreamSource
from app.sources.bitcoin_mempool import BitcoinMempoolSource
from app.sources.bsc import BscIntelSource, BscScanApiSource
from app.sources.dogecoin import DogecoinBitquerySource, DogecoinBlockchairSource, DogecoinCoreRpcSource, DogecoinGetBlockSource, DogecoinOklinkSource, DogecoinSoChainSource, DogechainExplorerSource
from app.sources.ethereum_blockchair import EthereumBlockchairSource
from app.sources.ethereum_ens import EthereumEnsSource
from app.sources.ethereum_etherscan_api import EthereumEtherscanApiSource
from app.sources.ethereum_ethplorer import EthereumEthplorerSource
from app.sources.ethereum_etherscan_html import EthereumEtherscanHtmlSource
from app.sources.ethereum_labels import EthereumLabelsSource
from app.sources.evm_rpc import ArbitrumRpcSource, AvalancheRpcSource, BscRpcSource, EthereumRpcSource, OptimismRpcSource, PolygonRpcSource
from app.sources.evm_scans_html import ArbiscanHtmlSource, BscScanHtmlSource, OptimisticEtherscanHtmlSource, PolygonScanHtmlSource
from app.sources.fragment import FragmentPublicSource
from app.sources.risk_cryptoscamdb import CryptoScamDbSource
from app.sources.solana import SolanaRpcSource, SolscanPublicApiSource
from app.sources.telegram_identity import TelegramIdentitySource
from app.sources.ton_public_pages import DtonPublicSource, GetgemsPublicSource, TonscanPublicSource, TonviewerPublicSource
from app.sources.ton_tonapi import TonApiSource
from app.sources.ton_toncenter import TonCenterSource
from app.sources.ton_toncenter_v3 import TonCenterV3Source
from app.sources.ton_tonconsole import TonConsoleSource
from app.sources.tron import TronGridSource, TronScanSource
from app.utils.detect import ETH_RE, detect_candidates
from app.nft_cli import SEARCH_MAX_TRANSACTIONS, SEARCH_MODE, analyze_search_input


console = Console()
ACCENT = "green"
WHITE = "white"
MUTED = "grey42"
ALERT = "bright_white"
PROMPT = "gansar"
LANGUAGE = "ru"

UI = {
    "ru": {
        "menu_scope": "меню",
        "target_scope": "цель",
        "queue_scope": "очередь",
        "menu": [
            ("1", "Досье адреса"),
            ("2", "Пакетная очередь"),
            ("3", "Граф связей"),
            ("4", "Помощь"),
            ("5", "Язык: RU / ENG"),
            ("6", "Выход"),
            ("7", "О проекте"),
        ],
        "language": "язык переключен",
        "session_closed": "сессия закрыта",
        "unknown_command": "неизвестная команда",
        "menu_error": "ошибка меню",
        "input_error": "ошибка ввода",
        "address_required": "нужен адрес",
        "batch_error": "ошибка очереди",
        "file_not_found": "файл не найден",
        "file_empty": "в файле нет адресов",
        "enter": "Enter для возврата",
        "dossier_complete": "досье готово",
        "address": "адрес",
        "chains": "сети",
        "tx": "транзакции",
        "counterparties": "контрагенты",
        "ton_assets": "TON активы",
        "telegram": "Telegram",
        "html": "HTML",
        "pdf": "PDF",
        "session": "сессия",
        "target": "цель",
        "source": "источник",
        "sources_queued": "источники в очереди",
        "waiting_sources": "ожидание источников",
        "connected": "подключен",
        "failed": "ошибка",
        "queued": "очередь",
        "probing": "запрос",
        "slow": "медленно",
        "collecting": "сбор",
        "partial": "частично",
        "ok": "норма",
        "timeout": "таймаут",
        "source_failed": "источник не ответил",
        "source_connected": "источник подключен",
        "source_timeout": "таймаут источника",
        "source_error": "ошибка источника",
        "tx_parsed": "транзакций разобрано",
        "nft_linked": "NFT найдено",
        "username_linked": "имен найдено",
        "gift_linked": "подарков найдено",
        "telegram_linked": "Telegram связей найдено",
        "counterparty_tagged": "контрагентов размечено",
        "risk_signal": "risk сигналов",
        "graph_updated": "граф обновлен",
        "queue": "очередь",
        "batch": "пакет",
        "current": "текущий",
        "processed": "обработано",
        "left": "осталось",
        "analysis_title": "досье адреса",
        "graph_title": "граф связей",
        "help_title": "СПРАВОЧНЫЙ ЦЕНТР GANSAR",
    },
    "en": {
        "menu_scope": "menu",
        "target_scope": "target",
        "queue_scope": "queue",
        "menu": [
            ("1", "Address dossier"),
            ("2", "Batch queue"),
            ("3", "Relationship graph"),
            ("4", "Help"),
            ("5", "Language: RU / ENG"),
            ("6", "Exit"),
            ("7", "About"),
        ],
        "language": "language switched",
        "session_closed": "session closed",
        "unknown_command": "unknown command",
        "menu_error": "menu error",
        "input_error": "input error",
        "address_required": "address is required",
        "batch_error": "batch error",
        "file_not_found": "file not found",
        "file_empty": "file has no addresses",
        "enter": "Enter to return",
        "dossier_complete": "dossier complete",
        "address": "address",
        "chains": "chains",
        "tx": "tx",
        "counterparties": "counterparties",
        "ton_assets": "TON assets",
        "telegram": "Telegram",
        "html": "html",
        "pdf": "pdf",
        "session": "session",
        "target": "target",
        "source": "source",
        "sources_queued": "sources queued",
        "waiting_sources": "waiting for sources",
        "connected": "connected",
        "failed": "failed",
        "queued": "queued",
        "probing": "probing",
        "slow": "slow",
        "collecting": "collecting",
        "partial": "partial",
        "ok": "ok",
        "timeout": "timeout",
        "source_failed": "source failed",
        "source_connected": "source connected",
        "source_timeout": "source timeout",
        "source_error": "source error",
        "tx_parsed": "tx parsed",
        "nft_linked": "nft linked",
        "username_linked": "username linked",
        "gift_linked": "gift linked",
        "telegram_linked": "telegram identity linked",
        "counterparty_tagged": "counterparty tagged",
        "risk_signal": "risk signal",
        "graph_updated": "graph updated",
        "queue": "queue",
        "batch": "batch",
        "current": "current",
        "processed": "processed",
        "left": "left",
        "analysis_title": "address dossier",
        "graph_title": "relationship graph",
        "help_title": "GANSAR HELP CENTER",
    },
}

def tr(key: str) -> str:
    return UI[LANGUAGE].get(key, key)


def chain_label(chain: str) -> str:
    if chain == "eth":
        return "ethereum"
    if chain == "btc":
        return "bitcoin"
    if chain == "doge":
        return "dogecoin"
    if chain == "bsc":
        return "bnb chain"
    return chain


def source_label(name: str) -> str:
    return {"blockstream_esplora": "blockstream", "mempool_space": "mempool", "solscan_public_api": "solscan", "bscscan_api": "bscscan", "bsc_intel": "bsc"}.get(name, name)


@dataclass(frozen=True)
class SourceMeta:
    name: str
    chain: str
    mode: str
    cls: type


@dataclass
class SourceRunState:
    name: str
    chain: str
    mode: str
    status: str = "queued"
    response_time: float | None = None
    tx_count: int = 0
    details: str = "-"


@dataclass
class InvestigationState:
    address: str
    source_states: dict[str, SourceRunState]
    stage: str = "boot"
    current_source: str = "-"
    feed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started: float = field(default_factory=time.monotonic)
    last_progress: float = field(default_factory=time.monotonic)
    diagnostics: list[dict] = field(default_factory=list)
    initial_html: str | None = None
    initial_seconds: float | None = None
    deep_running: bool = False


SOURCE_CATALOG = [
    SourceMeta("blockstream_esplora", "btc", "api", BitcoinBlockstreamSource),
    SourceMeta("mempool_space", "btc", "api", BitcoinMempoolSource),
    SourceMeta("blockchair_dogecoin", "doge", "api", DogecoinBlockchairSource),
    SourceMeta("sochain_dogecoin", "doge", "api", DogecoinSoChainSource),
    SourceMeta("oklink_dogecoin", "doge", "api", DogecoinOklinkSource),
    SourceMeta("dogechain_explorer", "doge", "html", DogechainExplorerSource),
    SourceMeta("dogecoin_core_rpc", "doge", "rpc", DogecoinCoreRpcSource),
    SourceMeta("bitquery_dogecoin", "doge", "api", DogecoinBitquerySource),
    SourceMeta("getblock_dogecoin", "doge", "rpc", DogecoinGetBlockSource),
    SourceMeta("etherscan_api", "eth", "api", EthereumEtherscanApiSource),
    SourceMeta("ethereum_rpc", "eth", "rpc", EthereumRpcSource),
    SourceMeta("ethereum_ens", "eth", "rpc", EthereumEnsSource),
    SourceMeta("blockchair_ethereum", "eth", "api", EthereumBlockchairSource),
    SourceMeta("ethplorer", "eth", "api", EthereumEthplorerSource),
    SourceMeta("ethereum_labels", "eth", "api", EthereumLabelsSource),
    SourceMeta("etherscan_html", "eth", "html", EthereumEtherscanHtmlSource),
    SourceMeta("bscscan_api", "bsc", "api", BscScanApiSource),
    SourceMeta("bsc_intel", "bsc", "api", BscIntelSource),
    SourceMeta("bsc_rpc", "bsc", "rpc", BscRpcSource),
    SourceMeta("bscscan_html", "bsc", "html", BscScanHtmlSource),
    SourceMeta("polygon_rpc", "polygon", "rpc", PolygonRpcSource),
    SourceMeta("polygonscan_html", "polygon", "html", PolygonScanHtmlSource),
    SourceMeta("arbitrum_rpc", "arbitrum", "rpc", ArbitrumRpcSource),
    SourceMeta("arbiscan_html", "arbitrum", "html", ArbiscanHtmlSource),
    SourceMeta("optimism_rpc", "optimism", "rpc", OptimismRpcSource),
    SourceMeta("optimistic_etherscan_html", "optimism", "html", OptimisticEtherscanHtmlSource),
    SourceMeta("avalanche_rpc", "avalanche", "rpc", AvalancheRpcSource),
    SourceMeta("tronscan", "tron", "api", TronScanSource),
    SourceMeta("trongrid", "tron", "api", TronGridSource),
    SourceMeta("tonapi", "ton", "api", TonApiSource),
    SourceMeta("tonconsole", "ton", "fallback", TonConsoleSource),
    SourceMeta("tonviewer_public", "ton", "html", TonviewerPublicSource),
    SourceMeta("toncenter", "ton", "fallback", TonCenterSource),
    SourceMeta("toncenter_v3", "ton", "fallback", TonCenterV3Source),
    SourceMeta("telegram_identity", "ton", "identity", TelegramIdentitySource),
    SourceMeta("fragment_public", "ton", "market", FragmentPublicSource),
    SourceMeta("getgems_public", "ton", "market", GetgemsPublicSource),
    SourceMeta("tonscan_public", "ton", "html", TonscanPublicSource),
    SourceMeta("dton_public", "ton", "html", DtonPublicSource),
    SourceMeta("solscan_public_api", "solana", "api", SolscanPublicApiSource),
    SourceMeta("solana_rpc", "solana", "rpc", SolanaRpcSource),
    SourceMeta("cryptoscamdb", "multi", "risk", CryptoScamDbSource),
]


def _banner() -> str:
    return "\n".join(
        [
            " ██████╗  █████╗ ███╗   ██╗███████╗ █████╗ ██████╗ ",
            "██╔════╝ ██╔══██╗████╗  ██║██╔════╝██╔══██╗██╔══██╗",
            "██║  ███╗███████║██╔██╗ ██║███████╗███████║██████╔╝",
            "██║   ██║██╔══██║██║╚██╗██║╚════██║██╔══██║██╔══██╗",
            "╚██████╔╝██║  ██║██║ ╚████║███████║██║  ██║██║  ██║",
            " ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝",
            "                                                   ",
        ]
    )


def _terminal_width(default: int = 96) -> int:
    return max(72, min(console.width or default, 132))


def _prompt(scope: str) -> str:
    return " " * max(0, (_terminal_width() - 24) // 2) + f"[bold {ACCENT}]{PROMPT}[/][{MUTED}]::[/][{WHITE}]{scope}[/] [{ACCENT}]>[/] "


def _line(label: str, value: str, style: str = WHITE) -> Text:
    text = Text()
    text.append("[+] ", style=ACCENT)
    text.append(label, style=MUTED)
    text.append(" ")
    text.append(value, style=style)
    return text


def startup_screen() -> None:
    console.clear()
    console.print()
    console.print(Align.center(Text(_banner(), style=f"bold {ACCENT}")))
    console.print()


def _menu_lines() -> Group:
    rows = UI[LANGUAGE]["menu"]
    lines = []
    for key, value in rows:
        text = Text()
        text.append(f"[{key}] ", style=ACCENT)
        text.append(value, style=WHITE)
        lines.append(Align.center(text))
    return Group(*lines)


def main_menu() -> str:
    console.print()
    console.print(_menu_lines())
    return console.input(_prompt(tr("menu_scope"))).strip().lower()


def _initial_source_states() -> dict[str, SourceRunState]:
    return {item.name: SourceRunState(item.name, item.chain, item.mode) for item in SOURCE_CATALOG}


def _active_source_states(address: str, selected_chains: list[str] | None = None) -> dict[str, SourceRunState]:
    # A name is not an address on six networks. NFT source rows are added only
    # when the resolver actually makes a request.
    candidates = selected_chains or detect_candidates(address)
    names: list[str] = []
    if "btc" in candidates:
        names.extend(["blockstream_esplora", "mempool_space"])
    if "doge" in candidates:
        names.extend(["blockchair_dogecoin", "sochain_dogecoin", "oklink_dogecoin", "dogechain_explorer", "dogecoin_core_rpc", "bitquery_dogecoin", "getblock_dogecoin"])
    if "eth" in candidates:
        names.extend(["etherscan_api", "ethereum_rpc", "ethereum_ens", "blockchair_ethereum", "ethplorer", "ethereum_labels", "etherscan_html"])
    if "bsc" in candidates:
        names.extend(["bscscan_api", "bsc_intel", "bsc_rpc", "bscscan_html"])
    if "polygon" in candidates:
        names.extend(["polygon_rpc", "polygonscan_html"])
    if "arbitrum" in candidates:
        names.extend(["arbitrum_rpc", "arbiscan_html"])
    if "optimism" in candidates:
        names.extend(["optimism_rpc", "optimistic_etherscan_html"])
    if "avalanche" in candidates:
        names.append("avalanche_rpc")
    if "tron" in candidates:
        names.extend(["tronscan", "trongrid"])
    if "ton" in candidates:
        names.extend(["tonapi", "tonviewer_public"])
    if "solana" in candidates:
        names.extend(["solscan_public_api", "solana_rpc"])
    states = _initial_source_states()
    return {name: states[name] for name in names if name in states}


def _source_produced_data(result: Any, name: str) -> bool:
    groups = [
        getattr(result, "balances", []),
        getattr(result, "transactions", []),
        getattr(result, "tokens", []),
        getattr(result, "ton_assets", []),
        getattr(result, "telegram_identities", []),
        getattr(result, "labels", []),
        getattr(result, "risk_flags", []),
    ]
    return any(getattr(item, "source", None) == name for group in groups for item in group) or (name == "ethereum_ens" and bool(getattr(result, "ens_name", None) or getattr(result, "reverse_ens", None) or getattr(result, "resolver", None) or getattr(result, "text_records", None))) or (name.startswith(("blockchair_dogecoin", "sochain_dogecoin", "oklink_dogecoin", "dogechain_explorer")) and bool(getattr(result, "dogecoin", None)))


def _source_delta_feed(result: Any, name: str) -> list[str]:
    events: list[str] = []
    if name == "ethereum_ens":
        ens_name = getattr(result, "ens_name", None) or getattr(result, "reverse_ens", None)
        if ens_name:
            events.append(f"[+] ens: found {ens_name}")
        else:
            events.append("[!] ens: no records")
        for warning in list(getattr(result, "ens_warnings", []) or [])[:2]:
            events.append(f"[!] ens: {warning}")
        return events[:4]
    if name in {"tronscan", "trongrid"}:
        tokens = [item for item in getattr(result, "tokens", []) if getattr(item, "source", None) == name and getattr(item, "chain", None) == "tron"]
        txs = [item for item in getattr(result, "transactions", []) if getattr(item, "source", None) == name and getattr(item, "chain", None) == "tron"]
        trc20_txs = [item for item in txs if str(getattr(item, "raw", {}).get("type") or "").lower() == "trc20_transfer"]
        if tokens:
            events.append(f"[+] trc20: assets {len(tokens)}")
        if trc20_txs:
            events.append(f"[+] trc20: transfers {len(trc20_txs)}")
        for warning in list(getattr(result, "warnings", []) or [])[:2]:
            if str(warning).startswith(("tron:", name)):
                events.append(f"[!] tron: {str(warning).split(': ', 1)[-1]}")
        return events[:4]
    if name in {"blockchair_dogecoin", "sochain_dogecoin", "oklink_dogecoin", "dogechain_explorer", "dogecoin_core_rpc", "bitquery_dogecoin", "getblock_dogecoin"}:
        txs = [item for item in getattr(result, "transactions", []) if getattr(item, "source", None) == name and getattr(item, "chain", None) == "doge"]
        balances = [item for item in getattr(result, "balances", []) if getattr(item, "source", None) == name and getattr(item, "chain", None) == "doge"]
        doge_data = getattr(result, "dogecoin", {}) or {}
        if balances:
            events.append(f"[+] doge: balance {balances[0].amount:g}")
        if txs:
            events.append(f"[+] doge: tx events {len(txs)}")
        if doge_data.get("unspent_outputs") is not None:
            events.append(f"[+] doge: utxo {doge_data.get('unspent_outputs')}")
        for warning in list(getattr(result, "warnings", []) or [])[:2]:
            if str(warning).startswith(("dogecoin:", name)):
                events.append(f"[!] doge: {str(warning).split(': ', 1)[-1]}")
        return events[:4]
    if name in {"solscan_public_api", "solana_rpc"}:
        tokens = [item for item in getattr(result, "tokens", []) if getattr(item, "source", None) == name and getattr(item, "chain", None) == "solana"]
        txs = [item for item in getattr(result, "transactions", []) if getattr(item, "source", None) == name and getattr(item, "chain", None) == "solana"]
        spl_txs = [item for item in txs if str(getattr(item, "raw", {}).get("type") or "").lower() == "spl_transfer"]
        if tokens:
            events.append(f"[+] spl: assets {len(tokens)}")
        if spl_txs:
            events.append(f"[+] spl: transfers {len(spl_txs)}")
        for warning in list(getattr(result, "warnings", []) or [])[:2]:
            if str(warning).startswith(("solana:", name)):
                events.append(f"[!] solana: {str(warning).split(': ', 1)[-1]}")
        return events[:4]
    if name in {"bscscan_api", "bsc_intel", "bsc_rpc", "bscscan_html"}:
        tokens = [item for item in getattr(result, "tokens", []) if getattr(item, "source", None) == name and getattr(item, "chain", None) == "bsc"]
        txs = [item for item in getattr(result, "transactions", []) if getattr(item, "source", None) == name and getattr(item, "chain", None) == "bsc"]
        risks = [item for item in getattr(result, "risk_flags", []) if getattr(item, "source", None) in {name, "goplus", "honeypot.is"} and getattr(item, "chain", None) == "bsc"]
        bsc_data = getattr(result, "bsc", {}) or {}
        source_status = bsc_data.get("source_status") or {}
        if tokens:
            events.append(f"[+] bep20: assets {len(tokens)}")
        if txs:
            events.append(f"[+] bsc: tx events {len(txs)}")
        if risks:
            events.append(f"[+] bsc: risk hints {len(risks)}")
        if source_status.get("bscscan_api") == "key_required":
            events.append("[!] bscscan: key_required")
        if source_status.get("dexscreener") == "ok":
            events.append("[+] dexscreener: pairs")
        return events[:4]
    assets = [item for item in getattr(result, "ton_assets", []) if getattr(item, "source", None) == name]
    identities = [item for item in getattr(result, "telegram_identities", []) if getattr(item, "source", None) == name and getattr(item, "confidence", "unknown") != "unknown"]
    labels = [item for item in getattr(result, "labels", []) if getattr(item, "source", None) == name]
    risks = [item for item in getattr(result, "risk_flags", []) if getattr(item, "source", None) == name]
    nft_count = sum(1 for item in assets if getattr(item, "type", "") == "nft")
    username_count = sum(1 for item in assets if getattr(item, "type", "") == "username")
    gift_count = sum(1 for item in assets if getattr(item, "type", "") == "gift")
    if nft_count:
        events.append(f"{tr('nft_linked')} {nft_count}")
    if username_count:
        events.append(f"{tr('username_linked')} {username_count}")
    if gift_count:
        events.append(f"{tr('gift_linked')} {gift_count}")
    if identities:
        events.append(f"{tr('telegram_linked')} {len(identities)}")
    if labels:
        events.append(f"{tr('counterparty_tagged')} {len(labels)}")
    if risks:
        events.append(f"{tr('risk_signal')} {len(risks)}")
    return events[:4]


def _source_stream(states: dict[str, SourceRunState]) -> Group:
    order = {"running": 0, "online": 1, "slow": 2, "skipped": 3, "rate_limited": 3, "error": 4, "queued": 5, "done": 6}
    lines = []
    for source in sorted(states.values(), key=lambda item: (order.get(item.status, 9), item.name))[:10]:
        marker = "[+]"
        marker_style = ACCENT
        event = tr("connected")
        signal = f"tx={source.tx_count}"
        if source.status == "error":
            marker = "[!]"
            marker_style = ALERT
            event = tr("failed")
            signal = source.details[:46]
        elif source.status in {"skipped", "rate_limited"}:
            marker = "[!]"
            marker_style = ALERT
            event = tr(source.status)
            signal = source.details[:46]
        elif source.status == "queued":
            marker = "[ ]"
            marker_style = MUTED
            event = tr("queued")
            signal = source.mode
        elif source.status == "running":
            marker = "[~]"
            marker_style = ACCENT
            event = tr("probing")
            signal = source.mode
        elif source.status == "slow":
            event = tr("slow")
        if source.response_time is not None and source.status not in {"queued", "running"}:
            signal = f"{signal} {source.response_time:.1f}s"
        text = Text()
        text.append(f"{marker} ", style=marker_style)
        text.append(source_label(source.name), style=WHITE)
        text.append(f" {event}", style=ACCENT if source.status != "queued" else MUTED)
        text.append(f"  {chain_label(source.chain)}  {signal}", style=MUTED)
        lines.append(text)
    return Group(*lines) if lines else Group(Text(f"[ ] {tr('sources_queued')}", style=MUTED))


def _feed(state: InvestigationState) -> Group:
    items = state.feed[-7:] or [tr("waiting_sources")]
    lines = []
    for item in items:
        text = Text()
        marker = "[+]"
        style = ACCENT
        body = item
        if item.startswith("[!] "):
            marker = "[!]"
            style = ALERT
            body = item[4:]
        elif item.startswith("[>] "):
            marker = "[>]"
            body = item[4:]
        elif item.startswith("[~] "):
            marker = "[~]"
            body = item[4:]
        elif item.startswith("[+] "):
            body = item[4:]
        text.append(f"{marker} ", style=style)
        text.append(body, style=WHITE if tr("graph_updated") in body else MUTED)
        lines.append(text)
    return Group(*lines)


def _analysis_view(state: InvestigationState) -> Group:
    completed = sum(1 for item in state.source_states.values() if item.status in {"online", "slow", "error", "skipped", "rate_limited", "done"})
    total = len(state.source_states)
    lines: list[Any] = [
        Text.from_markup(f"[{ACCENT}]{tr('session')}[/] [{WHITE}]{escape(state.stage)}[/] [{MUTED}]{completed}/{total}[/]"),
        Text.from_markup(f"[{MUTED}]{tr('target')}[/] [{WHITE}]{escape(state.address)}[/]"),
        Text.from_markup(f"[{MUTED}]{tr('source')}[/] [{ACCENT}]{escape(state.current_source)}[/]"),
        Text(f"elapsed {time.monotonic()-state.started:.1f}s · last event {time.monotonic()-state.last_progress:.1f}s ago", style=MUTED),
        Text(""),
        _source_stream(state.source_states),
        Text(""),
        _feed(state),
    ]
    if state.initial_html:
        label = "Первый HTML" if LANGUAGE == "ru" else "Initial HTML"
        lines.insert(4, Text(f"{label}: {state.initial_seconds or 0:.1f}s · {state.initial_html}", style=ACCENT))
        if state.deep_running:
            lines.insert(5, Text("Глубокое исследование продолжается · Ctrl+C: сохранить и остановить" if LANGUAGE == "ru" else "Deep investigation continues · Ctrl+C: save and stop", style=MUTED))
    if state.errors:
        lines.append(Text(""))
        for error in state.errors[-4:]:
            lines.append(Text.from_markup(f"[{ALERT}][!] {escape(error)}[/]"))
    return Group(*lines)


def _search_progress(state: InvestigationState, event: dict) -> None:
    """Display real resolver/provider/analyzer events, scoped to this search."""
    state.last_progress = time.monotonic()
    state.diagnostics.append(event)
    stage = str(event.get("stage") or "unknown")
    state.stage = stage
    if stage == "initial_html.ready":
        state.initial_html = str(event.get("path") or "")
        state.initial_seconds = float(event.get("elapsed_seconds") or time.monotonic()-state.started)
        state.deep_running = True
    elif stage in {"investigation.complete", "investigation.stopped"}:
        state.deep_running = False
    source = event.get("source")
    if stage == "collectors.start":
        catalog = {item.name: item for item in SOURCE_CATALOG}
        for name in event.get("sources", []):
            meta = catalog.get(name)
            state.source_states.setdefault(name, SourceRunState(name, meta.chain if meta else "multi", meta.mode if meta else "api"))
    if source:
        nft_source = stage.startswith(("nft.", "attribution."))
        catalog = next((item for item in SOURCE_CATALOG if item.name == source), None)
        item = state.source_states.setdefault(source, SourceRunState(source, "ton" if nft_source else catalog.chain if catalog else "multi", "nft" if nft_source else "api"))
        state.current_source = source
        if stage in {"source.start", "ens.resolve.start", "nft.request_started", "attribution.request_started"}:
            item.status = "running"
        elif stage in {"source.result", "ens.resolve.complete", "ens.resolve.error", "nft.request_completed", "attribution.request_completed"}:
            status = event.get("status", "unknown")
            if stage == "ens.resolve.complete":
                status = "ok"
            item.status = "online" if status in {"ok", "empty", "partial", "experimental"} else "error" if status in {"timeout", "error", "unavailable", "not_found"} else status
            item.details = str(event.get("error") or status)
            item.tx_count = int(event.get("transactions", event.get("events", item.tx_count)) or 0)
            state.errors.extend(str(error) for error in event.get("errors", []) if str(error) not in state.errors)
        elif stage in {"nft.rate_wait", "nft.request_retry", "attribution.rate_wait", "attribution.request_retry"}:
            delay = event.get("wait_seconds", event.get("retry_after_seconds", event.get("delay_seconds", "")))
            item.details = f"{stage}: {delay}s"
    seconds = event.get("elapsed_seconds", time.monotonic()-state.started)
    detail = source or event.get("target") or event.get("scope") or event.get("status") or ""
    if stage == "ens.resolve.complete":
        detail = f"{event.get('name', '')} → {event.get('resolved_address') or event.get('target', '')} · Ethereum"
    elif stage == "ens.resolve.start":
        detail = str(event.get("query") or source or "")
    if event.get("requests") is not None:
        detail = f"{detail} requests={event['requests']} assets={event.get('assets', '?')} events={event.get('events', '?')}"
    state.feed.append(f"[>] {seconds:.1f}s {stage} {detail}")
    # Diagnostics retain timestamps separately; terminal feed stays bounded.
    if len(state.feed) > 200:
        del state.feed[:-100]


async def _write_search_html(report: Any, graph: dict, output_dir: Path, progress: Any = None, *, checkpoint: bool = False) -> Path:
    from datetime import datetime, timezone
    stage = "checkpoint.html" if checkpoint else "html"
    if progress:
        progress({"stage": stage + ".start", "timestamp": datetime.now(timezone.utc).isoformat(),
            "transactions": len(report.transactions)})
    writing = asyncio.create_task(asyncio.to_thread(export_html, report, graph, output_dir=output_dir, language=LANGUAGE))
    cancelled_after_save = None
    while True:
        try:
            path = await asyncio.shield(writing)
            break
        except asyncio.CancelledError as cancelled:
            # Atomic output IO belongs to this session. A second cancellation
            # must not cancel its asyncio wrapper while its OS thread writes.
            if writing.cancelled():
                raise
            if cancelled_after_save is None:
                cancelled_after_save = cancelled
    if progress:
        progress({"stage": stage + ".complete", "timestamp": datetime.now(timezone.utc).isoformat(), "path": str(path),
            "status": "partial" if checkpoint else "saved", "cancelled_after_save": cancelled_after_save is not None})
    if cancelled_after_save is not None:
        raise cancelled_after_save
    return path


def _source_error_lines(name: str, errors: list[str]) -> list[str]:
    lines = []
    if any("http 429" in item for item in errors):
        lines.append(f"{name}: http 429 after retry; fallback")
    for item in errors:
        if "http 429" in item:
            continue
        if item not in lines:
            lines.append(item)
    return lines[:3]


def _patch_source_observer(state: InvestigationState) -> dict[type, Callable[..., Any]]:
    originals: dict[type, Callable[..., Any]] = {}
    for meta in SOURCE_CATALOG:
        original = meta.cls.fetch
        originals[meta.cls] = original

        async def wrapped(self: Any, address: str, *args: Any, _original: Callable[..., Any] = original, _meta: SourceMeta = meta, **kwargs: Any) -> Any:
            run_state = state.source_states.setdefault(_meta.name, SourceRunState(_meta.name, _meta.chain, _meta.mode))
            run_state.status = "running"
            run_state.details = tr("collecting")
            display_name = source_label(_meta.name)
            state.current_source = display_name
            if _meta.name == "blockstream_esplora":
                state.feed.append("[>] blockstream: address lookup")
            elif _meta.name == "mempool_space":
                state.feed.append("[>] mempool: transactions")
            elif _meta.name == "tronscan":
                state.feed.append("[>] tronscan: lookup")
                state.feed.append("[>] tronscan: transfers")
                state.feed.append("[>] trc20: assets")
            elif _meta.name == "trongrid":
                state.feed.append("[>] trongrid: lookup")
            elif _meta.name == "solscan_public_api":
                state.feed.append("[>] solscan: lookup")
            elif _meta.name == "solana_rpc":
                state.feed.append("[>] solana rpc: balance")
                state.feed.append("[>] solana rpc: signatures")
                state.feed.append("[>] spl: assets")
            else:
                state.feed.append(f"[>] {display_name}: {tr('probing')}")
            if _meta.name == "ethereum_ens":
                state.feed.append("[>] ens: lookup")
                state.feed.append("[>] ens: reverse lookup")
            start = time.perf_counter()
            try:
                result = await _original(self, address, *args, **kwargs)
                elapsed = time.perf_counter() - start
                run_state.response_time = elapsed
                run_state.tx_count = len(getattr(result, "transactions", []))
                source_errors = [str(item) for item in getattr(result, "errors", []) if str(item).startswith(f"{_meta.name}:")]
                source_warnings = [str(item) for item in getattr(result, "warnings", []) if str(item).startswith(f"{_meta.name}:")]
                source_health = [item for item in getattr(result, "source_health", []) if getattr(item, "source", None) == _meta.name]
                explicit_status = next((item.status for item in source_health if item.status in {"skipped", "rate_limited", "timeout", "error"}), "")
                terminal_errors = _source_error_lines(_meta.name, source_errors)
                state.errors.extend(terminal_errors)
                if explicit_status in {"skipped", "rate_limited"}:
                    run_state.status = explicit_status
                    detail = next((item.details for item in source_health if item.status == explicit_status and item.details), "")
                    run_state.details = detail or (source_warnings[0] if source_warnings else explicit_status)
                    state.feed.append(f"[!] {display_name}: {run_state.details}")
                elif source_errors and not _source_produced_data(result, _meta.name):
                    run_state.status = "error"
                    run_state.details = terminal_errors[0] if terminal_errors else source_errors[0]
                    state.feed.append(f"[!] {display_name}: {tr('source_failed')}")
                else:
                    run_state.status = "slow" if elapsed >= 3.0 else "online"
                    run_state.details = tr("partial") if source_errors else tr("ok")
                    state.feed.append(f"[+] {display_name}: {tr('source_connected')}")
                if run_state.tx_count:
                    state.feed.append(f"{tr('tx_parsed')} {run_state.tx_count}")
                state.feed.extend(_source_delta_feed(result, _meta.name))
                return result
            except asyncio.CancelledError:
                run_state.response_time = time.perf_counter() - start
                if run_state.status not in {"online", "slow", "skipped", "rate_limited"} and not run_state.tx_count:
                    run_state.status = "error"
                    run_state.details = "timeout"
                    state.feed.append(f"{_meta.name} {tr('source_timeout')}")
                raise
            except Exception as exc:
                run_state.response_time = time.perf_counter() - start
                run_state.status = "error"
                run_state.details = str(exc)
                state.errors.append(f"{_meta.name}: {exc}")
                state.feed.append(f"{_meta.name} {tr('source_error')}")
                raise

        meta.cls.fetch = wrapped
    return originals


def _restore_sources(originals: dict[type, Callable[..., Any]]) -> None:
    for cls, original in originals.items():
        cls.fetch = original


def _select_evm_chains(address: str) -> list[str] | None:
    if not ETH_RE.match(address.strip()):
        return None
    console.print(_line("chain", "1 Ethereum"))
    console.print(_line("chain", "2 BNB Chain"))
    console.print(_line("chain", "3 Ethereum + BNB Chain"))
    choice = console.input(_prompt("chain")).strip().lower()
    if choice in {"2", "bsc", "bnb", "bnb chain", "bsc chain"}:
        return ["bsc"]
    if choice in {"3", "both", "all", "eth+bsc", "ethereum+bsc"}:
        return ["eth", "bsc"]
    return ["eth"]


async def _analyze_with_live_console(address: str, output_dir: Path, timeout: float = 18.0, max_txs: int = SEARCH_MAX_TRANSACTIONS, selected_chains: list[str] | None = None, *, mode: str = SEARCH_MODE, nft_options: dict | None = None, supervised: bool = False) -> tuple[Any, Path, Path | None]:
    output_dir.mkdir(parents=True, exist_ok=True)
    state = InvestigationState(address=address, source_states=_active_source_states(address, selected_chains))
    chains = selected_chains or detect_candidates(address)
    for chain in chains:
        state.feed.append(f"[>] {chain_label(chain)}: address detected")
    if "bsc" in chains:
        state.feed.extend(["[>] bscscan: lookup", "[>] bscscan: txs", "[>] bep20: transfers", "[>] goplus: security", "[>] honeypot: check", "[>] dexscreener: pairs"])
    # Progress callbacks replace process-wide fetch monkeypatches, which could
    # mix source state between concurrent investigations.
    progress = lambda event: _search_progress(state, event)
    async def report_ready(partial, graph):
        path = await _write_search_html(partial, graph, output_dir, progress, checkpoint=True)
        state.feed.append(f"[+] Partial checkpoint: {path.resolve()} · NFT enrichment continues")
        console.print(Text(f"[+] Частичный HTML: {path.resolve()} · сбор NFT продолжается" if LANGUAGE == "ru" else f"[+] Partial HTML: {path.resolve()} · NFT collection continues", style=ACCENT))
    task = None
    html_task = None
    try:
        if supervised:
            from app.search_runtime import run_bounded_search
            task = asyncio.create_task(run_bounded_search(address, output_dir, timeout=timeout, max_txs=max_txs,
                selected_chains=selected_chains, nft_options=nft_options, language=LANGUAGE, progress=progress))
            with Live(_analysis_view(state), console=console, refresh_per_second=8, transient=False) as live:
                while not task.done():
                    live.update(_analysis_view(state))
                    await asyncio.sleep(.1)
                result = await task
                state.stage = "saved"
                live.update(_analysis_view(state))
                return result
        state.feed.append("[>] resolving input; full supported analysis with bounded source budgets")
        task = asyncio.create_task(analyze_search_input(address, timeout=timeout, max_txs=max_txs,
            selected_chains=selected_chains, nft_options=nft_options, address_analyzer=analyze_address,
            progress=progress, on_report_ready=report_ready))
        with Live(_analysis_view(state), console=console, refresh_per_second=8, transient=False) as live:
            while not task.done():
                live.update(_analysis_view(state))
                await asyncio.sleep(0.15)
            report, graph = await task
            if report.input_resolution.get("owner_analysis_address"):
                state.feed.append("[+] verified NFT owner analyzed: " + report.input_resolution["owner_analysis_address"])
            reduction = graph.get("reduction") or {}
            if "btc" in getattr(report, "detected_chains", []):
                btc_health = [item for item in getattr(report, "source_health", []) if getattr(item, "source", "") in {"blockstream_esplora", "mempool_space"}]
                partial = any(getattr(item, "status", "") in {"partial", "timeout", "error", "rate_limited"} for item in btc_health) or bool(getattr(report, "errors", []))
                state.feed.append("[+] bitcoin: partial data collected" if partial else "[+] bitcoin: data collected")
            if "tron" in getattr(report, "detected_chains", []):
                tron_health = [item for item in getattr(report, "source_health", []) if getattr(item, "source", "") in {"tronscan", "trongrid"}]
                partial = any(getattr(item, "status", "") in {"partial", "timeout", "error", "rate_limited"} for item in tron_health) or any(str(item).startswith(("tron:", "tronscan:", "trongrid:")) for item in list(getattr(report, "errors", []) or []) + list(getattr(report, "warnings", []) or []))
                state.feed.append("[+] tron: partial data collected" if partial else "[+] tron: data collected")
            if "solana" in getattr(report, "detected_chains", []):
                solana_health = [item for item in getattr(report, "source_health", []) if getattr(item, "source", "") in {"solscan_public_api", "solana_rpc"}]
                partial = any(getattr(item, "status", "") in {"partial", "timeout", "error", "rate_limited", "skipped"} for item in solana_health) or any(str(item).startswith(("solana:", "solscan_public_api:", "solana_rpc:")) for item in list(getattr(report, "errors", []) or []) + list(getattr(report, "warnings", []) or []))
                state.feed.append("[+] solana: partial data collected" if partial else "[+] solana: data collected")
            if "eth" in getattr(report, "detected_chains", []):
                ens_name = getattr(report, "ens_name", None) or getattr(report, "reverse_ens", None)
                state.feed.append(f"[+] ens: found {ens_name}" if ens_name else "[!] ens: no records")
                for warning in list(getattr(report, "ens_warnings", []) or [])[:2]:
                    state.feed.append(f"[!] ens: {warning}")
            if "bsc" in getattr(report, "detected_chains", []):
                bsc_health = [item for item in getattr(report, "source_health", []) if getattr(item, "source", "") in {"bscscan_api", "bsc_intel", "bsc_rpc", "bscscan_html"}]
                partial = any(getattr(item, "status", "") in {"partial", "timeout", "error", "rate_limited", "skipped"} for item in bsc_health) or any(str(item).startswith(("bsc:", "bscscan_api:", "bsc_intel:", "bsc_rpc:", "bscscan_html:")) for item in list(getattr(report, "errors", []) or []) + list(getattr(report, "warnings", []) or []))
                state.feed.append("[+] bsc: assets collected")
                state.feed.append("[+] bsc: risk checked")
                if partial:
                    state.feed.append("[!] bsc: partial data")
            if "ton" in getattr(report, "detected_chains", []):
                ton_health = [item for item in getattr(report, "source_health", []) if getattr(item, "source", "") in {"tonapi", "ton_assets_fallback", "ton_intelligence", "tonviewer_username_history"}]
                tonapi_limited = any(getattr(item, "source", "") == "tonapi" and getattr(item, "status", "") == "rate_limited" for item in ton_health)
                recovered = next((item for item in ton_health if getattr(item, "source", "") == "ton_assets_fallback" and "recovered" in str(getattr(item, "details", ""))), None)
                if tonapi_limited:
                    state.feed.append("[!] tonapi: assets 429")
                if recovered:
                    fallback_sources = sorted({asset.source for asset in getattr(report, "ton_assets", []) if getattr(asset, "source", "") != "tonapi"})
                    for source in fallback_sources[:3]:
                        state.feed.append(f"[>] fallback: {source} assets")
                    state.feed.append(f"[+] ton assets recovered {len(getattr(report, 'ton_assets', []))}")
                username_history_items = [item for item in ton_health if getattr(item, "source", "") == "tonviewer_username_history"]
                username_history = next((item for item in username_history_items if not re.search(r"(^|; )found=0(;|$)", str(getattr(item, "details", "") or ""))), username_history_items[0] if username_history_items else None)
                if username_history:
                    details = str(getattr(username_history, "details", "") or "")
                    state.feed.append("[>] tonviewer: username history")
                    if "wallet_fallback=1" in details:
                        state.feed.append("[>] tonviewer: wallet history fallback")
                    if getattr(username_history, "status", "") == "timeout":
                        state.feed.append("[!] tonviewer: timeout")
                    elif re.search(r"(^|; )found=0(;|$)", details):
                        state.feed.append("[~] tonviewer: history unavailable")
                    else:
                        state.feed.append("[+] tonviewer: history found")
                intelligence = next((item for item in ton_health if getattr(item, "source", "") == "ton_intelligence"), None)
                if intelligence:
                    state.feed.append("[>] ton: username history")
                    state.feed.append("[>] ton: gift tracing")
                    state.feed.append("[>] ton: jetton flows")
                    state.feed.append("[+] ton intelligence ready")
            state.stage = "graph"
            state.feed.append(f"{tr('graph_updated')} nodes={reduction.get('default_nodes', len(graph.get('nodes', [])))} edges={reduction.get('default_edges', len(graph.get('edges', [])))}")
            live.update(_analysis_view(state))
            await asyncio.sleep(0.15)
            state.stage = "html"
            live.update(_analysis_view(state))
            html_task = asyncio.create_task(_write_search_html(report, graph, output_dir, progress))
            while not html_task.done():
                live.update(_analysis_view(state))
                await asyncio.sleep(0.15)
            html_path = await html_task
            pdf_path = None
            state.stage = "done"
            state.feed.append("[+] report created")
            live.update(_analysis_view(state))
            await asyncio.sleep(0.15)
            return report, html_path, pdf_path
    except asyncio.CancelledError:
        if supervised and task is not None:
            # The foreground UI owns the managed session. Ctrl+C requests a
            # save/stop and returns its retained report to the normal summary.
            if not task.done():
                task.cancel()
            result = await task
            state.stage = "stopped"
            return result
        raise
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if html_task is not None and not html_task.done():
            # Threaded file writes cannot be interrupted safely. Finish the
            # atomic exporter before leaving the owning UI operation.
            await asyncio.gather(html_task, return_exceptions=True)
        from app.utils.http import close_shared_clients
        await close_shared_clients()


async def _analyze_quiet(address: str, output_dir: Path, timeout: float = 18.0, max_txs: int = SEARCH_MAX_TRANSACTIONS, selected_chains: list[str] | None = None, *, pdf: bool = False, nft_options: dict | None = None, machine_exports: bool = False, progress: Any = None, close_clients: bool = True, supervised: bool = False, deadline: float | None = None, checkpoint_callback: Any = None, continuous: bool = False, model_callback: Any = None) -> tuple[Any, Path, Path | None]:
    output_dir.mkdir(parents=True, exist_ok=True)
    if supervised:
        from app.search_runtime import run_bounded_search
        return await run_bounded_search(address, output_dir, timeout=timeout, max_txs=max_txs,
            selected_chains=selected_chains, nft_options=nft_options, pdf=pdf, machine_exports=machine_exports,
            language=LANGUAGE, progress=progress)
    export_lock = asyncio.Lock()
    try:
        async def report_ready(partial, graph):
            async with export_lock:
                if continuous:
                    partial.coverage["investigation_lifecycle"] = {"phase": "deep_running", "data_complete": False}
                    partial.coverage.setdefault("search_execution", {}).update({"phase": "deep_running",
                        "html_pending_update": False})
                path = await _write_search_html(partial, graph, output_dir, progress, checkpoint=True)
                if checkpoint_callback:
                    await checkpoint_callback(partial, graph, path)
        report, graph = await analyze_search_input(address, timeout=timeout, max_txs=max_txs,
            selected_chains=selected_chains, nft_options=nft_options, address_analyzer=analyze_address,
            progress=progress, on_report_ready=report_ready, on_model_ready=model_callback, deadline=deadline, continuous=continuous)
        if deadline is not None:
            report.coverage.setdefault("search_execution", {"status": "partial", "data_complete": False,
                "reason": "Bounded provider sample; complete chain history has not been established"})
        if continuous:
            stopped = report.coverage.get("search_execution", {}).get("status") == "stopped"
            execution = report.coverage.setdefault("search_execution", {})
            execution.update({"phase": "stopped" if stopped else "finished", "html_pending_update": False})
            if execution.get("status") == "running":
                execution["status"] = "completed"
            report.coverage["investigation_lifecycle"] = {"phase": "stopped" if stopped else "finished",
                "data_complete": False, "reason": "available_streams_finished_or_source_limits"}
        if len(report.transactions) >= 1000:
            # Completed collector/exception cycles must not overlap a second
            # full render model. Reachable reports and active jobs stay owned.
            import gc
            reclaim_started = time.monotonic()
            collected = gc.collect()
            if progress:
                progress({"stage": "final.memory_reclaimed", "transactions": len(report.transactions),
                    "collected_objects": collected, "seconds": time.monotonic()-reclaim_started})
        html_path = await _write_search_html(report, graph, output_dir, progress)
        if machine_exports and report.nft_intelligence:
            from app.exporters.nft_exporter import export_nft_machine_data
            from app.nft_cli import _add_raw_observations
            from app.ton_nft.models import NFTIntelligenceReport
            nft = NFTIntelligenceReport.model_validate(report.nft_intelligence)
            if (report.nft_intelligence.get("owner_analysis_reference") or {}).get("location") == "parent_address_report":
                nft.owner_analysis_snapshot = report.model_dump(mode="json", exclude={"nft_intelligence"})
            paths = export_nft_machine_data(nft, output_dir)
            _add_raw_observations(nft, paths, output_dir, (nft_options or {}).get("store_path"))
        pdf_path = await export_pdf(html_path, output_dir=output_dir) if pdf else None
        return report, html_path, pdf_path
    finally:
        if close_clients:
            from app.utils.http import close_shared_clients
            await close_shared_clients()


def _safe_output_name(address: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", address.strip())
    return cleaned[:80] or "address"


def _command_progress() -> Callable[[dict], None]:
    """Print actual stage changes and occasional activity, without per-request spam."""
    from datetime import datetime, timezone
    from app.utils.security import sanitize_observation
    previous_time = float("-inf")
    important = {"investigation.finalizing", "initial_html.ready", "investigation.deep", "investigation.checkpoint", "investigation.stopping", "investigation.stopped", "investigation.complete", "input.classified", "input.error", "target.resolved", "address.start", "address.complete", "address.error",
        "ens.resolve.start", "ens.resolve.complete", "ens.resolve.error",
        "nft.input_resolution", "nft.target_resolved", "nft.primary_history", "nft.owner_inventory", "nft.owner_history",
        "nft.transaction_details", "nft.related_wallets", "nft.complete", "checkpoint.html.complete", "html.start", "html.complete"}
    def progress(event: dict) -> None:
        nonlocal previous_time
        stage = str(event.get("stage") or "unknown")
        failed_source = stage == "source.result" and event.get("status") in {"error", "timeout", "unavailable", "rate_limited"}
        now = time.monotonic()
        if stage not in important and not failed_source and now-previous_time < 5:
            return
        previous_time = now
        stamp = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        detail = " ".join(str(event[key]) for key in ("source", "status") if event.get(key))
        if stage == "ens.resolve.complete":
            detail = f"{event.get('name', '')} → {event.get('resolved_address') or event.get('target', '')} · Ethereum"
        elif stage == "ens.resolve.start":
            detail = str(event.get("query") or "")
        elif stage == "initial_html.ready":
            detail = f"{event.get('elapsed_seconds', 0):.1f}s · {event.get('path', '')} · " + ("предварительный HTML готов; глубокое исследование продолжается" if LANGUAGE == "ru" else "preliminary HTML ready; deep investigation continues")
        elif stage == "investigation.deep":
            detail = "глубокое исследование продолжается · Ctrl+C: сохранить и остановить" if LANGUAGE == "ru" else "deep investigation continues · Ctrl+C: save and stop"
        elif stage == "investigation.checkpoint":
            detail += f" transactions={event.get('transactions', 0)} assets={event.get('assets', 0)}"
        if event.get("requests") is not None:
            detail = f"{detail} requests={event['requests']} assets={event.get('assets', '?')} events={event.get('events', '?')}"
        console.print(Text(str(sanitize_observation(f"[{stamp}] {stage} {detail}")), style=MUTED))
    return progress


def _path_text(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def final_summary(address: str, report: Any, html_path: Path, pdf_path: Path | None) -> None:
    identities = len([item for item in getattr(report, "telegram_identities", []) if item.confidence != "unknown"])
    assets = len(getattr(report, "ton_assets", [])) + len(getattr(report, "tokens", []))
    console.print()
    lifecycle = getattr(report, "coverage", {}).get("investigation_lifecycle", {})
    stopped = lifecycle.get("phase") == "stopped" or getattr(report, "coverage", {}).get("search_execution", {}).get("status") == "stopped"
    title = ("Исследование остановлено; собранные данные сохранены" if stopped else "Исследование завершено; отчёт сохранён") if LANGUAGE == "ru" else ("Investigation stopped; observations saved" if stopped else "Investigation finished; report saved")
    console.print(Text(f"[+] {title}", style=ACCENT))
    if getattr(report, "coverage", {}).get("search_execution", {}).get("data_complete") is False:
        console.print(Text("[!] Частичный результат: ограничения источников и продолжение указаны в HTML."
            if LANGUAGE == "ru" else "[!] Partial result: source limits and continuation are described in the HTML.", style=ALERT))
    console.print(_line(tr("address"), address))
    if getattr(report, "input_resolution", {}).get("owner_analysis_address"):
        console.print(_line("On-chain owner", report.input_resolution["owner_analysis_address"]))
    console.print(_line(tr("chains"), ", ".join(chain_label(chain) for chain in report.detected_chains) if report.detected_chains else "-"))
    if getattr(report, "ens_name", None) or getattr(report, "reverse_ens", None):
        console.print(_line("ENS", getattr(report, "ens_name", None) or getattr(report, "reverse_ens", None)))
    console.print(_line(tr("tx"), str(len(report.transactions))))
    console.print(_line(tr("counterparties"), str(len(report.counterparties))))
    console.print(_line("assets", str(assets)))
    console.print(_line(tr("telegram"), str(identities)))
    console.print(_line(tr("html"), _path_text(html_path), ACCENT))
    if pdf_path is not None:
        console.print(_line(tr("pdf"), _path_text(pdf_path), ACCENT))


def error_panel(title: str, message: str) -> None:
    console.print()
    console.print(Text.from_markup(f"[{ALERT}][!] {escape(title)}[/] [{MUTED}]{escape(str(message))}[/]"))


def analyze_flow(title: str = "analysis") -> None:
    address = console.input(_prompt(tr("target_scope"))).strip()
    if not address:
        error_panel(tr("input_error"), tr("address_required"))
        return
    try:
        selected_chains = _select_evm_chains(address)
        report, html_path, pdf_path = asyncio.run(_analyze_with_live_console(address, Path("output"), selected_chains=selected_chains, supervised=True))
        final_summary(address, report, html_path, pdf_path)
        import webbrowser
        try:
            webbrowser.open(html_path.resolve().as_uri())
        except OSError:
            pass
    except Exception as exc:
        error_panel(title, str(exc))


def help_screen() -> None:
    console.print()
    console.print(Align.center(Text(tr("help_title"), style=ACCENT)))
    if LANGUAGE == "ru":
        rows = [
            ("анализ", "вставьте адрес в [1]; система определит сети, запустит источники, соберет балансы, транзакции, метки, TON активы и Telegram-связи"),
            ("граф", "[3] запускает тот же сбор и открывает отчет с фокусом на связях: адреса, NFT, имена, подарки, сервисы, tx-узлы"),
            ("полный экран", "в HTML нажмите Полный экран в блоке графа; Esc или Закрыть возвращают обычный режим"),
            ("поиск связей", "используйте поиск узла, затем Изолировать или Путь; несвязанные элементы затемняются"),
            ("фильтры", "фильтруйте тип узла, тип связи и минимальное число tx; Сброс возвращает базовую карту"),
            ("язык", "[5] переключает RU/ENG в терминале; HTML имеет отдельный переключатель в правой панели"),
            ("HTML", "после анализа путь к report.html выводится в финале; файл лежит в output"),
            ("сети", "TON, BTC, ETH, BSC, Polygon, Arbitrum, Optimism, Avalanche, Tron, Solana"),
            ("сущности", "кошельки, транзакции, NFT, имена, подарки, домены, жетоны, контракты, биржи, сервисы, маркетплейсы"),
            ("сценарий", "1) адрес -> 2) сигналы -> 3) поиск в графе -> 4) изоляция/путь -> 5) таймлайн транзакций -> 6) ссылки на доказательства"),
        ]
    else:
        rows = [
            ("analysis", "paste an address in [1]; the system detects chains and collects balances, tx, labels, TON assets and Telegram links"),
            ("graph", "[3] runs collection and opens the report around relationships: addresses, NFT, usernames, gifts, services, tx nodes"),
            ("fullscreen", "in the HTML report press Fullscreen in the graph block; Esc or Close returns to normal mode"),
            ("link search", "use node search, then Isolate or Trace path; unrelated elements are dimmed"),
            ("filters", "filter node type, relationship type and minimum tx count; Reset returns the base map"),
            ("language", "[5] switches RU/ENG in terminal; HTML has its own switch in the side panel"),
            ("HTML", "the report.html path is printed after analysis; the file is written to output"),
            ("chains", "TON, BTC, ETH, BSC, Polygon, Arbitrum, Optimism, Avalanche, Tron, Solana"),
            ("entities", "wallets, tx, NFT, usernames, gifts, domains, jettons, contracts, exchanges, services, marketplaces"),
            ("workflow", "1) address -> 2) signals -> 3) graph search -> 4) isolate/path -> 5) tx timeline -> 6) evidence links"),
        ]
    for label, value in rows:
        console.print(_line(label, value))
    console.input(f"\n[bright_black]{tr('enter')}[/bright_black]")


@dataclass
class BatchItemState:
    address: str
    status: str = "queued"
    stage: str = "queued"
    started: float | None = None
    last_progress: float | None = None
    timestamp: str | None = None
    details: str = ""


@dataclass
class BatchState:
    total: int
    current: str = "-"
    completed: int = 0
    failed: int = 0
    last_error: str = "-"
    items: dict[int, BatchItemState] = field(default_factory=dict)


def _batch_progress(state: BatchState, item: BatchItemState, event: dict) -> None:
    item.stage = str(event.get("stage") or "unknown")
    item.last_progress = time.monotonic()
    item.timestamp = str(event.get("timestamp") or "")
    item.details = " ".join(str(event[key]) for key in ("source", "status") if event.get(key))
    if event.get("requests") is not None:
        item.details += f" requests={event['requests']} assets={event.get('assets', '?')} events={event.get('events', '?')}"
    state.current = item.address


def _batch_view(state: BatchState, addresses: list[str]) -> Group:
    active = [(index, item) for index, item in state.items.items() if item.status == "running"]
    waiting = [(index, item) for index, item in state.items.items() if item.status == "queued"]
    visible = active + waiting[:max(0, 6 - len(active))]
    if not visible:
        visible = list(state.items.items())[-5:]
    queue_lines = []
    now = time.monotonic()
    for index, item in visible:
        detail = f"{index+1:02d} {item.address} · {item.status} · {item.stage}"
        if item.started is not None:
            detail += f" · elapsed {now-item.started:.1f}s"
        if item.last_progress is not None:
            detail += f" · last event {now-item.last_progress:.1f}s ago"
        if item.timestamp:
            detail += f" · {item.timestamp}"
        if item.details:
            detail += f" · {item.details}"
        queue_lines.append(Text(detail, style=WHITE if item.status == "running" else MUTED))
    if state.completed + state.failed >= len(addresses):
        queue_lines.append(Text(f"[+] {tr('queue')} complete" if LANGUAGE == "en" else "[+] очередь завершена", style=ACCENT))
    return Group(
        Text.from_markup(f"[{ACCENT}]{tr('queue')}[/] [white]{tr('batch')}[/]"),
        Text.from_markup(f"[{MUTED}]{tr('current')}[/] [white]{escape(state.current)}[/]"),
        Text.from_markup(f"[{ACCENT}][+][/] {tr('processed')} [white]{state.completed}[/]"),
        Text.from_markup(f"[{MUTED}][ ][/] {tr('failed')} [white]{state.failed}[/]"),
        Text.from_markup(f"[{MUTED}][ ][/] {tr('left')} [white]{max(0, state.total - state.completed - state.failed)}[/]"),
        Text(""),
        Group(*queue_lines),
        Text.from_markup(f"[{ALERT}]{escape(state.last_error)}[/]") if state.failed else Text(""),
    )


async def batch_flow(*, supervised: bool = False) -> None:
    raw_path = console.input(_prompt(tr("queue_scope"))).strip()
    file_path = Path(raw_path)
    if not file_path.exists():
        error_panel(tr("batch_error"), f"{tr('file_not_found')}: {file_path}")
        return
    addresses = [line.strip() for line in file_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not addresses:
        error_panel(tr("batch_error"), tr("file_empty"))
        return
    state = BatchState(total=len(addresses), items={index: BatchItemState(address) for index, address in enumerate(addresses)})
    if supervised:
        from app.search_runtime import run_bounded_jobs
        jobs = [{"query": address, "output": str((Path("output") / _safe_output_name(address)).resolve())} for address in addresses]
        for item in state.items.values():
            item.status, item.started = "running", time.monotonic()
        task = asyncio.create_task(run_bounded_jobs(jobs, language=LANGUAGE,
            progress=lambda index, event: _batch_progress(state, state.items[index], event), return_on_cancel=True))
        try:
            with Live(_batch_view(state, addresses), console=console, refresh_per_second=6, transient=False) as live:
                while not task.done():
                    live.update(_batch_view(state, addresses))
                    await asyncio.sleep(.1)
                for index, result in enumerate(await task):
                    state.items[index].status = result["status"]
                    if result.get("error"):
                        state.failed += 1
                        state.last_error = result["error"]
                    else:
                        state.completed += 1
                live.update(_batch_view(state, addresses))
        except asyncio.CancelledError:
            if not task.done():
                task.cancel()
            results = await task
            for index, result in enumerate(results):
                state.items[index].status = result["status"]
                if result.get("error"):
                    state.failed += 1
                    state.last_error = result["error"]
                else:
                    state.completed += 1
            console.print(Text("[+] Исследование остановлено; полученные отчёты сохранены" if LANGUAGE == "ru" else "[+] Investigation stopped; obtained reports saved", style=ACCENT))
            return
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        console.input(f"\n[bright_black]{tr('enter')}[/bright_black]")
        return
    lock = asyncio.Lock()
    queue = asyncio.Queue()
    for index, address in enumerate(addresses):
        queue.put_nowait((index, address))

    async def worker() -> None:
        while True:
            try:
                index, address = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            async with lock:
                state.current = address
                item = state.items[index]
                item.status, item.stage, item.started = "running", "starting", time.monotonic()
            try:
                await _analyze_quiet(address, Path("output") / _safe_output_name(address),
                    progress=lambda event, current=item: _batch_progress(state, current, event), close_clients=False)
                async with lock:
                    state.completed += 1
                    item.status = "saved"
            except asyncio.CancelledError:
                item.status = "cancelled"
                raise
            except Exception as exc:
                from app.utils.security import sanitize_observation
                async with lock:
                    state.failed += 1
                    state.last_error = str(sanitize_observation(f"{address}: {exc}"))
                    item.status, item.details = "failed", str(sanitize_observation(str(exc)))
            finally:
                queue.task_done()

    tasks = []
    try:
        with Live(_batch_view(state, addresses), console=console, refresh_per_second=6, transient=False) as live:
            tasks = [asyncio.create_task(worker()) for _ in range(min(4, len(addresses)))]
            while any(not task.done() for task in tasks):
                live.update(_batch_view(state, addresses))
                await asyncio.sleep(0.2)
            await asyncio.gather(*tasks)
            live.update(_batch_view(state, addresses))
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        from app.utils.http import close_shared_clients
        await close_shared_clients()
    console.input(f"\n[bright_black]{tr('enter')}[/bright_black]")


def toggle_language() -> None:
    global LANGUAGE
    LANGUAGE = "en" if LANGUAGE == "ru" else "ru"
    console.print(Text(f"[+] {tr('language')}: {LANGUAGE.upper()}", style=ACCENT))


def open_about_page() -> bool:
    """Open the local project page; browser lifetime never owns the CLI loop."""
    path = Path(__file__).resolve().parent.parent / "htmlG" / "about.html"
    title = "О проекте" if LANGUAGE == "ru" else "About"
    if not path.is_file():
        error_panel(title, f"{tr('file_not_found')}: {path}")
        return False
    try:
        opened = webbrowser.open(path.as_uri(), new=2)
    except (OSError, webbrowser.Error, ValueError) as exc:
        message = "Не удалось открыть браузер" if LANGUAGE == "ru" else "Could not open the browser"
        error_panel(title, f"{message}: {exc}\n{path}")
        return False
    if not opened:
        message = "Браузер не запущен. Откройте файл вручную" if LANGUAGE == "ru" else "Browser did not open. Open the file manually"
        error_panel(title, f"{message}: {path}")
        return False
    console.print(Text(f"{title}: {path}", style=MUTED))
    return True


def run() -> None:
    startup_screen()
    while True:
        choice = main_menu()
        if choice == "1":
            analyze_flow(tr("analysis_title"))
        elif choice == "2":
            asyncio.run(batch_flow(supervised=True))
        elif choice == "3":
            analyze_flow(tr("graph_title"))
        elif choice == "4":
            help_screen()
        elif choice == "5":
            toggle_language()
        elif choice == "7":
            open_about_page()
        elif choice == "6":
            console.print(f"[bright_black]{tr('session_closed')}[/bright_black]")
            break
        else:
            error_panel(tr("menu_error"), tr("unknown_command"))


def main() -> None:
    global LANGUAGE
    if len(sys.argv) == 1:
        run()
        return
    from app.nft_cli import command_parser, print_nft_summary, run_nft_command
    parser = command_parser()
    args = parser.parse_args()
    LANGUAGE = args.language
    if args.attribution_store:
        import os
        os.environ["GANSAR_ATTRIBUTION_DATASET"] = str(args.attribution_store.resolve())
    if args.update_attribution_datasets:
        from app.attribution.datasets import update_datasets,DEFAULT_LOCAL_SNAPSHOT
        import json
        try:
            summary=asyncio.run(update_datasets(store_path=args.attribution_store or DEFAULT_LOCAL_SNAPSHOT,
                sources_path=args.attribution_sources))
            console.print(Text(json.dumps(summary,ensure_ascii=False,default=str)))
        except Exception as exc:
            from app.utils.security import sanitize_observation
            error_panel("Attribution datasets",str(sanitize_observation(str(exc))))
            raise SystemExit(1) from None
    elif args.reexport:
        try:
            result, paths = asyncio.run(run_nft_command(args))
            print_nft_summary(result, paths, console, LANGUAGE)
        except Exception as exc:
            from app.utils.security import sanitize_observation
            error_panel("TON NFT", str(sanitize_observation(str(exc))))
            raise SystemExit(1) from None
    elif args.address or args.ton_nft:
        try:
            from app.nft_cli import budget_from_args
            if args.incremental and not args.resume:
                parser.error("--incremental requires --resume ID")
            nft_options = {"mode": SEARCH_MODE, "scope": args.scope, "budget": budget_from_args(args),
                           "store_path": args.snapshot, "investigation_id": args.resume,
                           "resume": bool(args.resume), "incremental": args.incremental}
            query = args.address or args.ton_nft
            report, html_path, pdf_path = asyncio.run(_analyze_quiet(query, args.output or Path("output"),
                pdf=args.pdf and not args.no_pdf, nft_options=nft_options, machine_exports=args.machine_exports,
                progress=_command_progress(), supervised=True))
            final_summary(query, report, html_path, pdf_path)
        except Exception as exc:
            from app.utils.security import sanitize_observation
            error_panel("Address analysis", str(sanitize_observation(str(exc))))
            raise SystemExit(1) from None
    elif args.resume or args.incremental:
        parser.error("--resume/--incremental requires --address QUERY")
    else:
        run()


if __name__ == "__main__":
    main()
