from __future__ import annotations

import re

import base64
import json
import shutil
import hashlib
from functools import lru_cache
from dataclasses import dataclass
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape, pass_eval_context
from markupsafe import Markup
from app.exporters.payload_transport import pack_json, decoder_script
from app.utils.security import sanitize_observation
from app.utils.ton_normalize import ton_canonical_address
from app.attribution.normalize import address_id, canonical_address
from app.utils.event_identity import event_identity
from app.exporters.render_security import safe_href, safe_image_url, safe_graph_payload, guard_rendered_html, guard_rendered_chunks

from app.models.report import AddressReport, Transaction
from app.sources.registry import SOURCE_BY_NAME


@dataclass(frozen=True)
class HtmlExportResult:
    output_path: Path


BACKGROUND_DEFAULTS = {
    "image": "",
    "video": "",
    "overlay_opacity": 0.72,
    "blur": 0,
    "vignette": 0.84,
    "grid_opacity": 0.05,
    "animated": True,
    "gradient": "radial-gradient(circle at 50% 12%, rgba(99,183,120,.12), transparent 34%), linear-gradient(180deg, rgba(5,8,7,.94), rgba(2,3,3,1) 620px)",
}

GRAPH_ICON_FILES = {
    "ton_wallet": "ton.svg",
    "bitcoin": "bitcoin.svg",
    "dogecoin": "dogecoin.svg",
    "ethereum": "ethereum.svg",
    "solana": "solana.svg",
    "tron": "tron.svg",
    "telegram": "telegram.svg",
    "nft": "badge.svg",
    "gift": "gift.svg",
    "counterparty": "wallet-cards.svg",
    "contract": "file-badge.svg",
    "service": "server-cog.svg",
    "unknown": "unknown.svg",
}

GRAPH_3D_VENDOR_FILES = ("3d-force-graph.min.js",)

MARKETPLACE_COVER_IMAGES = {
    "Fragment": "https://fragment.com/favicon.ico",
    "Getgems": "https://getgems.io/favicon.ico",
    "Portals": "https://portals.market/favicon.ico",
    "TON Diamonds": "https://ton.diamonds/favicon.ico",
}

BROKEN_IMAGE_HOSTS = {"dns-cdn.gramcoin.org"}

FON_MIME = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
}

LOGO_MIME = {
    **FON_MIME,
    ".svg": "image/svg+xml",
}

VIDEO_EXTENSIONS = {".mp4", ".webm"}
FON_MEDIA_ORDER = (
    "background.mp4",
    "background.webm",
    "background.gif",
    "background.webp",
    "background.png",
    "background.jpg",
    "background.jpeg",
)
LOGO_MEDIA_ORDER = (
    "logo.mp4",
    "logo.webm",
    "logo.gif",
    "logo.webp",
    "logo.png",
    "logo.jpg",
    "logo.jpeg",
)

I18N = {
    "ru": {
        "report_mark": "GANSAR",
        "title": "Крипто-досье",
        "report_kind": "OSINT investigator report",
        "risk": "риск",
        "nodes": "узлов",
        "edges": "связей",
        "nav_graph": "Граф связей",
        "nav_signals": "Сигналы",
        "nav_ton_activity": "Анализ TON-активности",
        "nav_tron_activity": "Анализ TRON-активности",
        "nav_dogecoin_activity": "Анализ Dogecoin-активности",
        "nav_wallet_migration": "Миграция кошелька",
        "nav_behavioral_fingerprint": "Поведенческий профиль",
        "nav_address_story": "История адреса",
        "nav_assets": "Активы",
        "nav_identity": "Telegram идентичность",
        "nav_ens": "ENS",
        "nav_transactions": "Транзакции",
        "nav_sources": "Источники",
        "transactions": "транзакции",
        "counterparties": "контрагенты",
        "ton_assets": "Активы",
        "telegram_links": "Telegram связи",
        "graph_workspace": "Граф связей",
        "graph_2d": "2D-граф",
        "graph_3d": "3D-граф",
        "key_relationships": "ключевые связи",
        "graph_hint": "перетаскивание, колесо, двойной клик",
        "fullscreen": "Полный экран",
        "close": "Закрыть",
        "fit_graph": "Вписать граф",
        "reset_camera": "Сброс камеры",
        "pause_physics": "Пауза физики",
        "resume": "Продолжить",
        "center_address": "Центрировать адрес",
        "show_labels": "Показать подписи",
        "hide_labels": "Скрыть подписи",
        "show_images": "Показать изображения",
        "hide_images": "Скрыть изображения",
        "graph_3d_unavailable": "3D-граф недоступен",
        "graph_3d_slow_warning": "3D-граф может работать медленнее на больших кейсах",
        "target": "Цель",
        "reset": "Сброс",
        "isolate": "Изолировать",
        "trace_path": "Путь",
        "search_node": "Поиск узла",
        "all_node_types": "Все типы узлов",
        "all_relationships": "Все связи",
        "minimum_tx": "минимум tx",
        "relationship_inspector": "Инспектор связей",
        "state": "состояние",
        "select_node_edge": "выберите узел или связь",
        "signals": "Сигналы",
        "ton_activity_intelligence": "Анализ TON-активности",
        "tron_activity_intelligence": "Анализ TRON-активности",
        "dogecoin_activity_intelligence": "Анализ Dogecoin-активности",
        "wallet_migration_activity": "Wallet Migration Activity",
        "behavioral_fingerprint": "Поведенческий профиль",
        "address_story": "История адреса",
        "address_story_hint": "Хронология построена только из датированных фактов отчёта.",
        "address_story_empty": "Датированные события по адресу не найдены.",
        "address_story_events": "событий",
        "address_story_shown": "показано",
        "address_story_first": "первое событие",
        "address_story_last": "последнее событие",
        "address_story_sources": "источники",
        "address_story_hidden": "скрыто событий",
        "address_story_period": "период",
        "address_story_transactions": "транзакции",
        "address_story_counterparties": "контрагенты",
        "address_story_activities": "активности",
        "address_story_expand": "Развернуть историю",
        "address_story_collapse": "Свернуть историю",
        "activity_label": "Активность",
        "observation_label": "Наблюдение",
        "facts_label": "Факты",
        "evidence_label": "Доказательства",
        "data_confidence": "Уверенность данных",
        "insufficient_data": "данных недостаточно",
        "not_detected": "не обнаружено",
        "high": "высокая",
        "medium": "средняя",
        "low": "низкая",
        "peak_activity": "Пик активности",
        "first_activity": "Первая активность",
        "last_activity": "Последняя активность",
        "active_weekdays": "Активные дни",
        "active_hours": "Активные часы",
        "average_transfer": "Средний перевод",
        "median_transfer": "Медианный перевод",
        "tx_per_day": "Транзакций в день",
        "active_days": "Активных дней",
        "unique_counterparties": "Уникальных контрагентов",
        "asset_count": "Активов",
        "nft_count": "NFT",
        "gift_count": "Подарков",
        "marketplace_interactions": "Marketplace interactions",
        "defi_interactions": "DeFi interactions",
        "dominant_asset": "Основной актив",
        "heatmap": "Тепловая карта активности",
        "wallet_migration_observation": "Наблюдение",
        "no_signals": "Активные источники не вернули уверенных сигналов.",
        "assets": "Активы",
        "no_photo": "Нет фото",
        "no_assets_found": "Активы не найдены",
        "source": "источник",
        "open_evidence": "открыть доказательство",
        "identity": "Telegram идентичность",
        "ens_identity": "ENS",
        "ens_name": "ENS имя",
        "reverse_ens": "reverse ENS",
        "reverse_status": "reverse статус",
        "resolver": "resolver",
        "owner": "owner",
        "resolved_address": "resolved address",
        "text_records": "text records",
        "no_ens": "ENS записи не найдены.",
        "unavailable": "недоступно",
        "verified": "подтверждено",
        "unverified": "не подтверждено",
        "status": "статус",
        "username": "имя",
        "domain": "домен",
        "gift": "подарок",
        "tx_title": "Транзакции",
        "filter_transactions": "Фильтр транзакций",
        "no_tx_filter_results": "Нет транзакций по выбранному фильтру",
        "all_tx_types": "Все типы tx",
        "copied": "скопировано",
        "copy_hash": "копировать хэш",
        "copy_address": "копировать адрес",
        "details": "детали",
        "balances": "балансы",
        "bnb_overview": "BNB Chain",
        "contract_intelligence": "contract intelligence",
        "security_risk": "risk / security",
        "dex_liquidity": "DEX / liquidity",
        "approvals": "approvals",
        "top_counterparties": "top counterparties",
        "warnings": "предупреждения",
        "gas_fee": "gas fee",
        "method": "method",
        "hash": "хэш",
        "from": "от",
        "to": "кому",
        "counterparty": "контрагент",
        "service": "сервис",
        "asset": "актив",
        "ton_wallet": "TON кошелёк",
        "telegram_entity": "Telegram",
        "nft_entity": "NFT",
        "counterparty_entity": "контрагент",
        "contract_entity": "контракт",
        "service_entity": "сервис",
        "sources": "Источники",
        "no_sources": "Нет записей о состоянии источников.",
        "type": "тип",
        "entity": "сущность",
        "chain": "сеть",
        "links": "связи",
        "evidence": "доказательство",
        "open": "открыть",
        "telegram_project": "Наш Telegram-проект:",
        "isolated_node": "узел изолирован",
        "path": "путь",
        "hops": "переходов",
        "sent": "отправлено",
        "received": "получено",
        "self": "самому себе",
        "unknown": "неизвестно",
        "nft_transfer": "NFT перевод",
        "token_transfer": "перевод токена",
        "contract_call": "вызов контракта",
        "trx_transfer": "TRX перевод",
        "trc20_transfer": "TRC20 перевод",
        "usdt_transfer": "USDT перевод",
        "resource_event": "resource event",
        "permission_update": "permission update",
        "defi_interaction": "DeFi interaction",
        "swap": "swap",
        "meme_token_event": "meme token event",
        "failed_transfer": "failed transfer",
        "doge_received": "DOGE получен",
        "doge_sent": "DOGE отправлен",
        "doge_consolidation": "DOGE consolidation",
        "doge_large_transfer": "крупный DOGE перевод",
        "doge_dust_activity": "DOGE dust activity",
        "transfer": "перевод",
        "external_message": "внешнее сообщение (не перевод)",
        "username_history": "История Telegram usernames",
        "ownership_history_unavailable": "История владения недоступна",
        "current_owner": "текущий владелец",
        "previous_owners": "предыдущие владельцы",
        "last_transfer": "последний перевод",
        "sale_history": "история продаж",
        "gift_tracing": "Трассировка подарков",
        "gift_route_intelligence": "Gift Route Intelligence",
        "gift_route_hint": "Мини-досье строится только по реальным Gift metadata и transfer events.",
        "gift_route": "Маршрут подарка",
        "gift_route_stats": "Что известно о подарке",
        "gift_route_alerts": "Подозрительные перемещения",
        "gift_route_no_alerts": "Рассчитанных флагов по доступной истории нет.",
        "gift_route_history": "История",
        "gift_route_related": "Связанные адреса",
        "gift_route_sources": "Источники",
        "gift_route_unavailable": "Маршрут недоступен: источники не вернули историю переходов.",
        "gift_route_origin": "Происхождение",
        "gift_route_traits": "Признаки",
        "gift_route_show_all": "Показать все маршруты",
        "gift_route_shown": "Показано: {shown} из {total}",
        "sender": "отправитель",
        "receiver": "получатель",
        "transfer_chain": "цепочка переводов",
        "jetton_flows": "Jetton потоки",
        "net_flow": "нетто поток",
        "transfer_count": "число переводов",
        "largest_transfer": "крупнейший перевод",
        "recent_transfers": "последние переводы",
        "metadata_unavailable": "метаданные недоступны",
        "stablecoin_hint": "stablecoin",
        "view_transactions": "Посмотреть транзакции",
        "hide_transactions": "Скрыть транзакции",
        "transaction_history": "История транзакций",
        "transaction_history_unavailable": "История транзакций недоступна",
        "open_in_tonviewer": "Открыть в Tonviewer",
        "received_nft": "Получен NFT",
        "sent_nft": "Отправлен NFT",
        "received_ton": "Получен TON",
        "sent_ton": "Отправлен TON",
        "nft_transfer": "NFT transfer",
    },
    "en": {
        "report_mark": "GANSAR",
        "title": "Crypto dossier",
        "report_kind": "OSINT investigator report",
        "risk": "risk",
        "nodes": "nodes",
        "edges": "edges",
        "nav_graph": "Graph workspace",
        "nav_signals": "Signals",
        "nav_ton_activity": "TON Activity Intelligence",
        "nav_tron_activity": "TRON Activity Intelligence",
        "nav_dogecoin_activity": "Dogecoin Activity Intelligence",
        "nav_wallet_migration": "Wallet Migration",
        "nav_behavioral_fingerprint": "Behavioral Fingerprint",
        "nav_address_story": "Address Story",
        "nav_assets": "Assets",
        "nav_identity": "Telegram identity",
        "nav_ens": "ENS",
        "nav_transactions": "Transactions",
        "nav_sources": "Sources",
        "transactions": "transactions",
        "counterparties": "counterparties",
        "ton_assets": "Assets",
        "telegram_links": "Telegram links",
        "graph_workspace": "Graph workspace",
        "graph_2d": "2D Graph",
        "graph_3d": "3D Graph",
        "key_relationships": "key relationships",
        "graph_hint": "drag, wheel, double click",
        "fullscreen": "Fullscreen",
        "close": "Close",
        "fit_graph": "Fit graph",
        "reset_camera": "Reset camera",
        "pause_physics": "Pause physics",
        "resume": "Resume",
        "center_address": "Center address",
        "show_labels": "Show labels",
        "hide_labels": "Hide labels",
        "show_images": "Show images",
        "hide_images": "Hide images",
        "graph_3d_unavailable": "3D graph unavailable",
        "graph_3d_slow_warning": "3D graph may be slower on large cases",
        "target": "Target",
        "reset": "Reset",
        "isolate": "Isolate",
        "trace_path": "Trace path",
        "search_node": "Search node",
        "all_node_types": "All node types",
        "all_relationships": "All relationships",
        "minimum_tx": "minimum tx",
        "relationship_inspector": "Relationship inspector",
        "state": "state",
        "select_node_edge": "select a node or edge",
        "signals": "Signals",
        "ton_activity_intelligence": "TON Activity Intelligence",
        "tron_activity_intelligence": "TRON Activity Intelligence",
        "dogecoin_activity_intelligence": "Dogecoin Activity Intelligence",
        "wallet_migration_activity": "Wallet Migration Activity",
        "behavioral_fingerprint": "Behavioral Fingerprint",
        "address_story": "Address Story",
        "address_story_hint": "Timeline built only from dated report facts.",
        "address_story_empty": "No dated address events found.",
        "address_story_events": "events",
        "address_story_shown": "shown",
        "address_story_first": "first event",
        "address_story_last": "last event",
        "address_story_sources": "sources",
        "address_story_hidden": "hidden events",
        "address_story_period": "period",
        "address_story_transactions": "transactions",
        "address_story_counterparties": "counterparties",
        "address_story_activities": "activities",
        "address_story_expand": "Expand history",
        "address_story_collapse": "Collapse history",
        "activity_label": "Activity",
        "observation_label": "Observation",
        "facts_label": "Facts",
        "evidence_label": "Evidence",
        "data_confidence": "Data confidence",
        "insufficient_data": "insufficient data",
        "not_detected": "not detected",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "peak_activity": "Peak activity",
        "first_activity": "First activity",
        "last_activity": "Last activity",
        "active_weekdays": "Active weekdays",
        "active_hours": "Active hours",
        "average_transfer": "Average transfer",
        "median_transfer": "Median transfer",
        "tx_per_day": "Transactions per day",
        "active_days": "Active days",
        "unique_counterparties": "Unique counterparties",
        "asset_count": "Assets",
        "nft_count": "NFT",
        "gift_count": "Gifts",
        "marketplace_interactions": "Marketplace interactions",
        "defi_interactions": "DeFi interactions",
        "dominant_asset": "Dominant asset",
        "heatmap": "Activity heatmap",
        "wallet_migration_observation": "Observation",
        "no_signals": "No high-confidence signals returned by active sources.",
        "assets": "Assets",
        "no_photo": "No photo",
        "no_assets_found": "No assets found",
        "source": "source",
        "open_evidence": "open evidence",
        "identity": "Telegram identity",
        "ens_identity": "ENS",
        "ens_name": "ENS name",
        "reverse_ens": "reverse ENS",
        "reverse_status": "reverse status",
        "resolver": "resolver",
        "owner": "owner",
        "resolved_address": "resolved address",
        "text_records": "text records",
        "no_ens": "No ENS records found.",
        "unavailable": "unavailable",
        "verified": "verified",
        "unverified": "unverified",
        "status": "status",
        "username": "username",
        "domain": "domain",
        "gift": "gift",
        "tx_title": "Transactions",
        "filter_transactions": "Filter transactions",
        "no_tx_filter_results": "No transactions for selected filter",
        "all_tx_types": "All tx types",
        "copied": "copied",
        "copy_hash": "copy hash",
        "copy_address": "copy address",
        "details": "details",
        "balances": "balances",
        "bnb_overview": "BNB overview",
        "contract_intelligence": "Contract intelligence",
        "security_risk": "Risk / security",
        "dex_liquidity": "DEX / liquidity",
        "approvals": "Approvals",
        "top_counterparties": "Top counterparties",
        "warnings": "warnings",
        "gas_fee": "gas fee",
        "method": "method",
        "hash": "hash",
        "from": "from",
        "to": "to",
        "counterparty": "counterparty",
        "service": "service",
        "asset": "asset",
        "ton_wallet": "TON wallet",
        "telegram_entity": "Telegram",
        "nft_entity": "NFT",
        "counterparty_entity": "counterparty",
        "contract_entity": "contract",
        "service_entity": "service",
        "sources": "Sources",
        "no_sources": "No source health records.",
        "type": "type",
        "entity": "entity",
        "chain": "chain",
        "links": "links",
        "evidence": "evidence",
        "open": "open",
        "telegram_project": "Our Telegram project:",
        "isolated_node": "isolated node",
        "path": "path",
        "hops": "hops",
        "sent": "sent",
        "received": "received",
        "self": "self",
        "unknown": "unknown",
        "nft_transfer": "NFT transfer",
        "token_transfer": "token transfer",
        "contract_call": "contract call",
        "trx_transfer": "TRX transfer",
        "trc20_transfer": "TRC20 transfer",
        "usdt_transfer": "USDT transfer",
        "resource_event": "resource event",
        "permission_update": "permission update",
        "defi_interaction": "DeFi interaction",
        "swap": "swap",
        "meme_token_event": "meme token event",
        "failed_transfer": "failed transfer",
        "doge_received": "DOGE received",
        "doge_sent": "DOGE sent",
        "doge_consolidation": "DOGE consolidation",
        "doge_large_transfer": "large DOGE transfer",
        "doge_dust_activity": "DOGE dust activity",
        "transfer": "transfer",
        "external_message": "external message (not a transfer)",
        "username_history": "Telegram username history",
        "ownership_history_unavailable": "Ownership history unavailable",
        "current_owner": "current owner",
        "previous_owners": "previous owners",
        "last_transfer": "last transfer",
        "sale_history": "sale history",
        "gift_tracing": "Gift tracing",
        "gift_route_intelligence": "Gift Route Intelligence",
        "gift_route_hint": "Mini dossiers are built only from real Gift metadata and transfer events.",
        "gift_route": "Gift route",
        "gift_route_stats": "What is known",
        "gift_route_alerts": "Suspicious movements",
        "gift_route_no_alerts": "No calculated flags in the available history.",
        "gift_route_history": "History",
        "gift_route_related": "Related addresses",
        "gift_route_sources": "Sources",
        "gift_route_unavailable": "Route unavailable: sources did not return transfer history.",
        "gift_route_origin": "Origin",
        "gift_route_traits": "Traits",
        "gift_route_show_all": "Show all routes",
        "gift_route_shown": "Shown: {shown} of {total}",
        "sender": "sender",
        "receiver": "receiver",
        "transfer_chain": "transfer chain",
        "jetton_flows": "Jetton flows",
        "net_flow": "net flow",
        "transfer_count": "transfer count",
        "largest_transfer": "largest transfer",
        "recent_transfers": "recent transfers",
        "metadata_unavailable": "metadata unavailable",
        "stablecoin_hint": "stablecoin",
        "view_transactions": "View transactions",
        "hide_transactions": "Hide transactions",
        "transaction_history": "Transaction history",
        "transaction_history_unavailable": "Transaction history unavailable",
        "open_in_tonviewer": "Open in Tonviewer",
        "received_nft": "Received NFT",
        "sent_nft": "Sent NFT",
        "received_ton": "Received TON",
        "sent_ton": "Sent TON",
        "nft_transfer": "NFT transfer",
    },
}


TON_ACTIVITY_TEXT = {
    "ru": {
        "activities": {
            "high": "высокая",
            "medium": "средняя",
            "low": "низкая",
            "not_detected": "не обнаружена",
            "insufficient_data": "данных недостаточно",
        },
        "confidence": {
            "high": "высокая",
            "medium": "средняя",
            "low": "низкая",
        },
        "status": {
            "ok": "данные есть",
            "not_detected": "не обнаружено",
            "insufficient_data": "данных недостаточно",
        },
        "titles": {
            "NFT Username Activity": "Активность NFT-юзернеймов",
            "NFT Rental Activity": "Возможная аренда / краткосрочное удержание NFT-юзернеймов",
            "Username Trading Activity": "Торговля / перепродажа Telegram NFT-юзернеймов",
            "Telegram Gifts Activity": "Активность с Telegram gifts",
            "Gift Distribution Activity": "Массовое получение / передача подарков",
            "Jetton Activity": "Активность по jettons",
            "Marketplace Activity": "Взаимодействия с TON marketplace",
            "Counterparty Diversity": "Разнообразие контрагентов",
            "Transfer Frequency": "Частота переводов",
            "Asset Diversity": "Разнообразие активов",
        },
        "observations": {
            "nft_username_detected": "Зафиксирована активность Telegram NFT-юзернеймов по найденным активам и событиям передачи.",
            "nft_username_not_detected": "Telegram NFT-юзернеймы не обнаружены по собранным данным.",
            "nft_username_insufficient": "Источники не вернули достаточно данных по Telegram NFT-юзернеймам или их истории.",
            "nft_rental_detected": "Зафиксирован паттерн, похожий на краткосрочное удержание NFT-юзернеймов.",
            "nft_rental_not_detected": "Паттерн краткосрочного удержания NFT-юзернеймов не обнаружен.",
            "nft_rental_insufficient": "История transfer events по NFT-юзернеймам недоступна или неполная.",
            "username_trading_detected": "Активность похожа на торговлю NFT-юзернеймами: есть marketplace или transfer факты.",
            "username_trading_not_detected": "Marketplace или transfer факты для торговли NFT-юзернеймами не обнаружены.",
            "username_trading_insufficient": "История username NFT недостаточна для оценки торговой активности.",
            "telegram_gifts_detected": "Зафиксирована активность с Telegram gifts по найденным gift assets и событиям.",
            "telegram_gifts_not_detected": "Telegram gifts не обнаружены по собранным данным.",
            "telegram_gifts_insufficient": "Источники не вернули достаточно данных по Telegram gifts.",
            "gift_distribution_detected": "Зафиксирована массовая активность с Telegram gifts по количеству передач или контрагентов.",
            "gift_distribution_not_detected": "Массовая активность с Telegram gifts не обнаружена.",
            "gift_distribution_insufficient": "Данных по истории Telegram gifts недостаточно для оценки распределения.",
            "jetton_detected": "Зафиксирована активность по jettons на основе балансов и transfer events.",
            "jetton_not_detected": "Jetton activity не обнаружена по собранным данным.",
            "jetton_insufficient": "Источники не вернули достаточно данных по jettons.",
            "marketplace_detected": "Зафиксированы взаимодействия с TON marketplace по labels или event data.",
            "marketplace_not_detected": "TON marketplace activity не обнаружена по labels, events или контрагентам.",
            "marketplace_insufficient": "Данных по marketplace labels или events недостаточно.",
            "counterparty_diversity_detected": "Зафиксировано разнообразие контрагентов по TON transactions и asset events.",
            "counterparty_diversity_not_detected": "Контрагенты не обнаружены по собранным TON данным.",
            "counterparty_diversity_insufficient": "Источники не вернули достаточно данных по TON контрагентам.",
            "transfer_frequency_detected": "Зафиксирована частота TON transfers/events по временной истории кошелька.",
            "transfer_frequency_not_detected": "TON transfers/events не обнаружены по собранным данным.",
            "transfer_frequency_insufficient": "Временная история TON transfers/events недостаточна.",
            "asset_diversity_detected": "Зафиксировано разнообразие TON активов по NFT, gifts, jettons и коллекциям.",
            "asset_diversity_not_detected": "TON активы не обнаружены по собранным данным.",
            "asset_diversity_insufficient": "Источники не вернули достаточно данных по TON активам.",
        },
        "facts": {
            "username_nfts": "NFT-юзернеймов",
            "username_assets": "username assets",
            "incoming_username_nft_transfers": "входящих передач username NFT",
            "outgoing_username_nft_transfers": "исходящих передач username NFT",
            "unique_usernames": "уникальных username",
            "transfer_events": "событий передачи",
            "marketplace_events": "marketplace events",
            "short_holds": "коротких удержаний",
            "average_holding_days": "среднее удержание, дней",
            "median_holding_days": "медианное удержание, дней",
            "received_username_nfts": "получено username NFT",
            "sent_username_nfts": "отправлено username NFT",
            "unique_counterparties": "уникальных контрагентов",
            "short_hold_threshold_days": "порог короткого удержания, дней",
            "purchase_events": "purchase events",
            "sale_events": "sale events",
            "outgoing": "исходящих",
            "incoming": "входящих",
            "marketplaces": "marketplaces",
            "priced_events": "events с ценой",
            "total_gifts": "всего gifts",
            "nft_gifts": "NFT gifts",
            "regular_gifts": "обычные gifts",
            "unique_senders": "уникальных отправителей",
            "unique_receivers": "уникальных получателей",
            "jettons": "jettons",
            "jetton_transfers": "jetton transfers",
            "largest_transfer": "крупнейший transfer",
            "top_counterparties": "топ контрагентов",
            "weak_metadata_jettons": "jettons со слабой metadata",
            "stablecoin_hints": "stablecoin hints",
            "top_marketplace": "основной marketplace",
            "source_labels": "source labels",
            "incoming_counterparties": "входящих контрагентов",
            "outgoing_counterparties": "исходящих контрагентов",
            "repeated_counterparties": "повторяющихся контрагентов",
            "total_events": "всего tx/events",
            "tx_per_day": "tx/events в день",
            "active_days": "активных дней",
            "peak_day": "пиковый день",
            "last_7_days": "активность за 7 дней",
            "last_30_days": "активность за 30 дней",
            "first_activity": "первая активность",
            "last_activity": "последняя активность",
            "most_active_days": "самые активные дни",
            "nft_count": "NFT count",
            "username_nft_count": "username NFT count",
            "gifts_count": "gifts count",
            "jettons_count": "jettons count",
            "unique_collections": "уникальных коллекций",
            "unique_token_types": "уникальных типов активов",
        },
        "evidence": {
            "TonAPI account assets": "TonAPI account assets",
            "TonAPI events": "TonAPI events",
            "Tonviewer history": "Tonviewer history",
            "NFT transfer events": "NFT transfer events",
            "Marketplace events": "marketplace events",
            "Telegram gift assets": "Telegram gift assets",
            "Gift transfer events": "gift transfer events",
            "TonAPI jettons": "TonAPI jettons",
            "Toncenter jetton transfers": "Toncenter jetton transfers",
            "Jetton transfers": "jetton transfers",
            "Marketplace labels": "marketplace labels",
            "TON transactions": "TON transactions",
            "Asset metadata": "asset metadata",
        },
    },
    "en": {
        "activities": {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "not_detected": "not detected",
            "insufficient_data": "insufficient data",
        },
        "confidence": {
            "high": "high",
            "medium": "medium",
            "low": "low",
        },
        "status": {
            "ok": "data available",
            "not_detected": "not detected",
            "insufficient_data": "insufficient data",
        },
        "titles": {
            "NFT Username Activity": "NFT Username Activity",
            "NFT Rental Activity": "NFT Rental Activity",
            "Username Trading Activity": "Username Trading Activity",
            "Telegram Gifts Activity": "Telegram Gifts Activity",
            "Gift Distribution Activity": "Gift Distribution Activity",
            "Jetton Activity": "Jetton Activity",
            "Marketplace Activity": "Marketplace Activity",
            "Counterparty Diversity": "Counterparty Diversity",
            "Transfer Frequency": "Transfer Frequency",
            "Asset Diversity": "Asset Diversity",
        },
        "observations": {
            "nft_username_detected": "Telegram NFT username activity was found from assets and transfer events.",
            "nft_username_not_detected": "Telegram NFT usernames were not detected in the collected data.",
            "nft_username_insufficient": "Sources did not return enough Telegram NFT username or history data.",
            "nft_rental_detected": "A pattern similar to short-term NFT username holding was found.",
            "nft_rental_not_detected": "Short-term NFT username holding was not detected.",
            "nft_rental_insufficient": "NFT username transfer history is unavailable or incomplete.",
            "username_trading_detected": "Activity resembles NFT username trading: marketplace or transfer facts are present.",
            "username_trading_not_detected": "Marketplace or transfer facts for NFT username trading were not detected.",
            "username_trading_insufficient": "Username NFT history is insufficient to assess trading activity.",
            "telegram_gifts_detected": "Telegram gifts activity was found from gift assets and events.",
            "telegram_gifts_not_detected": "Telegram gifts were not detected in the collected data.",
            "telegram_gifts_insufficient": "Sources did not return enough Telegram gifts data.",
            "gift_distribution_detected": "Mass Telegram gifts activity was found from transfer or counterparty counts.",
            "gift_distribution_not_detected": "Mass Telegram gifts activity was not detected.",
            "gift_distribution_insufficient": "Telegram gifts history is insufficient to assess distribution.",
            "jetton_detected": "Jetton activity was found from balances and transfer events.",
            "jetton_not_detected": "Jetton activity was not detected in the collected data.",
            "jetton_insufficient": "Sources did not return enough jetton data.",
            "marketplace_detected": "TON marketplace interactions were found from labels or event data.",
            "marketplace_not_detected": "TON marketplace activity was not detected from labels, events, or counterparties.",
            "marketplace_insufficient": "Marketplace labels or events are insufficient.",
            "counterparty_diversity_detected": "Counterparty diversity was found from TON transactions and asset events.",
            "counterparty_diversity_not_detected": "Counterparties were not detected in the collected TON data.",
            "counterparty_diversity_insufficient": "Sources did not return enough TON counterparty data.",
            "transfer_frequency_detected": "TON transfers/events frequency was found from wallet time history.",
            "transfer_frequency_not_detected": "TON transfers/events were not detected in the collected data.",
            "transfer_frequency_insufficient": "TON transfers/events time history is insufficient.",
            "asset_diversity_detected": "TON asset diversity was found across NFT, gifts, jettons, and collections.",
            "asset_diversity_not_detected": "TON assets were not detected in the collected data.",
            "asset_diversity_insufficient": "Sources did not return enough TON asset data.",
        },
        "facts": {
            "username_nfts": "NFT usernames",
            "username_assets": "username assets",
            "incoming_username_nft_transfers": "incoming username NFT transfers",
            "outgoing_username_nft_transfers": "outgoing username NFT transfers",
            "unique_usernames": "unique usernames",
            "transfer_events": "transfer events",
            "marketplace_events": "marketplace events",
            "short_holds": "short holds",
            "average_holding_days": "average holding, days",
            "median_holding_days": "median holding, days",
            "received_username_nfts": "received username NFTs",
            "sent_username_nfts": "sent username NFTs",
            "unique_counterparties": "unique counterparties",
            "short_hold_threshold_days": "short hold threshold, days",
            "purchase_events": "purchase events",
            "sale_events": "sale events",
            "outgoing": "outgoing",
            "incoming": "incoming",
            "marketplaces": "marketplaces",
            "priced_events": "priced events",
            "total_gifts": "total gifts",
            "nft_gifts": "NFT gifts",
            "regular_gifts": "regular gifts",
            "unique_senders": "unique senders",
            "unique_receivers": "unique receivers",
            "jettons": "jettons",
            "jetton_transfers": "jetton transfers",
            "largest_transfer": "largest transfer",
            "top_counterparties": "top counterparties",
            "weak_metadata_jettons": "jettons with weak metadata",
            "stablecoin_hints": "stablecoin hints",
            "top_marketplace": "top marketplace",
            "source_labels": "source labels",
            "incoming_counterparties": "incoming counterparties",
            "outgoing_counterparties": "outgoing counterparties",
            "repeated_counterparties": "repeated counterparties",
            "total_events": "total tx/events",
            "tx_per_day": "tx/events per day",
            "active_days": "active days",
            "peak_day": "peak day",
            "last_7_days": "last 7 days activity",
            "last_30_days": "last 30 days activity",
            "first_activity": "first activity",
            "last_activity": "last activity",
            "most_active_days": "most active days",
            "nft_count": "NFT count",
            "username_nft_count": "username NFT count",
            "gifts_count": "gifts count",
            "jettons_count": "jettons count",
            "unique_collections": "unique collections",
            "unique_token_types": "unique token types",
        },
        "evidence": {
            "TonAPI account assets": "TonAPI account assets",
            "TonAPI events": "TonAPI events",
            "Tonviewer history": "Tonviewer history",
            "NFT transfer events": "NFT transfer events",
            "Marketplace events": "marketplace events",
            "Telegram gift assets": "Telegram gift assets",
            "Gift transfer events": "gift transfer events",
            "TonAPI jettons": "TonAPI jettons",
            "Toncenter jetton transfers": "Toncenter jetton transfers",
            "Jetton transfers": "jetton transfers",
            "Marketplace labels": "marketplace labels",
            "TON transactions": "TON transactions",
            "Asset metadata": "asset metadata",
        },
    },
}


TRON_ACTIVITY_TEXT = {
    "ru": {
        "activities": {
            "high": "высокая",
            "medium": "средняя",
            "low": "низкая",
            "not_detected": "не обнаружена",
            "insufficient_data": "данных недостаточно",
        },
        "confidence": {"high": "высокая", "medium": "средняя", "low": "низкая"},
        "status": {"ok": "данные доступны", "not_detected": "не обнаружено", "insufficient_data": "данных недостаточно"},
        "titles": {
            "USDT TRC20 Flow Activity": "Активность USDT TRC20 потока",
            "P2P / Exchange Flow Activity": "P2P / exchange-like поток",
            "Resource Usage Activity": "Использование Energy / Bandwidth",
            "Permission Control Activity": "Контроль permissions / multisig",
            "TRON DeFi Activity": "TRON DeFi активность",
            "TRON Memecoin Activity": "SunPump / memecoin активность",
            "Counterparty Intelligence": "Core TRON Counterparties",
            "Stablecoin Status": "Статус stablecoin-переводов",
        },
        "observations": {
            "usdt_trc20_flow_detected": "Зафиксирована активность USDT TRC20 по фактическим transfer events.",
            "usdt_trc20_flow_not_detected": "USDT TRC20 transfers не обнаружены по собранным данным.",
            "usdt_trc20_flow_insufficient": "Источники не вернули достаточно TRC20 данных для анализа USDT.",
            "p2p_exchange_flow_detected": "Активность похожа на обменный / P2P поток по частоте, контрагентам или same-day in/out фактам.",
            "p2p_exchange_flow_not_detected": "Достаточные факты exchange-like / P2P потока не обнаружены.",
            "p2p_exchange_flow_insufficient": "Данных по TRON transfers недостаточно для оценки exchange-like потока.",
            "resource_usage_detected": "Найдены данные по использованию TRON resources и комиссиям.",
            "resource_usage_optimized": "Зафиксированы признаки оптимизации комиссий по resources и TRX fee burn.",
            "resource_usage_not_detected": "Данные по Energy / Bandwidth activity не обнаружены.",
            "resource_usage_insufficient": "Источники не вернули достаточно данных по TRON resources.",
            "permission_control_detected": "Найдены нестандартные permission признаки или permission update activity.",
            "permission_control_normal": "По данным источника отображается обычная permission-конфигурация кошелька.",
            "permission_control_not_detected": "Permission activity не обнаружена.",
            "permission_control_insufficient": "Источник не вернул достаточно данных по owner / active permissions.",
            "tron_defi_detected": "Найдены DeFi-взаимодействия по labels, методам или тексту событий источника.",
            "tron_defi_not_detected": "TRON DeFi activity не обнаружена по собранным labels и событиям.",
            "tron_defi_insufficient": "Данных по TRON transactions недостаточно для оценки DeFi activity.",
            "tron_memecoin_detected": "Найдены SunPump / memecoin факты по labels, token metadata или событиям.",
            "tron_memecoin_not_detected": "SunPump / memecoin activity не обнаружена по собранным данным.",
            "tron_memecoin_insufficient": "Источники не вернули достаточно данных для SunPump / memecoin оценки.",
            "counterparty_intelligence_detected": "Зафиксированы TRON контрагенты и распределение взаимодействий.",
            "counterparty_intelligence_not_detected": "TRON контрагенты не обнаружены по собранным данным.",
            "counterparty_intelligence_insufficient": "Источники не вернули достаточно данных по TRON контрагентам.",
            "stablecoin_status_detected": "Найдены факты failed TRC20 transfers или source labels по stablecoin status.",
            "stablecoin_status_not_detected": "Freeze / blacklist evidence не обнаружено по собранным данным.",
            "stablecoin_status_insufficient": "Данных TRC20 transfer status недостаточно для stablecoin status.",
        },
        "facts": {
            "total_received_usdt": "получено USDT",
            "total_sent_usdt": "отправлено USDT",
            "net_usdt_flow": "net USDT flow",
            "transfer_count": "число transfers",
            "incoming_count": "входящих",
            "outgoing_count": "исходящих",
            "largest_incoming": "крупнейший входящий",
            "largest_outgoing": "крупнейший исходящий",
            "top_usdt_counterparties": "топ USDT контрагентов",
            "first_usdt_activity": "первая USDT активность",
            "last_usdt_activity": "последняя USDT активность",
            "active_days": "активных дней",
            "average_transfer_amount": "средняя сумма transfer",
            "repeated_amounts": "повторяющиеся суммы",
            "repeated_counterparties": "повторяющихся контрагентов",
            "unique_counterparties": "уникальных контрагентов",
            "average_holding_hours": "среднее удержание, часов",
            "same_day_in_out": "same-day in/out",
            "top_exchange_like_addresses": "exchange-like адреса",
            "transfer_velocity": "transfer velocity",
            "energy_usage": "Energy usage",
            "bandwidth_usage": "Bandwidth usage",
            "trx_fee_burn": "TRX fee burn",
            "resource_events": "resource events",
            "resource_delegation_fields": "поля resource delegation",
            "possible_fee_optimization": "признаки оптимизации комиссий",
            "usdt_transfers": "USDT transfers",
            "owner_threshold": "owner threshold",
            "owner_key_count": "owner keys",
            "active_permissions": "active permissions",
            "active_key_count": "active keys",
            "owner_active_diff": "owner != active",
            "multisig": "multisig",
            "custom_active_permissions": "custom active permissions",
            "permission_update_transactions": "permission update tx",
            "defi_contracts": "DeFi contracts",
            "swaps": "swaps",
            "lending_events": "lending events",
            "interaction_count": "interaction count",
            "first_interaction": "first interaction",
            "last_interaction": "last interaction",
            "token_created": "token created",
            "token_bought": "token bought",
            "early_holder": "early holder",
            "liquidity_event": "liquidity event",
            "migration_event": "migration event",
            "holder_concentration": "holder concentration",
            "sunpump_matches": "SunPump matches",
            "incoming_counterparties": "входящих контрагентов",
            "outgoing_counterparties": "исходящих контрагентов",
            "top_by_transfer_count": "top by transfer count",
            "top_by_usdt_volume": "top by USDT volume",
            "top_by_trx_volume": "top by TRX volume",
            "top_by_trc20_tokens": "top by TRC20 tokens",
            "failed_trc20_transfers": "failed TRC20 transfers",
            "freeze_blacklist_events": "freeze / blacklist events",
            "known_blacklist_labels": "blacklist labels",
            "checked_usdt_transfers": "проверено USDT transfers",
        },
        "evidence": {
            "TRC20 transfers": "TRC20 transfers",
            "USDT TRC20 contract": "USDT TRC20 contract",
            "USDT TRC20 transfers": "USDT TRC20 transfers",
            "Explorer labels": "explorer labels",
            "TRON account resources": "TRON account resources",
            "TRON transaction fees": "TRON transaction fees",
            "TRON account permissions": "TRON account permissions",
            "Permission update transactions": "permission update transactions",
            "TRON transactions": "TRON transactions",
            "Token metadata": "token metadata",
            "TRC20 transfer status": "TRC20 transfer status",
        },
    },
    "en": {
        "activities": {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "not_detected": "not detected",
            "insufficient_data": "insufficient data",
        },
        "confidence": {"high": "high", "medium": "medium", "low": "low"},
        "status": {"ok": "data available", "not_detected": "not detected", "insufficient_data": "insufficient data"},
        "titles": {
            "USDT TRC20 Flow Activity": "USDT TRC20 Flow Activity",
            "P2P / Exchange Flow Activity": "P2P / Exchange Flow Activity",
            "Resource Usage Activity": "Resource Usage Activity",
            "Permission Control Activity": "Permission Control Activity",
            "TRON DeFi Activity": "TRON DeFi Activity",
            "TRON Memecoin Activity": "TRON Memecoin Activity",
            "Counterparty Intelligence": "Core TRON Counterparties",
            "Stablecoin Status": "Stablecoin Status",
        },
        "observations": {
            "usdt_trc20_flow_detected": "USDT TRC20 activity was found from transfer events.",
            "usdt_trc20_flow_not_detected": "USDT TRC20 transfers were not detected in the collected data.",
            "usdt_trc20_flow_insufficient": "Sources did not return enough TRC20 data to analyze USDT.",
            "p2p_exchange_flow_detected": "Activity resembles an exchange-like / P2P flow based on frequency, counterparties, or same-day in/out facts.",
            "p2p_exchange_flow_not_detected": "Sufficient exchange-like / P2P flow facts were not detected.",
            "p2p_exchange_flow_insufficient": "TRON transfer data is insufficient to assess exchange-like flow.",
            "resource_usage_detected": "TRON resource and fee usage data was found.",
            "resource_usage_optimized": "Fee optimization signs were found from resources and TRX fee burn.",
            "resource_usage_not_detected": "Energy / Bandwidth activity data was not detected.",
            "resource_usage_insufficient": "Sources did not return enough TRON resource data.",
            "permission_control_detected": "Custom permission signs or permission update activity were found.",
            "permission_control_normal": "The source data shows a standard wallet permission configuration.",
            "permission_control_not_detected": "Permission activity was not detected.",
            "permission_control_insufficient": "The source did not return enough owner / active permission data.",
            "tron_defi_detected": "DeFi interactions were found from labels, methods, or source event text.",
            "tron_defi_not_detected": "TRON DeFi activity was not detected from collected labels and events.",
            "tron_defi_insufficient": "TRON transaction data is insufficient to assess DeFi activity.",
            "tron_memecoin_detected": "SunPump / memecoin facts were found from labels, token metadata, or events.",
            "tron_memecoin_not_detected": "SunPump / memecoin activity was not detected in the collected data.",
            "tron_memecoin_insufficient": "Sources did not return enough data to assess SunPump / memecoin activity.",
            "counterparty_intelligence_detected": "TRON counterparties and interaction distribution were found.",
            "counterparty_intelligence_not_detected": "TRON counterparties were not detected in the collected data.",
            "counterparty_intelligence_insufficient": "Sources did not return enough TRON counterparty data.",
            "stablecoin_status_detected": "Failed TRC20 transfer facts or source labels for stablecoin status were found.",
            "stablecoin_status_not_detected": "Freeze / blacklist evidence was not detected in the collected data.",
            "stablecoin_status_insufficient": "TRC20 transfer status data is insufficient for stablecoin status.",
        },
        "facts": {
            "total_received_usdt": "total received USDT",
            "total_sent_usdt": "total sent USDT",
            "net_usdt_flow": "net USDT flow",
            "transfer_count": "transfer count",
            "incoming_count": "incoming count",
            "outgoing_count": "outgoing count",
            "largest_incoming": "largest incoming",
            "largest_outgoing": "largest outgoing",
            "top_usdt_counterparties": "top USDT counterparties",
            "first_usdt_activity": "first USDT activity",
            "last_usdt_activity": "last USDT activity",
            "active_days": "active days",
            "average_transfer_amount": "average transfer amount",
            "repeated_amounts": "repeated amounts",
            "repeated_counterparties": "repeated counterparties",
            "unique_counterparties": "unique counterparties",
            "average_holding_hours": "average holding, hours",
            "same_day_in_out": "same-day in/out",
            "top_exchange_like_addresses": "top exchange-like addresses",
            "transfer_velocity": "transfer velocity",
            "energy_usage": "Energy usage",
            "bandwidth_usage": "Bandwidth usage",
            "trx_fee_burn": "TRX fee burn",
            "resource_events": "resource events",
            "resource_delegation_fields": "resource delegation fields",
            "possible_fee_optimization": "possible fee optimization",
            "usdt_transfers": "USDT transfers",
            "owner_threshold": "owner threshold",
            "owner_key_count": "owner key count",
            "active_permissions": "active permissions",
            "active_key_count": "active key count",
            "owner_active_diff": "owner != active",
            "multisig": "multisig",
            "custom_active_permissions": "custom active permissions",
            "permission_update_transactions": "permission update transactions",
            "defi_contracts": "DeFi contracts",
            "swaps": "swaps",
            "lending_events": "lending events",
            "interaction_count": "interaction count",
            "first_interaction": "first interaction",
            "last_interaction": "last interaction",
            "token_created": "token created",
            "token_bought": "token bought",
            "early_holder": "early holder",
            "liquidity_event": "liquidity event",
            "migration_event": "migration event",
            "holder_concentration": "holder concentration",
            "sunpump_matches": "SunPump matches",
            "incoming_counterparties": "incoming counterparties",
            "outgoing_counterparties": "outgoing counterparties",
            "top_by_transfer_count": "top by transfer count",
            "top_by_usdt_volume": "top by USDT volume",
            "top_by_trx_volume": "top by TRX volume",
            "top_by_trc20_tokens": "top by TRC20 tokens",
            "failed_trc20_transfers": "failed TRC20 transfers",
            "freeze_blacklist_events": "freeze / blacklist events",
            "known_blacklist_labels": "known blacklist labels",
            "checked_usdt_transfers": "checked USDT transfers",
        },
        "evidence": {
            "TRC20 transfers": "TRC20 transfers",
            "USDT TRC20 contract": "USDT TRC20 contract",
            "USDT TRC20 transfers": "USDT TRC20 transfers",
            "Explorer labels": "explorer labels",
            "TRON account resources": "TRON account resources",
            "TRON transaction fees": "TRON transaction fees",
            "TRON account permissions": "TRON account permissions",
            "Permission update transactions": "permission update transactions",
            "TRON transactions": "TRON transactions",
            "Token metadata": "token metadata",
            "TRC20 transfer status": "TRC20 transfer status",
        },
    },
}


DOGE_ACTIVITY_TEXT = {
    "ru": {
        "activities": {
            "high": "высокая",
            "medium": "средняя",
            "low": "низкая",
            "not_detected": "не обнаружена",
            "insufficient_data": "данных недостаточно",
        },
        "confidence": {"high": "высокая", "medium": "средняя", "low": "низкая"},
        "status": {"ok": "данные доступны", "not_detected": "не обнаружено", "insufficient_data": "данных недостаточно"},
        "titles": {
            "DOGE Balance Summary": "Сводка DOGE balance",
            "UTXO Activity": "UTXO активность",
            "Dust Activity": "Dust активность",
            "Consolidation Activity": "Consolidation активность",
            "Exchange / Deposit Flow": "Exchange / deposit flow",
            "Whale Transfer Activity": "Крупные DOGE переводы",
            "Counterparty Diversity": "Разнообразие контрагентов",
            "Transfer Frequency": "Частота переводов",
        },
        "observations": {
            "doge_balance_summary_detected": "Зафиксирована DOGE активность по balance, totals или transaction facts.",
            "doge_balance_summary_not_detected": "DOGE balance и transactions не обнаружены по собранным данным.",
            "doge_balance_summary_insufficient": "Источники не вернули достаточно DOGE данных для balance summary.",
            "utxo_activity_detected": "Найдены UTXO facts по unspent/spent outputs и transaction inputs/outputs.",
            "utxo_activity_not_detected": "UTXO activity не обнаружена по собранным данным.",
            "utxo_activity_insufficient": "Источники не вернули достаточно UTXO данных.",
            "dust_activity_detected": "Найдены мелкие DOGE outputs или повторяющиеся небольшие суммы.",
            "dust_activity_not_detected": "Dust activity не обнаружена по собранным outputs.",
            "dust_activity_insufficient": "Данных по DOGE outputs недостаточно для dust analysis.",
            "consolidation_activity_detected": "Зафиксированы transactions с большим числом inputs или sweep-паттерном.",
            "consolidation_activity_not_detected": "Consolidation activity не обнаружена.",
            "consolidation_activity_insufficient": "Данных по DOGE inputs недостаточно для consolidation analysis.",
            "exchange_deposit_flow_detected": "Обнаружены факты, похожие на exchange/deposit flow: множество контрагентов, fan-in/fan-out или быстрый outgoing.",
            "exchange_deposit_flow_not_detected": "Достаточные факты exchange/deposit flow не обнаружены.",
            "exchange_deposit_flow_insufficient": "DOGE transaction данных недостаточно для оценки exchange/deposit flow.",
            "whale_transfer_activity_detected": "Найдены крупные DOGE transfers по фактическим суммам.",
            "whale_transfer_activity_not_detected": "Крупные DOGE transfers не обнаружены по собранным данным.",
            "whale_transfer_activity_insufficient": "Данных по DOGE transfer amounts недостаточно.",
            "counterparty_diversity_detected": "Зафиксированы DOGE контрагенты и распределение взаимодействий.",
            "counterparty_diversity_not_detected": "DOGE контрагенты не обнаружены по собранным данным.",
            "counterparty_diversity_insufficient": "Источники не вернули достаточно DOGE counterparty данных.",
            "transfer_frequency_detected": "Найдены DOGE transaction timestamps и active-day факты.",
            "transfer_frequency_not_detected": "DOGE transfer frequency не обнаружена.",
            "transfer_frequency_insufficient": "Источники не вернули достаточно DOGE transaction timestamps.",
        },
        "facts": {
            "balance_doge": "balance DOGE",
            "total_received": "получено DOGE",
            "total_sent": "отправлено DOGE",
            "tx_count": "число tx",
            "first_activity": "первая активность",
            "last_activity": "последняя активность",
            "utxo_count": "UTXO count",
            "spent_outputs": "spent outputs",
            "unspent_outputs": "unspent outputs",
            "dust_outputs": "dust outputs",
            "dust_threshold_doge": "dust threshold DOGE",
            "incoming_dust_outputs": "incoming dust outputs",
            "outgoing_dust_outputs": "outgoing dust outputs",
            "repeated_small_amounts": "повторяющиеся малые суммы",
            "consolidation_tx_count": "consolidation tx count",
            "sweep_pattern_count": "sweep pattern count",
            "max_inputs_in_tx": "max inputs in tx",
            "incoming_counterparties": "входящих контрагентов",
            "outgoing_counterparties": "исходящих контрагентов",
            "quick_outgoing_count": "быстрых outgoing",
            "fan_in_fan_out_tx_count": "fan-in/fan-out tx",
            "source_exchange_labels": "source exchange labels",
            "largest_incoming": "крупнейший входящий",
            "largest_outgoing": "крупнейший исходящий",
            "largest_transfer": "крупнейший transfer",
            "largest_transfer_share": "доля largest transfer",
            "top_tx": "top tx",
            "unique_counterparties": "уникальных контрагентов",
            "repeated_counterparties": "повторяющихся контрагентов",
            "top_counterparties": "топ контрагентов",
            "total_tx": "всего tx",
            "fetched_tx_details": "получено tx details",
            "tx_per_day": "tx per day",
            "active_days": "активных дней",
            "peak_day": "пиковый день",
            "peak_day_tx": "tx в пиковый день",
            "last_7_days": "активность 7 дней",
            "last_30_days": "активность 30 дней",
        },
        "evidence": {
            "Blockchair address dashboard": "Blockchair address dashboard",
            "DOGE balance source": "DOGE balance source",
            "Blockchair UTXO list": "Blockchair UTXO list",
            "DOGE transaction inputs/outputs": "DOGE transaction inputs/outputs",
            "DOGE transaction outputs": "DOGE transaction outputs",
            "Blockchair transaction dashboard": "Blockchair transaction dashboard",
            "DOGE transaction inputs": "DOGE transaction inputs",
            "UTXO spend pattern": "UTXO spend pattern",
            "DOGE transfer timing": "DOGE transfer timing",
            "Source labels": "source labels",
            "Fan-in/fan-out transaction facts": "fan-in/fan-out transaction facts",
            "DOGE transfer amounts": "DOGE transfer amounts",
            "Blockchair address totals": "Blockchair address totals",
            "DOGE transaction counterparties": "DOGE transaction counterparties",
            "UTXO inputs/outputs": "UTXO inputs/outputs",
            "DOGE transaction timestamps": "DOGE transaction timestamps",
        },
    },
    "en": {
        "activities": {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "not_detected": "not detected",
            "insufficient_data": "insufficient data",
        },
        "confidence": {"high": "high", "medium": "medium", "low": "low"},
        "status": {"ok": "data available", "not_detected": "not detected", "insufficient_data": "insufficient data"},
        "titles": {
            "DOGE Balance Summary": "DOGE Balance Summary",
            "UTXO Activity": "UTXO Activity",
            "Dust Activity": "Dust Activity",
            "Consolidation Activity": "Consolidation Activity",
            "Exchange / Deposit Flow": "Exchange / Deposit Flow",
            "Whale Transfer Activity": "Whale Transfer Activity",
            "Counterparty Diversity": "Counterparty Diversity",
            "Transfer Frequency": "Transfer Frequency",
        },
        "observations": {
            "doge_balance_summary_detected": "DOGE activity was found from balance, totals, or transaction facts.",
            "doge_balance_summary_not_detected": "DOGE balance and transactions were not detected in the collected data.",
            "doge_balance_summary_insufficient": "Sources did not return enough DOGE data for the balance summary.",
            "utxo_activity_detected": "UTXO facts were found from unspent/spent outputs and transaction inputs/outputs.",
            "utxo_activity_not_detected": "UTXO activity was not detected in the collected data.",
            "utxo_activity_insufficient": "Sources did not return enough UTXO data.",
            "dust_activity_detected": "Small DOGE outputs or repeated small amounts were found.",
            "dust_activity_not_detected": "Dust activity was not detected from collected outputs.",
            "dust_activity_insufficient": "DOGE output data is insufficient for dust analysis.",
            "consolidation_activity_detected": "Transactions with many inputs or a sweep pattern were found.",
            "consolidation_activity_not_detected": "Consolidation activity was not detected.",
            "consolidation_activity_insufficient": "DOGE input data is insufficient for consolidation analysis.",
            "exchange_deposit_flow_detected": "Exchange/deposit-like facts were found: multiple counterparties, fan-in/fan-out, or quick outgoing flow.",
            "exchange_deposit_flow_not_detected": "Sufficient exchange/deposit flow facts were not detected.",
            "exchange_deposit_flow_insufficient": "DOGE transaction data is insufficient to assess exchange/deposit flow.",
            "whale_transfer_activity_detected": "Large DOGE transfers were found from factual amounts.",
            "whale_transfer_activity_not_detected": "Large DOGE transfers were not detected in the collected data.",
            "whale_transfer_activity_insufficient": "DOGE transfer amount data is insufficient.",
            "counterparty_diversity_detected": "DOGE counterparties and interaction distribution were found.",
            "counterparty_diversity_not_detected": "DOGE counterparties were not detected in the collected data.",
            "counterparty_diversity_insufficient": "Sources did not return enough DOGE counterparty data.",
            "transfer_frequency_detected": "DOGE transaction timestamps and active-day facts were found.",
            "transfer_frequency_not_detected": "DOGE transfer frequency was not detected.",
            "transfer_frequency_insufficient": "Sources did not return enough DOGE transaction timestamps.",
        },
        "facts": {
            "balance_doge": "balance DOGE",
            "total_received": "total received DOGE",
            "total_sent": "total sent DOGE",
            "tx_count": "tx count",
            "first_activity": "first activity",
            "last_activity": "last activity",
            "utxo_count": "UTXO count",
            "spent_outputs": "spent outputs",
            "unspent_outputs": "unspent outputs",
            "dust_outputs": "dust outputs",
            "dust_threshold_doge": "dust threshold DOGE",
            "incoming_dust_outputs": "incoming dust outputs",
            "outgoing_dust_outputs": "outgoing dust outputs",
            "repeated_small_amounts": "repeated small amounts",
            "consolidation_tx_count": "consolidation tx count",
            "sweep_pattern_count": "sweep pattern count",
            "max_inputs_in_tx": "max inputs in tx",
            "incoming_counterparties": "incoming counterparties",
            "outgoing_counterparties": "outgoing counterparties",
            "quick_outgoing_count": "quick outgoing count",
            "fan_in_fan_out_tx_count": "fan-in/fan-out tx count",
            "source_exchange_labels": "source exchange labels",
            "largest_incoming": "largest incoming",
            "largest_outgoing": "largest outgoing",
            "largest_transfer": "largest transfer",
            "largest_transfer_share": "largest transfer share",
            "top_tx": "top tx",
            "unique_counterparties": "unique counterparties",
            "repeated_counterparties": "repeated counterparties",
            "top_counterparties": "top counterparties",
            "total_tx": "total tx",
            "fetched_tx_details": "fetched tx details",
            "tx_per_day": "tx per day",
            "active_days": "active days",
            "peak_day": "peak day",
            "peak_day_tx": "peak day tx",
            "last_7_days": "last 7 days",
            "last_30_days": "last 30 days",
        },
        "evidence": {
            "Blockchair address dashboard": "Blockchair address dashboard",
            "DOGE balance source": "DOGE balance source",
            "Blockchair UTXO list": "Blockchair UTXO list",
            "DOGE transaction inputs/outputs": "DOGE transaction inputs/outputs",
            "DOGE transaction outputs": "DOGE transaction outputs",
            "Blockchair transaction dashboard": "Blockchair transaction dashboard",
            "DOGE transaction inputs": "DOGE transaction inputs",
            "UTXO spend pattern": "UTXO spend pattern",
            "DOGE transfer timing": "DOGE transfer timing",
            "Source labels": "source labels",
            "Fan-in/fan-out transaction facts": "fan-in/fan-out transaction facts",
            "DOGE transfer amounts": "DOGE transfer amounts",
            "Blockchair address totals": "Blockchair address totals",
            "DOGE transaction counterparties": "DOGE transaction counterparties",
            "UTXO inputs/outputs": "UTXO inputs/outputs",
            "DOGE transaction timestamps": "DOGE transaction timestamps",
        },
    },
}


def _background_config(output_dir: Path) -> dict:
    config = dict(BACKGROUND_DEFAULTS)
    for path in (Path(__file__).with_name("report_background.json"), output_dir / "report_background.json"):
        if not path.exists():
            continue
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(loaded, dict):
            config.update({key: loaded[key] for key in config.keys() & loaded.keys()})
    fon_media = _fon_media(output_dir)
    if fon_media["url"]:
        config.update({"overlay_opacity": 0.78, "blur": 0, "animated": False, "grid_opacity": 0.032})
        if fon_media["type"] == "video":
            config.update({"video": fon_media["url"], "image": ""})
        else:
            config.update({"image": fon_media["url"], "video": ""})
    return config


def _select_media_path(root: Path, mime_map: dict[str, str], preferred: tuple[str, ...]) -> Path | None:
    paths = [path for path in root.iterdir() if path.is_file() and path.suffix.lower() in mime_map]
    if not paths:
        return None
    by_name = {path.name.lower(): path for path in sorted(paths, key=lambda item: item.name.lower())}
    for filename in preferred:
        path = by_name.get(filename)
        if path:
            return path
    return sorted(paths, key=lambda item: item.name.lower())[0]


def _media_type(path: Path) -> str:
    if path.suffix.lower() in VIDEO_EXTENSIONS:
        return "video"
    return "image"


def _copy_media(output_dir: Path, path: Path, folder: str, mime: str) -> str:
    try:
        asset_dir = output_dir / folder
        asset_dir.mkdir(parents=True, exist_ok=True)
        dest = asset_dir / path.name
        if path.resolve() != dest.resolve():
            shutil.copy2(path, dest)
        return f"{folder}/{quote(dest.name)}"
    except OSError:
        pass
    try:
        data = base64.b64encode(path.read_bytes()).decode("ascii")
    except OSError:
        return ""
    return f"data:{mime};base64,{data}"


def _fon_media(output_dir: Path) -> dict:
    project_root = Path(__file__).resolve().parents[2]
    roots = [project_root / "fon", Path.cwd() / "crypto_osint" / "fon", Path.cwd() / "fon"]
    seen = set()
    for root in roots:
        try:
            resolved = root.resolve()
        except OSError:
            resolved = root
        if resolved in seen or not root.is_dir():
            continue
        seen.add(resolved)
        path = _select_media_path(root, FON_MIME, FON_MEDIA_ORDER)
        if not path:
            continue
        url = _copy_media(output_dir, path, "fon", FON_MIME[path.suffix.lower()])
        if url:
            return {"url": url, "type": _media_type(path)}
    return {"url": "", "type": ""}


def _logo_config(output_dir: Path) -> dict:
    media = _logo_media(output_dir)
    return {"image": media["url"] if media["type"] == "image" else "", "video": media["url"] if media["type"] == "video" else ""}


def _logo_media(output_dir: Path) -> dict:
    project_root = Path(__file__).resolve().parents[2]
    roots = [project_root / "logo", Path.cwd() / "crypto_osint" / "logo", Path.cwd() / "logo"]
    seen = set()
    for root in roots:
        try:
            resolved = root.resolve()
        except OSError:
            resolved = root
        if resolved in seen or not root.is_dir():
            continue
        seen.add(resolved)
        path = _select_media_path(root, LOGO_MIME, LOGO_MEDIA_ORDER)
        if not path:
            continue
        url = _copy_media(output_dir, path, "logo", LOGO_MIME[path.suffix.lower()])
        if url:
            return {"url": url, "type": _media_type(path)}
    return {"url": "", "type": ""}


def _graph_icons() -> dict[str, str]:
    icon_dir = Path(__file__).with_name("assets") / "graph-icons"
    icons = {}
    for key, filename in GRAPH_ICON_FILES.items():
        try:
            icons[key] = (icon_dir / filename).read_text(encoding="utf-8").strip()
        except OSError:
            icons[key] = ""
    return icons


def _graph_3d_vendor_js() -> str:
    vendor_dir = Path(__file__).with_name("assets") / "vendor"
    parts = []
    for filename in GRAPH_3D_VENDOR_FILES:
        try:
            parts.append((vendor_dir / filename).read_text(encoding="utf-8").strip())
        except OSError:
            continue
    return "\n".join(parts)


def _telegram_service_presentation_assets() -> dict[str, str]:
    """Load only the isolated local Telegram presentation, without stale caches."""
    directory = Path(__file__).with_name("assets")
    result = {}
    for kind in ("css", "js"):
        path = directory / f"telegram-service-intelligence.{kind}"
        try:
            result[kind] = path.read_text(encoding="utf-8") if path.stat().st_size <= 1_000_000 else ""
        except (OSError, UnicodeError):
            result[kind] = ""
    return result


def _telegram_service_local_logos() -> dict[str, dict]:
    """Embed unchanged, explicitly named local art only in Telegram UI JSON.

    This does not broaden the shared HTML/image sanitizer. The isolated client
    uses these renderer-validated data URLs as img sources, never as SVG markup.
    Unknown or ambiguous filenames and unsupported/unsafe images stay neutral.
    """
    from xml.etree import ElementTree

    directories = {
        "cryptobot": Path(__file__).resolve().parents[2] / "icon_crypto",
        "xrocket": Path(__file__).parent / "assets" / "service-logos",
    }
    limits = {"bytes": 2_000_000, "side": 4096, "pixels": 16_000_000, "frames": 64}
    mimes = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
             ".webp": "image/webp", ".gif": "image/gif", ".svg": "image/svg+xml"}
    result = {key: {"url": "", "file": "", "status": "missing", "sha256": "",
                    "reason": "No uniquely named local logo is available."} for key in ("cryptobot", "xrocket")}

    def dimensions(width, height, frames=1):
        return (0 < width <= limits["side"] and 0 < height <= limits["side"]
                and 0 < frames <= limits["frames"] and width * height * frames <= limits["pixels"])

    def raster_ok(raw, suffix):
        if suffix == ".png":
            if not raw.startswith(b"\x89PNG\r\n\x1a\n") or len(raw) < 33 or raw[12:16] != b"IHDR":
                return False
            width, height = int.from_bytes(raw[16:20], "big"), int.from_bytes(raw[20:24], "big")
            offset, frames, ended = 8, 1, False
            while offset + 12 <= len(raw):
                size = int.from_bytes(raw[offset:offset + 4], "big")
                if offset + size + 12 > len(raw):
                    return False
                tag = raw[offset + 4:offset + 8]
                if tag == b"acTL":
                    if size != 8:
                        return False
                    frames = int.from_bytes(raw[offset + 8:offset + 12], "big")
                if tag == b"IEND":
                    ended = size == 0
                    break
                offset += size + 12
            return ended and dimensions(width, height, frames)
        if suffix in {".jpg", ".jpeg"}:
            if not raw.startswith(b"\xff\xd8"):
                return False
            offset = 2
            while offset + 4 <= len(raw):
                if raw[offset] != 255:
                    return False
                while offset < len(raw) and raw[offset] == 255:
                    offset += 1
                if offset >= len(raw):
                    return False
                marker = raw[offset]
                offset += 1
                if marker in {0x01, 0xD8, *range(0xD0, 0xD8)}:
                    continue
                size = int.from_bytes(raw[offset:offset + 2], "big")
                if size < 2 or offset + size > len(raw):
                    return False
                if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
                    return size >= 8 and dimensions(int.from_bytes(raw[offset + 5:offset + 7], "big"), int.from_bytes(raw[offset + 3:offset + 5], "big"))
                if marker in {0xD9, 0xDA}:
                    return False
                offset += size
            return False
        if suffix == ".webp":
            if len(raw) < 30 or raw[:4] != b"RIFF" or raw[8:12] != b"WEBP" or int.from_bytes(raw[4:8], "little") + 8 != len(raw):
                return False
            offset, canvas, frames = 12, None, 0
            while offset + 8 <= len(raw):
                tag, size = raw[offset:offset + 4], int.from_bytes(raw[offset + 4:offset + 8], "little")
                chunk = raw[offset + 8:offset + 8 + size]
                if len(chunk) != size:
                    return False
                if tag == b"VP8X" and size == 10:
                    canvas = (int.from_bytes(chunk[4:7], "little") + 1, int.from_bytes(chunk[7:10], "little") + 1)
                elif tag == b"VP8 " and size >= 10 and chunk[3:6] == b"\x9d\x01\x2a":
                    canvas = canvas or (int.from_bytes(chunk[6:8], "little") & 0x3FFF, int.from_bytes(chunk[8:10], "little") & 0x3FFF)
                elif tag == b"VP8L" and size >= 5 and chunk[0] == 0x2F:
                    canvas = canvas or (1 + chunk[1] + ((chunk[2] & 63) << 8), 1 + (chunk[2] >> 6) + (chunk[3] << 2) + ((chunk[4] & 15) << 10))
                elif tag == b"ANMF":
                    if size < 16 or canvas is None:
                        return False
                    frame_width, frame_height = int.from_bytes(chunk[6:9], "little") + 1, int.from_bytes(chunk[9:12], "little") + 1
                    if int.from_bytes(chunk[:3], "little") * 2 + frame_width > canvas[0] or int.from_bytes(chunk[3:6], "little") * 2 + frame_height > canvas[1]:
                        return False
                    frames += 1
                offset += 8 + size + (size & 1)
            return canvas is not None and offset == len(raw) and dimensions(*canvas, max(1, frames))
        if suffix == ".gif":
            if len(raw) < 14 or raw[:6] not in {b"GIF87a", b"GIF89a"}:
                return False
            width, height = int.from_bytes(raw[6:8], "little"), int.from_bytes(raw[8:10], "little")
            offset = 13 + (3 * (2 ** ((raw[10] & 7) + 1)) if raw[10] & 128 else 0)
            frames = 0
            while offset < len(raw):
                tag = raw[offset]
                offset += 1
                if tag == 0x3B:
                    return dimensions(width, height, frames)
                if tag == 0x21:
                    offset += 1
                elif tag == 0x2C and offset + 9 <= len(raw):
                    frame_width = int.from_bytes(raw[offset + 4:offset + 6], "little")
                    frame_height = int.from_bytes(raw[offset + 6:offset + 8], "little")
                    if (not dimensions(frame_width, frame_height)
                            or int.from_bytes(raw[offset:offset + 2], "little") + frame_width > width
                            or int.from_bytes(raw[offset + 2:offset + 4], "little") + frame_height > height):
                        return False
                    packed = raw[offset + 8]
                    frames += 1
                    if not dimensions(width, height, frames):
                        return False
                    offset += 9 + (3 * (2 ** ((packed & 7) + 1)) if packed & 128 else 0) + 1
                else:
                    return False
                while offset < len(raw) and raw[offset]:
                    offset += raw[offset] + 1
                offset += 1
            return False
        return False

    def svg_ok(raw):
        try:
            text = raw.decode("utf-8-sig")
            if re.search(r"<!\s*(?:DOCTYPE|ENTITY)|<\?xml-stylesheet", text, re.I):
                return False
            root = ElementTree.fromstring(text)
        except (UnicodeError, ElementTree.ParseError):
            return False
        tags = {"svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon", "defs",
                "linearGradient", "radialGradient", "stop", "clipPath", "mask", "title", "desc"}
        for node in root.iter():
            tag = node.tag.removeprefix("{http://www.w3.org/2000/svg}")
            if tag not in tags or (node is root and tag != "svg"):
                return False
            for attribute, value in node.attrib.items():
                local = attribute.rsplit("}", 1)[-1].lower()
                if local.startswith("on") or local in {"href", "src", "style", "base"} or "\\" in value:
                    return False
                if re.search(r"url\s*\(", value, re.I) and not re.fullmatch(r"url\(\s*#[A-Za-z_][A-Za-z0-9_.:-]*\s*\)", value):
                    return False
        viewbox = root.get("viewBox", "").replace(",", " ").split()
        try:
            width = float(root.get("width", "").removesuffix("px"))
            height = float(root.get("height", "").removesuffix("px"))
        except ValueError:
            try:
                width, height = float(viewbox[2]), float(viewbox[3])
            except (IndexError, ValueError):
                width, height = 300, 150
        return dimensions(width, height)

    for key, record in result.items():
        directory = directories[key]
        try:
            if not directory.is_dir() or directory.is_symlink() or getattr(directory, "is_junction", lambda: False)():
                continue
            paths = list(directory.iterdir())
        except OSError:
            continue
        matches = [path for path in paths if re.sub(r"[\s_-]+", "", path.stem).casefold() == key and path.suffix.lower() in mimes]
        if len(matches) != 1:
            if matches:
                record.update(status="ambiguous", reason="Multiple exact service filenames; no artwork selected.")
            continue
        path = matches[0]
        record["file"] = path.name
        try:
            if path.is_symlink() or not path.is_file() or path.resolve().parent != directory.resolve():
                raise ValueError("Logo must be a regular file inside its mapped service directory.")
            with path.open("rb") as stream:
                raw = stream.read(limits["bytes"] + 1)
            if not raw or len(raw) > limits["bytes"]:
                raise ValueError("Logo exceeds the 2MB bound or is empty.")
            record["sha256"] = hashlib.sha256(raw).hexdigest()
            # The supplied cryptobot.png is JPEG; preserve its original bytes
            # and validate/embed its actual format rather than the extension.
            image_suffix = path.suffix.lower()
            if raw.startswith(b"\xff\xd8\xff"):
                image_suffix = ".jpg"
            elif raw.startswith(b"\x89PNG\r\n\x1a\n"):
                image_suffix = ".png"
            valid = svg_ok(raw) if image_suffix == ".svg" else raster_ok(raw, image_suffix)
            if not valid:
                raise ValueError("Unsafe, malformed or unsupported image, dimensions or frame count.")
            record.update(url=f"data:{mimes[image_suffix]};base64," + base64.b64encode(raw).decode("ascii"),
                          status="available", reason="Unchanged local artwork; renderer-validated offline image.")
        except (OSError, ValueError):
            record.update(status="rejected", reason="Local artwork failed bounded image validation.")
    return result


def _chain_label(chain: str) -> str:
    if chain == "eth":
        return "ethereum"
    if chain == "btc":
        return "bitcoin"
    if chain == "doge":
        return "dogecoin"
    if chain == "bsc":
        return "BNB Chain"
    return chain


def _balance_views(report: AddressReport) -> list[dict]:
    out = []
    for balance in report.balances:
        amount = f"{balance.amount:,.8f}".rstrip("0").rstrip(".")
        out.append(
            {
                "chain": _chain_label(balance.chain),
                "asset": balance.asset,
                "amount": amount,
                "source": balance.source,
                "url": balance.url or "",
            }
        )
    return out[:20]


def _chain_summaries(report: AddressReport) -> list[dict]:
    summaries = []
    for chain in report.detected_chains:
        tx_count = sum(1 for tx in report.transactions if tx.chain == chain)
        balance_count = sum(1 for balance in report.balances if balance.chain == chain)
        token_count = sum(1 for token in report.tokens if token.chain == chain)
        label_count = sum(1 for label in report.labels if label.chain == chain)
        sources = sorted({source for source in report.sources_used if (meta := SOURCE_BY_NAME.get(source)) and chain in meta.chains})
        summaries.append(
            {
                "chain": _chain_label(chain),
                "transactions": tx_count,
                "balances": balance_count,
                "tokens": token_count,
                "labels": label_count,
                "sources": sources,
            }
        )
    return summaries


def _is_ton_jetton_tx(tx: Transaction) -> bool:
    if tx.chain != "ton":
        return False
    asset = str(tx.asset or "").lower()
    raw = tx.raw or {}
    action = str(raw.get("action_type") or raw.get("asset_type") or raw.get("provider") or raw.get("type") or "").lower()
    return asset.startswith("jetton:") or "jetton" in asset or "jetton" in action


def _ton_insights(report: AddressReport) -> dict:
    ton_txs = [tx for tx in report.transactions if tx.chain == "ton"]
    jetton_txs = [tx for tx in ton_txs if _is_ton_jetton_tx(tx)]
    nft_txs = [tx for tx in ton_txs if (tx.asset or "").startswith("NFT:")]
    jettons = [token for token in report.tokens if token.chain == "ton" and token.raw.get("asset_type") == "jetton"]
    nfts = [token for token in report.tokens if token.chain == "ton" and token.raw.get("asset_type") == "nft"]
    recurring = [c for c in report.counterparties if c.chain == "ton" and c.tx_count >= 3][:10]
    large = sorted([tx for tx in ton_txs if tx.amount and tx.amount >= 100], key=lambda tx: tx.amount or 0, reverse=True)[:10]
    services = []
    markers = ("wallet", "telegram", "getgems", "fragment", "ston", "dedust", "tonkeeper", "exchange")
    for label in report.labels:
        low = label.label.lower()
        if label.chain == "ton" and any(marker in low for marker in markers):
            services.append(label)
    return {
        "tx_count": len(ton_txs),
        "jetton_transfers": len(jetton_txs),
        "nft_transfers": len(nft_txs),
        "jettons": len(jettons),
        "nfts": len(nfts),
        "recurring": recurring,
        "large": large,
        "services": services[:10],
    }


def _ton_activity_text(language: str, group: str, key: str, fallback: str = "") -> str:
    values = TON_ACTIVITY_TEXT.get(language, TON_ACTIVITY_TEXT["ru"]).get(group, {})
    return values.get(key, fallback or key)


def _ton_activity_value_pair(group: str, key: str, fallback: str = "") -> dict:
    return {
        "ru": _ton_activity_text("ru", group, key, fallback),
        "en": _ton_activity_text("en", group, key, fallback),
    }


def _ton_activity_fact_value(value: object, presentation=None) -> str:
    if isinstance(value, datetime):
        return _time_text(value)
    if isinstance(value, float):
        return _number_text(value, 4)
    if isinstance(value, list):
        items = []
        for item in value[:8]:
            text = presentation.text(item) if presentation else str(item)
            items.append(_short(text, 10, 6) if len(text) > 24 else text)
        return ", ".join(items) if items else "-"
    return str(value)


def _icon_data_url(name: str) -> str:
    path = Path(__file__).with_name("assets") / "graph-icons" / name
    try:
        data = path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    return "data:image/svg+xml;base64," + base64.b64encode(data.encode("utf-8")).decode("ascii")


def _ton_logo_cover() -> dict:
    return {
        "url": _icon_data_url("ton.svg"),
        "fallback_url": _icon_data_url("ton.svg"),
        "alt": "TON logo",
        "source": "TON logo",
        "fit": "contain",
    }


def _cover_from_url(url: str, alt: str, source: str, fit: str = "cover", fallback_url: str = "") -> dict:
    fallback = fallback_url or _ton_logo_cover()["fallback_url"]
    return {"url": url or fallback, "fallback_url": fallback, "alt": alt or "TON asset", "source": source or "TON", "fit": fit if url else "contain"}


def _asset_cover(asset, source_label: str = "") -> dict | None:
    if not asset:
        return None
    raw = getattr(asset, "raw", {}) or {}
    source_name = getattr(asset, "source", "") or ""
    url = _normalize_asset_image(getattr(asset, "image_url", None), source_name) or _asset_image_url(raw, source_name)
    if not url:
        return None
    title = getattr(asset, "title", None) or getattr(asset, "name", None) or getattr(asset, "asset_id", None) or "TON asset"
    source = source_label or f"{source_name} asset image".strip()
    return _cover_from_url(url, str(title), source, "cover")


def _token_cover(token, source_label: str = "") -> dict | None:
    if not token:
        return None
    raw = getattr(token, "raw", {}) or {}
    source_name = getattr(token, "source", "") or ""
    url = _asset_image_url(raw, source_name)
    if not url:
        return None
    title = getattr(token, "symbol", None) or getattr(token, "name", None) or getattr(token, "contract", None) or "TON jetton"
    source = source_label or f"{getattr(token, 'source', '')} token image".strip()
    return _cover_from_url(url, str(title), source, "contain")


def _first_cover(items: list[dict | None]) -> dict:
    return next((item for item in items if item and item.get("url")), None) or _ton_logo_cover()


def _marketplace_cover(names: list[str], asset_cover: dict | None = None) -> dict:
    fallback = (asset_cover or _ton_logo_cover()).get("url") or _ton_logo_cover()["fallback_url"]
    for name in names:
        url = MARKETPLACE_COVER_IMAGES.get(str(name))
        if url:
            return _cover_from_url(url, f"{name} logo", f"{name} favicon", "contain", fallback)
    return asset_cover or _ton_logo_cover()


def _ton_activity_cover(report: AddressReport, signal) -> dict:
    title = signal.title
    username_assets = [asset for asset in report.ton_assets if asset.type == "username"]
    gift_assets = [asset for asset in report.ton_assets if asset.type == "gift"]
    visible_assets = [asset for asset in report.ton_assets if asset.type in {"username", "gift", "nft", "collectible", "domain"}]
    jetton_tokens = [token for token in report.tokens if token.chain == "ton" and (token.raw or {}).get("asset_type") == "jetton"]
    jetton_tokens.sort(key=lambda item: float(item.amount or 0), reverse=True)
    marketplace_assets = [asset for asset in report.ton_assets if asset.marketplace]
    if title in {"NFT Username Activity", "NFT Rental Activity"}:
        return _first_cover([_asset_cover(asset, "NFT asset image") for asset in username_assets] + [_ton_logo_cover()])
    if title == "Username Trading Activity":
        markets = list((signal.facts or {}).get("marketplaces") or [])
        market_cover = _marketplace_cover(markets) if markets else None
        return _first_cover([market_cover, *[_asset_cover(asset, "Telegram username NFT image") for asset in username_assets], _ton_logo_cover()])
    if title in {"Telegram Gifts Activity", "Gift Distribution Activity"}:
        return _first_cover([_asset_cover(asset, "Telegram Gift image") for asset in gift_assets] + [_ton_logo_cover()])
    if title == "Jetton Activity":
        return _first_cover([_token_cover(token, "largest jetton logo") for token in jetton_tokens] + [_asset_cover(asset, "jetton logo") for asset in report.ton_assets if asset.type == "jetton"] + [_ton_logo_cover()])
    if title == "Marketplace Activity":
        markets = list((signal.facts or {}).get("marketplaces") or [])
        market_asset_cover = _first_cover([_asset_cover(asset, "marketplace asset image") for asset in marketplace_assets]) if marketplace_assets else None
        return _marketplace_cover(markets, market_asset_cover)
    if title in {"Counterparty Diversity", "Transfer Frequency"}:
        return _ton_logo_cover()
    if title == "Asset Diversity":
        by_collection = Counter(asset.collection or asset.type for asset in visible_assets)
        preferred_collection = by_collection.most_common(1)[0][0] if by_collection else ""
        preferred_assets = [asset for asset in visible_assets if (asset.collection or asset.type) == preferred_collection] or visible_assets
        return _first_cover([_asset_cover(asset, "most represented asset image") for asset in preferred_assets] + [_asset_cover(asset, "asset image") for asset in visible_assets] + [_ton_logo_cover()])
    return _ton_logo_cover()


def _ton_activity_signal_views(report: AddressReport, language: str, presentation=None) -> dict:
    if "ton" not in report.detected_chains or not report.ton_activity_intelligence:
        return {"available": False, "signals": []}
    signals = []
    for signal in report.ton_activity_intelligence:
        title = _ton_activity_value_pair("titles", signal.title, signal.title)
        activity = _ton_activity_value_pair("activities", signal.activity, signal.activity)
        confidence = _ton_activity_value_pair("confidence", signal.confidence, signal.confidence)
        status = _ton_activity_value_pair("status", signal.status, signal.status)
        observation_key = str((signal.raw or {}).get("observation_key") or signal.observation or "")
        observation = _ton_activity_value_pair("observations", observation_key, signal.observation)
        facts = []
        for key, value in signal.facts.items():
            label = _ton_activity_value_pair("facts", key, key.replace("_", " "))
            facts.append(
                {
                    "key": key,
                    "label": label[language],
                    "label_ru": label["ru"],
                    "label_en": label["en"],
                    "value": _ton_activity_fact_value(value, presentation),
                    "full_value": presentation.text(value) if presentation else str(value),
                }
            )
        evidence = []
        for value in signal.evidence:
            label = _ton_activity_value_pair("evidence", value, value)
            evidence.append({"label": label[language], "label_ru": label["ru"], "label_en": label["en"]})
        signals.append(
            {
                "title": title[language],
                "title_ru": title["ru"],
                "title_en": title["en"],
                "activity": signal.activity,
                "activity_class": signal.activity.replace("_", "-"),
                "activity_label": activity[language],
                "activity_ru": activity["ru"],
                "activity_en": activity["en"],
                "observation": observation[language],
                "observation_ru": observation["ru"],
                "observation_en": observation["en"],
                "facts": facts,
                "evidence": evidence,
                "sources": signal.source[:8],
                "confidence_label": confidence[language],
                "confidence_ru": confidence["ru"],
                "confidence_en": confidence["en"],
                "status_label": status[language],
                "status_ru": status["ru"],
                "status_en": status["en"],
                "cover": _ton_activity_cover(report, signal),
            }
        )
    return {"available": True, "signals": signals}


def _tron_activity_text(language: str, group: str, key: str, fallback: str = "") -> str:
    values = TRON_ACTIVITY_TEXT.get(language, TRON_ACTIVITY_TEXT["ru"]).get(group, {})
    return values.get(key, fallback or key)


def _tron_activity_value_pair(group: str, key: str, fallback: str = "") -> dict:
    return {
        "ru": _tron_activity_text("ru", group, key, fallback),
        "en": _tron_activity_text("en", group, key, fallback),
    }


def _tron_logo_cover() -> dict:
    fallback = _icon_data_url("tron.svg") or _icon_data_url("server-cog.svg")
    return {
        "url": fallback,
        "fallback_url": fallback,
        "alt": "TRON logo",
        "source": "TRON logo",
        "fit": "contain",
    }


def _tron_cover_from_url(url: str, alt: str, source: str, fit: str = "cover") -> dict:
    fallback = _tron_logo_cover()["fallback_url"]
    return {"url": url or fallback, "fallback_url": fallback, "alt": alt or "TRON asset", "source": source or "TRON", "fit": fit if url else "contain"}


def _tron_token_cover(token, source_label: str = "") -> dict | None:
    if not token:
        return None
    raw = getattr(token, "raw", {}) or {}
    source_name = getattr(token, "source", "") or ""
    url = _asset_image_url(raw, source_name)
    if not url:
        return None
    title = getattr(token, "symbol", None) or getattr(token, "name", None) or getattr(token, "contract", None) or "TRC20 token"
    source = source_label or f"{source_name} token logo".strip()
    return _tron_cover_from_url(url, str(title), source, "contain")


def _tron_activity_cover(report: AddressReport, signal) -> dict:
    title = signal.title
    tron_tokens = [token for token in report.tokens if token.chain == "tron"]
    usdt_tokens = [token for token in tron_tokens if (token.contract or "") == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t" or (token.symbol or "").upper() == "USDT"]
    sorted_tokens = sorted(tron_tokens, key=lambda item: float(item.amount or 0), reverse=True)
    if title == "USDT TRC20 Flow Activity":
        return _first_cover([_tron_token_cover(token, "USDT TRC20 token logo") for token in usdt_tokens] + [_tron_logo_cover()])
    if title in {"P2P / Exchange Flow Activity", "Counterparty Intelligence", "Resource Usage Activity", "Permission Control Activity", "Stablecoin Status"}:
        return _tron_logo_cover()
    if title in {"TRON DeFi Activity", "TRON Memecoin Activity"}:
        return _first_cover([_tron_token_cover(token, "TRC20 token logo") for token in sorted_tokens] + [_tron_logo_cover()])
    return _tron_logo_cover()


def _tron_activity_signal_views(report: AddressReport, language: str) -> dict:
    if "tron" not in report.detected_chains or not report.tron_activity_intelligence:
        return {"available": False, "signals": []}
    signals = []
    for signal in report.tron_activity_intelligence:
        title = _tron_activity_value_pair("titles", signal.title, signal.title)
        activity = _tron_activity_value_pair("activities", signal.activity, signal.activity)
        confidence = _tron_activity_value_pair("confidence", signal.confidence, signal.confidence)
        status = _tron_activity_value_pair("status", signal.status, signal.status)
        observation_key = str((signal.raw or {}).get("observation_key") or signal.observation or "")
        observation = _tron_activity_value_pair("observations", observation_key, signal.observation)
        facts = []
        for key, value in signal.facts.items():
            label = _tron_activity_value_pair("facts", key, key.replace("_", " "))
            facts.append(
                {
                    "key": key,
                    "label": label[language],
                    "label_ru": label["ru"],
                    "label_en": label["en"],
                    "value": _ton_activity_fact_value(value),
                }
            )
        evidence = []
        for value in signal.evidence:
            label = _tron_activity_value_pair("evidence", value, value)
            evidence.append({"label": label[language], "label_ru": label["ru"], "label_en": label["en"]})
        signals.append(
            {
                "title": title[language],
                "title_ru": title["ru"],
                "title_en": title["en"],
                "activity": signal.activity,
                "activity_class": signal.activity.replace("_", "-"),
                "activity_label": activity[language],
                "activity_ru": activity["ru"],
                "activity_en": activity["en"],
                "observation": observation[language],
                "observation_ru": observation["ru"],
                "observation_en": observation["en"],
                "facts": facts,
                "evidence": evidence,
                "sources": signal.source[:8],
                "confidence_label": confidence[language],
                "confidence_ru": confidence["ru"],
                "confidence_en": confidence["en"],
                "status_label": status[language],
                "status_ru": status["ru"],
                "status_en": status["en"],
                "cover": _tron_activity_cover(report, signal),
            }
        )
    return {"available": True, "signals": signals}


def _doge_activity_text(language: str, group: str, key: str, fallback: str = "") -> str:
    values = DOGE_ACTIVITY_TEXT.get(language, DOGE_ACTIVITY_TEXT["ru"]).get(group, {})
    return values.get(key, fallback or key)


def _doge_activity_value_pair(group: str, key: str, fallback: str = "") -> dict:
    return {
        "ru": _doge_activity_text("ru", group, key, fallback),
        "en": _doge_activity_text("en", group, key, fallback),
    }


def _doge_logo_cover() -> dict:
    fallback = _icon_data_url("dogecoin.svg") or _icon_data_url("bitcoin.svg") or _icon_data_url("server-cog.svg")
    return {
        "url": fallback,
        "fallback_url": fallback,
        "alt": "Dogecoin logo",
        "source": "Dogecoin logo",
        "fit": "contain",
    }


def _doge_activity_cover(report: AddressReport, signal) -> dict:
    return _doge_logo_cover()


def _dogecoin_activity_signal_views(report: AddressReport, language: str) -> dict:
    if "doge" not in report.detected_chains or not report.dogecoin_activity_intelligence:
        return {"available": False, "signals": []}
    signals = []
    for signal in report.dogecoin_activity_intelligence:
        title = _doge_activity_value_pair("titles", signal.title, signal.title)
        activity = _doge_activity_value_pair("activities", signal.activity, signal.activity)
        confidence = _doge_activity_value_pair("confidence", signal.confidence, signal.confidence)
        status = _doge_activity_value_pair("status", signal.status, signal.status)
        observation_key = str((signal.raw or {}).get("observation_key") or signal.observation or "")
        observation = _doge_activity_value_pair("observations", observation_key, signal.observation)
        facts = []
        for key, value in signal.facts.items():
            label = _doge_activity_value_pair("facts", key, key.replace("_", " "))
            facts.append(
                {
                    "key": key,
                    "label": label[language],
                    "label_ru": label["ru"],
                    "label_en": label["en"],
                    "value": _ton_activity_fact_value(value),
                }
            )
        evidence = []
        for value in signal.evidence:
            label = _doge_activity_value_pair("evidence", value, value)
            evidence.append({"label": label[language], "label_ru": label["ru"], "label_en": label["en"]})
        signals.append(
            {
                "title": title[language],
                "title_ru": title["ru"],
                "title_en": title["en"],
                "activity": signal.activity,
                "activity_class": signal.activity.replace("_", "-"),
                "activity_label": activity[language],
                "activity_ru": activity["ru"],
                "activity_en": activity["en"],
                "observation": observation[language],
                "observation_ru": observation["ru"],
                "observation_en": observation["en"],
                "facts": facts,
                "evidence": evidence,
                "sources": signal.source[:8],
                "confidence_label": confidence[language],
                "confidence_ru": confidence["ru"],
                "confidence_en": confidence["en"],
                "status_label": status[language],
                "status_ru": status["ru"],
                "status_en": status["en"],
                "cover": _doge_activity_cover(report, signal),
            }
        )
    return {"available": True, "signals": signals}


WEEKDAY_TEXT = {
    "ru": ["Понедельник", "Вторник", "Среда", "Четверг", "Пятница", "Суббота", "Воскресенье"],
    "en": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"],
}

MIGRATION_FACT_LABELS = {
    "ru": {
        "transferred_nft": "переведено NFT",
        "transferred_gifts": "переведено подарков",
        "transferred_jettons": "переведено jettons",
        "transferred_value": "переведено TON/TRX/ETH и т.д.",
        "asset_count": "число активов",
        "counterparties": "число контрагентов",
        "migration_start": "дата начала миграции",
        "last_activity": "дата последней активности",
        "activity_after_output": "активность после вывода",
        "destination_candidate": "адрес назначения",
        "transactions": "транзакций",
        "asset_events": "asset events",
    },
    "en": {
        "transferred_nft": "transferred NFT",
        "transferred_gifts": "transferred gifts",
        "transferred_jettons": "transferred jettons",
        "transferred_value": "transferred TON/TRX/ETH etc.",
        "asset_count": "asset count",
        "counterparties": "counterparties",
        "migration_start": "migration start",
        "last_activity": "last activity",
        "activity_after_output": "activity after output",
        "destination_candidate": "destination address",
        "transactions": "transactions",
        "asset_events": "asset events",
    },
}

MIGRATION_OBSERVATIONS = {
    "ru": {
        "insufficient_data": "Данных недостаточно для оценки миграции активов.",
        "not_detected": "Признаки миграции активов не обнаружены по собранным данным.",
    },
    "en": {
        "insufficient_data": "Insufficient data to evaluate asset migration.",
        "not_detected": "Asset migration indicators were not detected in collected data.",
    },
}


def _level_label(level: str, language: str) -> str:
    return I18N[language].get(level, level.replace("_", " "))


def _migration_observation(signal, language: str) -> str:
    if signal.status == "insufficient_data":
        return MIGRATION_OBSERVATIONS[language]["insufficient_data"]
    if signal.status == "not_detected":
        return MIGRATION_OBSERVATIONS[language]["not_detected"]
    if language == "en":
        if signal.activity == "high":
            return "Asset migration indicators were recorded: clustered asset outflow, repeated destination, and limited activity after the outflow."
        if signal.activity == "medium":
            return "Several asset migration indicators were recorded from outgoing transfers and a repeated destination address."
        return "Outgoing transfers exist, but collected facts are not enough to identify a mass asset migration pattern."
    return signal.observation


def _wallet_migration_view(report: AddressReport, language: str, presentation=None) -> dict:
    signal = report.wallet_migration
    if not signal:
        return {"available": False}
    labels = MIGRATION_FACT_LABELS[language]
    facts = []
    for key, value in (signal.facts or {}).items():
        facts.append({"label": labels.get(key, key.replace("_", " ")), "value": _ton_activity_fact_value(value, presentation), "full_value": presentation.text(value) if presentation else str(value)})
    return {
        "available": True,
        "title": I18N[language]["wallet_migration_activity"],
        "activity": _level_label(signal.activity, language),
        "activity_class": signal.activity.replace("_", "-"),
        "observation": _migration_observation(signal, language),
        "facts": facts,
        "evidence": signal.evidence[:8],
        "sources": signal.source[:8],
        "confidence": _level_label(signal.confidence, language),
        "status": _level_label(signal.status, language),
        "compact_warning": signal.status == "insufficient_data",
    }


def _weekday_text(day: int, language: str) -> str:
    values = WEEKDAY_TEXT[language]
    try:
        return values[int(day) % 7]
    except Exception:
        return str(day)


def _behavioral_fingerprint_view(report: AddressReport, language: str) -> dict:
    fp = report.behavioral_fingerprint
    if not fp:
        return {"available": False}
    weekdays = [_weekday_text(day, language) for day in fp.active_weekdays[:5]]
    active_hours = [f"{int(hour):02d}:00" for hour in fp.active_hours[:8]]
    metrics = [
        {"label": I18N[language]["first_activity"], "value": _time_text(fp.first_activity)},
        {"label": I18N[language]["last_activity"], "value": _time_text(fp.last_activity)},
        {"label": I18N[language]["peak_activity"], "value": fp.peak_activity_window or "-"},
        {"label": I18N[language]["active_weekdays"], "value": ", ".join(weekdays) if weekdays else "-"},
        {"label": I18N[language]["active_hours"], "value": ", ".join(active_hours) if active_hours else "-"},
        {"label": I18N[language]["average_transfer"], "value": _number_text(fp.average_transfer_amount, 4) if fp.average_transfer_amount is not None else "-"},
        {"label": I18N[language]["median_transfer"], "value": _number_text(fp.median_transfer_amount, 4) if fp.median_transfer_amount is not None else "-"},
        {"label": I18N[language]["tx_per_day"], "value": _number_text(fp.tx_per_day, 3) if fp.tx_per_day is not None else "-"},
        {"label": I18N[language]["active_days"], "value": str(fp.active_days)},
        {"label": I18N[language]["unique_counterparties"], "value": str(fp.unique_counterparties)},
        {"label": I18N[language]["asset_count"], "value": str(fp.asset_count)},
        {"label": I18N[language]["nft_count"], "value": str(fp.nft_count)},
        {"label": I18N[language]["gift_count"], "value": str(fp.gift_count)},
        {"label": I18N[language]["marketplace_interactions"], "value": str(fp.marketplace_interactions)},
        {"label": I18N[language]["defi_interactions"], "value": str(fp.defi_interactions)},
        {"label": I18N[language]["dominant_asset"], "value": fp.dominant_asset or "-"},
    ]
    max_count = max([int(item.get("count") or 0) for item in fp.heatmap] or [0])
    heatmap = []
    by_cell = {(int(item.get("weekday") or 0), int(item.get("hour") or 0)): int(item.get("count") or 0) for item in fp.heatmap}
    for day in range(7):
        row = {"label": _weekday_text(day, language)[:3], "cells": []}
        for hour in range(24):
            count = by_cell.get((day, hour), 0)
            intensity = 0 if max_count <= 0 else round(count / max_count, 3)
            row["cells"].append({"hour": hour, "count": count, "intensity": intensity})
        heatmap.append(row)
    return {
        "available": True,
        "title": I18N[language]["behavioral_fingerprint"],
        "status": _level_label(fp.status, language),
        "compact_warning": fp.status == "insufficient_data",
        "metrics": metrics,
        "heatmap": heatmap,
        "sources": fp.source[:8],
    }


def _number_text(value: object, precision: int = 8) -> str:
    # Keep the argument for view compatibility. Source digits must not be
    # rounded to zero or displayed in scientific notation.
    if value is None:
        return ""
    try:
        amount = Decimal(str(value))
        if not amount.is_finite():
            return ""
        result = format(amount, ",f")
        return result.rstrip("0").rstrip(".") if "." in result else result
    except (InvalidOperation, TypeError, ValueError):
        return str(value)


def _clean_username(value: object) -> str:
    text = str(value or "").strip()
    text = text.replace("https://t.me/", "").replace("http://t.me/", "").strip("/")
    return text.lstrip("@")


def _asset_sale_fields(asset) -> dict:
    intelligence = (asset.raw or {}).get("nft_intelligence")
    if intelligence:
        money = intelligence.get("last_confirmed_sale") or {}
        return {"price": str(money.get("amount") or ""), "price_currency": money.get("currency") or "",
                "price_verification": "observed successful sale; see action verification" if money else ""}
    return {"price": _number_text(asset.last_sale_price), "price_currency": "TON", "price_verification": ""}


def _event_views(events: list, limit: int = 8) -> list[dict]:
    ordered = sorted(events, key=lambda event: event.timestamp or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    out = []
    for event in ordered[:limit]:
        price = str(event.price_decimal) if event.price_decimal is not None else _number_text(event.price) if event.price is not None else ""
        out.append(
            {
                "type": event.event_type,
                "time": _time_text(event.timestamp),
                "from": event.from_address or "",
                "from_short": _short(event.from_address),
                "to": event.to_address or "",
                "to_short": _short(event.to_address),
                "price": price,
                "tx_hash": event.tx_hash or "",
                "tx_short": _short(event.tx_hash, 10, 8),
                "source": event.source,
                "marketplace": event.marketplace or "",
                "evidence_url": event.evidence_url or "",
            }
        )
    return out


def _asset_history_events_for_view(asset) -> list:
    events = list(getattr(asset, "history_events", []) or [])
    seen = {event.event_id or (event.event_type, event.tx_hash, event.from_address, event.to_address, event.timestamp, event.price) for event in events}
    for event in list(getattr(asset, "transfer_history", []) or []) + list(getattr(asset, "sale_history", []) or []):
        key = event.event_id or (event.event_type, event.tx_hash, event.from_address, event.to_address, event.timestamp, event.price)
        if key not in seen:
            seen.add(key)
            events.append(event)
    return events


def _username_history(report: AddressReport, language: str) -> dict:
    entries: dict[str, dict] = {}
    empty_text = I18N[language]["ownership_history_unavailable"]
    for asset in report.ton_assets:
        if asset.type != "username":
            continue
        username = _clean_username(asset.title or asset.name or asset.asset_id)
        key = (username or asset.asset_id).lower()
        events = _asset_history_events_for_view(asset)
        last_transfer = max([event.timestamp for event in events if event.timestamp], default=asset.last_seen)
        raw = asset.raw or {}
        entries[key] = {
            "username": username or asset.title or asset.name or asset.asset_id,
            "current_owner": asset.owner_address if asset.ownership_status == "current" and asset.ownership_verified else "",
            "current_owner_short": _short(asset.owner_address) if asset.ownership_status == "current" and asset.ownership_verified else "",
            "previous_owners": [{"value": owner, "short": _short(owner)} for owner in asset.previous_owners[:8] if owner],
            "events": _event_views(events, 8),
            "transfer_count": len([event for event in events if event.event_type not in {"sale", "listing", "marketplace_sale", "marketplace_purchase"}]),
            "sale_count": len([event for event in events if event.event_type in {"sale", "listing", "marketplace_sale", "marketplace_purchase"}]),
            **_asset_sale_fields(asset),
            "marketplace": asset.marketplace or "",
            "source": asset.source,
            "nft_address": asset.asset_id if asset.asset_id != username else "",
            "nft_short": _short(asset.asset_id),
            "collection": asset.collection or "",
            "evidence_url": getattr(asset, "history_evidence_url", None) or raw.get("history_evidence_url") or asset.external_url or asset.evidence_url or "",
            "last_transfer": _time_text(last_transfer),
            "confidence": f"{asset.confidence:.2f}",
            "status": "" if (asset.previous_owners or events) else raw.get("history_status_label") or empty_text,
        }
    for identity in report.telegram_identities:
        if identity.confidence == "unknown" or not identity.username:
            continue
        username = _clean_username(identity.username)
        key = username.lower()
        if key in entries:
            continue
        entries[key] = {
            "username": username,
            "current_owner": "",
            "current_owner_short": "",
            "previous_owners": [],
            "events": [],
            "transfer_count": 0,
            "sale_count": 0,
            "price": "",
            "marketplace": "",
            "source": identity.source,
            "nft_address": (identity.asset_ids or [""])[0],
            "nft_short": _short((identity.asset_ids or [""])[0]),
            "collection": "",
            "evidence_url": identity.evidence_url or "",
            "last_transfer": "",
            "confidence": identity.confidence,
            "status": empty_text,
        }
    return {"entries": sorted(entries.values(), key=lambda item: item["username"].lower())[:40], "empty_text": empty_text}


def _gift_tracing(report: AddressReport, language: str) -> dict:
    entries: dict[str, dict] = {}
    unavailable = I18N[language]["unavailable"]
    for asset in report.ton_assets:
        if asset.type != "gift":
            continue
        events = list(asset.transfer_history or []) + list(asset.sale_history or [])
        ordered = sorted(events, key=lambda event: event.timestamp or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        latest_transfer = next((event for event in ordered if event.from_address or event.to_address), None)
        key = (asset.asset_id or asset.title or asset.name).lower()
        entries[key] = {
            "title": asset.title or asset.name or asset.asset_id,
            "asset_id": asset.asset_id,
            "asset_short": _short(asset.asset_id),
            "image_url": asset.image_url or _asset_image_url(asset.raw or {}, asset.source),
            "current_owner": asset.owner_address if asset.ownership_status == "current" and asset.ownership_verified else "",
            "current_owner_short": _short(asset.owner_address) if asset.ownership_status == "current" and asset.ownership_verified else "",
            "sender": latest_transfer.from_address if latest_transfer else "",
            "sender_short": _short(latest_transfer.from_address) if latest_transfer else unavailable,
            "receiver": latest_transfer.to_address if latest_transfer else "",
            "receiver_short": _short(latest_transfer.to_address) if latest_transfer else unavailable,
            "previous_owners": [{"value": owner, "short": _short(owner)} for owner in asset.previous_owners[:8] if owner],
            "events": _event_views(events, 10),
            "sale_count": len(asset.sale_history or []),
            **_asset_sale_fields(asset),
            "marketplace": asset.marketplace or "",
            "source": asset.source,
            "evidence_url": asset.evidence_url or asset.external_url or "",
            "status": "" if events or asset.previous_owners else unavailable,
        }
    for identity in report.telegram_identities:
        if identity.confidence == "unknown":
            continue
        for gift in identity.gifts:
            key = gift.lower()
            if key in entries:
                continue
            entries[key] = {
                "title": gift,
                "asset_id": "",
                "asset_short": "",
                "image_url": "",
                "current_owner": "",
                "current_owner_short": "",
                "sender": "",
                "sender_short": unavailable,
                "receiver": "",
                "receiver_short": unavailable,
                "previous_owners": [],
                "events": [],
                "sale_count": 0,
                "price": "",
                "marketplace": "",
                "source": identity.source,
                "evidence_url": identity.evidence_url or "",
                "status": unavailable,
            }
    return {"entries": sorted(entries.values(), key=lambda item: item["title"].lower())[:30]}


def _gift_route_labels(language: str) -> dict[str, str]:
    return {
        "ru": {
            "collection": "Коллекция",
            "rarity": "Редкость",
            "current_owner": "Текущий владелец",
            "previous_owners": "Предыдущие владельцы",
            "owner_count": "Количество владельцев",
            "transfer_count": "Передач",
            "first_seen": "Первое появление",
            "last_transfer": "Последняя передача",
            "age": "Возраст",
            "unique_addresses": "Уникальных адресов",
            "longest_holder": "Самый долгий владелец",
            "shortest_holder": "Самый короткий владелец",
            "route_unavailable": "Маршрут недоступен",
            "known_previous_owner": "известный предыдущий владелец",
            "current": "текущий владелец",
            "source_owner": "владелец до передачи",
            "receiver": "получатель",
            "event": "событие",
            "tx": "tx",
            "source": "источник",
            "times": "раз",
            "holding": "удержание",
            "related_count": "участий",
            "unknown": "неизвестно",
            "days": "дн",
            "hours": "ч",
            "minutes": "мин",
            "transfers_24h": "Передан {count} раз за 24 часа",
            "owners_week": "Сменил {count} владельцев за неделю",
            "dominant_holder": "Более 80% рассчитанной истории удержания приходится на один адрес",
            "original_date": "дата",
            "recipient": "получатель",
            "telegram_id": "Telegram ID",
            "model": "Model",
            "backdrop": "Backdrop",
            "symbol": "Symbol",
        },
        "en": {
            "collection": "Collection",
            "rarity": "Rarity",
            "current_owner": "Current owner",
            "previous_owners": "Previous owners",
            "owner_count": "Owner count",
            "transfer_count": "Transfers",
            "first_seen": "First seen",
            "last_transfer": "Last transfer",
            "age": "Age",
            "unique_addresses": "Unique addresses",
            "longest_holder": "Longest holder",
            "shortest_holder": "Shortest holder",
            "route_unavailable": "Route unavailable",
            "known_previous_owner": "known previous owner",
            "current": "current owner",
            "source_owner": "owner before transfer",
            "receiver": "receiver",
            "event": "event",
            "tx": "tx",
            "source": "source",
            "times": "times",
            "holding": "holding",
            "related_count": "mentions",
            "unknown": "unknown",
            "days": "d",
            "hours": "h",
            "minutes": "min",
            "transfers_24h": "Transferred {count} times in 24 hours",
            "owners_week": "Changed {count} owners in one week",
            "dominant_holder": "More than 80% of calculated holding history belongs to one address",
            "original_date": "date",
            "recipient": "recipient",
            "telegram_id": "Telegram ID",
            "model": "Model",
            "backdrop": "Backdrop",
            "symbol": "Symbol",
        },
    }.get(language, {})


def _gift_route_metadata(asset) -> dict:
    raw = asset.raw or {}
    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    content = raw.get("content") if isinstance(raw.get("content"), dict) else {}
    return {**content, **metadata}


def _gift_route_collection(asset) -> dict:
    raw = asset.raw or {}
    collection = raw.get("collection")
    return collection if isinstance(collection, dict) else {}


def _gift_route_is_candidate(asset) -> bool:
    metadata = _gift_route_metadata(asset)
    raw = asset.raw or {}
    text = " ".join(
        str(item or "")
        for item in (
            asset.type,
            asset.title,
            asset.name,
            asset.collection,
            asset.image_url,
            asset.animation_url,
            raw.get("asset_type"),
            metadata.get("name"),
            metadata.get("image"),
            metadata.get("lottie"),
            metadata.get("description"),
            metadata.get("original_details"),
        )
    ).lower()
    return (
        asset.type == "gift"
        or "/gift/" in text
        or "telegram gift" in text
        or "collectible gift" in text
        or "gifted to" in text
        or bool(metadata.get("original_details"))
    )


def _gift_route_dt(value) -> datetime | None:
    dt = _story_datetime(value)
    if dt and dt.tzinfo:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _gift_route_time(value) -> str:
    dt = _gift_route_dt(value)
    if not dt:
        return ""
    if dt.hour == 0 and dt.minute == 0 and dt.second == 0:
        return dt.strftime("%Y-%m-%d")
    return dt.strftime("%Y-%m-%d %H:%M")


def _gift_duration_text(seconds: float | int | None, language: str) -> str:
    if seconds is None or seconds <= 0:
        return ""
    labels = _gift_route_labels(language)
    minutes = int(seconds // 60)
    hours = int(seconds // 3600)
    days = int(seconds // 86400)
    if days >= 1:
        rest_hours = int((seconds % 86400) // 3600)
        return f"{days} {labels['days']}" + (f" {rest_hours} {labels['hours']}" if rest_hours and days < 14 else "")
    if hours >= 1:
        return f"{hours} {labels['hours']}"
    return f"{max(1, minutes)} {labels['minutes']}"


def _gift_route_trait_rows(metadata: dict, language: str) -> tuple[list[dict], str]:
    labels = _gift_route_labels(language)
    traits = []
    rarity = _story_text(metadata.get("rarity") or metadata.get("rank") or metadata.get("rarity_rank"))
    raw_attributes = metadata.get("attributes") if isinstance(metadata.get("attributes"), list) else []
    for item in raw_attributes:
        if not isinstance(item, dict):
            continue
        label = _story_text(item.get("trait_type") or item.get("type") or item.get("name"))
        value = _story_text(item.get("value"))
        if not label or not value:
            continue
        traits.append({"label": labels.get(label.lower(), label), "value": value})
        if not rarity and label.lower() in {"rarity", "rare", "rank", "rarity rank"}:
            rarity = value
    return traits[:8], rarity


def _gift_route_event_label(asset, event, language: str) -> str:
    direction = _asset_event_direction(asset, event)
    return _asset_history_event_label(event, direction, language)


def _gift_route_intelligence(report: AddressReport, language: str) -> dict:
    labels = _gift_route_labels(language)
    unavailable = I18N[language]["unavailable"]
    entries = []
    candidates = [asset for asset in report.ton_assets if _gift_route_is_candidate(asset)]

    for asset in candidates:
        metadata = _gift_route_metadata(asset)
        collection_raw = _gift_route_collection(asset)
        traits, rarity = _gift_route_trait_rows(metadata, language)
        events = sorted(_asset_history_events_for_view(asset), key=lambda event: _gift_route_dt(event.timestamp) or datetime.min)
        transfer_events = [event for event in events if event.from_address or event.to_address]
        integrated_nft = bool((asset.raw or {}).get("nft_intelligence"))
        verified_owner = asset.owner_address if asset.ownership_status == "current" and asset.ownership_verified else ""
        if integrated_nft:
            transfer_events = sorted(asset.transfer_history, key=lambda event: (event.logical_time or -1, event.action_index or 0))
        route_is_continuous = all(left.to_address and left.to_address == right.from_address for left, right in zip(transfer_events, transfer_events[1:]))
        route_steps = []
        address_counts: Counter[str] = Counter()
        holding_starts: dict[str, datetime] = {}
        holding_seconds: Counter[str] = Counter()
        event_times = [_gift_route_dt(event.timestamp) for event in transfer_events if _gift_route_dt(event.timestamp)]

        def add_address(address: str) -> None:
            if address:
                address_counts[address] += 1

        def append_step(address: str, role: str, stamp=None, event=None) -> None:
            if not address:
                return
            add_address(address)
            if route_steps and route_steps[-1]["address"] == address:
                return
            event_label = _gift_route_event_label(asset, event, language) if event else role
            route_steps.append(
                {
                    "address": address,
                    "short": _short(address, 10, 7),
                    "role": role,
                    "time": _gift_route_time(stamp),
                    "event": event_label,
                    "source": getattr(event, "source", "") if event else asset.source,
                    "evidence_url": getattr(event, "evidence_url", "") if event else "",
                    "is_current": bool(verified_owner and address == verified_owner),
                    "is_target": address == report.target_address,
                }
            )

        for event in transfer_events:
            stamp = _gift_route_dt(event.timestamp)
            from_address = event.from_address or ""
            to_address = event.to_address or ""
            if from_address:
                append_step(from_address, labels["source_owner"], None, event)
                if stamp and from_address in holding_starts and stamp > holding_starts[from_address]:
                    holding_seconds[from_address] += (stamp - holding_starts[from_address]).total_seconds()
                    holding_starts.pop(from_address, None)
            if to_address:
                append_step(to_address, labels["receiver"], event.timestamp, event)
                if stamp:
                    holding_starts[to_address] = stamp

        route_status = "event_route" if len(route_steps) >= 2 and transfer_events else ""
        if not route_steps and asset.previous_owners and not integrated_nft:
            for owner in asset.previous_owners:
                append_step(owner, labels["known_previous_owner"])
            append_step(verified_owner, labels["current"])
            route_status = "known_owners" if len(route_steps) >= 2 else ""
        elif verified_owner and (not route_steps or route_steps[-1]["address"] != verified_owner):
            append_step(verified_owner, labels["current"])
        if integrated_nft and not route_is_continuous:
            # The full evidence timeline shows each observed segment and its gap.
            # A compact route must not connect disconnected ownership histories.
            route_steps, route_status = [], ""
            holding_starts.clear()
            holding_seconds.clear()

        for owner in asset.previous_owners:
            add_address(owner)
        add_address(asset.owner_address)
        for event in transfer_events:
            add_address(event.from_address)
            add_address(event.to_address)
            if event.counterparty:
                add_address(event.counterparty)

        known_dates = [dt for dt in (_gift_route_dt(asset.first_seen), _gift_route_dt(asset.last_seen), _gift_route_dt(asset.collected_at)) if dt]
        known_dates.extend(event_times)
        original_details = metadata.get("original_details") if isinstance(metadata.get("original_details"), dict) else {}
        original_date = _gift_route_dt(original_details.get("date")) if original_details else None
        if original_date:
            known_dates.append(original_date)
        first_known = min(known_dates) if known_dates else None
        last_known = max(known_dates) if known_dates else None
        last_transfer_dt = max(event_times) if event_times else None
        if last_known:
            for address, started in list(holding_starts.items()):
                if started and last_known > started:
                    holding_seconds[address] += (last_known - started).total_seconds()

        duration_values = [(address, seconds) for address, seconds in holding_seconds.items() if seconds > 0]
        longest = max(duration_values, key=lambda item: item[1], default=None)
        shortest = min(duration_values, key=lambda item: item[1], default=None)
        age_seconds = (last_known - first_known).total_seconds() if first_known and last_known and last_known >= first_known else None
        owner_count = len([address for address in address_counts if address])
        transfer_count = len(transfer_events)

        alerts = []
        sorted_times = sorted(event_times)
        max_24h = 0
        for index, left in enumerate(sorted_times):
            count = 0
            for right in sorted_times[index:]:
                if (right - left).total_seconds() <= 86400:
                    count += 1
            max_24h = max(max_24h, count)
        if max_24h >= 7:
            alerts.append({"title": labels["transfers_24h"].format(count=max_24h), "detail": f"{labels['transfer_count']}: {transfer_count}"})

        max_week_owners = 0
        for index, left in enumerate(sorted_times):
            owners = set()
            for event in transfer_events:
                stamp = _gift_route_dt(event.timestamp)
                if not stamp or stamp < left or (stamp - left).total_seconds() > 7 * 86400:
                    continue
                if event.from_address:
                    owners.add(event.from_address)
                if event.to_address:
                    owners.add(event.to_address)
            max_week_owners = max(max_week_owners, len(owners))
        if max_week_owners >= 5:
            alerts.append({"title": labels["owners_week"].format(count=max_week_owners), "detail": "7d"})

        total_holding = sum(holding_seconds.values())
        if total_holding > 0:
            dominant_address, dominant_seconds = max(holding_seconds.items(), key=lambda item: item[1])
            share = dominant_seconds / total_holding
            if share >= 0.8:
                alerts.append({"title": labels["dominant_holder"], "detail": f"{_short(dominant_address, 10, 7)} · {round(share * 100)}%"})

        related = []
        for address, count in address_counts.most_common(18):
            related.append(
                {
                    "address": address,
                    "short": _short(address, 10, 7),
                    "count": count,
                    "holding": _gift_duration_text(holding_seconds.get(address), language),
                    "is_current": bool(verified_owner and address == verified_owner),
                    "is_target": address == report.target_address,
                }
            )

        history = []
        for event in events[:16]:
            amount_text, _ = _asset_history_amount(event, event.direction)
            history.append(
                {
                    "time": _gift_route_time(event.timestamp) or unavailable,
                    "label": _gift_route_event_label(asset, event, language),
                    "from": event.from_address or "",
                    "from_short": _short(event.from_address, 10, 7),
                    "to": event.to_address or "",
                    "to_short": _short(event.to_address, 10, 7),
                    "amount": amount_text,
                    "marketplace": event.marketplace or "",
                    "source": event.source,
                    "evidence_url": event.evidence_url or "",
                    "tx_hash": event.tx_hash or "",
                    "tx_short": _short(event.tx_hash, 10, 7),
                }
            )

        origin = []
        if original_date:
            origin.append({"label": labels["original_date"], "value": _gift_route_time(original_date)})
        if original_details:
            if original_details.get("recipient_name"):
                origin.append({"label": labels["recipient"], "value": _story_text(original_details.get("recipient_name"))})
            if original_details.get("recipient_telegram_id"):
                origin.append({"label": labels["telegram_id"], "value": _story_text(original_details.get("recipient_telegram_id"))})

        collection_image = _story_text(
            collection_raw.get("image")
            or collection_raw.get("image_url")
            or collection_raw.get("avatar")
            or collection_raw.get("cover")
        )
        image_url = asset.image_url or _asset_image_url(asset.raw or {}, asset.source) or _story_text(metadata.get("image"))
        evidence_url = getattr(asset, "history_evidence_url", None) or asset.evidence_url or asset.external_url or ""
        sources = list(dict.fromkeys([asset.source] + [event.source for event in events if event.source]))
        stats = [
            {"label": labels["owner_count"], "value": str(owner_count) if owner_count else unavailable},
            {"label": labels["transfer_count"], "value": str(transfer_count)},
            {"label": labels["age"], "value": _gift_duration_text(age_seconds, language) or unavailable},
            {"label": labels["unique_addresses"], "value": str(owner_count) if owner_count else unavailable},
            {"label": labels["longest_holder"], "value": f"{_short(longest[0], 10, 7)} · {_gift_duration_text(longest[1], language)}" if longest else unavailable},
            {"label": labels["shortest_holder"], "value": f"{_short(shortest[0], 10, 7)} · {_gift_duration_text(shortest[1], language)}" if shortest else unavailable},
        ]
        facts = [
            {"label": labels["collection"], "value": asset.collection or unavailable},
            {"label": labels["rarity"], "value": rarity or unavailable},
            {"label": labels["current_owner"], "value": _short(asset.owner_address, 10, 7) if asset.ownership_status == "current" and asset.ownership_verified else unavailable, "title": asset.owner_address if asset.ownership_status == "current" and asset.ownership_verified else ""},
            {"label": labels["previous_owners"], "value": str(len(asset.previous_owners or []))},
            {"label": labels["first_seen"], "value": _gift_route_time(first_known) or unavailable},
            {"label": labels["last_transfer"], "value": _gift_route_time(last_transfer_dt) or unavailable},
        ]

        entries.append(
            {
                "_sort": (transfer_count, owner_count, last_known or datetime.min, asset.title or asset.name or asset.asset_id),
                "asset_id": asset.asset_id,
                "asset_short": _short(asset.asset_id, 10, 7),
                "title": asset.title or asset.name or asset.asset_id,
                "collection": asset.collection or "",
                "rarity": rarity,
                "image_url": image_url,
                "collection_image_url": collection_image,
                "current_owner": asset.owner_address if asset.ownership_status == "current" and asset.ownership_verified else "",
                "current_owner_short": _short(asset.owner_address, 10, 7) if asset.ownership_status == "current" and asset.ownership_verified else "",
                "route_status": route_status,
                "route_available": bool(route_status),
                "route_steps": route_steps[:32],
                "stats": stats,
                "facts": facts,
                "traits": traits,
                "origin": origin,
                "alerts": alerts[:6],
                "history": history,
                "related_addresses": related,
                "sources": sources[:8],
                "evidence_url": evidence_url,
                "external_url": asset.external_url or "",
                "marketplace": asset.marketplace or "",
                "transfer_count": transfer_count,
                "owner_count": owner_count,
            }
        )

    entries.sort(key=lambda item: item["_sort"], reverse=True)
    for entry in entries:
        entry.pop("_sort", None)
    return {
        "entries": entries,
        "total": len(entries),
        "with_routes": sum(1 for entry in entries if entry["route_available"]),
        "with_alerts": sum(1 for entry in entries if entry["alerts"]),
    }


def _jetton_flow_analysis(report: AddressReport, language: str) -> dict:
    token_meta: dict[str, dict] = {}
    lookup: dict[str, str] = {}

    def put_meta(keys: list[str], data: dict) -> str:
        clean_keys = [str(item or "").strip().lower() for item in keys if str(item or "").strip()]
        key = clean_keys[0] if clean_keys else str(len(token_meta))
        current = token_meta.setdefault(key, {"sources": [], "links": []})
        for field, value in data.items():
            if field in {"sources", "links"}:
                current[field] = list(dict.fromkeys(current.get(field, []) + [item for item in value if item]))
            elif value not in (None, "", [], {}) and not current.get(field):
                current[field] = value
        for item in clean_keys:
            lookup[item] = key
        return key

    for token in report.tokens:
        if token.chain != "ton" or (token.raw or {}).get("asset_type") != "jetton":
            continue
        raw = token.raw or {}
        image = _asset_image_url(raw, token.source)
        put_meta(
            [token.contract or "", token.symbol or "", token.name or ""],
            {
                "contract": token.contract or "",
                "symbol": token.symbol or "",
                "name": token.name or "",
                "image_url": image,
                "balance": _number_text(token.amount) if token.amount is not None else "",
                "sources": [token.source],
                "links": [token.url or ""],
                "metadata_available": bool(token.symbol or token.name or token.contract),
                "verification": raw.get("verification") or "",
            },
        )
    for asset in report.ton_assets:
        if asset.type != "jetton":
            continue
        put_meta(
            [asset.asset_id, asset.title or "", asset.name or ""],
            {
                "contract": asset.asset_id,
                "symbol": asset.title or "",
                "name": asset.name or asset.title or "",
                "image_url": asset.image_url or _asset_image_url(asset.raw or {}, asset.source),
                "sources": [asset.source],
                "links": [asset.evidence_url or asset.external_url or ""],
                "metadata_available": bool(asset.title or asset.name or asset.asset_id),
                "verification": (asset.raw or {}).get("verification") or "",
            },
        )

    flows: dict[str, dict] = {}

    def flow_for(tx: Transaction | None, asset_label: str, master: str = "") -> dict:
        candidates = [master, asset_label, asset_label.removeprefix("JETTON:")]
        key = next((lookup[item.strip().lower()] for item in candidates if item and item.strip().lower() in lookup), "")
        if not key:
            key = put_meta(candidates, {"symbol": asset_label.removeprefix("JETTON:"), "contract": master, "sources": [tx.source if tx else ""], "links": [tx.url if tx else ""], "metadata_available": bool(master)})
        meta = token_meta.get(key, {})
        current = flows.setdefault(
            key,
            {
                "name": meta.get("name") or meta.get("symbol") or asset_label.removeprefix("JETTON:") or meta.get("contract") or "JETTON",
                "symbol": meta.get("symbol") or asset_label.removeprefix("JETTON:") or "",
                "contract": meta.get("contract") or master or "",
                "contract_short": _short(meta.get("contract") or master),
                "image_url": meta.get("image_url") or "",
                "balance": meta.get("balance") or "",
                "sources": list(meta.get("sources") or []),
                "links": list(meta.get("links") or []),
                "received": 0.0,
                "sent": 0.0,
                "transfer_count": 0,
                "counterparties": {},
                "largest": None,
                "first_seen_raw": None,
                "last_seen_raw": None,
                "recent": [],
                "metadata_available": bool(meta.get("metadata_available")),
                "verification": meta.get("verification") or "",
            },
        )
        if tx:
            current["sources"] = list(dict.fromkeys(current["sources"] + [tx.source]))
            if tx.url:
                current["links"] = list(dict.fromkeys(current["links"] + [tx.url]))
        return current

    for key, meta in token_meta.items():
        flow_for(None, meta.get("symbol") or meta.get("name") or meta.get("contract") or "JETTON", meta.get("contract") or "")

    for tx in report.transactions:
        if not _is_ton_jetton_tx(tx):
            continue
        raw = tx.raw or {}
        asset_label = str(tx.asset or "JETTON")
        master = str(raw.get("jetton_master") or raw.get("contract") or raw.get("token_contract") or "")
        flow = flow_for(tx, asset_label, master)
        amount = float(tx.amount or 0.0)
        if tx.direction == "in":
            flow["received"] += amount
        elif tx.direction == "out":
            flow["sent"] += amount
        flow["transfer_count"] += 1
        counterparty = tx.from_address if tx.direction == "in" else tx.to_address if tx.direction == "out" else tx.to_address or tx.from_address or ""
        if counterparty:
            cp = flow["counterparties"].setdefault(counterparty, {"address": counterparty, "short": _short(counterparty), "count": 0, "amount": 0.0})
            cp["count"] += 1
            cp["amount"] += amount
        largest = flow["largest"]
        if amount and (largest is None or amount > largest["amount_raw"]):
            flow["largest"] = {"amount_raw": amount, "amount": _number_text(amount), "direction": tx.direction, "hash": tx.tx_hash or "", "hash_short": _short(tx.tx_hash, 10, 8), "url": tx.url or "", "time": _time_text(tx.timestamp)}
        if tx.timestamp:
            flow["first_seen_raw"] = min([item for item in (flow["first_seen_raw"], tx.timestamp) if item])
            flow["last_seen_raw"] = max([item for item in (flow["last_seen_raw"], tx.timestamp) if item])
        if len(flow["recent"]) < 8:
            flow["recent"].append(
                {
                    "amount": _number_text(amount),
                    "direction": tx.direction,
                    "counterparty": counterparty,
                    "counterparty_short": _short(counterparty),
                    "time": _time_text(tx.timestamp),
                    "hash": tx.tx_hash or "",
                    "hash_short": _short(tx.tx_hash, 10, 8),
                    "url": tx.url or "",
                    "source": tx.source,
                }
            )

    entries = []
    for flow in flows.values():
        flow["received_text"] = _number_text(flow["received"])
        flow["sent_text"] = _number_text(flow["sent"])
        flow["net"] = flow["received"] - flow["sent"]
        flow["net_text"] = _number_text(flow["net"])
        flow["top_counterparties"] = sorted(flow["counterparties"].values(), key=lambda item: (item["count"], item["amount"]), reverse=True)[:5]
        for cp in flow["top_counterparties"]:
            cp["amount_text"] = _number_text(cp["amount"])
        flow["first_seen"] = _time_text(flow["first_seen_raw"])
        flow["last_seen"] = _time_text(flow["last_seen_raw"])
        flow["largest_transfer"] = flow["largest"] or {}
        flow["links"] = [item for item in flow["links"] if item][:4]
        flow["sources"] = [item for item in flow["sources"] if item][:4]
        symbol = str(flow.get("symbol") or flow.get("name") or "").upper()
        flow["stablecoin_hint"] = bool(flow["metadata_available"] and symbol in {"USDT", "USD₮", "USDC"})
        flow["metadata_label"] = "" if flow["metadata_available"] else I18N[language]["metadata_unavailable"]
        entries.append(flow)
    entries.sort(key=lambda item: (item["transfer_count"], abs(item["net"]), item["received"] + item["sent"]), reverse=True)
    return {"entries": entries[:12]}


def _tonviewer_asset_url(asset) -> str:
    raw = asset.raw or {}
    url = getattr(asset, "history_evidence_url", None) or raw.get("history_evidence_url") or asset.external_url or asset.evidence_url or ""
    if url and "tonviewer.com" in url and "/transaction/" not in url:
        return url
    return f"https://tonviewer.com/{asset.asset_id}" if asset.asset_id else url


def _asset_event_direction(asset, event) -> str:
    raw = event.raw or {}
    direction = str(raw.get("direction") or getattr(event, "direction", "") or "").lower()
    if direction in {"in", "out", "self"}:
        return direction
    owner = str(asset.owner_address or "").lower()
    if owner and str(event.to_address or "").lower() == owner:
        return "in"
    if owner and str(event.from_address or "").lower() == owner:
        return "out"
    return "unknown"


def _asset_history_event_label(event, direction: str, language: str) -> str:
    raw = event.raw or {}
    label = str(raw.get("event_label") or getattr(event, "title", None) or "")
    if label:
        mapped = {
            "received nft": I18N[language]["received_nft"],
            "sent nft": I18N[language]["sent_nft"],
            "received ton": I18N[language]["received_ton"],
            "sent ton": I18N[language]["sent_ton"],
            "nft transfer": I18N[language]["nft_transfer"],
        }.get(label.lower())
        if mapped:
            return mapped
        return label
    currency = str(raw.get("currency") or event.asset or "").upper()
    if event.event_type == "received_ton":
        return I18N[language]["received_ton"]
    if event.event_type == "sent_ton":
        return I18N[language]["sent_ton"]
    if event.event_type == "received_nft":
        return I18N[language]["received_nft"]
    if event.event_type == "sent_nft":
        return I18N[language]["sent_nft"]
    if "TON" in currency and event.price is not None:
        return I18N[language]["received_ton"] if direction == "in" else I18N[language]["sent_ton"] if direction == "out" else "TON"
    if event.event_type in {"sale", "listing"} and event.price is not None:
        return I18N[language]["sent_nft"] if direction == "out" else I18N[language]["received_nft"] if direction == "in" else I18N[language]["nft_transfer"]
    if direction == "in":
        return I18N[language]["received_nft"]
    if direction == "out":
        return I18N[language]["sent_nft"]
    return I18N[language]["nft_transfer"]


def _asset_history_label_key(event, direction: str) -> str:
    raw = event.raw or {}
    label = str(raw.get("event_label") or getattr(event, "title", None) or "").lower()
    mapped = {
        "received nft": "received_nft",
        "sent nft": "sent_nft",
        "received ton": "received_ton",
        "sent ton": "sent_ton",
        "nft transfer": "nft_transfer",
    }.get(label)
    if mapped:
        return mapped
    if event.event_type in {"received_nft", "sent_nft", "received_ton", "sent_ton"}:
        return event.event_type
    if event.event_type == "transfer" and direction == "unknown":
        return "nft_transfer"
    return ""


def _asset_history_amount(event, direction: str) -> tuple[str, str]:
    raw = event.raw or {}
    if raw.get("nft_intelligence"):
        money = raw.get("money") or {}
        if not money:
            return "", ""
        role = "sale consideration" if raw.get("nft_event_type") == "sale" else "accompanying amount"
        return f"{money.get('amount', 'UNKNOWN')} {money.get('currency', '')} · {role}".strip(), ""
    amount = raw.get("amount")
    if amount in (None, ""):
        amount = getattr(event, "amount", None)
    if amount in (None, ""):
        amount = event.price
    if amount in (None, ""):
        return "", ""
    currency = str(raw.get("currency") or "TON")
    sign = ""
    label = str(raw.get("event_label") or "").lower()
    if "received ton" in label or ("ton" in currency.lower() and direction == "in"):
        sign = "+"
    elif "sent ton" in label or ("ton" in currency.lower() and direction == "out"):
        sign = "-"
    elif event.event_type in {"sale", "listing"}:
        sign = "+" if direction == "out" else "-" if direction == "in" else ""
    value = _number_text(amount)
    css = "plus" if sign == "+" else "minus" if sign == "-" else ""
    return f"{sign} {value} {currency}".strip(), css


def _asset_history_badge(event, direction: str, amount: str, amount_class: str) -> tuple[str, str]:
    if amount:
        return amount, amount_class
    if event.event_type == "received_nft":
        return "+ NFT", "plus"
    if event.event_type == "sent_nft":
        return "NFT", "minus"
    if event.event_type in {"transfer", "sale", "listing", "marketplace_sale", "marketplace_purchase"}:
        return "NFT", ""
    return "", ""


def _asset_history_time_text(value) -> tuple[str, str]:
    if isinstance(value, datetime):
        visible = value.strftime("%Y-%m-%d %H:%M")
        return visible, value.isoformat(sep=" ", timespec="seconds")
    text = str(value or "")
    return text, text


def _asset_history_counterparty_text(event, direction: str, counterparty: str, counterparty_label: str, marketplace: str, language: str) -> tuple[str, str]:
    from_short = _short(event.from_address, 10, 6)
    to_short = _short(event.to_address, 10, 6)
    from_full = event.from_address or ""
    to_full = event.to_address or ""
    label_parts = [item for item in (counterparty_label, marketplace) if item]
    label_suffix = f" · {' · '.join(dict.fromkeys(label_parts))}" if label_parts else ""
    if direction == "in" and counterparty:
        prefix = I18N[language]["from"]
        return f"{prefix} {_short(counterparty, 10, 6)}{label_suffix}", counterparty
    if direction == "out" and counterparty:
        prefix = "to" if language == "en" else "к"
        return f"{prefix} {_short(counterparty, 10, 6)}{label_suffix}", counterparty
    if from_short and to_short:
        return f"{from_short} -> {to_short}{label_suffix}", f"{from_full} -> {to_full}"
    if counterparty:
        return f"{_short(counterparty, 10, 6)}{label_suffix}", counterparty
    if label_suffix:
        return label_suffix.lstrip(" · "), ""
    return "", ""


def _asset_history_rows(asset, language: str, limit: int = 8) -> list[dict]:
    username = _clean_username(asset.title or asset.name or asset.asset_id)
    events = sorted(_asset_history_events_for_view(asset), key=lambda event: (event.logical_time is not None, event.logical_time or 0, event.action_index or 0, _story_sort_dt(event.timestamp) if event.timestamp else datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
    rows = []
    for event in events[:limit]:
        raw = event.raw or {}
        direction = _asset_event_direction(asset, event)
        counterparty = str(raw.get("counterparty") or getattr(event, "counterparty", None) or "")
        if not counterparty:
            counterparty = event.from_address if direction == "in" else event.to_address if direction == "out" else event.to_address or event.from_address or ""
        amount, amount_class = _asset_history_amount(event, direction)
        badge, badge_class = _asset_history_badge(event, direction, amount, amount_class)
        suspicious = str(raw.get("suspicious_label") or getattr(event, "suspicious_label", None) or "")
        time_text, time_title = _asset_history_time_text(event.timestamp)
        marketplace = event.marketplace or raw.get("marketplace") or ""
        counterparty_label = raw.get("counterparty_label") or getattr(event, "counterparty_label", None) or event.marketplace or ""
        counterparty_text, counterparty_title = _asset_history_counterparty_text(event, direction, counterparty, counterparty_label, marketplace, language)
        rows.append(
            {
                "time": time_text,
                "time_title": time_title,
                "event_type": event.event_type,
                "label": _asset_history_event_label(event, direction, language),
                "label_i18n": _asset_history_label_key(event, direction),
                "direction": direction,
                "asset_title": raw.get("asset_title") or getattr(event, "title", None) or asset.title or asset.name or asset.asset_id,
                "username": raw.get("username") or getattr(event, "username", None) or username,
                "nft_address": raw.get("nft_address") or getattr(event, "nft_address", None) or asset.asset_id,
                "counterparty": counterparty,
                "counterparty_short": _short(counterparty),
                "counterparty_label": counterparty_label,
                "counterparty_text": counterparty_text,
                "counterparty_title": counterparty_title,
                "amount": amount,
                "amount_class": amount_class,
                "badge": badge,
                "badge_class": badge_class,
                "currency": raw.get("currency") or getattr(event, "currency", None) or "",
                "tx_hash": event.tx_hash or "",
                "tx_short": _short(event.tx_hash, 10, 8),
                "marketplace": marketplace,
                "suspicious_label": suspicious,
                "evidence_url": event.evidence_url or raw.get("evidence_url") or _tonviewer_asset_url(asset),
                "source": event.source,
            }
        )
    return rows


def _asset_card_view(asset, language: str) -> dict:
    raw = asset.raw or {}
    history_rows = _asset_history_rows(asset, language)
    tonviewer_url = _tonviewer_asset_url(asset)
    history_loaded = asset.type == "username" or bool(history_rows or raw.get("history_source") or raw.get("history_status") or getattr(asset, "history_status", None))
    return {
        "asset_id": asset.asset_id,
        "type": asset.type,
        "name": asset.name,
        "title": asset.title,
        "collection": asset.collection,
        "image_url": asset.image_url or _asset_image_url(raw, asset.source),
        "source": asset.source,
        "marketplace": asset.marketplace,
        "ownership_status": getattr(asset, "ownership_status", "unknown"),
        "ownership_verified": getattr(asset, "ownership_verified", False),
        "owner_address": asset.owner_address,
        "nft_details": raw.get("nft_intelligence") or {},
        "external_url": asset.external_url,
        "sort_time": asset.last_seen or asset.first_seen or datetime.min.replace(tzinfo=timezone.utc),
        "history": {
            "enabled": asset.type == "username" or bool(history_rows or raw.get("nft_intelligence")),
            "total": len(_asset_history_events_for_view(asset)),
            "loaded": history_loaded,
            "rows": history_rows,
            "title": I18N[language]["transaction_history"],
            "empty": I18N[language]["transaction_history_unavailable"],
            "tonviewer_url": tonviewer_url,
            "status": getattr(asset, "history_status", None) or raw.get("history_status") or ("found" if history_rows else "unavailable" if history_loaded else ""),
        },
    }


def _asset_groups(report: AddressReport, language: str) -> dict:
    labels = (
        {
            "username": "Telegram имена",
            "gift": "Gifts",
            "nft": "NFT",
            "domain": "Domains",
            "jetton": "Jettons",
            "collectible": "Collectibles",
        }
        if language == "en"
        else {
            "username": "Telegram usernames",
            "gift": "Подарки",
            "nft": "NFT",
            "domain": "Домены",
            "jetton": "Жетоны",
            "collectible": "Коллекционные активы",
        }
    )
    groups = {key: {"label": label, "assets": []} for key, label in labels.items()}
    for asset in report.ton_assets:
        groups.setdefault(asset.type, {"label": labels.get(asset.type, asset.type), "assets": []})
        groups[asset.type]["assets"].append(_asset_card_view(asset, language))
    for group in groups.values():
        group["assets"].sort(key=lambda item: item.get("sort_time") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return groups


def _token_asset_groups(report: AddressReport, language: str) -> list[dict]:
    labels = {
        "erc20": "ERC-20",
        "erc721": "NFT ERC-721",
        "erc1155": "NFT ERC-1155",
        "trc20": "TRC20",
        "trc721": "TRC721",
        "spl_token": "SPL tokens",
        "solana_nft": "Solana NFT",
        "contract": "Contracts",
        "bep20": "BEP20",
        "bep721": "BSC NFT BEP721",
        "bep1155": "BSC NFT BEP1155",
        "bsc_contract": "BSC contracts",
        "dex_pair": "DEX pairs",
        "token": "Tokens",
    }
    groups: dict[str, dict] = {}
    transfer_counts = Counter()
    for tx in report.transactions:
        if tx.chain != "tron":
            continue
        raw = tx.raw or {}
        if str(raw.get("type") or "").lower() != "trc20_transfer":
            continue
        key = (str(raw.get("contract") or "").lower(), str(tx.asset or "").upper())
        transfer_counts[key] += 1
    for token in report.tokens:
        asset_type = str((token.raw or {}).get("asset_type") or "token")
        if token.chain == "ton" and asset_type in {"jetton", "nft"}:
            continue
        key = asset_type if asset_type in labels else "token"
        groups.setdefault(key, {"label": labels[key], "tokens": []})
        amount = "" if token.amount is None else f"{token.amount:,.8f}".rstrip("0").rstrip(".")
        token_id = str((token.raw or {}).get("token_id") or "")
        raw = token.raw or {}
        token_info = raw.get("token_info") or {}
        decimals = raw.get("decimals") or token_info.get("tokenDecimal") or token_info.get("decimals")
        price = raw.get("price") or token_info.get("price") or token_info.get("priceInUsd") or token_info.get("price_usd")
        token_age = raw.get("token_age") or token_info.get("issue_time") or token_info.get("date_created") or token_info.get("create_time")
        holder_count = raw.get("holder_count") or token_info.get("nrOfTokenHolders") or token_info.get("holder_count") or token_info.get("holders_count")
        verified = raw.get("verified") if raw.get("verified") not in (None, "") else token_info.get("verified") or token_info.get("vip") or token_info.get("isOfficial")
        transfers = transfer_counts[(str(token.contract or "").lower(), str(token.symbol or "").upper())]
        groups[key]["tokens"].append(
            {
                "chain": _chain_label(token.chain),
                "contract": token.contract or "",
                "symbol": token.symbol or "",
                "name": token.name or "",
                "amount": amount,
                "source": token.source,
                "url": token.url or "",
                "asset_type": asset_type,
                "holding_status": getattr(token, "holding_status", "unknown"),
                "token_id": token_id,
                "image_url": _asset_image_url(token.raw or {}, token.source),
                "decimals": "" if decimals in (None, "") else str(decimals),
                "transfers": transfers,
                "price": "" if price in (None, "") else str(price),
                "token_age": "" if token_age in (None, "") else str(token_age),
                "holder_count": "" if holder_count in (None, "") else str(holder_count),
                "verified": "" if verified in (None, "") else str(verified),
            }
        )
    for group in groups.values():
        group["tokens"].sort(key=lambda item: (item["chain"], item["symbol"], item["name"], item["contract"]))
    return [groups[key] for key in sorted(groups)]


def _asset_counts(asset_groups: dict) -> dict:
    return {key: len(group.get("assets", [])) for key, group in asset_groups.items()}


def _asset_total(report: AddressReport) -> int:
    ton_ids = {
        ton_canonical_address(asset.asset_id) or ("asset_id", asset.asset_id or index)
        for index, asset in enumerate(report.ton_assets)
    }
    ton_ids.update(
        ton_canonical_address(token.contract) or ("token_contract", token.contract or index)
        for index, token in enumerate(report.tokens) if token.chain == "ton"
    )
    return len(ton_ids) + sum(token.chain != "ton" for token in report.tokens)


def _source_health_labels(source_health: dict, language: str) -> dict:
    labels = (
        {"ok": "works", "partial": "partial", "empty": "empty", "timeout": "timeout", "error": "error", "experimental": "experimental", "skipped": "skipped", "rate_limited": "limited", "unavailable": "unavailable"}
        if language == "en"
        else {"ok": "работает", "partial": "частично", "empty": "пусто", "timeout": "таймаут", "error": "ошибка", "experimental": "экспериментально", "skipped": "пропущено", "rate_limited": "лимит", "unavailable": "недоступно"}
    )
    return {name: labels.get(item.status, item.status) for name, item in source_health.items()}


def _source_capabilities(source_meta: dict) -> dict:
    labels = {
        "balance": "balance",
        "transactions": "transactions",
        "internal_transactions": "internal transactions",
        "utxo_view": "UTXO",
        "stats": "stats",
        "mempool_status": "mempool status",
        "contract_hints": "contract hints",
        "labels": "labels",
        "tokens": "tokens",
        "bep20_balances": "BEP20 balances",
        "bep20_transfers": "BEP20 transfers",
        "approvals": "approvals",
        "security": "security",
        "dex_liquidity": "DEX liquidity",
        "trc20_balances": "TRC20 balances",
        "trc20_transfers": "TRC20 transfers",
        "spl_tokens": "SPL tokens",
        "token_accounts": "token accounts",
        "signatures": "signatures",
        "account_info": "account info",
        "resources": "resources",
        "token_metadata": "token metadata",
        "nonce": "nonce",
        "ens_reverse_lookup": "ENS reverse lookup",
        "ens_forward_lookup": "ENS forward lookup",
        "resolver": "resolver",
        "text_records": "text records",
        "jettons": "jettons",
        "telegram_usernames": "Telegram usernames",
        "telegram_ids_if_public": "public Telegram IDs",
        "dns_identity": "TON DNS",
        "gift_identity": "gift identity",
        "usernames": "usernames",
        "domains": "domains",
        "gifts": "gifts",
        "marketplace_metadata": "marketplace metadata",
        "explorer_evidence": "explorer evidence",
        "nft_cards": "NFT cards",
        "images": "images",
        "analytics_evidence": "analytics evidence",
        "transactions_decoded": "decoded transactions",
        "blacklist": "blacklist",
        "jetton_transfers": "jetton transfers",
        "nft_items": "NFT",
        "contract_state": "contract state",
        "nft_transfers": "NFT transfers",
    }
    out = {}
    for name, meta in source_meta.items():
        out[name] = ", ".join(labels.get(item, item) for item in (meta.capabilities if meta else ()))
    return out


def _short(value: str | None, head: int = 9, tail: int = 6) -> str:
    text = str(value or "")
    return f"{text[:head]}...{text[-tail:]}" if len(text) > head + tail + 4 else text


def _tx_kind(tx: Transaction) -> str:
    asset = str(tx.asset or "")
    raw = tx.raw or {}
    if tx.chain == "ton" and raw.get("message_index") == "in":
        message_type = ((raw.get("transaction") or {}).get("in_msg") or {}).get("msg_type")
        if message_type and message_type != "int_msg":
            return "external_message"
    action = str(raw.get("action_type") or raw.get("type") or raw.get("provider") or "").lower()
    status = str(raw.get("status") or raw.get("final_result") or "").upper()
    if tx.chain == "doge":
        input_count = int(raw.get("input_count") or len(tx.inputs or []))
        dust_outputs = int(raw.get("dust_output_count") or 0)
        if dust_outputs:
            return "doge_dust_activity"
        if input_count >= 10 and tx.direction in {"out", "self"}:
            return "doge_consolidation"
        try:
            if float(tx.amount or 0) >= 10_000:
                return "doge_large_transfer"
        except (TypeError, ValueError):
            pass
        if tx.direction == "in":
            return "doge_received"
        if tx.direction == "out":
            return "doge_sent"
    if tx.chain == "tron":
        from app.attribution.program_transaction_fingerprints import tron_native_contracts
        native_types={item.get("type") for item in tron_native_contracts(tx) if isinstance(item,dict)}
        raw_text = json.dumps(raw, ensure_ascii=False, default=str).lower() if raw else ""
        tron_event_text = " ".join(str(raw.get(key) or "") for key in ("method", "function_name", "event_type", "contract_type", "provider", "type", "status")).lower()
        if status and status not in {"SUCCESS", "CONFIRMED"}:
            return "failed_transfer"
        if "AccountPermissionUpdateContract" in native_types or action == "permission_update" or str(raw.get("contract_type") or "") == "46" or re.search(r'"(?:account)?permissionupdatecontract"\s*:', raw_text):
            return "permission_update"
        if "sunpump" in raw_text or "memecoin" in raw_text or "meme token" in raw_text:
            return "meme_token_event"
        if "swap" in tron_event_text or "sunswap" in tron_event_text:
            return "swap"
        if any(marker in tron_event_text for marker in ("justlend", "lending", "borrow", "staking", "vote")):
            return "defi_interaction"
        if action == "resource" or native_types & {"DelegateResourceContract","UnDelegateResourceContract"} or str(raw.get("contract_type") or "") in {"57", "58"}:
            return "resource_event"
        if "trc20" in action:
            contract = str(raw.get("contract") or (raw.get("token_info") or {}).get("tokenId") or "").strip()
            if contract == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t" or asset.upper() == "USDT":
                return "usdt_transfer"
            return "trc20_transfer"
        if asset.upper() == "TRX":
            return "trx_transfer"
    if action.startswith("nft_") and raw.get("nft_intelligence"):
        return action
    if "approval" in action:
        return "approval"
    if "swap" in action or "liquidity" in action:
        return "contract_call"
    if asset.startswith("NFT:") or "nft" in action:
        return "nft_transfer"
    if asset.startswith("JETTON:") or "jetton" in action or "trc20" in action or "erc20" in action or "bep20" in action or "spl_transfer" in action or "token_transfer" in action:
        return "token_transfer"
    if "contract" in action or "call" in action or "out_msg" in action:
        return "contract_call"
    return "transfer"


def _service_tag(tx: Transaction, labels_by_address: dict[tuple[str, str], list[str]]) -> str:
    for address in (tx.from_address, tx.to_address):
        if not address:
            continue
        labels = labels_by_address.get((tx.chain, address.lower()), [])
        if labels:
            return labels[0]
    raw = tx.raw or {}
    provider = str(raw.get("provider") or raw.get("action_type") or "")
    service_markers = ("tonapi", "toncenter", "fragment", "getgems", "trongrid", "solana_rpc", "solscan", "etherscan", "ethplorer", "blockchair", "mempool", "bscscan", "goplus", "honeypot", "dexscreener", "pancakeswap")
    for marker in service_markers:
        if marker in provider.lower() or marker in tx.source.lower():
            return marker
    return ""


def _btc_value(value) -> str:
    try:
        return f"{float(value):,.8f}".rstrip("0").rstrip(".")
    except (TypeError, ValueError):
        return ""


def _time_text(value) -> str:
    if isinstance(value, datetime):
        return value.isoformat(sep=" ", timespec="seconds")
    return str(value or "-")


def _utxo_io_summary(items: list[dict], asset: str) -> str:
    parts = []
    for item in items[:3]:
        address = str(item.get("address") or "coinbase")
        label = "target" if item.get("target") else _short(address, 10, 6)
        amount = _btc_value(item.get("value"))
        parts.append(f"{label} {amount} {asset}".strip())
    if len(items) > 3:
        parts.append(f"+{len(items) - 3}")
    return ", ".join(parts)


def _btc_io_summary(items: list[dict]) -> str:
    return _utxo_io_summary(items, "BTC")


def _bitcoin_summary(report: AddressReport) -> dict:
    data = dict(report.bitcoin or {})
    btc_balances = [balance for balance in report.balances if balance.chain == "btc"]
    if not data and not btc_balances and "btc" not in report.detected_chains:
        return {"available": False}
    balance = data.get("balance")
    if balance is None and btc_balances:
        balance = btc_balances[0].amount
    utxos = []
    for item in list(data.get("utxos") or [])[:40]:
        utxos.append(
            {
                "tx_hash": item.get("tx_hash") or item.get("txid") or "",
                "vout": item.get("vout"),
                "value": _btc_value(item.get("value")),
                "confirmations": item.get("confirmations"),
                "status": item.get("status") or "-",
                "url": item.get("url") or "",
                "source": item.get("source") or "",
            }
        )
    links = data.get("explorer_links") or {}
    return {
        "available": True,
        "balance": _btc_value(balance),
        "total_received": _btc_value(data.get("total_received")),
        "total_sent": _btc_value(data.get("total_sent")),
        "tx_count": data.get("tx_count") if data.get("tx_count") is not None else sum(1 for tx in report.transactions if tx.chain == "btc"),
        "first_seen": _time_text(data.get("first_seen")),
        "last_seen": _time_text(data.get("last_seen")),
        "unspent_outputs": data.get("unspent_outputs") if data.get("unspent_outputs") is not None else len(utxos),
        "utxos": utxos,
        "links": [{"label": key, "url": value} for key, value in links.items() if value],
        "warnings": list(dict.fromkeys(list(data.get("warnings") or []) + [item for item in report.warnings if str(item).startswith("bitcoin:")]))[:10],
        "partial": bool(data.get("partial")),
    }


def _dogecoin_summary(report: AddressReport) -> dict:
    data = dict(report.dogecoin or {})
    doge_balances = [balance for balance in report.balances if balance.chain == "doge"]
    if not data and not doge_balances and "doge" not in report.detected_chains:
        return {"available": False}
    balance = data.get("balance")
    if balance is None and doge_balances:
        balance = doge_balances[0].amount
    utxos = []
    for item in list(data.get("utxos") or [])[:40]:
        utxos.append(
            {
                "tx_hash": item.get("tx_hash") or item.get("txid") or "",
                "vout": item.get("vout"),
                "value": _btc_value(item.get("value")),
                "confirmations": item.get("confirmations"),
                "status": item.get("status") or "-",
                "url": item.get("url") or "",
                "source": item.get("source") or "",
            }
        )
    links = data.get("explorer_links") or {}
    return {
        "available": True,
        "balance": _btc_value(balance),
        "total_received": _btc_value(data.get("total_received")),
        "total_sent": _btc_value(data.get("total_sent")),
        "tx_count": data.get("tx_count") if data.get("tx_count") is not None else sum(1 for tx in report.transactions if tx.chain == "doge"),
        "first_seen": _time_text(data.get("first_seen")),
        "last_seen": _time_text(data.get("last_seen")),
        "spent_outputs": data.get("spent_outputs"),
        "unspent_outputs": data.get("unspent_outputs") if data.get("unspent_outputs") is not None else len(utxos),
        "dust_outputs": data.get("dust_outputs"),
        "utxos": utxos,
        "links": [{"label": key, "url": value} for key, value in links.items() if value],
        "warnings": list(dict.fromkeys(list(data.get("warnings") or []) + [item for item in report.warnings if str(item).startswith(("dogecoin:", "blockchair_dogecoin:", "sochain_dogecoin:", "oklink_dogecoin:", "dogechain_explorer:", "dogecoin_core_rpc:"))]))[:10],
        "partial": bool(data.get("partial")),
    }


def _tron_summary(report: AddressReport) -> dict:
    data = dict(report.tron or {})
    if not data and "tron" not in report.detected_chains:
        return {"available": False}
    trx_balance = next((balance for balance in report.balances if balance.chain == "tron" and balance.asset.upper() == "TRX"), None)
    txs = [tx for tx in report.transactions if tx.chain == "tron"]
    tokens = [token for token in report.tokens if token.chain == "tron"]
    usdt = next((token for token in tokens if (token.contract or "") == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t" or (token.symbol or "").upper() == "USDT"), None)
    resources = []
    for key, value in (data.get("resources") or {}).items():
        if value in (None, "", [], {}):
            continue
        text = value
        if isinstance(value, (dict, list)):
            try:
                text = json.dumps(value, ensure_ascii=False, default=str)[:260]
            except Exception:
                text = str(value)[:260]
        resources.append({"key": key, "value": text})
    links = data.get("explorer_links") or {}
    first_seen = data.get("first_seen") or min([tx.timestamp for tx in txs if tx.timestamp], default=None)
    last_seen = data.get("last_seen") or max([tx.timestamp for tx in txs if tx.timestamp], default=None)
    return {
        "available": True,
        "balance": "" if trx_balance is None else f"{trx_balance.amount:,.8f}".rstrip("0").rstrip("."),
        "tx_count": data.get("tx_count") if data.get("tx_count") is not None else len(txs),
        "first_seen": _time_text(first_seen),
        "last_seen": _time_text(last_seen),
        "resources": resources[:16],
        "links": [{"label": key, "url": value} for key, value in links.items() if value],
        "token_count": len(tokens),
        "usdt_balance": "" if usdt is None or usdt.amount is None else f"{usdt.amount:,.8f}".rstrip("0").rstrip("."),
        "warnings": list(dict.fromkeys(list(data.get("warnings") or []) + [item for item in report.warnings if str(item).startswith(("tron:", "tronscan:", "trongrid:"))]))[:10],
        "partial": bool(data.get("partial")),
    }


def _solana_summary(report: AddressReport) -> dict:
    data = dict(report.solana or {})
    if not data and "solana" not in report.detected_chains:
        return {"available": False}
    sol_balance = next((balance for balance in report.balances if balance.chain == "solana" and balance.asset.upper() == "SOL"), None)
    txs = [tx for tx in report.transactions if tx.chain == "solana"]
    tokens = [token for token in report.tokens if token.chain == "solana"]
    account = dict(data.get("account") or {})
    links = data.get("explorer_links") or {}
    first_seen = data.get("first_seen") or min([tx.timestamp for tx in txs if tx.timestamp], default=None)
    last_seen = data.get("last_seen") or max([tx.timestamp for tx in txs if tx.timestamp], default=None)
    account_rows = []
    for key in ("owner_program", "account_type", "executable", "space"):
        value = account.get(key)
        if value not in (None, "", [], {}):
            account_rows.append({"key": key, "value": value})
    return {
        "available": True,
        "balance": "" if sol_balance is None else f"{sol_balance.amount:,.9f}".rstrip("0").rstrip("."),
        "lamports": data.get("lamports"),
        "tx_count": data.get("tx_count") if data.get("tx_count") is not None else len(txs),
        "signature_count": data.get("signature_count") if data.get("signature_count") is not None else len(txs),
        "tx_count_sample": bool(data.get("tx_count_sample")),
        "first_seen": _time_text(first_seen),
        "last_seen": _time_text(last_seen),
        "token_count": len(tokens),
        "spl_token_count": sum(1 for token in tokens if (token.raw or {}).get("asset_type") == "spl_token"),
        "nft_count": sum(1 for token in tokens if (token.raw or {}).get("asset_type") == "solana_nft"),
        "token_accounts": data.get("token_accounts"),
        "account": account_rows,
        "links": [{"label": key, "url": value} for key, value in links.items() if value],
        "warnings": list(dict.fromkeys(list(data.get("warnings") or []) + [item for item in report.warnings if str(item).startswith(("solana:", "solana_rpc:", "solscan_public_api:"))]))[:10],
        "partial": bool(data.get("partial")),
    }


def _bsc_summary(report: AddressReport) -> dict:
    data = dict(report.bsc or {})
    if not data and "bsc" not in report.detected_chains:
        return {"available": False}
    bnb_balance = next((balance for balance in report.balances if balance.chain == "bsc" and balance.asset.upper() == "BNB"), None)
    txs = [tx for tx in report.transactions if tx.chain == "bsc"]
    tokens = [token for token in report.tokens if token.chain == "bsc"]
    risks = [flag for flag in report.risk_flags if flag.chain == "bsc"]
    links = data.get("explorer_links") or {}
    first_seen = data.get("first_seen") or min([tx.timestamp for tx in txs if tx.timestamp], default=None)
    last_seen = data.get("last_seen") or max([tx.timestamp for tx in txs if tx.timestamp], default=None)
    contract = []
    for key in ("is_contract", "code_size", "verified", "contract_name", "token_symbol", "creator", "owner", "holder_count"):
        value = data.get(key)
        if value not in (None, "", [], {}):
            contract.append({"key": key, "value": value})
    sources = [{"key": key, "value": value} for key, value in (data.get("source_status") or {}).items()]
    dex_pairs = []
    seen_pairs = set()
    for item in data.get("dex_pairs") or []:
        pair = item.get("pair_address") or item.get("url") or repr(item)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        dex_pairs.append(
            {
                "dex": item.get("dex") or item.get("source") or "DEX",
                "pair_address": item.get("pair_address") or "",
                "symbol": item.get("symbol") or item.get("name") or "",
                "liquidity_usd": item.get("liquidity_usd"),
                "volume_24h": item.get("volume_24h"),
                "price_usd": item.get("price_usd"),
                "buy_count_24h": item.get("buy_count_24h"),
                "sell_count_24h": item.get("sell_count_24h"),
                "url": item.get("url") or "",
            }
        )
    return {
        "available": True,
        "balance": "" if bnb_balance is None else f"{bnb_balance.amount:,.8f}".rstrip("0").rstrip("."),
        "tx_count": data.get("tx_count") if data.get("tx_count") is not None else len(txs),
        "transactions_sample_count": data.get("transactions_sample_count") if data.get("transactions_sample_count") is not None else len(txs),
        "normal_transactions_count": data.get("normal_transactions_count"),
        "internal_transactions_count": data.get("internal_transactions_count"),
        "bep20_transfers_count": data.get("bep20_transfers_count") if data.get("bep20_transfers_count") is not None else sum(1 for tx in txs if (tx.raw or {}).get("asset_type") == "bep20"),
        "nft_transfers_count": data.get("nft_transfers_count") if data.get("nft_transfers_count") is not None else sum(1 for tx in txs if (tx.raw or {}).get("asset_type") in {"bep721", "bep1155"}),
        "approvals_count": data.get("approvals_count") if data.get("approvals_count") is not None else sum(1 for tx in txs if (tx.raw or {}).get("type") == "approval"),
        "first_seen": _time_text(first_seen),
        "last_seen": _time_text(last_seen),
        "token_count": len(tokens),
        "stablecoins": (data.get("stablecoins") or [])[:12],
        "contract": contract,
        "security": (data.get("security") or [])[:16],
        "risk_count": len(risks),
        "dex_pairs": dex_pairs[:16],
        "approvals": (data.get("approvals") or [])[:20],
        "sources": sources,
        "links": [{"label": key, "url": value} for key, value in links.items() if value],
        "warnings": list(dict.fromkeys(list(data.get("warnings") or []) + [item for item in report.warnings if str(item).startswith(("bsc:", "bscscan_api:", "bsc_intel:", "bsc_rpc:", "bscscan_html:"))]))[:12],
        "partial": bool(data.get("partial")),
    }


@lru_cache(maxsize=1)
def _service_logos() -> dict[str, dict]:
    """Only pinned, bundled official assets can become a service logo."""
    directory = Path(__file__).parent / "assets" / "service-logos"
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    out = {}
    for service_id, asset in manifest.get("assets", {}).items():
        filename = asset.get("file", "")
        if Path(filename).name != filename or asset.get("mime") not in {"image/png", "image/svg+xml"}:
            continue
        content = (directory / filename).read_bytes()
        if hashlib.sha256(content).hexdigest() != asset.get("sha256"):
            continue
        url = f"data:{asset['mime']};base64," + base64.b64encode(content).decode("ascii")
        if safe_image_url(url):
            out[service_id] = {**asset, "url": url}
    return out


def _wallet_application_view(value: dict | None, logos: dict, evidence: dict | None = None) -> dict:
    """Keep signing-application evidence distinct from address/service labels."""
    client = dict(value or {})
    status = str(client.get("status") or "UNKNOWN").upper()
    if status not in {"CONFIRMED", "PROBABLE", "POSSIBLE", "UNKNOWN"}:
        status = "UNKNOWN"
    client["status"] = status
    client["name"] = (client.get("name") or client.get("application_name") or "UNKNOWN") if status != "UNKNOWN" else "UNKNOWN"
    # A service icon or wallet version is never an application observation.
    has_evidence = any(ref in (evidence or {}) for ref in client.get("evidence_ids", []))
    logo = logos.get(client.get("application_id")) if status in {"CONFIRMED", "PROBABLE"} and has_evidence else None
    client["logo"] = logo["url"] if logo else ""
    client["logo_source_url"] = safe_href((logo or {}).get("source_url"))
    client["logo_license"] = (logo or {}).get("license") or "No verified reusable official local asset"
    for field in ("checks", "observations", "rejected_hypotheses", "investigative_leads"):
        client[field] = [{**row, "source_urls": list(dict.fromkeys(url for value in row.get("source_urls", [])
            if (url := safe_href(value))))} for row in client.get(field, []) if isinstance(row, dict)]
    return client


def _artwork_notices(service_views: dict) -> list[dict]:
    used = set()
    for record in service_views.get("addresses", {}).values():
        used.update(claim.get("service_id") for claim in record.get("attributions", []) if claim.get("logo"))
        client = record.get("client_attribution") or {}
        if client.get("logo"):
            used.add(client.get("application_id"))
    directory = Path(__file__).parent / "assets" / "service-logos"
    notices = []
    for key, asset in _service_logos().items():
        if key not in used:
            continue
        notice = {field: asset.get(field) for field in ("name", "source_url", "sha256", "license")}
        filename = asset.get("license_file") or asset.get("guidance_file")
        if filename and Path(filename).name == filename:
            notice["license_text"] = (directory / filename).read_text(encoding="utf-8")
        notices.append(notice)
    return notices


# GANSAR_INFERENTIAL_BEGIN
def _inferential_service_projection(data: dict) -> dict:
    """Keep canonical inference once; neighbor raw reports stay in checkpoints."""
    result = {}
    service = data.get("telegram_service_intelligence")
    if isinstance(service, dict):
        result["telegram_service_intelligence"] = service
    inference = data.get("inferential_intelligence")
    if isinstance(inference, dict) and inference:
        fields = ("schema_version", "rule_version", "analysis_performed_at", "clusters", "relationships", "paths",
                  "profiles", "comparisons", "motifs", "hypotheses", "entity_associations", "cross_chain_messages",
                  "coverage", "method_coverage", "diagnostics", "stats", "journal", "frontier", "limitations")
        result["inferential_intelligence"] = {field: inference[field] for field in fields if field in inference}
    context = data.get("investigation_context")
    if isinstance(context, dict) and context:
        fields = ("schema_version", "target_keys", "frontier", "journal", "sessions", "total_http_requests", "coverage",
                  "journal_entries_omitted")
        lean = {field: context[field] for field in fields if field in context}
        histories = context.get("histories") or {}
        lean["retained_history_count"] = len(histories) if isinstance(histories, dict) else 0
        result["investigation_context"] = lean
    return result


def _inferential_public_urls(value):
    """Only public URLs in canonical inference fields may become browser links."""
    found = set()
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if key in {"url", "source_url", "explorer_url", "evidence_url"} and isinstance(child, str):
                    if url := safe_href(child):
                        found.add(url)
                elif key in {"source_urls", "evidence_urls"} and isinstance(child, list):
                    found.update(url for value in child if (url := safe_href(value)))
                elif isinstance(child, (dict, list)):
                    stack.append(child)
        elif isinstance(item, list):
            stack.extend(child for child in item if isinstance(child, (dict, list)))
    return found
# GANSAR_INFERENTIAL_END


def _service_views_for_data(report: AddressReport, data: dict, *, qualified: bool = False) -> dict:
    if not data:
        return {}
    from app.attribution.provenance import compact_service_provenance
    data = compact_service_provenance(data)
    logos = _service_logos()
    evidence = {row.get("evidence_id"): {**row, "url": safe_href(row.get("url"))} for row in data.get("evidence", [])}
    relationships = {str(row.get("relationship_id") or index): row for index, row in enumerate(data.get("relationships") or [])}
    related = {}
    for relationship_id, relation in relationships.items():
        for key in {relation.get("from_key"), relation.get("to_key")} - {None, ""}:
            related.setdefault(key, []).append(relationship_id)
    addresses = {}
    for address, item in data.get("addresses", {}).items():
        claims = []
        references = list(item.get("evidence_ids") or []) + list((item.get("contract") or {}).get("evidence_ids") or [])
        for assertion in item.get("attributions") or []:
            status = str(assertion.get("status") or "UNKNOWN").upper()
            if status not in {"CONFIRMED", "PROBABLE", "POSSIBLE", "UNKNOWN"}:
                status = "UNKNOWN"
            source_urls = list(dict.fromkeys(url for value in [assertion.get("source_url"), *(assertion.get("source_urls") or [])]
                if (url := safe_href(value))))
            observed_times = list(dict.fromkeys(value for value in [assertion.get("observed_at"), *(assertion.get("observation_timestamps") or [])] if value))
            logo = logos.get(assertion.get("service_id")) if status != "UNKNOWN" else None
            claims.append({**assertion, "status": status, "name": (assertion.get("name") or assertion.get("entity_name") or "UNKNOWN") if status != "UNKNOWN" else "UNKNOWN",
                "source_url": source_urls[0] if source_urls else "", "source_urls": source_urls,
                "observed_at": observed_times[0] if observed_times else None, "observation_timestamps": observed_times,
                "logo": logo["url"] if logo else "",
                "logo_source_url": safe_href((logo or {}).get("source_url")),
                "logo_license": (logo or {}).get("license") or "No licensed official local logo available"})
            references.extend(assertion.get("evidence_ids") or [])
            references.extend(assertion.get("conflicting_evidence") or [])
        chain = str(item.get("blockchain") or item.get("chain") or (address.split(":", 1)[0] if qualified else "ton"))
        raw_address = item.get("address") or (address.split(":", 1)[-1] if qualified else address)
        raw_address = canonical_address(chain, raw_address) or raw_address
        key = address_id(chain, raw_address) if qualified else ton_canonical_address(address) or address
        if not key:
            continue
        for relationship_id in related.get(key, []):
            references.extend(relationships[relationship_id].get("evidence_ids") or [])
        addresses[key] = {**item, "key": key, "blockchain": chain, "address": raw_address, "attributions": claims,
            "relationship_ids": related.get(key, []),
            "evidence": [evidence[ref] for ref in dict.fromkeys(references) if ref in evidence],
            "client_attribution": _wallet_application_view(item.get("client_attribution") or item.get("wallet_application") or {
                "status": "UNKNOWN", "reason": "A standard wallet contract does not identify the signing application."}, logos, evidence)}
    target_chain = str(data.get("target_chain") or (report.detected_chains or ["ton"])[0])
    target_key = address_id(target_chain, data.get("target_address") or report.target_address) if qualified else ton_canonical_address(report.target_address) or report.target_address
    return {"addresses": addresses, "target_address": data.get("target_address") or report.target_address,
        "target_key": target_key, "target_chain": target_chain,
        "coverage": data.get("coverage") or {}, "stats": data.get("stats") or {}, "evidence": list(evidence.values()),
        "relationships": relationships,
        "source_observations": data.get("source_observations", {}),
        "transaction_origins": data.get("transaction_origins", {}),
        "transaction_fingerprints": data.get("transaction_fingerprints", {}),
        "transaction_origin_coverage": data.get("transaction_origin_coverage", {}),
        # GANSAR_INFERENTIAL_BEGIN
        **_inferential_service_projection(data),
        # GANSAR_INFERENTIAL_END
        "warnings": data.get("warnings") or [], "errors": data.get("errors") or []}


def _ton_service_views(report: AddressReport) -> dict:
    """Compatibility view for callers of the original TON-only exporter."""
    return _service_views_for_data(report, getattr(report, "ton_service_intelligence", None) or {})


def _attribution_views(report: AddressReport) -> dict:
    data = getattr(report, "attribution_intelligence", None) or {}
    if data:
        return _service_views_for_data(report, data, qualified=True)
    legacy = _ton_service_views(report)
    if not legacy:
        return {}
    legacy["addresses"] = {address_id("ton", key): {**record, "key": address_id("ton", key)}
        for key, record in legacy["addresses"].items()}
    legacy["target_chain"] = "ton"
    legacy["target_key"] = address_id("ton", report.target_address)
    return legacy



def _ton_message_execution(tx: Transaction) -> str:
    """Account-side execution observations; never imply recipient credit."""
    from app.utils.event_identity import canonical_hash
    raw = tx.raw or {}
    identity = event_identity(tx)
    message_hash = identity.split(":")[2] if identity.startswith("ton:message:") else ""
    if not canonical_hash(message_hash):
        return "UNKNOWN"
    observations = [raw, *(entry.get("raw") or {} for entry in tx.provenance if isinstance(entry, dict))]
    statuses = {"sender": set(), "recipient": set()}
    credits = set()
    for observation in observations:
        native = observation.get("transaction")
        if not isinstance(native, dict):
            continue
        account_value = native.get("account") or native.get("account_addr")
        account = ton_canonical_address(account_value.get("address") if isinstance(account_value, dict) else account_value)
        messages = [native.get("in_msg"), *(native.get("out_msgs") or [])]
        for message in messages:
            if not isinstance(message, dict) or canonical_hash(message.get("hash") or message.get("msg_hash")) != message_hash:
                continue
            def endpoint(value):
                return ton_canonical_address(value.get("address") if isinstance(value, dict) else value)
            sender, recipient = endpoint(message.get("source")), endpoint(message.get("destination"))
            role = "sender" if account and account == sender else "recipient" if account and account == recipient else None
            if not role:
                continue
            description = native.get("description") or {}
            success = native.get("success")
            failed = native.get("aborted") is True or description.get("aborted") is True
            failed = failed or any(isinstance(container.get(key), dict) and container[key].get("success") is False
                for container in [native, description] for key in ["compute_phase", "compute_ph", "action_phase", "action"])
            compute = description.get("compute_ph") or native.get("compute_phase") or {}
            action = description.get("action") or native.get("action_phase") or {}
            phases_ok = description.get("aborted") is False and compute.get("success") is True and (not action or action.get("success") is True)
            statuses[role].add("FAILED" if failed or success is False else "SUCCESS" if success is True or phases_ok else "UNKNOWN")
            if role == "recipient":
                phase = native.get("credit_phase") or description.get("credit_ph") or {}
                credit = phase.get("credit") if isinstance(phase, dict) else None
                if isinstance(credit, dict):
                    credit = credit.get("grams")
                if credit is not None and str(credit).isdigit():
                    credits.add(_number_text(Decimal(str(credit)) / Decimal(10**9)) + " TON")
    credit_text = " / ".join(sorted(credits)) + " (credit phase; final balance not inferred)" if credits else "UNKNOWN"
    return "sender execution: " + (" / ".join(sorted(statuses["sender"])) or "UNKNOWN") + "; recipient execution: " + (" / ".join(sorted(statuses["recipient"])) or "UNKNOWN") + "; recipient credit phase: " + credit_text


def _transaction_views(report: AddressReport, language: str, service_views: dict | None = None) -> list[dict]:
    ens_aliases = {row["address"]: row["name"] for row in _ens_wallet_identities(report)}
    service_views = _attribution_views(report) if service_views is None else service_views
    service_addresses = service_views.get("addresses", {})
    labels_by_address: dict[tuple[str, str], list[str]] = {}
    risk_by_address: dict[tuple[str, str], list[str]] = {}
    for label in report.labels:
        labels_by_address.setdefault((label.chain, label.address.lower()), []).append(label.label)
    for flag in report.risk_flags:
        if flag.chain != "multi":
            risk_by_address.setdefault((flag.chain, flag.address.lower()), []).append(flag.severity)
    target_by_chain = {chain: report.target_address.lower() for chain in report.detected_chains or ["ton"]}
    out = []
    tx_labels = I18N[language]
    for tx in report.transactions:
        target = target_by_chain.get(tx.chain, report.target_address.lower())
        from_key = (tx.from_address or "").lower()
        to_key = (tx.to_address or "").lower()
        direction = tx.direction
        raw = tx.raw or {}
        if tx.chain in {"btc", "doge"}:
            asset_label = "DOGE" if tx.chain == "doge" else "BTC"
            inputs = list(tx.inputs or [])
            outputs = list(tx.outputs or [])
            input_summary = raw.get("input_summary") or _utxo_io_summary(inputs, asset_label)
            output_summary = raw.get("output_summary") or _utxo_io_summary(outputs, asset_label)
            amount = "" if tx.amount is None else f"{tx.amount:,.8f}".rstrip("0").rstrip(".")
            fee_text = _btc_value(tx.fee if tx.fee is not None else raw.get("fee"))
            confirmations = tx.confirmations if tx.confirmations is not None else raw.get("confirmations")
            kind = _tx_kind(tx)
            service = _service_tag(tx, labels_by_address)
            out.append(
                {
                    "hash": tx.tx_hash or "",
                    "hash_short": _short(tx.tx_hash, 10, 8),
                    "chain": _chain_label(tx.chain),
                    "chain_raw": tx.chain,
                    "time": tx.timestamp.isoformat(sep=" ", timespec="seconds") if tx.timestamp else "-",
                    "from": "",
                    "to": "",
                    "from_short": input_summary or "-",
                    "to_short": output_summary or "-",
                    "counterparty": "",
                    "counterparty_short": "",
                    "amount": amount,
                    "asset": asset_label,
                    "direction": direction,
                    "direction_label": tx_labels.get("sent" if direction == "out" else "received" if direction == "in" else direction, direction),
                    "kind": kind,
                    "kind_label": tx_labels.get(kind, kind),
                    "source": tx.source,
                    "url": tx.url or "",
                    "service": service,
                    "gas_fee": fee_text,
                    "fee": fee_text,
                    "confirmations": confirmations if confirmations is not None else "",
                    "inputs_summary": input_summary,
                    "outputs_summary": output_summary,
                    "method": "",
                    "tags": list(dict.fromkeys(([service] if service else []) + ([f"{confirmations} conf"] if confirmations not in (None, "") else [])))[:4],
                    "q": " ".join(str(item or "") for item in (tx.chain, tx.tx_hash, input_summary, output_summary, tx.asset, tx.source, service, kind, confirmations)).lower(),
                }
            )
            continue
        if direction == "unknown" and _tx_kind(tx) != "external_message":
            if from_key == target and to_key == target:
                direction = "self"
            elif from_key == target:
                direction = "out"
            elif to_key == target:
                direction = "in"
        counterparty = tx.to_address if direction == "out" else tx.from_address if direction == "in" else tx.to_address or tx.from_address or ""
        amount = _number_text(tx.amount_decimal if tx.amount_decimal is not None else tx.amount)
        kind = _tx_kind(tx)
        address_tags = labels_by_address.get((tx.chain, (counterparty or "").lower()), [])
        suspicious = any(item in {"medium", "high"} for item in risk_by_address.get((tx.chain, (counterparty or "").lower()), []))
        service = _service_tag(tx, labels_by_address)
        gas_fee = raw.get("gas_fee_eth")
        if gas_fee is None and raw.get("fee") is not None:
            gas_fee = raw.get("fee")
        gas_fee_text = ""
        try:
            if gas_fee is not None:
                gas_fee_text = f"{float(gas_fee):,.10f}".rstrip("0").rstrip(".")
        except Exception:
            gas_fee_text = str(gas_fee or "")
        method = str(raw.get("function_name") or raw.get("method") or raw.get("method_id") or "").strip()
        confirmations = tx.confirmations if tx.confirmations is not None else raw.get("confirmations")
        status = str(raw.get("status") or raw.get("final_result") or "").strip()
        out.append(
            {
                "hash": tx.tx_hash or "",
                "hash_short": _short(tx.tx_hash, 10, 8),
                "chain": _chain_label(tx.chain),
                "chain_raw": tx.chain,
                "time": tx.timestamp.isoformat(sep=" ", timespec="seconds") if tx.timestamp else "-",
                "from": tx.from_address or "",
                "to": tx.to_address or "",
                "from_short": _short(tx.from_address),
                "to_short": _short(tx.to_address),
                "counterparty": counterparty or "",
                "counterparty_short": _short(counterparty),
                "amount": amount,
                "asset": tx.asset or "UNKNOWN",
                "direction": direction,
                "direction_label": tx_labels.get("sent" if direction == "out" else "received" if direction == "in" else direction, direction),
                "kind": kind,
                "kind_label": tx_labels.get(kind, kind),
                "source": tx.source,
                "url": tx.url or "",
                "service": service,
                "gas_fee": gas_fee_text,
                "fee": "",
                "confirmations": confirmations if confirmations is not None else "",
                "inputs_summary": "",
                "outputs_summary": "",
                "method": method,
                "tags": list(dict.fromkeys(([service] if service else []) + ([status] if status else []) + address_tags + (["suspicious"] if suspicious else [])))[:4],
                "q": " ".join(str(item or "") for item in (tx.chain, tx.tx_hash, tx.from_address, tx.to_address, tx.asset, tx.source, service, kind, status,
                    *(ens_aliases.get(canonical_address("eth", value), "") for value in (tx.from_address, tx.to_address) if tx.chain == "eth"))).lower(),
            }
        )
    # Keep source actions and remote trace context visible without presenting
    # either as another independently observed payment by this wallet.
    ton_symbols = {}
    for token in report.tokens:
        master = ton_canonical_address(token.contract) if token.chain == "ton" else None
        symbol = token.symbol
        if master and symbol and not ton_canonical_address(symbol):
            ton_symbols.setdefault(master, symbol)
    target_ton = ton_canonical_address(report.target_address)
    for row, tx in zip(out, report.transactions):
        row["operation_identity"] = event_identity(tx)
        if tx.chain == "ton":
            raw = tx.raw or {}
            provider_action = raw.get("provider") == "tonapi_events" or raw.get("asset_type") == "action" or raw.get("action_index") is not None
            incident = target_ton in {ton_canonical_address(tx.from_address), ton_canonical_address(tx.to_address)} if target_ton else False
            row["observation_scope"] = "target" if incident else "trace_context"
            row["operation_kind"] = "provider_action" if provider_action else "source_operation"
            if not provider_action and row["operation_identity"].startswith("ton:message:"):
                row["kind_label"] = "Нативное сообщение" if language == "ru" else "Native message"
                row["direction_label"] = ("Исходящее сообщение" if row["direction"] == "out" else "Входящее сообщение" if row["direction"] == "in" else row["direction_label"]) if language == "ru" else ("Outgoing message" if row["direction"] == "out" else "Incoming message" if row["direction"] == "in" else row["direction_label"])
                row["execution_observation"] = _ton_message_execution(tx)
            if provider_action:
                row["kind_label"] = "Событие источника (не дополнительный перевод)" if language == "ru" else "Provider action (not an additional transfer)"
            if not incident:
                row["kind_label"] = ("Контекст trace · " if language == "ru" else "Trace context · ") + row["kind_label"]
            master = ton_canonical_address(str(tx.asset or "").removeprefix("JETTON:")) if str(tx.asset or "").startswith("JETTON:") else None
            if master:
                row["asset_label"] = ton_symbols.get(master) or tx.asset
                row["asset_contract"] = master
        if row["operation_identity"] in service_views.get("transaction_origins", {}):
            row["transaction_origin_ref"] = row["operation_identity"]
        if service_views and (getattr(report, "attribution_intelligence", None) or tx.chain == "ton"):
            legacy_service = row.get("service")
            row["service"] = ""
            row["tags"] = [tag for tag in row.get("tags", []) if tag != legacy_service]
            row["sender_service_address"] = ton_canonical_address(tx.from_address) or tx.from_address or ""
            row["recipient_service_address"] = ton_canonical_address(tx.to_address) or tx.to_address or ""
            sender_addresses = [str(item.get("address")) for item in tx.inputs if item.get("address")] if tx.chain in {"btc", "doge"} else [tx.from_address] if tx.from_address else []
            recipient_addresses = [str(item.get("address")) for item in tx.outputs if item.get("address")] if tx.chain in {"btc", "doge"} else [tx.to_address] if tx.to_address else []
            row["sender_service_keys"] = list(dict.fromkeys(key for value in sender_addresses if (key := address_id(tx.chain, value))))
            row["recipient_service_keys"] = list(dict.fromkeys(key for value in recipient_addresses if (key := address_id(tx.chain, value))))
            row["sender_service_key"] = row["sender_service_keys"][0] if len(row["sender_service_keys"]) == 1 else ""
            row["recipient_service_key"] = row["recipient_service_keys"][0] if len(row["recipient_service_keys"]) == 1 else ""
            row["event_id"] = tx.event_id
            row["trace_id"] = (tx.raw or {}).get("trace_id") or ""
            for address_key in row["sender_service_keys"] + row["recipient_service_keys"]:
                for claim in service_addresses.get(address_key, {}).get("attributions", []):
                    row["q"] += " " + " ".join(str(claim.get(field) or "") for field in ("name", "entity_name", "service_id", "status", "entity_type", "relationship", "category", "method")).lower()
        detail = (tx.raw or {}).get("nft_intelligence") or {}
        if detail:
            row["event_id"] = tx.event_id
            row["logical_time"] = detail.get("logical_time")
            row["verification"] = detail.get("verification")
            row["status"] = detail.get("status")
            row["nft_details"] = detail
            row["provenance"] = tx.provenance
            money = detail.get("money") or {}
            if money:
                role = "sale consideration" if detail.get("event_type") == "sale" else "accompanying amount; not a sale price"
                row["consideration"] = f"{money.get('amount', 'UNKNOWN')} {money.get('currency', '')} · {role}".strip()
            row["q"] += " " + json.dumps(detail, ensure_ascii=False, default=str).lower()
    return out


def _story_text(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() in {"", "-", "none", "null", "undefined"} else text


def _story_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    text = _story_text(value)
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        pass
    if len(normalized) >= 10:
        try:
            return datetime.strptime(normalized[:10], "%Y-%m-%d")
        except ValueError:
            return None
    return None


def _story_sort_dt(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def _story_sources(values: object) -> list[str]:
    if isinstance(values, (list, tuple, set)):
        raw_values = values
    else:
        raw_values = [values]
    return list(dict.fromkeys(_story_text(item) for item in raw_values if _story_text(item)))


def _story_fact(label: str, value: object, *, shorten: bool = False) -> dict:
    text = _story_text(value)
    if not text:
        return {}
    if shorten and len(text) > 24:
        text = _short(text, 10, 7)
    return {"label": label, "value": text}


def _story_asset_badge(asset_type: str, event_type: str = "", marketplace: str = "") -> str:
    if event_type in {"sale", "listing", "marketplace_sale", "marketplace_purchase"} or marketplace:
        return "marketplace"
    if asset_type == "username" or asset_type == "domain":
        return "telegram"
    if asset_type == "gift":
        return "gift"
    if asset_type == "jetton":
        return "jetton"
    return "nft"


def _story_asset_label(asset_type: str, language: str) -> str:
    labels = {
        "ru": {
            "username": "Telegram username",
            "domain": "TON DNS",
            "gift": "Gift",
            "jetton": "Jetton",
            "nft": "NFT",
            "collectible": "Collectible",
        },
        "en": {
            "username": "Telegram username",
            "domain": "TON DNS",
            "gift": "Gift",
            "jetton": "Jetton",
            "nft": "NFT",
            "collectible": "Collectible",
        },
    }
    return labels.get(language, labels["ru"]).get(asset_type, asset_type or "asset")


def _story_labels(language: str) -> dict[str, str]:
    return {
        "ru": {
            "wallet": "Кошелёк",
            "transaction": "Транзакция",
            "nft": "NFT",
            "gift": "Gift",
            "jetton": "Jetton",
            "telegram": "Telegram",
            "marketplace": "Marketplace",
            "counterparty": "Контрагент",
            "activity": "Активность",
            "first_activity": "Первая зафиксированная активность",
            "last_activity": "Последняя зафиксированная активность",
            "activity_burst": "Период высокой активности",
            "asset_first_seen": "Актив впервые зафиксирован",
            "asset_last_seen": "Актив повторно зафиксирован",
            "telegram_evidence": "Telegram evidence зафиксирован",
            "counterparty_first": "Первое взаимодействие с контрагентом",
            "counterparty_last": "Последнее взаимодействие с контрагентом",
            "activity_chain_first": "Начало цепочки активности",
            "activity_chain_last": "Конец цепочки активности",
            "direction": "направление",
            "amount": "сумма",
            "owner": "владелец",
            "collection": "коллекция",
            "marketplace_field": "marketplace",
            "tx_count": "tx count",
            "end": "конец",
            "labels": "labels",
            "transaction_data": "transaction data",
        },
        "en": {
            "wallet": "Wallet",
            "transaction": "Transaction",
            "nft": "NFT",
            "gift": "Gift",
            "jetton": "Jetton",
            "telegram": "Telegram",
            "marketplace": "Marketplace",
            "counterparty": "Counterparty",
            "activity": "Activity",
            "first_activity": "First recorded activity",
            "last_activity": "Last recorded activity",
            "activity_burst": "High activity period",
            "asset_first_seen": "Asset first seen",
            "asset_last_seen": "Asset seen again",
            "telegram_evidence": "Telegram evidence recorded",
            "counterparty_first": "First counterparty interaction",
            "counterparty_last": "Last counterparty interaction",
            "activity_chain_first": "Activity chain started",
            "activity_chain_last": "Activity chain ended",
            "direction": "direction",
            "amount": "amount",
            "owner": "owner",
            "collection": "collection",
            "marketplace_field": "marketplace",
            "tx_count": "tx count",
            "end": "end",
            "labels": "labels",
            "transaction_data": "transaction data",
        },
    }.get(language, {})


def _address_story(report: AddressReport, language: str, presentation=None) -> dict:
    def story_short(value, head=9, tail=6):
        return _short(presentation.text(value) if presentation else value, head, tail)

    def story_fact(label, value, *, shorten=False):
        shown = presentation.text(value) if presentation else value
        result = _story_fact(label, shown, shorten=shorten)
        if result:
            result["full_value"] = shown
        return result

    labels = _story_labels(language)
    tx_labels = I18N[language]
    events: list[dict] = []
    seen: set[tuple] = set()
    tx_sources = _story_sources([tx.source for tx in report.transactions])
    timeline_source = ", ".join(tx_sources[:4]) or labels["transaction_data"]

    def add_event(
        when: object,
        badge: str,
        event_type: str,
        title: str,
        description: str,
        *,
        source: object = "",
        evidence_url: str = "",
        facts: list[dict] | None = None,
    ) -> None:
        stamp = _story_datetime(when)
        title = _story_text(title)
        description = _story_text(description)
        if not stamp or not title or not description:
            return
        source_text = ", ".join(_story_sources(source))
        evidence_text = _story_text(evidence_url)
        clean_facts = [fact for fact in (facts or []) if fact and _story_text(fact.get("value"))]
        sort_dt = _story_sort_dt(stamp)
        key = (sort_dt.isoformat(timespec="seconds"), badge, event_type, title, description, evidence_text)
        if key in seen:
            return
        seen.add(key)
        events.append(
            {
                "_sort": sort_dt,
                "datetime": stamp.isoformat(),
                "date": sort_dt.strftime("%Y-%m-%d"),
                "time": sort_dt.strftime("%H:%M"),
                "badge": badge,
                "type": event_type,
                "title": title,
                "description": description,
                "source": source_text,
                "evidence_url": evidence_text,
                "facts": clean_facts[:8],
            }
        )

    timeline = report.wallet_timeline
    if timeline and timeline.first_activity:
        add_event(
            timeline.first_activity,
            "wallet",
            labels["wallet"],
            labels["first_activity"],
            f"{_chain_label((report.detected_chains or ['ton'])[0])}: {report.target_address}",
            source=timeline_source,
            facts=[
                story_fact(tx_labels["chain"], _chain_label((report.detected_chains or ["ton"])[0])),
                story_fact(tx_labels["hash"], report.target_address, shorten=True),
            ],
        )
    if timeline and timeline.last_activity and timeline.last_activity != timeline.first_activity:
        add_event(
            timeline.last_activity,
            "wallet",
            labels["wallet"],
            labels["last_activity"],
            f"{_chain_label((report.detected_chains or ['ton'])[0])}: {report.target_address}",
            source=timeline_source,
            facts=[
                story_fact(tx_labels["chain"], _chain_label((report.detected_chains or ["ton"])[0])),
                story_fact(tx_labels["hash"], report.target_address, shorten=True),
            ],
        )
    if timeline:
        for burst in timeline.bursts[:24]:
            add_event(
                burst.start_time,
                "activity",
                labels["activity"],
                labels["activity_burst"],
                f"{_chain_label(burst.chain)}: {burst.tx_count} tx",
                source=timeline_source,
                facts=[
                    story_fact(tx_labels["chain"], _chain_label(burst.chain)),
                    story_fact(labels["tx_count"], burst.tx_count),
                    story_fact(labels["end"], _time_text(burst.end_time)),
                ],
            )

    for tx in report.transactions:
        if not tx.timestamp:
            continue
        kind = _tx_kind(tx)
        direction = tx.direction
        target = report.target_address.lower()
        from_key = (tx.from_address or "").lower()
        to_key = (tx.to_address or "").lower()
        if direction == "unknown" and kind != "external_message":
            if from_key == target and to_key == target:
                direction = "self"
            elif from_key == target:
                direction = "out"
            elif to_key == target:
                direction = "in"
        counterparty = tx.to_address if direction == "out" else tx.from_address if direction == "in" else tx.to_address or tx.from_address or ""
        amount = _number_text(tx.amount_decimal if tx.amount_decimal is not None else tx.amount)
        amount_text = f"{amount} {tx.asset or 'UNKNOWN'}".strip()
        badge = "transaction"
        if kind == "nft_transfer":
            badge = "nft"
        elif kind == "token_transfer" or _is_ton_jetton_tx(tx):
            badge = "jetton"
        title = tx_labels.get(kind, kind.replace("_", " "))
        direction_label = tx_labels.get("sent" if direction == "out" else "received" if direction == "in" else direction, direction)
        execution_observation = ""
        if tx.chain == "ton":
            raw = tx.raw or {}
            if raw.get("provider") == "tonapi_events" or raw.get("asset_type") == "action" or raw.get("action_index") is not None:
                title = "Событие источника (не дополнительный перевод)" if language == "ru" else "Provider action (not an additional transfer)"
            elif event_identity(tx).startswith("ton:message:"):
                title = "Нативное сообщение" if language == "ru" else "Native message"
                direction_label = ("Исходящее сообщение" if direction == "out" else "Входящее сообщение" if direction == "in" else direction_label) if language == "ru" else ("Outgoing message" if direction == "out" else "Incoming message" if direction == "in" else direction_label)
                execution_observation = _ton_message_execution(tx)
        parts = [direction_label, amount_text, _chain_label(tx.chain)]
        if counterparty:
            parts.append(f"{tx_labels['counterparty']}: {story_short(counterparty, 10, 7)}")
        add_event(
            tx.timestamp,
            badge,
            labels["transaction"],
            title,
            " | ".join(item for item in parts if _story_text(item)),
            source=tx.source,
            evidence_url=tx.url or "",
            facts=[
                story_fact(tx_labels["chain"], _chain_label(tx.chain)),
                story_fact(labels["direction"], direction_label),
                story_fact(labels["amount"], amount_text),
                story_fact(tx_labels["asset"], tx.asset or "UNKNOWN"),
                story_fact(tx_labels["counterparty"], counterparty, shorten=True),
                story_fact(tx_labels["hash"], tx.tx_hash, shorten=True),
                story_fact("Статус исполнения / credit phase" if language == "ru" else "Execution / credit phase", execution_observation),
            ],
        )

    for asset in report.ton_assets:
        asset_name = _story_text(asset.title or asset.name or asset.asset_id)
        asset_type = _story_asset_label(asset.type, language)
        asset_badge = _story_asset_badge(asset.type)
        asset_evidence = getattr(asset, "history_evidence_url", None) or asset.evidence_url or asset.external_url or ""
        base_description = " | ".join(item for item in (asset_type, asset_name, asset.collection or "") if _story_text(item))
        if asset.first_seen:
            add_event(
                asset.first_seen,
                asset_badge,
                labels.get(asset_badge, asset_type),
                labels["asset_first_seen"],
                base_description,
                source=asset.source,
                evidence_url=asset_evidence,
                facts=[
                    story_fact(tx_labels["type"], asset_type),
                    story_fact(tx_labels["asset"], asset_name, shorten=True),
                    story_fact(labels["collection"], asset.collection),
                    story_fact(labels["owner"], asset.owner_address, shorten=True),
                ],
            )
        if asset.last_seen and asset.last_seen != asset.first_seen:
            add_event(
                asset.last_seen,
                asset_badge,
                labels.get(asset_badge, asset_type),
                labels["asset_last_seen"],
                base_description,
                source=asset.source,
                evidence_url=asset_evidence,
                facts=[
                    story_fact(tx_labels["type"], asset_type),
                    story_fact(tx_labels["asset"], asset_name, shorten=True),
                    story_fact(labels["collection"], asset.collection),
                    story_fact(labels["owner"], asset.owner_address, shorten=True),
                ],
            )
        for event in _asset_history_events_for_view(asset):
            if not event.timestamp:
                continue
            direction = _asset_event_direction(asset, event)
            event_label = _asset_history_event_label(event, direction, language)
            marketplace = _story_text(event.marketplace or asset.marketplace)
            badge = _story_asset_badge(asset.type, event.event_type, marketplace)
            counterparty = event.counterparty or event.counterparty_label or event.from_address or event.to_address
            amount = event.amount if event.amount is not None else event.price
            amount_text = ""
            if amount is not None:
                amount_text = f"{_number_text(amount)} {event.currency or event.asset or 'TON'}".strip()
            details = [asset_type, asset_name]
            if marketplace:
                details.append(marketplace)
            if counterparty:
                details.append(f"{tx_labels['counterparty']}: {story_short(counterparty, 10, 7)}")
            add_event(
                event.timestamp,
                badge,
                labels.get(badge, asset_type),
                event_label,
                " | ".join(item for item in details if _story_text(item)),
                source=event.source or asset.source,
                evidence_url=event.evidence_url or asset_evidence,
                facts=[
                    story_fact(tx_labels["type"], asset_type),
                    story_fact(tx_labels["asset"], asset_name, shorten=True),
                    story_fact(labels["amount"], amount_text),
                    story_fact(tx_labels["from"], event.from_address, shorten=True),
                    story_fact(tx_labels["to"], event.to_address, shorten=True),
                    story_fact(labels["marketplace_field"], marketplace),
                    story_fact(tx_labels["hash"], event.tx_hash, shorten=True),
                ],
            )

    ranked_counterparties = sorted(
        [item for item in report.counterparties if item.first_seen or item.last_seen],
        key=lambda item: (item.tx_count, _story_sort_dt(item.last_seen or item.first_seen or datetime.min.replace(tzinfo=timezone.utc))),
        reverse=True,
    )
    for counterparty in ranked_counterparties[:60]:
        label_text = ", ".join(counterparty.labels[:3])
        description = " | ".join(
            item
            for item in (
                _chain_label(counterparty.chain),
                story_short(counterparty.address, 10, 7),
                f"{counterparty.tx_count} tx" if counterparty.tx_count else "",
                label_text,
            )
            if item
        )
        facts = [
            story_fact(tx_labels["chain"], _chain_label(counterparty.chain)),
            story_fact(tx_labels["counterparty"], counterparty.address, shorten=True),
            story_fact(labels["tx_count"], counterparty.tx_count),
            story_fact(labels["labels"], label_text),
        ]
        if counterparty.first_seen:
            add_event(counterparty.first_seen, "counterparty", labels["counterparty"], labels["counterparty_first"], description, source=timeline_source, facts=facts)
        if counterparty.last_seen and counterparty.last_seen != counterparty.first_seen:
            add_event(counterparty.last_seen, "counterparty", labels["counterparty"], labels["counterparty_last"], description, source=timeline_source, facts=facts)

    for chain in report.activity_chains[:40]:
        facts = [
            story_fact(tx_labels["type"], chain.chain_type),
            story_fact(tx_labels["asset"], chain.asset),
            story_fact(tx_labels["hash"], ", ".join(story_short(item, 10, 7) for item in chain.tx_hashes[:3])),
        ]
        if chain.first_seen:
            add_event(chain.first_seen, "activity", labels["activity"], labels["activity_chain_first"], chain.summary or chain.title, source=chain.source, evidence_url=chain.evidence_url or "", facts=facts)
        if chain.last_seen and chain.last_seen != chain.first_seen:
            add_event(chain.last_seen, "activity", labels["activity"], labels["activity_chain_last"], chain.summary or chain.title, source=chain.source, evidence_url=chain.evidence_url or "", facts=facts)

    for identity in report.telegram_identities:
        identity_name = identity.username or identity.telegram_user_id or ", ".join(identity.domains[:2]) or identity.wallet_address
        description = " | ".join(item for item in (identity_name, identity.confidence, identity.wallet_address) if _story_text(item))
        evidence_items = list(identity.evidence or [])
        identity_collected_at = getattr(identity, "collected_at", None)
        if identity_collected_at:
            add_event(
                identity_collected_at,
                "telegram",
                labels["telegram"],
                labels["telegram_evidence"],
                description,
                source=identity.source,
                evidence_url=identity.evidence_url or "",
                facts=[
                    story_fact(tx_labels["username"], identity.username),
                    story_fact(tx_labels["hash"], identity.wallet_address, shorten=True),
                    story_fact(tx_labels["status"], identity.confidence),
                ],
            )
        for evidence in evidence_items[:20]:
            add_event(
                evidence.collected_at,
                "telegram",
                labels["telegram"],
                labels["telegram_evidence"],
                description,
                source=evidence.source or identity.source,
                evidence_url=evidence.evidence_url or identity.evidence_url or "",
                facts=[
                    story_fact(tx_labels["username"], identity.username),
                    story_fact(tx_labels["hash"], evidence.evidence_tx or evidence.nft_contract or identity.wallet_address, shorten=True),
                    story_fact(tx_labels["status"], evidence.confidence),
                ],
            )

    ordered = sorted(events, key=lambda item: item["_sort"])
    total = len(ordered)
    if total > 360:
        visible = ordered[:80] + ordered[-280:]
    else:
        visible = ordered
    for event in visible:
        event.pop("_sort", None)
    source_list = list(dict.fromkeys(event["source"] for event in ordered if event.get("source")))[:14]
    counts = Counter(event["badge"] for event in ordered)
    count_labels = {
        "wallet": labels["wallet"],
        "transaction": labels["transaction"],
        "nft": labels["nft"],
        "gift": labels["gift"],
        "jetton": labels["jetton"],
        "telegram": labels["telegram"],
        "marketplace": labels["marketplace"],
        "counterparty": labels["counterparty"],
        "activity": labels["activity"],
    }
    first = ordered[0]["date"] if ordered else "-"
    last = ordered[-1]["date"] if ordered else "-"
    return {
        "events": visible,
        "total": total,
        "shown": len(visible),
        "hidden": max(0, total - len(visible)),
        "first": first,
        "last": last,
        "period": f"{first} -> {last}" if ordered else "-",
        "summary": {
            "transactions": counts.get("transaction", 0),
            "counterparties": counts.get("counterparty", 0),
            "activities": counts.get("activity", 0),
        },
        "sources": source_list,
        "type_counts": [{"badge": badge, "label": count_labels.get(badge, badge), "value": value} for badge, value in counts.most_common()],
    }


def _observations(report: AddressReport, language: str) -> list[dict]:
    out = []
    for balance in report.balances[:6]:
        amount = f"{balance.amount:,.8f}".rstrip("0").rstrip(".")
        out.append({"level": _chain_label(balance.chain), "text": f"{balance.asset} balance: {amount}"})
    eth_tokens = [token for token in report.tokens if token.chain == "eth"]
    if eth_tokens:
        out.append({"level": "asset", "text": f"Ethereum assets found: {len(eth_tokens)}"})
    tron_tokens = [token for token in report.tokens if token.chain == "tron"]
    if tron_tokens:
        out.append({"level": "asset", "text": f"TRC20 assets found: {len(tron_tokens)}"})
    doge_txs = [tx for tx in report.transactions if tx.chain == "doge"]
    if doge_txs:
        out.append({"level": "dogecoin", "text": f"DOGE transactions found: {len(doge_txs)}"})
    solana_tokens = [token for token in report.tokens if token.chain == "solana"]
    if solana_tokens:
        out.append({"level": "asset", "text": f"Solana assets found: {len(solana_tokens)}"})
    bsc_tokens = [token for token in report.tokens if token.chain == "bsc"]
    if bsc_tokens:
        out.append({"level": "asset", "text": f"BSC assets found: {len(bsc_tokens)}"})
    if report.ens_name or report.reverse_ens:
        out.append({"level": "ENS", "text": f"ENS record: {report.ens_name or report.reverse_ens}"})
    if report.ton_assets:
        text = f"TON digital assets found: {len(report.ton_assets)}" if language == "en" else f"Найдены TON цифровые активы: {len(report.ton_assets)}"
        out.append({"level": "signal" if language == "en" else "сигнал", "text": text})
    username_count = sum(1 for asset in report.ton_assets if asset.type == "username")
    gift_count = sum(1 for asset in report.ton_assets if asset.type == "gift")
    if username_count:
        out.append({"level": "link", "text": f"Telegram/TON usernames: {username_count}"})
    if gift_count:
        out.append({"level": "asset", "text": f"public collectible gifts: {gift_count}"})
    confirmed = [item for item in report.telegram_identities if item.confidence == "confirmed"]
    likely = [item for item in report.telegram_identities if item.confidence == "likely"]
    if confirmed:
        out.append({"level": "confirmed", "text": f"confirmed Telegram links: {len(confirmed)}"})
    elif likely:
        out.append({"level": "likely", "text": f"likely Telegram links: {len(likely)}"})
    for flag in report.risk_flags[:8]:
        out.append({"level": flag.severity, "text": flag.details or flag.flag})
    for warning in report.warnings[:4]:
        out.append({"level": "warning", "text": warning})
    return out[:14]


def _telegram_summary(report: AddressReport, language: str) -> dict:
    labels = (
        {"confirmed": "confirmed", "likely": "likely", "weak": "weak signal", "unknown": "not found"}
        if language == "en"
        else {"confirmed": "подтверждено", "likely": "вероятно", "weak": "слабый сигнал", "unknown": "не найдено"}
    )
    identities = report.telegram_identities or []
    visible = [item for item in identities if item.confidence != "unknown"]
    status = "unknown"
    for level in ("confirmed", "likely", "weak"):
        if any(item.confidence == level for item in identities):
            status = level
            break
    usernames = sorted({item.username for item in visible if item.username})
    telegram_ids = sorted({item.telegram_user_id for item in visible if item.telegram_user_id})
    domains = sorted({domain for item in visible for domain in item.domains})
    gifts = sorted({gift for item in visible for gift in item.gifts})
    evidence_count = sum(len(item.evidence) for item in visible)
    return {
        "status": status,
        "status_label": labels[status],
        "items": visible,
        "usernames": usernames,
        "telegram_ids": telegram_ids,
        "domains": domains,
        "gifts": gifts,
        "evidence_count": evidence_count,
    }


def _avatar_image(value: str | None) -> str:
    text = str(value or "").strip()
    low = text.lower()
    if low.startswith(("https://", "http://", "data:image/")):
        return text
    if low.startswith("ipfs://"):
        return "https://ipfs.io/ipfs/" + text[7:].lstrip("/")
    return ""


IMAGE_FIELD_NAMES = ("image_url", "image", "logo_url", "logo", "tokenLogo", "token_logo", "logoURI", "icon_url", "icon", "iconUrl", "token_icon", "tokenIcon", "thumbnail_url", "thumbnail")
IMAGE_NESTED_FIELDS = ("tokenInfo", "token_info", "metadata", "collection")


def _normalize_asset_image(value: object, source: str = "") -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    low = text.lower()
    if low.startswith(("https://", "http://")):
        try:
            host = urlparse(text).netloc.lower().split("@")[-1].split(":")[0]
        except ValueError:
            host = ""
        if host in BROKEN_IMAGE_HOSTS:
            return ""
        return text
    if low.startswith("data:image/"):
        return text
    if low.startswith("//"):
        return f"https:{text}"
    if low.startswith("ipfs://"):
        payload = text[7:].lstrip("/")
        if payload.startswith("ipfs/"):
            payload = payload[5:]
        return f"https://ipfs.io/ipfs/{payload}" if payload else ""
    if text.startswith("/"):
        if source == "ethplorer":
            return urljoin("https://ethplorer.io", text)
        if source == "etherscan_html":
            return urljoin("https://etherscan.io", text)
    return ""


def _asset_image_url(raw: dict, source: str = "") -> str:
    if not isinstance(raw, dict):
        return ""
    for field in IMAGE_FIELD_NAMES:
        image = _normalize_asset_image(raw.get(field), source)
        if image:
            return image
    for field in IMAGE_NESTED_FIELDS:
        nested = raw.get(field)
        if isinstance(nested, dict):
            image = _asset_image_url(nested, source)
            if image:
                return image
    return ""


def _record_href(key: str, value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    low_key = key.lower()
    profile_hosts = {"com.github": {"github.com"}, "com.twitter": {"x.com", "twitter.com"},
        "telegram": {"t.me", "telegram.me"}, "org.telegram": {"t.me", "telegram.me"},
        "com.telegram": {"t.me", "telegram.me"}}
    if low_key in profile_hosts and text.lower().startswith(("https://", "http://")):
        try:
            host = (urlparse(text).hostname or "").lower().removeprefix("www.")
        except ValueError:
            return ""
        return safe_href(text) if host in profile_hosts[low_key] else ""
    if low_key == "com.github":
        name = text.removeprefix("@").strip("/")
        return f"https://github.com/{quote(name)}" if name and "/" not in name else ""
    if low_key == "com.twitter":
        name = text.removeprefix("@").strip("/")
        return f"https://x.com/{quote(name)}" if name and "/" not in name else ""
    if low_key == "url":
        return text if text.lower().startswith(("http://", "https://")) else f"https://{text}"
    if low_key == "email":
        return f"mailto:{text}" if "@" in text else ""
    if low_key in {"telegram", "org.telegram", "com.telegram"}:
        name = text.removeprefix("@").replace("https://t.me/", "").replace("http://t.me/", "").strip("/")
        return f"https://t.me/{quote(name)}" if name and "/" not in name else ""
    if low_key == "avatar":
        return _normalize_asset_image(text)
    if text.lower().startswith(("http://", "https://")):
        return text
    return ""


def _record_display(key: str, value: str) -> str:
    text = str(value or "").strip()
    low_key = key.lower()
    if low_key == "com.github":
        return text.removeprefix("@")
    if low_key == "com.twitter":
        name = text.removeprefix("@")
        return f"@{name}" if name else ""
    if low_key == "telegram":
        name = text.removeprefix("@").replace("https://t.me/", "").replace("http://t.me/", "").strip("/")
        return f"@{name}" if name else text
    return text


def _record_label(key: str) -> str:
    return {
        "com.github": "GitHub",
        "com.twitter": "Twitter/X",
        "url": "Website",
        "description": "Description",
        "email": "Email",
        "telegram": "Telegram",
        "avatar": "Avatar",
    }.get(key.lower(), key)


def _ens_record_views(records: dict[str, str]) -> list[dict]:
    out = []
    for key, value in records.items():
        text = str(value or "").strip()
        if not text:
            continue
        out.append(
            {
                "key": key,
                "label": _record_label(str(key)),
                "display": _record_display(str(key), text),
                "title": text,
                "href": _record_href(str(key), text),
            }
        )
    return out


def _ens_wallet_identities(report: AddressReport) -> list[dict]:
    """Bind a retained verified ENS result to its exact Ethereum wallet.

    This is presentation metadata, never a financial entity or an additional
    lookup. Reverse publications and other-chain address records cannot supply
    an Ethereum wallet's display name.
    """
    from app.sources.ethereum_ens import normalize_name
    profile = getattr(report, "ens_profile", None) or {}
    provenance = profile.get("provenance") or {}
    if not isinstance(provenance, dict):
        return []
    target = canonical_address("eth", report.target_address)
    resolved = canonical_address("eth", report.ens_resolved_address or "")
    profile_address = canonical_address("eth", profile.get("resolved_address") or "")
    source_address = canonical_address("eth", profile.get("source_address") or "")
    if ("eth" not in report.detected_chains or not target or target != resolved
            or target != profile_address or target != source_address
            or profile.get("forward_verified") is not True
            or profile.get("source") != "ethereum_ens"
            or provenance.get("chain_id") != 1
            or provenance.get("network") != "ethereum-mainnet"):
        return []
    try:
        name = normalize_name(profile.get("name") or "")
        retained_name = normalize_name(report.ens_name or "")
    except ValueError:
        return []
    if name != retained_name:
        return []
    primary = bool(profile.get("primary_verified") is True and report.ens_reverse_valid is True
                   and profile.get("primary_name") == name and report.reverse_ens == name)
    return [{"chain": "eth", "address": target, "name": name,
        "forward_verified": True, "primary_verified": primary,
        "verification": "forward_verified", "source": "ethereum_ens",
        "source_url": safe_href(profile.get("source_url")),
        "retrieved_at": profile.get("retrieved_at"), "provenance": dict(provenance),
        "ownership_claim": False}]


def _ens_summary(report: AddressReport, language: str) -> dict:
    status_labels = I18N[language]
    reverse_valid = report.ens_reverse_valid
    if reverse_valid is True:
        reverse_status = status_labels["verified"]
    elif reverse_valid is False:
        reverse_status = status_labels["unverified"]
    else:
        reverse_status = status_labels["unavailable"]
    records = {key: value for key, value in (report.text_records or {}).items() if value}
    resolver = report.resolver or report.ens_reverse_resolver or ""
    owner = report.ens_owner or ""
    resolved_address = report.ens_resolved_address or ""
    profile = getattr(report, "ens_profile", None) or {}
    return {
        "available": "eth" in report.detected_chains or bool(report.ens_name or report.reverse_ens or report.resolver or records or report.ens_warnings),
        "found": bool(report.ens_name or report.reverse_ens or report.resolver or records),
        "ens_name": report.ens_name,
        "reverse_ens": report.reverse_ens,
        "reverse_status": reverse_status,
        "resolver": resolver,
        "resolver_short": _short(resolver, 8, 6) if resolver else "",
        "reverse_resolver": report.ens_reverse_resolver,
        "owner": owner,
        "owner_short": _short(owner, 8, 6) if owner else "",
        "resolved_address": resolved_address,
        "resolved_address_short": _short(resolved_address, 8, 6) if resolved_address else "",
        "avatar": report.avatar,
        "avatar_image": _avatar_image((profile.get("avatar") or {}).get("thumbnail") or report.avatar),
        "text_records": records,
        "record_views": _ens_record_views(records),
        "warnings": report.ens_warnings,
        "profile": profile,
        "wallet_identities": _ens_wallet_identities(report),
    }


def _asset_paths(report: AddressReport) -> list[dict]:
    out = []
    for asset in report.ton_assets:
        if asset.type not in {"username", "gift", "nft", "domain", "collectible"}:
            continue
        steps = []
        if asset.first_seen:
            steps.append({"kind": "first_seen", "label": "first seen", "time": asset.first_seen, "details": asset.source, "evidence": asset.evidence_url})
        if asset.previous_owners:
            for owner in asset.previous_owners[:6]:
                steps.append({"kind": "previous_owner", "label": "previous owner", "time": None, "details": owner, "evidence": asset.evidence_url})
        events = sorted(asset.transfer_history + asset.sale_history, key=lambda event: event.timestamp or datetime.min.replace(tzinfo=timezone.utc))
        for event in events[:12]:
            label = {
                "mint": "mint",
                "first_owner": "first owner",
                "transfer": "transfer",
                "sale": "sale",
                "listing": "listing",
                "owner_change": "owner change",
                "current_owner": "current owner",
                "interaction": "interaction",
            }.get(event.event_type, event.event_type)
            details = " -> ".join(part for part in (event.from_address, event.to_address) if part)
            if event.price is not None or event.price_decimal is not None:
                price = str(event.price_decimal) if event.price_decimal is not None else str(event.price)
                consideration = f"{price} {event.currency or 'TON'} · sale consideration"
                details = f"{details} | {consideration}" if details else consideration
            steps.append({"kind": event.event_type, "label": label, "time": event.timestamp, "details": details or event.source, "evidence": event.evidence_url})
        if asset.owner_address and asset.ownership_status == "current" and asset.ownership_verified:
            steps.append({"kind": "current_owner", "label": "current owner", "time": asset.last_seen, "details": asset.owner_address, "evidence": asset.evidence_url})
        if steps:
            out.append({"asset": asset, "steps": steps})
    return out[:60]


def _wallet_behavior(report: AddressReport) -> dict:
    txs = [tx for tx in report.transactions if tx.timestamp]
    hours = Counter(tx.timestamp.hour for tx in txs if tx.timestamp)
    active_hours = [{"hour": hour, "count": count} for hour, count in hours.most_common(8)]
    gaps = []
    ordered = sorted([tx.timestamp for tx in txs if tx.timestamp])
    for left, right in zip(ordered, ordered[1:]):
        gap = right - left
        if gap.days >= 14:
            gaps.append({"from": left, "to": right, "days": gap.days})
    recurring = [c for c in report.counterparties if c.tx_count >= 3][:12]
    routing = [c for c in report.counterparties if c.total_in > 0 and c.total_out > 0][:12]
    exchanges = []
    markers = ("binance", "okx", "bybit", "kucoin", "mexc", "gate", "htx", "bitget", "coinbase", "kraken", "exchange")
    for c in report.counterparties:
        if any(marker in label.lower() for label in c.labels for marker in markers):
            exchanges.append(c)
    bursts = []
    for chain in sorted(set(tx.chain for tx in txs)):
        chain_txs = sorted([tx.timestamp for tx in txs if tx.chain == chain and tx.timestamp])
        if len(chain_txs) < 5:
            continue
        window = []
        for stamp in chain_txs:
            window = [item for item in window if (stamp - item).total_seconds() <= 3600]
            window.append(stamp)
            if len(window) >= 5:
                bursts.append({"chain": chain, "count": len(window), "time": stamp})
                break
    return {
        "active_hours": active_hours,
        "long_gaps": gaps[:8],
        "recurring": recurring,
        "routing": routing,
        "exchanges": exchanges[:12],
        "bursts": bursts[:8],
    }


def _browser_numbers(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and abs(value) > 9007199254740991:
        return str(value)
    if isinstance(value, dict):
        return {key: _browser_numbers(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_browser_numbers(item) for item in value]
    return value


def _browser_json(value) -> str:
    # JSON.parse restores every Unicode value. ASCII transport prevents one
    # supplementary character from widening hundreds of MB to four-byte str.
    return json.dumps(_browser_numbers(value), ensure_ascii=True, default=str).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def _input_resolution_view(report: AddressReport, language: str) -> dict:
    """Show the resolved object and analysis target as separate sourced facts."""
    resolution = getattr(report, "input_resolution", None) or {}
    if not resolution:
        return {}
    ru = language == "ru"
    unknown = "UNKNOWN"
    if resolution.get("input_kind") == "basename_name":
        fields = [("original_query", "Исходное имя" if ru else "Input name"),
            ("resolved_address", "Разрешённый EVM-адрес" if ru else "Resolved EVM address"),
            ("identity_chain", "Сеть имени" if ru else "Identity chain"), ("chain_id", "Chain ID"),
            ("forward_verified", "Проверка прямого разрешения" if ru else "Forward resolution verified")]
        return {"query": resolution.get("original_query"), "title": "Basenames / Base",
            "rows": [{"label": label, "value": resolution.get(key, unknown)} for key,label in fields],
            "notes": resolution.get("notes") or [], "raw": resolution, "evidence": [], "account_evidence": {},
            "caveat": "Разрешение имени не является доказательством владения registrar NFT. Финансовая история Base не собирается."
                if ru else "Name resolution does not prove registrar NFT ownership. Base financial history is not collected."}
    owner_verified = resolution.get("ownership_status") == "verified_onchain"
    owner_label = ("Текущий on-chain owner NFT" if ru else "Current on-chain NFT owner") if owner_verified else ("Наблюдаемый owner NFT" if ru else "NFT owner observation")
    labels = [
        ("original_query", "Исходный запрос" if ru else "Original query"),
        ("object_type", "Тип исходного объекта" if ru else "Input object type"),
        ("discovery_status", "Статус разрешения" if ru else "Discovery status"),
        ("nft_item_address", "Адрес NFT item" if ru else "NFT item address"),
        ("collection_address", "Адрес коллекции" if ru else "Collection address"),
        ("onchain_owner_address", owner_label),
        ("ownership_status", "Проверка владения" if ru else "Ownership verification"),
        ("owner_analysis_address", "Адрес анализа владельца" if ru else "Owner analysis address"),
        ("owner_analysis_status", "Статус анализа владельца" if ru else "Owner analysis status"),
        ("owner_account_type", "Тип owner account по источнику" if ru else "Source-reported owner account type"),
    ]
    evidence_by_id = {row.get("evidence_id"): row for row in (report.nft_intelligence or {}).get("evidence", [])}
    evidence = []
    for evidence_id in resolution.get("evidence_ids") or []:
        row = evidence_by_id.get(evidence_id, {})
        evidence.append({"id": evidence_id, "source": row.get("source") or unknown,
            "status": row.get("status") or unknown, "url": safe_href(row.get("url")),
            "observation_id": row.get("observation_id") or unknown})
    return {"query": resolution.get("original_query") or unknown,
        "rows": [{"label": label, "value": resolution.get(key) if resolution.get(key) not in (None, "") else unknown} for key, label in labels],
        "evidence": evidence, "account_evidence": resolution.get("owner_account_evidence") or {},
        "notes": resolution.get("notes") or [], "raw": resolution,
        "title": "Исходный объект и адрес анализа" if ru else "Input object and analysis address",
        "caveat": "Владение NFT, тип аккаунта владельца и личность человека — отдельные утверждения. Балансы, операции и риск относятся к указанному адресу анализа. Статус анализа владельца показан отдельно."
            if ru else "NFT ownership, owner account type and personal identity are separate claims. Balances, transactions and risk refer to the stated analysis address. Owner analysis status is shown separately."}


def _transaction_tree_view(report: AddressReport, transaction_views: list[dict],
                           observation_views: list[dict], language: str) -> dict:
    """A compact presentation index over retained evidence, never a new ledger.

    Financial rows keep their existing identities and amounts. Native TON
    execution is joined only through exact account/message hashes, not address,
    time, value, query ID or a provider's broad trace label. Shared components
    prevent a large batch transaction being copied into every observation row.
    """
    from app.utils.event_identity import canonical_hash

    accounts, messages, observation_seeds = {}, {}, {}
    observation_rows = {}
    for index, row in enumerate(observation_views):
        observation_rows.setdefault(str(row.get("operation_identity") or ""), []).append(index)

    def address(value):
        return ton_canonical_address(value.get("address") if isinstance(value, dict) else value)

    def timestamp(value):
        if type(value) is int or isinstance(value, str) and value.isdecimal():
            try:
                number = int(value)
                return datetime.fromtimestamp(number, timezone.utc).isoformat() if number > 0 else None
            except (ValueError, OverflowError, OSError):
                return None
        return None

    def integer(value):
        if type(value) is int and value >= 0:
            return value
        if isinstance(value, str) and value.isdecimal() and len(value) <= 120:
            return int(value)
        return None

    def merge_fact(record, field, value):
        if value is None or value == "":
            return
        conflicts = record.setdefault("conflicts", {})
        if field in conflicts:
            if value not in conflicts[field]:
                conflicts[field].append(value)
            return
        previous = record.get(field)
        if previous is None or previous == "":
            record[field] = value
        elif previous != value:
            conflicts[field] = [previous, value]
            record[field] = None

    def seed(oid):
        return observation_seeds.setdefault(oid, {"accounts": set(), "messages": set(),
            "hashes": set(), "trace_ids": set()})

    # Labels are taken from a retained decoded name or an exact TON opcode.
    # Decoded jetton base-unit quantities are not relabelled as TON value.
    op_names = {0x0f8a7ea5: "Jetton Transfer", 0x178d4519: "Jetton Internal Transfer",
                0x7362d09c: "Jetton Notify", 0xd53276db: "Excess",
                0x5fcc3d14: "NFT Transfer", 0x05138d91: "NFT Ownership Assigned"}

    def add_message(raw, oid, source, url, account_id=None, side=None):
        if not isinstance(raw, dict):
            return None
        digest = canonical_hash(raw.get("hash") or raw.get("msg_hash"))
        if not digest:
            return None
        mid = "ton:message:" + digest
        row = messages.setdefault(mid, {"id": mid, "hash": digest, "sources": set(),
            "urls": set(), "observation_ids": set(), "sender_account_ids": set(),
            "recipient_account_ids": set(), "conflicts": {}})
        row["sources"].add(source)
        if safe_href(url):
            row["urls"].add(safe_href(url))
        row["observation_ids"].add(oid)
        seed(oid)["messages"].add(mid)
        for key, value in (("from", address(raw.get("source"))), ("to", address(raw.get("destination"))),
                           ("lt", str(raw["created_lt"]) if raw.get("created_lt") is not None else None),
                           ("time", timestamp(raw.get("created_at"))),
                           ("message_type", raw.get("msg_type")),
                           ("bounced", raw.get("bounced") if type(raw.get("bounced")) is bool else None)):
            merge_fact(row, key, value)
        value = raw.get("value")
        if isinstance(value, dict):
            value = value.get("grams")
        base_units = integer(value)
        if base_units is not None:
            merge_fact(row, "amount_base_units", str(base_units))
            # Decimal placement is exact for arbitrary retained integer width;
            # a display helper must not inherit the process Decimal precision.
            whole, fraction = divmod(base_units, 1_000_000_000)
            merge_fact(row, "amount_decimal", str(whole) + "." + str(fraction).zfill(9))
            merge_fact(row, "asset", "TON")
        opcode = raw.get("opcode", raw.get("op_code"))
        try:
            code = int(opcode, 16 if opcode.lower().startswith("0x") else 10) if isinstance(opcode, str) else opcode
            code = code if type(code) is int and 0 <= code < 2**32 else None
        except (ValueError, TypeError):
            code = None
        if code is not None:
            merge_fact(row, "opcode", f"0x{code:08x}")
        decoded = raw.get("decoded_op_name") or raw.get("decoded_opcode")
        kind = op_names.get(code) or (str(decoded) if isinstance(decoded, str) else None)
        merge_fact(row, "kind", kind)
        if account_id is not None:
            row["sender_account_ids" if side == "out" else "recipient_account_ids"].add(account_id)
            accounts[account_id]["out_message_ids" if side == "out" else "in_message_ids"].add(mid)
        return mid

    def add_account(digest, account_address, oid, source, *, native=None, lt=None, when=None):
        digest = canonical_hash(digest)
        if not digest:
            return None
        aid = "ton:tx:" + digest
        row = accounts.setdefault(aid, {"id": aid, "hash": digest, "sources": set(),
            "observation_ids": set(), "in_message_ids": set(), "out_message_ids": set(),
            "body_observed": False, "conflicts": {}})
        row["sources"].add(source)
        row["observation_ids"].add(oid)
        seed(oid)["accounts"].add(aid)
        seed(oid)["hashes"].add(digest)
        merge_fact(row, "address", account_address)
        merge_fact(row, "lt", str(lt) if lt is not None else None)
        merge_fact(row, "time", timestamp(when))
        if native is not None:
            row["body_observed"] = True
            merge_fact(row, "aborted", native.get("aborted") if type(native.get("aborted")) is bool else None)
        return aid

    def inspect_raw(raw, tx, oid, source, url):
        if not isinstance(raw, dict):
            return
        refs = seed(oid)
        trace = canonical_hash(raw.get("trace_id"))
        if trace:
            refs["trace_ids"].add("ton:trace:" + trace)
        native = raw.get("transaction")
        if isinstance(native, dict):
            transaction_id = native.get("transaction_id") if isinstance(native.get("transaction_id"), dict) else {}
            digest = native.get("hash") or transaction_id.get("hash")
            incoming = native.get("in_msg") if isinstance(native.get("in_msg"), dict) else {}
            own_address = address(native.get("account") or native.get("account_addr") or native.get("address"))
            # The native account body explicitly lists this incoming message.
            # Its destination is the execution account when no account field exists.
            own_address = own_address or address(incoming.get("destination"))
            aid = add_account(digest, own_address, oid, source, native=native,
                lt=native.get("lt") or transaction_id.get("lt"), when=native.get("now") or native.get("utime"))
            add_message(incoming, oid, source, url, aid, "in")
            for msg in native.get("out_msgs") or [] if isinstance(native.get("out_msgs"), list) else []:
                add_message(msg, oid, source, url, aid, "out")
        msg = raw.get("message")
        if isinstance(msg, dict):
            side = "in" if raw.get("message_index") == "in" else "out" if type(raw.get("message_index")) is int else None
            parents = {digest for value in (raw.get("parent_hash"), tx.tx_hash) if (digest := canonical_hash(value))} if side else set()
            parent = next(iter(parents)) if len(parents) == 1 else ""
            aid = add_account(parent, address(msg.get("source" if side == "out" else "destination")), oid, source,
                lt=raw.get("lt")) if parent and side else None
            add_message(msg, oid, source, url, aid, side)
        transfer = raw.get("transfer")
        if isinstance(transfer, dict):
            digest = canonical_hash(transfer.get("transaction_hash"))
            if digest:
                refs["hashes"].add(digest)
            trace = canonical_hash(transfer.get("trace_id"))
            if trace:
                refs["trace_ids"].add("ton:trace:" + trace)
        action = raw.get("action")
        if isinstance(action, dict):
            for name in ("transactions", "base_transactions"):
                for value in action.get(name) or [] if isinstance(action.get(name), list) else []:
                    digest = canonical_hash(value.get("hash") if isinstance(value, dict) else value)
                    if digest:
                        refs["hashes"].add(digest)
            # Full account bodies are explicit evidence, unlike a broad trace ID.
            for value in action.get("transactions_full") or [] if isinstance(action.get("transactions_full"), list) else []:
                if isinstance(value, dict):
                    inspect_raw({"transaction": value}, tx, oid, source, url)

    for tx in report.transactions:
        if tx.chain != "ton":
            continue
        oid = event_identity(tx)
        inspect_raw(tx.raw or {}, tx, oid, tx.source, tx.url)
        for proof in tx.provenance:
            if isinstance(proof, dict) and isinstance(proof.get("raw"), dict):
                inspect_raw(proof["raw"], tx, oid, str(proof.get("source") or tx.source), proof.get("url") or tx.url)

    # Account/message membership is authoritative only if the known execution
    # address agrees with that side of the message. Conflicts stay inspectable.
    for msg in messages.values():
        immutable_conflict = any(field in msg["conflicts"] for field in ("from", "to", "amount_decimal", "amount_base_units"))
        for side, field, address_field in (("out", "sender_account_ids", "from"), ("in", "recipient_account_ids", "to")):
            for aid in list(msg[field]):
                account = accounts[aid]
                known = account.get("address")
                if immutable_conflict or (known and msg.get(address_field) and known != msg[address_field]) or "address" in account["conflicts"]:
                    msg[field].discard(aid)
                    account["out_message_ids" if side == "out" else "in_message_ids"].discard(msg["id"])
        if len(msg["sender_account_ids"]) > 1 or len(msg["recipient_account_ids"]) > 1:
            # One immutable message cannot have two distinct sending/receiving
            # account executions. Retain candidate IDs, but draw no chosen link.
            for field, account_field in (("sender_account_ids", "out_message_ids"), ("recipient_account_ids", "in_message_ids")):
                if len(msg[field]) > 1:
                    msg["conflicts"][field] = sorted(msg[field])
                    for aid in msg[field]:
                        accounts[aid][account_field].discard(msg["id"])
                    msg[field].clear()
    for aid, account in accounts.items():
        if len(account["in_message_ids"]) > 1:
            # Providers can expose different full/normalized external-message
            # hashes for one account TX. Without a retained hash-alias proof,
            # these are alternatives, not simultaneous incoming executions.
            alternatives = sorted(account["in_message_ids"])
            account["conflicts"]["in_message_ids"] = alternatives
            account["alternative_in_message_ids"] = alternatives
            for mid in alternatives:
                messages[mid]["recipient_account_ids"].discard(aid)
            account["in_message_ids"].clear()

    # Every immutable object is stored once. Components are purely display
    # membership over proved in/out hashes; addresses never connect executions.
    parent = {key: key for key in [*accounts, *messages]}

    def find(key):
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def join(a, b):
        left, right = find(a), find(b)
        if left != right:
            parent[max(left, right)] = min(left, right)

    for mid, message in messages.items():
        for aid in message["sender_account_ids"] | message["recipient_account_ids"]:
            join(mid, aid)
    component_rows, component_for = {}, {}
    for key in parent:
        root = find(key)
        cid = "trace-component:" + hashlib.sha256(root.encode()).hexdigest()
        component_for[key] = cid
        row = component_rows.setdefault(cid, {"id": cid, "account_ids": [], "message_ids": [],
            "roots": [], "root_message_ids": [], "complete": False,
            "limitations": ["Retained execution subset; missing message/account sides are not reconstructed."]})
        row["account_ids" if key in accounts else "message_ids"].append(key)
    for row in component_rows.values():
        row["account_ids"].sort()
        row["message_ids"].sort()
        row["roots"] = [aid for aid in row["account_ids"] if not accounts[aid]["in_message_ids"]]
        row["root_message_ids"] = [mid for mid in row["message_ids"] if not messages[mid]["sender_account_ids"]]
        if not row["roots"] and not row["root_message_ids"] and row["account_ids"]:
            row["roots"] = [row["account_ids"][0]]
            row["limitations"].append("No unique execution root in retained data; traversal uses an explicit display entry and guards cycles.")

    groups = [
        {"id": "out", "kind": "financial", "label_ru": "Исходящие операции", "label_en": "Outgoing operations", "record_ids": []},
        {"id": "in", "kind": "financial", "label_ru": "Входящие операции", "label_en": "Incoming operations", "record_ids": []},
        {"id": "self", "kind": "financial", "label_ru": "Операции внутри адреса", "label_en": "Self operations", "record_ids": []},
        {"id": "unknown", "kind": "financial", "label_ru": "Другие финансовые операции", "label_en": "Other financial operations", "record_ids": []},
        {"id": "observations", "kind": "observation", "label_ru": "Все исходные наблюдения", "label_en": "All source observations", "record_ids": []},
    ]
    records, group_by_id = {}, {row["id"]: row for row in groups}
    for view, rows in (("financial", transaction_views), ("observation", observation_views)):
        for index, row in enumerate(rows):
            rid = ("f:" if view == "financial" else "o:") + str(index)
            oid = str(row.get("operation_identity") or "")
            provenance = row.get("financial_provenance") or {}
            oids = {oid} if view == "observation" else set(provenance.get("observation_ids") or []) | set(provenance.get("context_observation_ids") or [])
            if view == "financial" and oid in observation_seeds:
                oids.add(oid)
            direct_accounts, direct_messages, hashes, trace_ids = set(), set(), set(), set()
            for ref in oids:
                known = observation_seeds.get(ref) or {}
                direct_accounts.update(known.get("accounts") or [])
                direct_messages.update(known.get("messages") or [])
                hashes.update(known.get("hashes") or [])
                trace_ids.update(known.get("trace_ids") or [])
            hashes.update(digest for value in [row.get("hash"), *(provenance.get("account_transaction_hashes") or [])]
                          if (digest := canonical_hash(value)))
            direct_accounts.update("ton:tx:" + digest for digest in hashes if "ton:tx:" + digest in accounts)
            mid = None
            if oid.startswith("ton:message:"):
                digest = canonical_hash(oid.split(":")[2])
                mid = "ton:message:" + digest if digest else None
                if mid and mid in messages:
                    direct_messages.add(mid)
            component_ids = sorted({component_for[key] for key in direct_accounts | direct_messages if key in component_for})
            # A full native account body can contain hundreds of contextual
            # messages. Its component is already shared; the record seed only
            # highlights its own immutable message, not every batch sibling.
            selected_messages = {mid} if oid.startswith("ton:message:") and mid in direct_messages else set()
            records[rid] = {"id": rid, "view": view, "row_index": index, "operation_id": oid,
                "observation_ids": sorted(oids), "observation_row_indices": sorted({i for ref in oids for i in observation_rows.get(ref, [])}),
                "account_ids": sorted(direct_accounts), "message_ids": sorted(selected_messages), "component_ids": component_ids,
                "transaction_hashes": sorted(hashes), "trace_ids": sorted(trace_ids), "complete": False,
                "limitations": [] if component_ids else ["No source-bound message execution available for this row; the original observation remains accessible."]}
            direction = row.get("direction") if row.get("direction") in {"in", "out", "self"} else "unknown"
            group_by_id[direction if view == "financial" else "observations"]["record_ids"].append(rid)
    for group in groups:
        group["label"] = group["label_ru" if language == "ru" else "label_en"]
        group["count"] = len(group["record_ids"])

    def portable(row):
        return {key: sorted(value) if isinstance(value, set) else value for key, value in row.items()}

    return {"version": 1, "target": report.target_address,
        "counts": {"financial_operations": len(transaction_views), "observations": len(observation_views),
            "account_transactions": len(accounts), "messages": len(messages), "execution_components": len(component_rows)},
        "groups": groups, "records": records, "accounts": {key: portable(row) for key, row in accounts.items()},
        "messages": {key: portable(row) for key, row in messages.items()}, "components": component_rows,
        "history_complete": False, "source_transactions_modified": False,
        "scope": "Financial operations and source observations remain separate; only exact native message/account hashes establish execution links."}


def _prepare_html_template(
    report: AddressReport,
    graph: dict,
    output_dir: Path,
    language: str = "ru",
):
    output_dir.mkdir(parents=True, exist_ok=True)
    from app.exporters.ton_presentation import TonPresentation
    presentation = TonPresentation(report, graph)
    # The saved owner dossier reconstructs offline reports; its ordinary views
    # are already present here. Exclude only this internal duplicate while
    # preparing the local render copy, before redaction and model validation.
    # The caller's report, stored snapshot and machine exports remain complete.
    exclusions = {"nft_intelligence": {"owner_analysis_snapshot"}}
    if report.attribution_intelligence:
        # Unified facts already retain all legacy TON observations and their
        # pooled raw sources. The compatibility copy is not used by these views.
        exclusions["ton_service_intelligence"] = True
    # AddressReport's inherited before-validator applies portable_observation
    # (including full secret redaction) to this entire tree. An extra outer
    # sanitizer repeats the same walk; retain model/child/URL/HTML guards.
    from app.models.report import validated_report_copy
    report = validated_report_copy(report, exclude=exclusions)
    graph = safe_graph_payload(graph or {})
    nft_data = getattr(report, "nft_intelligence", None)
    service_views = _attribution_views(report)
    for node in graph.get("nodes", []):
        chain = node.get("chain")
        value = node.get("address") or node.get("service_address") or str(node.get("id", "")).split(":", 2)[-1]
        key = node.get("service_key") or (address_id(chain, value) if chain and chain != "multi" else "")
        if key in service_views.get("addresses", {}):
            node["service_key"] = key
    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["safe_href"] = safe_href
    env.filters["safe_image"] = safe_image_url
    env.filters["browser_json"] = _browser_json
    env.filters["packed_browser_json"] = lambda value: pack_json(_browser_json(value), threshold=64 * 1024)
    # Repeated large technical disclosures share one exact guarded value and
    # materialize only when their existing details panel is opened.
    disclosure_pool = {}
    @pass_eval_context
    def deferred_json(eval_ctx, value, indent=None):
        serialized = _browser_json(value)
        if len(serialized) < 16384:
            # Preserve Jinja's original safe JSON escaping/format for small text.
            return env.filters["tojson"](eval_ctx, value, indent=indent)
        key = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        disclosure_pool.setdefault(key, pack_json(serialized, threshold=16384))
        return Markup('<span hidden data-gansar-json-ref="' + key + '" data-json-indent="'
            + str(indent or 0) + '"></span>')
    env.filters["deferred_json"] = deferred_json
    env.filters["ton_display"] = presentation.text
    env.filters["ton_address"] = presentation.address
    env.filters["ton_href"] = presentation.href
    env.filters["ton_short"] = presentation.short
    env.filters["ton_label"] = presentation.label
    template = env.get_template("investigation_template.html")
    graph_json = pack_json(_browser_json(graph or {}))
    graph_icons_json = json.dumps(_graph_icons(), ensure_ascii=False, default=str).replace("</", "<\\/")
    graph_3d_vendor_js = _graph_3d_vendor_js()
    telegram_service_assets = _telegram_service_presentation_assets()
    source_meta = {name: SOURCE_BY_NAME.get(name) for name in report.sources_used}
    source_health = {item.source: item for item in report.source_health}
    language = language if language in I18N else "ru"
    asset_groups = _asset_groups(report, language)
    background = _background_config(output_dir)
    logo = _logo_config(output_dir)
    from app.aggregator.financial_operations import project_financial_operations
    financial_projection = project_financial_operations(report)
    financial_report = report.model_copy(update={"transactions": financial_projection["transactions"]})
    observation_views = _transaction_views(report, language, service_views)
    for row in observation_views:
        row["financial_classification"] = financial_projection["classification"].get(row["operation_identity"], {})
    transaction_views = _transaction_views(financial_report, language, service_views)
    for row, tx in zip(transaction_views, financial_report.transactions):
        projection = (tx.raw or {}).get("_economic_projection")
        if projection:
            row["operation_kind"] = "economic_operation"
            row["kind"] = "token_transfer" if str(tx.asset or "").startswith("JETTON:") else "transfer"
            row["kind_label"] = ("Перевод jetton" if row["kind"] == "token_transfer" else "Перевод TON") if language == "ru" else ("Jetton transfer" if row["kind"] == "token_transfer" else "TON transfer")
            row["direction_label"] = I18N[language].get("sent" if tx.direction == "out" else "received" if tx.direction == "in" else tx.direction, tx.direction)
            row["financial_provenance"] = projection
            row["q"] += " " + " ".join(projection.get("observation_ids", []))
            origin = next((ref for ref in projection.get("observation_ids", []) if ref in service_views.get("transaction_origins", {})), None)
            if origin:
                row["transaction_origin_ref"] = origin
    from app.aggregator.collection_audit import refresh_audit, transaction_digest
    refresh_audit(report, "html", normalized_model_records=len(report.transactions),
        embedded_operation_rows=len(observation_views), embedded_financial_rows=len(transaction_views),
        initial_dom_rows=min(60,len(transaction_views)), page_size=60, ui_page_limit_is_collection_limit=False,
        model_event_ids_sha256=transaction_digest(report.transactions),
        browser_operation_ids_sha256=hashlib.sha256("\n".join(sorted(str(row.get("operation_identity") or "")
            for row in observation_views)).encode()).hexdigest(),
        history_complete=False)
    public_urls = {safe_href(row.get("url")) for row in [*observation_views, *transaction_views]}
    public_urls.update(safe_href(row.get("url")) for row in (nft_data or {}).get("evidence", []))
    ens_view = _ens_summary(report, language)
    ens_profile = ens_view.get("profile") or {}
    public_context = report.public_address_context or {}
    for outcome in public_context.get("outcomes", []):
        if not isinstance(outcome, dict):
            continue
        public_urls.add(safe_href(outcome.get("source_url")))
        for claim in outcome.get("claims", []):
            if isinstance(claim, dict):
                public_urls.add(safe_href(claim.get("source_url")))
                value = claim.get("value") or {}
                if isinstance(value, dict):
                    public_urls.update(safe_href(value.get(field)) for field in ("profile_url", "website"))
    public_urls.update(safe_href(row.get("href")) for row in ens_view.get("record_views", []))
    public_urls.add(safe_href(ens_profile.get("source_url")))
    public_urls.update(safe_href(row.get("source_url")) for row in ens_profile.get("addresses", []))
    # Exact renderer-approved media URLs, not a host or scheme exception for
    # arbitrary metadata. Unavailable media leaves the underlying item intact.
    web3_media_urls = {safe_image_url(ens_view.get("avatar_image"), allow_local=False),
        safe_image_url((ens_profile.get("avatar") or {}).get("url"), allow_local=False),
        safe_image_url((ens_profile.get("avatar") or {}).get("thumbnail"), allow_local=False)}
    for item in (nft_data or {}).get("assets", []):
        web3_media_urls.update(safe_image_url(item.get(field), allow_local=False)
            for field in ("image_url", "thumbnail_url"))
    for outcome in public_context.get("outcomes", []):
        for claim in outcome.get("claims", []) if isinstance(outcome, dict) else []:
            if not isinstance(claim, dict):
                continue
            value = claim.get("value") or {}
            if isinstance(value, dict):
                web3_media_urls.update(safe_image_url(value.get(field), allow_local=False)
                    for field in ("avatar_thumbnail", "avatar_url", "image_url"))
    public_urls.update(row.get("url") for row in service_views.get("evidence", []) if row.get("url"))
    public_urls.update(url for row in service_views.get("addresses", {}).values() for claim in row["attributions"] for url in claim.get("source_urls", []))
    public_urls.update(url for row in service_views.get("addresses", {}).values()
        for field in ("checks", "observations", "rejected_hypotheses", "investigative_leads")
        for check in row.get("client_attribution", {}).get(field, [])
        for url in check.get("source_urls", []) if safe_href(url))
    public_urls.update(safe_href(url) for result in service_views.get("transaction_fingerprints", {}).values()
        for field in ("implementation_observations", "construction_fingerprints", "investigative_leads", "checks")
        for observation in result.get(field, []) for url in observation.get("source_urls", []) if safe_href(url))
    # GANSAR_INFERENTIAL_BEGIN
    public_urls.update(_inferential_public_urls(service_views.get("inferential_intelligence") or {}))
    # GANSAR_INFERENTIAL_END
    # Scoped proof membership is a list of IDs, not another copy of every full
    # provider fact. The browser resolves those IDs against the one proof map.
    browser_services = {**service_views, "addresses": {key:{**{field:value for field,value in record.items() if field!="evidence"},
        "scoped_evidence_ids":[proof["evidence_id"] for proof in record.get("evidence",[])]}
        for key,record in service_views.get("addresses",{}).items()}}
    from app.exporters.source_transport import prepare_source_observations
    browser_pool, source_transport, source_chunks = prepare_source_observations(browser_services.get("source_observations") or {})
    browser_services["source_observations"] = browser_pool
    transaction_tree = _transaction_tree_view(report, transaction_views, observation_views, language)
    browser_payload = {"report": nft_data or {}, "graph": (graph or {}).get("nft_intelligence_graph") or {}, "transaction_views": transaction_views,
        "observation_views": observation_views, "financial_counts": financial_projection["counts"],
        "transaction_tree": transaction_tree,
        "ens": ens_view, "public_address_context": public_context,
        "web3_media_urls": sorted(url for url in web3_media_urls if url),
        "public_urls": sorted(url for url in public_urls if url), "services": browser_services,
        "collection_audit": report.collection_audit}
    if source_transport:
        browser_payload["_source_observation_transport"] = source_transport
    nft_payload_json = pack_json(_browser_json(browser_payload))
    # The original template reads these summary fields and only the lengths of
    # the two sequences. Full transactions, NFT records and source proofs are
    # already supplied through their complete browser payloads below.
    template_report = report.model_dump(include={
        "target_address", "coverage", "detected_chains", "risk_score",
        "collection_audit", "warnings", "errors",
    })
    template_report.update(transactions=report.transactions, counterparties=report.counterparties)
    display_i18n = I18N
    if "ton" in report.detected_chains:
        display_i18n = {key: dict(labels) for key, labels in I18N.items()}
        display_i18n["ru"]["transactions"] = "наблюдений операций"
        display_i18n["en"]["transactions"] = "operation observations"
        display_i18n["ru"]["graph_hint"] += "; денежный граф — native/jetton записи; actions — отдельные наблюдения, покрытие может быть неполным"
        display_i18n["en"]["graph_hint"] += "; financial graph uses native/jetton records; actions are observations and coverage may be partial"
    context = dict(
        report=template_report,
        nft_intelligence=nft_data,
        ton_services=service_views,
        artwork_notices=_artwork_notices(service_views),
        input_resolution=_input_resolution_view(report, language),
        nft_payload_json=nft_payload_json,
        json_decoder_js=decoder_script(),
        payload_transport_js=(Path(__file__).with_name("assets") / "payload-transport.js").read_text(encoding="utf-8"),
        disclosure_pool=disclosure_pool,
        ton_presentation_json=_browser_json(presentation.mapping),
        ton_presentation_js=(Path(__file__).with_name("assets") / "ton-presentation.js").read_text(encoding="utf-8"),
        source_observation_chunks=source_chunks,
        transaction_total=len(observation_views),
        financial_total=len(transaction_views),
        financial_counts=financial_projection["counts"],
        graph=graph,
        graph_json=graph_json,
        graph_icons_json=graph_icons_json,
        graph_3d_vendor_js=graph_3d_vendor_js,
        telegram_service_css=telegram_service_assets["css"],
        telegram_service_js=telegram_service_assets["js"],
        telegram_service_artwork_json=_browser_json(_telegram_service_local_logos()),
        language=language,
        i18n=display_i18n,
        t=display_i18n[language],
        background=background,
        logo=logo,
        source_meta=source_meta,
        source_health=source_health,
        source_health_labels=_source_health_labels(source_health, language),
        source_capabilities=_source_capabilities(source_meta),
        chain_summaries=_chain_summaries(report),
        chain_labels={chain: _chain_label(chain) for chain in report.detected_chains},
        balance_views=_balance_views(report),
        bsc_summary=_bsc_summary(report),
        dogecoin_summary=_dogecoin_summary(report),
        tron_summary=_tron_summary(report),
        solana_summary=_solana_summary(report),
        ton_insights=_ton_insights(report),
        ton_activity=_ton_activity_signal_views(report, language, presentation),
        tron_activity=_tron_activity_signal_views(report, language),
        dogecoin_activity=_dogecoin_activity_signal_views(report, language),
        wallet_migration=_wallet_migration_view(report, language, presentation),
        behavioral_fingerprint=_behavioral_fingerprint_view(report, language),
        address_story=_address_story(report, language, presentation),
        wallet_behavior=_wallet_behavior(report),
        asset_groups=asset_groups,
        asset_group_list=list(asset_groups.values()),
        token_asset_groups=_token_asset_groups(report, language),
        username_history=_username_history(report, language),
        gift_tracing=_gift_tracing(report, language),
        gift_route_intelligence=_gift_route_intelligence(report, language),
        jetton_flows=_jetton_flow_analysis(financial_report, language),
        asset_total=_asset_total(report),
        asset_counts=_asset_counts(asset_groups),
        observations=_observations(report, language),
        bitcoin_summary=_bitcoin_summary(report),
        telegram_summary=_telegram_summary(report, language),
        ens_summary=_ens_summary(report, language),
        asset_paths=_asset_paths(report),
        transaction_views=transaction_views[:60],
    )
    return template, context


def render_html_report(
    report: AddressReport,
    graph: dict,
    output_dir: Path,
    language: str = "ru",
) -> str:
    template, context = _prepare_html_template(report, graph, output_dir, language)
    html = template.render(**context)
    # Explicit string-return callers retain their original API. Production
    # file exports below never assemble this full Unicode document in memory.
    del context, template
    return guard_rendered_html(html)


def export_html_report(report: AddressReport, graph: dict, output_dir: Path,
                       filename: str = "report.html", language: str = "ru") -> HtmlExportResult:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    template, context = _prepare_html_template(report, graph, output_dir, language)
    out = output_dir / filename
    temporary = out.with_name(out.name + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            for part in guard_rendered_chunks(template.generate(**context)):
                stream.write(part)
        temporary.replace(out)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return HtmlExportResult(output_path=out)
