from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SourceInfo:
    name: str
    chains: tuple[str, ...]
    source_type: str
    reliability: str
    rate_limit: str
    capabilities: tuple[str, ...]


SOURCE_REGISTRY: tuple[SourceInfo, ...] = (
    SourceInfo("mempool_space", ("btc",), "api", "high", "public shared", ("balance", "transactions", "utxo_view")),
    SourceInfo("blockstream_esplora", ("btc",), "api", "high", "public shared", ("balance", "transactions", "utxo_view")),
    SourceInfo("blockchair_dogecoin", ("doge",), "api", "medium", "public shared", ("balance", "transactions", "utxo_view", "stats")),
    SourceInfo("sochain_dogecoin", ("doge",), "api", "medium", "optional API key", ("balance", "transactions", "utxo_view")),
    SourceInfo("oklink_dogecoin", ("doge",), "api", "medium", "optional API key", ("balance", "transactions", "labels")),
    SourceInfo("dogechain_explorer", ("doge",), "html", "low", "public page may block", ("explorer_evidence",)),
    SourceInfo("dogecoin_core_rpc", ("doge",), "rpc", "medium", "optional local node", ("stats", "mempool_status")),
    SourceInfo("bitquery_dogecoin", ("doge",), "api", "medium", "optional API key", ("transactions", "labels")),
    SourceInfo("getblock_dogecoin", ("doge",), "rpc", "medium", "optional API key", ("transactions", "utxo_view")),
    SourceInfo("etherscan_api", ("eth",), "api", "high", "optional API key", ("balance", "transactions", "tokens", "nft_transfers", "contract_state")),
    SourceInfo("blockchair_ethereum", ("eth",), "api", "medium", "public shared", ("balance", "transactions", "contract_hints")),
    SourceInfo("ethplorer", ("eth",), "api", "medium", "public freekey or optional API key", ("balance", "transactions", "tokens", "contract_hints")),
    SourceInfo("ethereum_labels", ("eth",), "api", "medium", "optional API key", ("labels",)),
    SourceInfo("ethereum_rpc", ("eth",), "rpc", "medium", "public shared", ("balance", "nonce")),
    SourceInfo("ethereum_ens", ("eth",), "rpc", "medium", "public shared", ("ens_reverse_lookup", "ens_forward_lookup", "resolver", "text_records")),
    SourceInfo("etherscan_html", ("eth",), "html", "low", "anti-bot prone", ("labels", "tokens")),
    SourceInfo("bscscan_api", ("bsc",), "api", "medium", "key required for BNB Chain V2", ("balance", "transactions", "internal_transactions", "bep20_transfers", "nft_transfers", "contract_state")),
    SourceInfo("bsc_intel", ("bsc",), "api+rpc", "medium", "public shared", ("balance", "nonce", "contract_state", "bep20_balances", "bep20_transfers", "nft_transfers", "approvals", "token_metadata", "images", "security", "dex_liquidity", "labels")),
    SourceInfo("bsc_rpc", ("bsc",), "rpc", "medium", "10k/5min public endpoint", ("balance", "nonce")),
    SourceInfo("bscscan_html", ("bsc",), "html", "low", "anti-bot prone", ("labels",)),
    SourceInfo("polygon_rpc", ("polygon",), "rpc", "medium", "public shared", ("balance", "nonce")),
    SourceInfo("polygonscan_html", ("polygon",), "html", "low", "anti-bot prone", ("labels",)),
    SourceInfo("arbitrum_rpc", ("arbitrum",), "rpc", "medium", "public shared", ("balance", "nonce")),
    SourceInfo("arbiscan_html", ("arbitrum",), "html", "low", "anti-bot prone", ("labels",)),
    SourceInfo("optimism_rpc", ("optimism",), "rpc", "medium", "rate-limited public endpoint", ("balance", "nonce")),
    SourceInfo("optimistic_etherscan_html", ("optimism",), "html", "low", "anti-bot prone", ("labels",)),
    SourceInfo("avalanche_rpc", ("avalanche",), "rpc", "medium", "public shared", ("balance", "nonce")),
    SourceInfo("tronscan", ("tron",), "api", "medium", "public shared", ("balance", "transactions", "trc20_balances", "trc20_transfers", "resources", "token_metadata", "images")),
    SourceInfo("trongrid", ("tron",), "api", "medium", "public shared", ("balance", "transactions", "trc20_transfers", "token_metadata")),
    SourceInfo("tonapi", ("ton",), "api", "high", "public shared", ("balance", "transactions", "jettons")),
    SourceInfo("tonconsole", ("ton",), "api", "medium", "optional API key", ("balance", "transactions", "jettons", "nfts")),
    SourceInfo("toncenter", ("ton",), "api", "medium", "1 rps without API key", ("transactions",)),
    SourceInfo("toncenter_v3", ("ton",), "api", "experimental", "public shared, 429-prone", ("labels", "jetton_transfers", "nft_items", "nft_transfers", "contract_state")),
    SourceInfo("telegram_identity", ("ton",), "api+html", "experimental", "public pages", ("telegram_usernames", "telegram_ids_if_public", "dns_identity", "gift_identity")),
    SourceInfo("fragment_public", ("ton",), "html", "experimental", "public pages", ("usernames", "domains", "gifts", "marketplace_metadata")),
    SourceInfo("tonviewer_public", ("ton",), "html", "medium", "public pages", ("labels", "explorer_evidence")),
    SourceInfo("tonscan_public", ("ton",), "html", "experimental", "public pages", ("labels", "explorer_evidence")),
    SourceInfo("getgems_public", ("ton",), "html", "experimental", "public pages", ("nft_cards", "images", "marketplace_metadata")),
    SourceInfo("dton_public", ("ton",), "html", "experimental", "public pages", ("labels", "analytics_evidence")),
    SourceInfo("solscan_public_api", ("solana",), "api", "low", "public API unavailable, explorer fallback", ("explorer_evidence",)),
    SourceInfo("solana_rpc", ("solana",), "rpc", "medium", "public shared", ("balance", "account_info", "signatures", "transactions_decoded", "token_accounts", "spl_tokens")),
    SourceInfo("cryptoscamdb", ("multi",), "api", "experimental", "public shared, intermittent 5xx", ("blacklist",)),
)


SOURCE_REGISTRY += tuple(SourceInfo("sourcify_"+chain,(chain,),"public api","medium","public bounded; no key",
    ("verified_contract_metadata","deployment_relation","proxy_resolution"))
    for chain in ("eth","bsc","polygon","arbitrum","optimism","avalanche"))
SOURCE_REGISTRY += (SourceInfo("tron_contract_metadata",("tron",),"public api","medium","public bounded; no key",("contract_metadata","creator","proxy_resolution")),)
SOURCE_REGISTRY += tuple(SourceInfo("etherscan_api_" + chain, (chain,), "api", "high", "optional API key; provider plan availability",
    ("balance", "transactions", "tokens", "nft_transfers", "contract_state", "resumable_history"))
    for chain in ("polygon", "arbitrum", "optimism", "avalanche"))
SOURCE_REGISTRY += tuple(SourceInfo("blockscout_"+chain,(chain,),"public api","medium","verified legacy instance; migration may require free API key",
    ("native_history","erc20_transfers","internal_call_context","resumable_history")) for chain in ("eth","optimism"))
SOURCE_REGISTRY += tuple(SourceInfo("blockcypher_"+chain,(chain,),"public api","medium","bounded no-key fallback; shared free-tier quota",
    ("balance","transactions","exact_utxo_details","source_verification")) for chain in ("btc","doge"))
SOURCE_REGISTRY += (SourceInfo("wormholescan", ("eth","bsc","polygon","arbitrum","optimism","avalanche"), "public api", "medium", "bounded documented address lookup plus exact public RPC receipts; no retries",
    ("cross_chain_message_evidence","exact_redemption_receipts","no_financial_rows")),)
SOURCE_REGISTRY += (
    SourceInfo("lens_public", ("eth","bsc","polygon","arbitrum","optimism","avalanche"), "public api", "medium",
        "target only; 1 request/second; bounded response cache", ("public_lens_account_roles", "self_published_profile", "no_financial_rows")),
    SourceInfo("basenames", ("eth","bsc","polygon","arbitrum","optimism","avalanche"), "public rpc", "medium",
        "target only; Base chain context 8453; bounded", ("base_name_resolution", "primary_forward_check", "profile_records", "no_base_financial_claim")),
    SourceInfo("eas_eth", ("eth",), "public api", "medium", "target only; bounded read; 300-second cache",
        ("indexed_onchain_attestations", "author_recipient_roles", "revocation_expiry", "no_identity_confirmation")),
)
SOURCE_BY_NAME = {source.name: source for source in SOURCE_REGISTRY}
