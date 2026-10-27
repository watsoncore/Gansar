from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class SourcePlan:
    name: str
    priority: int
    timeout: float
    retries: int = 0
    health_score: float = 1.0
    parsing_confidence: float = 0.6
    fallback_role: str = "default"
    last_success: datetime | None = None
    last_fail: datetime | None = None
    fail_count: int = 0
    enabled: bool = True
    recovery_seconds: float = 60.0
    half_open: bool = False


class SourceManager:
    def __init__(self, plans: dict[str, SourcePlan]):
        self._plans = plans

    def plan(self, name: str, default_timeout: float) -> SourcePlan:
        plan = self._plans.get(name)
        if plan is None:
            plan = SourcePlan(name=name, priority=50, timeout=default_timeout)
            self._plans[name] = plan
        return plan

    def timeout(self, name: str, default_timeout: float) -> float:
        return self.plan(name, default_timeout).timeout

    def retries(self, name: str, default_timeout: float) -> int:
        return self.plan(name, default_timeout).retries

    def priority(self, name: str) -> int:
        return self._plans.get(name, SourcePlan(name=name, priority=50, timeout=5)).priority

    def should_run(self, name: str, default_timeout: float) -> bool:
        plan = self.plan(name, default_timeout)
        if (not plan.enabled or plan.fail_count >= 3 or plan.health_score < 0.2) and plan.last_fail:
            elapsed = (datetime.now(timezone.utc) - plan.last_fail).total_seconds()
            if elapsed >= plan.recovery_seconds and not plan.half_open:
                plan.half_open = True
                return True
            return False
        return plan.enabled and plan.fail_count < 3 and plan.health_score >= 0.2

    def record_success(self, name: str, parsing_confidence: float | None = None) -> None:
        plan = self.plan(name, 5.0)
        plan.last_success = datetime.now(timezone.utc)
        plan.fail_count = 0
        plan.health_score = min(1.0, max(0.35, plan.health_score + 0.12))
        plan.enabled = True
        plan.half_open = False
        if parsing_confidence is not None:
            plan.parsing_confidence = max(plan.parsing_confidence, parsing_confidence)

    def record_fail(self, name: str) -> None:
        plan = self.plan(name, 5.0)
        plan.last_fail = datetime.now(timezone.utc)
        plan.half_open = False
        plan.fail_count += 1
        plan.health_score = max(0.0, plan.health_score - 0.22)
        if plan.fail_count >= 3:
            plan.enabled = False

    def details(self, name: str, default_timeout: float) -> str:
        plan = self.plan(name, default_timeout)
        parts = [plan.fallback_role, f"health={plan.health_score:.2f}", f"confidence={plan.parsing_confidence:.2f}"]
        if plan.last_success:
            parts.append(f"last_success={plan.last_success.isoformat()}")
        if plan.last_fail:
            parts.append(f"last_fail={plan.last_fail.isoformat()}")
        return "; ".join(parts)


def build_default_source_manager() -> SourceManager:
    return SourceManager(
        {
            "tonapi": SourcePlan("tonapi", 0, 36.0, retries=0, parsing_confidence=0.86),
            "tonconsole": SourcePlan("tonconsole", 1, 12.0, retries=0, parsing_confidence=0.84, fallback_role="authenticated_fallback"),
            "tonviewer_public": SourcePlan("tonviewer_public", 1, 10.0, retries=1, parsing_confidence=0.68),
            "toncenter": SourcePlan("toncenter", 2, 7.0, retries=0, parsing_confidence=0.72, fallback_role="fallback"),
            "toncenter_v3": SourcePlan("toncenter_v3", 3, 8.0, retries=0, parsing_confidence=0.76, fallback_role="asset_fallback"),
            "tonscan_public": SourcePlan("tonscan_public", 6, 3.5, retries=0, health_score=0.7, parsing_confidence=0.38, fallback_role="experimental"),
            "dton_public": SourcePlan("dton_public", 7, 3.5, retries=0, health_score=0.7, parsing_confidence=0.34, fallback_role="experimental"),
            "getgems_public": SourcePlan("getgems_public", 8, 6.0, retries=0, health_score=0.55, parsing_confidence=0.52, fallback_role="experimental"),
            "fragment_public": SourcePlan("fragment_public", 9, 6.0, retries=0, health_score=0.55, parsing_confidence=0.52, fallback_role="experimental"),
            "telegram_identity": SourcePlan("telegram_identity", 10, 9.0, retries=0, health_score=0.55, parsing_confidence=0.58, fallback_role="identity_fallback"),
            "blockstream_esplora": SourcePlan("blockstream_esplora", 0, 4.0, retries=1, parsing_confidence=0.8),
            "mempool_space": SourcePlan("mempool_space", 1, 4.0, retries=1, parsing_confidence=0.78, fallback_role="fallback"),
            "wormholescan": SourcePlan("wormholescan", 2, 8.0, retries=0, parsing_confidence=0.70, fallback_role="exact_protocol_evidence_no_financial_rows"),
            "blockcypher_btc": SourcePlan("blockcypher_btc", 3, 16.0, retries=0, parsing_confidence=0.72, fallback_role="public_history_fallback"),
            "blockcypher_doge": SourcePlan("blockcypher_doge", 3, 16.0, retries=0, parsing_confidence=0.72, fallback_role="public_history_fallback"),
            "blockscout_eth": SourcePlan("blockscout_eth", 1, 12.0, retries=0, parsing_confidence=0.76, fallback_role="public_indexed_history"),
            "blockscout_optimism": SourcePlan("blockscout_optimism", 1, 12.0, retries=0, parsing_confidence=0.76, fallback_role="public_indexed_history"),
            "blockchair_dogecoin": SourcePlan("blockchair_dogecoin", 0, 12.0, retries=1, parsing_confidence=0.78),
            "sochain_dogecoin": SourcePlan("sochain_dogecoin", 1, 4.0, retries=0, parsing_confidence=0.62, fallback_role="key_required_fallback"),
            "oklink_dogecoin": SourcePlan("oklink_dogecoin", 2, 4.0, retries=0, parsing_confidence=0.62, fallback_role="key_required_fallback"),
            "dogechain_explorer": SourcePlan("dogechain_explorer", 3, 4.0, retries=0, parsing_confidence=0.32, fallback_role="explorer_link"),
            "dogecoin_core_rpc": SourcePlan("dogecoin_core_rpc", 4, 4.0, retries=0, parsing_confidence=0.7, fallback_role="optional_local_rpc"),
            "bitquery_dogecoin": SourcePlan("bitquery_dogecoin", 5, 3.0, retries=0, parsing_confidence=0.48, fallback_role="key_required_skeleton"),
            "getblock_dogecoin": SourcePlan("getblock_dogecoin", 6, 3.0, retries=0, parsing_confidence=0.48, fallback_role="key_required_skeleton"),
            "etherscan_api": SourcePlan("etherscan_api", 0, 5.0, retries=0, parsing_confidence=0.84, fallback_role="authenticated_primary"),
            "ethereum_rpc": SourcePlan("ethereum_rpc", 0, 4.0, retries=1, parsing_confidence=0.65),
            "ethereum_ens": SourcePlan("ethereum_ens", 1, 24.0, retries=0, parsing_confidence=0.76, fallback_role="identity_lookup"),
            "lens_public": SourcePlan("lens_public", 10, 10.0, retries=0, parsing_confidence=0.6, fallback_role="target_only_public_context"),
            "basenames": SourcePlan("basenames", 10, 14.0, retries=0, parsing_confidence=0.7, fallback_role="target_only_base_identity"),
            "eas_eth": SourcePlan("eas_eth", 10, 6.0, retries=0, parsing_confidence=0.6, fallback_role="target_only_public_assertions"),
            "blockchair_ethereum": SourcePlan("blockchair_ethereum", 1, 4.0, retries=0, parsing_confidence=0.62, fallback_role="fallback"),
            "ethplorer": SourcePlan("ethplorer", 2, 4.0, retries=0, parsing_confidence=0.62, fallback_role="public_token_fallback"),
            "ethereum_labels": SourcePlan("ethereum_labels", 4, 4.0, retries=0, health_score=0.8, parsing_confidence=0.62, fallback_role="label_fallback"),
            "etherscan_html": SourcePlan("etherscan_html", 5, 4.0, retries=0, health_score=0.55, parsing_confidence=0.36, fallback_role="experimental"),
            "bscscan_api": SourcePlan("bscscan_api", 0, 4.0, retries=0, parsing_confidence=0.82, fallback_role="key_required_primary"),
            "bsc_intel": SourcePlan("bsc_intel", 0, 42.0, retries=0, parsing_confidence=0.72, fallback_role="public_bsc_enrichment"),
            "bsc_rpc": SourcePlan("bsc_rpc", 1, 4.0, retries=1, parsing_confidence=0.65),
            "polygon_rpc": SourcePlan("polygon_rpc", 1, 4.0, retries=1, parsing_confidence=0.65),
            "arbitrum_rpc": SourcePlan("arbitrum_rpc", 1, 4.0, retries=1, parsing_confidence=0.65),
            "optimism_rpc": SourcePlan("optimism_rpc", 1, 4.0, retries=1, parsing_confidence=0.65),
            "avalanche_rpc": SourcePlan("avalanche_rpc", 1, 4.0, retries=1, parsing_confidence=0.65),
            "tronscan": SourcePlan("tronscan", 0, 5.0, retries=1, parsing_confidence=0.76),
            "trongrid": SourcePlan("trongrid", 1, 5.0, retries=1, parsing_confidence=0.7, fallback_role="fallback"),
            "solscan_public_api": SourcePlan("solscan_public_api", 0, 2.0, retries=0, parsing_confidence=0.2, fallback_role="explorer_link"),
            "solana_rpc": SourcePlan("solana_rpc", 1, 15.0, retries=0, parsing_confidence=0.7),
            "cryptoscamdb": SourcePlan("cryptoscamdb", 20, 3.0, retries=0, health_score=0.5, parsing_confidence=0.5, fallback_role="experimental"),
        }
    )
