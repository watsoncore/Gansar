from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from app.models.report import AddressReport, RiskFlag, Transaction


def score_risk(report: AddressReport) -> tuple[int, list[RiskFlag]]:
    score = 0
    flags: list[RiskFlag] = []
    from app.utils.event_identity import transaction_success
    txs = [t for t in report.transactions if transaction_success(t) is not False and str((t.raw or {}).get("type") or "").lower() not in {"approval", "approval_for_all"}]

    if not txs:
        return (40 if any(flag.severity == "high" for flag in report.risk_flags) else 0), []

    small_in = 0
    out_to_one: Counter[str] = Counter()
    out_counterparties: Counter[str] = Counter()
    timepoints = []
    chain_counts = Counter([t.chain for t in txs])
    by_chain_time = defaultdict(list)

    for t in txs:
        if t.timestamp:
            timepoints.append(t.timestamp)
            by_chain_time[t.chain].append(t.timestamp)
        if t.direction == "in" and t.amount is not None and t.amount > 0 and t.amount < 0.01:
            small_in += 1
        if t.direction == "out" and t.to_address:
            out_to_one[t.to_address] += 1
            out_counterparties[t.to_address] += 1

    if small_in >= 25:
        score += 18
        flags.append(
            RiskFlag(
                chain="multi",
                address=report.target_address,
                flag="many_small_incoming",
                severity="medium",
                source="heuristics",
                details=f"Small incoming tx count: {small_in}",
            )
        )

    if out_to_one:
        addr, cnt = out_to_one.most_common(1)[0]
        if cnt >= 15:
            score += 14
            flags.append(
                RiskFlag(
                    chain="multi",
                    address=report.target_address,
                    flag="many_outgoing_to_one",
                    severity="medium",
                    source="heuristics",
                    details=f"Outgoing tx to one address: {cnt} -> {addr}",
                )
            )

    if timepoints:
        timepoints.sort()
        span = timepoints[-1] - timepoints[0]
        if span <= timedelta(hours=2) and len(timepoints) >= 40:
            score += 18
            flags.append(
                RiskFlag(
                    chain="multi",
                    address=report.target_address,
                    flag="high_activity_short_window",
                    severity="high",
                    source="heuristics",
                    details=f"{len(timepoints)} tx within {span}",
            )
        )

    for chain, points in by_chain_time.items():
        points.sort()
        if len(points) >= 20 and points[-1] - points[0] <= timedelta(minutes=30):
            score += 12
            flags.append(
                RiskFlag(
                    chain=chain,
                    address=report.target_address,
                    flag="chain_velocity_burst",
                    severity="medium",
                    source="heuristics",
                    details=f"{len(points)} {chain} tx within {points[-1] - points[0]}",
                )
            )

    outgoing = [c for c in report.counterparties if c.total_out > 0]
    if len(outgoing) >= 20 and sum(1 for c in outgoing if c.tx_count <= 2) >= 15:
        score += 16
        flags.append(
            RiskFlag(
                chain="multi",
                address=report.target_address,
                flag="fanout_mixer_like_pattern",
                severity="medium",
                source="heuristics",
                details=f"Outgoing spread across {len(outgoing)} counterparties",
            )
        )

    exchange_labels = ("binance", "coinbase", "kraken", "okx", "bybit", "kucoin", "gate", "mexc", "huobi", "htx", "bitget", "exchange")
    exchange_out = 0
    for c in report.counterparties:
        if c.total_out > 0 and any(marker in label.lower() for label in c.labels for marker in exchange_labels):
            exchange_out += c.tx_count
    if exchange_out >= 8:
        score += 8
        flags.append(
            RiskFlag(
                chain="multi",
                address=report.target_address,
                flag="repeated_exchange_deposit_behavior",
                severity="low",
                source="heuristics",
                details=f"Outgoing tx to labeled exchanges: {exchange_out}",
            )
        )

    if len(chain_counts) >= 4 and sum(chain_counts.values()) >= 10:
        score += 8
        flags.append(
            RiskFlag(
                chain="multi",
                address=report.target_address,
                flag="broad_multichain_activity",
                severity="low",
                source="heuristics",
                details=", ".join(f"{chain}:{count}" for chain, count in chain_counts.items()),
            )
        )

    contract_like = 0
    for tok in report.tokens:
        if tok.contract and tok.chain in {"eth", "bsc", "polygon", "arbitrum", "optimism", "avalanche"}:
            contract_like += 1
    if contract_like >= 5:
        score += 10
        flags.append(
            RiskFlag(
                chain="multi",
                address=report.target_address,
                flag="contract_interactions_detected",
                severity="low",
                source="heuristics",
                details=f"Contract-like interactions: {contract_like}",
            )
        )

    external_high = sum(1 for rf in report.risk_flags if rf.severity == "high")
    if external_high:
        score += 40

    return min(100, score), flags

