from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, localcontext
import hashlib
import json
from typing import Any

from app.utils.ton_normalize import ton_canonical_address

from .models import (CollectionCoverage, CoverageStatus, NFTEvent, NFTIntelligenceReport,
                     NFTPortfolio, Money, VerificationStatus)


def canonical_hash(value: Any) -> str | None:
    if not value:
        return None
    import base64
    text = str(value).removeprefix("0x")
    if len(text) == 64:
        try:
            bytes.fromhex(text)
            return text.lower()
        except ValueError:
            pass
    try:
        raw = base64.b64decode(text.replace("-", "+").replace("_", "/") + "=" * (-len(text) % 4), validate=True)
        if len(raw) == 32:
            return raw.hex()
    except Exception:
        pass
    return str(value)


def event_identity(source: str, asset: str, kind: str, *, transaction_hash: str | None = None,
                   trace_id: str | None = None, logical_time: int | None = None,
                   action_index: int | None = None, message_hash: str | None = None,
                   query_id: str | None = None, raw: dict | None = None,
                   occurrence: int = 0) -> str:
    """Merge only records with a strong shared namespace, never hash alone.

    Indexed action position belongs to a provider's trace, not to another
    provider's transaction. Unindexed records use the complete response record
    plus an occurrence ordinal; this preserves identical multiple actions.
    """
    body: dict[str, Any] = {"source": source, "asset": asset, "kind": kind,
                            "transaction": canonical_hash(transaction_hash),
                            "trace": canonical_hash(trace_id), "lt": logical_time}
    if message_hash:
        body["message"] = canonical_hash(message_hash)
    elif action_index is not None:
        body["action_index"] = action_index
    else:
        body["query_id"] = query_id
        body["raw"] = raw or {}
        body["occurrence"] = occurrence
    return "ton:nft:event:" + hashlib.sha256(json.dumps(body, sort_keys=True, default=str,
                                       separators=(",", ":")).encode()).hexdigest()


def money_from_price(value: Any, *, default_currency: str | None = None,
                     default_decimals: int | None = None) -> Money | None:
    if value is None:
        return None
    if isinstance(value, dict):
        currency = value.get("currency_type") or value.get("currency") or value.get("token_name") or default_currency
        units = value.get("value", value.get("amount"))
        decimals = value.get("decimals", default_decimals)
        contract = ton_canonical_address(value.get("jetton") or value.get("token_contract"))
    else:
        currency, units, decimals, contract = default_currency, value, default_decimals, None
    if not currency or units is None:
        return None
    if str(currency).lower() == "ton":
        currency = "TON"
    try:
        base_units = int(str(units))
        dec = int(decimals) if decimals is not None else None
        if dec is not None and not 0 <= dec <= 255:
            return None
        with localcontext() as context:
            context.prec = max(80, len(str(abs(base_units))) + (dec or 0) + 2)
            amount = Decimal(base_units).scaleb(-dec) if dec is not None else None
        return Money(currency=str(currency), token_contract=contract, base_units=base_units,
                     decimals=dec, amount=amount)
    except (ValueError, TypeError, ArithmeticError):
        return None


def event_sort_key(event: NFTEvent) -> tuple:
    # Native logical time is authoritative for TON ordering. Unknown records
    # remain at the end and are never used to infer time intervals.
    return (event.logical_time is None, event.logical_time or 0,
            event.timestamp or datetime.max.replace(tzinfo=timezone.utc),
            event.action_index if event.action_index is not None else 2**31, event.event_id)


def merge_event(existing: NFTEvent, incoming: NFTEvent) -> NFTEvent:
    for name in ("evidence_ids", "observation_ids", "provider_event_ids"):
        setattr(existing, name, list(dict.fromkeys(getattr(existing, name) + getattr(incoming, name))))
    # Keep each raw observation reference, and never silently upgrade failure.
    if existing.status != incoming.status:
        existing.raw.setdefault("status_conflicts", []).append({"status": incoming.status,
                                                               "observation_ids": incoming.observation_ids})
        existing.status = "unknown"
    for key, value in incoming.raw.items():
        existing.raw.setdefault(key, value)
    return existing


def analyze_report(report: NFTIntelligenceReport, wallet: str | None = None) -> None:
    before_corroboration = len(report.events)
    report.events = corroborate_events(report.events, report.assets)
    report.stats["corroborated_event_records"] = report.stats.get("corroborated_event_records", 0) + before_corroboration-len(report.events)
    report.events.sort(key=event_sort_key)
    by_asset: dict[str, list[NFTEvent]] = defaultdict(list)
    for event in report.events:
        by_asset[event.asset_address].append(event)
    signals = []
    wallet_pairs: dict[tuple[str, str], set[str]] = defaultdict(set)
    related_wallets = set()
    for asset in report.assets:
        events = by_asset[asset.address]
        asset.event_ids = [e.event_id for e in events]
        transfers = [e for e in events if e.event_type in {"transfer", "mint"} and e.status == "success"
                     and e.verification == VerificationStatus.VERIFIED_ONCHAIN]
        owners: dict[str, dict] = {}
        chain: list[str] = []
        last = None
        for event in transfers:
            for address, role in ((event.from_address, "sender"), (event.to_address, "recipient")):
                if address:
                    related_wallets.add(address)
                    entry = owners.setdefault(address, {"address": address, "event_ids": [], "evidence_ids": [],
                        "first_observed_at": event.timestamp, "last_observed_at": event.timestamp,
                        "logical_times": [], "transaction_hashes": [], "roles": []})
                    entry["event_ids"].append(event.event_id)
                    entry["evidence_ids"] = list(dict.fromkeys(entry["evidence_ids"] + event.evidence_ids))
                    entry["last_observed_at"] = event.timestamp or entry["last_observed_at"]
                    if event.logical_time is not None:
                        entry["logical_times"].append(event.logical_time)
                    if event.transaction_hash:
                        entry["transaction_hashes"].append(event.transaction_hash)
                    if role not in entry["roles"]:
                        entry["roles"].append(role)
            if event.from_address and event.to_address:
                wallet_pairs[(event.from_address, event.to_address)].add(asset.address)
                if not chain:
                    chain.append(event.from_address)
                if chain[-1] != event.from_address:
                    signals.append({"type": "ownership_history_gap", "asset_address": asset.address,
                        "event_ids": [event.event_id], "classification": "data_limitation",
                        "explanation": "Sender differs from last observed owner; missing events or provider interpretation conflict"})
                if event.to_address in chain and event.to_address != event.from_address:
                    signals.append({"type": "return_to_previous_owner", "asset_address": asset.address,
                        "wallet_address": event.to_address, "event_ids": [event.event_id],
                        "evidence_ids": event.evidence_ids, "classification": "observed_pattern",
                        "explanation": "NFT returned to a previously observed wallet; this does not establish common control"})
                chain.append(event.to_address)
            if last and last.timestamp and event.timestamp and 0 <= (event.timestamp-last.timestamp).total_seconds() <= 3600:
                signals.append({"type": "rapid_nft_transfers", "asset_address": asset.address,
                    "event_ids": [last.event_id, event.event_id], "classification": "heuristic",
                    "seconds": (event.timestamp-last.timestamp).total_seconds(),
                    "explanation": "Two observed successful transitions within one hour; no motive or identity inferred"})
            last = event
        intervals = []
        for first, second in zip(transfers, transfers[1:]):
            if (first.to_address and first.to_address == second.from_address and first.timestamp and second.timestamp
                    and second.timestamp >= first.timestamp):
                intervals.append({"owner_address": first.to_address, "start": first.timestamp, "end": second.timestamp,
                                  "seconds": (second.timestamp-first.timestamp).total_seconds(),
                                  "event_ids": [first.event_id, second.event_id], "bounded_observation": True})
        asset.historical_owners = list(owners.values())
        asset.ownership_summary = {"observed_transfer_count": len(transfers), "unique_observed_owners": len(owners),
            "first_observed_owner": transfers[0].from_address or transfers[0].to_address if transfers else None,
            "first_observed_transaction": transfers[0].transaction_hash if transfers else None,
            "last_observed_transfer": transfers[-1].model_dump(mode="json") if transfers else None,
            "ownership_intervals": intervals, "is_genesis_proven": False,
            "history_status": _asset_history_status(report, asset.address),
            "notes": ["First observed owner is not asserted to be original owner; history may be partial"]}
        asset.ownership_summary["provider_reported_successful_actions"] = sum(e.status == "success" and
            e.verification == VerificationStatus.PROVIDER_REPORTED for e in events)
        sales = [e for e in events if e.event_type == "sale" and e.status == "success" and e.money]
        asset.last_confirmed_sale = sales[-1].money if sales else None
    for (source, destination), assets in wallet_pairs.items():
        if len(assets) >= 3:
            signals.append({"type": "multiple_nfts_same_route", "from_address": source, "to_address": destination,
                "asset_addresses": sorted(assets), "classification": "observed_pattern",
                "explanation": "Three or more observed NFTs use this directed route; no common owner assumption"})
    report.signals = signals
    report.related_wallets = sorted(related_wallets)
    if wallet:
        report.portfolio = build_portfolio(report, wallet)
    report.stats.update({"assets": len(report.assets), "collections": len(report.collections),
                         "unique_events": len(report.events), "evidence": len(report.evidence),
                         "observations": len(report.observations), "coverage_complete": False,
                         "parser_version": "1.0.0", "signals": len(signals),
                         "provider_pages": sum(c.pages for c in report.coverage),
                         "provider_records": sum(c.records for c in report.coverage)})
    for coverage in report.coverage:
        if not coverage.complete:
            coverage.missing_ranges = [{"status": "UNKNOWN", "before_oldest_observed_lt": coverage.oldest_lt,
                "after_newest_observed_lt": coverage.newest_lt, "reason": coverage.gap_reason or "Provider does not guarantee full chain coverage"}]


def _asset_history_status(report: NFTIntelligenceReport, address: str) -> str:
    rows = [c for c in report.coverage if address in c.scope and "history" in c.scope]
    if not rows:
        return CoverageStatus.UNKNOWN
    return CoverageStatus.PARTIAL if any(c.status != CoverageStatus.INDEXER_EXHAUSTED for c in rows) else CoverageStatus.INDEXER_EXHAUSTED


def build_portfolio(report: NFTIntelligenceReport, wallet: str) -> NFTPortfolio:
    wallet = ton_canonical_address(wallet)
    out = NFTPortfolio(wallet_address=wallet)
    for asset in report.assets:
        if asset.current_owner == wallet:
            if asset.current_owner_status == VerificationStatus.VERIFIED_ONCHAIN:
                out.current_holdings.append(asset.address)
                out.by_collection.setdefault(asset.collection_address or "standalone", []).append(asset.address)
                out.by_kind.setdefault(asset.kind, []).append(asset.address)
            else:
                out.reported_holdings.append(asset.address)
        elif any(a.beneficial_owner == wallet for a in asset.ownership):
            out.reported_holdings.append(asset.address)
    counterparties: Counter = Counter()
    received, sent, historical = set(), set(), set()
    for event in report.events:
        if event.status != "success" or event.event_type not in {"transfer", "sale", "mint"}:
            continue
        direction = None
        if event.to_address == wallet:
            received.add(event.asset_address)
            direction = "in"
            if event.from_address and event.from_address != wallet:
                counterparties[event.from_address] += 1
        if event.from_address == wallet:
            sent.add(event.asset_address)
            direction = "out"
            if event.to_address and event.to_address != wallet:
                counterparties[event.to_address] += 1
        if direction:
            historical.add(event.asset_address)
            out.timeline.append({"event_id": event.event_id, "asset_address": event.asset_address,
                "timestamp": event.timestamp, "logical_time": event.logical_time, "direction": direction,
                "event_type": event.event_type})
            # Sale consideration is buyer out / seller in, opposite NFT direction.
            if event.money and event.money.amount is not None:
                if event.money.currency != "TON" and not event.money.token_contract:
                    # Symbols and generic "jetton" do not identify a token.
                    # Keep the event price but do not add incompatible amounts.
                    continue
                key = event.money.currency + ":" + (event.money.token_contract or "native")
                totals = out.financial_totals.setdefault(key, {"sale_in": Decimal(0), "sale_out": Decimal(0),
                                                               "attached_transfer_in": Decimal(0), "attached_transfer_out": Decimal(0)})
                if event.event_type == "sale":
                    total_key = "sale_out" if direction == "in" else "sale_in"
                elif event.event_type == "transfer":
                    total_key = "attached_transfer_" + direction
                else:
                    continue
                with localcontext() as context:
                    context.prec = max(80, len(str(totals[total_key])) + len(str(event.money.amount)) + 4)
                    totals[total_key] += event.money.amount
    out.received_assets, out.sent_assets = sorted(received), sorted(sent)
    out.historical_holdings = sorted(historical - set(out.current_holdings))
    out.counterparties = [{"address": address, "event_count": count} for address, count in counterparties.most_common()]
    out.coverage_status = CoverageStatus.PARTIAL
    out.notes = ["Current holdings require fresh on-chain owner; historical transfers do not prove present ownership",
                 "Sale prices are provider-interpreted successful actions; forward amounts are separated from sale consideration",
                 "Portfolio history and totals cover collected events only; no claim of complete lifetime portfolio"]
    return out


def corroborate_events(events: list[NFTEvent], assets: list) -> list[NFTEvent]:
    """Merge displayed actions only when transaction membership and directed NFT agree."""
    verified_items = {a.address for a in assets if a.standard_status == VerificationStatus.VERIFIED_ONCHAIN}
    for event in events:
        if (event.asset_address in verified_items and event.raw.get("transaction_aborted") is False
                and event.status == "success" and event.raw.get("transaction_is_emulated") is not True
                and ton_canonical_address(event.raw.get("nft_address")) == event.asset_address
                and event.transaction_hash and event.logical_time is not None
                and event.from_address and event.to_address and event.event_type == "transfer"):
            event.verification = VerificationStatus.VERIFIED_ONCHAIN
    transfers = [e for e in events if e.verification == VerificationStatus.VERIFIED_ONCHAIN and e.event_type == "transfer"]
    transfer_ids = {e.event_id for e in transfers}
    lookup: dict[tuple, list[NFTEvent]] = defaultdict(list)
    for transfer in transfers:
        lookup[(transfer.transaction_hash, transfer.asset_address, transfer.from_address, transfer.to_address)].append(transfer)
    removed = set()
    for event in events:
        if event.event_id in transfer_ids or event.event_type != "transfer":
            continue
        base = {canonical_hash(h) for h in event.raw.get("base_transactions", [])}
        if event.transaction_hash:
            base.add(event.transaction_hash)
        matches = [t for tx in base for t in lookup.get((tx, event.asset_address, event.from_address, event.to_address), [])
                   if event.status == t.status or event.status == "unknown"]
        if len(matches) == 1:
            target = matches[0]
            target.evidence_ids = list(dict.fromkeys(target.evidence_ids + event.evidence_ids))
            target.observation_ids = list(dict.fromkeys(target.observation_ids + event.observation_ids))
            target.provider_event_ids = list(dict.fromkeys(target.provider_event_ids + event.provider_event_ids))
            target.raw.setdefault("corroborating_observations", []).append(event.model_dump(mode="json"))
            removed.add(event.event_id)
    return [e for e in events if e.event_id not in removed]
