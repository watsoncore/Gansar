"""Bounded, explainable history profiles over collected economic observations.

All amounts remain Decimal strings partitioned by asset. Temporal proximity is
not fund tracing: no balance, common-control, service or signing-app assertion
is made here. A profile describes the collected window, never lifetime history.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, localcontext
import hashlib
import json
import time


METHOD = "behavioral_profiles_v1"
LIMITATIONS = [
    "Collected histories are partial and can omit competing transfers or older activity.",
    "An ordered similar-amount pair does not establish movement of the same money or custody.",
    "Shared services, market routers, payroll systems and SDKs can create the same behavior for unrelated users.",
    "UTC activity windows do not identify geography, a person or a signing application.",
]
_NON_MONEY = {"approval", "approve", "resource_delegation", "resource_undelegation", "contract_call", "failed"}


def _id(kind, *basis):
    return "behavior:" + kind + ":" + hashlib.sha256(json.dumps(basis, sort_keys=True, default=str).encode()).hexdigest()


def _stamp(value):
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.astimezone(timezone.utc) if result.tzinfo else None
    except (ValueError, OverflowError):
        return None


def _decimal(value):
    # Floats cannot regain the precision lost upstream. Unbounded exponents are
    # rejected to keep adversarial provider payloads within the local budget.
    if not isinstance(value, (str, int)) or isinstance(value, bool) or len(str(value)) > 1200:
        return None
    try:
        number = Decimal(value)
        if number.is_finite() and number > 0 and abs(number.as_tuple().exponent) <= 1000 and len(number.as_tuple().digits) <= 1000:
            return number
    except (InvalidOperation, ValueError):
        pass
    return None


def _exact(values):
    if not values:
        return {"sum": "0", "minimum": None, "median": None, "maximum": None, "recurring_denominations": []}
    # Exact addition even when integer and fractional magnitudes differ by far
    # more than the ambient Decimal context precision.
    ordered = sorted(values)
    precision = max(v.adjusted() for v in values) - min(v.as_tuple().exponent for v in values) + len(str(len(values))) + 8
    with localcontext() as ctx:
        ctx.prec = max(40, precision)
        middle = len(ordered) // 2
        median = ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2
        return {"sum": str(sum(values, Decimal(0))), "minimum": str(ordered[0]), "median": str(median),
                "maximum": str(ordered[-1]), "recurring_denominations": [
                    {"amount_decimal": str(amount), "count": count} for amount, count in Counter(values).most_common(10) if count > 1]}


def _distribution(counts):
    total = sum(counts.values())
    with localcontext() as ctx:
        ctx.prec = 24
        return {"unique": len(counts), "total": total,
                "top_share": str(Decimal(max(counts.values())) / total) if total else None,
                "herfindahl": str(sum((Decimal(n) / total) ** 2 for n in counts.values())) if total else None,
                "recurring_counterparties": sum(n > 1 for n in counts.values()),
                "counterparties": [{"address_key": key, "count": n} for key, n in counts.most_common(30)]}


def _intervals(stamps):
    distinct = sorted(set(stamps))
    gaps = [Decimal(str((b - a).total_seconds())) for a, b in zip(distinct, distinct[1:])]
    return {"distinct_timestamp_count": len(distinct), "interval_count": len(gaps),
            **_exact(gaps), "scope": "intervals between observed distinct timestamps; inactivity outside the sample is unknown"}


def _hypothesis(key, asset, motif, coverage, verified):
    supported = (motif["independent_pair_count"] >= 3 and len(motif["active_utc_dates"]) >= 2
                 and motif["temporal_span_seconds"] >= 86400)
    confidence = "POSSIBLE" if supported else "WEAK_LEAD"
    return {"hypothesis_id": _id("hypothesis", key, asset, motif["recipient_key"]), "subject": key,
            "claim": "Possible intermediate forwarding/deposit-sweep role toward the observed recipient; service and custody remain unknown.",
            "claim_type": "infrastructure_role", "role": "DEPOSIT_SWEEP_CANDIDATE", "confidence": confidence,
            "evidence_ids": motif["evidence_ids"], "dependency_groups": motif["dependency_groups"],
            "supporting_observations": [{"motif_id": motif["motif_id"], "independent_pairs": motif["independent_pair_count"],
                "active_utc_dates": motif["active_utc_dates"], "recipient_key": motif["recipient_key"], "asset_key": asset}],
            "contradicting_observations": motif["contradicting_observations"],
            "alternative_explanations": ["A personal wallet periodically forwards payments.",
                "An unrelated automated merchant or market router uses the same route.",
                "Uncollected history or pre-existing balances explain the amount similarity.",
                "The recipient is a shared exchange deposit endpoint used by independent customers."],
            "coverage": coverage, "missing_evidence": ["Complete history and historical balances", "Independent operator/role confirmation",
                "Competing routes outside the collected window", "Destination-side execution/asset credit where applicable"],
            "proposed_next_experiment": "Expand disjoint older/newer history windows and test whether the same asset-specific recipient and timing persist; seek independent role evidence.",
            "status": "OPEN", "first_observed": motif["first_observed"], "last_verified": verified,
            "limitations": LIMITATIONS}


def _motifs(key, rows, coverage, verified, allowed):
    results, hypotheses = [], []
    assets = defaultdict(list)
    for row in rows:
        assets[row["asset_key"]].append(row)
    for asset, events in sorted(assets.items()):
        if not allowed():
            break
        # Unplaced events can invalidate apparent adjacency. Do not silently
        # remove them and then reconstruct an apparently clean funding route.
        if any(row["_time"] is None for row in events):
            continue
        events.sort(key=lambda r: (r["_time"], r["operation_id"]))
        pairs = defaultdict(list)
        # Consecutive observed events avoid assigning one funding to several
        # outflows. Equal timestamps are deliberately not given an order.
        for previous, following in zip(events, events[1:]):
            if not allowed():
                break
            if previous["to_key"] != key or following["from_key"] != key:
                continue
            if previous["from_key"] == key or following["to_key"] == key:
                continue
            if previous["success"] is not True or following["success"] is not True:
                continue
            # Keep contract-value observations in profiles and in this ordered
            # sequence: deleting one could manufacture adjacency across it.
            if any(r.get("native_value_purpose") == "jetton_transfer_request" for r in (previous, following)):
                continue
            delay = (following["_time"] - previous["_time"]).total_seconds()
            if not 0 < delay <= 3600 or previous["transaction_hash"] == following["transaction_hash"]:
                continue
            if previous["_amount"] is None or following["_amount"] is None:
                continue
            with localcontext() as ctx:
                # Exact cross products enforce boundaries before the displayed
                # ratio is rounded; ambient precision cannot admit 0.7999… .
                ctx.prec = max(40, len(previous["_amount"].as_tuple().digits) + len(following["_amount"].as_tuple().digits) + 8)
                if not previous["_amount"] * Decimal("0.8") <= following["_amount"] <= previous["_amount"] * Decimal("1.05"):
                    continue
                ctx.prec = 40
                ratio = following["_amount"] / previous["_amount"]
            evidence = set(previous["evidence_ids"]) | set(following["evidence_ids"])
            groups = {previous["dependency_group"], following["dependency_group"]}
            # An operation without provenance may describe a profile, but never
            # supports a temporal hypothesis.
            if (not previous["evidence_ids"] or not following["evidence_ids"] or len(groups) < 2
                    or set(previous["evidence_ids"]).intersection(following["evidence_ids"])):
                continue
            pairs[following["to_key"]].append({"incoming_operation_id": previous["operation_id"],
                "outgoing_operation_id": following["operation_id"], "source_key": previous["from_key"],
                "incoming_transaction_hash": previous["transaction_hash"], "outgoing_transaction_hash": following["transaction_hash"],
                "incoming_amount_decimal": str(previous["_amount"]), "outgoing_amount_decimal": str(following["_amount"]),
                "amount_ratio": str(ratio), "amount_ratio_precision_digits": 40, "delay_seconds": delay,
                "incoming_timestamp": previous["_time"].isoformat(), "outgoing_timestamp": following["_time"].isoformat(),
                "evidence_ids": sorted(evidence), "dependency_groups": sorted(groups)})
        for recipient, candidates in sorted(pairs.items()):
            used_groups, used_evidence, independent = set(), set(), []
            for pair in candidates:
                if used_groups.intersection(pair["dependency_groups"]) or used_evidence.intersection(pair["evidence_ids"]):
                    continue
                independent.append(pair)
                used_groups.update(pair["dependency_groups"])
                used_evidence.update(pair["evidence_ids"])
            if not independent:
                continue
            outflows = [r for r in events if r["from_key"] == key and r["to_key"] != key]
            attached = sum(r.get("native_value_purpose") == "jetton_transfer_request" for r in outflows)
            unrelated = sum(r["to_key"] != recipient for r in outflows)
            contradictions = ([{"kind": "alternative_outgoing_recipients", "count": unrelated,
                "scope": "observed same-asset native destinations, including contract request attachments; not distinct ultimate beneficiaries"}] if unrelated else [])
            unknown = sum(r["success"] is None for r in events)
            if unknown:
                contradictions.append({"kind": "unknown_execution_outcome", "count": unknown})
            dates = sorted({p["incoming_timestamp"][:10] for p in independent})
            span = (_stamp(independent[-1]["outgoing_timestamp"]) - _stamp(independent[0]["incoming_timestamp"])).total_seconds()
            motif = {"motif_id": _id("motif", key, asset, recipient), "type": "ORDERED_FUNDING_FORWARD_CANDIDATE",
                "subject": key, "asset_key": asset, "recipient_key": recipient,
                "independent_pair_count": len(independent), "correlated_pair_count": len(candidates) - len(independent),
                "active_utc_dates": dates, "temporal_span_seconds": span,
                "period_support": "MULTIPLE_UTC_DATES" if len(dates) >= 2 and span >= 86400 else "SHORT_OBSERVATION_WINDOW",
                "pairs": independent[:50], "pairs_display_truncated": len(independent) > 50,
                "evidence_ids": sorted(used_evidence), "dependency_groups": sorted(used_groups),
                "same_asset_outgoing_count": len(outflows), "alternative_recipient_outgoing_count": unrelated,
                "contract_request_native_outgoing_count": attached,
                "contradicting_observations": contradictions,
                "first_observed": independent[0]["incoming_timestamp"], "last_observed": independent[-1]["outgoing_timestamp"],
                "thresholds": {"maximum_delay_seconds": 3600, "minimum_amount_ratio": "0.8", "maximum_amount_ratio": "1.05",
                    "minimum_independent_pairs_for_possible": 3, "minimum_span_seconds_for_possible": 86400},
                "fund_tracing": "NOT_ESTABLISHED", "limitations": LIMITATIONS}
            # Multiple competing destinations undermine an exclusive deposit
            # role; the temporal observations remain available for inspection.
            hypothesis = _hypothesis(key, asset, motif, coverage, verified)
            if unrelated > len(independent) or unknown:
                hypothesis["confidence"] = "WEAK_LEAD"
            results.append(motif)
            hypotheses.append(hypothesis)
    return results, hypotheses


def _profile(key, rows, coverage):
    incoming = [r for r in rows if r["to_key"] == key and r["from_key"] != key]
    outgoing = [r for r in rows if r["from_key"] == key and r["to_key"] != key]
    stamps = [r["_time"] for r in rows if r["_time"]]
    assets = {}
    by_asset = defaultdict(list)
    for row in rows:
        by_asset[row["asset_key"]].append(row)
    for asset, selected in sorted(by_asset.items()):
        ins = [r["_amount"] for r in selected if r["to_key"] == key and r["from_key"] != key and r["_amount"] is not None and r["success"] is True]
        outs = [r["_amount"] for r in selected if r["from_key"] == key and r["to_key"] != key and r["_amount"] is not None and r["success"] is True]
        unverified_ins = [r["_amount"] for r in selected if r["to_key"] == key and r["from_key"] != key and r["_amount"] is not None and r["success"] is None]
        unverified_outs = [r["_amount"] for r in selected if r["from_key"] == key and r["to_key"] != key and r["_amount"] is not None and r["success"] is None]
        assets[asset] = {"incoming": _exact(ins), "outgoing": _exact(outs),
                         "unverified_incoming_value_observations": _exact(unverified_ins),
                         "unverified_outgoing_value_observations": _exact(unverified_outs),
                         "unknown_amount_count": sum(r["_amount"] is None for r in selected),
                         "amount_precision_counts": dict(sorted(Counter(r["_amount_precision"] for r in selected).items())),
                         "financial_statistics_scope": "Successful exact normalized decimal/base-unit observations; unverified execution separate, display floats excluded. Values are not historical balances or destination credit proof."}
    dates = sorted({stamp.date().isoformat() for stamp in stamps})
    # Per-period counts expose drift; they cannot prove periodicity with a
    # sampled history. No local-time or geographical inference is attempted.
    periods = defaultdict(lambda: {"incoming": 0, "outgoing": 0, "unknown_execution": 0})
    for row in rows:
        if row["_time"]:
            period = row["_time"].strftime("%Y-%m")
            periods[period]["incoming"] += row["to_key"] == key and row["from_key"] != key
            periods[period]["outgoing"] += row["from_key"] == key and row["to_key"] != key
            periods[period]["unknown_execution"] += row["success"] is None
    return {"profile_id": _id("profile", key), "address_key": key, "blockchain": rows[0]["blockchain"],
            "observation_count": len(rows), "transaction_count": len({r["transaction_hash"] for r in rows}),
            "incoming_count": len(incoming), "outgoing_count": len(outgoing), "self_transfer_count": len(rows) - len(incoming) - len(outgoing),
            "unknown_success_count": sum(r["success"] is None for r in rows), "unknown_timestamp_count": len(rows) - len(stamps),
            "incoming_counterparties": _distribution(Counter(r["from_key"] for r in incoming)),
            "outgoing_counterparties": _distribution(Counter(r["to_key"] for r in outgoing)),
            "assets": assets, "first_observed": min(stamps).isoformat() if stamps else None,
            "last_observed": max(stamps).isoformat() if stamps else None, "active_utc_dates": dates,
            "active_utc_date_count": len(dates), "intervals_seconds": _intervals(stamps),
            "utc_hour_counts": dict(sorted(Counter(str(s.hour) for s in stamps).items())),
            "utc_weekday_counts": dict(sorted(Counter(str(s.weekday()) for s in stamps).items())),
            "monthly_windows": dict(sorted(periods.items())), "periodicity": "NOT_ESTABLISHED",
            "evidence_ids": sorted({e for r in rows for e in r["evidence_ids"]}),
            "dependency_groups": sorted({r["dependency_group"] for r in rows}),
            "coverage": {**coverage, "status": "PARTIAL", "lifetime_history_complete": False}, "limitations": LIMITATIONS}


def _compare(left, right, neighborhoods, popularity):
    lk, rk = left["address_key"], right["address_key"]
    shared = neighborhoods[lk] & neighborhoods[rk]
    rare = [key for key in shared if popularity[key] <= 5]
    general = [key for key in shared if popularity[key] > 5]
    enough = all(p["observation_count"] >= 6 and p["active_utc_date_count"] >= 2 for p in (left, right))
    shared_assets = sorted(set(left["assets"]) & set(right["assets"]))
    dimensions = [{"dimension": "shared_counterparties", "shared_count": len(shared), "rare_in_sample_count": len(rare),
                   "popular_in_sample_count": len(general), "interpretation": "Shared popular services are weak context; popularity is sample-relative."}]
    differences = []
    for side in ("incoming", "outgoing"):
        field = side + "_counterparties"
        a, b = left[field], right[field]
        if a["total"] and b["total"]:
            with localcontext() as ctx:
                ctx.prec = 24
                delta = abs(Decimal(a["top_share"]) - Decimal(b["top_share"]))
            dimensions.append({"dimension": side + "_counterparty_concentration", "absolute_difference": str(delta),
                               "similar": delta <= Decimal("0.15")})
            if delta > Decimal("0.3"):
                differences.append({"dimension": side + "_counterparty_concentration", "left": a["top_share"], "right": b["top_share"]})
    if set(left["assets"]) != set(right["assets"]):
        differences.append({"dimension": "assets", "left_only": sorted(set(left["assets"]) - set(right["assets"])),
                            "right_only": sorted(set(right["assets"]) - set(left["assets"]))})
    dimensions.append({"dimension": "temporal_support", "status": "COMPARABLE_SAMPLED_WINDOWS" if enough else "INSUFFICIENT_HISTORY",
                       "left_active_utc_dates": left["active_utc_date_count"], "right_active_utc_dates": right["active_utc_date_count"]})
    if enough:
        for field in ("utc_hour_counts", "utc_weekday_counts"):
            a, b = left[field], right[field]
            with localcontext() as ctx:
                ctx.prec = 24
                atotal, btotal = sum(a.values()), sum(b.values())
                overlap = sum(min(Decimal(a.get(bucket, 0)) / atotal, Decimal(b.get(bucket, 0)) / btotal)
                              for bucket in set(a) | set(b))
            dimensions.append({"dimension": field + "_normalized_overlap", "overlap": str(overlap),
                "interpretation": "Descriptive sample timing similarity; shared queues and schedules can coincide. No geographic or controller inference."})
            if overlap < Decimal("0.2"):
                differences.append({"dimension": field, "normalized_overlap": str(overlap)})
        dimensions.append({"dimension": "observed_utc_date_overlap",
                           "shared_date_count": len(set(left["active_utc_dates"]) & set(right["active_utc_dates"]))})
    correlated = sorted(set(left["dependency_groups"]) & set(right["dependency_groups"]))
    return {"comparison_id": _id("comparison", *sorted([lk, rk])), "left_key": lk, "right_key": rk,
            "relationship": "BEHAVIORAL_SIMILARITY_CANDIDATE", "status": "WEAK_LEAD" if enough and rare and shared_assets else "UNKNOWN",
            "dimensions": dimensions, "differences": differences, "shared_counterparty_keys": sorted(shared)[:30],
            "shared_asset_keys": shared_assets, "correlated_dependency_groups": correlated,
            "evidence_ids": sorted(set(left["evidence_ids"]) | set(right["evidence_ids"])),
            "dependency_groups": sorted(set(left["dependency_groups"]) | set(right["dependency_groups"])),
            "common_controller": "UNKNOWN", "signing_application": "UNKNOWN", "limitations": LIMITATIONS}


def _technical_profile(rows, technical):
    counts, evidence, seen = Counter(), set(), set()
    for row in rows:
        fingerprint = technical.get((row["blockchain"], row["transaction_hash"])) or {}
        for field in ("construction_fingerprints", "implementation_observations"):
            for finding in fingerprint.get(field) or []:
                name = finding.get("rule_id") or finding.get("method") or finding.get("kind")
                marker = (row["transaction_hash"], field, str(name))
                if name and marker not in seen:
                    seen.add(marker)
                    counts[field + ":" + str(name)] += 1
                    evidence.update(str(e) for e in finding.get("evidence_ids") or [] if e)
    return {"features": dict(sorted(counts.items())), "evidence_ids": sorted(evidence),
            "scope": "Observed construction/implementation features; shared SDKs and dApps can reproduce them.",
            "signing_application": "UNKNOWN", "confidence_effect": "NONE"}


def analyze_behavioral_profiles(data, *, max_seconds=2.0, max_profiles=500, max_comparisons=100):
    """Analyze normalized directed projections without I/O or address expansion.

    UTXO transaction incidence is retained upstream and never expanded into
    fictitious input-to-output address transfers here. Budget exhaustion yields
    partial outputs and explicit reasons rather than erasing existing results.
    """
    started = time.monotonic()
    deadline = started + max(0.0, float(max_seconds))
    verified = data.get("analysis_performed_at") or datetime.now(timezone.utc).isoformat()
    diagnostics = Counter()
    truncated = False

    def allowed():
        nonlocal truncated
        if time.monotonic() >= deadline:
            truncated = True
            return False
        return True

    source_rows = data.get("operations") or []
    coverage = {"status": "PARTIAL", "history": data.get("coverage") or {}, "network_requests": 0}
    output = {"profiles": [], "comparisons": [], "motifs": [], "hypotheses": [], "evidence": [],
              "coverage": coverage, "diagnostics": {}}
    groups, seen_ids, seen_projection, seen_transaction_edges = defaultdict(list), set(), {}, {}
    normalized = []
    for raw in source_rows:
        if not allowed():
            break
        diagnostics["operations_examined"] += 1
        if not isinstance(raw, dict) or raw.get("success") is False or raw.get("kind") in _NON_MONEY:
            diagnostics["failed_or_nonmonetary_excluded"] += 1
            continue
        keys = [raw.get("from_key"), raw.get("to_key")]
        chain, tx = raw.get("blockchain"), raw.get("transaction_hash")
        if not chain or not tx or not all(isinstance(k, str) and k.startswith(chain + ":") for k in keys):
            diagnostics["invalid_network_projection_excluded"] += 1
            continue
        if chain in {"btc", "doge"}:
            diagnostics["utxo_address_projections_excluded"] += 1
            continue
        asset = raw.get("asset_key")
        if not isinstance(asset, str) or not asset.startswith(chain + ":"):
            diagnostics["missing_asset_excluded"] += 1
            continue
        row = dict(raw)
        row["_amount"], row["_time"] = _decimal(raw.get("amount_decimal")), _stamp(raw.get("timestamp"))
        row["_amount_precision"] = str(raw.get("amount_precision") or "normalized_decimal")
        if row["_amount_precision"] == "display_float":
            row["_amount"] = None
            diagnostics["display_float_amounts_excluded_from_financial_inference"] += 1
        row["success"] = raw.get("success") if isinstance(raw.get("success"), bool) else None
        row["evidence_ids"] = sorted({str(e) for e in raw.get("evidence_ids") or [] if e})
        row["dependency_group"] = str(raw.get("dependency_group") or chain + ":tx:" + str(tx))
        projection = (chain, tx, *keys, asset, str(row["_amount"]))
        row["operation_id"] = str(raw.get("operation_id") or _id("operation", projection))
        # The adapter gives exact event IDs. If absent, identical projections
        # cannot be counted twice merely because two providers returned them.
        event_id = row["operation_id"]
        if event_id in seen_ids:
            diagnostics["duplicate_operation_ids_excluded"] += 1
            continue
        # Same evidence + same projection is always duplication. Distinct event
        # IDs with independent proof can represent repeated equal transfers.
        evidence_projection = (projection, tuple(row["evidence_ids"]))
        if evidence_projection in seen_projection:
            diagnostics["duplicate_evidence_projections_excluded"] += 1
            continue
        # Differently named upstream evidence still describes one root economic
        # observation unless a stable event identity differentiates it.
        if projection in seen_transaction_edges and row["dependency_group"] == seen_transaction_edges[projection]:
            diagnostics["duplicate_dependency_projections_excluded"] += 1
            continue
        seen_ids.add(event_id)
        seen_projection[evidence_projection] = event_id
        seen_transaction_edges[projection] = row["dependency_group"]
        normalized.append(row)
    # Prioritize targets without allowing unbounded neighbor profile growth.
    target_keys = set(data.get("target_keys") or [])
    admitted = sorted({r[k] for r in normalized for k in ("from_key", "to_key")}, key=lambda k: (k not in target_keys, k))
    selected_keys = set(admitted[:max(0, int(max_profiles))])
    diagnostics["profiles_omitted_by_limit"] = max(0, len(admitted) - len(selected_keys))
    for row in normalized:
        for key in {row["from_key"], row["to_key"]} & selected_keys:
            groups[key].append(row)
    neighborhoods = {key: {r["to_key"] if r["from_key"] == key else r["from_key"] for r in rows} - {key}
                     for key, rows in groups.items()}
    popularity = Counter(neighbor for neighbors in neighborhoods.values() for neighbor in neighbors)
    indexed = {}
    technical = {}
    for ref, fingerprint in (data.get("technical") or {}).items():
        if not allowed():
            break
        if isinstance(fingerprint, dict) and fingerprint.get("transaction_hash") and fingerprint.get("blockchain"):
            technical[(fingerprint["blockchain"], fingerprint["transaction_hash"])] = fingerprint
    for key in sorted(groups, key=lambda k: (k not in target_keys, k)):
        if not allowed():
            break
        profile = _profile(key, groups[key], coverage)
        profile["technical_behavior"] = _technical_profile(groups[key], technical)
        output["profiles"].append(profile)
        indexed[key] = profile
        motifs, hypotheses = _motifs(key, groups[key], profile["coverage"], verified, allowed)
        output["motifs"].extend(motifs)
        output["hypotheses"].extend(hypotheses)
    # Bounded inverted neighborhoods avoid an all-pairs 500**2 comparison pass.
    reverse = defaultdict(list)
    for key in indexed:
        for neighbor in neighborhoods[key]:
            reverse[neighbor].append(key)
    compared = set()
    limit = max(0, int(max_comparisons))
    for neighbor in sorted(reverse, key=lambda n: (popularity[n], n)):
        if len(output["comparisons"]) >= limit or not allowed():
            break
        candidates = sorted(reverse[neighbor], key=lambda k: (k not in target_keys, k))[:20]
        for i, left in enumerate(candidates):
            for right in candidates[i + 1:]:
                if len(output["comparisons"]) >= limit or not allowed():
                    break
                pair = tuple(sorted((left, right)))
                if pair in compared or indexed[left]["blockchain"] != indexed[right]["blockchain"]:
                    continue
                compared.add(pair)
                output["comparisons"].append(_compare(indexed[left], indexed[right], neighborhoods, popularity))
    coverage.update({"status": "TRUNCATED" if truncated or diagnostics["profiles_omitted_by_limit"] else "PARTIAL",
        "operations_available": len(source_rows), "operations_analyzed": len(normalized), "profiles_available": len(admitted),
        "profiles_analyzed": len(output["profiles"]), "comparison_limit": limit, "time_budget_exhausted": truncated,
        "comparison_limit_reached": bool(limit and len(output["comparisons"]) >= limit),
        "comparison_search": "Bounded shared-neighborhood candidates; at most 20 profiles per shared neighbor.",
        "utxo_transactions_available": len(data.get("utxo_transactions") or []), "utxo_address_flow_inference": "NOT_PERFORMED",
        "elapsed_seconds": time.monotonic() - started, "method": METHOD})
    output["diagnostics"] = dict(diagnostics)
    return output
