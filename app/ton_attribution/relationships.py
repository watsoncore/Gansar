"""Bounded TON relationship analysis of evidence already collected by Gansar.

There is no network access, service-address mapping, wallet-client fingerprint,
or common-controller heuristic here. ``CONFIRMED`` refers to the named observed
relation, never to a person or an unverified service's ownership.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, localcontext
import hashlib
import json
import time
from typing import Any

from app.models.report import AddressReport
from app.ton_nft.analytics import canonical_hash
from app.ton_nft.protocol import decode_boc
from app.utils.event_identity import event_identity, transaction_success
from app.utils.security import safe_public_url, sanitize_observation
from app.utils.ton_normalize import ton_canonical_address, ton_datetime

ACCOUNT_SPEC = "https://docs.ton.org/foundations/status"
TRACE_SPEC = "https://docs.ton.org/foundations/traces"
SCHEMA_SPEC = "https://raw.githubusercontent.com/tonkeeper/opentonapi/master/api/openapi.yml"
NFT_SPEC = "https://raw.githubusercontent.com/ton-blockchain/TEPs/master/text/0062-nft-standard.md"
JETTON_SPEC = "https://raw.githubusercontent.com/ton-blockchain/TEPs/master/text/0074-jettons-standard.md"
V5_SPEC = "https://docs.ton.org/contracts/standard/wallets/v5"
EVENTS_SPEC = "https://docs.tonapi.io/tonapi/rest-api/events"
OPCODES = {
    0x5FCC3D14: ("nft_transfer_request", NFT_SPEC),
    0x05138D91: ("nft_ownership_assigned_notification", NFT_SPEC),
    0x0F8A7EA5: ("jetton_transfer_request", JETTON_SPEC),
    0x7362D09C: ("jetton_transfer_notification", JETTON_SPEC),
    0x595F07BC: ("jetton_burn_request", JETTON_SPEC),
    0x7BDD97DE: ("jetton_burn_notification", JETTON_SPEC),
    0xD53276DB: ("token_excesses", JETTON_SPEC),
    0x7369676E: ("wallet_v5_external_signed_request", V5_SPEC),
    0x73696E74: ("wallet_v5_internal_signed_request", V5_SPEC),
    0x6578746E: ("wallet_v5_extension_request", V5_SPEC),
}
LIMITATIONS = [
    "Direct or repeated transfers do not establish a shared owner, signing application, deposit-address assignment, or service control.",
    "An opcode is an observed message header. Its value can be copied by arbitrary contracts; it does not alone prove successful token/NFT transfer or a wallet application.",
    "Account state-update hashes are not contract-code hashes. Ordinary data/balance changes are not contract upgrades.",
    "StateInit in a message is a deployment/reactivation candidate; successful deployment requires account transition evidence.",
    "A current uninit/nonexist observation does not prove an address has never been deployed or identify a service-specific derivation.",
    "Trace identifiers group provider-reported causal messages; collected traces and historical contract state are partial, not complete blockchain proofs.",
    "Service interaction confidence is capped by the counterparty label; TonAPI and Tonkeeper registry labels are not independent sources.",
    "A successful sender-account transaction proves message emission, not successful processing or final asset credit at every destination.",
]


def _id(prefix: str, basis: Any) -> str:
    return prefix + hashlib.sha256(json.dumps(basis, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()


def _address(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("address") or value.get("account_address")
    return ton_canonical_address(value) if isinstance(value, str) else None


def _hash(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    result = canonical_hash(value)
    return result if result and len(result) == 64 and all(c in "0123456789abcdef" for c in result) else None


def _state(value: Any) -> str | None:
    aliases = {"nonexist": "nonexist", "uninit": "uninit", "uninitialized": "uninit", "active": "active", "frozen": "frozen"}
    return aliases.get(str(value).casefold())


def _success(row: dict, fallback: bool | None = None) -> bool | None:
    description = row.get("description") if isinstance(row.get("description"), dict) else {}
    values = (row.get("success"), description.get("success"))
    if row.get("emulated") is True:
        return None
    if row.get("aborted") is True or description.get("aborted") is True or False in values:
        return False
    if True in values:
        return True
    if row.get("aborted") is False or description.get("aborted") is False:
        return True
    return fallback


def _opcode(message: dict) -> tuple[int | None, str | None]:
    value = message.get("opcode", message.get("op_code"))
    if value is not None and not isinstance(value, bool):
        try:
            if isinstance(value, str):
                value = int(value, 16 if value.lower().startswith(("0x", "-0x")) else 10)
            if isinstance(value, int) and -(2**31) <= value < 2**32:
                return value & 0xFFFFFFFF, "provider_message_header"
        except ValueError:
            pass
    raw = message.get("raw_body")
    if isinstance(raw, str) and len(raw) <= 8192:
        try:
            cell = decode_boc(raw.lower() if raw[:8].lower() == "b5ee9c72" else raw)
            if cell.bit_length >= 32:
                return int.from_bytes(cell.data[:4], "big"), "raw_body_first_32_bits"
        except (ValueError, OverflowError):
            pass
    return None, None


def analyze_ton_relationships(report: AddressReport, intelligence: dict | None = None, *,
                              max_records: int = 20000, deadline: float | None = None) -> dict:
    """Analyze existing TON evidence, without modifying report or making requests.

    ``deadline`` is an absolute monotonic time (the event-loop time on supported
    runtimes). Limits count raw transaction/message candidates, not only results.
    Cross-provider and sender/recipient duplicates merge by physical message hash;
    absent that hash, exact transaction/message-index identity is used cautiously.
    """
    if max_records < 0:
        raise ValueError("max_records must be nonnegative")
    started = time.monotonic(); now = datetime.now(timezone.utc).isoformat()
    intelligence = intelligence if intelligence is not None else report.ton_service_intelligence
    intelligence = intelligence if isinstance(intelligence, dict) else {}
    target = _address(report.target_address)
    evidence: dict[str, dict] = {}; messages: dict[str, dict] = {}; histories: dict[str, dict] = {}
    traces: dict[str, dict] = {}; operations: dict[str, dict] = {}
    counts = {"records_examined": 0, "duplicate_messages": 0, "transaction_rows": 0}
    truncated = False
    observed_transactions: set[tuple[str | None, str, str]] = set()
    account_states = intelligence.get("addresses", {})

    def allowed() -> bool:
        nonlocal truncated
        if counts["records_examined"] >= max_records or deadline is not None and time.monotonic() >= deadline:
            truncated = True
            return False
        counts["records_examined"] += 1
        return True

    def fact(source: str, url: str | None, observation_id: str | None, relation: str,
             facts: dict, *, tx_hash: str | None = None, at: str | None = None) -> str:
        clean_url = url if safe_public_url(url) else None
        basis = {"source": source, "url": clean_url, "observation_id": observation_id,
                 "relation": relation, "transaction_hash": tx_hash, "facts": facts}
        eid = _id("ton:relationship:evidence:", basis)
        evidence.setdefault(eid, {"evidence_id": eid, "source": source, "source_url": clean_url, "url": clean_url,
            "observation_id": observation_id, "observed_at": at or now, "relation": relation,
            "transaction_hash": tx_hash, "facts": facts})
        return eid

    def transaction(row: dict, context: dict) -> None:
        if not isinstance(row, dict) or not allowed():
            return
        transaction_id = row.get("transaction_id") if isinstance(row.get("transaction_id"), dict) else {}
        tx_hash = _hash(row.get("hash") or transaction_id.get("hash") or context.get("tx_hash"))
        account = _address(row.get("account") or row.get("address") or context.get("account"))
        # A transaction's sender is not its account: use destination only for
        # the incoming-message wrapper or an explicit collector account context.
        if not account and isinstance(row.get("in_msg"), dict):
            account = _address(row["in_msg"].get("destination"))
        key = (account, tx_hash or _id("unhashed:", [context.get("event_id"), row.get("lt")]), context["source"])
        if key in observed_transactions:
            return
        observed_transactions.add(key); counts["transaction_rows"] += 1
        state_before = row.get("account_state_before") if isinstance(row.get("account_state_before"), dict) else {}
        state_after = row.get("account_state_after") if isinstance(row.get("account_state_after"), dict) else {}
        before = _state(row.get("orig_status") or state_before.get("status"))
        after = _state(row.get("end_status") or state_after.get("status"))
        success = _success(row, context.get("success"))
        description = row.get("description") if isinstance(row.get("description"), dict) else {}
        emulated = row.get("emulated") is True or context.get("emulated") is True
        block_time = ton_datetime(row.get("utime", row.get("now")))
        common = {"address": account, "transaction_hash": tx_hash, "logical_time": str(row.get("lt")) if row.get("lt") is not None else None,
                  "timestamp": block_time.isoformat() if block_time else context.get("timestamp"),
                  "execution_status": "emulated" if emulated else "success" if success is True else "failed" if success is False else "unknown",
                  "event_ids": [context["event_id"]] if context.get("event_id") else []}
        def history(kind, status, facts, rationale):
            if not account:
                return
            eid = fact(context["source"], context.get("url"), context.get("observation_id"), kind,
                       {**facts, "account": account, "emulated": emulated}, tx_hash=tx_hash, at=context.get("observed_at"))
            hid = _id("ton:contract-history:", [account, tx_hash, kind, facts])
            entry = histories.setdefault(hid, {"history_id": hid, "kind": kind, "status": status, **common, **facts,
                "reason": rationale, "evidence_ids": [eid], "source_urls": [context["url"]] if safe_public_url(context.get("url")) else [],
                "method": "explicit_transaction_account_states", "specification_urls": [ACCOUNT_SPEC, SCHEMA_SPEC]})
            entry["evidence_ids"] = sorted(set(entry["evidence_ids"] + [eid]))
            if safe_public_url(context.get("url")):
                entry["source_urls"] = sorted(set(entry["source_urls"] + [context["url"]]))
        if before and after and before != after:
            kind = "account_activated" if before in {"nonexist", "uninit"} and after == "active" else "account_reactivated" if before == "frozen" and after == "active" else "account_status_changed"
            history(kind, "CONFIRMED" if not emulated and success is True else "POSSIBLE",
                {"before_status": before, "after_status": after},
                "Explicit beginning/end account states in one transaction; activation does not identify deployer control or wallet application.")
        before_address, after_address = _address(state_before.get("address")), _address(state_after.get("address"))
        code_before, code_after = _hash(state_before.get("code_hash")), _hash(state_after.get("code_hash"))
        if (code_before and code_after and code_before != code_after and account
                and (not before_address or before_address == account) and (not after_address or after_address == account)):
            history("contract_code_changed", "CONFIRMED" if not emulated and success is True else "POSSIBLE",
                {"before_code_hash": code_before, "after_code_hash": code_after},
                "Distinct code hashes for the same account before/after this exact transaction; upgrade intent, operator and client are not inferred.")
        old_state, new_state = _hash(row.get("state_update_old")), _hash(row.get("state_update_new"))
        if old_state and new_state and old_state != new_state:
            history("account_state_hash_changed", "CONFIRMED" if not emulated else "POSSIBLE",
                {"before_state_hash": old_state, "after_state_hash": new_state},
                "Full account-state hashes differ; this is not evidence of a contract-code upgrade.")
        context = {**context, "trace_id": row.get("trace_id") or context.get("trace_id"), "asset": "TON"}
        inbound = row.get("in_msg")
        if isinstance(inbound, dict):
            message(inbound, {**context, **common, "tx_hash": tx_hash, "account": account,
                             "success": success, "emulated": emulated, "message_index": "in"})
            if inbound.get("init") or inbound.get("state_init"):
                if not (before in {"nonexist", "uninit", "frozen"} and after == "active" and success is True and not emulated):
                    history("state_init_observed", "POSSIBLE", {"before_status": before, "after_status": after},
                            "Inbound StateInit is present, but successful deployment/reactivation is not established by the collected states.")
        outbound = row.get("out_msgs") or []
        if isinstance(outbound, list):
            for index, row_message in enumerate(outbound):
                if not allowed():
                    break
                if isinstance(row_message, dict):
                    message(row_message, {**context, **common, "tx_hash": tx_hash, "account": account,
                        "success": success, "emulated": emulated, "message_index": index}, count=False)

    def message(row: dict, context: dict, *, count: bool = True) -> None:
        if count and not allowed():
            return
        frm, to = _address(row.get("source")), _address(row.get("destination"))
        index = context.get("message_index")
        # Only the source of an explicit outgoing message can be filled from
        # transaction.account. Missing external-in source remains null.
        if frm is None and isinstance(index, int):
            frm = _address(context.get("account"))
        if to is None and index == "in":
            to = _address(context.get("account"))
        tx_hash, message_hash = _hash(context.get("tx_hash")), _hash(row.get("hash") or context.get("message_hash"))
        identity = message_hash or _id("message:", [tx_hash, index, frm, to,
            context.get("event_id") if not tx_hash or context.get("normalized_row") else None])
        value = row.get("value", context.get("amount_base_units"))
        try:
            amount = Decimal(str(value)).scaleb(-9) if value is not None else None
            if amount is not None and not amount.is_finite():
                amount = None
        except InvalidOperation:
            amount = None
        if context.get("normalized_row"):
            amount = context.get("normalized_amount")
        success = _success(row, context.get("success"))
        if row.get("bounced") is True:
            success = False
        emulated = context.get("emulated") is True
        opcode, opcode_method = _opcode(row)
        facts = {"message_hash": message_hash, "from_address": frm, "to_address": to,
            "message_index": index, "opcode": f"0x{opcode:08x}" if opcode is not None else None,
            "success": success, "bounced": row.get("bounced"), "amount_decimal": str(amount) if amount is not None else None}
        eid = fact(context["source"], context.get("url"), context.get("observation_id"), "observed_message", facts,
                   tx_hash=tx_hash, at=context.get("observed_at"))
        event_id = context.get("event_id")
        if identity in messages:
            counts["duplicate_messages"] += 1
            existing = messages[identity]
            existing["evidence_ids"].add(eid)
            if tx_hash: existing["transaction_hashes"].add(tx_hash)
            if event_id: existing["event_ids"].add(event_id)
            if success is False and existing["success"] is True or success is True and existing["success"] is False:
                existing["conflicts"].add("Message execution status differs between collected account observations.")
                existing["success"] = None
            elif existing["success"] is None and not existing["conflicts"]:
                existing["success"] = success
        else:
            messages[identity] = {"message_id": identity, "message_hash": message_hash, "from_address": frm, "to_address": to,
                "asset": context.get("asset") or "TON", "amount_decimal": amount, "success": success,
                "asset_contract": _address(context.get("asset_contract")),
                "emulated": emulated, "timestamp": context.get("timestamp"), "event_ids": {event_id} if event_id else set(),
                "transaction_hashes": {tx_hash} if tx_hash else set(), "evidence_ids": {eid}, "conflicts": set(),
                "provider_interpreted": context.get("provider_interpreted", False)}
        trace = _hash(context.get("trace_id") or row.get("trace_id"))
        if trace:
            entry = traces.setdefault(trace, {"trace_id": trace, "status": "PROBABLE", "complete": False,
                "message_ids": set(), "transaction_hashes": set(), "event_ids": set(), "addresses": set(), "evidence_ids": set(),
                "reason": "Exact provider trace identifier in collected records; partial causal grouping does not imply shared control.",
                "specification_urls": [TRACE_SPEC]})
            entry["message_ids"].add(identity); entry["evidence_ids"].add(eid)
            entry["addresses"].update(a for a in (frm, to) if a)
            if tx_hash: entry["transaction_hashes"].add(tx_hash)
            if event_id: entry["event_ids"].add(event_id)
        if opcode is not None:
            op_id = _id("ton:operation:", [identity, opcode])
            known = OPCODES.get(opcode)
            entry = operations.setdefault(op_id, {"operation_id": op_id, "message_id": identity,
                "message_hash": message_hash, "opcode": f"0x{opcode:08x}", "name": known[0] if known else "unknown_opcode",
                "status": "CONFIRMED" if not emulated else "POSSIBLE", "interpretation_status": "POSSIBLE" if known else "UNKNOWN",
                "execution_status": "emulated" if emulated else "success" if success is True else "failed" if success is False else "unknown",
                "method": opcode_method, "from_address": frm, "to_address": to,
                "transaction_hashes": set(), "event_ids": set(), "evidence_ids": set(),
                "decoded_op_name": str(row["decoded_op_name"])[:160] if row.get("decoded_op_name") else None,
                "specification_urls": [known[1]] if known else [],
                "reason": "Exact observed opcode; a standard operation header is not a service/client fingerprint or completed asset-transfer proof."})
            entry["evidence_ids"].add(eid)
            if tx_hash: entry["transaction_hashes"].add(tx_hash)
            if event_id: entry["event_ids"].add(event_id)

    # Existing collector wrappers preserve full account transactions under raw.
    for tx in report.transactions:
        if truncated:
            break
        if tx.chain != "ton":
            continue
        if not allowed():
            break
        raw = tx.raw or {}
        context = {"source": tx.source, "url": tx.url, "event_id": event_identity(tx), "tx_hash": tx.tx_hash,
            "timestamp": tx.timestamp.isoformat() if tx.timestamp else None, "success": transaction_success(tx),
            "observation_id": raw.get("observation_id"), "message_index": raw.get("message_index"),
            "trace_id": raw.get("trace_id"), "message_hash": raw.get("message_hash"), "asset": tx.asset,
            "emulated": raw.get("transaction_is_emulated") is True,
            "provider_interpreted": raw.get("asset_type") == "action" or bool(raw.get("action_type")),
            "account": raw.get("account"), "asset_contract": raw.get("token_contract") or raw.get("jetton_master") or raw.get("contract")}
        full = raw.get("transaction") or raw.get("transaction_details")
        if isinstance(full, dict):
            transaction(full, context)
        selected_message = raw.get("message")
        if isinstance(selected_message, dict):
            message(selected_message, {**context, "asset": "TON"})
        elif not full:
            # Native normalized rows can express token amounts, while message
            # value always expresses TON. Keep this row's asset/amount separate.
            fake = {"source": tx.from_address, "destination": tx.to_address, "hash": raw.get("message_hash"),
                    "opcode": raw.get("opcode", raw.get("op_code"))}
            message(fake, {**context, "normalized_row": True, "normalized_amount": tx.amount_decimal,
                           "asset": tx.asset or "unknown"})
        # Explicit bounded provenance paths, not an unbounded recursive raw scan.
        for provenance in tx.provenance[:8]:
            p_raw = provenance.get("raw") if isinstance(provenance, dict) else None
            if isinstance(p_raw, dict) and isinstance(p_raw.get("transaction"), dict):
                transaction(p_raw["transaction"], {**context, "source": provenance.get("source", tx.source),
                    "url": provenance.get("url") or tx.url, "observation_id": p_raw.get("observation_id")})
    # P0 keeps original low-level transaction states in sanitized observations.
    for observation in intelligence.get("observations", []):
        if truncated:
            break
        if not isinstance(observation, dict):
            continue
        body = observation.get("raw")
        if observation.get("status") != "ok" or not isinstance(body, dict) or not isinstance(body.get("transactions"), list):
            continue
        for row in body["transactions"]:
            if truncated:
                break
            transaction(row, {"source": observation.get("source", "unknown"), "url": observation.get("endpoint"),
                "observed_at": observation.get("collected_at"), "observation_id": observation.get("observation_id"),
                "account": target, "asset": "TON", "trace_id": row.get("trace_id") if isinstance(row, dict) else None})
    # Exact transaction details collected for NFT events expose code/state data.
    nft = report.nft_intelligence or {}
    for event in nft.get("events", []):
        if truncated:
            break
        raw = event.get("raw") if isinstance(event, dict) else None
        if isinstance(raw, dict) and isinstance(raw.get("transaction_details"), dict):
            transaction(raw["transaction_details"], {"source": "ton_nft_transaction_details", "url": None,
                "account": event.get("asset_address"), "tx_hash": event.get("transaction_hash"),
                "event_id": event.get("event_id"), "trace_id": event.get("trace_id"), "timestamp": event.get("timestamp"),
                "emulated": raw.get("transaction_is_emulated") is True})

    routes: dict[tuple, dict] = {}
    for record in messages.values():
        if deadline is not None and time.monotonic() >= deadline:
            truncated = True; break
        frm, to = record["from_address"], record["to_address"]
        if (not target or not frm or not to or frm == to or target not in (frm, to)
                or record["success"] is False or record["emulated"]):
            continue
        cp, direction = (to, "out") if frm == target else (frm, "in")
        asset_id = "ton:native:TON" if record["asset"] == "TON" else "ton:token:" + record["asset_contract"] if record["asset_contract"] else "unqualified:" + record["asset"]
        key = (cp, direction, asset_id)
        route = routes.setdefault(key, {"relationship_id": _id("ton:relationship:", [target, *key]),
            "blockchain": "ton", "from_address": frm, "to_address": to, "counterparty": cp,
            "direction": direction, "asset": record["asset"], "asset_id": asset_id,
            "asset_identity_status": "UNKNOWN" if asset_id.startswith("unqualified:") else "CONFIRMED",
            "message_count": 0, "successful_message_count": 0,
            "amount_total_decimal": Decimal(0), "amounts_known": 0, "message_ids": set(),
            "transaction_hashes": set(), "event_ids": set(), "evidence_ids": set(), "timestamps": [],
            "conflicts": set(), "provider_interpreted": False})
        route["message_count"] += 1; route["successful_message_count"] += record["success"] is True
        if record["amount_decimal"] is not None:
            with localcontext() as context:
                context.prec = 100
                route["amount_total_decimal"] += record["amount_decimal"]
            route["amounts_known"] += 1
        route["message_ids"].add(record["message_id"]); route["transaction_hashes"].update(record["transaction_hashes"])
        route["event_ids"].update(record["event_ids"]); route["evidence_ids"].update(record["evidence_ids"])
        route["conflicts"].update(record["conflicts"])
        route["provider_interpreted"] |= record["provider_interpreted"]
        if record["timestamp"]: route["timestamps"].append(record["timestamp"])
    relationships = []
    for route in routes.values():
        labels = account_states.get(route["counterparty"], {}).get("attributions", [])
        service_labels = [label for label in labels if label.get("category") != "public_address_label"]
        confidence = "CONFIRMED" if route["message_count"] == route["successful_message_count"] else "PROBABLE"
        if route["provider_interpreted"] or route["conflicts"]:
            confidence = "POSSIBLE"
        label_statuses = {label.get("status", "UNKNOWN") for label in service_labels}
        status = "POSSIBLE" if "POSSIBLE" in label_statuses else "PROBABLE" if "PROBABLE" in label_statuses and confidence == "CONFIRMED" else confidence
        if "UNKNOWN" in label_statuses: status = "UNKNOWN"
        for label in service_labels:
            route["conflicts"].update(str(value) for value in label.get("conflicts", []))
        route["conflicts"].update(str(value) for value in account_states.get(route["counterparty"], {}).get("conflicts", []))
        if route["conflicts"]:
            status = "POSSIBLE"
        route.update({"kind": "repeated_service_route" if service_labels and route["message_count"] >= 2 else "service_interaction" if service_labels else "repeated_counterparty_route" if route["message_count"] >= 2 else "direct_counterparty_interaction",
            "status": status, "movement_status": confidence, "method": "deduplicated_direct_message_route",
            "service_attribution_ids": [label["attribution_id"] for label in service_labels if label.get("attribution_id")],
            "service_ids": sorted({label["service_id"] for label in service_labels if label.get("service_id")}),
            "first_seen": min(route["timestamps"]) if route["timestamps"] else None,
            "last_seen": max(route["timestamps"]) if route["timestamps"] else None,
            "reason": "Observed direct messages with this exact counterparty; repeated routes describe interaction frequency, not address ownership or application usage.",
            "alternative_explanations": ["Ordinary payments", "Withdrawals/refunds or purchases", "Interaction through a shared service account"],
            "ownership_inference": "UNKNOWN", "deposit_assignment": "UNKNOWN", "history_complete": False})
        route["execution_scope"] = "collected local account/message observations; destination credit is not inferred"
        route.pop("timestamps"); route["amount_total_decimal"] = str(route["amount_total_decimal"]) if route["amounts_known"] and route["asset_identity_status"] == "CONFIRMED" else None
        for label in service_labels: route["evidence_ids"].update(label.get("evidence_ids", []))
        relationships.append(route)
    limitations = list(LIMITATIONS)
    current_status = account_states.get(target, {}).get("account_status", "unknown")
    if current_status in {"uninit", "nonexist", "uninitialized"}:
        limitations.append("Target currently has no active code. Historical deployment, private service assignment, and derivation remain UNKNOWN unless separate collected history proves a specific relation.")
    result = {"schema_version": "1.0", "target_address": target, "relationships": relationships,
        "contract_history": list(histories.values()), "operations": list(operations.values()), "traces": list(traces.values()),
        "evidence": list(evidence.values()), "limitations": limitations,
        "coverage": {"status": "TRUNCATED" if truncated else "PARTIAL", "history_complete": False,
            "current_account_status": current_status, "max_records": max_records,
            "deployment_history_status": "OBSERVED" if histories else "UNKNOWN",
            "gap_reason": "Record/deadline budget reached" if truncated else "Only already collected account/message samples analyzed; missing history remains unknown"},
        "stats": {**counts, "unique_messages": len(messages), "relationships": len(relationships),
                  "contract_history_records": len(histories), "operations": len(operations), "traces": len(traces),
                  "network_requests": 0, "elapsed_seconds": time.monotonic()-started}}

    def json_value(value):
        if isinstance(value, set): return sorted(value)
        if isinstance(value, dict): return {key: json_value(item) for key, item in value.items()}
        if isinstance(value, list): return [json_value(item) for item in value]
        return value
    return sanitize_observation(json_value(result))
