"""Bounded, I/O-free Wormhole message and exact redemption evidence.

An event or matching VAA body is not destination execution, common control, or
signing-client evidence. Deployments are deliberately limited to published pins.
"""
from __future__ import annotations

import base64
import hashlib
import re
import time
from collections import Counter

from app.attribution.normalize import CHAIN_IDS, address_id, canonical_address, normalize_chain

_PIN = "b684a42abb9926b291d7f4c46ad898fbdd324157"
_SOURCE = f"https://github.com/wormhole-foundation/wormhole/blob/{_PIN}/ethereum/contracts/Implementation.sol"
_VAA_SOURCE = f"https://github.com/wormhole-foundation/wormhole/blob/{_PIN}/ethereum/contracts/Messages.sol"
_DEPLOYMENT_SOURCE = f"https://github.com/wormhole-foundation/wormhole/blob/{_PIN}/sdk/js/src/utils/consts.ts"
_TUTORIAL = "https://wormhole.com/docs/products/messaging/tutorials/replace-signatures/"
_DEPLOYMENTS = {
    "eth": {
        "wormhole_chain_id": 2,
        "core": "0x98f3c9e6e3face36baad05fe09d375ef1464288b",
        "token_bridge": "0x3ee18b2214aff97000d974cf647e7c347e8fa585",
        "source_url": _DEPLOYMENT_SOURCE,
    },
    "bsc": {"wormhole_chain_id": 4, "core": "0x98f3c9e6e3face36baad05fe09d375ef1464288b", "token_bridge": "0xb6f6d86a8f9879a9c87f643768d9efc38c1da6e7", "source_url": _DEPLOYMENT_SOURCE},
    "polygon": {"wormhole_chain_id": 5, "core": "0x7a4b5a56256163f07b2c80a7ca55abe66c4ec4d7", "token_bridge": "0x5a58505a96d1dbf8df91cb21b54419fc36e93fde", "source_url": _DEPLOYMENT_SOURCE},
    "avalanche": {"wormhole_chain_id": 6, "core": "0x54a8e5f9c4cba08f9943965859f6c34eaf03e26c", "token_bridge": "0x0e082f06ff657d94310cb8ce8b0d9a04541d8052", "source_url": _DEPLOYMENT_SOURCE},
    "arbitrum": {"wormhole_chain_id": 23, "core": "0xa5f208e072434bc67592e4c49c1b991ba79bca46", "token_bridge": "0x0b2402144bb366a632d14b83f244d2e0e21bd39c", "source_url": _DEPLOYMENT_SOURCE},
    "optimism": {"wormhole_chain_id": 24, "core": "0xee91c335eab126df5fdb3797ea9d6ad93aec9722", "token_bridge": "0x1d68124e65fafc907325e3edbf8c4d84499daa8b", "source_url": _DEPLOYMENT_SOURCE},
}
LOG_MESSAGE_PUBLISHED = "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2"
TRANSFER_REDEEMED = "0xcaf280c8cfeba144da67230d9b009c8f868a75bac9a528fa0474be1ba317c169"
_BRIDGE_SOURCE = f"https://github.com/wormhole-foundation/wormhole/blob/{_PIN}/ethereum/contracts/bridge/Bridge.sol"
_MAX_PAYLOAD = 65536
_MAX_ENCODED = 180000
_LIMITATIONS = [
    "A successful source receipt alone proves message emission; destination execution requires the separately retained exact redemption receipt.",
    "VAA bytes are parsed and bound to an event when supplied; Guardian signatures are not verified locally.",
    "Emitter/sequence uniqueness depends on source-chain finality; finalized block membership is not checked here.",
    "Protocol usage, intended recipient, relayer and common amount/time do not establish common control or signing application.",
    "Only the pinned Wormhole deployments on existing supported EVM networks are decoded; absence of an anchor is not absence of bridging.",
]


def _context_observations(report):
    """Actual RPC evidence, retained outside financial Transaction collections."""
    coverage = _get(report, "coverage", {}) or {}
    context = coverage.get("wormhole_execution_evidence") if isinstance(coverage, dict) else None
    records = context.get("records", []) if isinstance(context, dict) else []
    out = []
    for record in records[:2] if isinstance(records, list) else []:
        if not isinstance(record, dict):
            continue
        chain = normalize_chain(record.get("source_chain"))
        native, receipt = record.get("source_transaction"), record.get("source_receipt")
        if (chain not in _DEPLOYMENTS or _integer(record.get("source_rpc_chain_id")) != CHAIN_IDS[chain]
                or not isinstance(native, dict) or not isinstance(receipt, dict)
                or not _hex(native.get("hash"), 32)
                or _hex(native.get("hash"), 32) != _hex(receipt.get("transactionHash"), 32)
                or _hex(native.get("blockHash"), 32) != _hex(receipt.get("blockHash"), 32)):
            continue
        proof = record.get("source_provenance") if isinstance(record.get("source_provenance"), dict) else {}
        operation = record.get("operation") if isinstance(record.get("operation"), dict) else {}
        vaa = operation.get("vaa") if isinstance(operation.get("vaa"), dict) else {}
        out.append({"chain": chain, "tx_hash": native["hash"], "success": _integer(receipt.get("status")) == 1,
                    "source": proof.get("source"),
                    "raw": {"receipt": receipt, "receipt_provenance": proof,
                            "wormhole_vaa": vaa.get("raw"),
                            "wormhole_execution_evidence": record}})
    return out


def _destination_execution(raw, message, intent, payload):
    """Bind successful destination redemption to the exact emitted message.

    This returns protocol evidence only. It never adds a financial operation or
    infers owner, relayer ownership, fiat value, or a token mapping from a name.
    """
    record = raw.get("wormhole_execution_evidence")
    if not isinstance(record, dict) or not intent:
        return None
    chain = normalize_chain(record.get("destination_chain"))
    pin = _DEPLOYMENTS.get(chain)
    receipt, native = record.get("destination_receipt"), record.get("destination_transaction")
    if (not pin or pin["wormhole_chain_id"] != intent["recipient_wormhole_chain_id"]
            or _integer(record.get("destination_rpc_chain_id")) != CHAIN_IDS[chain]
            or not isinstance(receipt, dict) or not isinstance(native, dict)
            or _integer(receipt.get("status")) != 1 or not _hex(receipt.get("transactionHash"), 32)
            or _hex(native.get("hash"), 32) != _hex(receipt.get("transactionHash"), 32)
            or not _hex(receipt.get("blockHash"), 32)
            or _hex(native.get("blockHash"), 32) != _hex(receipt.get("blockHash"), 32)
            or _integer(native.get("blockNumber")) != _integer(receipt.get("blockNumber"))):
        return None
    # The caller's/indexer's 'completed' label is insufficient. The receipt must
    # contain the published Token Bridge event with all three exact key fields.
    matches = []
    logs = receipt.get("logs")
    if not isinstance(logs, list):
        return None
    for log in logs[:512]:
        if not isinstance(log, dict) or log.get("removed") is True:
            continue
        topics = log.get("topics")
        if (canonical_address(chain, log.get("address")) != pin["token_bridge"]
                or not isinstance(topics, list) or len(topics) != 4
                or _hex(topics[0], 32) != TRANSFER_REDEEMED
                or any(_hex(topic, 32) is None for topic in topics)
                or _integer(topics[1]) != message["emitter_chain_id"]
                or topics[2].lower()[2:] != message["emitter_address_hex"]
                or _integer(topics[3]) != _integer(message["sequence"])
                or log.get("data") != "0x"
                or _hex(log.get("transactionHash"), 32) != _hex(receipt.get("transactionHash"), 32)
                or _hex(log.get("blockHash"), 32) != _hex(receipt.get("blockHash"), 32)
                or _integer(log.get("logIndex")) is None or _integer(log.get("logIndex")) < 0):
            continue
        matches.append(log)
    if len(matches) != 1 or not message["vaa_binding"]["body_matches_event"]:
        return None
    # Direct completeTransfer(bytes) permits an additional calldata/body check.
    # Composed calls can still be proven by the unique exact redemption event.
    calldata = _hex(native.get("input"))
    input_binding = "NOT_A_DIRECT_COMPLETE_TRANSFER_CALL"
    if canonical_address(chain, native.get("to")) == pin["token_bridge"] and calldata and calldata[:10] == "0xc6878519":
        data = bytes.fromhex(calldata[10:])
        if len(data) < 64 or int.from_bytes(data[:32], "big") != 32:
            return None
        size = int.from_bytes(data[32:64], "big")
        if size > _MAX_PAYLOAD or len(data) != 64 + (size + 31) // 32 * 32 or any(data[64 + size:]):
            return None
        binding = _vaa("0x" + data[64:64 + size].hex(), chain_id=message["emitter_chain_id"],
                       emitter=message["emitter_address_hex"], sequence=_integer(message["sequence"]),
                       nonce=message["nonce"], consistency=message["consistency_level"],
                       payload=payload)
        if not binding["body_matches_event"]:
            return None
        input_binding = "EXACT_SOURCE_MESSAGE_BODY"
    recipient = intent["recipient_address_hex"]
    return {"status": "VERIFIED_CROSS_CHAIN_TRANSFER", "verification_scope": "exact_source_message_and_successful_destination_redemption_receipts",
            "transaction_edge": False, "blockchain": chain, "transaction_hash": receipt["transactionHash"].lower(),
            "block_hash": receipt["blockHash"].lower(), "block_number": _integer(receipt.get("blockNumber")),
            "log_index": _integer(matches[0]["logIndex"]), "bridge_contract": pin["token_bridge"],
            "recipient_address": "0x" + recipient[-40:] if recipient[:24] == "0" * 24 else None,
            "message_id": message["message_id"], "calldata_binding": input_binding,
            "normalized_protocol_amount_integer": intent["normalized_amount_integer"],
            "asset_mapping_status": "NOT_HISTORICALLY_VERIFIED", "ownership_status": "UNKNOWN",
            "finality_verified": False, "signatures_verified_locally": False,
            "source": record.get("destination_provenance") if isinstance(record.get("destination_provenance"), dict) else {},
            "source_urls": [_BRIDGE_SOURCE, pin["source_url"]],
            "limitations": ["Public RPC receipt observations; source/destination finality and historical proxy runtime are not verified locally.",
                            "Protocol amount is normalized to at most 8 decimals; do not treat it as a wallet balance delta or use it as raw token units.",
                            "Successful redemption is not proof that source sender, destination recipient or relayer share a controller."]}


def receipt_targets(chain):
    """Published hydration candidates, qualified by the observed source network."""
    deployment = _DEPLOYMENTS.get(normalize_chain(chain))
    return tuple(deployment[k] for k in ("core", "token_bridge")) if deployment else ()


def _get(value, key, default=None):
    return value.get(key, default) if isinstance(value, dict) else getattr(value, key, default)


def _integer(value):
    if isinstance(value, bool):
        return None
    try:
        if isinstance(value, int):
            return value
        if isinstance(value, str) and len(value) <= 80:
            return int(value, 16 if value.startswith(("0x", "0X")) else 10)
    except ValueError:
        pass
    return None


def _hex(value, size=None):
    if not isinstance(value, str) or len(value) > _MAX_ENCODED:
        return None
    if not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value):
        return None
    if size is not None and len(value) != 2 + size * 2:
        return None
    return value.lower()


def _event(data):
    """Strict ABI(uint64,uint32,bytes,uint8), without permissive offset aliases."""
    encoded = _hex(data)
    if not encoded or len(encoded) < 2 + 160 * 2:
        return None
    raw = bytes.fromhex(encoded[2:])
    if len(raw) % 32:
        return None
    words = [int.from_bytes(raw[n:n + 32], "big") for n in range(0, 128, 32)]
    sequence, nonce, offset, consistency = words
    if sequence >= 2 ** 64 or nonce >= 2 ** 32 or offset != 128 or consistency >= 256:
        return None
    length = int.from_bytes(raw[128:160], "big")
    if length > _MAX_PAYLOAD or len(raw) != 160 + ((length + 31) // 32) * 32:
        return None
    if any(raw[160 + length:]):
        return None
    return sequence, nonce, consistency, raw[160:160 + length]


def _vaa(value, *, chain_id, emitter, sequence, nonce, consistency, payload):
    result = {"provided": value is not None, "body_matches_event": False,
              "signatures_verified": False, "status": "UNAVAILABLE"}
    if value is None:
        return result
    if isinstance(value, dict):
        value = value.get("data", value)
        value = value.get("vaa", value.get("vaaBytes")) if isinstance(value, dict) else None
    if not isinstance(value, str) or len(value) > _MAX_ENCODED:
        return {**result, "status": "REJECTED", "reason": "malformed_or_oversized_vaa"}
    try:
        encoded = _hex(value) if value.startswith("0x") else None
        raw = bytes.fromhex(encoded[2:]) if encoded else base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return {**result, "status": "REJECTED", "reason": "malformed_vaa_encoding"}
    if len(raw) < 57 or len(raw) > _MAX_PAYLOAD + 6 + 255 * 66 + 51 or raw[0] != 1:
        return {**result, "status": "REJECTED", "reason": "unsupported_or_truncated_vaa"}
    count = raw[5]
    offset = 6 + count * 66
    if len(raw) < offset + 51:
        return {**result, "status": "REJECTED", "reason": "truncated_vaa_signatures_or_body"}
    body = raw[offset:]
    match = (int.from_bytes(body[8:10], "big") == chain_id and body[10:42].hex() == emitter
             and int.from_bytes(body[42:50], "big") == sequence
             and int.from_bytes(body[4:8], "big") == nonce and body[50] == consistency
             and body[51:] == payload)
    return {**result, "status": "BODY_BOUND_SIGNATURES_UNVERIFIED" if match else "REJECTED",
            "body_matches_event": match, "guardian_set_index": int.from_bytes(raw[1:5], "big"),
            "signature_count": count, "vaa_sha256": hashlib.sha256(raw).hexdigest(),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "reason": "exact_body_fields_and_payload_match" if match else "vaa_event_binding_mismatch"}


def _transfer_intent(payload):
    # Only called for the pinned Token Bridge emitter. Payload-1 has a fixed size;
    # payload-3 carries arbitrary application bytes after its fixed fields.
    if not payload or not ((payload[0] == 1 and len(payload) == 133) or (payload[0] == 3 and len(payload) >= 133)):
        return None
    return {"payload_type": payload[0], "normalized_amount_integer": str(int.from_bytes(payload[1:33], "big")),
            "token_address_hex": payload[33:65].hex(), "token_wormhole_chain_id": int.from_bytes(payload[65:67], "big"),
            "recipient_address_hex": payload[67:99].hex(), "recipient_wormhole_chain_id": int.from_bytes(payload[99:101], "big"),
            "destination_execution_verified": False, "status": "INTENDED_DESTINATION_ONLY",
            "amount_semantics": "Token Bridge normalized protocol amount; not a target-balance delta or a fiat value."}


def analyze_cross_chain(report, payload, *, max_records=2000, max_seconds=1.5):
    """Return source-message facts without mutating report, payload, or financials.

    Reads ordinary tx.raw receipt envelopes and optional tx.raw.wormhole_vaa
    (base64, hex, or a Wormholescan response). Both outer rows and logs consume
    the shared record budget. No amount/time-only cross-chain links are emitted.
    """
    started = time.monotonic()
    limit = max(0, int(max_records))
    deadline = started + max(0.0, float(max_seconds))
    transactions = [*_context_observations(report), *(_get(report, "transactions", []) or [])]
    result = {"messages": [], "relationships": [], "hypotheses": [], "evidence": [],
              "coverage": {"status": "PARTIAL", "history_complete": False, "network_requests": 0,
                           "transactions_available": len(transactions), "transactions_examined": 0,
                           "logs_examined": 0, "max_records": limit, "max_seconds": max(0.0, float(max_seconds)),
                           "signature_verification_performed": False, "destination_execution_checked": False,
                           "supported_source_networks": sorted(_DEPLOYMENTS), "limitations": list(_LIMITATIONS)}}
    consumed = 0
    skipped = Counter()
    seen = set()
    by_message = {}

    def permitted():
        return consumed < limit and time.monotonic() < deadline

    for tx in transactions:
        if not permitted():
            result["coverage"]["status"] = "TRUNCATED"
            break
        consumed += 1
        result["coverage"]["transactions_examined"] += 1
        chain = normalize_chain(_get(tx, "chain"))
        deployment = _DEPLOYMENTS.get(chain)
        if not deployment:
            skipped["source_network_not_pinned"] += 1
            continue
        tx_hash = _hex(_get(tx, "tx_hash"), 32)
        raw = _get(tx, "raw", {})
        raw = raw if isinstance(raw, dict) else {}
        receipt = next((raw[k] for k in ("receipt", "transaction_receipt", "rpc_receipt") if isinstance(raw.get(k), dict)), None)
        if isinstance(receipt, dict) and isinstance(receipt.get("result"), dict):
            receipt = receipt["result"]
        if not receipt:
            skipped["receipt_unavailable"] += 1
            continue
        proof = raw.get("receipt_provenance", {})
        proof = proof if isinstance(proof, dict) else {}
        if not tx_hash or _hex(receipt.get("transactionHash"), 32) != tx_hash:
            skipped["receipt_hash_mismatch"] += 1
            continue
        if _integer(receipt.get("status")) != 1 or _get(tx, "success") is False or raw.get("emulated") is True:
            skipped["failed_unknown_or_emulated"] += 1
            continue
        chain_ids = [v for v in (raw.get("chainId"), receipt.get("chainId"), proof.get("chain_id")) if v is not None]
        if any(_integer(v) != CHAIN_IDS[chain] for v in chain_ids):
            skipped["chain_id_mismatch"] += 1
            continue
        logs = receipt.get("logs")
        if not isinstance(logs, list):
            skipped["logs_unavailable"] += 1
            continue
        for log in logs:
            if not permitted():
                result["coverage"]["status"] = "TRUNCATED"
                break
            consumed += 1
            result["coverage"]["logs_examined"] += 1
            if not isinstance(log, dict) or log.get("removed") is True:
                skipped["removed_or_invalid_log"] += 1
                continue
            if canonical_address(chain, log.get("address")) != deployment["core"]:
                continue
            if _hex(log.get("transactionHash"), 32) != tx_hash:
                skipped["log_hash_mismatch"] += 1
                continue
            block_hash = _hex(receipt.get("blockHash"), 32)
            if not block_hash or _hex(log.get("blockHash"), 32) != block_hash:
                skipped["log_block_hash_missing_or_mismatch"] += 1
                continue
            log_index = _integer(log.get("logIndex"))
            topics = log.get("topics")
            if log_index is None or log_index < 0 or not isinstance(topics, list) or len(topics) != 2:
                skipped["malformed_event_topics_or_index"] += 1
                continue
            emitter_topic = _hex(topics[1], 32)
            if _hex(topics[0], 32) != LOG_MESSAGE_PUBLISHED or not emitter_topic or emitter_topic[2:26] != "0" * 24:
                skipped["event_signature_or_sender_mismatch"] += 1
                continue
            decoded = _event(log.get("data"))
            if decoded is None:
                skipped["malformed_event_abi"] += 1
                continue
            sequence, nonce, consistency, body = decoded
            emitter = emitter_topic[2:]
            message_id = f"{deployment['wormhole_chain_id']}/{emitter}/{sequence}"
            payload_hash = hashlib.sha256(body).hexdigest()
            identity = (chain, tx_hash, log_index, message_id, payload_hash)
            if identity in seen:
                skipped["duplicate_physical_event"] += 1
                continue
            seen.add(identity)
            event_id = "cross_chain:" + hashlib.sha256("|".join(map(str, identity)).encode()).hexdigest()[:24]
            dependency = f"{chain}:transaction:{tx_hash}"
            vaa = _vaa(raw.get("wormhole_vaa"), chain_id=deployment["wormhole_chain_id"], emitter=emitter,
                       sequence=sequence, nonce=nonce, consistency=consistency, payload=body)
            intent = _transfer_intent(body) if "0x" + emitter[-40:] == deployment["token_bridge"] else None
            message = {"message_id": message_id, "protocol": "wormhole", "blockchain": chain,
                       "source_transaction_hash": tx_hash, "source_block_hash": block_hash,
                       "source_block_number": _integer(receipt.get("blockNumber")), "source_log_index": log_index,
                       "core_contract": deployment["core"], "emitter_address": "0x" + emitter[-40:],
                       "emitter_address_hex": emitter, "emitter_chain_id": deployment["wormhole_chain_id"],
                       "sequence": str(sequence), "nonce": nonce, "consistency_level": consistency,
                       "payload_sha256": payload_hash, "payload_bytes": len(body),
                       "status": "OBSERVED_SOURCE_MESSAGE", "settlement_status": "UNKNOWN",
                       "signatures_verified": False, "finality_verified": False, "vaa_binding": vaa,
                       "intended_transfer": intent, "evidence_ids": [event_id], "dependency_group": dependency,
                       "source_urls": [_SOURCE, deployment["source_url"]], "limitations": list(_LIMITATIONS)}
            prior = by_message.get(message_id)
            if prior and (prior["payload_sha256"] != payload_hash or prior["source_block_hash"] != block_hash):
                prior["message_identity_conflict"] = True
                message["message_identity_conflict"] = True
                skipped["message_identity_conflict"] += 1
            by_message[message_id] = message
            result["messages"].append(message)
            execution = _destination_execution(raw, message, intent, body)
            if execution:
                message["status"] = execution["status"]
                message["settlement_status"] = "OBSERVED_DESTINATION_EXECUTION"
                message["destination_execution"] = execution
                message["limitations"] = execution["limitations"]
                if intent:
                    intent["destination_execution_verified"] = True
                    intent["status"] = "OBSERVED_DESTINATION_REDEMPTION"
                result["coverage"]["destination_execution_checked"] = True
                destination_id = event_id + ":destination"
                destination_dependency = f"{execution['blockchain']}:transaction:{execution['transaction_hash']}"
                message["evidence_ids"].append(destination_id)
                result["evidence"].append({"evidence_id": destination_id,
                    "source": execution["source"].get("source"), "upstream": execution["source"].get("source"),
                    "url": execution["source"].get("source_url"), "observed_at": execution["source"].get("observed_at"),
                    "blockchain": execution["blockchain"], "address": execution["bridge_contract"],
                    "transaction_hash": execution["transaction_hash"], "relation": "wormhole_destination_execution",
                    "dependency_group": destination_dependency, "message_dependency_group": f"wormhole:message:{message_id}",
                    "response_sha256": execution["source"].get("response_sha256"),
                    "facts": execution, "source_urls": execution["source_urls"],
                    "source_independence": "Exact source event and destination redemption form one protocol transfer proof; not independent control evidence."})
                result["relationships"].append({"relationship_id": destination_id,
                    "blockchain": chain, "destination_blockchain": execution["blockchain"],
                    "from_key": address_id(chain, message["emitter_address"]),
                    "to_key": address_id(execution["blockchain"], execution["bridge_contract"]),
                    "type": "verified_cross_chain_message_execution", "status": "CONFIRMED",
                    "claim_scope": "exact_protocol_message_execution", "transaction_edge": False,
                    "message_id": message_id, "evidence_ids": [event_id, destination_id],
                    "transaction_hashes": [tx_hash, execution["transaction_hash"]],
                    "dependency_groups": [dependency, destination_dependency], "ownership_status": "UNKNOWN",
                    "signing_application_status": "UNKNOWN", "limitations": execution["limitations"]})
            result["evidence"].append({"evidence_id": event_id, "source": proof.get("source") or _get(tx, "source") or "receipt",
                "upstream": proof.get("source") or _get(tx, "source") or "receipt", "url": proof.get("source_url") or _get(tx, "url"),
                "observed_at": proof.get("observed_at"), "blockchain": chain,
                "address": message["emitter_address"], "transaction_hash": tx_hash,
                "relation": "wormhole_source_message_emission", "dependency_group": dependency,
                "message_dependency_group": f"wormhole:message:{message_id}",
                "response_sha256": proof.get("response_sha256"), "source_urls": [_SOURCE, _VAA_SOURCE, _TUTORIAL],
                "facts": {k: message[k] for k in ("message_id", "source_log_index", "source_block_hash", "payload_sha256", "vaa_binding")},
                "source_independence": "Receipt event, projections and matching VAA body are one protocol-message anchor, not independent ownership evidence."})
            result["relationships"].append({"relationship_id": event_id, "blockchain": chain,
                "from_key": address_id(chain, message["emitter_address"]), "to_key": address_id(chain, deployment["core"]),
                "type": "protocol_message_emission", "status": "CONFIRMED", "claim_scope": "source_receipt_event_only",
                "message_id": message_id, "evidence_ids": [event_id], "transaction_hashes": [tx_hash],
                "dependency_group": dependency, "ownership_status": "UNKNOWN", "signing_application_status": "UNKNOWN",
                "reason": "Exact pinned Core event, transaction/block envelope and strict ABI; " +
                    ("the separate exact destination redemption is retained." if execution else "destination settlement remains unknown."),
                "limitations": list(_LIMITATIONS)})
            if intent and not execution:
                result["hypotheses"].append({"hypothesis_id": event_id + ":destination", "subject": message_id,
                    "claim_type": "cross_chain_destination_execution", "claim": "Find a destination execution bound to this exact protocol message.",
                    "status": "OPEN", "confidence_category": "UNKNOWN", "evidence_ids": [event_id],
                    "supporting_observations": ["A pinned Token Bridge emitter published a structurally valid transfer-intent payload."],
                    "contradicting_observations": [], "alternative_explanations": ["Message may remain unredeemed, fail or be affected by a source reorganization."],
                    "missing_evidence": ["Successful destination execution consuming this exact message; local signature/finality verification."],
                    "proposed_next_experiment": "Obtain the destination receipt or chain-native redemption record and verify its exact protocol anchor.",
                    "dependency_group": dependency, "coverage": "source_only"})
    result["coverage"].update(records_examined=consumed, messages_decoded=len(result["messages"]),
                              verified_destination_executions=sum(bool(m.get("destination_execution")) for m in result["messages"]),
                              skip_reasons=dict(skipped), elapsed_seconds=time.monotonic() - started)
    return result
