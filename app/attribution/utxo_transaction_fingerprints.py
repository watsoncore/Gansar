"""Offline BTC/DOGE construction observations, never wallet or owner proof.

Implementation links identify reproducible code behaviour at pinned commits.
Matching public transaction fields can only produce POSSIBLE compatibility.
No private keys, API calls, clustering, or claimed ground-truth app labels occur.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

_FINAL = 0xFFFFFFFF
_NONFINAL = _FINAL - 1
_RBF = _FINAL - 2
_BIPS = "https://github.com/bitcoin/bips/blob/130b8e0fa7f30fa45532f080b87b8db27a79e46e/"
_SOURCES = {
    "bitcoin_core": "https://github.com/bitcoin/bitcoin/blob/6799119cef7ead71e2b2fc7928a0ea58d720c708/src/wallet/spend.cpp#L995",
    "electrum": "https://github.com/spesmilo/electrum/blob/38cc1dbe5ccbae7dca71c25e6c0cbe59d77d93da/electrum/wallet.py#L2012",
    "electrum_sort": "https://github.com/spesmilo/electrum/blob/38cc1dbe5ccbae7dca71c25e6c0cbe59d77d93da/electrum/transaction.py#L2496",
    "sparrow_drongo": "https://github.com/sparrowwallet/drongo/blob/499a656b0fb0aaed701aa4d32702a3c32818c813/src/main/java/com/sparrowwallet/drongo/wallet/Wallet.java#L1266",
    "dogecoin_core": "https://github.com/dogecoin/dogecoin/blob/a1c5f3d4cbf453b98ba8fcfb45ef0e286da1c5a3/src/wallet/wallet.cpp#L2405",
}
_LIMITATIONS = [
    "Construction fields are copyable and shared across applications, forks, libraries, hardware signers and custom transactions; they do not identify a wallet UI or its operator.",
    "Pinned implementation behaviour is not ground truth for the origin of a public transaction; software versions and user settings can change it.",
    "A common-input ownership assumption is not proof: CoinJoin, PayJoin, collaborative signing and shared custody can combine different parties' inputs.",
    "Change, round amounts, address freshness, output position and script-family matching do not establish common ownership; no addresses are merged here.",
    "A 100-block locktime window is a bounded compatibility screen, not an exclusion rule; delayed confirmation and offline signing can move valid examples outside it.",
]


def _mapping(value: Any) -> dict:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump()
    return {}


def _integer(value: Any, maximum: int | None = None) -> int | None:
    # Floats, booleans, negative values and arbitrary strings are not wire facts.
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    if isinstance(value, str) and (not value.isascii() or not value.isdecimal()):
        return None
    try:
        result = int(value)
    except (ValueError, TypeError):
        return None
    return result if result >= 0 and (maximum is None or result <= maximum) else None


def _first_int(record: dict, keys: tuple[str, ...], maximum: int | None = None) -> int | None:
    for key in keys:
        if key in record:
            return _integer(record[key], maximum)
    return None


def _hex(value: Any, size: int | None = None) -> bytes | None:
    if not isinstance(value, str) or len(value) % 2 or (size is not None and len(value) != size * 2):
        return None
    try:
        data = bytes.fromhex(value)
    except ValueError:
        return None
    return data if len(data) * 2 == len(value) else None


def _rows(record: dict, *keys: str) -> list[dict]:
    for key in keys:
        value = record.get(key)
        if isinstance(value, list):
            # Preserve invalid rows so completeness guards cannot silently drop them.
            return [_mapping(item) for item in value]
    return []


def _address(row: dict) -> str | None:
    prevout = _mapping(row.get("prevout"))
    value = row.get("address") or row.get("recipient") or row.get("scriptpubkey_address") or prevout.get("scriptpubkey_address")
    if not value and isinstance(row.get("addresses"), list) and len(row["addresses"]) == 1:
        value = row["addresses"][0]
    return value if isinstance(value, str) and value else None


def _prevout_script(row: dict) -> bytes | None:
    prevout = _mapping(row.get("prevout"))
    return _hex(prevout.get("scriptpubkey") if "scriptpubkey" in prevout else row.get("script_hex"))


def analyze_utxo_transaction(tx: Any, address_records: Any = None) -> dict[str, list]:
    """Inspect collected Transaction/provider data without I/O or address merging.

    Supports existing Esplora ``raw.provider_record`` (vin/vout), Blockchair
    DOGE dashboards (transaction/inputs/outputs, spending_sequence), decoded
    Core-style dictionaries and BlockCypher records. ``address_records`` is
    accepted for integration compatibility; third-party labels cannot establish
    the construction application's identity and are deliberately not promoted.
    """
    result = {name: [] for name in ("implementation_observations", "construction_fingerprints", "investigative_leads", "evidence", "checks", "limitations")}
    item = _mapping(tx)
    chain = item.get("chain")
    if chain not in {"btc", "doge"}:
        result["checks"].append({"check": "supported_utxo_chain", "status": "not_applicable"})
        return result
    result["limitations"].extend(_LIMITATIONS)
    raw = _mapping(item.get("raw"))
    payload = _mapping(raw.get("provider_record")) or raw
    metadata = _mapping(payload.get("transaction")) or payload
    provider_hash = metadata.get("txid") or metadata.get("hash")
    projected_hash = item.get("tx_hash")
    if provider_hash is not None and projected_hash:
        bound = _hex(provider_hash, 32) is not None and _hex(projected_hash, 32) is not None and provider_hash.lower() == projected_hash.lower()
        result["checks"].append({"check": "provider_transaction_hash_binding", "status": "matched" if bound else "unavailable", "facts": {"provider_hash": provider_hash, "projected_hash": projected_hash}})
        if not bound:
            result["limitations"].append("Provider transaction identifier does not match the projected transaction; its construction fields were not attached.")
            return result
    inputs = _rows(payload, "vin", "inputs")
    outputs = _rows(payload, "vout", "outputs")
    # Normalized rows lack wire sequences/scripts in existing adapters. Never
    # fill those gaps from default sequence numbers or address prefixes.
    if not inputs:
        inputs = _rows(item, "inputs")
    if not outputs:
        outputs = _rows(item, "outputs")
    version = _first_int(metadata, ("version", "ver"), 0x7FFFFFFF)
    locktime = _first_int(metadata, ("locktime", "lock_time", "nLockTime"), _FINAL)
    sequences = [_first_int(row, ("sequence", "nSequence", "spending_sequence"), _FINAL) for row in inputs]
    expected_inputs = _first_int(metadata, ("input_count", "vin_sz"))
    complete_inputs = bool(inputs) and (expected_inputs is None or expected_inputs == len(inputs))
    complete_sequences = complete_inputs and all(value is not None for value in sequences)
    expected_outputs = _first_int(metadata, ("output_count", "vout_sz"))
    complete_outputs = bool(outputs) and (expected_outputs is None or expected_outputs == len(outputs))
    status = _mapping(payload.get("status"))
    block_height = _first_int(status, ("block_height",))
    if block_height is None:
        block_height = _first_int(metadata, ("block_height", "block_id"))
    if block_height is None:
        block_height = _first_int(raw, ("block_height", "block_id"))
    coinbase = any(row.get("is_coinbase") is True or (isinstance(row.get("coinbase"), str) and bool(row["coinbase"])) or (chain == "btc" and row.get("coinbase") is True) for row in inputs) or metadata.get("is_coinbase") is True
    evidence_id = f"utxo-construction:{chain}:{item.get('tx_hash') or metadata.get('txid') or metadata.get('hash') or 'unknown'}"
    tx_urls = [item["url"]] if isinstance(item.get("url"), str) and item["url"] else []
    facts = {"version": version, "locktime": locktime, "sequences": sequences, "input_count": len(inputs), "output_count": len(outputs), "block_height": block_height, "coinbase": coinbase}
    result["evidence"].append({"evidence_id": evidence_id, "blockchain": chain, "transaction_hash": item.get("tx_hash"), "source": item.get("source", "collected_transaction"), "source_urls": tx_urls, "role": "UNKNOWN", "relation": "serialized_transaction_construction", "facts": facts})

    def observe(kind: str, observed: dict) -> None:
        result["implementation_observations"].append({"kind": kind, "status": "CONFIRMED", "role": "UNKNOWN", "facts": observed, "evidence_ids": [evidence_id], "source_urls": tx_urls})

    def check(name: str, match: bool | None, **details: Any) -> None:
        result["checks"].append({"check": name, "status": "insufficient_data" if match is None else "matched" if match else "not_matched", "facts": details})

    def profile(kind: str, label: str, implementations: list[str], urls: list[str], matched: dict, alternatives: list[str]) -> None:
        result["construction_fingerprints"].append({"kind": kind, "name": label, "status": "POSSIBLE", "role": "HEURISTIC_ASSOCIATION", "relationship": "construction_compatibility", "compatible_implementations": implementations, "facts": matched, "evidence_ids": [evidence_id], "source_urls": urls, "implementation_evidence_role": "VERIFIED_IMPLEMENTATION", "alternative_explanations": alternatives, "limitations": [_LIMITATIONS[0], _LIMITATIONS[1]]})
        for url in urls:
            if not any(entry.get("url") == url for entry in result["evidence"]):
                result["evidence"].append({"evidence_id": "utxo-implementation:" + url, "source": "pinned_primary_source", "url": url, "role": "PUBLICLY_CLAIMED_SOURCE" if url.startswith(_BIPS) else "VERIFIED_IMPLEMENTATION", "relation": "published_construction_code_or_specification", "facts": {"does_not_verify_transaction_origin": True}})

    if version is not None or locktime is not None or complete_sequences:
        observe("utxo_wire_fields", facts)
    check("wire_sequences_complete", complete_sequences, missing_sequence_count=sum(value is None for value in sequences), expected_input_count=expected_inputs)
    if coinbase:
        check("wallet_construction_profiles", False, reason="Coinbase construction is a mining role, not a spending-wallet profile.")
        return result
    if chain == "btc" and complete_sequences:
        observe("bip125_explicit_signaling", {"signals_opt_in_rbf": any(value < _NONFINAL for value in sequences), "definition": "At least one input nSequence is less than 0xfffffffe.", "does_not_establish_mempool_replacement_policy": True})
        result["limitations"].append("BIP125 signaling is a serialized fact, not proof that a particular node will accept a replacement; inherited signaling and current full-RBF policies are not evaluated.")

    recent_height = locktime is not None and block_height is not None and 0 < locktime < 500_000_000 and 1 <= block_height - locktime <= 100
    uniform_sequence = complete_sequences and len(set(sequences)) == 1 and sequences[0] in {_RBF, _NONFINAL}
    screenable = version is not None and locktime is not None and complete_sequences and block_height is not None
    core_match = recent_height and uniform_sequence and version == (2 if chain == "btc" else 1)
    check("height_locktime_standard_sequence", core_match if screenable else None, window_blocks=100, comparison_height=block_height, comparison_is_confirmation_not_creation_tip=True)
    if core_match:
        names = ["Bitcoin Core", "Electrum", "Sparrow/Drongo"] if chain == "btc" else ["Dogecoin Core"]
        urls = [_SOURCES[key] for key in (("bitcoin_core", "electrum", "sparrow_drongo") if chain == "btc" else ("dogecoin_core",))]
        profile("height_locktime_standard_sequence", "Height locktime with standard nonfinal sequence", names, urls, {"version": version, "locktime": locktime, "blocks_before_confirmation": block_height - locktime, "uniform_sequence": sequences[0]}, ["Other wallets and forks implement the same anti-fee-sniping construction.", "A user can set these transaction fields manually."])

    input_keys = []
    for row in inputs:
        txid = _hex(row.get("txid") or row.get("prev_hash") or row.get("transaction_hash") or row.get("tx_hash"), 32)
        index = _first_int(row, ("vout", "output_index", "index"), _FINAL)
        input_keys.append((txid, index) if txid is not None and index is not None else None)
    output_keys = []
    for row in outputs:
        amount = _first_int(row, ("value_sats", "value"))
        script = _hex(row.get("scriptpubkey") if "scriptpubkey" in row else row.get("script_hex") if "script_hex" in row else row.get("script") if isinstance(row.get("script"), str) else _mapping(row.get("scriptPubKey")).get("hex"))
        output_keys.append((amount, script) if amount is not None and script is not None else None)
    input_order = input_keys == sorted(input_keys) if complete_inputs and len(inputs) >= 2 and all(key is not None for key in input_keys) else None
    output_order = output_keys == sorted(output_keys) if complete_outputs and len(outputs) >= 2 and all(key is not None for key in output_keys) else None
    check("bip69_input_order", input_order, minimum_items=2, no_address_prefix_substitution=True)
    check("bip69_output_order", output_order, minimum_items=2, amounts_require_integer_base_units=True)
    if input_order is not None or output_order is not None:
        observe("bip69_ordering", {"inputs_sorted": input_order, "outputs_sorted": output_order})
    if chain == "btc" and core_match and input_order is True and output_order is True:
        profile("bip69_height_locktime", "BIP69 order with height locktime and uniform sequence", ["Electrum"], [_SOURCES["electrum"], _SOURCES["electrum_sort"], _BIPS + "bip-0069.mediawiki"], {"inputs_sorted": True, "outputs_sorted": True, "version": version, "uniform_sequence": sequences[0]}, ["Randomly ordered inputs and outputs can coincide with BIP69.", "Other BIP69 implementations, forks and custom tools share this pattern."])

    prev_scripts = [_prevout_script(row) for row in inputs]
    all_taproot = complete_inputs and all(script is not None and len(script) == 34 and script[:2] == b"\x51\x20" for script in prev_scripts)
    relative_sequences = [value for value in sequences if value is not None and 1 <= value <= 65535]
    relative_match = version == 2 and locktime == 0 and all_taproot and complete_sequences and len(relative_sequences) == 1 and all(value == _RBF or 1 <= value <= 65535 for value in sequences)
    if chain == "btc":
        check("taproot_relative_locktime_antifeesniping", relative_match if version is not None and locktime is not None and complete_sequences and all(script is not None for script in prev_scripts) else None)
    if chain == "btc" and relative_match:
        profile("taproot_relative_locktime_antifeesniping", "Taproot relative-locktime anti-fee-sniping compatible construction", ["Sparrow/Drongo"], [_SOURCES["sparrow_drongo"], _BIPS + "bip-0326.mediawiki"], {"version": 2, "locktime": 0, "relative_sequence": relative_sequences[0], "all_prevout_scripts": "P2TR", "other_sequences": "0xfffffffd", "prevout_age_verified": False}, ["BIP326 is a public proposal other implementations can follow.", "CSV contract settlement or manually constructed transactions can have the same fields; prevout ages and intent are not established."])

    # A conservative warning screen, not a CoinJoin classifier. Repeated amounts
    # occur in batching, self transfers and synthetic/fake mixes too.
    amounts = [_first_int(row, ("value_sats", "value")) for row in outputs]
    repeated = {amount: count for amount, count in Counter(value for value in amounts if value is not None and value > 0).items() if count >= 3}
    equal_output_shape = complete_inputs and complete_outputs and len(inputs) >= 3 and bool(repeated)
    check("equal_output_collaborative_caution", equal_output_shape, minimum_inputs=3, minimum_equal_outputs=3)
    if equal_output_shape:
        result["investigative_leads"].append({"kind": "collaborative_transaction_caution", "status": "POSSIBLE", "role": "HEURISTIC_ASSOCIATION", "relationship": "collaborative_construction_candidate", "facts": {"repeated_positive_output_amounts": repeated}, "evidence_ids": [evidence_id], "source_urls": [_BIPS + "bip-0078.mediawiki"], "alternative_explanations": ["Batched equal payments, self transfers or a fake mix can have the same shape."], "limitations": ["This is not identification of CoinJoin, a mixer service, participant ownership, or a wallet application."]})
    else:
        input_addresses = {_address(row) for row in inputs} - {None}
        reused = sorted(input_addresses.intersection({_address(row) for row in outputs} - {None}))
        if reused:
            observe("exact_input_output_address_reuse", {"addresses": reused})
            result["investigative_leads"].append({"kind": "reused_address_return_candidate", "status": "POSSIBLE", "role": "HEURISTIC_ASSOCIATION", "relationship": "possible_return_output", "addresses": reused, "evidence_ids": [evidence_id], "source_urls": tx_urls, "limitations": ["Exact address reuse is observable; change, self payment and common ownership are not established.", "PayJoin and collaborative signing may be present even without repeated equal outputs."]})
    return result
