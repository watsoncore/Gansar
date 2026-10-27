"""Deterministic contract/message observations; no HTTP or expected-service maps."""
from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal
import json
import time
import unittest

from app.models.report import AddressReport, Transaction
from app.ton_attribution.relationships import analyze_ton_relationships

TARGET = "0:"+"a1"*32
SERVICE = "0:"+"b1"*32
OTHER = "0:"+"c1"*32
HASH = "d1"*32
MSG = "e1"*32
TRACE = "f1"*32


def tx(*, tx_hash=HASH, message_hash=MSG, sender=TARGET, recipient=SERVICE, amount="1.000000001", success=True, raw=None):
    return Transaction(chain="ton", tx_hash=tx_hash, from_address=sender, to_address=recipient,
        amount_decimal=Decimal(amount), amount=float(amount), asset="TON", source="fixture",
        timestamp=datetime(2026, 10, 16, tzinfo=timezone.utc), success=success,
        url="https://example.org/transaction/"+tx_hash,
        raw=raw if raw is not None else {"message_hash": message_hash, "message_index": "in"})


def report(rows=None):
    return AddressReport(target_address=TARGET, detected_chains=["ton"], transactions=rows or [])


def full_transaction(**kwargs):
    return {"hash": HASH, "account": {"address": TARGET}, "lt": 10, "utime": 1792108800,
        "success": True, "aborted": False, "orig_status": "active", "end_status": "active",
        "in_msg": {"hash": MSG, "source": {"address": OTHER}, "destination": {"address": TARGET},
                   "value": "1000000001", "op_code": "0x7362d09c"}, "out_msgs": [], **kwargs}


class TonRelationshipsTests(unittest.TestCase):
    def test_same_symbol_tokens_not_summed_as_one_verified_asset(self):
        first, second = tx(), tx(tx_hash="d2"*32, message_hash="e2"*32)
        first.asset = second.asset = "USD"
        result = analyze_ton_relationships(report([first, second]))
        self.assertEqual(result["relationships"][0]["asset_identity_status"], "UNKNOWN")
        self.assertIsNone(result["relationships"][0]["amount_total_decimal"])
        first.raw["jetton_master"] = OTHER
        second.raw["jetton_master"] = SERVICE
        result = analyze_ton_relationships(report([first, second]))
        self.assertEqual(len(result["relationships"]), 2)
        self.assertEqual(len({r["asset_id"] for r in result["relationships"]}), 2)

    def test_service_interaction_does_not_attribute_target_or_controller(self):
        item = report([tx()])
        intelligence = {"addresses": {SERVICE: {"attributions": [{"attribution_id": "label:fixture",
            "service_id": "fixture_service", "category": "custodial_service", "status": "PROBABLE", "evidence_ids": ["e:label"]}]}}}
        original = deepcopy(intelligence)
        result = analyze_ton_relationships(item, intelligence)
        relation = result["relationships"][0]
        self.assertEqual(relation["kind"], "service_interaction")
        self.assertEqual(relation["movement_status"], "CONFIRMED")
        self.assertEqual(relation["status"], "PROBABLE")
        self.assertEqual(relation["counterparty"], SERVICE)
        self.assertEqual(relation["ownership_inference"], "UNKNOWN")
        self.assertEqual(relation["deposit_assignment"], "UNKNOWN")
        self.assertIn("e:label", relation["evidence_ids"])
        self.assertEqual(intelligence, original)
        self.assertFalse(item.ton_service_intelligence)

    def test_cross_account_message_duplicates_not_repeat_or_double_amount(self):
        rows = [tx(), tx(tx_hash="d2"*32)]
        result = analyze_ton_relationships(report(rows))
        relation = result["relationships"][0]
        self.assertEqual(relation["kind"], "direct_counterparty_interaction")
        self.assertEqual(relation["message_count"], 1)
        self.assertEqual(Decimal(relation["amount_total_decimal"]), Decimal("1.000000001"))
        self.assertEqual(len(relation["transaction_hashes"]), 2)
        self.assertEqual(len(relation["event_ids"]), 2)
        self.assertEqual(result["stats"]["duplicate_messages"], 1)

    def test_distinct_messages_same_account_transaction_count_separately(self):
        rows = [tx(raw={"message_hash": MSG, "message_index": 0}),
                tx(message_hash="e2"*32, raw={"message_hash": "e2"*32, "message_index": 1})]
        result = analyze_ton_relationships(report(rows))
        self.assertEqual(result["relationships"][0]["message_count"], 2)
        self.assertEqual(result["relationships"][0]["kind"], "repeated_counterparty_route")
        self.assertEqual(result["relationships"][0]["ownership_inference"], "UNKNOWN")

    def test_repeated_service_route_keeps_direction_asset_and_exact_amount(self):
        rows = [tx(), tx(tx_hash="d2"*32, message_hash="e2"*32, amount="2.000000002"),
                tx(tx_hash="d3"*32, message_hash="e3"*32, sender=SERVICE, recipient=TARGET)]
        intel = {"addresses": {SERVICE: {"attributions": [{"attribution_id": "a", "service_id": "example", "category": "exchange", "status": "CONFIRMED"}]}}}
        result = analyze_ton_relationships(report(rows), intel)
        self.assertEqual(len(result["relationships"]), 2)
        outgoing = next(r for r in result["relationships"] if r["direction"] == "out")
        self.assertEqual(outgoing["kind"], "repeated_service_route")
        self.assertEqual(outgoing["amount_total_decimal"], "3.000000003")
        self.assertEqual(outgoing["status"], "CONFIRMED")
        self.assertEqual(outgoing["ownership_inference"], "UNKNOWN")

    def test_unknown_execution_not_confirmed_failed_and_emulated_excluded(self):
        rows = [tx(success=None), tx(tx_hash="d2"*32, message_hash="e2"*32, success=False),
                tx(tx_hash="d3"*32, raw={"message_hash": "e3"*32, "transaction_is_emulated": True})]
        result = analyze_ton_relationships(report(rows))
        relation = result["relationships"][0]
        self.assertEqual(relation["message_count"], 1)
        self.assertEqual(relation["status"], "PROBABLE")
        self.assertEqual(result["stats"]["unique_messages"], 3)

    def test_provider_action_is_not_promoted_to_chain_confirmed(self):
        result = analyze_ton_relationships(report([tx(raw={"action_type": "TonTransfer", "message_hash": MSG})]))
        self.assertEqual(result["relationships"][0]["status"], "POSSIBLE")

    def test_conflicting_message_success_preserved_without_confirmed_route(self):
        result = analyze_ton_relationships(report([tx(success=True), tx(tx_hash="d2"*32, success=False)]))
        self.assertEqual(result["relationships"][0]["status"], "POSSIBLE")
        self.assertTrue(result["relationships"][0]["conflicts"])

    def test_uninitialized_to_active_is_observed_activation_not_controller(self):
        full = full_transaction(orig_status="uninit", end_status="active")
        result = analyze_ton_relationships(report([tx(raw={"transaction": full})]))
        activation = next(h for h in result["contract_history"] if h["kind"] == "account_activated")
        self.assertEqual(activation["status"], "CONFIRMED")
        self.assertEqual(activation["address"], TARGET)
        self.assertEqual(activation["before_status"], "uninit")
        self.assertTrue(activation["evidence_ids"])
        self.assertFalse(any("controller" in key for key in activation))

    def test_frozen_reactivation_not_first_deployment(self):
        result = analyze_ton_relationships(report([tx(raw={"transaction": full_transaction(orig_status="frozen", end_status="active")})]))
        self.assertEqual(result["contract_history"][0]["kind"], "account_reactivated")

    def test_state_init_without_active_transition_is_candidate_only(self):
        full = full_transaction(success=False, aborted=True, orig_status="uninit", end_status="uninit")
        full["in_msg"]["init"] = {"boc": "not-executed-stateinit"}
        result = analyze_ton_relationships(report([tx(raw={"transaction": full})]))
        self.assertEqual(result["contract_history"][0]["kind"], "state_init_observed")
        self.assertEqual(result["contract_history"][0]["status"], "POSSIBLE")

    def test_state_update_hash_change_is_not_contract_upgrade(self):
        full = full_transaction(state_update_old="11"*32, state_update_new="22"*32)
        result = analyze_ton_relationships(report([tx(raw={"transaction": full})]))
        self.assertEqual([h["kind"] for h in result["contract_history"]], ["account_state_hash_changed"])
        self.assertIn("not evidence", result["contract_history"][0]["reason"])

    def test_code_hash_change_requires_same_account_explicit_code_hashes(self):
        full = full_transaction(account_state_before={"address": TARGET, "code_hash": "11"*32},
            account_state_after={"address": TARGET, "code_hash": "22"*32})
        result = analyze_ton_relationships(report([tx(raw={"transaction_details": full})]))
        self.assertEqual(result["contract_history"][0]["kind"], "contract_code_changed")
        self.assertEqual(result["contract_history"][0]["status"], "CONFIRMED")
        full["account_state_before"]["address"] = OTHER
        self.assertFalse(analyze_ton_relationships(report([tx(raw={"transaction": full})]))["contract_history"])

    def test_same_transaction_multiple_sources_keeps_corroboration(self):
        full = full_transaction(orig_status="uninit", end_status="active")
        first, second = tx(raw={"transaction": full}), tx(raw={"transaction": full})
        second.source = "independent_fixture"
        result = analyze_ton_relationships(report([first, second]))
        self.assertEqual(len(result["contract_history"]), 1)
        self.assertEqual(len(result["contract_history"][0]["evidence_ids"]), 2)
        self.assertEqual(result["stats"]["unique_messages"], 1)

    def test_opcode_protocol_candidate_never_wallet_application(self):
        full = full_transaction()
        result = analyze_ton_relationships(report([tx(raw={"transaction": full})]))
        operation = result["operations"][0]
        self.assertEqual(operation["opcode"], "0x7362d09c")
        self.assertEqual(operation["name"], "jetton_transfer_notification")
        self.assertEqual(operation["status"], "CONFIRMED")
        self.assertEqual(operation["interpretation_status"], "POSSIBLE")
        self.assertFalse(any(key in operation for key in ("service_id", "wallet_application", "client")))
        full["in_msg"]["op_code"] = "0x7369676e"
        wallet_op = analyze_ton_relationships(report([tx(raw={"transaction": full})]))["operations"][0]
        self.assertEqual(wallet_op["name"], "wallet_v5_external_signed_request")
        self.assertNotIn("Tonkeeper", json.dumps(wallet_op))

    def test_raw_body_header_and_unknown_opcode_retained(self):
        data = bytes.fromhex("5fcc3d14")
        cell = bytes([0, 8])+data
        body = base64.b64encode(bytes.fromhex("b5ee9c720101010100")+bytes([len(cell),0])+cell).decode()
        full = full_transaction(); full["in_msg"].pop("op_code"); full["in_msg"]["raw_body"] = body
        operation = analyze_ton_relationships(report([tx(raw={"transaction": full})]))["operations"][0]
        self.assertEqual(operation["name"], "nft_transfer_request")
        self.assertEqual(operation["method"], "raw_body_first_32_bits")
        full["in_msg"]["op_code"] = "0x12345678"
        operation = analyze_ton_relationships(report([tx(raw={"transaction": full})]))["operations"][0]
        self.assertEqual(operation["name"], "unknown_opcode")
        self.assertEqual(operation["interpretation_status"], "UNKNOWN")

    def test_trace_identifier_causal_group_is_partial(self):
        result = analyze_ton_relationships(report([tx(raw={"message_hash": MSG, "trace_id": TRACE}),
            tx(tx_hash="d2"*32, raw={"message_hash": "e2"*32, "trace_id": TRACE})]))
        self.assertEqual(len(result["traces"]), 1)
        trace = result["traces"][0]
        self.assertEqual(len(trace["message_ids"]), 2)
        self.assertFalse(trace["complete"])
        self.assertEqual(trace["status"], "PROBABLE")

    def test_current_uninit_does_not_erase_historical_activation(self):
        intel = {"addresses": {TARGET: {"account_status": "nonexist"}}}
        result = analyze_ton_relationships(report([tx(raw={"transaction": full_transaction(orig_status="uninit", end_status="active")})]), intel)
        self.assertTrue(result["contract_history"])
        self.assertTrue(any("never been deployed" in note for note in result["limitations"]))
        self.assertEqual(result["coverage"]["current_account_status"], "nonexist")
        self.assertFalse(result["coverage"]["history_complete"])

    def test_p0_observation_raw_and_nft_details_use_existing_evidence_only(self):
        full = full_transaction(orig_status="uninit", end_status="active")
        item = report()
        item.nft_intelligence = {"events": [{"event_id": "nft:event", "asset_address": TARGET,
            "raw": {"transaction_details": {**full, "hash": "d2"*32}}}]}
        intelligence = {"observations": [{"status": "ok", "source": "tonapi", "endpoint": "https://tonapi.io/v2/blockchain/accounts/fixture/transactions",
            "collected_at": "2026-10-16T12:00:00Z", "observation_id": "obs:fixture", "raw": {"transactions": [full]}}]}
        result = analyze_ton_relationships(item, intelligence)
        self.assertEqual(len(result["contract_history"]), 2)
        self.assertEqual(result["stats"]["network_requests"], 0)
        self.assertTrue(any(e["observation_id"] == "obs:fixture" for e in result["evidence"]))

    def test_record_and_deadline_limits_preserve_truthful_partial(self):
        item = report([tx(), tx(tx_hash="d2"*32, message_hash="e2"*32)])
        limited = analyze_ton_relationships(item, max_records=2)
        self.assertEqual(limited["coverage"]["status"], "TRUNCATED")
        self.assertEqual(limited["relationships"][0]["message_count"], 1)
        expired = analyze_ton_relationships(item, deadline=time.monotonic()-1)
        self.assertFalse(expired["relationships"])
        self.assertEqual(expired["coverage"]["status"], "TRUNCATED")

    def test_non_ton_rows_ignored_and_output_contains_no_secret_from_raw(self):
        item = report([tx(raw={"message_hash": MSG, "Authorization": "Bearer fixture_secret"})])
        item.transactions.append(Transaction(chain="eth", tx_hash="eth", source="fixture", from_address="0x1", to_address="0x2"))
        result = analyze_ton_relationships(item)
        self.assertEqual(len(result["relationships"]), 1)
        self.assertNotIn("fixture_secret", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
