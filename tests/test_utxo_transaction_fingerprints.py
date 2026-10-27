"""Construction compatibility stays separate from wallet/owner attribution."""
import copy
import unittest

from app.attribution.utxo_transaction_fingerprints import analyze_utxo_transaction
from app.models.report import Transaction


def transaction(chain="btc", **overrides):
    provider = {
        "version": 2 if chain == "btc" else 1,
        "locktime": 900000,
        "status": {"block_height": 900001},
        "vin": [
            {"txid": "01" * 32, "vout": 0, "sequence": 0xFFFFFFFD, "prevout": {"scriptpubkey": "5120" + "11" * 32, "scriptpubkey_address": "same"}},
            {"txid": "02" * 32, "vout": 1, "sequence": 0xFFFFFFFD, "prevout": {"scriptpubkey": "5120" + "22" * 32}},
        ],
        "vout": [
            {"value": 1000, "scriptpubkey": "0014" + "33" * 20, "scriptpubkey_address": "same"},
            {"value": 2000, "scriptpubkey": "0014" + "44" * 20},
        ],
    }
    provider.update(overrides)
    return Transaction(chain=chain, tx_hash="a" * 64, source="offline_fixture", raw={"provider_record": provider})


def profiles(result):
    return {row["kind"] for row in result["construction_fingerprints"]}


def checked(result, name):
    return next(row for row in result["checks"] if row["check"] == name)


class UtxoConstruction(unittest.TestCase):
    def test_esplora_bip69_and_height_profile_are_only_possible(self):
        result = analyze_utxo_transaction(transaction())
        self.assertEqual(profiles(result), {"height_locktime_standard_sequence", "bip69_height_locktime"})
        for row in result["construction_fingerprints"]:
            self.assertEqual(row["status"], "POSSIBLE")
            self.assertEqual(row["role"], "HEURISTIC_ASSOCIATION")
            self.assertEqual(row["relationship"], "construction_compatibility")
            self.assertTrue(row["alternative_explanations"])
        self.assertTrue(all(isinstance(value, list) for value in result.values()))

    def test_transaction_dict_and_model_have_identical_results_and_are_not_mutated(self):
        tx = transaction().model_dump()
        before = copy.deepcopy(tx)
        self.assertEqual(analyze_utxo_transaction(tx), analyze_utxo_transaction(Transaction(**tx)))
        self.assertEqual(tx, before)

    def test_provider_transaction_identity_must_match_projected_hash(self):
        for field in ("txid", "hash"):
            tx = transaction(**{field: "b" * 64})
            result = analyze_utxo_transaction(tx)
            self.assertFalse(profiles(result))
            self.assertFalse(result["implementation_observations"])
            self.assertEqual(checked(result, "provider_transaction_hash_binding")["status"], "unavailable")
        tx = transaction(txid="A" * 64)
        self.assertTrue(profiles(analyze_utxo_transaction(tx)))

    def test_wrong_version_or_unconfirmed_or_timestamp_locktime_cannot_match(self):
        for overrides in ({"version": 1}, {"status": {}}, {"locktime": 500000000}, {"locktime": 900001}, {"locktime": 899899}):
            with self.subTest(overrides=overrides):
                self.assertFalse(profiles(analyze_utxo_transaction(transaction(**overrides))))

    def test_input_order_uses_displayed_tx_hash_then_numeric_index(self):
        tx = transaction().model_dump()
        vin = tx["raw"]["provider_record"]["vin"]
        # BIP69 compares reversed wire hashes, i.e. conventional displayed txids.
        vin[0]["txid"] = "00" * 31 + "ff"
        vin[1]["txid"] = "01" + "00" * 31
        self.assertEqual(checked(analyze_utxo_transaction(tx), "bip69_input_order")["status"], "matched")
        vin[1]["txid"] = vin[0]["txid"]
        vin[0]["vout"], vin[1]["vout"] = 10, 2
        self.assertEqual(checked(analyze_utxo_transaction(tx), "bip69_input_order")["status"], "not_matched")

    def test_reverse_input_or_output_order_removes_electrum_compatibility_only(self):
        for key in ("vin", "vout"):
            tx = transaction().model_dump()
            tx["raw"]["provider_record"][key].reverse()
            self.assertEqual(profiles(analyze_utxo_transaction(tx)), {"height_locktime_standard_sequence"})

    def test_bip69_equal_amount_tiebreaker_requires_script_not_address(self):
        tx = transaction().model_dump()
        rows = tx["raw"]["provider_record"]["vout"]
        rows[1]["value"] = rows[0]["value"]
        rows[0]["scriptpubkey"], rows[1]["scriptpubkey"] = "ffff", "0000"
        result = analyze_utxo_transaction(tx)
        self.assertEqual(checked(result, "bip69_output_order")["status"], "not_matched")
        del rows[0]["scriptpubkey"]
        self.assertEqual(checked(analyze_utxo_transaction(tx), "bip69_output_order")["status"], "insufficient_data")

    def test_one_input_is_not_meaningful_input_order_evidence(self):
        tx = transaction().model_dump()
        tx["raw"]["provider_record"]["vin"].pop()
        result = analyze_utxo_transaction(tx)
        self.assertNotIn("bip69_height_locktime", profiles(result))
        self.assertEqual(checked(result, "bip69_input_order")["status"], "insufficient_data")

    def test_missing_or_invalid_sequence_never_becomes_a_default(self):
        for value in (None, -1, 0x100000000, True, 4294967293.0, "fdffffff", "１２"):
            tx = transaction().model_dump()
            tx["raw"]["provider_record"]["vin"][0]["sequence"] = value
            result = analyze_utxo_transaction(tx)
            self.assertFalse(profiles(result))
            self.assertEqual(checked(result, "wire_sequences_complete")["status"], "not_matched")

    def test_partial_input_list_cannot_match_profiles(self):
        result = analyze_utxo_transaction(transaction(input_count=3))
        self.assertFalse(profiles(result))
        self.assertEqual(checked(result, "bip69_input_order")["status"], "insufficient_data")

    def test_nonfinal_nonrbf_is_compatible_but_mixed_or_final_sequences_are_not(self):
        for sequences, expected in (([0xFFFFFFFE] * 2, True), ([0xFFFFFFFF] * 2, False), ([0xFFFFFFFD, 0xFFFFFFFE], False)):
            tx = transaction().model_dump()
            for row, sequence in zip(tx["raw"]["provider_record"]["vin"], sequences):
                row["sequence"] = sequence
            self.assertEqual("height_locktime_standard_sequence" in profiles(analyze_utxo_transaction(tx)), expected)

    def test_bip125_is_only_serialized_signaling_and_not_doge_policy(self):
        for chain in ("btc", "doge"):
            result = analyze_utxo_transaction(transaction(chain))
            rows = [row for row in result["implementation_observations"] if row["kind"] == "bip125_explicit_signaling"]
            self.assertEqual(bool(rows), chain == "btc")
            if rows:
                self.assertTrue(rows[0]["facts"]["signals_opt_in_rbf"])
                self.assertTrue(rows[0]["facts"]["does_not_establish_mempool_replacement_policy"])

    def test_blockchair_doge_spending_sequence_is_not_previous_transaction_version(self):
        tx = Transaction(chain="doge", tx_hash="d" * 64, source="blockchair_dogecoin", raw={"provider_record": {
            "transaction": {"version": 1, "lock_time": 6422451, "block_id": 6422462, "input_count": 1, "output_count": 2},
            "inputs": [{"transaction_hash": "b" * 64, "index": 1, "spending_sequence": 4294967293, "is_from_coinbase": True}],
            "outputs": [{"value": 1000, "script_hex": "76a914" + "11" * 20 + "88ac"}, {"value": 2000, "script_hex": "a914" + "22" * 20 + "87"}],
        }})
        result = analyze_utxo_transaction(tx)
        self.assertEqual(profiles(result), {"height_locktime_standard_sequence"})
        self.assertEqual(result["construction_fingerprints"][0]["compatible_implementations"], ["Dogecoin Core"])

    def test_blockcypher_doge_keys_are_accepted(self):
        tx = Transaction(chain="doge", tx_hash="d" * 64, source="fixture", raw={"ver": 1, "lock_time": 6422451, "block_height": 6422462, "vin_sz": 1, "vout_sz": 1,
            "inputs": [{"prev_hash": "b" * 64, "output_index": 1, "sequence": 4294967293}], "outputs": [{"value": 1000, "script": "51"}]})
        self.assertEqual(profiles(analyze_utxo_transaction(tx)), {"height_locktime_standard_sequence"})

    def test_normalized_doge_coinbase_flag_is_previous_output_origin(self):
        tx = Transaction(chain="doge", tx_hash="d" * 64, source="fixture", raw={"version": 1, "lock_time": 50, "block_id": 51},
            inputs=[{"coinbase": True, "sequence": 4294967293}], outputs=[{"value_sats": 1000}])
        result = analyze_utxo_transaction(tx)
        self.assertEqual(profiles(result), {"height_locktime_standard_sequence"})
        self.assertFalse(result["evidence"][0]["facts"]["coinbase"])

    def test_bip326_style_relative_profile_requires_all_serialized_prevouts_taproot(self):
        tx = transaction(locktime=0).model_dump()
        tx["raw"]["provider_record"]["vin"][0]["sequence"] = 42
        result = analyze_utxo_transaction(tx)
        self.assertEqual(profiles(result), {"taproot_relative_locktime_antifeesniping"})
        self.assertFalse(result["construction_fingerprints"][0]["facts"]["prevout_age_verified"])
        tx["raw"]["provider_record"]["vin"][1]["prevout"]["scriptpubkey"] = "0014" + "22" * 20
        self.assertFalse(profiles(analyze_utxo_transaction(tx)))

    def test_relative_profile_rejects_multiple_low_sequences_time_units_and_disabled_flag(self):
        for sequences in ([42, 43], [0x40002A, 0xFFFFFFFD], [0x8000002A, 0xFFFFFFFD], [0, 0xFFFFFFFD], [65536, 0xFFFFFFFD]):
            tx = transaction(locktime=0).model_dump()
            for row, sequence in zip(tx["raw"]["provider_record"]["vin"], sequences):
                row["sequence"] = sequence
            self.assertFalse(profiles(analyze_utxo_transaction(tx)))

    def test_address_only_taproot_prefix_is_not_relative_profile_evidence(self):
        tx = transaction(locktime=0).model_dump()
        tx["raw"]["provider_record"]["vin"][0]["sequence"] = 42
        del tx["raw"]["provider_record"]["vin"][1]["prevout"]["scriptpubkey"]
        tx["raw"]["provider_record"]["vin"][1]["prevout"]["scriptpubkey_address"] = "bc1p" + "a" * 58
        self.assertFalse(profiles(analyze_utxo_transaction(tx)))

    def test_normalized_float_amounts_and_missing_wire_fields_do_not_create_profiles(self):
        tx = Transaction(chain="btc", tx_hash="a" * 64, source="fixture", inputs=[{"address": "same", "value": 1.0}], outputs=[{"address": "same", "value": 0.9}])
        result = analyze_utxo_transaction(tx)
        self.assertFalse(profiles(result))
        self.assertEqual(checked(result, "bip69_output_order")["status"], "insufficient_data")
        self.assertEqual(result["investigative_leads"][0]["status"], "POSSIBLE")

    def test_equal_output_shape_is_caution_and_suppresses_change_candidate(self):
        tx = transaction().model_dump()
        p = tx["raw"]["provider_record"]
        p["vin"].append({"txid": "03" * 32, "vout": 0, "sequence": 0xFFFFFFFD})
        p["vout"] = [{"value": 1000, "scriptpubkey": "51", "scriptpubkey_address": "same"}] * 3
        result = analyze_utxo_transaction(tx)
        self.assertEqual([row["kind"] for row in result["investigative_leads"]], ["collaborative_transaction_caution"])
        self.assertEqual(result["investigative_leads"][0]["status"], "POSSIBLE")
        self.assertIn("fake mix", result["investigative_leads"][0]["alternative_explanations"][0])

    def test_reuse_and_public_labels_never_prove_wallet_ui_change_or_owner(self):
        tx = transaction()
        result = analyze_utxo_transaction(tx, address_records={"same": {"wallet": "Electrum", "status": "CONFIRMED"}})
        self.assertEqual(result, analyze_utxo_transaction(tx))
        leads = result["investigative_leads"]
        self.assertEqual(leads[0]["relationship"], "possible_return_output")
        self.assertTrue(all(row["status"] == "POSSIBLE" for row in leads))
        self.assertFalse(any("owner" in row.get("relationship", "") for row in leads))

    def test_coinbase_and_other_network_do_not_get_wallet_profiles(self):
        tx = transaction().model_dump()
        tx["raw"]["provider_record"]["vin"][0]["is_coinbase"] = True
        self.assertFalse(profiles(analyze_utxo_transaction(tx)))
        tx["chain"] = "eth"
        result = analyze_utxo_transaction(tx)
        self.assertEqual(result["checks"], [{"check": "supported_utxo_chain", "status": "not_applicable"}])


if __name__ == "__main__":
    unittest.main()
