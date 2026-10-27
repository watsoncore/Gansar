"""Adversarial behavioral inference tests; all generated data is synthetic."""
import copy
from datetime import datetime, timedelta, timezone
from decimal import localcontext
import unittest

from app.attribution.behavioral_profiles import analyze_behavioral_profiles


def operation(index, sender="eth:fund", receiver="eth:target", amount="10", stamp=None, **options):
    return {"operation_id": "op:" + str(index), "blockchain": "eth", "transaction_hash": "tx:" + str(index),
            "from_key": sender, "to_key": receiver, "asset_key": "eth:native", "amount_decimal": amount,
            "timestamp": stamp or "2026-10-01T12:00:00Z", "success": True, "kind": "transfer",
            "evidence_ids": ["e:" + str(index)], "dependency_group": "eth:tx:" + str(index), **options}


def route(count=3):
    rows = []
    for i in range(count):
        day = datetime(2026, 10, 1, 12, tzinfo=timezone.utc) + timedelta(days=i)
        rows += [operation(2 * i, stamp=day.isoformat()),
                 operation(2 * i + 1, "eth:target", "eth:sink", "9.9", stamp=(day + timedelta(seconds=60)).isoformat())]
    return {"operations": rows, "target_keys": ["eth:target"], "coverage": {"history_complete": False}}


def target(result):
    return next(p for p in result["profiles"] if p["address_key"] == "eth:target")


class BehavioralProfiles(unittest.TestCase):
    def test_repeated_temporal_route_is_possible_without_owner_or_service(self):
        result = analyze_behavioral_profiles(route())
        self.assertEqual(len(result["motifs"]), 1)
        motif = result["motifs"][0]
        self.assertEqual(motif["independent_pair_count"], 3)
        self.assertEqual(motif["period_support"], "MULTIPLE_UTC_DATES")
        h = result["hypotheses"][0]
        self.assertEqual(h["confidence"], "POSSIBLE")
        self.assertEqual(h["role"], "DEPOSIT_SWEEP_CANDIDATE")
        self.assertTrue(h["alternative_explanations"])
        self.assertFalse(h["coverage"]["lifetime_history_complete"])
        self.assertEqual(motif["fund_tracing"], "NOT_ESTABLISHED")
        self.assertEqual(set(h["evidence_ids"]), {"e:" + str(i) for i in range(6)})

    def test_exact_asset_partition_survives_host_decimal_precision(self):
        rows = [operation(0, amount="123456789012345678901234567890.123456789"),
                operation(1, amount="0.000000001"), operation(2, amount="999", asset_key="eth:token:x")]
        with localcontext() as ctx:
            ctx.prec = 6
            profile = target(analyze_behavioral_profiles({"operations": rows}))
        self.assertEqual(profile["assets"]["eth:native"]["incoming"]["sum"], "123456789012345678901234567890.123456790")
        self.assertEqual(profile["assets"]["eth:token:x"]["incoming"]["sum"], "999")

    def test_different_asset_outgoing_cannot_be_a_sweep(self):
        data = route()
        for row in data["operations"][1::2]:
            row["asset_key"] = "eth:unrelated-token"
        self.assertEqual(analyze_behavioral_profiles(data)["motifs"], [])

    def test_failed_and_approval_observations_never_form_motifs(self):
        for option in ({"success": False}, {"kind": "approval"}, {"kind": "resource_delegation"}):
            data = route()
            for row in data["operations"][1::2]:
                row.update(option)
            self.assertEqual(analyze_behavioral_profiles(data)["motifs"], [])

    def test_unknown_success_cannot_establish_ordered_movement(self):
        data = route()
        for row in data["operations"][1::2]:
            row["success"] = None
        result = analyze_behavioral_profiles(data)
        self.assertEqual(result["hypotheses"], [])
        self.assertEqual(target(result)["unknown_success_count"], 3)
        self.assertEqual(target(result)["assets"]["eth:native"]["outgoing"]["sum"], "0")
        self.assertEqual(target(result)["assets"]["eth:native"]["unverified_outgoing_value_observations"]["sum"], "29.7")

    def test_unknown_timestamp_prevents_false_clean_adjacency(self):
        data = route()
        data["operations"].append(operation(9, "eth:target", "eth:other", timestamp=None))
        result = analyze_behavioral_profiles(data)
        self.assertEqual(result["motifs"], [])
        self.assertEqual(target(result)["unknown_timestamp_count"], 1)

    def test_tied_timestamps_and_same_transaction_do_not_create_order(self):
        for same_tx in (False, True):
            data = route(1)
            if same_tx:
                data["operations"][1]["transaction_hash"] = data["operations"][0]["transaction_hash"]
            else:
                data["operations"][1]["timestamp"] = data["operations"][0]["timestamp"]
            self.assertEqual(analyze_behavioral_profiles(data)["motifs"], [])

    def test_duplicate_economic_projection_does_not_increase_counts(self):
        data = route()
        duplicate = copy.deepcopy(data["operations"][0])
        duplicate["operation_id"] = "other-provider-id"
        data["operations"].append(duplicate)
        result = analyze_behavioral_profiles(data)
        self.assertEqual(target(result)["observation_count"], 6)
        self.assertEqual(result["diagnostics"]["duplicate_evidence_projections_excluded"], 1)

    def test_correlated_pairs_are_not_independent_repetitions(self):
        data = route()
        for row in data["operations"][::2]:
            row["evidence_ids"] = ["shared-funding-proof"]
        result = analyze_behavioral_profiles(data)
        self.assertEqual(result["motifs"][0]["independent_pair_count"], 1)
        self.assertEqual(result["motifs"][0]["correlated_pair_count"], 2)
        self.assertEqual(result["hypotheses"][0]["confidence"], "WEAK_LEAD")

    def test_shared_root_dependency_cannot_support_a_pair(self):
        data = route()
        for row in data["operations"]:
            row["dependency_group"] = "one-trace"
        self.assertEqual(analyze_behavioral_profiles(data)["hypotheses"], [])

    def test_multiple_pairs_on_one_day_are_weak(self):
        data = route()
        for i, row in enumerate(data["operations"]):
            row["timestamp"] = (datetime(2026, 10, 1, 12, tzinfo=timezone.utc) + timedelta(minutes=i)).isoformat()
        self.assertEqual(analyze_behavioral_profiles(data)["hypotheses"][0]["confidence"], "WEAK_LEAD")

    def test_midnight_boundary_is_not_multiple_independent_periods(self):
        data = route()
        for i, row in enumerate(data["operations"]):
            row["timestamp"] = (datetime(2026, 10, 1, 23, 58, tzinfo=timezone.utc) + timedelta(minutes=i)).isoformat()
        result = analyze_behavioral_profiles(data)
        self.assertEqual(result["hypotheses"][0]["confidence"], "WEAK_LEAD")
        self.assertEqual(result["motifs"][0]["period_support"], "SHORT_OBSERVATION_WINDOW")

    def test_unprovenanced_pairs_are_not_hypotheses(self):
        data = route()
        for row in data["operations"]:
            row["evidence_ids"] = []
        self.assertEqual(analyze_behavioral_profiles(data)["hypotheses"], [])

    def test_amount_ratio_and_delay_boundaries(self):
        for change in ({"amount_decimal": "10000"}, {"timestamp": "2026-10-02T12:00:00Z"}):
            data = route(1)
            data["operations"][1].update(change)
            self.assertEqual(analyze_behavioral_profiles(data)["motifs"], [])

    def test_ratio_boundary_cannot_round_false_match_into_acceptance(self):
        data = route(1)
        data["operations"][0]["amount_decimal"] = "1"
        data["operations"][1]["amount_decimal"] = "0.7" + "9" * 100
        self.assertEqual(analyze_behavioral_profiles(data)["motifs"], [])

    def test_same_evidence_on_both_halves_cannot_prove_a_pair(self):
        data = route()
        for row in data["operations"]:
            row["evidence_ids"] = ["one-proof"]
        self.assertEqual(analyze_behavioral_profiles(data)["motifs"], [])

    def test_utxo_incidence_is_not_fabricated_as_address_movement(self):
        data = {"operations": [operation(0, "btc:a", "btc:b", blockchain="btc")],
                "utxo_transactions": [{"transaction_hash": "btc-tx", "input_keys": ["btc:a"], "output_keys": ["btc:b"]}]}
        result = analyze_behavioral_profiles(data)
        self.assertEqual(result["profiles"], [])
        self.assertEqual(result["coverage"]["utxo_transactions_available"], 1)

    def test_network_qualified_identities_cannot_mix(self):
        data = {"operations": [operation(0, "eth:a", "bsc:b")]}
        self.assertEqual(analyze_behavioral_profiles(data)["profiles"], [])

    def test_shared_service_and_short_history_do_not_establish_owner(self):
        rows = [operation(i, "eth:user" + str(i), "eth:popular") for i in range(12)]
        result = analyze_behavioral_profiles({"operations": rows})
        self.assertTrue(result["comparisons"])
        self.assertEqual({c["status"] for c in result["comparisons"]}, {"UNKNOWN"})
        self.assertEqual({c["common_controller"] for c in result["comparisons"]}, {"UNKNOWN"})
        self.assertEqual(result["hypotheses"], [])

    def test_technical_shared_sdk_is_description_without_confidence_effect(self):
        data = route(1)
        data["technical"] = {"ref": {"blockchain": "eth", "transaction_hash": "tx:0", "construction_fingerprints": [
            {"rule_id": "shared_sdk", "evidence_ids": ["proof-sdk"]}]}}
        behavior = target(analyze_behavioral_profiles(data))["technical_behavior"]
        self.assertEqual(behavior["features"], {"construction_fingerprints:shared_sdk": 1})
        self.assertEqual(behavior["confidence_effect"], "NONE")
        self.assertEqual(behavior["signing_application"], "UNKNOWN")

    def test_profile_comparison_exposes_timing_differences_without_geography(self):
        rows = []
        for i in range(6):
            for name, hour in (("left", 12), ("right", 3)):
                rows.append(operation(str(i) + name, "eth:" + name, "eth:shared-service",
                    stamp=datetime(2026, 10, i + 1, hour, tzinfo=timezone.utc).isoformat()))
        result = analyze_behavioral_profiles({"operations": rows})
        comparison = next(c for c in result["comparisons"] if {c["left_key"], c["right_key"]} == {"eth:left", "eth:right"})
        timing = next(d for d in comparison["dimensions"] if d["dimension"] == "utc_hour_counts_normalized_overlap")
        self.assertEqual(timing["overlap"], "0")
        self.assertTrue(any(d["dimension"] == "utc_hour_counts" for d in comparison["differences"]))
        self.assertEqual(comparison["common_controller"], "UNKNOWN")

    def test_stable_hypothesis_ids_and_no_input_mutation(self):
        data = route()
        saved = copy.deepcopy(data)
        a, b = analyze_behavioral_profiles(data), analyze_behavioral_profiles(data)
        self.assertEqual(data, saved)
        self.assertEqual(a["hypotheses"][0]["hypothesis_id"], b["hypotheses"][0]["hypothesis_id"])

    def test_resource_limits_prioritize_target_and_retain_explicit_coverage(self):
        data = route()
        result = analyze_behavioral_profiles(data, max_profiles=1, max_comparisons=0)
        self.assertEqual([p["address_key"] for p in result["profiles"]], ["eth:target"])
        self.assertEqual(result["coverage"]["status"], "TRUNCATED")
        self.assertEqual(result["comparisons"], [])
        expired = analyze_behavioral_profiles(data, max_seconds=0)
        self.assertEqual(expired["profiles"], [])
        self.assertTrue(expired["coverage"]["time_budget_exhausted"])

    def test_nonfinite_floats_and_extreme_exponents_cannot_poison_sums(self):
        data = {"operations": [operation(i, amount=amount) for i, amount in enumerate(["NaN", "Infinity", "1e9999999", 0.1])]}
        profile = target(analyze_behavioral_profiles(data))
        self.assertEqual(profile["assets"]["eth:native"]["incoming"]["sum"], "0")
        self.assertEqual(profile["assets"]["eth:native"]["unknown_amount_count"], 4)

    def test_display_float_cannot_recover_exact_amount_or_ratio(self):
        data = route()
        for row in data["operations"]:
            row["amount_precision"] = "display_float"
        result = analyze_behavioral_profiles(data)
        self.assertEqual(result["motifs"], [])
        native = target(result)["assets"]["eth:native"]
        self.assertEqual(native["incoming"]["sum"], "0")
        self.assertEqual(native["unknown_amount_count"], 6)
        self.assertEqual(native["amount_precision_counts"], {"display_float": 6})

    def test_upstream_analysis_timestamp_keeps_verification_deterministic(self):
        data = route()
        data["analysis_performed_at"] = "2026-10-20T12:34:56Z"
        result = analyze_behavioral_profiles(data)
        self.assertEqual(result["hypotheses"][0]["last_verified"], data["analysis_performed_at"])


if __name__ == "__main__":
    unittest.main()
