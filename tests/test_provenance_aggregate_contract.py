"""Real observations survive dedupe without manufacturing aggregate responses."""
from copy import deepcopy
from decimal import Decimal
import math
from types import SimpleNamespace
import unittest

from app.utils.event_identity import event_identity, merge_provenance, observation


def item(raw, *, source="provider_A", url="https://example.org/provider-A", prior=None):
    return SimpleNamespace(raw=raw, source=source, url=url, provenance=list(prior or []),
                           chain="ton", tx_hash="a" * 64, asset="TON")


class ProvenanceAggregateContractTests(unittest.TestCase):
    def test_two_fresh_provider_bodies_retained_without_later_hybrid(self):
        current = item({"provider_a_field": {"hash": "a" * 64}})
        other = item({"provider_b_field": {"hash": "b" * 64}},
                     source="provider_B", url="https://example.org/provider-B")
        expected = [observation(current), observation(other)]
        identity = event_identity(current)
        merge_provenance(current, other)
        self.assertEqual(current.provenance, expected)
        self.assertEqual(current.raw, {**expected[0]["raw"], **expected[1]["raw"]})
        for _ in range(3):
            merge_provenance(current)
            merge_provenance(current, other)
            self.assertEqual(current.provenance, expected)
            self.assertEqual(event_identity(current), identity)

    def test_new_source_or_public_url_context_always_captured(self):
        for changes in ({"source": "provider_B"}, {"url": "https://example.org/provider-A?page=2"}):
            with self.subTest(changes=changes):
                current = item({"a": 1})
                merge_provenance(current)
                for key, value in changes.items():
                    setattr(current, key, value)
                merge_provenance(current)
                self.assertEqual(len(current.provenance), 2)
                self.assertEqual(current.provenance[-1], observation(current))

    def test_context_uses_sanitized_public_url(self):
        current = item({"a": 1}, url="https://example.org/provider-A?api_key=first")
        saved = observation(current)
        # Additional metadata makes full-record dedupe different from proving
        # that a newly built bare observation is already covered.
        saved["request_id"] = "retained-original"
        current.provenance = [saved]
        current.url = "https://example.org/provider-A?api_key=second"
        merge_provenance(current)
        self.assertEqual(current.provenance, [saved])

    def test_genuine_value_empty_or_key_deletion_is_captured(self):
        for changed in ({"a": 2, "b": 2}, {"a": 1}, {}, {"a": 1, "b": 2, "c": 3}):
            with self.subTest(changed=changed):
                current = item({"a": 1, "b": 2})
                merge_provenance(current)
                saved = deepcopy(current.provenance)
                current.raw = changed
                merge_provenance(current)
                self.assertEqual(current.provenance[:-1], saved)
                self.assertEqual(current.provenance[-1], observation(current))

    def test_bool_int_float_and_signed_zero_differences_are_captured(self):
        for old, new in ((True, 1), (False, 0), (1, 1.0), (0.0, -0.0), (-0.0, 0.0)):
            with self.subTest(old=old, new=new):
                current = item({"value": old})
                merge_provenance(current)
                current.raw = {"value": new}
                merge_provenance(current)
                self.assertEqual(len(current.provenance), 2)
                value = current.provenance[-1]["raw"]["value"]
                self.assertIs(type(value), type(new))
                if type(new) is float and new == 0.0:
                    self.assertEqual(math.copysign(1.0, value), math.copysign(1.0, new))

    def test_nested_key_or_list_order_change_is_captured(self):
        original = {"nested": {"a": 1, "b": 2}, "list": [1, 2]}
        for changed in ({"nested": {"a": 1}, "list": [1, 2]},
                        {"nested": {"a": True, "b": 2}, "list": [1, 2]},
                        {"nested": {"a": 1, "b": 2}, "list": [2, 1]}):
            with self.subTest(changed=changed):
                current = item(original)
                merge_provenance(current)
                current.raw = changed
                merge_provenance(current)
                self.assertEqual(len(current.provenance), 2)

    def test_reordered_object_keys_are_same_body(self):
        current = item({"a": 1, "nested": {"first": 1, "second": 2}})
        saved = observation(current)
        saved["request_id"] = "keep"
        current.provenance = [saved]
        current.raw = {"nested": {"second": 2, "first": 1}, "a": 1}
        merge_provenance(current)
        self.assertEqual(current.provenance, [saved])

    def test_unsupported_tuple_and_decimal_do_not_prove_coverage(self):
        for previous, changed in (([1, 2], (1, 2)), ("1.0", Decimal("1.0"))):
            with self.subTest(changed=changed):
                current = item({"value": previous})
                saved = observation(current)
                saved["request_id"] = "keep"
                current.provenance = [saved]
                current.raw = {"value": changed}
                merge_provenance(current)
                self.assertEqual(len(current.provenance), 2)
                self.assertEqual(current.provenance[0], saved)
                self.assertEqual(current.provenance[1], observation(current))

    def test_existing_full_custom_records_and_digest_collisions_survive(self):
        old_a = observation(item({"a": 1}))
        old_b = observation(item({"b": 2}, source="provider_B"))
        old_a.update(raw_digest="same-recorded-digest", custom={"request": 1})
        old_b.update(raw_digest="same-recorded-digest", custom={"request": 2})
        historical_hybrid = observation(item({"a": 1, "b": 2}))
        historical_hybrid["custom"] = "old aggregate remains untouched"
        current = item({"a": 1, "b": 2}, prior=[old_a, old_b, historical_hybrid, deepcopy(old_a)])
        before = deepcopy(current.provenance)
        merge_provenance(current)
        self.assertEqual(current.provenance, before[:3])
        self.assertEqual(current.raw, {"a": 1, "b": 2})

    def test_current_and_other_are_checked_against_separate_own_prior_records(self):
        a = observation(item({"a": 1}))
        b_with_metadata = observation(item({"b": 2}, source="provider_B"))
        b_with_metadata["request_id"] = "previous-real-record"
        current = item({"a": 1}, prior=[a, b_with_metadata])
        fresh_other = item({"b": 2}, source="provider_B")
        merge_provenance(current, fresh_other)
        # Other had no own provenance. Its fresh provider record is captured,
        # even though current already held a record with matching body/context.
        self.assertEqual(current.provenance, [a, b_with_metadata, observation(fresh_other)])
        self.assertEqual(fresh_other.provenance, [])
        self.assertEqual(current.raw, {"a": 1, "b": 2})

    def test_other_prior_union_is_not_captured_as_a_new_provider_body(self):
        a = observation(item({"a": 1}))
        b = observation(item({"b": 2}, source="provider_B"))
        c = observation(item({"c": 3}, source="provider_C"))
        current = item({"a": 1}, prior=[a])
        other = item({"b": 2, "c": 3}, source="provider_B", prior=[b, c])
        merge_provenance(current, other)
        self.assertEqual(current.provenance, [a, b, c])
        self.assertEqual(current.raw, {"a": 1, "b": 2, "c": 3})

    def test_changed_provider_value_equal_to_other_source_still_captured(self):
        a = observation(item({"value": 1}))
        b = observation(item({"value": 2}, source="provider_B"))
        current = item({"value": 2}, prior=[a, b])
        merge_provenance(current)
        self.assertEqual(current.provenance, [a, b, observation(current)])

    def test_union_requires_all_retained_top_level_keys_and_first_values(self):
        a = observation(item({"a": 1, "shared": "first"}))
        b = observation(item({"b": 2, "shared": "second"}, source="provider_B"))
        for raw, expected_count in (({"a": 1, "b": 2, "shared": "first"}, 2),
                                    ({"a": 1, "b": 2, "shared": "second"}, 3),
                                    ({"a": 1, "shared": "changed"}, 3)):
            with self.subTest(raw=raw):
                current = item(raw, prior=[deepcopy(a), deepcopy(b)])
                merge_provenance(current)
                self.assertEqual(len(current.provenance), expected_count)


if __name__ == "__main__":
    unittest.main()
