"""Storage normalization parity and allocation-boundary regressions, offline."""
from __future__ import annotations

import copy
from datetime import date, datetime, time, timezone
from decimal import Decimal
from enum import Enum, IntEnum
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID

from pydantic import BaseModel
from pydantic_core import to_json

from app.ton_nft import storage
from app.utils.security import sanitize_observation


def legacy_canonical(owner):
    return json.dumps(sanitize_observation(json.loads(to_json(owner))),
        ensure_ascii=False, separators=(",", ":"))


class StringEnum(str, Enum):
    VALUE = "public enum value"


class NumberEnum(IntEnum):
    VALUE = 7


class StringSubclass(str):
    pass


class ListSubclass(list):
    pass


class PublicModel(BaseModel):
    marker: str


class OwnerNativeJsonTests(unittest.TestCase):
    def test_native_owner_skips_normalized_clone_with_identical_legacy_bytes_and_redaction(self):
        owner = {"target_address": "0:" + "1" * 64,
            "transactions": [{"tx_hash": "a" * 64, "raw": {
                "authorization": "Bearer private_synthetic_marker",
                "public_url": "https://example.org/evidence?id=123&api_key=private_synthetic_marker",
                "unicode": "Доказательство", "values": [None, True, False, 0, -4, 2 ** 100,
                    0.0, -0.0, 1.2345678901234567, 5e-324, 1.7976931348623157e308]}}]}
        before = copy.deepcopy(owner)
        canonical = legacy_canonical(owner)
        self.assertTrue(storage._is_native_json_tree(owner))
        with tempfile.TemporaryDirectory() as directory:
            store = storage.InvestigationStore(Path(directory) / "test.sqlite3")
            try:
                with patch.object(storage.json, "loads", side_effect=AssertionError("Native owner must not allocate normalized clone")):
                    with store.db:
                        reference = store._owner_reference("native", owner)
                row = store.db.execute("SELECT input_sha256,content_sha256,owner_json FROM owner_snapshots").fetchone()
            finally:
                store.close()
        self.assertEqual(row[0], hashlib.sha256(to_json(owner)).hexdigest())
        self.assertEqual(row[1], hashlib.sha256(canonical.encode()).hexdigest())
        self.assertEqual(row[2], canonical)
        self.assertEqual(reference["sha256"], row[1])
        self.assertNotIn("private_synthetic_marker", row[2])
        self.assertIn("123", row[2])
        self.assertIn("Доказательство", row[2])
        self.assertEqual(owner, before)

    def test_python_values_subclasses_nonstring_keys_and_nonfinite_numbers_keep_legacy_normalization(self):
        cases = [datetime(2026, 10, 17, 12, 34, tzinfo=timezone.utc), date(2026, 10, 17),
            time(12, 34), Decimal("123.4500"), b"public bytes", ("tuple", 7), {3, 7},
            UUID("12345678-1234-5678-1234-567812345678"), Path("public/file"),
            StringEnum.VALUE, NumberEnum.VALUE, StringSubclass("public subclass"),
            ListSubclass(["public list", 7]), PublicModel(marker="public model"),
            float("nan"), float("inf"), float("-inf"),
            {True: "boolean key", "true": "string key", 1: "integer key", "1": "collision"}]
        original_loads = json.loads
        with tempfile.TemporaryDirectory() as directory:
            store = storage.InvestigationStore(Path(directory) / "test.sqlite3")
            try:
                for index, value in enumerate(cases):
                    with self.subTest(kind=type(value).__name__, index=index):
                        owner = {"public": value, "transactions": []}
                        before = to_json(owner)
                        expected = legacy_canonical(owner)
                        self.assertFalse(storage._is_native_json_tree(owner))
                        with patch.object(storage.json, "loads", wraps=original_loads) as loads:
                            with store.db:
                                store._owner_reference(f"fallback-{index}", owner)
                        self.assertEqual(loads.call_count, 1)
                        actual = store.db.execute("SELECT owner_json FROM owner_snapshots WHERE investigation_id=?",
                            (f"fallback-{index}",)).fetchone()[0]
                        self.assertEqual(actual, expected)
                        self.assertEqual(to_json(owner), before)
            finally:
                store.close()

    def test_unchanged_owner_cache_skips_shape_and_redaction_but_nested_mutation_is_saved(self):
        owner = {"transactions": [{"raw": {"public_marker": "first"}}]}
        with tempfile.TemporaryDirectory() as directory:
            store = storage.InvestigationStore(Path(directory) / "test.sqlite3")
            try:
                with store.db:
                    first = store._owner_reference("nested", owner)
                with patch.object(storage, "_is_native_json_tree", side_effect=AssertionError("Unchanged cache must not rewalk")), \
                        patch.object(storage, "sanitize_observation", side_effect=AssertionError("Unchanged cache must not redact twice")):
                    with store.db:
                        self.assertEqual(store._owner_reference("nested", owner), first)
                owner["transactions"][0]["raw"].update({"public_marker": "changed", "password": "private_nested_marker"})
                with store.db:
                    second = store._owner_reference("nested", owner)
                self.assertNotEqual(first["sha256"], second["sha256"])
                stored = store.db.execute("SELECT owner_json FROM owner_snapshots").fetchone()[0]
                self.assertEqual(stored, legacy_canonical(owner))
                self.assertIn("changed", stored)
                self.assertNotIn("private_nested_marker", stored)
                self.assertEqual(owner["transactions"][0]["raw"]["password"], "private_nested_marker")
            finally:
                store.close()

    def test_redacted_native_tree_is_detached_and_failed_replacement_rolls_back(self):
        shared = {"values": ["original public value"]}
        owner = {"transactions": [], "left": shared, "right": shared}
        clean = sanitize_observation(owner)
        self.assertIsNot(clean, owner)
        self.assertIsNot(clean["left"], clean["right"])
        clean["left"]["values"].append("local change")
        self.assertEqual(shared["values"], ["original public value"])
        self.assertEqual(clean["right"]["values"], ["original public value"])
        with tempfile.TemporaryDirectory() as directory:
            store = storage.InvestigationStore(Path(directory) / "test.sqlite3")
            try:
                with store.db:
                    first = store._owner_reference("rollback", owner)
                before = store.db.execute("SELECT * FROM owner_snapshots").fetchone()
                owner["left"]["values"].append("new actual value")
                with self.assertRaisesRegex(RuntimeError, "synthetic later SQL failure"):
                    with store.db:
                        store._owner_reference("rollback", owner)
                        raise RuntimeError("synthetic later SQL failure")
                self.assertEqual(store.db.execute("SELECT * FROM owner_snapshots").fetchone(), before)
                with store.db:
                    final = store._owner_reference("rollback", owner)
                self.assertNotEqual(first["sha256"], final["sha256"])
                self.assertEqual(store.db.execute("SELECT owner_json FROM owner_snapshots").fetchone()[0], legacy_canonical(owner))
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
