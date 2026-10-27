"""Depth bounding reuses only the sanitizer's detached private containers."""
from datetime import datetime, timezone
from decimal import Decimal
import json
import unittest

from app.utils import security


def previous_portable(value, max_depth=48):
    clean = security.sanitize_observation(value)
    def visit(item, depth):
        if security._deep_tail_payload(item) is not None:
            return item
        if isinstance(item, (dict, list, tuple)) and depth >= max_depth:
            return {"_gansar_encoding": security._DEEP_TAIL_ENCODING,
                "json": json.dumps(item, ensure_ascii=False, default=str, separators=(",", ":"))}
        if isinstance(item, dict):
            return {key: visit(child, depth+1) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [visit(child, depth+1) for child in item]
        return item
    return visit(clean, 0)


class PortableDetachedTreeTests(unittest.TestCase):
    def test_subclasses_tuples_and_repeated_references_remain_detached(self):
        class D(dict):
            pass
        class L(list):
            pass
        shared = D(password="original-secret", values=L(["Подарок 💎", "Bearer original-token"]))
        now, number = datetime.now(timezone.utc), Decimal("0.000000000000000001")
        source = D(first=shared, second=shared, tuple=(shared, now, number, 2**256))
        result = security.portable_observation(source)
        self.assertEqual(result, previous_portable(source))
        self.assertIs(type(result), dict)
        self.assertIs(type(result["tuple"]), list)
        self.assertIs(result["tuple"][1], now)
        self.assertIs(result["tuple"][2], number)
        self.assertIsNot(result["first"], result["second"])
        self.assertIsNot(result["first"]["values"], shared["values"])
        result["first"]["values"].append("changed output")
        self.assertEqual(shared["values"], ["Подарок 💎", "Bearer original-token"])
        self.assertEqual(shared["password"], "original-secret")

    def test_exact_codec_bytes_and_boundary_order_survive(self):
        encoded = {"_gansar_encoding": security._DEEP_TAIL_ENCODING,
            "json": json.dumps({"password": "must-redact", "url": "https://example.com/?api_key=hidden", "emoji": "💎"}, ensure_ascii=False)}
        source = {"payload": {"previous": [encoded, {"safe": "literal\\u2028"}]}, "safe": "Привет"}
        for depth in (0, 1, 2, 3, 48):
            with self.subTest(depth=depth):
                expected = previous_portable(source, depth)
                result = security.portable_observation(source, max_depth=depth)
                self.assertEqual(result, expected)
                self.assertEqual(json.dumps(result, ensure_ascii=False), json.dumps(expected, ensure_ascii=False))
                self.assertEqual(security.portable_observation(result, max_depth=depth), result)
                self.assertNotIn("must-redact", str(result))
                self.assertNotIn("api_key=hidden", str(result))
        self.assertIn("must-redact", encoded["json"])

    def test_later_encoding_failure_never_mutates_the_caller(self):
        class Unserializable:
            def __str__(self):
                raise ValueError("encoding failed")
        first = {"password": "original", "list": [1, 2]}
        broken = Unserializable()
        source = {"first": first, "later": {"object": broken}}
        with self.assertRaisesRegex(ValueError, "encoding failed"):
            security.portable_observation(source, max_depth=1)
        self.assertIs(source["first"], first)
        self.assertEqual(first, {"password": "original", "list": [1, 2]})
        self.assertIs(source["later"]["object"], broken)


if __name__ == "__main__":
    unittest.main()
