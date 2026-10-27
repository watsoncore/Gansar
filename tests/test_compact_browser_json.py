"""JSON transport stays lossless while avoiding a whole four-byte string."""
import json
import sys
import unittest

from app.exporters.html_exporter import _browser_json


class CompactBrowserJsonTests(unittest.TestCase):
    def test_ascii_transport_preserves_unicode_metadata_and_exact_safe_numeric_types(self):
        metadata = {"💎": "Подарок 中文 \U0001f600", "rtl": "اسم", "separators": "\u2028\u2029",
            "escaped": r"literal\u2028", "controls": "\x00\t\n", "lone_surrogate": "\ud800"}
        source = {"metadata": metadata, "raw": "a" * 100000, "safe_integer": 9007199254740991,
            "large_integer": 2**256, "boolean": True, "fraction": 0.0000000000000001}
        encoded = _browser_json(source)
        self.assertTrue(encoded.isascii())
        decoded = json.loads(encoded)
        self.assertEqual(decoded, {**source, "large_integer": str(2**256)})
        self.assertEqual(source["large_integer"], 2**256)
        self.assertLess(sys.getsizeof(encoded), 2 * len(encoded), "One emoji must not widen the entire large transport string")

    def test_script_boundary_and_ampersand_guards_survive_compact_encoding(self):
        source = {"metadata": '</script><script>alert("💎")</script>&', "html": "<b>Привет</b>"}
        encoded = _browser_json(source)
        self.assertTrue(encoded.isascii())
        for unsafe in ("</script", "<", ">", "&"):
            self.assertNotIn(unsafe, encoded)
        self.assertEqual(json.loads(encoded), source)


if __name__ == "__main__":
    unittest.main()
