"""Compressed-owner bytes parsing preserves legacy JSON and codec checks."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import random
import struct
import unittest
from unittest.mock import patch
import zlib

from app.ton_nft import storage


def wrapper(payload: bytes, *, count=0):
    digest = hashlib.sha256(payload).hexdigest()
    compressed = zlib.compress(payload)
    text = json.dumps({"_gansar_encoding": "zlib_json", "version": 1,
        "uncompressed_bytes": len(payload), "sha256": digest,
        "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
        "transaction_count": count, "data": base64.b64encode(compressed).decode("ascii")},
        ensure_ascii=False, separators=(",", ":"))
    return text, digest


def typed_values(value):
    if type(value) is float:
        return ("float", "nan" if math.isnan(value) else struct.pack("!d", value).hex())
    if type(value) is dict:
        return ("dict", [(key, typed_values(child)) for key, child in value.items()])
    if type(value) is list:
        return ("list", [typed_values(child) for child in value])
    return (type(value).__name__, value)


class OwnerBytesParserTests(unittest.TestCase):
    def test_native_typed_unicode_bytes_match_stdlib_without_whole_owner_unicode_parse(self):
        rng = random.Random(20261017)
        floats = []
        for _ in range(4096):
            number = struct.unpack("!d", rng.getrandbits(64).to_bytes(8, "big"))[0]
            if math.isfinite(number):
                floats.append(number)
        owner = {"transactions": [{"raw": {"emoji": "🎁💎🚀", "unicode": "Доказательство 中文",
            "long_integer": 10 ** 1000, "values": [None, True, False, -4, 2 ** 100,
                0.0, -0.0, 5e-324, 1.7976931348623157e308], "floats": floats}}]}
        payload = json.dumps(owner, ensure_ascii=False, separators=(",", ":")).encode()
        text, digest = wrapper(payload, count=1)
        original_loads, original_core = json.loads, storage.from_json
        expected = original_loads(payload)

        def loads_header_only(value, *args, **kwargs):
            self.assertIsInstance(value, str, "Native body must be parsed from bytes by the core parser")
            return original_loads(value, *args, **kwargs)

        with patch.object(storage.json, "loads", side_effect=loads_header_only), \
                patch.object(storage, "from_json", wraps=original_core) as parser:
            actual = storage.decode_owner_snapshot(text, digest)
        self.assertEqual(typed_values(actual), typed_values(expected))
        parser.assert_called_once_with(payload, allow_inf_nan=True, allow_partial=False, cache_strings=False)

    def test_duplicate_keys_nonfinite_numbers_negative_zero_and_large_integer_match_stdlib(self):
        payload = (b'{"transactions":[],"duplicate":1,"duplicate":2,"nan":NaN,"pos":Infinity,'
            b'"neg":-Infinity,"negative_zero":-0.0,"zero":-0,"overflow":1e309,"big":' + b"9" * 1000 + b"}")
        text, digest = wrapper(payload)
        self.assertEqual(typed_values(storage.decode_owner_snapshot(text, digest)), typed_values(json.loads(payload)))

    def test_legacy_bom_surrogate_escape_and_deep_tree_fall_back_without_semantic_change(self):
        cases = [b'\xef\xbb\xbf{"transactions":[],"public":1}',
            b'{"transactions":[],"surrogate":"\\ud800"}',
            b'{"transactions":[],"deep":' + b"[" * 220 + b"0" + b"]" * 220 + b"}"]
        original_loads, original_core = json.loads, storage.from_json
        for index, payload in enumerate(cases):
            with self.subTest(index=index):
                text, digest = wrapper(payload)
                expected = original_loads(payload)
                with patch.object(storage.json, "loads", wraps=original_loads) as loads, \
                        patch.object(storage, "from_json", wraps=original_core) as parser:
                    actual = storage.decode_owner_snapshot(text, digest)
                self.assertEqual(typed_values(actual), typed_values(expected))
                self.assertEqual(parser.call_count, 1)
                self.assertTrue(any(isinstance(call.args[0], bytes) for call in loads.call_args_list))

    def test_incomplete_trailing_invalid_utf8_nonobject_and_wrong_count_remain_errors(self):
        cases = [(b'{"transactions":[]', 0), (b'{"transactions":[]} trailing', 0),
            (b'{"transactions":[],"public":"\xff"}', 0), (b"[]", 0),
            (b'{"transactions":[{"public":1}]}', 0)]
        for payload, count in cases:
            with self.subTest(payload=payload):
                text, digest = wrapper(payload, count=count)
                with self.assertRaises((ValueError, UnicodeError)):
                    storage.decode_owner_snapshot(text, digest)

    def test_header_checksum_and_bounded_size_checks_precede_parser(self):
        text, digest = wrapper(b'{"transactions":[],"emoji":"public"}')
        for changes, expected in [({"uncompressed_bytes": storage.MAX_OWNER_SNAPSHOT_BYTES + 1}, digest),
                ({"compressed_sha256": "0" * 64}, digest), ({}, "0" * 64)]:
            with self.subTest(changes=changes):
                data = json.loads(text)
                data.update(changes)
                changed = json.dumps(data, separators=(",", ":"))
                with patch.object(storage, "from_json", side_effect=AssertionError("Unverified body must not be parsed")):
                    with self.assertRaises(ValueError):
                        storage.decode_owner_snapshot(changed, expected)

    def test_ownerless_codec_and_plain_legacy_paths_remain_compatible(self):
        payload = b'{"transactions":[],"public":"legacy"}'
        text, digest = wrapper(payload)
        with patch.object(storage, "from_json", side_effect=AssertionError("Ownerless/legacy must not invoke bytes parser")), \
                patch.object(storage.zlib, "decompressobj", side_effect=AssertionError("Ownerless must not inflate")):
            self.assertIsNone(storage.decode_owner_snapshot(text, digest, include_owner=False))
            self.assertEqual(storage.decode_owner_snapshot(payload.decode(), digest), json.loads(payload))


if __name__ == "__main__":
    unittest.main()
