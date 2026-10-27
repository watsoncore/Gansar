"""Portable model regression: synthetic boundaries and sealed actual offline raw.

The two compressed samples are unchanged observations extracted from a failed
local live worker. Replaying them makes no API requests and is not live proof.
Their original provenance and uncompressed SHA-256 are retained beside them.
"""
from __future__ import annotations

import copy
import gzip
import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from app.utils.security import portable_observation, sanitize_observation


ENCODING = 'json_deep_provider_tail'
FIXTURES = Path(__file__).parent / 'fixtures' / 'deep_provider_tail'


def codec(value):
    return {'_gansar_encoding': ENCODING, 'json': json.dumps(value, ensure_ascii=False, separators=(',', ':'))}


def at_depth(value, depth):
    for _ in range(depth):
        value = {'child': value}
    return value


def descend(value, depth):
    for _ in range(depth):
        value = value['child']
    return value


def sample(name):
    manifest = json.loads((FIXTURES / 'provenance.json').read_text(encoding='utf-8'))
    raw = gzip.decompress((FIXTURES / (name + '.json.gz')).read_bytes())
    expected = manifest['samples'][name]
    if len(raw) != expected['uncompressed_bytes'] or hashlib.sha256(raw).hexdigest() != expected['sha256']:
        raise AssertionError('Sealed actual observation changed: ' + name)
    return raw, manifest


class DeepTailBoundaryTests(unittest.TestCase):
    def test_exact_safe_codec_is_a_leaf_at_and_above_depth_boundary(self):
        leaf = {'_gansar_encoding': ENCODING, 'json': ' { "prev": [1, {"public": "Привет"}] } '}
        for depth in (0, 46, 47, 48):
            with self.subTest(depth=depth):
                value = at_depth(leaf, depth)
                once = portable_observation(value)
                self.assertEqual(once, value)
                self.assertEqual(portable_observation(once), once)
                self.assertIsNot(descend(once, depth), leaf)

    def test_changed_ancestor_boundary_packs_once_without_unfolding_old_layers(self):
        inner = codec({'prev': {'public': 'original observation'}, 'index': 16})
        historical = codec(codec(inner))
        value = at_depth(historical, 49)
        once = portable_observation(value)
        self.assertEqual(portable_observation(once), once)
        newly_bounded = descend(once, 48)
        self.assertEqual(json.loads(newly_bounded['json']), {'child': historical})
        self.assertEqual(json.loads(newly_bounded['json'])['child']['json'], historical['json'])

    def test_forged_valid_codec_cannot_hide_nested_secrets_or_urls(self):
        value = codec({'public': 'unchanged', 'private_key': 'fixture_key',
            'nested': [codec({'authorization': 'fixture_auth', 'safe': 42})],
            'link': 'https://user:fixture_pass@example.com/proof?api_key=fixture_query&page=2',
            'text': 'Bearer fixture_bearer password=fixture_password'})
        before = copy.deepcopy(value)
        clean = portable_observation(at_depth(value, 48))
        rendered = json.dumps(clean)
        for secret in ('fixture_key', 'fixture_auth', 'fixture_pass', 'fixture_query', 'fixture_bearer', 'fixture_password'):
            self.assertNotIn(secret, rendered)
        outer = json.loads(descend(clean, 48)['json'])
        self.assertEqual(outer['private_key'], '[REDACTED]')
        self.assertEqual(json.loads(outer['nested'][0]['json'])['authorization'], '[REDACTED]')
        self.assertEqual(outer['public'], 'unchanged')
        self.assertEqual(json.loads(outer['nested'][0]['json'])['safe'], 42)
        self.assertEqual(portable_observation(clean), clean)
        self.assertEqual(value, before)

    def test_extra_fields_or_wrong_marker_receive_ordinary_depth_and_redaction(self):
        for value in ({**codec({'public': 'payload'}), 'authorization': 'fixture_auth'},
                      {'_gansar_encoding': 'other_codec', 'json': '{}', 'private_key': 'fixture_key'},
                      {'_gansar_encoding': ENCODING, 'json': {'password': 'fixture_password'}}):
            with self.subTest(value=value):
                bounded = descend(portable_observation(at_depth(value, 48)), 48)
                self.assertEqual(json.loads(bounded['json']), sanitize_observation(value))
                self.assertNotIn('fixture_', json.dumps(bounded))

    def test_malformed_scalar_duplicate_and_non_json_payloads_are_not_opaque(self):
        for payload in ('{broken Bearer fixture_token', '42', '"scalar"',
                        '{"x": 1, "x": 2}', '{"x":NaN}', '[' * 1100 + '0' + ']' * 1100):
            with self.subTest(payload=payload[:50]):
                value = {'_gansar_encoding': ENCODING, 'json': payload}
                bounded = descend(portable_observation(at_depth(value, 48)), 48)
                # A non-codec object is bounded through the ordinary path; it
                # cannot mark itself trusted and skip the regular redaction.
                self.assertEqual(json.loads(bounded['json']), sanitize_observation(value))
                self.assertNotIn('fixture_token', json.dumps(bounded))

    def test_new_deep_payload_still_retains_every_decoded_field_and_redacts(self):
        original = {'opcode': 0x0EC3C86D, 'query_id': '18446744073709551615',
                    'private_key': 'fixture_private', 'bytes': 'te6ccgEBAQEA'}
        value = at_depth(original, 300)
        clean = portable_observation(value)
        current = clean
        for _ in range(300):
            if current.get('_gansar_encoding') == ENCODING:
                current = json.loads(current['json'])
            current = current['child']
        self.assertEqual(current, {**original, 'private_key': '[REDACTED]'})
        self.assertEqual(portable_observation(clean), clean)
        self.assertEqual(original['private_key'], 'fixture_private')

    def test_nested_individually_bounded_codecs_do_not_combine_python_recursion(self):
        public = codec(at_depth(codec(at_depth({'public': 'original deepest value'}, 500)), 500))
        self.assertEqual(portable_observation(public), public)
        self.assertEqual(portable_observation(portable_observation(public)), public)
        forged = codec(at_depth(codec(at_depth({'public': 'retained', 'private_key': 'fixture_nested_key'}, 500)), 500))
        clean = portable_observation(forged)
        self.assertNotIn('fixture_nested_key', clean['json'])
        inner = descend(json.loads(clean['json']), 500)
        leaf = descend(json.loads(inner['json']), 500)
        self.assertEqual(leaf, {'public': 'retained', 'private_key': '[REDACTED]'})
        self.assertEqual(portable_observation(clean), clean)


class ActualSavedTailReplayTests(unittest.TestCase):
    def test_actual_address_report_envelope_is_byte_identical_after_repeat_validation(self):
        raw, _ = sample('actual_deep_tail_envelope')
        value = json.loads(raw)
        once = portable_observation(value)
        twice = portable_observation(once)
        thrice = portable_observation(twice)
        for result in (once, twice, thrice):
            dumped = json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode()
            self.assertEqual(dumped, raw)

    def test_actual_transaction_report_graph_and_original_exporter_preserve_observations(self):
        from app.models.report import AddressReport, Transaction
        from app.graph.builder import build_graph_payload
        from app.exporters.html_exporter import export_html_report

        raw, manifest = sample('actual_deep_tail_transaction')
        original = json.loads(raw)
        tx = Transaction.model_validate(original)
        report = AddressReport(target_address=manifest['target_address'], detected_chains=['ton'], transactions=[tx])
        for _ in range(3):
            report = AddressReport.model_validate_json(report.model_dump_json())
            current = report.transactions[0].model_dump(mode='json')
            for field in ('event_id', 'tx_hash', 'source', 'url', 'raw', 'provenance'):
                self.assertEqual(current[field], original[field], 'Changed actual field: ' + field)
        graph = build_graph_payload(report)
        self.assertTrue(graph['nodes'])
        # The retained actual record is a provider action, not another monetary edge.
        self.assertEqual(tx.raw['asset_type'], 'action')
        self.assertEqual(graph['edges'], [])
        before = report.model_dump_json()
        validated = []
        validate = AddressReport.model_validate

        def capture(data, *args, **kwargs):
            result = validate(data, *args, **kwargs)
            validated.append(result)
            return result

        with tempfile.TemporaryDirectory() as directory, patch.object(AddressReport, 'model_validate', side_effect=capture):
            html = export_html_report(report, graph, Path(directory)).output_path.read_text(encoding='utf-8')
        self.assertEqual(report.model_dump_json(), before, 'Exporter mutated the retained actual model')
        self.assertEqual(len(validated), 1)
        current = validated[0].transactions[0].model_dump(mode='json')
        for field in ('event_id', 'tx_hash', 'source', 'url', 'raw', 'provenance'):
            self.assertEqual(current[field], original[field], 'Exporter changed actual field: ' + field)
        match = re.search(r'<script id="nft-payload"[^>]*>(.*?)</script>', html, re.S)
        self.assertIsNotNone(match)
        rows = json.loads(match.group(1))['transaction_views']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['operation_identity'], original['event_id'])
        self.assertEqual(rows[0]['hash'], original['tx_hash'])
        self.assertEqual(rows[0]['source'], original['source'])
        self.assertEqual(rows[0]['url'], original['url'])


if __name__ == '__main__':
    unittest.main()
