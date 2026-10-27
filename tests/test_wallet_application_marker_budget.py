"""Bounded synthetic TON BOC regressions; these are not live app claims."""
import base64
import copy
import unittest
from datetime import datetime, timezone

from app.attribution.wallet_application import analyze_wallet_applications
from app.models.report import AddressReport, Transaction


TARGET = '0:' + '1' * 64
OTHER = '0:' + '2' * 64
KEY = 'ton:' + TARGET


def token_body(query, *, fee=False, opcode=0x5fcc3d14):
    """Encode a real ordinary-cell BOC with a token header and optional ref."""
    body = opcode.to_bytes(4, 'big') + query.to_bytes(8, 'big')
    root = bytes([int(fee), len(body) * 2]) + body + (b'\x01' if fee else b'')
    child = b'\x00\x08' + bytes.fromhex('4d238543') if fee else b''
    cells = root + child
    header = bytes.fromhex('b5ee9c72') + bytes([1, 2, 1 + int(fee), 1, 0])
    return base64.b64encode(header + len(cells).to_bytes(2, 'big') + b'\x00' + cells).decode()


def transaction(index, body, *, incoming=False, success=True):
    tx_hash = f'{index:064x}'
    source, destination = (OTHER, TARGET) if incoming else (TARGET, OTHER)
    return Transaction(chain='ton', tx_hash=tx_hash, source='synthetic_protocol',
        from_address=source, to_address=destination, success=success,
        timestamp=datetime(2026, 10, 19, tzinfo=timezone.utc),
        url='https://example.org/synthetic-transaction/' + tx_hash,
        raw={'message_index': 0, 'message': {'hash': tx_hash, 'source': source,
            'destination': destination, 'msg_type': 'int_msg', 'raw_body': body}})


def analyze(rows, *, bound=1000):
    report = AddressReport(target_address=TARGET, detected_chains=['ton'], transactions=rows)
    payload = {'target_key': KEY, 'addresses': {KEY: {'address': TARGET,
        'blockchain': 'ton', 'account_type': 'wallet_contract',
        'contract': {'wallet_version': 'V4R2'}, 'attributions': []}},
        'evidence': [{'evidence_id': 'existing-proof', 'facts': {'retained': True}}]}
    before = copy.deepcopy(report)
    result = analyze_wallet_applications(report, payload, max_observations=bound, max_seconds=10)
    assert report == before, 'Application sampling must not mutate or remove native data.'
    return result, payload


class MarkerBudgetTests(unittest.TestCase):
    def assert_sound(self, result, payload, bound):
        observations = result['observations']
        self.assertLessEqual(len(observations), bound)
        proofs = {row['evidence_id']: row for row in payload['evidence']}
        self.assertEqual(proofs['existing-proof']['facts'], {'retained': True})
        self.assertTrue(all(row['observation_id'] in proofs for row in observations))
        refs = [ref for row in result['checks'] + result['candidates']
                for ref in row.get('evidence_ids', [])]
        self.assertTrue(all(ref in proofs for ref in refs))
        generated = {key for key in proofs if key.startswith('wallet-app:observation:')}
        self.assertEqual(generated, {row['observation_id'] for row in observations})
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertIsNone(result['name'])
        self.assertTrue(all(row['status'] == 'POSSIBLE' and not row['signing_application_confirmed']
                            for row in result['candidates']))

    def test_late_tonkeeper_marker_survives_default_generic_pool(self):
        rows = [transaction(i, token_body(i)) for i in range(1, 1001)]
        rows.append(transaction(1001, token_body((0x546de4ef << 32) | 99)))
        result, payload = analyze(rows)
        self.assertEqual([row['application_id'] for row in result['candidates']], ['tonkeeper'])
        self.assertEqual(result['coverage']['generic_observations_omitted'], 1)
        self.assertEqual(result['coverage']['marker_priority_replacements'], 1)
        self.assertEqual(result['coverage']['marker_observations_omitted'], 0)
        self.assertEqual(result['coverage']['status'], 'TRUNCATED')
        self.assert_sound(result, payload, 1000)

    def test_late_mytonwallet_fee_marker_survives_one_slot(self):
        result, payload = analyze([transaction(1, token_body(1)),
            transaction(2, token_body(2, fee=True))], bound=1)
        self.assertEqual([row['application_id'] for row in result['candidates']], ['mytonwallet'])
        self.assertTrue(result['observations'][0]['fields']['mywallet_fee_payload_present'])
        self.assertEqual(result['coverage']['marker_priority_replacements'], 1)
        self.assert_sound(result, payload, 1)

    def test_generic_header_cannot_displace_retained_marker(self):
        result, payload = analyze([transaction(1, token_body((0x546de4ef << 32) | 1)),
            transaction(2, token_body(2))], bound=1)
        self.assertEqual(result['candidates'][0]['application_id'], 'tonkeeper')
        self.assertEqual(result['coverage']['generic_observations_omitted'], 1)
        self.assertEqual(result['coverage']['marker_priority_replacements'], 0)
        self.assert_sound(result, payload, 1)

    def test_foreign_failed_and_notification_echo_have_no_marker_priority(self):
        for extra in [transaction(2, token_body((0x546de4ef << 32) | 2), incoming=True),
                      transaction(2, token_body((0x546de4ef << 32) | 2), success=False),
                      transaction(2, token_body((0x546de4ef << 32) | 2, opcode=0x7362d09c))]:
            with self.subTest(extra=extra.raw):
                result, payload = analyze([transaction(1, token_body(1)), extra], bound=1)
                self.assertFalse(result['candidates'])
                self.assertEqual(result['coverage']['marker_priority_replacements'], 0)
                self.assertEqual(result['observations'][0]['transaction_hash'], f'{1:064x}')
                self.assert_sound(result, payload, 1)

    def test_zero_budget_reports_decoded_marker_omission_without_false_negative(self):
        result, payload = analyze([transaction(1, token_body((0x546de4ef << 32) | 1))], bound=0)
        self.assertFalse(result['observations'])
        self.assertFalse(result['candidates'])
        self.assertEqual(result['coverage']['marker_observations_omitted'], 1)
        check = next(row for row in result['checks'] if row['method'] == 'tonkeeper_query_id_namespace')
        self.assertEqual(check['status'], 'unavailable')
        self.assertEqual(check['result']['decoded_marker_messages'], 1)
        self.assertEqual(check['result']['marker_observations_omitted'], 1)
        self.assert_sound(result, payload, 0)

    def test_all_marker_pool_stays_bounded_and_omissions_are_explicit(self):
        result, payload = analyze([transaction(1, token_body((0x546de4ef << 32) | 1)),
            transaction(2, token_body((0x546de4ef << 32) | 2))], bound=1)
        self.assertEqual(len(result['candidates'][0]['evidence_ids']), 1)
        self.assertEqual(result['coverage']['marker_observations_omitted'], 1)
        self.assertEqual(result['coverage']['marker_priority_replacements'], 0)
        check = next(row for row in result['checks'] if row['method'] == 'tonkeeper_query_id_namespace')
        self.assertEqual(check['result']['decoded_marker_messages'], 2)
        self.assertEqual(check['result']['marker_observations_omitted'], 1)
        self.assert_sound(result, payload, 1)


if __name__ == '__main__':
    unittest.main()
