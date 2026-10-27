"""Source-message boundaries, using a captured public mainnet receipt/VAA."""
import copy
import json
from pathlib import Path
import unittest

from app.attribution.cross_chain import analyze_cross_chain, receipt_targets

CAPTURES = Path(__file__).resolve().parent / 'fixtures/cross_chain'
TXID = '0x3ad91ec530187bb2ce3b394d587878cd1e9e037a97e51fbc34af89b2e0719367'
MESSAGE_ID = '2/0000000000000000000000003ee18b2214aff97000d974cf647e7c347e8fa585/164170'


def observed_report(*, vaa=True):
    receipt = json.loads((CAPTURES / 'wormhole_sample_receipt.json').read_text())['result']
    raw = {'receipt': receipt, 'receipt_provenance': {'chain_id': 1, 'source': 'publicnode',
            'source_url': 'https://ethereum-rpc.publicnode.com', 'observed_at': '2026-10-20T16:26:12Z'}}
    if vaa:
        raw['wormhole_vaa'] = json.loads((CAPTURES / 'wormhole_sample_vaa_response.json').read_text())
    return {'transactions': [{'chain': 'eth', 'tx_hash': TXID, 'success': True, 'raw': raw, 'source': 'captured_public_rpc'}]}


def message_log(report):
    return report['transactions'][0]['raw']['receipt']['logs'][-1]


class SourceProtocolAnchors(unittest.TestCase):
    def test_real_receipt_and_vaa_body_bind_without_claiming_settlement_or_owner(self):
        report = observed_report()
        before = copy.deepcopy(report)
        result = analyze_cross_chain(report, {})
        self.assertEqual(report, before)
        self.assertEqual(len(result['messages']), 1)
        message = result['messages'][0]
        self.assertEqual(message['message_id'], MESSAGE_ID)
        self.assertEqual(message['source_block_number'], 18833913)
        self.assertEqual(message['payload_sha256'], 'cb5ac0cf5422d228605b592edc923b321179df9955a1191306357419c7e86224')
        self.assertTrue(message['vaa_binding']['body_matches_event'])
        self.assertEqual(message['vaa_binding']['signature_count'], 13)
        self.assertFalse(message['signatures_verified'])
        self.assertFalse(message['vaa_binding']['signatures_verified'])
        self.assertEqual(message['settlement_status'], 'UNKNOWN')
        self.assertEqual(message['intended_transfer']['recipient_wormhole_chain_id'], 1)
        self.assertTrue(all(r['blockchain'] == 'eth' and r['claim_scope'] == 'source_receipt_event_only' for r in result['relationships']))
        self.assertTrue(all(r['ownership_status'] == 'UNKNOWN' for r in result['relationships']))
        self.assertEqual(result['coverage']['network_requests'], 0)
        self.assertEqual(len(result['hypotheses']), 1)

    def test_source_only_is_useful_without_vaa(self):
        result = analyze_cross_chain(observed_report(vaa=False), {})
        self.assertEqual(len(result['messages']), 1)
        self.assertFalse(result['messages'][0]['vaa_binding']['provided'])
        self.assertEqual(result['messages'][0]['settlement_status'], 'UNKNOWN')

    def test_wrong_source_contract_is_not_a_protocol_anchor(self):
        report = observed_report()
        message_log(report)['address'] = '0x' + '1' * 40
        self.assertFalse(analyze_cross_chain(report, {})['messages'])

    def test_unknown_emitter_does_not_inherit_token_bridge_payload_semantics(self):
        report = observed_report()
        message_log(report)['topics'][1] = '0x' + '0' * 24 + '1' * 40
        result = analyze_cross_chain(report, {})
        self.assertEqual(len(result['messages']), 1)
        self.assertIsNone(result['messages'][0]['intended_transfer'])
        self.assertFalse(result['messages'][0]['vaa_binding']['body_matches_event'])
        self.assertFalse(result['hypotheses'])

    def test_wrong_chain_or_chain_id_cannot_use_same_hex_deployment(self):
        report = observed_report()
        report['transactions'][0]['chain'] = 'bsc'
        self.assertFalse(analyze_cross_chain(report, {})['messages'])
        report = observed_report()
        report['transactions'][0]['raw']['receipt_provenance']['chain_id'] = 56
        self.assertFalse(analyze_cross_chain(report, {})['messages'])
        self.assertEqual(receipt_targets('unsupported_network'), ())
        self.assertEqual(len(receipt_targets('ethereum')), 2)

    def test_mismatched_receipt_log_or_block_hash_is_rejected(self):
        for location in ('receipt', 'log', 'block'):
            with self.subTest(location=location):
                report = observed_report()
                if location == 'receipt':
                    report['transactions'][0]['raw']['receipt']['transactionHash'] = '0x' + 'a' * 64
                elif location == 'log':
                    message_log(report)['transactionHash'] = '0x' + 'a' * 64
                else:
                    message_log(report)['blockHash'] = '0x' + 'a' * 64
                self.assertFalse(analyze_cross_chain(report, {})['messages'])

    def test_failed_removed_or_emulated_observations_do_not_create_anchors(self):
        for location in ('failed', 'removed', 'emulated'):
            with self.subTest(location=location):
                report = observed_report()
                if location == 'failed':
                    report['transactions'][0]['raw']['receipt']['status'] = '0x0'
                elif location == 'removed':
                    message_log(report)['removed'] = True
                else:
                    report['transactions'][0]['raw']['emulated'] = True
                self.assertFalse(analyze_cross_chain(report, {})['messages'])

    def test_malformed_abi_offsets_lengths_and_high_bits_are_rejected(self):
        for mutation in ('offset', 'length', 'sequence', 'padding', 'short', 'too_large'):
            with self.subTest(mutation=mutation):
                report = observed_report()
                encoded = bytearray.fromhex(message_log(report)['data'][2:])
                if mutation == 'offset':
                    encoded[64:96] = (0).to_bytes(32, 'big')
                elif mutation == 'length':
                    encoded[128:160] = (65537).to_bytes(32, 'big')
                elif mutation == 'sequence':
                    encoded[:32] = (2 ** 64).to_bytes(32, 'big')
                elif mutation == 'padding':
                    encoded[-1] = 1
                elif mutation == 'short':
                    encoded = encoded[:-32]
                else:
                    encoded += b'\0' * 100000
                message_log(report)['data'] = '0x' + encoded.hex()
                self.assertFalse(analyze_cross_chain(report, {})['messages'])

    def test_vaa_signature_header_cannot_confirm_authenticity(self):
        report = observed_report()
        report['transactions'][0]['raw']['wormhole_vaa'] = 'AA=='
        result = analyze_cross_chain(report, {})
        self.assertEqual(len(result['messages']), 1)
        self.assertEqual(result['messages'][0]['vaa_binding']['status'], 'REJECTED')
        self.assertFalse(result['messages'][0]['signatures_verified'])

    def test_same_amount_time_and_hex_on_other_chain_do_not_link(self):
        report = {'transactions': [{'chain': c, 'tx_hash': '0x' + 'a' * 64, 'success': True,
                  'from_address': '0x' + '1' * 40, 'to_address': '0x' + '2' * 40,
                  'amount_base_units': 100, 'timestamp': '2026-10-20T10:00:00Z', 'raw': {}}
                  for c in ('eth', 'bsc')]}
        result = analyze_cross_chain(report, {})
        self.assertFalse(result['messages'])
        self.assertFalse(result['relationships'])
        self.assertFalse(result['hypotheses'])

    def test_duplicate_asset_rows_share_one_physical_message(self):
        report = observed_report()
        report['transactions'].append(copy.deepcopy(report['transactions'][0]))
        result = analyze_cross_chain(report, {})
        self.assertEqual(len(result['messages']), 1)
        self.assertEqual(len(result['evidence']), 1)
        self.assertEqual(result['coverage']['skip_reasons']['duplicate_physical_event'], 1)

    def test_record_and_time_budgets_are_explicit(self):
        for options in ({'max_records': 0}, {'max_seconds': 0}, {'max_records': 1}):
            with self.subTest(options=options):
                result = analyze_cross_chain(observed_report(), {}, **options)
                self.assertEqual(result['coverage']['status'], 'TRUNCATED')
                self.assertFalse(result['messages'])
                self.assertLessEqual(result['coverage']['records_examined'], options.get('max_records', 2000))


if __name__ == '__main__':
    unittest.main()
