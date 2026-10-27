"""Protocol decoders and adversarial receipt cases; no network in tests."""
import copy
import unittest

from app.attribution.evm_transaction_fingerprints import (
    ACCOUNT_DEPLOYED, MM_DELEGATE, PROXY_CREATION, USER_OPERATION,
    analyze_evm_transaction,
)
from app.attribution.fingerprints import evm_code_fingerprint

A = '0x' + '11' * 20
B = '0x' + '22' * 20
C = '0x' + '33' * 20
TX = '0x' + 'ab' * 32
EP = '0x0000000071727de22e5e9d8baf0edac6f37da032'
SAFE13 = '0xa6b71e26c5e0845f74c812102ca7114b6a896ab2'
SAFE14 = '0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67'


def word(value):
    return value[2:].rjust(64, '0') if isinstance(value, str) else f'{value:064x}'


def receipt_tx(logs, chain='eth'):
    return {'chain': chain, 'tx_hash': TX, 'from_address': A, 'to_address': EP,
            'success': True, 'source': 'synthetic_protocol', 'raw': {
                'receipt': {'transactionHash': TX, 'from': A, 'status': '0x1', 'logs': logs}}}


def userop(success=1):
    return {'address': EP, 'topics': [USER_OPERATION, '0x' + 'cd' * 32,
            '0x' + word(B), '0x' + word(C)],
            'data': '0x' + ''.join(word(n) for n in (42, success, 1337, 123)),
            'logIndex': '0x2', 'transactionHash': TX}


class EvmInfrastructureFingerprints(unittest.TestCase):
    def test_user_operation_sender_paymaster_and_bundler_are_separate_on_all_six_chains(self):
        for chain in ('eth', 'bsc', 'polygon', 'arbitrum', 'optimism', 'avalanche'):
            with self.subTest(chain=chain):
                result = analyze_evm_transaction(receipt_tx([userop()], chain))
                row = result['implementation_observations'][0]
                self.assertEqual(row['subject_address'], B)
                self.assertEqual(row['fields']['paymaster_address'], C)
                self.assertEqual(row['fields']['outer_transaction_sender'], A)
                self.assertEqual(row['fields']['nonce'], '42')
                self.assertFalse(row['signing_application_confirmed'])
                self.assertFalse(result['construction_fingerprints'])

    def test_failed_user_operation_still_preserves_validated_execution_receipt(self):
        row = analyze_evm_transaction(receipt_tx([userop(0)]))['implementation_observations'][0]
        self.assertFalse(row['fields']['user_operation_success'])
        self.assertFalse(row['signing_application_confirmed'])

    def test_projected_asset_sender_cannot_become_outer_bundler(self):
        tx = receipt_tx([userop()])
        tx['from_address'] = C
        row = analyze_evm_transaction(tx)['implementation_observations'][0]
        self.assertEqual(row['fields']['outer_transaction_sender'], A)
        del tx['raw']['receipt']['from']
        row = analyze_evm_transaction(tx)['implementation_observations'][0]
        self.assertIsNone(row['fields']['outer_transaction_sender'])

    def test_account_deployed_decodes_inner_factory_not_outer_sender(self):
        log = {'address': EP, 'topics': [ACCOUNT_DEPLOYED, '0x' + 'cd' * 32, '0x' + word(B)],
               'data': '0x' + word(C) + word(0)}
        row = analyze_evm_transaction(receipt_tx([log]))['implementation_observations'][0]
        self.assertEqual(row['subject_address'], B)
        self.assertEqual(row['fields']['factory_address'], C)
        self.assertIsNone(row['fields']['paymaster_address'])

    def test_safe_factory_abi_indexing_is_version_specific(self):
        old = {'address': SAFE13, 'topics': [PROXY_CREATION], 'data': '0x' + word(B) + word(C)}
        new = {'address': SAFE14, 'topics': [PROXY_CREATION, '0x' + word(B)], 'data': '0x' + word(C)}
        for chain in ('eth', 'bsc', 'polygon', 'arbitrum', 'optimism', 'avalanche'):
            rows = analyze_evm_transaction(receipt_tx([old, new], chain))['implementation_observations']
            self.assertEqual([r['fields']['factory_version'] for r in rows], ['1.3.0', '1.4.1'])
            self.assertTrue(all(r['subject_address'] == B for r in rows))
        wrong = copy.deepcopy(old)
        wrong['address'] = SAFE14
        self.assertFalse(analyze_evm_transaction(receipt_tx([wrong]))['implementation_observations'])

    def test_copying_selector_topic_or_brand_label_does_not_create_claim(self):
        spoof = userop()
        spoof['address'] = C
        tx = receipt_tx([spoof])
        tx['raw'].update(input='0x1fad948c', wallet='MetaMask', app='Rabby')
        self.assertFalse(analyze_evm_transaction(tx)['implementation_observations'])
        tx = receipt_tx([])
        tx['raw']['input'] = '0x765e827f'
        self.assertFalse(analyze_evm_transaction(tx)['implementation_observations'])

    def test_wrong_receipt_hash_failed_status_removed_log_and_chain_mismatch_are_rejected(self):
        mutations = [
            lambda t: t['raw']['receipt'].update(transactionHash='0x' + 'ff' * 32),
            lambda t: t['raw']['receipt'].update(status='0x0'),
            lambda t: t.update(success=False),
            lambda t: t['raw'].update(emulated=True),
            lambda t: t['raw'].update(chainId='0x89'),
            lambda t: t['raw']['receipt']['logs'][0].update(removed=True),
            lambda t: t['raw']['receipt']['logs'][0].update(transactionHash='0x' + 'ff' * 32),
        ]
        for mutate in mutations:
            tx = receipt_tx([userop()])
            mutate(tx)
            self.assertFalse(analyze_evm_transaction(tx)['implementation_observations'])

    def test_invalid_abi_address_padding_and_noncanonical_bool_are_rejected(self):
        for kind in ('padding', 'bool', 'truncated', 'extra_topics'):
            log = userop()
            if kind == 'padding':
                log['topics'][2] = '0x' + 'ff' * 12 + B[2:]
            elif kind == 'bool':
                log = userop(2)
            elif kind == 'truncated':
                log['data'] = log['data'][:-2]
            else:
                log['topics'].append('0x' + word(0))
            self.assertFalse(analyze_evm_transaction(receipt_tx([log]))['implementation_observations'])

    def test_eip7702_exact_runtime_fingerprint_identifies_only_published_target(self):
        for chain in ('eth', 'bsc', 'polygon', 'arbitrum', 'optimism'):
            record = {'blockchain': chain, 'contract': evm_code_fingerprint('0xef0100' + MM_DELEGATE[2:])}
            tx = receipt_tx([], chain)
            row = analyze_evm_transaction(tx, {f'{chain}:{A}': record})['implementation_observations'][0]
            self.assertEqual(row['fields']['implementation_origin'], 'MetaMask Delegation Framework')
            self.assertFalse(row['fields']['delegate_runtime_verified'])
            self.assertFalse(row['signing_application_confirmed'])
        record = {'blockchain': 'avalanche', 'contract': evm_code_fingerprint('0xef0100' + MM_DELEGATE[2:])}
        row = analyze_evm_transaction(receipt_tx([], 'avalanche'), {'avalanche:' + A: record})['implementation_observations'][0]
        self.assertNotIn('implementation_origin', row['fields'])

    def test_runtime_record_must_be_network_scoped_nonconflicting_and_hash_consistent(self):
        base = {'blockchain': 'eth', 'contract': evm_code_fingerprint('0xef0100' + MM_DELEGATE[2:])}
        for kind in ('wrong_chain', 'conflict', 'hash', 'label_only'):
            record = copy.deepcopy(base)
            if kind == 'wrong_chain':
                record['blockchain'] = 'polygon'
            elif kind == 'conflict':
                record['contract']['runtime_observation_conflict'] = True
            elif kind == 'hash':
                record['contract']['code_hash'] = '0x' + '00' * 32
            else:
                record['contract'].pop('code_hash')
            self.assertFalse(analyze_evm_transaction(receipt_tx([]), {'eth:' + A: record})['implementation_observations'])

    def test_repeated_logs_do_not_multiply_evidence(self):
        log = userop()
        result = analyze_evm_transaction(receipt_tx([log, copy.deepcopy(log)]))
        self.assertEqual(len(result['evidence']), 1)
        self.assertEqual(len(result['implementation_observations']), 1)

    def test_unsupported_or_malformed_input_is_bounded_and_nonmutating(self):
        self.assertFalse(analyze_evm_transaction({'chain': 'ton'})['implementation_observations'])
        tx = receipt_tx([None, 0, {}, {'topics': [None], 'data': '0x'}])
        before = copy.deepcopy(tx)
        self.assertFalse(analyze_evm_transaction(tx)['implementation_observations'])
        self.assertEqual(tx, before)


if __name__ == '__main__':
    unittest.main()
