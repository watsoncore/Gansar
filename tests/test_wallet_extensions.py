"""Synthetic structural controls plus a verbatim public install message.

Synthetic storage is not application ground truth. Public probe provenance is
stored under validation/wallet_application/deep_research_20261020/mytonwallet.
"""
import base64
import hashlib
import unittest

from app.attribution.wallet_extensions import (
    decode_extension_install, extension_implementation, extension_wallet_from_data,
    extension_implementation_from_code,
)
from app.ton_attribution.fingerprints import ordinary_code_hash
from app.ton_attribution.service import _descriptor
from app.ton_nft.providers import Payload


def _boc(bits, ref=None):
    def pack(text, refs=()):
        padded = text + ('1' if len(text) % 8 else '')
        padded += '0' * (-len(padded) % 8)
        data = int(padded or '0', 2).to_bytes(len(padded) // 8, 'big')
        return bytes([len(refs), len(text) // 8 + (len(text) + 7) // 8]) + data + bytes(refs)
    payload = pack(bits, (1,) if ref is not None else ())
    if ref is not None:
        payload += pack(ref)
    blob = bytes.fromhex('b5ee9c72') + bytes([1, 2, 2 if ref is not None else 1, 1, 0])
    blob += len(payload).to_bytes(2, 'big') + b'\0' + payload
    return base64.b64encode(blob).decode()


def _uint(value, width):
    return f'{value:0{width}b}'


class ExtensionObservations(unittest.TestCase):
    def test_exact_exotic_library_code_has_bounded_header_and_crc_validation(self):
        payload = bytes([8, 66, 2]) + bytes.fromhex('701eede652337f699550cc51cb15263259aae6fc6eba976237945f142dda982d')
        raw = bytes.fromhex('b5ee9c7201010101002300') + payload
        result = extension_implementation_from_code(base64.b64encode(raw).decode())
        self.assertEqual(result['implementation_id'], 'mytonwallet_tg2fa')
        self.assertFalse(result['library_resolution_verified'])
        self.assertFalse(result['boc_crc_verified'])
        # Known CRC form generated independently with the standard CRC32C polynomial.
        def crc(data):
            table = []
            for i in range(256):
                value = i
                for _ in range(8):
                    value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
                table.append(value)
            value = 0xffffffff
            for byte in data:
                value = table[(value ^ byte) & 255] ^ (value >> 8)
            return (value ^ 0xffffffff).to_bytes(4, 'little')
        with_crc = raw[:4] + bytes([0x41]) + raw[5:]
        with_crc += crc(with_crc)
        self.assertTrue(extension_implementation_from_code(with_crc.hex())['boc_crc_verified'])
        indexed = raw[:4] + bytes([0x81]) + raw[5:11] + bytes([35]) + payload
        self.assertIsNotNone(extension_implementation_from_code(indexed.hex()))
        corrupted_crc = with_crc[:-1] + bytes([with_crc[-1] ^ 1])
        for invalid in [raw + b'\0', raw[:-1], corrupted_crc, raw[:11] + b'\0' + payload[1:],
                        raw[:13] + b'\1' + payload[3:], raw[:6] + b'\2' + raw[7:]]:
            self.assertIsNone(extension_implementation_from_code(invalid.hex()))
        self.assertIsNone(extension_implementation_from_code('0' * 1025))
        self.assertIsNone(extension_implementation_from_code(_boc('0' * 32)))

    def test_service_descriptor_uses_exact_exotic_fallback_without_app_claim(self):
        payload = bytes([8, 66, 2]) + bytes.fromhex('701eede652337f699550cc51cb15263259aae6fc6eba976237945f142dda982d')
        raw = bytes.fromhex('b5ee9c7201010101002300') + payload
        code = base64.b64encode(raw).decode()
        with self.assertRaises(ValueError):
            ordinary_code_hash(code)
        source = Payload({'status': 'active', 'code': code}, 'obs:extension', 'tonapi', 'tonapi.io', 'https://tonapi.io/v2/blockchain/accounts/fixture')
        evidence = []
        result = _descriptor('0:' + '11' * 32, {'raw_contract': source}, [], evidence)
        self.assertEqual(result['contract']['code_hash'], '14dbe27de307b26faf75361dc5429d1a14b5288f9a82ce08727513c02835e4f7')
        self.assertEqual(result['contract']['kind'], 'contract')
        self.assertIsNone(result['contract']['wallet_version'])
        self.assertEqual(result['client_attribution']['status'], 'UNKNOWN')
        self.assertFalse(result['conflicts'])
        fact = next(row['facts'] for row in evidence if row['relation'] == 'computed_contract_code_hash')
        self.assertIn('exotic library-reference', fact['algorithm'])
        self.assertFalse(fact['library_resolution_verified'])
        self.assertFalse(fact['client_application_inference'])

    def test_service_unsupported_exotic_keeps_unavailable_conflict(self):
        payload = bytes([8, 66, 2]) + bytes.fromhex('ff' * 32)
        code = (bytes.fromhex('b5ee9c7201010101002300') + payload).hex()
        source = Payload({'status': 'active', 'code': code}, 'obs:other', 'tonapi', 'tonapi.io', 'https://tonapi.io/v2/blockchain/accounts/fixture')
        result = _descriptor('0:' + '11' * 32, {'raw_contract': source}, [], [])
        self.assertIsNone(result['contract']['code_hash'])
        self.assertTrue(any('code cell hash unavailable' in row for row in result['conflicts']))
        self.assertEqual(result['client_attribution']['status'], 'UNKNOWN')

    def test_service_fallback_preserves_cross_provider_code_conflict(self):
        payload = bytes([8, 66, 2]) + bytes.fromhex('701eede652337f699550cc51cb15263259aae6fc6eba976237945f142dda982d')
        code = (bytes.fromhex('b5ee9c7201010101002300') + payload).hex()
        a = Payload({'status': 'active', 'code': code}, 'obs:a', 'tonapi', 'tonapi.io', 'https://tonapi.io/v2/blockchain/accounts/fixture')
        b = Payload({'status': 'active', 'code': _boc('0' * 32)}, 'obs:b', 'toncenter', 'toncenter.com', 'https://toncenter.com/api/v3/addressInformation')
        result = _descriptor('0:' + '11' * 32, {'raw_contract': a, 'address_information': b}, [], [])
        self.assertIsNone(result['contract']['code_hash'])
        self.assertEqual(len(result['contract']['code_hashes']), 2)
        self.assertEqual(result['contract']['status'], 'POSSIBLE')
        self.assertTrue(any('Code hashes differ' in row for row in result['conflicts']))
        self.assertEqual(result['client_attribution']['status'], 'UNKNOWN')

    def test_service_current_storage_owner_binding_needs_verified_code_and_exact_layout(self):
        payload = bytes([8, 66, 2]) + bytes.fromhex('701eede652337f699550cc51cb15263259aae6fc6eba976237945f142dda982d')
        code = (bytes.fromhex('b5ee9c7201010101002300') + payload).hex()
        data = 'te6ccgECAgEAAF0AAZsAAAAAgBk16LbQqgWQVppRreIlV1eDLOh4qNbtLI0o+jcaDQoMwdtyJT8+6PF5ZaBYorzx+Jqa0E2t5nZjJxwffmgHD9dAAAAAAAAAAAgBABQxMzkzNzYyNjA1'
        owner = '0:c9af45b685502c82b4d28d6f112ababc196743c546b769646947d1b8d0685066'
        source = lambda c, d: Payload({'status': 'active', 'code': c, 'data': d}, 'obs:binding', 'tonapi', 'tonapi.io', 'https://tonapi.io/v2/blockchain/accounts/fixture')
        evidence = []
        result = _descriptor('0:' + '11' * 32, {'raw_contract': source(code, data)}, [], evidence)
        state = result['contract']['extension_state']
        self.assertEqual(state['bound_wallet'], owner)
        self.assertEqual(state['implementation_id'], 'mytonwallet_tg2fa')
        self.assertTrue(state['current_state_only'])
        self.assertFalse(state['historical_registration_verified'])
        fact = next(row['facts'] for row in evidence if row['relation'] == 'computed_extension_wallet_binding')
        self.assertEqual(fact['bound_wallet'], owner)
        self.assertFalse(fact['active_v5_membership_verified'])
        self.assertEqual(result['client_attribution']['status'], 'UNKNOWN')
        for bad_code, bad_data in [(code, _boc('0' * 32)), (_boc('0' * 32), data), ('bad', data)]:
            facts = []
            invalid = _descriptor('0:' + '11' * 32, {'raw_contract': source(bad_code, bad_data)}, [], facts)
            self.assertNotIn('extension_state', invalid['contract'])
            self.assertFalse(any(row['relation'] == 'computed_extension_wallet_binding' for row in facts))

    def test_service_current_storage_cross_provider_owner_conflict_has_no_agreed_binding(self):
        payload = bytes([8, 66, 2]) + bytes.fromhex('701eede652337f699550cc51cb15263259aae6fc6eba976237945f142dda982d')
        code = (bytes.fromhex('b5ee9c7201010101002300') + payload).hex()
        def source(name, number):
            prefix = _uint(1, 32) + '100' + _uint(0, 8) + _uint(number, 256)
            data = _boc(prefix + '1' * 256 + '0' * 65, _uint(ord('7'), 8))
            return Payload({'status': 'active', 'code': code, 'data': data}, 'obs:' + name, name, name, 'https://example.org/' + name)
        evidence = []
        result = _descriptor('0:' + '11' * 32, {'raw_contract': source('a', 1), 'address_information': source('b', 2)}, [], evidence)
        self.assertNotIn('extension_state', result['contract'])
        self.assertTrue(any('Extension owner bindings differ' in row for row in result['conflicts']))
        self.assertEqual(result['contract']['status'], 'POSSIBLE')
        bindings = [row['facts']['bound_wallet'] for row in evidence if row['relation'] == 'computed_extension_wallet_binding']
        self.assertEqual(set(bindings), {'0:' + f'{1:064x}', '0:' + f'{2:064x}'})
        self.assertEqual(result['client_attribution']['status'], 'UNKNOWN')

    def test_published_full_and_library_representations_are_distinct(self):
        full = '701eede652337f699550cc51cb15263259aae6fc6eba976237945f142dda982d'
        library = hashlib.sha256(bytes([8, 66, 2]) + bytes.fromhex(full)).hexdigest()
        a, b = extension_implementation(full), extension_implementation(library)
        self.assertEqual(a['implementation_id'], b['implementation_id'])
        self.assertEqual(a['code_representation'], 'full_code')
        self.assertEqual(b['code_representation'], 'library_reference')
        self.assertEqual(b['library_code_hash'], full)
        self.assertEqual(b['signing_application'], 'UNKNOWN')
        self.assertEqual(b['confidence_ceiling'], 'POSSIBLE')

    def test_hash_normalization_and_unknown_hashes(self):
        raw = bytes.fromhex('c5ef19df22aee8b707bd7a181174e400a4225223c5ae40d8320f5ddd707d34a1')
        for value in [raw.hex().upper(), '0x' + raw.hex(), base64.b64encode(raw).decode()]:
            self.assertEqual(extension_implementation(value)['implementation_id'], 'tonkeeper_2fa')
        for value in [None, '', 'c5ef', 'a' * 1000, '00' * 32]:
            self.assertIsNone(extension_implementation(value))

    def test_subscription_code_identity_is_separate_from_2fa_installation(self):
        code_hash = '48942963827c5147fe935cd22e88ba418011fe656eab78b79c5c6343d84d421a'
        result = extension_implementation(code_hash)
        self.assertEqual(result['implementation_id'], 'tonkeeper_subscription_v2')
        self.assertEqual(result['evidence_scope'], 'extension_contract_implementation')
        self.assertEqual(result['signing_application'], 'UNKNOWN')
        self.assertTrue(any('subscriptions_v2.xml' in url for url in result['source_urls']))
        install = decode_extension_install('te6cckEBAQEABgAACENWMXSflLNF')
        self.assertNotEqual(install['construction_family_hint'], result['implementation_id'])
        self.assertIsNone(extension_wallet_from_data(_boc('0' * 876), result['implementation_id']))

    def test_same_opcode_has_two_published_shapes(self):
        opcode = _uint(0x43563174, 32)
        # Public Toncenter tx 3786b7d4d78f921b12479dc8deabae4fa8436431d3ee68c80e9044602f1bb434.
        real_body = 'te6cckEBAQEABgAACENWMXSflLNF'
        mtw = decode_extension_install(real_body)
        tk = decode_extension_install(_boc(opcode + '1' * 512))
        self.assertEqual(mtw['body_bits'], 32)
        self.assertEqual(mtw['construction_family_hint'], 'mytonwallet_tg2fa')
        self.assertEqual(tk['body_bits'], 544)
        self.assertEqual(tk['construction_family_hint'], 'tonkeeper_2fa')
        self.assertTrue(mtw['shared_opcode'])
        self.assertEqual(tk['signing_application'], 'UNKNOWN')
        self.assertFalse(tk['signature_verified'])
        for value in [_boc(opcode + '0'), _boc(opcode, ''), _boc('0' * 32), 'bad', 'a' * 20000]:
            self.assertIsNone(decode_extension_install(value))

    def test_storage_owner_binding_never_returns_identity_or_keys(self):
        owner = _uint(0x1234, 256)
        prefix = _uint(1, 32) + '100' + _uint(0, 8) + owner
        mtw = _boc(prefix + '1' * 256 + '0' * 65, _uint(ord('7'), 8))
        tk = _boc(prefix + '1' * 512 + '0' * 65)
        self.assertEqual(extension_wallet_from_data(mtw, 'mytonwallet_tg2fa'), '0:' + f'{0x1234:064x}')
        self.assertEqual(extension_wallet_from_data(tk, 'tonkeeper_2fa'), '0:' + f'{0x1234:064x}')
        self.assertIsNone(extension_wallet_from_data(mtw, 'tonkeeper_2fa'))
        self.assertIsNone(extension_wallet_from_data(tk, 'mytonwallet_tg2fa'))
        self.assertIsNone(extension_wallet_from_data(mtw, 'unverified_label'))
        self.assertIsNone(extension_wallet_from_data(_boc(prefix + '1' * 256 + '0' * 65, _uint(ord('x'), 8))))

    def test_public_stateinit_data_binds_to_real_install_sender(self):
        # Verbatim data subtree from the saved public transaction above. The
        # analysis script independently checks StateInit's representation hash
        # against the deployed address; this test checks storage decoding only.
        data = 'te6ccgECAgEAAF0AAZsAAAAAgBk16LbQqgWQVppRreIlV1eDLOh4qNbtLI0o+jcaDQoMwdtyJT8+6PF5ZaBYorzx+Jqa0E2t5nZjJxwffmgHD9dAAAAAAAAAAAgBABQxMzkzNzYyNjA1'
        expected = '0:c9af45b685502c82b4d28d6f112ababc196743c546b769646947d1b8d0685066'
        self.assertEqual(extension_wallet_from_data(data, 'mytonwallet_tg2fa'), expected)
        self.assertIsNone(extension_wallet_from_data(data, 'tonkeeper_2fa'))

    def test_tonkeeper_initial_and_pending_state_are_not_conflated(self):
        owner = '100' + _uint(255, 8) + _uint(42, 256)
        initial = _boc('0' * 32 + owner + '0' * 578)
        pending = _boc(_uint(1, 32) + owner + '1' * 512 + '1' + '0' * 64)
        self.assertEqual(extension_wallet_from_data(initial, 'tonkeeper_2fa'), '-1:' + f'{42:064x}')
        self.assertIsNone(extension_wallet_from_data(pending, 'tonkeeper_2fa'))
        for value in [None, 'bad', 'a' * 20000, _boc('0' * 32)]:
            self.assertIsNone(extension_wallet_from_data(value))


if __name__ == '__main__':
    unittest.main()
