"""Bounded, read-only observations of published wallet extension layouts.

An extension implementation or installation request does not identify a signing
application. The three installation/action opcodes shared by these projects are
deliberately never used as a standalone brand fingerprint.
"""
from __future__ import annotations

import base64
import hashlib
import re

from app.attribution.wallet_payload import Bits
from app.ton_nft.protocol import decode_boc

_MTW_CODE = '701eede652337f699550cc51cb15263259aae6fc6eba976237945f142dda982d'
_MTW_LIBRARY = '14dbe27de307b26faf75361dc5429d1a14b5288f9a82ce08727513c02835e4f7'
_TK_CODE = 'c5ef19df22aee8b707bd7a181174e400a4225223c5ae40d8320f5ddd707d34a1'
_TK_SUBSCRIPTION = '48942963827c5147fe935cd22e88ba418011fe656eab78b79c5c6343d84d421a'
_MTW_SOURCE = 'https://github.com/mytonwallet-org/mytonwallet/blob/bb3f357690633d274e390e799babaf1d642b31de/'
_MTW_CONTRACT = 'https://github.com/mytonwallet-org/tg2fa-extension/blob/7cbccf059c4600a4e350f3812416f3dee640d4ca/'
_TK_SOURCE = 'https://github.com/tonkeeper/2fa-extension/blob/e6f69f5c7e98c9644905ddcbecae5c06cd2f2a11/'
_TK_SUB_SOURCE = 'https://github.com/tonkeeper/ton-subscriptions/blob/a0aa878577e4b74c40c7c2c8bdd9e09dcb57547d/'
_FAMILIES = {
    'mytonwallet_tg2fa': {
        'family': 'MyTonWallet Telegram 2FA extension',
        'application_id': 'mytonwallet',
        'source_urls': [_MTW_SOURCE + 'src/config.ts', _MTW_SOURCE + 'src/api/chains/ton/contracts/MfaExtension.ts',
                        _MTW_CONTRACT + 'contracts/mfa_extension.fc'],
    },
    'tonkeeper_2fa': {
        'family': 'Tonkeeper 2FA extension',
        'application_id': 'tonkeeper',
        'source_urls': [_TK_SOURCE + 'build/TFAExtension.compiled.json',
                        _TK_SOURCE + 'wrappers/TFAExtension.ts', _TK_SOURCE + 'SPECIFICATION.md'],
    },
    'tonkeeper_subscription_v2': {
        'family': 'Tonkeeper subscription V2 extension',
        'application_id': 'tonkeeper',
        'source_urls': [_TK_SUB_SOURCE + 'contracts/nativeSub.tolk', _TK_SUB_SOURCE + 'contracts/state.tolk',
                        _TK_SUB_SOURCE + 'SPECIFICATION.md',
                        'https://github.com/tonkeeper/tongo/blob/0fe589df866d50e8a732aadc44a5ca4d5d83c6f6/abi/schemas/subscriptions_v2.xml',
                        'https://github.com/tonkeeper/tonkeeper-web/blob/d7ea32150635b53b8bc6fb6c5744434d9370a347/packages/core/src/service/ton-blockchain/encoder/subscription-encoder/subscription-encoder.ts'],
    },
}


def _hash_hex(value):
    if not isinstance(value, str) or len(value) > 90:
        return None
    text = value.strip()
    if text.startswith('0x'):
        text = text[2:]
    if re.fullmatch(r'[0-9a-fA-F]{64}', text):
        return text.lower()
    try:
        raw = base64.b64decode(text, altchars=b'-_', validate=True)
    except (ValueError, TypeError):
        return None
    return raw.hex() if len(raw) == 32 else None


def extension_implementation(code_hash):
    """Identify a published extension code representation, never its caller UI.

    The library-reference hash is the representation hash of exotic cell
    ``02 || library_hash``; it differs from the full implementation code hash.
    No address, account label, arbitrary metadata or incomplete hash is used.
    """
    digest = _hash_hex(code_hash)
    if digest in (_MTW_CODE, _MTW_LIBRARY):
        identity, representation = 'mytonwallet_tg2fa', 'library_reference' if digest == _MTW_LIBRARY else 'full_code'
        library_hash = _MTW_CODE if digest == _MTW_LIBRARY else None
    elif digest == _TK_CODE:
        identity, representation, library_hash = 'tonkeeper_2fa', 'full_code', None
    elif digest == _TK_SUBSCRIPTION:
        identity, representation, library_hash = 'tonkeeper_subscription_v2', 'full_code', None
    else:
        return None
    family = _FAMILIES[identity]
    return {
        'implementation_id': identity,
        'family': family['family'],
        'application_id': family['application_id'],
        'code_hash': digest,
        'code_representation': representation,
        'library_code_hash': library_hash,
        'library_resolution_verified': False if library_hash else None,
        'source_urls': list(family['source_urls']),
        'evidence_scope': 'extension_contract_implementation',
        'signing_application': 'UNKNOWN',
        'confidence_ceiling': 'POSSIBLE',
    }


def _crc32c(raw):
    """TON BOC CRC32C uses Castagnoli and stores the result little-endian."""
    value = 0xffffffff
    for byte in raw:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
    return (value ^ 0xffffffff).to_bytes(4, 'little')


def extension_implementation_from_code(value):
    """Recognize only the exact one-cell, pinned MyTonWallet library reference.

    This does not expand the general BOC decoder's exotic-cell support. Header,
    cell shape, byte counts and a present CRC are checked before hashing the
    representation. The currently resolved library bytecode is not verified.
    Ordinary or other exotic code remains outside this helper's scope.
    """
    if not isinstance(value, str) or len(value) > 1024:
        return None
    try:
        text = value.strip()
        raw = bytes.fromhex(text) if text.startswith('b5ee9c72') else base64.b64decode(text, validate=True)
        if len(raw) < 11 or raw[:4] != bytes.fromhex('b5ee9c72'):
            return None
        flags, offset_size = raw[4], raw[5]
        size = flags & 7
        if flags & 0x38 or not 1 <= size <= 4 or not 1 <= offset_size <= 8:
            return None
        pos = 6
        def uint(width):
            nonlocal pos
            if pos + width > len(raw):
                raise ValueError('truncated library reference BOC')
            result = int.from_bytes(raw[pos:pos+width], 'big')
            pos += width
            return result
        count, roots, absent = uint(size), uint(size), uint(size)
        total, root = uint(offset_size), uint(size)
        if (count, roots, absent, total, root) != (1, 1, 0, 35, 0):
            return None
        if flags & 0x80 and uint(offset_size) != total:
            return None
        has_crc = bool(flags & 0x40)
        if pos + total + (4 if has_crc else 0) != len(raw):
            return None
        if has_crc and _crc32c(raw[:-4]) != raw[-4:]:
            return None
        cell = raw[pos:pos+total]
        if cell != bytes([8, 66, 2]) + bytes.fromhex(_MTW_CODE):
            return None
        result = extension_implementation(hashlib.sha256(cell).hexdigest())
        if result:
            result['code_observation'] = 'exact_single_exotic_library_reference'
            result['boc_crc_verified'] = has_crc
        return result
    except (ValueError, TypeError, OverflowError):
        return None


def _cell(value):
    # Published bodies/data are much smaller. Reject excess input before the
    # shared decoder allocates cells; exotic code must be checked by hash.
    if not isinstance(value, str) or len(value) > 16_384:
        return None
    try:
        root = decode_boc(value)
        pending, seen = [(root, 0)], set()
        while pending:
            cell, depth = pending.pop()
            if id(cell) in seen:
                continue
            seen.add(id(cell))
            if len(seen) > 16 or depth > 3:
                return None
            pending.extend((child, depth + 1) for child in cell.refs)
        return root
    except (ValueError, TypeError, OverflowError):
        return None


def decode_extension_install(value):
    """Describe only exact published install body shapes.

    MyTonWallet emits 32 bits, Tonkeeper emits 32 + 256 + 256 bits. Both use
    opcode 0x43563174. Any client can submit either shape; matching code,
    transaction success and owner binding require separate evidence.
    """
    cell = _cell(value)
    if cell is None or cell.refs or cell.bit_length not in (32, 544):
        return None
    if Bits(cell).uint(32) != 0x43563174:
        return None
    identity = 'mytonwallet_tg2fa' if cell.bit_length == 32 else 'tonkeeper_2fa'
    return {
        'kind': 'extension_install_request',
        'opcode': '0x43563174',
        'body_bits': cell.bit_length,
        'construction_family_hint': identity,
        'shared_opcode': True,
        'copyable_construction': True,
        'signature_verified': False,
        'signing_application': 'UNKNOWN',
        'source_urls': list(_FAMILIES[identity]['source_urls']),
    }


def extension_wallet_from_data(value, implementation_id=None):
    """Return the owner from an exact ordinary storage layout or ``None``.

    The caller should supply a verified implementation_id from the code hash.
    Without that hint this is a structural observation only. Public keys and
    the Telegram identifier are never returned. Tonkeeper's variable-length
    pending delegation state is intentionally unsupported.
    """
    cell = _cell(value)
    if cell is None or implementation_id not in (None, *_FAMILIES):
        return None
    if cell.bit_length == 620 and len(cell.refs) == 1:
        identity = 'mytonwallet_tg2fa'
        identifier = cell.refs[0]
        # Decimal string stored by storeStringRefTail, bounded to uint64 text.
        if identifier.refs or not 8 <= identifier.bit_length <= 160 or identifier.bit_length % 8:
            return None
        if any(byte < 48 or byte > 57 for byte in identifier.data):
            return None
    elif cell.bit_length in (876, 877) and not cell.refs:
        identity = 'tonkeeper_2fa'
    else:
        return None
    if implementation_id is not None and implementation_id != identity:
        return None
    try:
        reader = Bits(cell)
        seqno = reader.uint(32)
        # Both pinned contracts store addr_std without anycast.
        if reader.uint(2) != 2 or reader.uint(1) != 0:
            return None
        workchain = reader.uint(8)
        if workchain >= 128:
            workchain -= 256
        address_hash = reader.uint(256)
        if identity == 'tonkeeper_2fa':
            # Initial data uses two zero flags; installed data uses one flag.
            if cell.bit_length == 877 and (seqno != 0 or reader.uint(578) != 0):
                return None
            if cell.bit_length == 876:
                reader.skip(512)
                if reader.uint(1) != 0:
                    return None
                reader.skip(64)
        return f'{workchain}:{address_hash:064x}'
    except (ValueError, TypeError, OverflowError):
        return None
