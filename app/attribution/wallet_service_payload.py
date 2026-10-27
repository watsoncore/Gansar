"""Bounded parsing of documented service payloads; no signing-client claims."""
from .wallet_payload import Bits
from app.ton_nft.protocol import decode_boc

BATTERY_RECEIVER='0:f007c6257ea5ff6d83b870619290825851c82a9628fa7e1b84c040212c0a692d'
BATTERY_SOURCES=[
 'https://github.com/tonkeeper/tonkeeper-web/blob/d7ea32150635b53b8bc6fb6c5744434d9370a347/packages/uikit/src/hooks/blockchain/usePurchaseBattery.ts',
 'https://github.com/tonkeeper/ton-assets/blob/922e01fb5190430cd698d769802b235ce8facb66/accounts/infrastructure.yaml',
]

def decode_battery_purchase(value):
    """Match opcode and both flags, validating address and optional snake tail.

    This is a published purchase-request shape, not a receipt or proof that
    Battery credited an account. Promo text is not retained by the detector.
    """
    if not isinstance(value,str) or len(value)>16_384:raise ValueError('purchase body exceeds input limit')
    cell=decode_boc(value);reader=Bits(cell)
    if reader.uint(32)!=0xb7b2515f:return None
    gift=bool(reader.uint(1));recipient=None
    if gift:
        if reader.uint(2)!=2 or reader.uint(1)!=0:raise ValueError('unsupported gift address')
        workchain=reader.uint(8);workchain=workchain-256 if workchain>=128 else workchain
        recipient=f'{workchain}:'+f'{reader.uint(256):064x}'
    promo=bool(reader.uint(1));promo_bytes=0
    if not promo:
        if reader.pos!=cell.bit_length or cell.refs:raise ValueError('unexpected purchase tail')
    else:
        seen=set();node=cell;offset=reader.pos;text=bytearray()
        while True:
            if id(node) in seen or len(seen)>=16:raise ValueError('purchase string exceeds limit')
            seen.add(id(node));remaining=node.bit_length-offset
            if remaining%8 or len(node.refs)>1:raise ValueError('invalid purchase snake string')
            promo_bytes+=remaining//8
            if promo_bytes>4096:raise ValueError('purchase string exceeds byte limit')
            part=Bits(node);part.pos=offset
            text.extend(part.uint(8) for _ in range(remaining//8))
            if not node.refs:break
            node=node.refs[0];offset=0
        text.decode('utf-8')
    return {'opcode':'0xb7b2515f','layout':'battery_purchase_request',
        'gift_present':gift,'gift_recipient':recipient,'promo_present':promo,'promo_bytes':promo_bytes,
        'body_bits':cell.bit_length,'signature_verified':False,'purchase_credit_verified':False,
        'signing_application_confirmed':False}


def decode_subscription_deploy(value, *, state_init=None):
    """Read the exact published subscription V2 deploy shape and optional init.

    Sources are pinned Tonkeeper inMessages.tolk/state.tolk and its Web
    SubscriptionEncoder. A body is copyable; only a supplied exact StateInit
    establishes its implementation and initial wallet binding. Execution,
    destination equality and service payment require transaction evidence.
    Metadata is opaque and is never interpreted as a wallet application name.
    """
    import base64
    import hashlib

    def bounded_cell(encoded):
        if not isinstance(encoded, str) or len(encoded) > 32_768:
            raise ValueError('subscription input exceeds limit')
        text = encoded.strip()
        raw = bytes.fromhex(text) if text.startswith('b5ee9c72') else base64.b64decode(text, validate=True)
        if len(raw) < 6 or raw[:4] != bytes.fromhex('b5ee9c72'):
            raise ValueError('invalid subscription BOC')
        flags, offset_size = raw[4], raw[5]
        size = flags & 7
        if flags & 0x38 or not 1 <= size <= 4 or not 1 <= offset_size <= 8:
            raise ValueError('unsupported subscription BOC flags')
        header = 6 + 3 * size + offset_size
        if header + size > len(raw):
            raise ValueError('truncated subscription BOC header')
        count = int.from_bytes(raw[6:6 + size], 'big')
        total = int.from_bytes(raw[6 + 3 * size:header], 'big')
        expected = header + size + (count * offset_size if flags & 0x80 else 0) + total
        if len(raw) != expected + (4 if flags & 0x40 else 0):
            raise ValueError('unexpected subscription BOC trailing bytes')
        if flags & 0x40:
            crc = 0xffffffff
            for byte in raw[:-4]:
                crc ^= byte
                for _ in range(8):
                    crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
            if (crc ^ 0xffffffff).to_bytes(4, 'little') != raw[-4:]:
                raise ValueError('invalid subscription BOC CRC32C')
        root = decode_boc(encoded)
        pending, seen = [(root, 0)], set()
        while pending:
            node, depth = pending.pop()
            if depth > 32:
                raise ValueError('subscription cell depth exceeds limit')
            if id(node) in seen:
                continue
            seen.add(id(node))
            if len(seen) > 128:
                raise ValueError('subscription cell count exceeds limit')
            pending.extend((ref, depth + 1) for ref in node.refs)
        return root

    def coins(reader):
        length = reader.uint(4)
        amount = reader.uint(length * 8)
        if length and amount < 1 << ((length - 1) * 8):
            raise ValueError('noncanonical subscription coins')
        return amount

    def address(reader):
        if reader.uint(2) != 2 or reader.uint(1) != 0:
            raise ValueError('unsupported subscription address')
        workchain = reader.uint(8)
        workchain = workchain - 256 if workchain >= 128 else workchain
        return f'{workchain}:{reader.uint(256):064x}'

    def digest(root):
        pending, hashes = [(root, False)], {}
        while pending:
            node, ready = pending.pop()
            if id(node) in hashes:
                continue
            if not ready:
                pending.append((node, True))
                pending.extend((ref, False) for ref in reversed(node.refs))
                continue
            children = [hashes[id(ref)] for ref in node.refs]
            representation = bytes([len(node.refs), node.bit_length // 8 + (node.bit_length + 7) // 8]) + node.data
            representation += b''.join(depth.to_bytes(2, 'big') for _, depth in children)
            representation += b''.join(value for value, _ in children)
            hashes[id(node)] = (hashlib.sha256(representation).digest(), max((depth for _, depth in children), default=-1) + 1)
        return hashes[id(root)][0].hex()

    def empty(node):
        return node.bit_length == 0 and not node.refs

    body = bounded_cell(value)
    reader = Bits(body)
    if reader.uint(32) != 0xf71783cb:
        return None
    if len(body.refs) != 2:
        raise ValueError('subscription deploy requires exactly two references')
    query_id = reader.uint(64)
    result = {
        'opcode': '0xf71783cb', 'layout': 'tonkeeper_subscription_v2_deploy',
        'query_id': query_id, 'tonkeeper_query_namespace': query_id >> 32 == 0x546de4ef,
        'first_charging_date': reader.uint(32), 'payment_per_period_nanoton': str(coins(reader)),
        'period_seconds': reader.uint(32), 'grace_period_seconds': reader.uint(32),
        'caller_fee_nanoton': str(coins(reader)), 'withdraw_address': address(reader),
        'body_bits': body.bit_length, 'withdraw_body_hash': digest(body.refs[0]),
        'metadata_cell_hash': digest(body.refs[1]), 'metadata_interpreted': False,
        'initial_state_verified': False, 'copyable_construction': True,
        'signature_verified': False, 'signing_application_confirmed': False,
        'source_urls': [
            'https://github.com/tonkeeper/ton-subscriptions/blob/a0aa878577e4b74c40c7c2c8bdd9e09dcb57547d/contracts/inMessages.tolk',
            'https://github.com/tonkeeper/ton-subscriptions/blob/a0aa878577e4b74c40c7c2c8bdd9e09dcb57547d/contracts/state.tolk',
            'https://github.com/tonkeeper/tonkeeper-web/blob/d7ea32150635b53b8bc6fb6c5744434d9370a347/packages/core/src/service/ton-blockchain/encoder/subscription-encoder/subscription-encoder.ts',
        ],
    }
    if reader.pos != body.bit_length:
        raise ValueError('unexpected subscription deploy tail')
    if state_init is None:
        return result
    init = bounded_cell(state_init)
    if init.bit_length != 5 or Bits(init).uint(5) != 6 or len(init.refs) != 2:
        raise ValueError('unsupported subscription StateInit')
    code, data = init.refs
    code_hash = digest(code)
    if code_hash != '48942963827c5147fe935cd22e88ba418011fe656eab78b79c5c6343d84d421a':
        raise ValueError('subscription StateInit code is not the published implementation')
    storage = Bits(data)
    if storage.uint(1) or storage.uint(32) or storage.uint(32) or storage.uint(2):
        raise ValueError('subscription StateInit is not uninitialized')
    if len(data.refs) != 3 or storage.uint(32) or coins(storage):
        raise ValueError('invalid subscription initial state')
    wallet = address(storage)
    version_tag = storage.uint(8)
    beneficiary = address(storage)
    subscription_id = storage.uint(32)
    if coins(storage) or storage.uint(32) or storage.pos != data.bit_length:
        raise ValueError('unexpected subscription initial state tail')
    if version_tag not in (4, 51):
        raise ValueError('unsupported subscription wallet version tag')
    precompiled, withdraw, metadata = data.refs
    if (precompiled.bit_length != 4 or Bits(precompiled).uint(4) != 0
            or len(precompiled.refs) != 1 or not empty(precompiled.refs[0])
            or withdraw.bit_length != 2 or Bits(withdraw).uint(2) != 0
            or len(withdraw.refs) != 1 or not empty(withdraw.refs[0]) or not empty(metadata)):
        raise ValueError('unexpected subscription initial references')
    result.update(initial_state_verified=True, deployment_code_hash=code_hash,
        deployment_address='0:' + digest(init), initial_wallet=wallet,
        initial_beneficiary=beneficiary, initial_subscription_id=subscription_id,
        wallet_version_tag=version_tag, evidence_scope='published_implementation_and_initial_wallet_binding')
    return result


def decode_evm_application_swap(value, application_id):
    """Return strictly decoded supported router calldata, or None (no I/O/state).

    Calldata alone is never attribution: require the exact published chain-specific
    router, target-originated outer transaction and confirmed success independently.
    Unsupported permit/multicall variants deliberately abstain.
    """
    import re
    if not isinstance(value, str) or len(value) % 2 or len(value) > 2_000_010 or len(value) < 10:
        return None
    if not re.fullmatch(r'0x[0-9a-fA-F]+', value):
        return None
    selector = value[:10].lower()
    data = bytes.fromhex(value[10:])

    def number(index):
        start = index * 32
        if start + 32 > len(data):
            raise ValueError('missing ABI word')
        return int.from_bytes(data[start:start + 32])

    def address(index):
        start = index * 32
        if start + 32 > len(data) or any(data[start:start + 12]):
            raise ValueError('noncanonical address')
        return '0x' + data[start + 12:start + 32].hex()

    def dynamic(index, head_size):
        offset = number(index)
        if offset < head_size or offset % 32 or offset + 32 > len(data):
            raise ValueError('invalid dynamic offset')
        size = int.from_bytes(data[offset:offset + 32])
        end = offset + 32 + size
        padded_end = offset + 32 + ((size + 31) // 32) * 32
        if padded_end > len(data) or any(data[end:padded_end]):
            raise ValueError('truncated or nonzero ABI padding')
        return data[offset + 32:end], offset, padded_end

    try:
        if application_id in ('metamask', 'metamask_swaps'):
            if selector != '0x5f575529' or len(data) < 128:
                return None
            aggregator, first, first_end = dynamic(0, 128)
            swap, second, second_end = dynamic(3, 128)
            # Every 2026-10-21 confirmed live sample has one trailing byte.
            # Its origin is unknown: retain it, never treat its value as branding.
            # Standard ABI without suffix is also valid. Other variants abstain.
            if first != 128 or second != first_end or len(data) - second_end not in (0, 1):
                return None
            aggregator_name = aggregator.decode('utf-8')
            amount = number(2)
            if not aggregator_name or len(aggregator) > 256 or len(swap) < 4 or amount == 0:
                return None
            return {'application_id': 'metamask', 'feature': 'Swaps',
                'method': 'swap(string,address,uint256,bytes)', 'selector': selector,
                'aggregator_id': aggregator_name, 'sell_token': address(1),
                'sell_amount': str(amount), 'swap_calldata_bytes': len(swap),
                'uninterpreted_suffix': data[second_end:].hex() or None,
                'claim_scope': 'APPLICATION_INTERACTION', 'signing_application': 'UNKNOWN'}

        if application_id not in ('rainbow', 'rainbow_swaps'):
            return None
        methods = {
            '0x3c2b9a7d': ('fillQuoteEthToToken', 4, 2, (0, 1)),
            '0x999b6464': ('fillQuoteTokenToEth', 5, 2, (0, 1)),
            '0x55e4b7be': ('fillQuoteTokenToToken', 6, 3, (0, 1, 2)),
        }
        method, words, dynamic_index, address_indices = methods[selector]
        head = words * 32
        if len(data) < head:
            return None
        addresses = [address(index) for index in address_indices]
        if any(item == '0x' + '0' * 40 for item in addresses):
            return None
        swap, offset, end = dynamic(dynamic_index, head)
        # Rainbow SDK permits an optional four-byte, copyable referrer hash suffix.
        if offset != head or len(swap) < 4 or len(data) - end not in (0, 4):
            return None
        result = {'application_id': 'rainbow', 'feature': 'Swaps',
            'method': method, 'selector': selector, 'swap_target': addresses[-1],
            'swap_calldata_bytes': len(swap), 'claim_scope': 'APPLICATION_INTERACTION',
            'signing_application': 'UNKNOWN', 'referrer_suffix': data[end:].hex() or None}
        if method == 'fillQuoteEthToToken':
            result.update(buy_token=addresses[0], fee_amount=str(number(3)))
        else:
            amount = number(words - 2)
            if amount == 0:
                return None
            result.update(sell_token=addresses[0], sell_amount=str(amount))
            if method == 'fillQuoteTokenToToken':
                result.update(buy_token=addresses[1], fee_amount=str(number(5)))
            else:
                result['fee_percentage_1e18'] = str(number(4))
        return result
    except (ValueError, UnicodeDecodeError, KeyError):
        return None
