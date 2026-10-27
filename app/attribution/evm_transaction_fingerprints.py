"""Bounded offline EVM infrastructure evidence; never a signing-UI verdict.

Only published infrastructure is allowlisted. ABI-shaped input, transaction
sender, arbitrary labels and an authorization tuple are not application proof.
Receipt observations are historical; collected runtime fingerprints are current.
"""
from __future__ import annotations

import hashlib
import json
import re

from app.utils.keccak import keccak_256
from app.utils.security import safe_public_url
from .normalize import CHAIN_IDS, EVM_CHAINS, canonical_address, normalize_chain

SAFE_PIN = 'e9cc9798ab834e7fe515d361566eb4a28c65387f'
AA_PIN = '1c6b669d0eea734e09a87e095ba15e076151718a'
MM_PIN = '555dd2043a69d4febba108465c5d79aabc65abdb'
SAFE_SOURCES = {
    '1.3.0': f'https://github.com/safe-global/safe-deployments/blob/{SAFE_PIN}/src/assets/v1.3.0/proxy_factory.json',
    '1.4.1': f'https://github.com/safe-global/safe-deployments/blob/{SAFE_PIN}/src/assets/v1.4.1/safe_proxy_factory.json',
}
AA_SOURCE = f'https://github.com/eth-infinitism/account-abstraction/blob/{AA_PIN}/contracts/interfaces/IEntryPoint.sol'
AA_DEPLOYMENT = f'https://github.com/eth-infinitism/account-abstraction/blob/{AA_PIN}/README.md'
AA_V06_DEPLOYMENT = 'https://github.com/eth-infinitism/account-abstraction/blob/abff2aca61a8f0934e533d0d352978055fddbd96/deployments/mainnet/EntryPoint.json'
MM_SOURCE = f'https://github.com/MetaMask/smart-accounts-kit/blob/{MM_PIN}/packages/delegation-deployments/src/contractAddresses.ts'
MM_CHAINS_SOURCE = f'https://github.com/MetaMask/smart-accounts-kit/blob/{MM_PIN}/packages/delegation-deployments/src/index.ts'
SAFE_FACTORIES = {
    '0xa6b71e26c5e0845f74c812102ca7114b6a896ab2': '1.3.0',
    '0xc22834581ebc8527d974f8a1c97e1bea4ef910bc': '1.3.0',
    '0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67': '1.4.1',
}
ENTRYPOINTS = {
    '0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789': '0.6',
    '0x0000000071727de22e5e9d8baf0edac6f37da032': '0.7',
    '0x4337084d9e255ff0702461cf8895ce9e3b5ff108': '0.8',
}
MM_DELEGATE = '0x63c0c19a282a1b52b07dd5a65b58948a07dae32b'
MM_CHAINS = EVM_CHAINS - {'avalanche'}  # The pinned registry does not list Avalanche.
LIMITATIONS = [
    'Contract implementation, deployment factory, bundler and paymaster are separate roles; none authenticates the signing application UI.',
    'Public implementations can be used through another compatible wallet, SDK, dApp or relayer; account keys can be imported.',
    'Receipt emitter addresses are matched to a pinned publication; historical emitter bytecode, signatures and canonical-chain finality are not independently verified here.',
    'Collected current runtime code cannot prove historical delegation or implementation at the transaction block.',
    'Missing receipt/code or absence of a marker does not exclude an application.',
]


def _topic(signature):
    return '0x' + keccak_256(signature.encode()).hex()


PROXY_CREATION = _topic('ProxyCreation(address,address)')
USER_OPERATION = _topic('UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)')
ACCOUNT_DEPLOYED = _topic('AccountDeployed(bytes32,address,address,address)')


def _hex(value, size=None):
    if not isinstance(value, str):
        return None
    if size is not None and len(value) != 2 + size * 2:
        return None
    if not re.fullmatch(r'0x(?:[a-fA-F0-9]{2})*', value):
        return None
    return value.lower()


def _word_address(value):
    value = _hex(value, 32)
    return '0x' + value[-40:] if value and value[2:26] == '0' * 24 else None


def _integer(value):
    if isinstance(value, (bool, float)):
        return None
    try:
        return int(value, 16) if isinstance(value, str) and value.startswith('0x') else int(value)
    except (ValueError, TypeError, OverflowError):
        return None


def _get(value, key, default=None):
    return value.get(key, default) if isinstance(value, dict) else getattr(value, key, default)


def analyze_evm_transaction(tx, address_records=None):
    """Return evidence collections from a normalized Transaction or dictionary.

    Supported receipt locations: raw.receipt, raw.transaction_receipt,
    raw.rpc_receipt. A receipt must match this transaction's hash and succeed.
    Account records are network-scoped normalized dossier records. No I/O occurs.
    """
    result = {key: [] for key in ('implementation_observations', 'construction_fingerprints',
                                'investigative_leads', 'evidence', 'checks')}
    result['limitations'] = list(LIMITATIONS)
    chain = normalize_chain(_get(tx, 'chain') or _get(tx, 'blockchain'))
    if chain not in EVM_CHAINS:
        result['checks'].append({'method': 'evm_transaction_fingerprints', 'status': 'not_applicable'})
        return result
    raw = _get(tx, 'raw') or {}
    raw = raw if isinstance(raw, dict) else {}
    tx_hash = _hex(_get(tx, 'tx_hash') or _get(tx, 'hash') or raw.get('hash'), 32)
    sender = canonical_address(chain, _get(tx, 'from_address') or _get(tx, 'from') or raw.get('from'))
    recipient = canonical_address(chain, _get(tx, 'to_address') or _get(tx, 'to') or raw.get('to'))
    source = _get(tx, 'source') or 'collected_public_evm_data'
    source_url = safe_public_url(_get(tx, 'url'))
    seen = set()

    def emit(method, subject, fields, urls, collection='implementation_observations', role=None, refs=(), state_time=None):
        basis = {'blockchain': chain, 'method': method, 'subject_address': subject,
                 'transaction_hash': tx_hash, 'fields': fields}
        identity = hashlib.sha256(json.dumps(basis, sort_keys=True, default=str).encode()).hexdigest()
        if identity in seen:
            return
        seen.add(identity)
        eid = 'wallet-app:evm:' + identity
        receipt_proof = raw.get('receipt_provenance') if role != 'delegated_code_reference' else None
        receipt_proof = receipt_proof if isinstance(receipt_proof, dict) else {}
        observed_source = receipt_proof.get('source') or source
        observed_url = safe_public_url(receipt_proof.get('source_url')) or source_url
        observed_at = receipt_proof.get('observed_at') or raw.get('observed_at') or raw.get('collected_at')
        if role == 'delegated_code_reference':
            observed_source, observed_url, observed_at = 'collected_current_runtime_fingerprint', None, state_time
        row = {**basis, 'observation_id': eid, 'status': 'observed', 'scope': role or method,
               'role': role or method, 'source': observed_source, 'source_url': observed_url,
               'observed_at': observed_at,
               'source_observation_time_available': bool(observed_at),
               'source_urls': urls, 'evidence_ids': [eid, *refs],
               'signing_application_confirmed': False, 'limitations': list(LIMITATIONS)}
        result[collection].append(row)
        result['evidence'].append({**basis, 'evidence_id': eid, 'source': observed_source,
            'source_url': observed_url, 'source_urls': urls, 'relation': method, 'facts': fields,
            'observed_at': observed_at, 'response_sha256': receipt_proof.get('response_sha256'),
            'source_observation_time_available': bool(observed_at),
            'response_hash_scope': receipt_proof.get('response_hash_scope'),
            'source_independence': 'One physical receipt/runtime observation, even when repeated by multiple providers.'})

    # Runtime is independently useful even when a transaction receipt is absent.
    records = address_records if isinstance(address_records, dict) else {}
    for address in dict.fromkeys(a for a in (sender, recipient) if a):
        record = records.get(f'{chain}:{address}') or records.get(address)
        if not isinstance(record, dict) or normalize_chain(record.get('blockchain') or record.get('chain') or chain) != chain:
            continue
        contract = record.get('contract') or {}
        if not isinstance(contract, dict) or contract.get('runtime_observation_conflict'):
            continue
        code = contract.get('runtime_code') or contract.get('code')
        delegate = None
        if _hex(code, 23) and code.lower().startswith('0xef0100'):
            delegate = '0x' + code[-40:].lower()
        elif contract.get('kind') == 'eip7702_delegation_designator':
            candidate = canonical_address(chain, contract.get('implementation'))
            if candidate:
                expected = '0x' + keccak_256(bytes.fromhex('ef0100' + candidate[2:])).hex()
                if _hex(contract.get('code_hash'), 32) == expected:
                    delegate = candidate
        if delegate:
            fields = {'delegate_address': delegate, 'runtime_scope': 'collected_current_account_code',
                      'delegate_runtime_verified': False}
            urls = ['https://eips.ethereum.org/EIPS/eip-7702']
            if delegate == MM_DELEGATE and chain in MM_CHAINS:
                fields.update(implementation_origin='MetaMask Delegation Framework',
                              implementation='EIP7702StatelessDeleGator', published_version='1.3.0',
                              match_scope='published_delegate_target_address')
                urls += [MM_SOURCE, MM_CHAINS_SOURCE]
            emit('evm_eip7702_delegate_target', address, fields, urls,
                 role='delegated_code_reference', refs=contract.get('evidence_ids', []), state_time=record.get('observed_at'))

    receipt = next((raw[k] for k in ('receipt', 'transaction_receipt', 'rpc_receipt') if isinstance(raw.get(k), dict)), None)
    reason = 'receipt_unavailable'
    logs = []
    if receipt:
        if not tx_hash or _hex(receipt.get('transactionHash'), 32) != tx_hash:
            reason = 'receipt_transaction_hash_mismatch_or_missing'
        elif _integer(receipt.get('status')) != 1 or _get(tx, 'success') is False or raw.get('emulated') is True:
            reason = 'receipt_failed_unknown_or_emulated'
        elif raw.get('chainId') is not None and _integer(raw['chainId']) != CHAIN_IDS[chain]:
            reason = 'transaction_chain_id_mismatch'
        elif isinstance(receipt.get('logs'), list):
            logs = receipt['logs'][:5000]
            reason = 'validated_receipt_envelope'
    result['checks'].append({'method': 'evm_receipt_infrastructure_events',
        'status': 'observed' if reason == 'validated_receipt_envelope' else 'unavailable',
        'result': {'reason': reason, 'logs_examined': len(logs),
                   'logs_truncated': bool(receipt and isinstance(receipt.get('logs'), list) and len(receipt['logs']) > 5000)},
        'source_urls': list(SAFE_SOURCES.values()) + [AA_SOURCE, AA_DEPLOYMENT, AA_V06_DEPLOYMENT, MM_SOURCE], 'evidence_ids': []})
    # Normalized token/internal rows can project a different sender. Only the
    # receipt/native RPC envelope may identify the outer transaction submitter.
    outer_sender = canonical_address(chain, receipt.get('from')) if receipt else None
    if not outer_sender and _hex(raw.get('hash'), 32) == tx_hash:
        outer_sender = canonical_address(chain, raw.get('from'))
    for log in logs:
        if not isinstance(log, dict) or log.get('removed') is True:
            continue
        if log.get('transactionHash') is not None and _hex(log['transactionHash'], 32) != tx_hash:
            continue
        if receipt.get('blockHash') and log.get('blockHash'):
            if not _hex(log['blockHash'], 32) or _hex(log['blockHash'], 32) != _hex(receipt['blockHash'], 32):
                continue
        address = canonical_address(chain, log.get('address'))
        topics = log.get('topics')
        encoded_data = log.get('data')
        if not isinstance(encoded_data, str) or len(encoded_data) > 2 + 32 * 8 * 2:
            continue
        data = _hex(encoded_data)
        if not isinstance(topics, list) or not topics or len(topics) > 4 or not data:
            continue
        topics = [_hex(t, 32) for t in topics]
        if not all(topics):
            continue
        words = ['0x' + data[i:i + 64] for i in range(2, len(data), 64)]
        if any(len(w) != 66 for w in words):
            continue
        log_index = _integer(log.get('logIndex'))
        if address in SAFE_FACTORIES and topics[0] == PROXY_CREATION:
            version = SAFE_FACTORIES[address]
            if version == '1.3.0' and len(topics) == 1 and len(words) == 2:
                proxy, singleton = map(_word_address, words)
            elif version == '1.4.1' and len(topics) == 2 and len(words) == 1:
                proxy, singleton = _word_address(topics[1]), _word_address(words[0])
            else:
                continue
            if proxy and singleton and int(proxy, 16) and int(singleton, 16):
                emit('evm_safe_proxy_creation', proxy,
                     {'factory_address': address, 'factory_version': version, 'singleton_address': singleton,
                      'log_index': log_index, 'implementation_origin': 'Safe',
                      'match_scope': 'published_factory_emitted_proxy_creation', 'current_implementation_verified': False},
                     [SAFE_SOURCES[version]], role='wallet_deployment_infrastructure')
        if address not in ENTRYPOINTS:
            continue
        deployment_source = {'0.6': AA_V06_DEPLOYMENT, '0.7': MM_SOURCE, '0.8': AA_DEPLOYMENT}[ENTRYPOINTS[address]]
        if topics[0] == USER_OPERATION and len(topics) == 4 and len(words) == 4:
            account, paymaster = _word_address(topics[2]), _word_address(topics[3])
            success = int(words[1], 16)
            if not account or not paymaster or success not in (0, 1):
                continue
            emit('evm_erc4337_user_operation', account,
                 {'entrypoint_address': address, 'entrypoint_version': ENTRYPOINTS[address],
                  'user_operation_hash': topics[1], 'paymaster_address': paymaster if int(paymaster, 16) else None,
                  'nonce': str(int(words[0], 16)), 'user_operation_success': bool(success),
                  'actual_gas_cost': str(int(words[2], 16)), 'actual_gas_used': str(int(words[3], 16)),
                  'outer_transaction_sender': outer_sender, 'outer_sender_role': 'transaction_submitter_or_bundler',
                  'log_index': log_index},
                 [AA_SOURCE, deployment_source], role='account_abstraction_execution')
        elif topics[0] == ACCOUNT_DEPLOYED and len(topics) == 3 and len(words) == 2:
            account, factory, paymaster = _word_address(topics[2]), _word_address(words[0]), _word_address(words[1])
            if account and factory and paymaster:
                emit('evm_erc4337_account_deployed', account,
                     {'entrypoint_address': address, 'entrypoint_version': ENTRYPOINTS[address],
                      'user_operation_hash': topics[1], 'factory_address': factory,
                      'paymaster_address': paymaster if int(paymaster, 16) else None, 'log_index': log_index},
                     [AA_SOURCE, deployment_source], role='account_abstraction_deployment')
    result['checks'].append({'method': 'evm_signing_application_identity', 'status': 'unavailable',
        'result': {'status': 'UNKNOWN', 'reason': 'Receipt and code roles do not authenticate MetaMask, Rabby, Coinbase Wallet or another signing UI.'},
        'source_urls': ['https://eips.ethereum.org/EIPS/eip-7702', 'https://eips.ethereum.org/EIPS/eip-4337'],
        'evidence_ids': []})
    return result
