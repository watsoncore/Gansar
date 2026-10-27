"""Offline Solana/TRON protocol-role observations; no signing-app inference.

The raw provider transaction must bind to the projected transaction hash.
Source pins describe supported layouts, not an attestation of historical code.
"""
from __future__ import annotations

import hashlib
from app.utils.detect import _base58_decode, BASE58_ALPHABET
from .normalize import canonical_address

SQUADS = 'SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf'
SQUADS_PIN = 'af94153ff77a28b6effe46b9c94baaa93742b48c'
TRON_PIN = '8432beca98c52ba04c82aea0b48ae9f9f882c82a'
SOLANA_RPC = 'https://solana.com/docs/rpc/json-structures'
TRON_SOURCE = f'https://github.com/tronprotocol/protocol/blob/{TRON_PIN}/core/Tron.proto'
TRON_PERMISSIONS = 'https://developers.tron.network/docs/multi-signature'
COMPUTE = 'ComputeBudget111111111111111111111111111111'
# Discriminator, multisig account position, minimum accounts. Generated SDK at pin.
SQUADS_LAYOUTS = {
    'c208a15799a419ab': ('vaultTransactionExecute', 0, 4),
    '32ddc75d28f58be9': ('multisigCreateV2', 2, 6),
    '30fa4ea8d0e2dad3': ('vaultTransactionCreate', 0, 5),
    'dc3c49e01e6c4f9f': ('proposalCreate', 0, 5),
    '9025a488bcd82af8': ('proposalApprove', 0, 3),
}
LIMITS = [
    'Program, permission, fee payer and signer roles do not identify Phantom, Solflare, Backpack, TronLink, TokenPocket or a physical person.',
    'An instruction may be composed by a dApp or SDK and signed by another application. No signing application is confirmed.',
    'Provider-reported success is not independent signature, historical bytecode or finality verification.',
    'Collected history is partial; absence of a marker never excludes an application.',
]

def _get(tx, key, default=None):
    return tx.get(key, default) if isinstance(tx, dict) else getattr(tx, key, default)

def _result():
    return {key: [] for key in ('implementation_observations', 'construction_fingerprints',
        'investigative_leads', 'evidence', 'checks', 'limitations')}

def _fact(rule, fields, urls, **extra):
    return dict(rule_id=rule, rule_version='2026-10-20.1', fields=fields, source_urls=urls,
        signing_application_confirmed=False, status='OBSERVED', **extra)

def _integer(value):
    return value if type(value) is int and value >= 0 else None

def analyze_solana_transaction(tx, address_records=None):
    out = _result()
    if _get(tx, 'chain') != 'solana': return out
    out['limitations'] = LIMITS[:]
    raw = _get(tx, 'raw', {}) or {}; provider = raw.get('provider_record') or {}
    transaction = provider.get('transaction') or {}; meta = provider.get('meta') or {}
    signatures = transaction.get('signatures') or []
    bound = bool(signatures and signatures[0] == _get(tx, 'tx_hash'))
    message = transaction.get('message') or {}
    keys = message.get('accountKeys') or []
    out['checks'].append({'method':'solana_message_roles', 'status':'observed' if bound else 'unavailable',
        'reason':'Requires full RPC transaction with matching first signature, message and metadata.', 'source_urls':[SOLANA_RPC]})
    if not bound or not isinstance(keys, list) or not keys or len(keys) > 512: return out
    parsed_keys = isinstance(keys[0], dict)
    keys = [v.get('pubkey') if isinstance(v, dict) else v for v in keys]
    if not parsed_keys:
        loaded = meta.get('loadedAddresses') or {}
        keys += list(loaded.get('writable') or []) + list(loaded.get('readonly') or [])
    def key(value):
        value = keys[value] if type(value) is int and 0 <= value < len(keys) else value if isinstance(value,str) else None
        return canonical_address('solana', value)
    header = message.get('header') or {}
    nsign = _integer(header.get('numRequiredSignatures'))
    fields = {'message_version':provider.get('version'), 'fee_payer':key(0),
        'signer_count':nsign, 'address_lookup_tables':len(message.get('addressTableLookups') or []),
        'rpc_success':meta.get('err') is None if 'err' in meta else None,
        'fee_lamports':meta.get('fee'), 'scope':'transaction_message_not_wallet_ui'}
    out['construction_fingerprints'].append(_fact('solana_message_roles_v1', fields, [SOLANA_RPC]))
    instructions = [(f'outer:{i}', v) for i,v in enumerate((message.get('instructions') or [])[:256])]
    for group in (meta.get('innerInstructions') or [])[:256]:
        if not isinstance(group,dict):continue
        remaining=1024-len(instructions)
        if remaining<=0:break
        instructions.extend((f'inner:{group.get("index")}:{i}',v) for i,v in enumerate((group.get('instructions') or [])[:min(256,remaining)]))
    compute = [];decoded_chars=0;omitted=0
    for position, ix in instructions[:1024]:
        if not isinstance(ix,dict): continue
        program = key(ix.get('programId') or ix.get('programIdIndex'))
        if program not in {SQUADS,COMPUTE}:continue
        encoded = ix.get('data')
        if not isinstance(encoded,str) or len(encoded)>2048 or decoded_chars+len(encoded)>65536:
            omitted+=1;continue
        decoded_chars+=len(encoded)
        data = _base58_decode(encoded)
        if program == COMPUTE:
            if data and ((data[0] == 2 and len(data)==5) or (data[0] == 3 and len(data)==9)):
                compute.append({'position':position, 'instruction_tag':data[0], 'value':int.from_bytes(data[1:],'little')})
        if program != SQUADS or not data: continue
        layout = SQUADS_LAYOUTS.get(data[:8].hex())
        accounts = ix.get('accounts') or []
        if not layout or len(accounts) < layout[2]: continue
        subject = key(accounts[layout[1]])
        if not subject: continue
        method = layout[0]; url=f'https://github.com/Squads-Protocol/v4/blob/{SQUADS_PIN}/sdk/multisig/src/generated/instructions/{method}.ts'
        row = _fact('solana_squads_v4_instruction_v1', {'program_id':program, 'instruction':method,
            'discriminator_hex':data[:8].hex(), 'instruction_position':position,
            'multisig_account':subject, 'fee_payer':key(0),
            'rpc_success':fields['rpc_success'], 'scope':'observed_protocol_instruction'}, [url, SOLANA_RPC],
            subject_address=subject, role='multisig_state_account', implementation='Squads v4',
            provenance_tier='HEURISTIC_ASSOCIATION',
            implementation_identification_scope='published program ID and instruction layout; historical program binary not verified')
        # A failed/unknown instruction is an attempt, not executed implementation proof.
        out['implementation_observations' if fields['rpc_success'] is True else 'construction_fingerprints'].append(row)
    if compute:
        out['construction_fingerprints'].append(_fact('solana_compute_budget_instructions_v1',
            {'instructions':compute, 'message_version':provider.get('version'),
             'scope':'instruction_presence_only; execution semantics depend on message version'},
            ['https://solana.com/docs/core/fees/compute-budget']))
    out['checks'].append({'method':'solana_squads_v4_instruction_v1',
        'status':'observed' if out['implementation_observations'] else 'not_found_in_checked_sample',
        'absence_excludes_application':False, 'instructions_checked':min(len(instructions),1024),
        'instruction_data_omitted':omitted, 'instruction_data_characters_decoded':decoded_chars,
        'source_urls':[f'https://github.com/Squads-Protocol/v4/tree/{SQUADS_PIN}']})
    return out

def _tron_address(value):
    if canonical_address('tron', value): return value
    if not isinstance(value,str) or len(value)!=42 or not value.startswith('41'): return None
    try: body=bytes.fromhex(value)
    except ValueError:return None
    checked=body+hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    n=int.from_bytes(checked,'big');result=''
    while n:n,rem=divmod(n,58);result=BASE58_ALPHABET[rem]+result
    return canonical_address('tron',result)

def tron_native_contracts(tx):
    """Only raw native contracts explicitly bound to this transaction hash."""
    raw=_get(tx,'raw',{}) or {};provider=raw.get('provider_record')
    if not isinstance(provider,dict) or not provider.get('txID') or provider['txID']!=_get(tx,'tx_hash'):return []
    native=provider.get('raw_data')
    contracts=native.get('contract') if isinstance(native,dict) else None
    return contracts[:32] if isinstance(contracts,list) else []

def is_tron_non_monetary(tx):
    return _get(tx,'chain')=='tron' and any(isinstance(c,dict) and c.get('type') in {
        'DelegateResourceContract','UnDelegateResourceContract','AccountPermissionUpdateContract'} for c in tron_native_contracts(tx))

def analyze_tron_transaction(tx, address_records=None):
    out = _result()
    if _get(tx,'chain') != 'tron': return out
    out['limitations']=LIMITS[:]
    raw=_get(tx,'raw',{}) or {}; provider=raw.get('provider_record') or {}
    contracts=(provider.get('raw_data') or {}).get('contract') or []
    bound=bool(provider.get('txID') and provider['txID']==_get(tx,'tx_hash'))
    out['checks'].append({'method':'tron_native_contract_roles', 'status':'observed' if bound else 'unavailable',
        'reason':'Requires matching txID and native raw_data.contract; explorer summary alone is insufficient.',
        'source_urls':[TRON_SOURCE,TRON_PERMISSIONS]})
    if not bound or not isinstance(contracts,list): return out
    ret=provider.get('ret') or []; successful=bool(ret and all(r.get('contractRet')=='SUCCESS' for r in ret))
    for i, contract in enumerate(contracts[:32]):
        if not isinstance(contract,dict):continue
        value=(contract.get('parameter') or {}).get('value') or {}; kind=contract.get('type')
        owner=_tron_address(value.get('owner_address'));receiver=_tron_address(value.get('receiver_address') or value.get('to_address'))
        fields={'contract_type':kind,'contract_index':i, 'owner_address':owner,'receiver_address':receiver,
            'permission_id':contract.get('Permission_id',contract.get('permission_id',0)),
            'rpc_success':successful, 'fund_flow_inferred':False}
        if kind=='AccountPermissionUpdateContract':
            configurations=[]
            for role,configs in [('owner',[value.get('owner')]),('witness',[value.get('witness')]),('active',value.get('actives') or [])]:
                for conf in configs[:8]:
                    if not isinstance(conf,dict):continue
                    configurations.append({'role':role,'id':conf.get('id',0 if role=='owner' else 1 if role=='witness' else None),
                        'threshold':conf.get('threshold'), 'operations_bitmap':conf.get('operations'),
                        'keys':[{'address':_tron_address(k.get('address')),'weight':k.get('weight')} for k in (conf.get('keys') or [])[:5] if isinstance(k,dict)]})
            fields.update(configuration=configurations, scope='permission_update_request; not current permission state or UI proof')
            out['implementation_observations' if successful else 'construction_fingerprints'].append(
                _fact('tron_permission_update_v1', fields,[TRON_SOURCE,TRON_PERMISSIONS],subject_address=owner,
                      role='permission_configuration_owner',implementation='TRON weighted account permissions',
                      provenance_tier='HEURISTIC_ASSOCIATION',
                      implementation_identification_scope='native permission protocol role; not a branded application or binary hash'))
        elif kind in {'DelegateResourceContract','UnDelegateResourceContract'}:
            fields.update(resource=value.get('resource','BANDWIDTH'), balance_sun=value.get('balance'),
                lock=value.get('lock'),scope='resource_delegation; balance is delegated stake, not payment or sale price')
            out['construction_fingerprints'].append(_fact('tron_resource_delegation_v1', fields,[TRON_SOURCE]))
        else:
            fields['scope']='native_contract_role; not signing application'
            out['construction_fingerprints'].append(_fact('tron_native_contract_roles_v1',fields,[TRON_SOURCE]))
    return out
