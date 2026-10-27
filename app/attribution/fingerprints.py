"""Public structural fingerprints identify contract/transaction roles, not apps."""
import re
from app.utils.detect import _base58check_version
from app.utils.keccak import keccak_256

def evm_code_fingerprint(code):
    if not isinstance(code,str) or not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*',code):return {}
    raw=bytes.fromhex(code[2:])
    result={'kind':'smart_contract' if raw else 'no_runtime_code','code_hash':'0x'+keccak_256(raw).hex(),
        'hash_algorithm':'Keccak-256 runtime bytes','code_size':len(raw),'status':'CONFIRMED',
        'limitations':['No runtime code alone does not establish an EOA controller or mobile wallet.',
                      'Current code does not establish historical deployment or upgrade history.']}
    match=re.fullmatch(r'363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3',code[2:].lower())
    if match:result.update(kind='eip1167_minimal_proxy',implementation='0x'+match.group(1),specification='https://eips.ethereum.org/EIPS/eip-1167')
    if raw[:3]==bytes.fromhex('ef0100') and len(raw)==23:
        result.update(kind='eip7702_delegation_designator',implementation='0x'+raw[3:].hex(),specification='https://eips.ethereum.org/EIPS/eip-7702')
    return result

def utxo_address_type(chain,address):
    if chain=='btc':
        lower=address.lower()
        if lower.startswith('bc1p'):return 'witness_v1_or_later_address'
        if lower.startswith('bc1q'):return 'segwit_v0_address'
        if address.startswith('1'):return 'p2pkh_address'
        if address.startswith('3'):return 'p2sh_address'
    if chain=='doge':return 'p2sh_address' if _base58check_version(address)==0x16 else 'p2pkh_address'
    return 'unknown'

def evm_selector(raw):
    value=raw.get('input') or raw.get('data') or ''
    if isinstance(value,str) and re.match(r'^0x[0-9a-fA-F]{8}',value):return value[:10].lower()
    return None
