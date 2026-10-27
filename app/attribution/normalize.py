"""Network-scoped identifiers. An identical hex address on two chains is distinct."""
import re
from app.utils.detect import _base58_decode, _base58check_version, is_bitcoin_address, is_dogecoin_address
from app.utils.ton_normalize import ton_canonical_address

EVM_CHAINS={'eth','bsc','polygon','arbitrum','optimism','avalanche'}
SUPPORTED_CHAINS=EVM_CHAINS|{'ton','tron','solana','btc','doge'}
CHAIN_IDS={'eth':1,'bsc':56,'polygon':137,'arbitrum':42161,'optimism':10,'avalanche':43114}
ALIASES={'ethereum':'eth','bitcoin':'btc','dogecoin':'doge','binance':'bsc','bnb':'bsc','avax':'avalanche','matic':'polygon'}

def normalize_chain(value):
    text=str(value or '').lower()
    return ALIASES.get(text,text)

def canonical_address(chain,value):
    chain=normalize_chain(chain)
    if not isinstance(value,str):return None
    value=value.strip()
    if chain in EVM_CHAINS:
        return value.lower() if re.fullmatch(r'0x[0-9a-fA-F]{40}',value) else None
    if chain=='ton':return ton_canonical_address(value)
    if chain=='btc':return (value.lower() if value.lower().startswith('bc1') else value) if is_bitcoin_address(value) else None
    if chain=='doge':return value if is_dogecoin_address(value) else None
    if chain=='tron':return value if value.startswith('T') and _base58check_version(value)==0x41 and len(_base58_decode(value) or b'')==25 else None
    if chain=='solana':return value if len(_base58_decode(value) or b'')==32 else None
    return None

def address_id(chain,value):
    chain=normalize_chain(chain);address=canonical_address(chain,value)
    return f'{chain}:{address}' if address else None
