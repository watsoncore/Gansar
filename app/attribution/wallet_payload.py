"""Read public TON request layouts; parsing is not signature verification.

Only the published contract layout, never an explorer label, selects a decoder.
Signatures/public keys are not retained by these observations. Unsupported or
truncated layouts stay unavailable rather than being guessed from random bytes.
"""
from app.ton_nft.protocol import decode_boc

V5_OPS={0x7369676e:'external_signed',0x73696e74:'internal_signed',0x6578746e:'extension_authorized'}
TG_OPS={0x63896e74:'internal_single',0x63896e75:'external_single',0x73896e74:'internal_batch',
        0x73896e75:'external_batch',0xfbba99c7:'internal_key_rotation',0xfbba99c8:'external_key_rotation'}
TOKEN_OPS={0x0f8a7ea5:'jetton_transfer_request',0x5fcc3d14:'nft_transfer_request',
           0x7362d09c:'jetton_transfer_notification',0x05138d91:'nft_ownership_assigned',
           0x595f07bc:'jetton_burn_request',0xd53276db:'excesses'}

class Bits:
    def __init__(self,cell):self.cell=cell;self.pos=0
    def uint(self,n):
        if n<0 or self.pos+n>self.cell.bit_length:raise ValueError('truncated published request layout')
        start=self.pos;self.pos+=n
        shift=len(self.cell.data)*8-self.pos
        return (int.from_bytes(self.cell.data,'big')>>shift)&((1<<n)-1)
    def skip(self,n):self.uint(n)

def body_boc(message):
    if not isinstance(message,dict):return None
    content=message.get('message_content') or message.get('msg_data') or {}
    value=message.get('raw_body') or message.get('body') or (content.get('body') if isinstance(content,dict) else None)
    return value if isinstance(value,str) and len(value)<=128_000 else None

def decode_token_header(value):
    cell=decode_boc(value);reader=Bits(cell);opcode=reader.uint(32)
    if opcode not in TOKEN_OPS:return {'opcode':f'0x{opcode:08x}','kind':'unrecognized_payload_header'}
    query=reader.uint(64)
    pending=[cell];seen=set();mywallet_fee=False;exact_cells=set()
    while pending and len(seen)<512:
        part=pending.pop()
        if id(part) in seen:continue
        seen.add(id(part))
        if part.bit_length==32 and not part.refs:
            exact_cells.add('0x'+part.data.hex())
            if part.data==bytes.fromhex('4d238543'):mywallet_fee=True
        pending.extend(part.refs)
    return {'opcode':f'0x{opcode:08x}','kind':TOKEN_OPS[opcode],'query_id':str(query),
            'query_id_prefix':f'0x{query>>32:08x}',
            'tonkeeper_query_namespace':query>>32==0x546de4ef,
            'mywallet_fee_payload_present':mywallet_fee,'nested_payload_cells_examined':len(seen),
            'nested_exact_cell_opcodes':sorted(exact_cells),
            'signature_verified':False,'operation_execution_not_inferred':True}

def decode_wallet_body(value,version):
    """Extract V1–V5/WalletTg headers with a trusted contract-version hint.

    Caller must associate the body with a request TO that account. Current code
    alone cannot prove the code used by every historical transaction.
    """
    cell=decode_boc(value);reader=Bits(cell);version=str(version or '').upper()
    out={'wallet_version_context':version,'signature_verified':False,'body_bits':cell.bit_length,
         'historical_code_verified':False,'send_modes':[]}
    if version.startswith(('V1','V2','V3','V4')):
        reader.skip(512)
        out['authorization']='signature_prefix';out['auth_mode']='signature_prefix'
        if version.startswith(('V3','V4')):
            out.update(wallet_id=reader.uint(32),valid_until=reader.uint(32),seqno=reader.uint(32))
        else:
            out['seqno']=reader.uint(32)
            if version.startswith('V2'):out['valid_until']=reader.uint(32)
        if version.startswith('V4'):
            out['wallet_operation']=reader.uint(8)
            if out['wallet_operation']!=0:
                out['layout']='v4_plugin_request';return out
        modes=len(cell.refs)
        if modes>4 or cell.bit_length-reader.pos!=modes*8:raise ValueError('request bits/references do not match V1–V4 transfer layout')
        out['send_modes']=[reader.uint(8) for _ in range(modes)]
        out.update(layout='standard_signed_transfer',message_count=modes)
    elif version=='V5R1':
        opcode=reader.uint(32)
        if opcode not in V5_OPS:raise ValueError('unsupported V5R1 authorization opcode')
        out.update(opcode=f'0x{opcode:08x}',authorization=V5_OPS[opcode],layout='v5r1_request')
        out['auth_mode']=V5_OPS[opcode]
        if opcode==0x6578746e:out['query_id']=str(reader.uint(64))
        else:
            out.update(wallet_id=reader.uint(32),valid_until=reader.uint(32),seqno=reader.uint(32))
            if cell.bit_length-reader.pos<514:raise ValueError('V5 signed request lacks tail signature')
        has_list=reader.uint(1);has_extensions=reader.uint(1)
        out['has_extension_actions']=bool(has_extensions)
        if has_list:
            if not cell.refs:raise ValueError('V5 action list reference missing')
            node=cell.refs[0];modes=[]
            while node.bit_length or node.refs:
                if len(modes)>=255:raise ValueError('V5 action list exceeds protocol maximum')
                sub=Bits(node)
                if sub.uint(32)!=0x0ec3c86d or len(node.refs)!=2:raise ValueError('unsupported V5 out action')
                modes.append(sub.uint(8))
                if node.bit_length!=40:raise ValueError('unexpected V5 out action payload')
                node=node.refs[0]
            out['send_modes']=list(reversed(modes));out['message_count']=len(modes)
        else:out['message_count']=0
    elif version=='WALLETTG':
        reader.skip(512);opcode=reader.uint(32)
        if opcode not in TG_OPS:raise ValueError('unsupported WalletTg request opcode')
        out.update(opcode=f'0x{opcode:08x}',authorization=TG_OPS[opcode],layout='wallet_tg_request',
                   wallet_id=reader.uint(32),valid_until=reader.uint(32),seqno=reader.uint(32))
        out['auth_mode']=TG_OPS[opcode]
        if 'single' in out['authorization']:out['send_modes']=[reader.uint(8)];out['message_count']=1
        out['config_indirection']=-123
    else:raise ValueError('no decoder for the observed contract implementation')
    return out
