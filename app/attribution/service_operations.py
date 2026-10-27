"""Bind service movements to retained native/provider records, never a coin ticker.

These gates qualify evidence for service projection only. They do not modify
collectors, source transactions, financial totals, or operator labels.
"""
from __future__ import annotations
from decimal import Decimal, InvalidOperation, localcontext
from datetime import datetime,timezone
from .normalize import address_id, canonical_address, EVM_CHAINS
from app.utils.event_identity import canonical_hash

TRANSFER_TOPIC='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'

def _dict(value): return value if isinstance(value,dict) else {}

def _integer(value):
    if type(value) is int:return value
    if isinstance(value,str) and len(value)<=120:
        try:return int(value,16 if value.startswith('0x') else 10)
        except ValueError:pass
    return None

def _equal_amount(value,decimals,expected):
    value=_integer(value);decimals=_integer(decimals)
    if value is None or value<=0 or decimals is None or not 0<=decimals<=36:return False
    with localcontext() as ctx:
        ctx.prec=max(100,len(str(value))+decimals+2)
        return Decimal(value).scaleb(-decimals)==expected

def source_time_matches(operation,raw):
    """Bind temporal routes to retained wire time, never the DTO alone."""
    chain=operation.get('blockchain');provider=_dict(raw.get('provider_record'));stamp=None;millis=False
    if chain=='ton':
        native=_dict(raw.get('transaction'));transfer=_dict(raw.get('transfer'))
        stamp=transfer.get('transaction_now') if transfer else native.get('utime',native.get('now'))
    elif chain=='tron':
        stamp=provider.get('block_timestamp',provider.get('block_ts',provider.get('timestamp')));millis=True
    elif chain=='btc':stamp=_dict(provider.get('status')).get('block_time')
    elif chain in EVM_CHAINS:
        stamp=provider.get('timeStamp',provider.get('timestamp'))
        if _integer(stamp) is None:
            header=_dict(raw.get('rpc_block'));receipt=_dict(raw.get('receipt'))
            if canonical_hash(header.get('hash'))==canonical_hash(receipt.get('blockHash')) and canonical_hash(header.get('hash')) and _integer(header.get('number'))==_integer(receipt.get('blockNumber')):
                stamp=header.get('timestamp')
    stamp=_integer(stamp)
    if stamp is None or stamp<0:return False
    try:
        observed=datetime.fromisoformat(str(operation.get('timestamp')).replace('Z','+00:00'))
        native=datetime.fromtimestamp(stamp/1000 if millis else stamp,tz=timezone.utc)
        return observed.tzinfo is not None and observed==native
    except (ValueError,TypeError,OverflowError,OSError):return False

def raw_records(operation,data):
    proofs=data.get('_service_evidence_index') or {e.get('evidence_id'):e for e in data.get('evidence',[])}
    for ref in operation.get('evidence_ids',[]):
        pointer=_dict(_dict(proofs.get(ref)).get('facts')).get('raw_reference') or {}
        source=_dict(data.get('source_observations',{}).get(pointer.get('source_observation_id')))
        raw=_dict(source.get('raw'))
        if source.get('blockchain')==operation.get('blockchain') and raw:
            yield raw,source

def validate_account_operation(operation,data):
    """Return scoped verified proof kind, or None; native TON has its own gate."""
    chain=operation.get('blockchain');asset=operation.get('asset_key')
    if chain not in EVM_CHAINS|{'tron','ton'} or not canonical_hash(operation.get('transaction_hash')):return None
    if operation.get('success') is False:return None
    for field in ('from_key','to_key'):
        value=operation.get(field)
        if not isinstance(value,str) or not value.startswith(chain+':') or address_id(chain,value.split(':',1)[1])!=value:return None
    try:amount=Decimal(str(operation.get('amount_decimal')))
    except (InvalidOperation,ValueError):return None
    if not amount.is_finite() or amount<=0 or abs(amount.adjusted())>128:return None
    txhash=canonical_hash(operation['transaction_hash'])
    def endpoints(frm,to):return address_id(chain,frm)==operation['from_key'] and address_id(chain,to)==operation['to_key']
    for raw,source in raw_records(operation,data):
        if not source_time_matches(operation,raw):continue
        provider=_dict(raw.get('rpc_transaction') or raw.get('provider_record'))
        if any(container.get('simulated') is True or container.get('emulated') is True for container in (raw,provider)):continue
        if chain=='ton' and asset and asset.startswith('ton:token:'):
            transfer=_dict(raw.get('transfer'));meta=_dict(raw.get('metadata'))
            if canonical_hash(transfer.get('transaction_hash'))!=txhash or transfer.get('transaction_aborted') is not False:continue
            if not endpoints(transfer.get('source'),transfer.get('destination')):continue
            master=canonical_address('ton',transfer.get('jetton_master'))
            if not master or asset!='ton:token:'+master:continue
            token_infos=[meta,*[r for r in meta.get('token_info',[]) if isinstance(r,dict)]]
            decimals=next((_dict(row.get('extra')).get('decimals',row.get('decimals')) for row in token_infos
                if row.get('valid') is True and row.get('type')=='jetton_masters'),None)
            if _equal_amount(transfer.get('amount'),decimals,amount):return 'ton_jetton_transfer'
        elif chain=='tron':
            if canonical_hash(provider.get('transaction_id') or provider.get('txID') or provider.get('hash'))!=txhash:continue
            if provider.get('revert') is True or provider.get('confirmed') is False:continue
            ok=provider.get('contractRet')=='SUCCESS' or provider.get('finalResult')=='SUCCESS'
            ret=provider.get('ret')
            ok=ok or isinstance(ret,list) and bool(ret) and all(_dict(r).get('contractRet')=='SUCCESS' for r in ret)
            if not ok:continue
            if asset=='tron:native':
                contract=_dict(provider.get('contractData'))
                if provider.get('contractType')==1 and endpoints(provider.get('ownerAddress') or contract.get('owner_address'),provider.get('toAddress') or contract.get('to_address')) and _equal_amount(contract.get('amount',provider.get('amount')),6,amount):return 'tron_native_transfer'
                from .program_transaction_fingerprints import _tron_address
                for wire in _dict(provider.get('raw_data')).get('contract',[])[:32]:
                    if not isinstance(wire,dict) or wire.get('type')!='TransferContract':continue
                    value=_dict(_dict(wire.get('parameter')).get('value'))
                    if endpoints(_tron_address(value.get('owner_address')),_tron_address(value.get('to_address'))) and _equal_amount(value.get('amount'),6,amount):return 'tron_native_transfer'
            elif asset and asset.startswith('tron:token:'):
                token=_dict(provider.get('tokenInfo') or provider.get('token_info'))
                master=canonical_address('tron',provider.get('contract_address') or token.get('address') or token.get('tokenId'))
                decimals=token.get('tokenDecimal',token.get('decimals'))
                if asset!='tron:token:'+str(master) or str(provider.get('event_type') or provider.get('type')).lower()!='transfer':continue
                if endpoints(provider.get('from_address') or provider.get('from'),provider.get('to_address') or provider.get('to')) and _equal_amount(provider.get('quant',provider.get('value')),decimals,amount):return 'tron_trc20_transfer'
        elif chain in EVM_CHAINS:
            receipt=_dict(raw.get('receipt') or raw.get('transaction_receipt') or raw.get('rpc_receipt'))
            receipt_ok=canonical_hash(receipt.get('transactionHash'))==txhash and _integer(receipt.get('status'))==1
            provider_ok=canonical_hash(provider.get('hash') or provider.get('transactionHash'))==txhash
            if asset==chain+':native' and provider_ok and endpoints(provider.get('from'),provider.get('to')):
                success=receipt_ok or provider.get('isError')=='0' or provider.get('txreceipt_status')=='1'
                # Contract internal-value transfers need their own trace proof;
                # an outer transaction's amount cannot validate an internal DTO.
                if success and not str(raw.get('type','')).startswith('internal') and provider.get('traceId') is None and _equal_amount(provider.get('value'),18,amount):return 'evm_native_transfer'
            if not asset or not asset.startswith(chain+':token:'):continue
            master=canonical_address(chain,asset.split(':token:',1)[1]);decimals=raw.get('decimals',raw.get('token_decimal'))
            if provider_ok:
                token=canonical_address(chain,provider.get('contractAddress') or provider.get('address'))
                decimals=provider.get('tokenDecimal',decimals)
                # A successful retained receipt or explicit provider execution
                # status is required; an indexed token row alone is not finality.
                success=receipt_ok or provider.get('isError')=='0' or provider.get('txreceipt_status')=='1'
                if success and token==master and endpoints(provider.get('from'),provider.get('to')) and _equal_amount(provider.get('value'),decimals,amount):return 'evm_token_transfer'
            if receipt_ok:
                for log in receipt.get('logs',[]):
                    if not isinstance(log,dict) or log.get('removed') is True:continue
                    topics=log.get('topics') or []
                    if len(topics)!=3 or str(topics[0]).lower()!=TRANSFER_TOPIC:continue
                    if canonical_address(chain,log.get('address'))!=master:continue
                    if canonical_hash(log.get('transactionHash'))!=txhash:continue
                    frm='0x'+str(topics[1])[-40:];to='0x'+str(topics[2])[-40:]
                    if endpoints(frm,to) and _equal_amount(log.get('data'),decimals,amount):return 'evm_erc20_transfer_log'
    return None

def validate_utxo_observation(item,data):
    """Validate actual UTXO sets; never allocate an input to any chosen output."""
    if item.get('blockchain')!='btc' or item.get('success') is not True:return False
    digest=canonical_hash(item.get('transaction_hash'))
    if not digest:return False
    for raw,source in raw_records(item,data):
        native=_dict(raw.get('provider_record'))
        if not source_time_matches(item,raw):continue
        if canonical_hash(native.get('txid'))!=digest or _dict(native.get('status')).get('confirmed') is not True:continue
        ins=native.get('vin');outs=native.get('vout')
        if not isinstance(ins,list) or not isinstance(outs,list):continue
        expected_in=[(address_id('btc',_dict(row.get('prevout')).get('scriptpubkey_address')),canonical_hash(row.get('txid')),row.get('vout'),_dict(row.get('prevout')).get('value')) for row in ins if isinstance(row,dict)]
        expected_out=[(address_id('btc',row.get('scriptpubkey_address')),index,row.get('value')) for index,row in enumerate(outs) if isinstance(row,dict)]
        actual_in=[(r.get('address_key'),canonical_hash(r.get('prev_tx_hash')),r.get('prev_index'),Decimal(str(r['value_decimal'])).scaleb(8) if r.get('value_decimal') is not None else None) for r in item.get('inputs',[])]
        actual_out=[(r.get('address_key'),r.get('index'),Decimal(str(r['value_decimal'])).scaleb(8) if r.get('value_decimal') is not None else None) for r in item.get('outputs',[])]
        keys_in=list(dict.fromkeys(r[0] for r in expected_in if r[0]));keys_out=list(dict.fromkeys(r[0] for r in expected_out if r[0]))
        if item.get('input_keys')!=keys_in or item.get('output_keys')!=keys_out:continue
        if expected_in==actual_in and expected_out==actual_out:return True
    return False

def ton_native_execution(native):
    """Account execution only; absence of an explicit failure is not success."""
    if not isinstance(native,dict):return None
    desc=_dict(native.get('description'))
    phases=[native.get(k) for k in ('compute_phase','action_phase')]+[desc.get(k) for k in ('compute_ph','action')]
    if native.get('success') is False or native.get('aborted') is True or desc.get('aborted') is True:return False
    if any(isinstance(p,dict) and (p.get('success') is False or p.get('no_funds') is True or p.get('valid') is False) for p in phases):return False
    if native.get('success') is True:return True
    compute=_dict(desc.get('compute_ph'));action=_dict(desc.get('action'))
    if desc.get('aborted') is False and compute.get('success') is True and action.get('success') is True:return True
    return None

def repair_ton_native_observations(report,payload,data,*,max_native_records=512,max_seconds=2.0):
    """Use the existing physical-message normalizer on exact retained accounts.

    A merged DTO may cite the other account's TX. Shallow normalization views
    correct that citation using the actual native hash, never altering the DTO.
    Raw is pooled once/native observation, not re-sanitized for every message.
    """
    import hashlib,json,time
    from .inference import _ton_projections
    from app.utils.security import safe_public_url
    start=time.monotonic();ops={};proofs={};pool={};seen=set();states={};truncated=False
    target=address_id('ton',report.target_address)
    for tx in report.transactions:
        if tx.chain!='ton':continue
        sources=[p for p in tx.provenance if isinstance(p,dict) and isinstance(_dict(p.get('raw')).get('transaction'),dict)]
        if not sources:sources=[{'source':tx.source,'url':tx.url,'raw':tx.raw}]
        for observation in sources:
            raw=_dict(observation.get('raw'));native=_dict(raw.get('transaction'))
            digest=canonical_hash(native.get('hash'));account=canonical_address('ton',_dict(native.get('account')).get('address') if isinstance(native.get('account'),dict) else native.get('account'))
            source=observation.get('source');identity=(digest,source,account)
            if not digest or not account or not source or identity in seen:continue
            if len(seen)>=max_native_records or time.monotonic()-start>max_seconds:truncated=True;break
            seen.add(identity)
            if raw.get('emulated') is True or native.get('emulated') is True or raw.get('simulated') is True or native.get('simulated') is True:continue
            success=ton_native_execution(native)
            context=None if address_id('ton',account)==target else address_id('ton',account)
            link='https://tonviewer.com/transaction/'+digest
            # Both URLs are retained: the exact account TX link and the original
            # DTO observation link, which may have cited the recipient-side TX.
            source_id='service:native-source:'+hashlib.sha256(json.dumps([digest,source,context,raw],sort_keys=True,default=str).encode()).hexdigest()
            pool[source_id]={'source':source,'url':link,'blockchain':'ton','transaction_hash':digest,'context_key':context,
                'original_observation_url':safe_public_url(observation.get('url')),'original_dto_transaction_hash':tx.tx_hash,'raw':raw}
            if success is not True:
                messages=[native.get('in_msg'),*(native.get('out_msgs') or [])]
                for message in messages:
                    message_hash=canonical_hash(_dict(message).get('hash'))
                    if not message_hash:continue
                    ref='service:native-state:'+hashlib.sha256(json.dumps([digest,source,context,message_hash]).encode()).hexdigest()
                    proofs[ref]={'evidence_id':ref,'source':source,'url':link,'blockchain':'ton','transaction_hash':digest,
                        'relation':'service_native_account_observation','facts':{'account_key':address_id('ton',account),'message_hash':message_hash,
                            'success':success,'raw_reference':{'context_key':context,'source_observation_id':source_id}}}
                    states.setdefault((address_id('ton',account),message_hash),[]).append((source_id,ref))
                continue
            view=tx.model_copy(update={'tx_hash':digest,'raw':raw,'source':source,'url':link,'success':True})
            for op in _ton_projections(view):
                if not op.get('message_hash'):continue
                ref='service:native-operation:'+hashlib.sha256(json.dumps([op['operation_id'],digest,source,context],sort_keys=True).encode()).hexdigest()
                priority=op.pop('_priority',0)
                op.update(source_family=source,source_url=link,evidence_ids=[ref],success=True)
                pointer={'context_key':context,'event_id':op['operation_id'],'source_observation_id':source_id}
                proofs[ref]={'evidence_id':ref,'source':source,'url':link,'blockchain':'ton','transaction_hash':digest,
                    'relation':'inference_operation_observation','facts':{**op,'execution_basis':'retained_native_execution_phases','raw_reference':pointer}}
                if op['operation_id'] not in ops or priority>ops[op['operation_id']][0]:ops[op['operation_id']]=(priority,op)
                states.setdefault((address_id('ton',account),op['message_hash']),[]).append((source_id,ref))
        if truncated:break
    data['_service_native_state_index']=states
    return {'operations':[row for _,row in ops.values()],'evidence':list(proofs.values()),'source_observations':pool,
        'coverage':{'native_records_examined':len(seen),'physical_operations':len(ops),'status':'TRUNCATED' if truncated else 'PARTIAL',
            'history_complete':False,'max_seconds':max_seconds,'max_native_records':max_native_records,'elapsed_seconds':time.monotonic()-start,
            'source_dtos_modified':False,'new_http_requests':0,'normalizer':'existing_inference._ton_projections'}}

def native_account_state(operation,address_key,data):
    """Exact account-side state; a sender/recipient TX is not interchangeable."""
    if operation.get('asset_key')!='ton:native' or not operation.get('message_hash'):return None
    entries=(data.get('_service_native_state_index') or {}).get((address_key,operation['message_hash']),[])
    results=[]
    for source_id,ref in entries:
        source=_dict(data.get('source_observations',{}).get(source_id));native=_dict(_dict(source.get('raw')).get('transaction'))
        execution=ton_native_execution(native)
        stamp=native.get('utime',native.get('now'));hash_value=canonical_hash(native.get('hash'))
        if not hash_value or _integer(stamp) is None:continue
        outputs=native.get('out_msgs')
        if not isinstance(outputs,list):continue
        messages=[('in',native.get('in_msg'))]+[('out',m) for m in outputs if isinstance(m,dict)]
        matched=next(((direction,m) for direction,m in messages if isinstance(m,dict) and canonical_hash(m.get('hash'))==operation['message_hash']),None)
        if not matched:continue
        direction,message=matched
        def party(value):return address_id('ton',value.get('address') if isinstance(value,dict) else value)
        if party(message.get('source'))!=operation['from_key'] or party(message.get('destination'))!=operation['to_key']:continue
        if not _equal_amount(message.get('value'),9,Decimal(operation['amount_decimal'])):continue
        end=_integer(native.get('end_balance',_dict(native.get('account_state_after')).get('balance')))
        fees=_integer(native.get('total_fees'));outs=native.get('out_msgs')
        if any(value is not None and value<0 for value in (end,fees)):continue
        complete=isinstance(outs,list) and all(isinstance(m,dict) and all(_integer(m.get(k)) is not None and _integer(m.get(k))>=0 for k in ('value','fwd_fee','ihr_fee')) for m in outs)
        values=sum(_integer(m['value']) for m in outs) if complete else None
        forwarded=sum(_integer(m['fwd_fee']) for m in outs) if complete else None
        ihr=sum(_integer(m['ihr_fee']) for m in outs) if complete else None
        results.append({'account_key':address_key,'transaction_hash':hash_value,'message_hash':operation['message_hash'],
            'execution_status':'SUCCESS' if execution is True else 'FAILED' if execution is False else 'UNKNOWN',
            'message_direction_at_account':direction,'lt':str(native.get('lt')) if native.get('lt') is not None else None,
            'prev_transaction_hash':canonical_hash(native.get('prev_trans_hash')) or None,
            'prev_lt':str(native.get('prev_trans_lt')) if native.get('prev_trans_lt') is not None else None,
            'timestamp':datetime.fromtimestamp(_integer(stamp),timezone.utc).isoformat(),'end_balance_base_units':str(end) if end is not None else None,
            'total_fees_base_units':str(fees) if fees is not None else None,'outgoing_value_base_units':str(values) if values is not None else None,
            'outgoing_forward_fees_base_units':str(forwarded) if forwarded is not None else None,'outgoing_ihr_fees_base_units':str(ihr) if ihr is not None else None,
            'outgoing_message_count':len(outs) if isinstance(outs,list) else None,'balance_inputs_complete':complete and fees is not None and end is not None,
            'raw_reference':{'source_observation_id':source_id,'context_key':source.get('context_key')},'source_url':source.get('url'),
            'source':source.get('source'),'evidence_ids':[ref]})
    if not results:return None
    result=max(results,key=lambda r:(r['execution_status']=='FAILED',r['balance_inputs_complete']))
    result['corroborating_evidence_ids']=list(dict.fromkeys(ref for row in results if row['transaction_hash']==result['transaction_hash'] for ref in row['evidence_ids']))
    return result
