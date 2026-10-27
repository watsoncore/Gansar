"""Explainable inference over collected evidence; no label/owner propagation.

Neighbor observations are scoped context and never enter target financials.
Physical operations, dependency groups, qualified assets and missing fields
remain distinct. Heuristics cannot confirm address control or signing software.
"""
from __future__ import annotations
from collections import Counter,defaultdict
from datetime import datetime,timezone
from decimal import Decimal,InvalidOperation,localcontext
import hashlib,json,time

from app.models.report import AddressReport,Transaction
from app.utils.event_identity import event_identity,canonical_hash,transaction_success
from app.utils.security import safe_public_url,sanitize_observation
from app.utils.ton_normalize import ton_canonical_address,ton_datetime
from .normalize import address_id,canonical_address,EVM_CHAINS
from .program_transaction_fingerprints import is_tron_non_monetary

VERSION='2026-10-20.1'
LIMITS=[
    'Observed paths show possible chronological activity, not allocation of fungible funds or common ownership.',
    'Shared funding, protocol, factory, paymaster, construction or behavior does not authenticate a service controller or signing application.',
    'Provider histories and the expansion frontier are partial. Unobserved alternatives may invalidate a role hypothesis.',
    'Confidence categories are uncalibrated evidence categories, not probabilities; dependent observations are grouped.',
]
NATIVE={'btc':{'BTC'},'doge':{'DOGE'},'eth':{'ETH'},'bsc':{'BNB'},'polygon':{'POL','MATIC'},
        'arbitrum':{'ETH'},'optimism':{'ETH'},'avalanche':{'AVAX'},'tron':{'TRX'},'solana':{'SOL'},'ton':{'TON'}}

def identifier(kind,value):
    return 'inference:'+kind+':'+hashlib.sha256(json.dumps(value,sort_keys=True,default=str,separators=(',',':')).encode()).hexdigest()

def _decimal(value):
    try:
        if len(str(value))>512:return None
        out=Decimal(str(value))
        return out if out.is_finite() and abs(out.adjusted())<=512 else None
    except (InvalidOperation,ValueError,TypeError):return None

def _timestamp(value):
    if isinstance(value,datetime):return value.isoformat()
    if isinstance(value,str):
        try:
            dt=datetime.fromisoformat(value.replace('Z','+00:00'))
            return dt.isoformat() if dt.tzinfo else None
        except ValueError:return None
    return None

def _mapping(value):return value if isinstance(value,dict) else {}

def _success(tx):
    value=transaction_success(tx)
    if value is not None:return value
    raw=tx.raw or {};provider=raw.get('provider_record') or {}
    if not isinstance(provider,dict):return None
    if tx.chain=='tron' and provider.get('txID')==tx.tx_hash:
        ret=provider.get('ret') or []
        return all(r.get('contractRet')=='SUCCESS' for r in ret) if isinstance(ret,list) and ret and all(isinstance(r,dict) for r in ret) else None
    receipt=raw.get('receipt') or raw.get('transaction_receipt') or raw.get('rpc_receipt') or {}
    if tx.chain in EVM_CHAINS and isinstance(receipt,dict) and str(receipt.get('transactionHash')).lower()==tx.tx_hash.lower():
        if receipt.get('status') in (1,'0x1'):return True
        if receipt.get('status') in (0,'0x0'):return False
    if tx.chain in EVM_CHAINS and str(provider.get('hash','')).lower()==tx.tx_hash.lower():
        if str(provider.get('isError',''))=='1' or str(provider.get('txreceipt_status',''))=='0':return False
        if str(provider.get('isError',''))=='0' or str(provider.get('txreceipt_status',''))=='1':return True
    if tx.chain in {'btc','doge'}:
        native=provider.get('transaction') or provider
        status=provider.get('status') or {}
        if isinstance(native,dict) and ((isinstance(status,dict) and status.get('confirmed') is True) or native.get('block_id') is not None):return True
    native=provider.get('transaction') or {};signatures=native.get('signatures') if isinstance(native,dict) else None
    if tx.chain=='solana' and isinstance(signatures,list) and signatures and signatures[0]==tx.tx_hash:
        meta=_mapping(provider.get('meta'))
        if 'err' in meta:return meta['err'] is None
    return None

def _asset(tx):
    raw=tx.raw or {};symbol=str(tx.asset or '').upper()
    provider=raw.get('provider_record') or {}
    if tx.chain=='tron' and isinstance(provider,dict):
        if provider.get('hash')==tx.tx_hash and provider.get('contractType')==1 and raw.get('native_contract_type')=='TransferContract':
            # Tronscan labels native TRX with tokenInfo/tokenType=trc10.
            # Contract type 1 is the native TransferContract wire operation.
            return 'tron:native'
        native=provider.get('raw_data') or {};contracts=native.get('contract') if isinstance(native,dict) else None
        if isinstance(contracts,list) and any(isinstance(c,dict) and c.get('type')=='TransferAssetContract' for c in contracts):
            # TRC10 asset_name is an asset ID, not a native TRX amount. Keep
            # its unit unresolved unless the collector retained exact metadata.
            return None
    token=raw.get('token_contract') or raw.get('jetton_master') or raw.get('contract')
    token_marker=token or raw.get('token_info') or raw.get('asset_type') in {'jetton','trc10','trc20','erc20','bep20','token'}
    if symbol in NATIVE.get(tx.chain,set()) and not token_marker:
        return tx.chain+':native'
    contract=raw.get('token_contract') or raw.get('jetton_master') or raw.get('contract') or _mapping(raw.get('token_info')).get('address')
    if isinstance(contract,dict):contract=contract.get('address')
    canonical=canonical_address(tx.chain,contract)
    if raw.get('asset_type') in {'erc721','erc1155'} or raw.get('type')=='nft_transfer':
        token_id=raw.get('token_id')
        return tx.chain+':nft:'+canonical+':'+str(token_id) if canonical and token_id is not None and str(token_id)!='' else None
    return tx.chain+':token:'+canonical if canonical else None

def _amount(tx):
    if tx.amount_decimal is not None:return str(tx.amount_decimal),'normalized_decimal'
    raw=tx.raw or {};provider=raw.get('provider_record') or {}
    if tx.chain in EVM_CHAINS and isinstance(provider,dict) and str(provider.get('hash','')).lower()==tx.tx_hash.lower() and _asset(tx)==tx.chain+':native':
        value=provider.get('value')
        if isinstance(value,str) and value.isdecimal() and len(value)<=100:value=int(value)
        if type(value) is int:
            from decimal import localcontext
            with localcontext() as ctx:
                ctx.prec=max(80,len(str(abs(value)))+20)
                return str(Decimal(value).scaleb(-18)),'native_base_units'
    if tx.chain=='tron' and isinstance(provider,dict) and provider.get('hash')==tx.tx_hash and provider.get('contractType')==1:
        amount=_mapping(provider.get('contractData')).get('amount',provider.get('amount'))
        if isinstance(amount,str) and amount.isdecimal() and len(amount)<=100:amount=int(amount)
        if type(amount) is int:return str(Decimal(amount)/10**6),'native_base_units'
    if isinstance(provider,dict) and tx.chain=='tron' and provider.get('txID')==tx.tx_hash:
        contracts=_mapping(provider.get('raw_data')).get('contract')
        for contract in contracts if isinstance(contracts,list) else []:
            if isinstance(contract,dict) and contract.get('type')=='TransferContract':
                value=_mapping(_mapping(contract.get('parameter')).get('value'))
                amount=value.get('amount')
                if type(amount) is int:return str(Decimal(amount)/10**6),'native_base_units'
    if tx.chain=='tron' and isinstance(provider,dict) and str(raw.get('type'))=='trc20_transfer':
        token=_mapping(raw.get('token_info'));precision=token.get('decimals');value=provider.get('value')
        if isinstance(precision,str) and precision.isdecimal():precision=int(precision)
        if isinstance(value,str) and value.isdecimal() and len(value)<=100:value=int(value)
        if type(precision) is int and 0<=precision<=36 and type(value) is int:
            from decimal import localcontext
            with localcontext() as ctx:
                ctx.prec=max(80,len(str(abs(value)))+precision+2)
                return str(Decimal(value).scaleb(-precision)),'native_base_units'
    value=_decimal(tx.amount)
    return (str(value),'display_float') if value is not None else (None,'unavailable')

def context_for(report):
    existing=(report.attribution_intelligence or {}).get('investigation_context') or {}
    targets=sorted({address_id(c,report.target_address) for c in report.detected_chains if address_id(c,report.target_address)})
    if existing.get('schema_version')=='1.0' and existing.get('target_keys')==targets:return existing
    return {'schema_version':'1.0','target_keys':targets,'histories':{},'frontier':[], 'journal':[],
        'sessions':0,'total_http_requests':0,'coverage':{'status':'PARTIAL','history_complete':False}}

def journal(context,action,*,subject=None,evidence_ids=(),decision='',result=None,cost=None,missing_data=(),timestamp=None,confidence_transition=None):
    basis=[action,subject,list(evidence_ids),decision,result]
    key=identifier('journal',basis)
    rows=context.setdefault('journal',[])
    if any(row.get('journal_id')==key for row in rows):return
    if len(rows)>=2000:
        context['journal_entries_omitted']=context.get('journal_entries_omitted',0)+1;return
    rows.append({'journal_id':key,'trigger':action,'timestamp':timestamp or datetime.now(timezone.utc).isoformat(),
        'subject':subject,'evidence_ids':list(evidence_ids),'source':'existing_gansar_investigation',
        'decision':decision,'result':result,'cost':cost or {'http_requests':0},'missing_data':list(missing_data),
        'confidence_transition':confidence_transition})

def _ton_projections(tx):
    raw=tx.raw or {};native=raw.get('transaction')
    full_native=isinstance(native,dict)
    if not isinstance(native,dict):
        message=raw.get('message')
        if not isinstance(message,dict):return []
        # Same outgoing message also occurs in the full parent transaction.
        # Use the identical physical identity so projections cannot inflate it.
        native={'out_msgs':[message],'account':tx.from_address}
    account=native.get('account') or raw.get('account')
    account=ton_canonical_address(account.get('address') if isinstance(account,dict) else account)
    result=[]
    outgoing=native.get('out_msgs');outgoing=outgoing if isinstance(outgoing,list) else []
    for direction,msgs in [('in',[native.get('in_msg')]),('out',outgoing)]:
        for msg in msgs[:256]:
            if not isinstance(msg,dict):continue
            def addr(v):return ton_canonical_address(v.get('address') if isinstance(v,dict) else v)
            frm,to=addr(msg.get('source')),addr(msg.get('destination'))
            if not frm or not to:continue
            amount=msg.get('value');amount=amount.get('value') if isinstance(amount,dict) else amount
            if isinstance(amount,str) and amount.isdecimal():amount=int(amount)
            if type(amount) is not int or amount<=0:continue
            digest=canonical_hash(msg.get('hash') or msg.get('msg_hash'))
            identity='ton:message:'+digest if digest else identifier('unhashed_ton_message',[canonical_hash(tx.tx_hash) or tx.tx_hash,direction,msg])
            stamp=ton_datetime(native.get('utime') or native.get('now')) or tx.timestamp
            success=native.get('success') if type(native.get('success')) is bool else _success(tx)
            priority=(3 if direction=='out' and account==frm else 2 if direction=='in' and account==to else 1)+(1 if full_native else 0)
            with localcontext() as precision:
                precision.prec=max(80,len(str(amount))+12)
                exact_amount=format(Decimal(amount).scaleb(-9),'f')
                if '.' in exact_amount:exact_amount=exact_amount.rstrip('0').rstrip('.')
            # TEP-74 requests attach native value for contract execution; it is
            # neither the requested jetton amount nor an ordinary native payout.
            opcode=msg.get('op_code') if msg.get('op_code') is not None else msg.get('opcode')
            purpose='jetton_transfer_request' if opcode in (0x0f8a7ea5,'0x0f8a7ea5','0xf8a7ea5','260734629') else None
            result.append({'operation_id':identity,'blockchain':'ton','transaction_hash':canonical_hash(tx.tx_hash) or tx.tx_hash,
                'from_key':address_id('ton',frm),'to_key':address_id('ton',to),'asset_key':'ton:native',
                'amount_decimal':exact_amount,'amount_precision':'native_base_units',
                'timestamp':_timestamp(stamp),'success':success,'kind':'native_internal_message',
                'message_hash':digest or None,**({'native_value_purpose':purpose} if purpose else {}),'dependency_group':'ton:tx:'+(canonical_hash(tx.tx_hash) or tx.tx_hash),
                'scope':'provider-observed internal message; sender emission is not independent recipient credit verification',
                '_priority':priority})
    return result

def _utxo(tx):
    raw=tx.raw or {};provider=raw.get('provider_record') or raw
    if not isinstance(provider,dict):return None
    native=provider.get('transaction') or provider
    if not isinstance(native,dict):return None
    native_hash=native.get('txid') or native.get('hash')
    if native_hash and str(native_hash).lower()!=tx.tx_hash.lower():return None
    wire_inputs=provider.get('vin') or provider.get('inputs') or tx.inputs
    wire_outputs=provider.get('vout') or provider.get('outputs') or tx.outputs
    if not isinstance(wire_inputs,list) or not isinstance(wire_outputs,list):return None
    def part(row,index,is_input):
        prev=row.get('prevout') or row
        if not isinstance(prev,dict):prev={}
        address=prev.get('scriptpubkey_address') or prev.get('recipient') or prev.get('address')
        value=prev.get('value');exact=type(value) is int and ('prevout' in row or 'recipient' in prev or 'scriptpubkey' in prev)
        output_index=row.get('vout',row.get('index',row.get('output_index'))) if is_input else row.get('n',row.get('index',index))
        output_index=output_index if type(output_index) is int and 0<=output_index<2**32 else None
        return {'address_key':address_id(tx.chain,address),'value_decimal':str(Decimal(value)/10**8) if exact else None,
            'script':prev.get('scriptpubkey') or prev.get('script_hex'),
            **({'prev_tx_hash':row.get('txid') or row.get('transaction_hash') or row.get('prev_hash'),
                'prev_index':output_index} if is_input else {'index':output_index})}
    inputs=[part(row,i,True) for i,row in enumerate(wire_inputs[:2000]) if isinstance(row,dict)]
    outputs=[part(row,i,False) for i,row in enumerate(wire_outputs[:2000]) if isinstance(row,dict)]
    return {'transaction_key':tx.chain+':tx:'+tx.tx_hash,'transaction_hash':tx.tx_hash,'blockchain':tx.chain,
        'input_keys':list(dict.fromkeys(p['address_key'] for p in inputs if p['address_key'])),
        'output_keys':list(dict.fromkeys(p['address_key'] for p in outputs if p['address_key'])),
        'inputs':inputs,'outputs':outputs,'timestamp':_timestamp(tx.timestamp),'success':_success(tx),
        'dependency_group':tx.chain+':tx:'+tx.tx_hash,'allocation':'UNKNOWN','ownership':'UNKNOWN'}

def build_inference_data(report,payload,*,max_transactions=20000,max_seconds=2.5):
    started=time.monotonic();observations={};utxo={};proofs={};counts=Counter();addresses=dict(payload.get('addresses') or {})
    technical=dict(payload.get('transaction_fingerprints') or {});context=context_for(report)
    sources=[(report,None)]
    for key,value in list(context.get('histories',{}).items())[:12]:
        try:
            neighbor=AddressReport.model_validate(value['report'])
            if address_id(key.split(':',1)[0],neighbor.target_address)!=key:continue
        except (ValueError,TypeError,KeyError):counts['invalid_context_histories']+=1;continue
        sources.append((neighbor,key))
        info=neighbor.attribution_intelligence or {}
        for address,record in info.get('addresses',{}).items():addresses.setdefault(address,record)
        technical.update(info.get('transaction_fingerprints') or {})
        for proof in info.get('evidence',[]):
            if proof.get('evidence_id'):proofs[proof['evidence_id']]=proof
    truncated=False;seen=0;source_pool={};raw_references={}
    def raw_reference(tx,context_key):
        # One source DTO can project many physical messages. Its immutable raw
        # needs the same full redaction/digest only once within this invocation.
        key=(id(tx),context_key)
        if key in raw_references:return dict(raw_references[key])
        raw=sanitize_observation(tx.raw or {})
        ref=identifier('source_observation',[tx.chain,tx.source,raw])
        source_pool.setdefault(ref,{'source':tx.source,'url':safe_public_url(tx.url) or '',
            'blockchain':tx.chain,'transaction_hash':tx.tx_hash,'context_key':context_key,'raw':raw})
        pointer={'context_key':context_key,'event_id':event_identity(tx),'source_observation_id':ref}
        raw_references[key]=pointer
        return dict(pointer)
    for source_report,context_key in sources:
        for tx in source_report.transactions:
            if seen>=max_transactions or time.monotonic()-started>max_seconds:truncated=True;break
            seen+=1;raw=tx.raw or {};kind=str(raw.get('type') or '').lower()
            if _success(tx) is False:counts['failed_excluded']+=1;continue
            if kind in {'approval','approval_for_all','resource','permission_update'} or is_tron_non_monetary(tx):counts['non_monetary_excluded']+=1;continue
            if tx.chain in {'btc','doge'}:
                item=_utxo(tx)
                if item and item['transaction_key'] not in utxo:
                    proof_id=identifier('utxo_observation',item)
                    item['evidence_ids']=[proof_id];utxo[item['transaction_key']]=item
                    proofs[proof_id]={'evidence_id':proof_id,'source':tx.source,'url':safe_public_url(tx.url) or '',
                        'blockchain':tx.chain,'transaction_hash':tx.tx_hash,'relation':'utxo_bipartite_observation',
                        'facts':{**item,'raw_reference':raw_reference(tx,context_key)}}
                continue
            projections=_ton_projections(tx) if tx.chain=='ton' else []
            if not projections:
                # TON action/value projections must not duplicate native messages.
                if tx.chain=='ton' and (raw.get('action') or raw.get('asset_type')=='action' or raw.get('provider')=='tonapi_events'):
                    counts['ton_action_money_excluded']+=1;continue
                frm,to=address_id(tx.chain,tx.from_address),address_id(tx.chain,tx.to_address)
                amount,precision=_amount(tx);asset=_asset(tx)
                if not frm or not to or not asset or not _decimal(amount) or _decimal(amount)<=0:
                    counts['missing_economic_fields']+=1;continue
                projections=[{'operation_id':event_identity(tx),'blockchain':tx.chain,'transaction_hash':tx.tx_hash,
                    'from_key':frm,'to_key':to,'asset_key':asset,'amount_decimal':amount,'amount_precision':precision,
                    'timestamp':_timestamp(tx.timestamp),'success':_success(tx),'kind':kind or 'transfer',
                    'dependency_group':tx.chain+':tx:'+tx.tx_hash,'_priority':0}]
            for op in projections:
                key=op['operation_id']
                if key in observations and observations[key].get('_priority',0)>=op['_priority']:
                    counts['duplicate_physical_observations']+=1;continue
                proof_id=identifier('operation_observation',[key,tx.source,context_key,op['from_key'],op['to_key'],op['amount_decimal']])
                op.update(evidence_ids=[proof_id],source_family=tx.source,source_url=safe_public_url(tx.url) or '')
                observations[key]=op
                proofs[proof_id]={'evidence_id':proof_id,'source':tx.source,'url':op['source_url'],'blockchain':tx.chain,
                    'transaction_hash':tx.tx_hash,'relation':'inference_operation_observation',
                    'facts':{k:v for k,v in op.items() if k!='_priority'}|{'raw_reference':raw_reference(tx,context_key)}}
                for address in (op['from_key'],op['to_key']):
                    addresses.setdefault(address,{'address_key':address,'blockchain':tx.chain,'address':address.split(':',1)[1],
                        'contract':{'kind':'unknown'},'attributions':[],'conflicts':[]})
        if truncated:break
    operations=[{k:v for k,v in row.items() if k!='_priority'} for row in observations.values()]
    return {'operations':operations,'utxo_transactions':list(utxo.values()),'addresses':addresses,'technical':technical,
        'target_keys':context['target_keys'],'evidence':list(proofs.values()),'source_observations':source_pool,
        'coverage':{'status':'TRUNCATED' if truncated else 'PARTIAL','history_complete':False,'transactions_examined':seen,
            'operations':len(operations),'utxo_transactions':len(utxo),'scoped_neighbor_histories':len(sources)-1,
            'normalization_omissions':dict(counts),'max_transactions':max_transactions,'max_seconds':max_seconds,
            'elapsed_seconds':time.monotonic()-started}}

def _dependency_score(hypothesis,operation_dependencies,addresses):
    refs=list(dict.fromkeys(hypothesis.get('evidence_ids') or []))
    # A derived record may declare provider responses, feature IDs or unrelated
    # transactions as dependencies. Only bindings resolved from its evidence
    # references establish physical observations; declarations cannot add votes.
    groups={str(operation_dependencies[ref]).replace(':physical_tx:',':tx:').replace(':transaction:',':tx:')
        for ref in refs if operation_dependencies.get(ref)}
    declared=set(hypothesis.get('dependency_groups') or [])
    if hypothesis.get('dependency_group'):declared.add(hypothesis['dependency_group'])
    declared={str(group).replace(':physical_tx:',':tx:').replace(':transaction:',':tx:') for group in declared}
    claimed=hypothesis.get('confidence') or hypothesis.get('confidence_category') or 'WEAK_LEAD'
    if claimed not in {'POSSIBLE','WEAK_LEAD','UNKNOWN','CONTRADICTED'}:claimed='POSSIBLE'
    if len(groups)<2 and claimed=='POSSIBLE':claimed='WEAK_LEAD'
    subjects=hypothesis.get('subjects') or hypothesis.get('members') or [hypothesis.get('subject')]
    conflicts=[value for key in subjects if isinstance(key,str) for value in addresses.get(key,{}).get('conflicts',[])]
    if conflicts and claimed=='POSSIBLE':claimed='WEAK_LEAD'
    return {'category':claimed,'independent_physical_observation_groups':len(groups),'dependency_groups':sorted(groups),
        'unresolved_declared_dependency_groups':sorted(declared-groups),
        'source_independence':'Shared providers and correlated features are not independent confirmations.',
        'conflicts':conflicts,'calibrated_probability':None,'control_status':'UNKNOWN','signing_application':'UNKNOWN',
        'confirmation_rule':'Heuristic motifs have no sufficient evidence rule for owner or signing UI confirmation.'}

def attach_inferential_intelligence(report,payload,*,analysis_performed_at=None):
    now=analysis_performed_at or datetime.now(timezone.utc).isoformat();started=time.monotonic()
    context=context_for(report);data=build_inference_data(report,payload)
    data['analysis_performed_at']=now
    from .graph_inference import analyze_graph_inference
    from .behavioral_profiles import analyze_behavioral_profiles
    graph=analyze_graph_inference(data);behavior=analyze_behavioral_profiles(data)
    from .cross_chain import analyze_cross_chain
    cross=analyze_cross_chain(report,payload)
    evidence={p['evidence_id']:p for p in payload.get('evidence',[]) if p.get('evidence_id')}
    for source in (data,graph,behavior,cross):
        for row in source.get('evidence',[]):
            if row.get('evidence_id'):evidence[row['evidence_id']]=row
    dependencies={ref:row['dependency_group'] for row in data['operations']+data['utxo_transactions'] for ref in row.get('evidence_ids',[])}
    dependencies.update({key:proof['dependency_group'] for key,proof in evidence.items() if proof.get('dependency_group')})
    # Technical fingerprints can bind physical transactions without a monetary
    # projection; retain those evidence bindings rather than trusting a claim's
    # unverified list of dependency names.
    dependencies.update({key:proof['blockchain']+':tx:'+proof['transaction_hash'] for key,proof in evidence.items()
        if key not in dependencies and isinstance(proof.get('blockchain'),str) and isinstance(proof.get('transaction_hash'),str) and proof['transaction_hash']})
    old=(report.attribution_intelligence or {}).get('inferential_intelligence') or {};old_h={h['id']:h for h in old.get('hypotheses',[]) if h.get('id')}
    hypotheses=[]
    for hypothesis in [*graph.get('hypotheses',[]),*behavior.get('hypotheses',[]),*cross.get('hypotheses',[])][:250]:
        row=dict(hypothesis);row['id']=row.get('id') or row.get('hypothesis_id') or identifier('hypothesis',[row.get('subject'),row.get('claim'),row.get('method')])
        assessment=_dependency_score(row,dependencies,data['addresses']);row['assessment']=assessment
        row['confidence']=assessment['category'];row['confidence_category']=assessment['category']
        row['status']=row.get('status') or 'OPEN';row['first_observed']=old_h.get(row['id'],{}).get('first_observed') or row.get('first_observed') or now
        row['last_verified']=now;row['verification_scope']='Reanalyzed against retained observations; not a new independent on-chain confirmation.'
        row.setdefault('coverage',{'status':'PARTIAL','history_complete':False});row.setdefault('missing_evidence',['Independent infrastructure role/controller evidence','Unobserved alternative history'])
        row.setdefault('proposed_next_experiment','Expand the relevant directed histories and test alternative destinations.')
        row.setdefault('alternative_explanations',LIMITS[:2]);row.setdefault('contradicting_observations',[])
        row.setdefault('supporting_observations',[]);row.setdefault('claim_type','infrastructure_role_hypothesis')
        row['address_control']='UNKNOWN';row['signing_application']='UNKNOWN';hypotheses.append(row)
        prior=old_h.get(row['id'],{})
        if prior.get('confidence')!=row['confidence']:
            journal(context,'hypothesis.assessed',subject=row['id'],evidence_ids=row.get('evidence_ids',[]),
                decision='Evidence-category assessment; no calibrated probability or controller inference',
                result={'confidence':row['confidence']},timestamp=now,
                confidence_transition={'from':prior.get('confidence','UNASSESSED'),'to':row['confidence']})
    present={h['id'] for h in hypotheses}
    for key,prior in old_h.items():
        if key not in present and len(hypotheses)<250:
            hypotheses.append({**prior,'status':'NOT_REOBSERVED_IN_CURRENT_SAMPLE',
                'missing_evidence':list(dict.fromkeys(prior.get('missing_evidence',[])+['Current bounded sample does not reproduce prior motif; absence is not contradiction.']))})
    relationships=[*graph.get('relationships',[]),*cross.get('relationships',[])]
    associations=[]
    for h in hypotheses:
        subject=h.get('subject');subject=subject if isinstance(subject,str) else None
        related=set(h.get('members') or h.get('subjects') or ([] if subject is None else [subject]))
        anchors=[{'address_key':key,'entity_name':c.get('entity_name') or c.get('name'),'status':c.get('status'),
            'relationship':'associated_with','evidence_ids':c.get('evidence_ids',[])} for key in related
            for c in data['addresses'].get(key,{}).get('attributions',[]) if c.get('status') not in {None,'UNKNOWN'}]
        if anchors:associations.append({'hypothesis_id':h['id'],'public_anchors':anchors,'status':'POSSIBLE',
            'address_control':'UNKNOWN','scope':'Published anchor participates in the motif; labels are not assigned to its other members.'})
    fingerprint=identifier('input',[(o['operation_id'],o['dependency_group']) for o in data['operations']])
    journal(context,'inference.completed',subject=context['target_keys'],evidence_ids=[],decision='Evaluate typed graph/temporal hypotheses without owner or UI propagation',
        result={'input_digest':fingerprint,'operations':len(data['operations']),'clusters':len(graph.get('clusters',[])),'hypotheses':len(hypotheses)},timestamp=now)
    payload['investigation_context']=context
    payload.setdefault('source_observations',{}).update(data['source_observations'])
    payload['inferential_intelligence']={'schema_version':'1.0','rule_version':VERSION,'analysis_performed_at':now,
        'clusters':graph.get('clusters',[]),'relationships':relationships,'paths':graph.get('paths',[]),
        'profiles':behavior.get('profiles',[]),'comparisons':behavior.get('comparisons',[]),'motifs':behavior.get('motifs',[]),
        'hypotheses':hypotheses,'entity_associations':associations,'cross_chain_messages':cross.get('messages',[]),
        'coverage':data['coverage'],'method_coverage':{'graph':graph.get('coverage',{}),'behavior':behavior.get('coverage',{}),'cross_chain':cross.get('coverage',{})},
        'diagnostics':{'graph':graph.get('diagnostics',{}),'behavior':behavior.get('diagnostics',{})},
        'stats':{'clusters':len(graph.get('clusters',[])),'hypotheses':len(hypotheses),'independently_confirmed_clusters':0,
            'confirmed_address_controllers':0,'confirmed_signing_applications':0,'elapsed_seconds':time.monotonic()-started},
        'journal':context['journal'],'frontier':context['frontier'],'limitations':LIMITS}
    payload['evidence']=list(evidence.values());payload['stats']['evidence']=len(evidence)
    return payload['inferential_intelligence']
