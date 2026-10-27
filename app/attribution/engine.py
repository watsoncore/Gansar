"""Evidence correlation over existing collectors, with network-scoped identities.

No provider label, source verification, transfer, opcode or wallet version can
identify a signing application. New datasets are loaded locally, never refreshed
during a user search. No network or recursive address expansion occurs here.
"""
from collections import Counter,defaultdict
from datetime import datetime,timezone
import hashlib
import json
import time
from urllib.parse import urlsplit

from app.utils.event_identity import event_identity,transaction_success
from app.utils.security import sanitize_observation,safe_public_url
from .normalize import address_id,canonical_address,normalize_chain,EVM_CHAINS
from .fingerprints import utxo_address_type,evm_selector
from .models import AttributionClaim
from .wallet_application import analyze_wallet_applications
from .transaction_origin import attach_transaction_origins
from .program_transaction_fingerprints import is_tron_non_monetary

LIMITATIONS=[
    'Publicly labeled counterparties do not establish the target service, controller, custody or signing application.',
    'History is a bounded provider sample. Missing labels, timeout and absence from a registry are not proof of no relationship.',
    'Repeated routes and co-spending are observations/heuristics; they never establish common ownership.',
    'Source verification and contract names do not prove the brand or operator of a contract.',
    'Current contract state does not establish historical upgrades; identical code can be deployed by unrelated parties.',
]

def _now():return datetime.now(timezone.utc).isoformat()
def _id(kind,*values):return 'attribution:'+kind+':'+hashlib.sha256(json.dumps(values,sort_keys=True,default=str).encode()).hexdigest()
def _host(url,source):return urlsplit(url).hostname or source
def _upstream(source,url):
    known={'tonapi':'tonapi.io','tonapi_nft':'tonapi.io','toncenter':'toncenter.com','toncenter_v3':'toncenter.com',
        'toncenter_nft':'toncenter.com','tonviewer_public':'tonapi.io','tronscan':'tronscan','tron_contract_metadata':'tronscan',
        'trongrid':'trongrid','solana_rpc':'solana_rpc','ethplorer':'ethplorer.io','etherscan_api':'etherscan',
        'etherscan_html':'etherscan','bscscan_api':'etherscan','bscscan_html':'etherscan'}
    return known.get(source,_host(url,source))

def correlate_attribution(report,*,dataset_records=None,max_transactions=20000,max_addresses=2500,max_seconds=2.5,session_observations=None,include_inference=True):
    """Attach one shared payload, preserving the legacy TON payload and report."""
    started=time.monotonic();observed=_now();truncated=False
    addresses={};evidence={};relationships=[];transactions=[];routes=defaultdict(list);errors=[];seen=set()
    def record(chain,address):
        nonlocal truncated
        chain=normalize_chain(chain);canonical=canonical_address(chain,address);key=address_id(chain,address)
        if not key:return None
        if key not in addresses:
            if len(addresses)>=max_addresses:truncated=True;return None
            addresses[key]={'address':canonical,'blockchain':chain,'address_key':key,'account_type':'unknown','account_status':'unknown',
                'contract':{'kind':'unknown','status':'UNKNOWN','evidence_ids':[]},'attributions':[],
                'client_attribution':{'status':'UNKNOWN','reason':'No reliable public evidence identifies a signing application or physical controller.'},
                'evidence_ids':[],'conflicts':[],'observed_at':None}
        return addresses[key]
    def fact(chain,address,source,url,relation,facts,when=None,tx=None,upstream=None):
        url=safe_public_url(url) or ''
        row={'source':source,'upstream':upstream or _upstream(source,url),'url':url,'observed_at':when or observed,
             'relation':relation,'blockchain':chain,'address':canonical_address(chain,address),'transaction_hash':tx,'facts':facts}
        row['source_independence']='Not inferred from URL count; shared source families are retained and do not increase confidence.'
        eid=_id('evidence',row);row['evidence_id']=eid;evidence[eid]=row
        item=record(chain,address)
        if item and relation!='transaction_participants' and eid not in item['evidence_ids']:item['evidence_ids'].append(eid)
        return eid
    for chain in report.detected_chains:record(chain,report.target_address)
    target_chain=next((c for c in report.detected_chains if address_id(c,report.target_address)),None)
    target_key=address_id(target_chain,report.target_address)
    # Reuse all validated TON observations, including independent state conflicts.
    ton=report.ton_service_intelligence or {}
    for address,row in ton.get('addresses',{}).items():
        item=record('ton',address)
        if item:item.update(sanitize_observation(row));item.update(blockchain='ton',address_key=address_id('ton',address))
    for row in ton.get('evidence',[]):
        if row.get('evidence_id'):evidence[row['evidence_id']]={**row,'blockchain':'ton'}
    for observation in report.contract_observations:
        chain=observation.get('blockchain');address=observation.get('address');item=record(chain,address)
        if not item:continue
        data=observation.get('raw',{});url=observation.get('source_url');source=observation.get('source','contract_source')
        eid=fact(chain,address,source,url,'verified_contract_observation',data,observation.get('observed_at'),upstream=observation.get('upstream'))
        contract=item['contract'];contract.setdefault('observations',[]).append({'source':source,'match':data.get('match'),
            'verified_at':data.get('verifiedAt'),'compilation':data.get('compilation'),'proxy_resolution':data.get('proxyResolution'),
            'evidence_id':eid})
        # Compilation name remains a code descriptor, never a brand assertion.
        if data.get('compilation'):contract['verified_name']=data['compilation'].get('name')
        deployment=data.get('deployment') or {}
        relations=[]
        if canonical_address(chain,deployment.get('deployer')):relations.append(('contract_deployer',deployment['deployer']))
        proxy=data.get('proxyResolution') or {}
        for implementation in proxy.get('implementations') or []:
            if isinstance(implementation,dict) and canonical_address(chain,implementation.get('address')):
                relations.append(('proxy_implementation',implementation['address']))
        for kind,to in relations:
            dest=record(chain,to)
            if dest:relationships.append({'relationship_id':_id(kind,chain,address,to),'blockchain':chain,
                'from_key':address_id(chain,address),'to_key':address_id(chain,to),'type':kind,'status':'PROBABLE',
                'evidence_ids':[eid],'reason':'Public verification service reports this technical relation; current RPC corroboration may be missing.',
                'alternative_explanations':['Deployment/implementation does not establish common controller or operator.'],'limitations':LIMITATIONS[3:5]})
    # Existing contract metadata is evidence about code, never an explorer-name
    # shortcut to controller identity. Preserve creator/proxy facts if supplied.
    for token in report.tokens:
        raw=token.raw or {}
        if token.chain not in EVM_CHAINS or raw.get('asset_type') not in {'contract','bsc_contract'}:continue
        item=record(token.chain,token.contract or token.address)
        if not item:continue
        eid=fact(token.chain,item['address'],token.source,token.url,'provider_contract_metadata',
            {k:raw.get(k) for k in ('contract_name','verified','proxy','implementation','creator') if k in raw})
        if raw.get('contract_name'):item['contract']['verified_name']=raw['contract_name']
        item['contract'].setdefault('evidence_ids',[]).append(eid)
        for kind,value in [('proxy_implementation',raw.get('implementation')),('contract_deployer',raw.get('creator'))]:
            dest=record(token.chain,value)
            if dest:relationships.append({'relationship_id':_id(kind,item['address_key'],dest['address_key']),
                'blockchain':token.chain,'from_key':item['address_key'],'to_key':dest['address_key'],'type':kind,
                'status':'PROBABLE','evidence_ids':[eid],'reason':'Collector reports this contract relation.',
                'alternative_explanations':['Reported implementation/deployer is not proof of present control.'],'limitations':LIMITATIONS[3:]})
    for balance in report.balances:
        item=record(balance.chain,balance.address)
        if not item:continue
        raw=balance.raw or {};fp=raw.get('contract_fingerprint')
        if isinstance(fp,dict) and fp:
            eid=fact(balance.chain,balance.address,balance.source,raw.get('rpc') or balance.url,'current_runtime_fingerprint',fp,raw.get('observed_at'))
            old=item['contract'].get('code_hash')
            if old and old!=fp.get('code_hash'):
                item['conflicts'].append('Runtime code hashes differ across collected observations; temporal change or inconsistent source.');fp={**fp,'status':'POSSIBLE'}
                item['contract']['runtime_observation_conflict']=True
            if item['contract'].get('runtime_observation_conflict'):fp={**fp,'status':'POSSIBLE'}
            item['contract'].update(fp);item['contract']['evidence_ids']=list(dict.fromkeys(item['contract'].get('evidence_ids',[])+[eid]))
            item['account_type']=fp['kind'];item['observed_at']=raw.get('observed_at') or observed
            if fp.get('implementation'):
                to=record(balance.chain,fp['implementation'])
                if to:relationships.append({'relationship_id':_id('proxy',balance.chain,balance.address,to['address']),
                    'blockchain':balance.chain,'from_key':address_id(balance.chain,balance.address),'to_key':to['address_key'],
                    'type':'delegation_target' if fp.get('kind')=='eip7702_delegation_designator' else 'proxy_implementation',
                    'status':'CONFIRMED','evidence_ids':[eid],
                    'reason':'Exact standardized runtime bytes encode the delegation target or proxy implementation address.',
                    'alternative_explanations':['Implementation is a code dependency, not proof of common control.'],'limitations':fp.get('limitations',[])})
    for chain in report.detected_chains:
        item=record(chain,report.target_address)
        if item and chain in {'btc','doge'}:
            item['account_type']=utxo_address_type(chain,item['address'])
            eid=fact(chain,item['address'],'validated_address_encoding','https://developer.bitcoin.org/devguide/transactions.html',
                'address_encoding',{'type':item['account_type'],'not_signing_client':True})
            item['contract']={'kind':'utxo_script_address','status':'CONFIRMED','evidence_ids':[eid]}
    # Existing Solana parsed state explicitly separates owner program from wallet.
    account=(report.solana or {}).get('account') or {}
    if account and account.get('owner_program'):
        item=record('solana',report.target_address)
        if item:
            owner=account.get('owner_program');item['account_type']='executable_program' if account.get('executable') else account.get('account_type') or 'program_owned_account'
            item['account_status']='observed';eid=fact('solana',report.target_address,'solana_rpc',account.get('rpc') or 'https://api.mainnet-beta.solana.com',
                'solana_account_state',account)
            item['contract'].update(kind=item['account_type'],status='CONFIRMED',owner_program=owner,evidence_ids=[eid])
            if owner and record('solana',owner):relationships.append({'relationship_id':_id('program_owner',report.target_address,owner),
                'blockchain':'solana','from_key':address_id('solana',report.target_address),'to_key':address_id('solana',owner),
                'type':'program_owned_by','status':'CONFIRMED','evidence_ids':[eid],
                'reason':'RPC account.owner identifies the executing owner program, not a person or custody platform.',
                'alternative_explanations':['A normal account owned by System Program can use many signing applications.'],'limitations':LIMITATIONS[:2]})
            parsed=account.get('parsed_info') or {}
            for role in ('mintAuthority','freezeAuthority','owner','delegate','authority','upgradeAuthority'):
                value=parsed.get(role);dest=record('solana',value)
                if dest:relationships.append({'relationship_id':_id('sol_authority',item['address_key'],role,dest['address_key']),
                    'blockchain':'solana','from_key':item['address_key'],'to_key':dest['address_key'],'type':'authority',
                    'authority_role':role,'status':'CONFIRMED','evidence_ids':[eid],
                    'reason':f'Parsed RPC account state reports {role}; cryptographic key role does not identify a physical person or app.',
                    'alternative_explanations':['Delegate, multisig or service-managed authority.'],'limitations':LIMITATIONS[:2]})
    permissions=(report.tron or {}).get('permissions') or {}
    if permissions:
        item=record('tron',report.target_address)
        if item:
            proof=fact('tron',report.target_address,'tron_collected_permissions','https://tronscan.org/#/address/'+report.target_address,
                'account_permission_configuration',permissions)
            for role,permission in permissions.items():
                for part in permission if isinstance(permission,list) else [permission]:
                    if not isinstance(part,dict):continue
                    for key in part.get('keys',[])[:64]:
                        if not isinstance(key,dict):continue
                        dest=record('tron',key.get('address'))
                        if dest:relationships.append({'relationship_id':_id('tron_authority',item['address_key'],role,dest['address_key']),
                            'blockchain':'tron','from_key':item['address_key'],'to_key':dest['address_key'],'type':'authority',
                            'authority_role':role,'threshold':part.get('threshold'),'weight':key.get('weight'),
                            'status':'PROBABLE','evidence_ids':[proof],
                            'reason':'Collected account permissions identify a key role subject to threshold, not a person or brand.',
                            'alternative_explanations':['Multisig, delegation or shared custody.'],'limitations':LIMITATIONS[:2]})
    if len(report.transactions)>max_transactions:truncated=True
    for tx in report.transactions[:max_transactions]:
        if time.monotonic()-started>max_seconds:truncated=True;break
        chain=tx.chain;eid=event_identity(tx)
        if eid in seen:continue
        seen.add(eid)
        participants=lambda rows:list(dict.fromkeys(address_id(chain,r.get('address')) for r in rows if isinstance(r,dict) and address_id(chain,r.get('address'))))
        senders=participants(tx.inputs) if chain in {'btc','doge'} else [address_id(chain,tx.from_address)]
        recipients=participants(tx.outputs) if chain in {'btc','doge'} else [address_id(chain,tx.to_address)]
        senders=[v for v in senders if v];recipients=[v for v in recipients if v]
        for key in senders+recipients:record(chain,key.split(':',1)[1])
        proof=fact(chain,report.target_address,tx.source,tx.url,'transaction_participants',
            {'event_id':eid,'senders':senders,'recipients':recipients,'amount_decimal':str(tx.amount_decimal) if tx.amount_decimal is not None else None,
             'asset':tx.asset,'success':transaction_success(tx),'selector':evm_selector(tx.raw) if chain in EVM_CHAINS else None},tx=tx.tx_hash)
        operation_type=str(tx.raw.get('type') or '').casefold()
        row={'event_id':eid,'blockchain':chain,'operation_type':operation_type,'tx_hash':tx.tx_hash,'trace_id':tx.raw.get('trace_id'),
            'from_key':senders[0] if len(senders)==1 else None,'to_key':recipients[0] if len(recipients)==1 else None,
            'sender_service_keys':senders,'recipient_service_keys':recipients,'from_address':tx.from_address,'to_address':tx.to_address,
            'amount_decimal':str(tx.amount_decimal) if tx.amount_decimal is not None else None,'asset':tx.asset,
            'timestamp':tx.timestamp.isoformat() if tx.timestamp else None,'success':transaction_success(tx),'evidence_ids':[proof]}
        transactions.append(row)
        if transaction_success(tx) is False:continue
        if operation_type in {'resource','permission_update'} or is_tron_non_monetary(tx):
            # Delegated stake/resources and permission changes are not payments.
            # Native contract type takes precedence over collector's generic type.
            row['operation_type']='resource_or_permission'
            continue
        if operation_type=='approval':
            # Collector amount is an allowance, never money transferred. A
            # submitted call alone is not proof of an effective allowance.
            frm=address_id(chain,tx.raw.get('owner') or tx.from_address)
            to=address_id(chain,tx.raw.get('spender') or tx.to_address)
            if frm and to:relationships.append({'relationship_id':_id('allowance',chain,eid),'blockchain':chain,
                'from_key':frm,'to_key':to,'type':'token_allowance_observation','status':'PROBABLE',
                'token_contract':tx.raw.get('token_contract'),'allowance_decimal':row['amount_decimal'],
                'evidence_ids':[proof],'transaction_hashes':[tx.tx_hash],
                'reason':'Collector reports an approval/allowance; no asset movement or present remaining allowance is inferred.',
                'alternative_explanations':['Allowance can be revoked, superseded or consumed.'],
                'limitations':LIMITATIONS[:3]})
            continue
        if chain in {'btc','doge'}:
            if len(senders)>1:
                relationships.append({'relationship_id':_id('co_inputs',chain,tx.tx_hash),'blockchain':chain,'type':'co_input_participation',
                    'from_key':senders[0],'to_key':senders[1],'participants':senders,'status':'POSSIBLE','evidence_ids':[proof],
                    'transaction_hashes':[tx.tx_hash],'reason':'Inputs appear in one transaction; collaborative spending/CoinJoin remains possible.',
                    'alternative_explanations':['CoinJoin, PayJoin, multisig or service aggregation; no owner cluster established.'],
                    'limitations':['No change output is assumed; input/output pairs are not invented.']})
            continue
        if row['from_key'] and row['to_key']:
            routes[(chain,row['from_key'],row['to_key'])].append(row)
        if chain=='solana':
            for program in (tx.raw.get('program_ids') or [])[:32]:
                if record(chain,program):relationships.append({'relationship_id':_id('program',chain,tx.tx_hash,program),
                    'blockchain':chain,'from_key':address_id(chain,report.target_address),'to_key':address_id(chain,program),
                    'type':'protocol_interaction','status':'CONFIRMED','evidence_ids':[proof],'transaction_hashes':[tx.tx_hash],
                    'reason':'Decoded transaction invokes this program; this does not identify the wallet application.',
                    'alternative_explanations':[],'limitations':LIMITATIONS[:2]})
    # Dataset adapters supply metadata, not executable code or arbitrary ranking.
    if dataset_records is None:
        from .datasets import lookup_dataset_records
        try:dataset_records=lookup_dataset_records(addresses.keys())
        except (OSError,ValueError,TypeError) as exc:
            errors.append({'source':'attribution_dataset','status':'unavailable','error':str(sanitize_observation(str(exc)))[:600]})
            dataset_records=[]
    dataset_records_matched=0
    for row in dataset_records:
        key=address_id(row.get('blockchain'),row.get('address'))
        if key not in addresses:continue
        dataset_records_matched+=1
        chain=row['blockchain'];address=row['address'];item=addresses[key]
        source=row.get('source') or 'public_dataset';url=row.get('source_url') or ''
        proof=fact(chain,address,source,url,'published_exact_address_label',
            {'name':row.get('entity_name'),'entity_id':row.get('entity_id'),'dataset_version':row.get('version'),
             'content_hash':row.get('content_hash'),'license':row.get('license'),'claim_type':row.get('entity_type'),
             'source_published_at':row.get('source_published_at'),'dataset_id':row.get('dataset_id'),
             'coverage_limitations':row.get('coverage_limitations',[])},
             row.get('observed_at'),upstream=row.get('upstream') or source)
        metadata=row.get('contract_metadata') or {}
        if metadata:
            item['contract'].setdefault('published_manifests',[]).append({**metadata,'evidence_id':proof})
            published=metadata.get('published_code_hash');actual=item['contract'].get('code_hash')
            if published and actual:
                matched=str(published).lower()==str(actual).lower()
                item['contract']['manifest_code_match']={'status':'CONFIRMED' if matched and not item['contract'].get('runtime_observation_conflict') else 'POSSIBLE',
                    'matched':matched,'evidence_ids':[proof]+item['contract'].get('evidence_ids',[]),
                    'relation':'exact_manifest_runtime_code' if matched else 'manifest_runtime_mismatch',
                    'runtime_observation_conflict':bool(item['contract'].get('runtime_observation_conflict'))}
                if not matched:item['conflicts'].append('Current runtime code does not match the published deployment manifest.')
        status='CONFIRMED' if row.get('authority')=='official_operator_publication' and row.get('relationship')=='official_published_address' else 'PROBABLE'
        claim={'attribution_id':_id('claim',key,proof,row.get('entity_id')),'blockchain':chain,'address':address,
            'entity_name':row.get('entity_name'),'name':row.get('entity_name'),'service_id':row.get('entity_id'),
            'entity_type':row.get('entity_type','public_address_label'),'category':row.get('entity_type','public_address_label'),
            'relationship':row.get('relationship') or 'published_address_label','status':status,
            'method':row.get('method') or 'exact_public_dataset_address','reason':'Exact network-scoped address appears in the cited publication; scope and source authority are preserved.',
            'confidence_rationale':'Direct publication' if status=='CONFIRMED' else 'Published public label; operator control not independently proved.',
            'evidence_ids':[proof],'source_url':url,'source_urls':[url],'observed_at':row.get('observed_at'),
            'observation_timestamps':[row['observed_at']] if row.get('observed_at') else [],'conflicts':[],
            'alternative_explanations':['Published label may be stale or describe a technical role rather than current control.'],
            'coverage_limitations':list(dict.fromkeys(row.get('coverage_limitations',[])+LIMITATIONS[:2]))}
        existing=next((c for c in item['attributions'] if chain=='ton' and str(c.get('name','')).casefold()==str(claim.get('name','')).casefold()),None)
        if existing:
            existing['evidence_ids']=list(dict.fromkeys(existing.get('evidence_ids',[])+[proof]))
            continue
        if not any(c.get('service_id')==claim['service_id'] and proof in c.get('evidence_ids',[]) for c in item['attributions']):item['attributions'].append(claim)
    for label in report.labels:
        item=record(label.chain,label.address)
        # Generic code/type/naming labels remain observations, never brands.
        parser=str(label.raw.get('parser') or '')
        if (not item or label.label.casefold() in {'contract','wallet','eoa','smart contract'} or label.source.endswith('_ens')
                or parser.startswith('public_page_') or label.raw.get('kind') or label.raw.get('contract_name')
                or label.label.startswith(('TON interface:','Contract:','Service signal:','Telegram marker:','TON DNS:'))):continue
        url=label.raw.get('url') or label.raw.get('source_url')
        if not safe_public_url(url):continue
        label_observed=label.raw.get('observed_at') or observed
        proof=fact(label.chain,label.address,label.source,url,'provider_account_label',{'label':label.label,'raw':label.raw},label_observed)
        item['attributions'].append({'attribution_id':_id('provider_label',item['address_key'],label.label,label.source),
            'name':label.label,'entity_name':label.label,'service_id':'label:'+hashlib.sha256(label.label.encode()).hexdigest()[:16],
            'category':'public_address_label','entity_type':'public_address_label','relationship':'provider_label',
            'status':'POSSIBLE','method':'provider_label','reason':'Provider label only; no independent operator proof.',
            'confidence_rationale':'Provider assertion','evidence_ids':[proof],'source_url':url,'source_urls':[url],
            'observed_at':label_observed,'conflicts':[],'alternative_explanations':['An account title/name may be misleading or stale.'],'coverage_limitations':LIMITATIONS[:2]})
    for item in addresses.values():
        # Preserve independent assertions and expose disagreement without a winner.
        claims=item['attributions'];strong={c.get('service_id') for c in claims if c.get('status') in {'PROBABLE','CONFIRMED'} and c.get('category') not in {'token','program'}}
        for claim in claims:
            claim.setdefault('blockchain',item['blockchain']);claim.setdefault('address',item['address'])
            claim.setdefault('entity_name',claim.get('name'));claim.setdefault('entity_type',claim.get('category','public_address_label'))
            claim.setdefault('relationship','published_address_label')
            claim.setdefault('confidence_rationale',claim.get('reason','No independent operator proof'))
            claim.setdefault('source_urls',[claim['source_url']] if claim.get('source_url') else [])
            claim.setdefault('observation_timestamps',[claim['observed_at']] if claim.get('observed_at') else [])
            claim.setdefault('alternative_explanations',['Public label may be stale; brand label is not proof of present controller or signing application.'])
            claim.setdefault('coverage_limitations',LIMITATIONS[:2]);claim.setdefault('conflicting_evidence',claim.get('conflicts',[]))
            claim.setdefault('icon_reference',claim.get('service_id'))
            # Validate the shared evidence contract without discarding legacy
            # HTML aliases such as name/service_id/source_url.
            claim.update(AttributionClaim.model_validate(claim).model_dump(mode='json'))
        if len(strong)>1:
            note='Conflicting published entity labels; no single current operator selected.'
            item['conflicts']=list(dict.fromkeys(item['conflicts']+[note]))
            for c in claims:
                c['conflicts']=list(dict.fromkeys(c.get('conflicts',[])+[note]))
                c['conflicting_evidence']=list(dict.fromkeys(c.get('conflicting_evidence',[])+[note]))
        item['evidence_ids']=list(dict.fromkeys(item['evidence_ids']))
    for (chain,frm,to),rows in routes.items():
        # Distinct source actions may overlap. Count hashes as operations, never
        # total a route's funds or infer a deposit account from repetition alone.
        hashes=list(dict.fromkeys(r['tx_hash'] for r in rows));repeated=len(hashes)>1
        refs=list(dict.fromkeys(e for r in rows for e in r['evidence_ids']))
        known=bool(addresses.get(frm,{}).get('attributions') or addresses.get(to,{}).get('attributions'))
        labels=addresses.get(frm,{}).get('attributions',[])+addresses.get(to,{}).get('attributions',[])
        movement_status='CONFIRMED' if all(r['success'] is True for r in rows) else 'PROBABLE'
        service_status='POSSIBLE' if any(c.get('status')=='POSSIBLE' for c in labels) else 'PROBABLE' if labels else 'UNKNOWN'
        contract_interaction=any(r.get('operation_type') in {'contract_call','solana_signature'} for r in rows)
        relationships.append({'relationship_id':_id('route',chain,frm,to),'blockchain':chain,'from_key':frm,'to_key':to,
            'type':'repeated_service_route' if repeated and known else 'contract_interaction' if contract_interaction else 'direct_transfer','status':service_status if repeated and known else movement_status,
            'movement_status':movement_status,'counterparty_label_status':service_status,
            'evidence_ids':refs,'transaction_hashes':hashes,'source_action_rows':len(rows),'distinct_account_transaction_hashes':len(hashes),
            'first_seen':min((r['timestamp'] for r in rows if r['timestamp']),default=None),
            'last_seen':max((r['timestamp'] for r in rows if r['timestamp']),default=None),
            'reason':'Observed directed operations. Repetition does not prove a deposit/withdrawal business purpose or common owner.',
            'alternative_explanations':['Payment, refund, withdrawal, deposit or unrelated repeated transfers.'],'limitations':LIMITATIONS[:3]})
    ton_analysis=ton.get('relationship_analysis') or {}
    if ton_analysis:
        errors.extend(ton_analysis.get('errors',[]))
        for row in ton_analysis.get('evidence',[]):
            if row.get('evidence_id'):evidence[row['evidence_id']]={**row,'blockchain':'ton'}
        # TON physical-message reconstruction supersedes generic account action
        # route counts, which can otherwise double-count both account sides.
        relationships=[r for r in relationships if r.get('blockchain')!='ton' or r.get('type') not in {'direct_transfer','repeated_service_route'}]
        for row in ton_analysis.get('relationships',[]):
            frm=address_id('ton',row.get('from_address') or row.get('sender') or (report.target_address if row.get('direction')=='out' else row.get('counterparty')))
            to=address_id('ton',row.get('to_address') or row.get('recipient') or (report.target_address if row.get('direction')=='in' else row.get('counterparty')))
            if not frm or not to:continue
            relationships.append({**row,'relationship_id':row.get('relationship_id') or _id('ton_route',frm,to,row.get('asset_id')),
                'blockchain':'ton','from_key':frm,'to_key':to,'type':row.get('kind','direct_transfer'),
                'limitations':ton_analysis.get('limitations',[])})
        # Existing contract facts in Signals/inspectors expose bounded history
        # summaries. Complete collected observations remain in the shared data.
        item=addresses.get(address_id('ton',report.target_address))
        if item:
            item['contract']['historical_analysis']={
                'coverage':ton_analysis.get('coverage',{}),'limitations':ton_analysis.get('limitations',[]),
                'summary_limit_per_kind':50,
                **{name:{'available':len(ton_analysis.get(name,[])),
                    'displayed':min(50,len(ton_analysis.get(name,[]))),
                    'observations':ton_analysis.get(name,[])[:50]}
                    for name in ('contract_history','operations','traces')}}
    payload={'schema_version':'1.0','target_address':report.target_address,'target_chain':target_chain,'target_key':target_key,
        'addresses':addresses,'evidence':list(evidence.values()),'transactions':transactions,'relationships':relationships,
        'source_observations':ton.get('source_observations') or {},
        'ton_relationship_analysis':ton_analysis,'coverage':{'status':'TRUNCATED' if truncated else 'PARTIAL',
            'history_complete':False,'networks':report.detected_chains,'transactions_available':len(report.transactions),
            'transactions_correlated':len(transactions),'max_transactions':max_transactions,'max_addresses':max_addresses,
            'dataset_refresh_in_search':False,'dataset_records_matched':dataset_records_matched,
            'dataset_lookup_scope':'Only network-qualified participants already observed in this report',
            'published_label_assertions':sum(len(r['attributions']) for r in addresses.values()),
            'observed_upstream_families':sorted({str(e.get('upstream')) for e in evidence.values() if e.get('upstream')}),
            'source_independence':'Shared family identifiers are not counted as independent confirmations.',
            'limits':LIMITATIONS},'warnings':LIMITATIONS,'errors':errors,
        'stats':{'evidence':len(evidence),'addresses':len(addresses),'relationships':len(relationships),
            'network_requests':0,'elapsed_seconds':time.monotonic()-started}}
    analyze_wallet_applications(report,payload)
    attach_transaction_origins(report,payload,session_observations=session_observations,analysis_performed_at=observed)
    if include_inference:
        from .inference import attach_inferential_intelligence
        attach_inferential_intelligence(report,payload,analysis_performed_at=observed)
    from .telegram_services import attribute_cryptobot_xrocket
    attribute_cryptobot_xrocket(report,payload)
    report.attribution_intelligence=sanitize_observation(payload)
    return report.attribution_intelligence
