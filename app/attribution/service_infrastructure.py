"""Service/exchange projection inside the existing attribution pipeline.

Consumes the current source-validated operation pool, current scoped histories,
dataset lookup and existing path/profile algorithms. No network, new ledger,
owner propagation, financial Transaction creation or parallel graph traversal.
"""
from __future__ import annotations

from collections import Counter,defaultdict
from bisect import bisect_left
from datetime import datetime,timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import time

from .datasets import lookup_dataset_records
from .normalize import address_id,canonical_address

METHOD='service_infrastructure_evidence_projection'
SUPPLEMENT=Path(__file__).resolve().parent/'assets/service_infrastructure_snapshot.json'
NAMES={'binance':'Binance','bybit':'Bybit','okx':'OKX','htx':'HTX','mexc':'MEXC',
       'bitget':'Bitget','kucoin':'KuCoin','gate_io':'Gate.io','fixedfloat':'FixedFloat',
       'changelly':'Changelly','coinpaymentsnet':'CoinPayments.net'}
ALIASES={'huobi':'htx','huobi_deposit':'htx','binance_hot_wallet':'binance',
         'gateio':'gate_io','gate':'gate_io','okex':'okx'}
STABLES={
 'eth:token:0xdac17f958d2ee523a2206206994597c13d831ec7':'USDT',
 'eth:token:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48':'USDC',
 'tron:token:TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t':'USDT',
 'ton:token:0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe':'USDT',
 'bsc:token:0x55d398326f99059ff775485246999027b3197955':'Binance-Peg USDT',
 'arbitrum:token:0xaf88d065e77c8cc2239327c5edb3a432268e5831':'USDC',
 'optimism:token:0x0b2c639c533813f4aa9d7837caf62653d097ff85':'USDC',
 'polygon:token:0x3c499c542cef5e3811e1192ce70d8cc03d5c3359':'USDC',
 'avalanche:token:0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e':'USDC'}
ASSET_REFERENCES=['https://tether.to/en/supported-protocols/',
 'https://developers.circle.com/stablecoins/usdc-contract-addresses',
 'https://bscscan.com/token/0x55d398326f99059ff775485246999027b3197955']


def _id(kind,*basis):
    return 'infrastructure:'+kind+':'+hashlib.sha256(json.dumps(basis,sort_keys=True,default=str).encode()).hexdigest()


def _service(row):
    value=str(row.get('entity_id') or '').casefold().strip()
    value=re.sub(r'(?:[_ -]?\d+)$','',value)
    value=ALIASES.get(value,value)
    if value in NAMES:return value
    # Other exact catalogue exchange entities remain usable without fuzzy brands.
    return value if row.get('entity_type')=='exchange' and re.fullmatch(r'[a-z][a-z0-9_]{1,80}',value) else None


def _reference_rows(keys):
    rows=lookup_dataset_records(keys)
    if SUPPLEMENT.exists():rows.extend(lookup_dataset_records(keys,path=SUPPLEMENT))
    out={}
    for row in rows:
        service=_service(row)
        key=address_id(row.get('blockchain'),row.get('address'))
        digest=row.get('upstream_content_hash') or row.get('content_hash')
        if not service or key not in keys or not re.fullmatch(r'[0-9a-fA-F]{64}',str(digest or '')):continue
        if row.get('status') not in {'PROBABLE','CONFIRMED'} or not str(row.get('source_url') or '').startswith('https://'):continue
        marker=(service,key,row.get('upstream'),row.get('source_url'))
        if marker not in out or row.get('published_role'):out[marker]=row
    return list(out.values())


def exchange_receipt_targets(report,chain):
    """Only actual collected participant keys; no I/O or catalogue-wide scans."""
    keys={key for tx in report.transactions if tx.chain==chain for value in (tx.from_address,tx.to_address)
          if (key:=address_id(chain,value))}
    return {canonical_address(chain,row['address']) for row in _reference_rows(keys)}


def source_bound_planning_data(report,data,*,max_seconds=.6):
    """Repair planning context with the existing TON normalizer/proof gates.

    Planning precedes final attribution. A merged UNKNOWN action observation
    must not suppress a separately retained successful native/typed transfer.
    No transactions are changed and the ordinary planner keeps all its limits.
    """
    if 'ton' not in report.detected_chains:return data
    from .inference import build_inference_data
    from .service_operations import repair_ton_native_observations,validate_account_operation,raw_records
    from .telegram_services import _validated_ton_native_operation,_digest,_timestamp,_catalogue,_public_labels
    started=time.monotonic();stop=started+max(0,min(.6,max_seconds))
    payload=report.attribution_intelligence or {}
    repaired=repair_ton_native_observations(report,payload,data,max_seconds=min(.2,max(0,stop-time.monotonic())))
    typed=[]
    for tx in report.transactions:
        if time.monotonic()>=stop:break
        if tx.chain=='ton' and isinstance((tx.raw or {}).get('transfer'),dict):typed.append(tx)
        if len(typed)>=512:break
    view=report.model_copy(update={'transactions':typed,'attribution_intelligence':{}})
    tokens=build_inference_data(view,{},max_transactions=512,max_seconds=min(.2,max(0,stop-time.monotonic())))
    proofs={p['evidence_id']:p for p in [*data['evidence'],*repaired['evidence'],*tokens['evidence']]}
    data['evidence']=list(proofs.values())
    data['source_observations'].update(repaired['source_observations'])
    data['source_observations'].update(tokens['source_observations'])
    data['_service_evidence_index']=proofs
    operations={r['operation_id']:r for r in data['operations']}
    for row in [*tokens['operations'],*repaired['operations']]:
        if time.monotonic()>=stop:break
        proof=('ton_native_message' if _validated_ton_native_operation(row,data) else validate_account_operation(row,data))
        if not proof or not _timestamp(row.get('timestamp')) or row.get('native_value_purpose')=='jetton_transfer_request':continue
        tx=_digest(row.get('transaction_hash'))
        if not tx:continue
        dependency=row.get('dependency_group') or 'ton:tx:'+tx
        if ':tx:' in dependency:dependency='ton:tx:'+str(_digest(dependency.split(':tx:',1)[1]) or tx)
        traces={digest for raw,_ in raw_records(row,data)
                if (digest:=_digest((raw.get('transfer') or {}).get('trace_id') or raw.get('trace_id')))}
        if len(traces)==1:dependency='ton:tx:'+next(iter(traces))
        operations[row['operation_id']]={**row,'success':True,'proof_kind':proof,'transaction_hash':tx,'dependency_group':dependency}
    keys={key for row in operations.values() for key in (row.get('from_key'),row.get('to_key')) if key}
    references=[*_catalogue(),*_public_labels(data,payload),*[_anchor(r) for r in _reference_rows(keys)]]
    known={r['address_key'] for r in references}
    for key in known:
        record=dict(data['addresses'].get(key) or {'address_key':key,'blockchain':key.split(':',1)[0],'address':key.split(':',1)[1]})
        record['attributions']=[*record.get('attributions',[]),{'entity_type':'published_service_reference','status':'PROBABLE',
                                'current_control':'UNKNOWN','planning_only':True}]
        data['addresses'][key]=record
    funding=defaultdict(list)
    for row in operations.values():
        if row.get('success') is True and row.get('from_key') in known:
            if (stamp:=_timestamp(row.get('timestamp'))):funding[(row['to_key'],row['asset_key'])].append(stamp)
    for stamps in funding.values():stamps.sort()
    staged=defaultdict(list)
    for row in operations.values():
        if row.get('success') is not True or row.get('to_key') in known or not _timestamp(row.get('timestamp')):continue
        stamps=funding.get((row['from_key'],row['asset_key']),[]);stamp=_timestamp(row['timestamp'])
        position=bisect_left(stamps,stamp)-1
        if position>=0 and 0<(stamp-stamps[position]).total_seconds()<=30*86400:
            staged[(row['from_key'],row['to_key'])].append(row)
    for rows in staged.values():
        assets={r['asset_key'] for r in rows}
        if any(a.endswith(':native') for a in assets) and assets.intersection(STABLES) and len({r['dependency_group'] for r in rows})>=2:
            for row in rows:row['planning_priority']=6
    data['operations']=list(operations.values())
    payload['evidence']=list({p['evidence_id']:p for p in [*payload.get('evidence',[]),*data['evidence']]}.values())
    payload.setdefault('source_observations',{}).update(data['source_observations'])
    report.attribution_intelligence=payload
    data['coverage']['source_bound_planning']={'status':'PARTIAL','max_seconds':.6,'elapsed_seconds':time.monotonic()-started,
        'source_transactions_unchanged':True,'history_complete':False}
    return data


def _anchor(row):
    service=_service(row)
    return {'service_id':service,'service':NAMES.get(service,row['entity_name']),
        'blockchain':row['blockchain'],'address':row['address'],
        'address_key':address_id(row['blockchain'],row['address']),
        'label_status':'PROBABLE','role':row.get('published_role') or 'publicly_labelled_service_address',
        'publication_url':row['source_url'],'observed_at':row.get('observed_at'),
        'source_published_at':row.get('source_published_at'),'valid_from':row.get('valid_from'),
        'valid_to':row.get('valid_to'),'capture_sha256':row.get('upstream_content_hash') or row.get('content_hash'),
        'reference_kind':'official_publication' if row.get('authority') in {'official_operator_publication','operator_publication'} else 'public_label',
        'authority':row.get('authority'),'claim_scope':'published_reference_only_current_control_unknown',
        'current_control':'UNKNOWN','source_record':row}


def _edge(row):
    return {key:row.get(key) for key in ('operation_id','transaction_hash','message_hash','blockchain',
        'from_key','to_key','asset_key','amount_decimal','timestamp','success','proof_kind','source_url','evidence_ids')}


def _retained_context_operations(report,data,valid):
    """Apply the same native proof repair to already collected scoped histories."""
    from app.models.report import AddressReport
    from .service_operations import repair_ton_native_observations
    from .telegram_services import _validated_ton_native_operation
    started=time.monotonic();proofs={p['evidence_id']:p for p in data['evidence']}
    histories=((report.attribution_intelligence or {}).get('investigation_context') or {}).get('histories',{})
    for key,history in list(histories.items())[:4]:
        if time.monotonic()-started>=.6:break
        try:neighbor=AddressReport.model_validate(history['report'])
        except (KeyError,TypeError,ValueError):
            data.setdefault('coverage',{}).setdefault('invalid_retained_role_histories',[]).append(key)
            continue
        chain=key.split(':',1)[0]
        if chain!='ton' or address_id(chain,neighbor.target_address)!=key:continue
        # A shallow normalization view retains the investigation target so the
        # existing repair marks each neighbor's native account as scoped context.
        view=neighbor.model_copy(update={'target_address':report.target_address})
        result=repair_ton_native_observations(view,{},data,max_seconds=min(.2,max(0,.6-(time.monotonic()-started))))
        proofs.update({p['evidence_id']:p for p in result['evidence']})
        data['source_observations'].update(result['source_observations'])
        data['_service_evidence_index']=proofs
        for row in result['operations']:
            if _validated_ton_native_operation(row,data):valid[row['operation_id']]={**row,'proof_kind':'ton_native_message'}
    data['evidence']=list(proofs.values())


def _behavioral_hypotheses(data,valid,anchors,target):
    """One specific behavioral category per subject/asset, never a fiat claim."""
    from .behavioral_profiles import _exact,_stamp
    by_key=defaultdict(list);known={row['address_key'] for row in anchors}
    exchange_known={row['address_key'] for row in anchors if row['service_id'] not in {'cryptobot','xrocket'}}
    for row in valid.values():
        if (row.get('success') is not True or row.get('asset_key') not in STABLES
                or row.get('native_value_purpose')=='jetton_transfer_request'
                or not _stamp(row.get('timestamp')) or row['from_key']==row['to_key']):continue
        for key in (row['from_key'],row['to_key']):by_key[(key,row['asset_key'])].append(row)
    hypotheses=[];motifs=[];evidence=[];assessments=[]
    for (key,asset),rows in sorted(by_key.items(),key=lambda pair:(pair[0][0]!=target,pair[0]))[:96]:
        if key in known:continue  # existing service label is not a new P2P hypothesis
        rows=list({r['operation_id']:r for r in rows}.values())
        incoming=[r for r in rows if r['to_key']==key];outgoing=[r for r in rows if r['from_key']==key]
        senders=Counter(r['from_key'] for r in incoming);recipients=Counter(r['to_key'] for r in outgoing)
        deps={r.get('dependency_group') or r['blockchain']+':tx:'+r['transaction_hash'] for r in rows}
        dates={r['timestamp'][:10] for r in rows};bilateral=set(senders)&set(recipients)
        repeated=sum(count for count in Counter(r['amount_decimal'] for r in rows).values() if count>=3)
        recurring={other for other in bilateral if senders[other]>=2 and recipients[other]>=2}
        known_ops=[r for r in rows if r['from_key'] in exchange_known or r['to_key'] in exchange_known]
        groups_in={r['transaction_hash'] for r in incoming};groups_out={r['transaction_hash'] for r in outgoing}
        checks={
          'possible_p2p_activity':{'three_recurrent_bilateral_counterparties':len(recurring)>=3,'two_utc_dates':len(dates)>=2,'repeated_denominations':repeated>=6,'ten_physical_operations':len(deps)>=10},
          'possible_payment_processor':{'five_sender_addresses':len(senders)>=5,'five_receiver_addresses':len(recipients)>=5,'twenty_physical_operations':len(deps)>=20,'two_utc_dates':len(dates)>=2,'repeated_denominations':repeated>=3},
          'possible_settlement_wallet':{'two_recurrent_bilateral_counterparties':len(recurring)>=2,'three_utc_dates':len(dates)>=3,'three_incoming_tx':len(groups_in)>=3,'three_outgoing_tx':len(groups_out)>=3,'repeated_denominations':repeated>=3},
          'possible_distribution_wallet':{'five_outgoing_transactions':len(groups_out)>=5,'five_receiver_addresses':len(recipients)>=5,'two_incoming_transactions':len(groups_in)>=2,'outgoing_fanout_exceeds_incoming':len(recipients)>len(senders)*2},
          'possible_exchange_operation':{'three_known_exchange_interactions':len({r['transaction_hash'] for r in known_ops})>=3,'three_other_counterparties':len((set(senders)|set(recipients))-known)>=3,'two_utc_dates':len(dates)>=2,'both_observed_directions':bool(incoming and outgoing)},
          'possible_otc_activity':{'independent_public_otc_role_evidence':False}}
        # A sampled transfer pattern does not provide off-chain OTC order evidence.
        qualified=[name for name,conditions in checks.items() if all(conditions.values())]
        priority=('possible_p2p_activity','possible_settlement_wallet','possible_distribution_wallet',
                  'possible_payment_processor','possible_exchange_operation','possible_otc_activity')
        category=next((name for name in priority if name in qualified),None)
        assessments.append({'address_key':key,'asset_key':asset,'selected':category or 'UNKNOWN','conditions':checks})
        if not category:continue
        refs=sorted({ref for r in rows for ref in r.get('evidence_ids',[])})
        hid=_id('behavior',key,asset,category);eid=hid+':evidence'
        facts={'category':category,'subject':key,'asset_key':asset,'asset_reference':STABLES[asset],
            'incoming_operations':len(incoming),'outgoing_operations':len(outgoing),'sender_addresses':len(senders),
            'receiver_addresses':len(recipients),'recurring_bilateral_addresses':sorted(recurring),
            'distinct_physical_transaction_groups':len(deps),'active_utc_dates':sorted(dates),
            'repeated_denomination_observations':repeated,'selected_rule_conditions':checks[category],
            'incoming_values':_exact([Decimal(r['amount_decimal']) for r in incoming]),
            'outgoing_values':_exact([Decimal(r['amount_decimal']) for r in outgoing]),
            'operations':[_edge(r) for r in sorted(rows,key=lambda r:(r['timestamp'],r['operation_id']))[:100]],
            'operations_display_truncated':len(rows)>100,'full_operation_ids':[r['operation_id'] for r in rows],
            'transaction_hashes':sorted({r['transaction_hash'] for r in rows}),'history_complete':False,
            'people_or_clients_count':'UNKNOWN','fiat_payment':'UNKNOWN','bank':'UNKNOWN','offchain_order':'UNKNOWN'}
        alternatives=['Business treasury, payroll, merchant settlement or an automated router.',
            'Independent customers may reuse a shared service; addresses are not independent persons.',
            'Partial history can omit competing flows; no bank, fiat payment or P2P order is established.']
        hypotheses.append({'id':hid,'hypothesis_id':hid,'subject':key,'claim_type':'behavioral_hypothesis',
            'claim':category.replace('_',' ')+'; observed stablecoin pattern, off-chain purpose unconfirmed.',
            'role':category,'confidence':'POSSIBLE','confidence_category':'POSSIBLE','status':'OPEN','method':METHOD,
            'evidence_ids':refs+[eid],'dependency_groups':sorted(deps),'supporting_observations':[facts],
            'alternative_explanations':alternatives,'address_control':'UNKNOWN','service_control':'UNKNOWN',
            'signing_application':'UNKNOWN','transaction_edge':False,'history_complete':False,
            'missing_evidence':['Independent business or order evidence','Unobserved alternative history'],
            'proposed_next_experiment':'Compare another disjoint history window and independently verify the commercial role.',
            'coverage':{'status':'PARTIAL','history_complete':False}})
        motifs.append({'motif_id':hid,'subject':key,'type':category,'evidence_ids':refs+[eid],**facts})
        evidence.append({'evidence_id':eid,'source':METHOD,'upstream':'existing_proven_financial_operations',
            'blockchain':key.split(':',1)[0],'address':key.split(':',1)[1],'relation':'behavioral_hypothesis',
            'facts':facts,'evidence_ids':refs,'source_urls':ASSET_REFERENCES})
    return {'hypotheses':hypotheses,'motifs':motifs,'evidence':evidence,'assessments':assessments,
        'coverage':{'status':'PARTIAL','subject_asset_limit':96,'stable_asset_matching':'exact_chain_and_contract_only',
            'category_selection':'one most specific qualifying category per subject/asset','offchain_order_inference':False}}


def attach_service_infrastructure(report,payload,data,valid,telegram_anchors):
    """Extend the same canonical inference fields and existing HTML inspectors."""
    from .telegram_services import _eligible_path
    from .graph_inference import analyze_graph_inference
    from .behavioral_profiles import analyze_behavioral_profiles
    from .service_role_patterns import discover_roles
    started=time.monotonic();target=payload.get('target_key')
    _retained_context_operations(report,data,valid)
    keys={k for op in valid.values() for k in (op['from_key'],op['to_key'])}
    labels=_reference_rows(keys)
    anchors=[*telegram_anchors,*[_anchor(row) for row in labels]]
    anchors=list({(r['service_id'],r['address_key']):r for r in anchors}.values())
    inference=payload.setdefault('inferential_intelligence',{})
    for field in ('relationships','hypotheses','motifs','clusters'):
        inference[field]=[row for row in inference.get(field,[]) if row.get('method')!=METHOD and row.get('method')!='service_infrastructure_typed_roles']
    payload['relationships']=[row for row in payload.get('relationships',[]) if row.get('method') not in {METHOD,'service_infrastructure_typed_roles'}]
    evidence={row['evidence_id']:row for row in payload.get('evidence',[]) if row.get('evidence_id') and row.get('source') not in {METHOD,'service_infrastructure_typed_roles'}}
    all_addresses=payload.setdefault('addresses',{})
    reference_index={}
    for anchor in anchors:
        if anchor['service_id'] in {'cryptobot','xrocket'}:continue
        label=anchor['source_record'];key=anchor['address_key']
        eid=_id('reference',key,anchor['service_id'],anchor['publication_url'],anchor['capture_sha256'])
        evidence[eid]={'evidence_id':eid,'source':label.get('source'),'upstream':label.get('upstream'),
            'url':anchor['publication_url'],'blockchain':anchor['blockchain'],'address':anchor['address'],
            'observed_at':anchor['observed_at'],'relation':'published_exact_service_reference','facts':label,
            'source_independence':'One registry/publication reference; not current operator control proof.'}
        reference_index[(anchor['service_id'],key)]=eid
        record=all_addresses.setdefault(key,{'address_key':key,'address':anchor['address'],'blockchain':anchor['blockchain'],
            'attributions':[],'contract':{'kind':'unknown'},'conflicts':[],'evidence_ids':[]})
        claim={'attribution_id':eid,'service_id':anchor['service_id'],'entity_name':anchor['service'],
            'name':anchor['service'],'entity_type':'published_service_reference','relationship':'publicly_labeled_address',
            'status':'PROBABLE','method':METHOD,'reason':'Exact published address reference; current/historical controller is unconfirmed.',
            'source_url':anchor['publication_url'],'source_urls':[anchor['publication_url']],'evidence_ids':[eid],
            'published_role':anchor['role'],'current_control':'UNKNOWN','source_published_at':anchor['source_published_at'],
            'valid_from':anchor.get('valid_from'),'valid_to':anchor.get('valid_to')}
        record['attributions']=[c for c in record.get('attributions',[]) if c.get('method')!=METHOD or c.get('service_id')!=anchor['service_id']]
        record['attributions'].append(claim)
    data['addresses']=all_addresses
    economic={key:row for key,row in valid.items() if row.get('native_value_purpose')!='jetton_transfer_request'
              and Decimal(str(row.get('amount_decimal') or '0'))>0 and row.get('from_key')!=row.get('to_key')}
    view={**data,'operations':list(economic.values()),'target_keys':[target]}
    # Same bounded graph/profile algorithms, now with the already verified pool;
    # older normalized data can be truncated before service repair completes it.
    graph=analyze_graph_inference(view,max_seconds=.7,max_paths=100)
    for field,identifier in (('clusters','cluster_id'),('hypotheses','hypothesis_id'),('relationships','relationship_id')):
        inference[field]=list({row[identifier]:row for row in [*inference.get(field,[]),*graph.get(field,[])] if row.get(identifier)}.values())
    paths={p.get('path_id'):p for p in [*inference.get('paths',[]),*graph.get('paths',[])] if p.get('path_id')}
    # Existing one-hop records must not consume the role analyzer's route cap
    # before already validated two/three-hop paths reach it.
    ordered_paths=sorted(paths.values(),key=lambda p:(_eligible_path(p,economic) is None,
                         target not in (p.get('nodes') or []),len(p.get('operation_ids') or [])))
    local_inference={**inference,'paths':ordered_paths}
    for proof in graph.get('evidence',[]):evidence[proof['evidence_id']]=proof
    data['_service_evidence_index']=evidence
    data['evidence']=list(evidence.values())
    findings=[];seen=set()
    for anchor in anchors:
        if anchor['service_id'] in {'cryptobot','xrocket'}:continue
        key=anchor['address_key'];publication=reference_index[(anchor['service_id'],key)]
        cases=[([row],[row['from_key'],row['to_key']],None) for row in economic.values()
               if target!=key and {row['from_key'],row['to_key']}=={target,key}]
        for path in paths.values():
            checked=_eligible_path(path,economic)
            if checked:
                rows,nodes=checked
                if (nodes[0]==target and nodes[-1]==key or nodes[0]==key and nodes[-1]==target):cases.append((rows,nodes,path))
        for rows,nodes,path in cases:
            identity=(anchor['service_id'],key,tuple(r['operation_id'] for r in rows))
            if identity in seen:continue
            seen.add(identity)
            direct=path is None;is_exchange=anchor['service_id'] not in {'fixedfloat','changelly','coinpaymentsnet'}
            category=('DIRECT EXCHANGE INTERACTION' if is_exchange else 'DIRECT EXCHANGE-SERVICE INTERACTION') if direct else 'INDIRECT SERVICE CONNECTION'
            direction='outgoing' if nodes[0]==target else 'incoming'
            label_date=anchor.get('source_published_at')
            temporal=('publication_postdates_operation' if label_date and any(r['timestamp'][:10]<str(label_date)[:10] for r in rows)
                      else 'publication_available_at_operation' if label_date else 'label_date_unknown')
            refs=list(dict.fromkeys([publication]+[ref for r in rows for ref in r['evidence_ids']]+((path or {}).get('evidence_ids') or [])))
            findings.append({'relationship_id':_id('connection',identity),'from_key':target,'to_key':key,
                'blockchain':anchor['blockchain'],'members':nodes,'type':category+' — '+anchor['service'],
                'category':category,'scope':'interacts_with','graph_scope':'economic' if direct else 'analytic',
                'status':'PROBABLE' if direct else 'POSSIBLE','service_id':anchor['service_id'],'service':anchor['service'],
                'method':METHOD,'direction':direction,'nodes':nodes,'hop_count':len(rows),
                'published_role':anchor['role'],'reference_url':anchor['publication_url'],'label_temporal_scope':temporal,
                'label_status':'PROBABLE','target_control':'UNKNOWN','current_anchor_control':'UNKNOWN',
                'claim_scope':'source_proven_transfer_with_published_reference' if direct else 'source_proven_chronological_route_not_exact_funds',
                'transaction_hashes':[row['transaction_hash'] for row in rows],'edges':[_edge(row) for row in rows],
                'evidence_ids':refs,'transaction_edge':False,'exact_funds_traced':False,'history_complete':False,
                'reason':category+'; physical transfers and publication prove separate facts. No customer account, P2P order or common controller is inferred.',
                'alternative_explanations':['Customer deposit/withdrawal, treasury, refund, merchant settlement or third-party routing.']})
    existing=(payload.get('telegram_service_intelligence') or {}).get('possible_service_infrastructure',[])
    # Supply the current engine's forwarding motifs for new exchange candidates.
    behavior=analyze_behavioral_profiles(view,max_seconds=.5,max_profiles=64,max_comparisons=0)
    for proof in behavior.get('evidence',[]):evidence[proof['evidence_id']]=proof
    seeds=list(existing)
    for motif in behavior.get('motifs',[]):
        matching=[a for a in anchors if a['address_key']==motif.get('recipient_key')]
        for anchor in matching:
            if anchor['service_id'] in {'cryptobot','xrocket'}:continue
            sequences=[{'sequence_id':_id('motif-sequence',p['incoming_operation_id'],p['outgoing_operation_id']),
                'incoming':{'operation_id':p['incoming_operation_id']},'outgoing':{'operation_id':p['outgoing_operation_id']},
                'balance_conservation_verified':False} for p in motif.get('pairs',[])]
            seeds.append({'candidate_id':motif['motif_id'],'service_id':anchor['service_id'],'address_key':motif['subject'],
                'official_anchor_key':anchor['address_key'],'observed_sequences':sequences})
    roles=discover_roles(data,economic,anchors,seeds,local_inference,target)
    behavior_new=_behavioral_hypotheses(data,valid,anchors,target)
    for proof in [*roles['evidence'],*behavior_new['evidence']]:evidence[proof['evidence_id']]=proof
    for relation in roles['relationships']:
        relation['scope']='shared_infrastructure_supported'
        relation['reason']='Possible operational role with source-bound repeated flows; common control remains UNKNOWN.'
    hypothesis_rows=[]
    for hypothesis in roles['hypotheses']:
        candidate=next(c for c in roles['candidates'] if c['service_id']==hypothesis['service_id'] and c['address_key']==hypothesis['subject'])
        hypothesis_rows.append({**hypothesis,'id':hypothesis['hypothesis_id'],'confidence':'POSSIBLE','confidence_category':'POSSIBLE',
            'status':'OPEN','claim':hypothesis['role']+' — '+candidate['service']+'; current control UNKNOWN.',
            'supporting_observations':[candidate],'alternative_explanations':candidate['alternatives'],
            'missing_evidence':['Independent address-specific operator confirmation','Complete historical role boundaries'],
            'coverage':{'status':'PARTIAL','history_complete':False},'address_control':'UNKNOWN','signing_application':'UNKNOWN'})
    inference.setdefault('hypotheses',[]).extend([*hypothesis_rows,*behavior_new['hypotheses']])
    inference.setdefault('motifs',[]).extend(behavior_new['motifs'])
    inference.setdefault('relationships',[]).extend([*findings,*roles['relationships']])
    inference['paths']=ordered_paths
    payload['relationships'].extend([*findings,*roles['relationships']])
    inference.setdefault('method_coverage',{})['service_infrastructure']={
        'status':'PARTIAL','operation_pool':len(valid),'reference_labels':len(labels),'direct_indirect_findings':len(findings),
        'typed_roles':roles['coverage'],'behavior':behavior_new['coverage'],
        'behavioral_assessments':behavior_new['assessments'],'network_requests':0,'elapsed_seconds':time.monotonic()-started}
    inference.setdefault('stats',{})['hypotheses']=len(inference['hypotheses'])
    payload['evidence']=list(evidence.values())
    payload.setdefault('source_observations',{}).update(data['source_observations'])
    payload['service_infrastructure_intelligence']={'findings':findings,'candidates':roles['candidates'],
        'behavioral_hypotheses':behavior_new['hypotheses'],'coverage':inference['method_coverage']['service_infrastructure']}
    return payload['service_infrastructure_intelligence']
