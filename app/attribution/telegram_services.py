"""Crypto Bot/xRocket evidence projection over Gansar's existing observations.

No HTTP, storage, wallet-app changes, new graph algorithms, or label propagation.
The optional caller hook is deliberately separate from this two-service layer.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from datetime import datetime,timezone
from decimal import Decimal,InvalidOperation
from pathlib import Path

from .normalize import address_id,canonical_address,normalize_chain,EVM_CHAINS
from .service_operations import validate_account_operation,validate_utxo_observation,source_time_matches,ton_native_execution,repair_ton_native_observations
from .inference import build_inference_data

SERVICES={'cryptobot':'Crypto Bot','xrocket':'xRocket'}
SERVICE_ALIASES={'crypto_bot':'cryptobot','cryptobot':'cryptobot','xrocket_bot':'xrocket','xrocket':'xrocket',
    'xrocket_bot_old':'xrocket','xrocket_bot_cold_storage':'xrocket','xrocket_bot_cold_storage_old':'xrocket'}
CATALOGUE=Path(__file__).with_name('assets')/'telegram_service_anchors.json'
LIMITATIONS=[
    'Official publications confirm the cited role/date; provider labels remain PROBABLE and do not authenticate current operator control.',
    'Transfers and routes do not establish a service account, common owner, wallet application or physical person.',
    'Only retained history is examined; absence of a result does not exclude service use.',
    'A temporal same-asset route does not prove allocation of the same funds through an intermediary.',
]
ALTERNATIVES=['Ordinary customer payment or refund','Exchange/payment intermediary',
              'Shared counterparty or another service','Pre-existing intermediary balance or unrelated onward transfer']
DISCOVERY_LIMITS={'max_candidates':64,'max_existing_paths':100,'max_seconds':1.0,
    'minimum_role_transactions':5,'minimum_diverse_counterparties':3,
    'minimum_role_transactions_outside_service_route':2,
    'minimum_active_utc_dates_for_distribution':2,'role_window_around_service_days':90,
    'minimum_native_role_amount':'0.001'}

def _eligible_path(path,valid):
    """Validate an existing path; never generate, extend, or traverse a graph."""
    from .graph_inference import MAX_ROUTE_DELAY
    ids=path.get('operation_ids') or []
    if not isinstance(ids,list) or not 2<=len(ids)<=3 or not all(identifier in valid for identifier in ids):return None
    rows=[valid[identifier] for identifier in ids]
    nodes=[rows[0]['from_key']]+[row['to_key'] for row in rows]
    if len(set(nodes))!=len(nodes):return None
    if len({row['transaction_hash'] for row in rows})!=len(rows):return None
    for before,after in zip(rows,rows[1:]):
        if before['to_key']!=after['from_key'] or before['asset_key']!=after['asset_key']:return None
        delay=(_timestamp(after['timestamp'])-_timestamp(before['timestamp'])).total_seconds()
        if not 0<delay<=MAX_ROUTE_DELAY:return None
    return rows,nodes

def _discover_infrastructure(data,valid,inference,anchors,target,evidence):
    """Project two-service role hypotheses from collected operations and paths.

    Candidate membership is local to the present evidence, never a new anchor.
    Repetition is independent by physical transaction, not provider or row count.
    """
    started=time.monotonic();deadline=started+DISCOVERY_LIMITS['max_seconds']
    incident=defaultdict(list)
    for row in valid.values():
        if row['from_key']==row['to_key']:continue
        incident[row['from_key']].append(row);incident[row['to_key']].append(row)
    anchor_keys={anchor['address_key'] for anchor in anchors}
    bindings=defaultdict(list);paths=[]
    for path in inference.get('paths',[])[:DISCOVERY_LIMITS['max_existing_paths']]:
        checked=_eligible_path(path,valid)
        if checked and all(ref in evidence for ref in path.get('evidence_ids',[])):
            paths.append((path,*checked))
    for anchor in anchors:
        key=anchor['address_key'];published=_timestamp(anchor['source_published_at'])
        for row in incident.get(key,[]):
            if _timestamp(row['timestamp'])<published:continue
            if not _role_amount(row):continue
            other=row['to_key'] if row['from_key']==key else row['from_key']
            if other not in anchor_keys:bindings[(anchor['service_id'],other,key)].append(([row],[row['from_key'],row['to_key']],[]))
        for path,rows,nodes in paths:
            if key not in (nodes[0],nodes[-1]) or any(_timestamp(row['timestamp'])<published for row in rows):continue
            if any(not _role_amount(row) for row in rows):continue
            for other in nodes:
                if other not in anchor_keys:bindings[(anchor['service_id'],other,key)].append((rows,nodes,path.get('evidence_ids',[])))
    candidates=[];rejected=[];truncated=False
    anchor_index={(anchor['service_id'],anchor['address_key']):anchor for anchor in anchors}
    # Prefer the investigated target, then candidates actually on its ready paths.
    ordered_bindings=sorted(bindings,key=lambda entry:(entry[1]!=target,entry))
    ordered=ordered_bindings[:DISCOVERY_LIMITS['max_candidates']]
    truncated=len(ordered)<len(ordered_bindings)
    # The generic correlator may only discover native outgoing participants in
    # its later normalizer, after its dataset step. Read the existing local
    # catalogue for counterevidence only; never introduce a new service label.
    counter_labels=defaultdict(list);counter_label_status='available'
    relevant=set()
    for _,key,_ in ordered:
        relevant.add(key)
        relevant.update(row['to_key'] for row in incident.get(key,[]))
    try:
        from .datasets import lookup_dataset_records
        # All keys come from the already bounded collected-operation corpus.
        # Do not silently omit a candidate/competing payee by lexical order.
        for label in lookup_dataset_records(relevant):
            label_key=address_id(label.get('blockchain'),label.get('address'))
            counter_labels[label_key].append({'service_id':label.get('entity_id'),'name':label.get('entity_name'),
                'category':label.get('entity_type','public_address_label'),'status':label.get('status','PROBABLE'),
                'method':'existing_public_catalogue_counterevidence','source_url':label.get('source_url'),
                'content_hash':label.get('content_hash'),'authority':label.get('authority')})
    except (OSError,ValueError,TypeError):counter_label_status='unavailable; do not infer ownership from omitted labels'
    for service,key,anchor_key in ordered:
        if time.monotonic()>deadline or len(candidates)>=DISCOVERY_LIMITS['max_candidates']:
            truncated=True;break
        anchor=anchor_index[(service,anchor_key)]
        grouped=defaultdict(list)
        published=_timestamp(anchor['source_published_at'])
        for row in incident.get(key,[]):
            if _timestamp(row['timestamp'])<published or not _role_amount(row):continue
            grouped[row['asset_key']].append(row)
        for asset,rows in grouped.items():
            if time.monotonic()>deadline:truncated=True;break
            bound=[route for route in bindings[(service,key,anchor_key)] if route[0][0]['asset_key']==asset]
            if not bound:continue
            binding_times=[_timestamp(row['timestamp']) for route in bound for row in route[0]
                           if key in {row['from_key'],row['to_key']}]
            available_rows=len(rows)
            rows=[row for row in rows if any(abs((_timestamp(row['timestamp'])-stamp).total_seconds())<=DISCOVERY_LIMITS['role_window_around_service_days']*86400 for stamp in binding_times)]
            incoming=[row for row in rows if row['to_key']==key]
            outgoing=[row for row in rows if row['from_key']==key]
            in_senders={row['from_key'] for row in incoming};out_recipients={row['to_key'] for row in outgoing}
            incoming_tx={row['transaction_hash'] for row in incoming};outgoing_tx={row['transaction_hash'] for row in outgoing}
            all_tx=incoming_tx|outgoing_tx;dates={row['timestamp'][:10] for row in rows}
            unique_bound={tuple(row['operation_id'] for row in route[0]):route for route in bound}
            independent=[];used=set()
            for route in sorted(unique_bound.values(),key=lambda item:(target not in (item[1][0],item[1][-1]),target not in item[1],len(item[0]),tuple(row['operation_id'] for row in item[0]))):
                dependencies={row['transaction_hash'] for row in route[0]}
                if used&dependencies:continue
                independent.append(route);used.update(dependencies)
            outside=all_tx-used
            role=[]
            collection=(len(incoming_tx)>=3 and len(in_senders)>=3 and len(outgoing_tx)>=2)
            distribution=(len(outgoing_tx)>=3 and len(out_recipients)>=3 and len(incoming_tx)>=2 and len(dates)>=2)
            if collection:role.append('deposit_or_consolidation_candidate')
            if distribution:role.append('withdrawal_or_distribution_candidate')
            if not role or len(all_tx)<DISCOVERY_LIMITS['minimum_role_transactions'] or len(outside)<2:
                rejected.append({'service_id':service,'address':key.split(':',1)[1],'address_key':key,'asset_key':asset,
                    'category':'SERVICE INTERACTION','infrastructure_status':'UNKNOWN',
                    'reason':'A concrete service route exists, but diverse recurring collection/distribution and separate role transactions are insufficient.',
                    'independent_transactions':len(all_tx),'incoming_transactions':len(incoming_tx),'outgoing_transactions':len(outgoing_tx),
                    'incoming_counterparties':len(in_senders),'outgoing_counterparties':len(out_recipients),
                    'service_bound_disjoint_routes':len(independent),'service_control':'UNKNOWN'})
                continue
            record=data['addresses'].get(key,{})
            counterclaims=[{'service_id':claim.get('service_id'),'name':claim.get('name') or claim.get('entity_name'),
                           'status':claim.get('status'),'method':claim.get('method'),'category':claim.get('category') or claim.get('entity_type')}
                for claim in [*record.get('attributions',[]),*counter_labels.get(key,[])] if SERVICE_ALIASES.get(claim.get('service_id'),claim.get('service_id')) not in {service,None}]
            conflicting=[claim for claim in counterclaims if claim.get('category')!='public_address_label' and
                         claim.get('status') in {'PROBABLE','CONFIRMED'} and not str(claim.get('service_id','')).startswith(('label:','registry:'))]
            degree=len(in_senders|out_recipients)
            from .graph_inference import MAX_NEIGHBORS
            ambiguous_public_hub=degree>MAX_NEIGHBORS and bool(counterclaims)
            if conflicting or ambiguous_public_hub:
                rejected.append({'service_id':service,'address':key.split(':',1)[1],'address_key':key,'category':'SERVICE INTERACTION',
                    'infrastructure_status':'UNKNOWN','reason':'Shared high-degree hub or conflicting published service/protocol attribution; no service infrastructure inference.',
                    'counterparty_degree':degree,'contradicting_claims':conflicting,'independent_transactions':len(all_tx)})
                continue
            # Published competing destinations are counterevidence, not a new
            # detector or an attribution of their users. A predominantly paid
            # marketplace/shared service is not a withdrawal-recipient set.
            destinations=defaultdict(set)
            for row in outgoing:destinations[row['to_key']].add(row['transaction_hash'])
            dominant=max(destinations,key=lambda dest:len(destinations[dest]),default=None)
            competing_destinations=[]
            if dominant and len(destinations[dominant])*5>=len(outgoing_tx)*4:
                competing_destinations=[{'address_key':dominant,'service_id':claim.get('service_id'),
                    'name':claim.get('name') or claim.get('entity_name'),'status':claim.get('status')}
                    for claim in [*data['addresses'].get(dominant,{}).get('attributions',[]),*counter_labels.get(dominant,[])]
                    if claim.get('status') in {'PROBABLE','CONFIRMED'} and
                    SERVICE_ALIASES.get(claim.get('service_id'),claim.get('service_id')) not in {service,None}]
            if competing_destinations and len(independent)<2:
                rejected.append({'service_id':service,'address':key.split(':',1)[1],'address_key':key,'category':'SERVICE INTERACTION',
                    'infrastructure_status':'UNKNOWN','reason':'Predominant outgoing payments to another publicly labelled service; trader/shared-destination alternative and single anchor route.',
                    'competing_destinations':competing_destinations,'independent_transactions':len(all_tx),
                    'meaningful_incoming_counterparties':len(in_senders),'meaningful_outgoing_counterparties':len(out_recipients)})
                continue
            # Conservative by design: operation count and common patterns cannot
            # authenticate the operator; no on-chain-only PROBABLE promotion.
            status='POSSIBLE'
            observed_ids={row['operation_id'] for row in rows}
            motifs=[motif for motif in inference.get('motifs',[])[:100]
                    if motif.get('subject')==key and motif.get('asset_key')==asset]
            refs=sorted({ref for row in rows for ref in row.get('evidence_ids',[])})
            route_refs=sorted({ref for route in independent for row in route[0] for ref in row.get('evidence_ids',[])}|
                              {ref for route in independent for ref in route[2]})
            stamps=sorted(row['timestamp'] for row in rows)
            candidate={'candidate_id':_identifier('infrastructure',[service,key,asset,anchor_key]),'service_id':service,
                'service':SERVICES[service],'blockchain':anchor['blockchain'],'address':key.split(':',1)[1],'address_key':key,
                'category':'POSSIBLE SERVICE INFRASTRUCTURE','status':status,'roles':role,'asset_key':asset,
                'method':'cryptobot_xrocket_collected_infrastructure_discovery','service_control':'UNKNOWN',
                'current_control':'UNKNOWN','signing_application':'UNKNOWN','confirmed_anchor':False,
                'official_anchor_key':anchor_key,'official_anchor_address':anchor['address'],
                'official_publication_url':anchor['publication_url'],'official_publication_date':anchor['source_published_at'],
                'basis':'Independently observed recurring collection/distribution plus a physical route to an officially published role address.',
                'observations':{'independent_transaction_count':len(all_tx),'physical_operation_count':len(observed_ids),'physical_message_count':sum(bool(r.get('message_hash')) for r in rows),
                    'incoming_transactions':len(incoming_tx),'outgoing_transactions':len(outgoing_tx),
                    'incoming_counterparties':len(in_senders),'outgoing_counterparties':len(out_recipients),
                    'active_utc_dates':sorted(dates),'independent_service_bound_routes':len(independent),
                    'role_transactions_outside_service_routes':len(outside),
                    'valid_role_operations_outside_90_day_windows':available_rows-len(rows),
                    'official_operator_publications':1,'independent_operator_control_confirmations':0},
                'first_observed':stamps[0],'last_observed':stamps[-1],
                'transaction_hashes':sorted(all_tx),'evidence_ids':refs+route_refs,
                'role_operations':[{field:row.get(field) for field in ('operation_id','transaction_hash','message_hash','from_key','to_key',
                    'asset_key','amount_decimal','timestamp','evidence_ids','source_url')} for row in sorted(rows,key=lambda item:item['timestamp'])[:100]],
                'role_operations_display_truncated':len(rows)>100,
                'service_routes':[{'nodes':nodes,'hop_count':len(route),'transaction_hashes':[row['transaction_hash'] for row in route],
                    'edges':[{field:row.get(field) for field in ('operation_id','transaction_hash','from_key','to_key','asset_key','amount_decimal','timestamp','evidence_ids','source_url')}
                             for row in route],'evidence_ids':path_refs,'exact_funds_traced':False}
                    for route,nodes,path_refs in independent[:12]],
                'existing_behavioral_motif_ids':[motif.get('motif_id') for motif in motifs],
                'contradicting_observations':counterclaims+([{'kind':'single_service_route','scope':'One route is insufficient by itself; classification also requires separate repeated role operations.'}] if len(independent)==1 else [])+
                    ([{'kind':'high_degree_endpoint','degree':degree,'scope':'Distribution role only; existing graph never expanded this hub to associate its unrelated customers.'}] if degree>MAX_NEIGHBORS else []),
                'alternative_explanations':ALTERNATIVES+['Personal wallet collecting/rebalancing payments','Unrelated automated payroll, merchant, airdrop or treasury operator'],
                'missing_evidence':['Independent address-specific service operator/role confirmation','Complete historical balances and competing routes',
                                    'Customer deposit/withdrawal assignment; temporal flow is not allocation proof'],
                'history_complete':False,'exact_funds_traced':False,
                'limitations':LIMITATIONS+['POSSIBLE infrastructure is a role hypothesis, not a member of a confirmed service ownership cluster.']}
            candidate['evidence_ids']=list(dict.fromkeys(refs+route_refs))
            candidates.append(candidate)
    return candidates,rejected[:128],{'status':'TRUNCATED' if truncated else 'PARTIAL','candidate_limit':DISCOVERY_LIMITS['max_candidates'],
        'max_seconds':DISCOVERY_LIMITS['max_seconds'],'elapsed_seconds':time.monotonic()-started,
        'existing_paths_examined':len(paths),'candidate_bindings_available':len(ordered_bindings),
        'candidate_bindings_selected':len(ordered),'candidate_asset_sets_examined':len(candidates)+len(rejected),
        'confirmed_candidates_added_to_catalogue':0,'label_propagation':False,'new_graph_algorithms':0,
        'thresholds':DISCOVERY_LIMITS,'input_coverage':data.get('coverage',{}),
        'runtime_http_requests':0,'counterlabel_lookup_status':counter_label_status,
        'counterlabel_keys_checked':len(relevant) if counter_label_status=='available' else 0,
        'missing_neighbor_history_policy':'No inferred edge; requires histories already collected by the existing bounded planner.'}

def _identifier(kind,value):
    return 'telegram-service:'+kind+':'+hashlib.sha256(json.dumps(value,sort_keys=True,default=str).encode()).hexdigest()

def _timestamp(value):
    try:
        stamp=datetime.fromisoformat(str(value).replace('Z','+00:00'))
        return stamp.astimezone(timezone.utc) if stamp.tzinfo else None
    except (ValueError,TypeError):return None

def _digest(value):
    from app.ton_nft.analytics import canonical_hash
    result=canonical_hash(value)
    return result if isinstance(result,str) and len(result)==64 and all(c in '0123456789abcdef' for c in result) else None

def _catalogue():
    # This is a curated, shipped exact-address list, never provider metadata.
    try:data=json.loads(CATALOGUE.read_text(encoding='utf-8'))
    except (OSError,ValueError):return []
    if not isinstance(data,dict) or data.get('schema_version')!='1.0':return []
    accepted=[]
    for row in data.get('anchors',[])[:32]:
        if not isinstance(row,dict):continue
        service=row.get('service_id');chain=row.get('blockchain')
        address=canonical_address(chain,row.get('address'))
        if service not in SERVICES or not address or row.get('authority') not in {
            'official_operator_publication','official_operator_publication_with_exact_chain_transaction_binding'}:continue
        chain=normalize_chain(chain)
        if not _timestamp(row.get('source_published_at')) or not _timestamp(row.get('observed_at')) or not _digest(row.get('capture_sha256')):continue
        from urllib.parse import urlsplit
        url=urlsplit(row.get('publication_url',''))
        if url.scheme!='https' or url.hostname!='t.me':continue
        prefix='/CryptoBotRU/' if service=='cryptobot' else '/xrocketnews/'
        if not url.path.startswith(prefix) or not url.path[len(prefix):].isdigit():continue
        if row['authority']=='official_operator_publication_with_exact_chain_transaction_binding':
            binding=row.get('derived_address_basis') or {}
            if (binding.get('native_account')!=address or not _digest(binding.get('transaction_hash')) or
                binding.get('transaction_hash')!=row.get('cited_transaction_hash') or binding.get('source_success') is not True or
                not _digest(binding.get('source_sha256'))):continue
        accepted.append({**row,'blockchain':chain,'address':address,'address_key':address_id(chain,address),
            'label_status':'CONFIRMED','reference_kind':'official_publication'})
    return accepted

def _service_data(report,payload):
    """Reuse the correlator's exact current operation proofs before rebuilding.

    Re-parsing all neighbor reports can consume the normalizer budget before it
    reaches any target transaction. The immediately preceding inference already
    retained these physical observations with raw-reference bindings.
    """
    operations={};utxo={}
    evidence=payload.get('evidence') or []
    pool=payload.get('source_observations') or {}
    for proof in evidence:
        facts=proof.get('facts') or {};reference=facts.get('raw_reference') or {}
        source=pool.get(reference.get('source_observation_id'))
        if not isinstance(source,dict) or source.get('blockchain')!=proof.get('blockchain'):continue
        if proof.get('relation')=='inference_operation_observation' and facts.get('operation_id'):
            row={k:v for k,v in facts.items() if k!='raw_reference'}
            row['evidence_ids']=list(dict.fromkeys([*row.get('evidence_ids',[]),proof['evidence_id']]))
            operations[row['operation_id']]=row
        elif proof.get('relation')=='utxo_bipartite_observation' and facts.get('transaction_key'):
            row={k:v for k,v in facts.items() if k!='raw_reference'};row['evidence_ids']=[proof['evidence_id']]
            utxo[row['transaction_key']]=row
    if operations or utxo or report.transactions:
        coverage=dict((payload.get('inferential_intelligence') or {}).get('coverage') or {})
        if not (operations or utxo) or coverage.get('transactions_examined',0)<len(report.transactions):
            from app.utils.event_identity import event_identity
            covered={(proof.get('facts') or {}).get('raw_reference',{}).get('event_id') for proof in evidence
                if (proof.get('facts') or {}).get('raw_reference',{}).get('source_observation_id') in pool}
            missing=[tx for tx in report.transactions if event_identity(tx) not in covered]
            # Normalize genuine current-report records before another neighbor
            # pass. Typed transfers precede large fan-out native transactions;
            # the actual report, source records and financial ordering stay put.
            ordered=sorted(missing,key=lambda tx:(not isinstance((tx.raw or {}).get('transfer'),dict),
                len(((tx.raw or {}).get('transaction') or {}).get('out_msgs') or [])))
            view=report.model_copy(update={'transactions':ordered,'attribution_intelligence':{}})
            current=build_inference_data(view,payload,max_seconds=8.0)
            for row in current['operations']:
                prior=operations.setdefault(row['operation_id'],row)
                prior['evidence_ids']=list(dict.fromkeys([*prior.get('evidence_ids',[]),*row.get('evidence_ids',[])]))
            for row in current['utxo_transactions']:utxo.setdefault(row['transaction_key'],row)
            evidence=list({row['evidence_id']:row for row in [*evidence,*current['evidence']]}.values())
            pool={**pool,**current['source_observations']}
            coverage['current_report_addendum']=current['coverage']
        return {'operations':list(operations.values()),'utxo_transactions':list(utxo.values()),
            'evidence':evidence,'source_observations':pool,'addresses':payload.get('addresses') or {},
            'coverage':{**coverage,'service_projection_input':'current_correlator_proofs_plus_missing_current_report_observations'}}
    return build_inference_data(report,payload,max_seconds=8.0)

def _dedupe_anchors(rows):
    result={}
    for row in rows:
        key=(row['service_id'],row['address_key'])
        if key not in result or row.get('label_status')=='CONFIRMED':result[key]=row
    return list(result.values())

def _public_labels(data,payload):
    """Exact retained catalogue assertions, separated from official anchors."""
    out=[]
    proofs={row.get('evidence_id'):row for row in payload.get('evidence',[])}
    for key,record in data.get('addresses',{}).items():
        chain=record.get('blockchain');address=canonical_address(chain,record.get('address'))
        if not address or address_id(chain,address)!=key:continue
        for claim in record.get('attributions',[]):
            service=SERVICE_ALIASES.get(claim.get('service_id'))
            if service not in SERVICES or claim.get('status') not in {'PROBABLE','CONFIRMED'}:continue
            for ref in claim.get('evidence_ids',[]):
                proof=proofs.get(ref,{})
                if proof.get('relation')!='published_exact_address_label' or address_id(chain,proof.get('address'))!=key:continue
                facts=proof.get('facts') or {};digest=_digest(facts.get('content_hash'))
                if normalize_chain(proof.get('blockchain'))!=normalize_chain(chain) or SERVICE_ALIASES.get(facts.get('entity_id'))!=service:continue
                if not digest or not _timestamp(proof.get('observed_at')) or not str(proof.get('url','')).startswith('https://'):continue
                out.append({'service_id':service,'blockchain':chain,'address':address,'address_key':key,
                    'label':claim.get('entity_name') or claim.get('name'),'role':'publicly_labelled_service_address',
                    'publication_url':proof['url'],'observed_at':proof['observed_at'],
                    'source_published_at':facts.get('source_published_at'),'capture_sha256':digest,
                    'authority':'community_public_address_registry','claim_scope':'public_provider_label_only',
                    'current_control':'UNKNOWN','label_status':'PROBABLE','reference_kind':'public_label'})
                break
    # The ordinary correlator's address budget may stop before an older funding
    # record. Resolve only exact endpoints already retained by this service pass.
    # This reuses the shipped registry, without a network search or owner votes.
    try:
        from .datasets import lookup_dataset_records
        keys={key for operation in data.get('operations',[]) for key in (operation.get('from_key'),operation.get('to_key')) if key}
        for label in lookup_dataset_records(keys):
            service=SERVICE_ALIASES.get(label.get('entity_id'));chain=normalize_chain(label.get('blockchain'))
            address=canonical_address(chain,label.get('address'));capture=_digest(label.get('upstream_content_hash') or label.get('content_hash'))
            if service not in SERVICES or not address or not capture or label.get('status') not in {'PROBABLE','CONFIRMED'}:continue
            if not _timestamp(label.get('observed_at')) or not str(label.get('source_url','')).startswith('https://'):continue
            out.append({'service_id':service,'blockchain':chain,'address':address,'address_key':address_id(chain,address),
                'label':label.get('entity_name'),'role':'publicly_labelled_service_address','publication_url':label['source_url'],
                'observed_at':label['observed_at'],'source_published_at':label.get('source_published_at'),'capture_sha256':capture,
                'authority':'community_public_address_registry','claim_scope':'public_provider_label_only',
                'source_record_sha256':label.get('content_hash'),'current_control':'UNKNOWN','label_status':'PROBABLE','reference_kind':'public_label'})
        data.setdefault('coverage',{})['service_reference_lookup']={'status':'available','current_operation_endpoint_keys':len(keys),
            'scope':'Exact two-service references from existing packaged registry; no ownership propagation'}
    except (OSError,ValueError,TypeError) as exc:
        data.setdefault('coverage',{})['service_reference_lookup']={'status':'unavailable','error_type':type(exc).__name__}
        payload.setdefault('errors',[]).append('cryptobot_xrocket: packaged service reference lookup unavailable: '+type(exc).__name__)
    try:catalogue=json.loads(CATALOGUE.read_text(encoding='utf-8'))
    except (OSError,ValueError):catalogue={}
    for row in catalogue.get('public_labels',[])[:64]:
        if not isinstance(row,dict):continue
        chain=normalize_chain(row.get('blockchain'));address=canonical_address(chain,row.get('address'))
        if row.get('service_id') not in SERVICES or not address or row.get('authority')!='provider_public_address_label':continue
        if not _digest(row.get('capture_sha256')) or not _timestamp(row.get('observed_at')) or not str(row.get('publication_url','')).startswith('https://'):continue
        out.append({**row,'blockchain':chain,'address':address,'address_key':address_id(chain,address),
            'label_status':'PROBABLE','reference_kind':'public_label','claim_scope':'public_provider_label_only','current_control':'UNKNOWN'})
    return out

def service_receipt_targets(chain):
    """Existing RPC enrichment may prove only already-observed exact endpoints."""
    return {row['address'] for row in _dedupe_anchors([*_catalogue(),*_public_labels({'addresses':{}},{})])
        if row['blockchain']==normalize_chain(chain)}

def _role_amount(row):
    amount=Decimal(row['amount_decimal'])
    return amount>=Decimal(DISCOVERY_LIMITS['minimum_native_role_amount']) if row.get('asset_key')=='ton:native' else amount>0

def _network_coverage(report,data,valid,utxo,anchors):
    chains=set(report.detected_chains)|{r.get('blockchain') for r in data['operations']}|{r.get('blockchain') for r in data['utxo_transactions']}
    return [{'blockchain':chain,'validated_operations':sum(r['blockchain']==chain for r in valid.values()),
        'validated_utxo_transactions':sum(r['blockchain']==chain for r in utxo),
        'observed_asset_keys':sorted({r['asset_key'] for r in data['operations'] if r['blockchain']==chain}|({chain+':native'} if any(r['blockchain']==chain for r in data['utxo_transactions']) else set())),
        'validated_asset_keys':sorted({r['asset_key'] for r in valid.values() if r['blockchain']==chain}|({chain+':native'} if any(r['blockchain']==chain for r in utxo) else set())),
        'unqualified_account_operations':sum(r['blockchain']==chain for r in data['operations'])-sum(r['blockchain']==chain for r in valid.values()),
        'official_role_addresses':sum(a['blockchain']==chain and a.get('label_status')=='CONFIRMED' for a in anchors),
        'public_label_addresses':sum(a['blockchain']==chain and a.get('label_status')=='PROBABLE' for a in anchors),
        'status':'PARTIAL','history_complete':False,
        'limitation':'No service inference from network or asset alone; exact service references and complete source proof are required.'}
        for chain in sorted(chains) if chain]

def _utxo_connections(utxo,anchors,target,evidence):
    result=[]
    try:catalogue=json.loads(CATALOGUE.read_text(encoding='utf-8'))
    except (OSError,ValueError):catalogue={}
    publications=[]
    for row in catalogue.get('published_transactions',[])[:64]:
        if not isinstance(row,dict) or row.get('blockchain')!='btc' or row.get('service_id') not in SERVICES:continue
        if row.get('authority')!='official_operator_transaction_publication' or not _digest(row.get('transaction_hash')):continue
        if not _digest(row.get('capture_sha256')) or not _timestamp(row.get('source_published_at')):continue
        from urllib.parse import urlsplit
        url=urlsplit(row.get('publication_url',''));prefix='/CryptoBotEN/' if row['service_id']=='cryptobot' else '/xrocketnews/'
        if url.scheme!='https' or url.hostname!='t.me' or not url.path.startswith(prefix) or not url.path[len(prefix):].isdigit():continue
        publications.append(row)
    for tx in utxo:
        inputs=set(tx['input_keys']);outputs=set(tx['output_keys'])
        if target not in inputs|outputs:continue
        source_url=next((evidence.get(ref,{}).get('url') for ref in tx['evidence_ids'] if evidence.get(ref,{}).get('url')),'')
        for publication in publications:
            if publication['transaction_hash']!=_digest(tx['transaction_hash']):continue
            ref=_identifier('transaction-publication',[publication['service_id'],tx['transaction_hash'],publication['capture_sha256']])
            evidence[ref]={'evidence_id':ref,'source':'official_service_transaction_publication','upstream':publication['service_id'],
                'url':publication['publication_url'],'observed_at':publication.get('source_observed_at'),
                'blockchain':'btc','transaction_hash':tx['transaction_hash'],'relation':'official_published_service_transaction',
                'facts':{key:publication.get(key) for key in ('role','source_published_at','capture_sha256','claim_scope','endpoint_role','current_address_control')},
                'source_independence':'Operator confirms the historical transaction purpose; no input/output address ownership is authenticated.'}
            result.append({'relationship_id':_identifier('published-utxo',[publication['service_id'],target,tx['transaction_hash']]),
                'target_key':target,'service_id':publication['service_id'],'service':SERVICES[publication['service_id']],
                'blockchain':'btc','category':'OFFICIALLY CITED CONSOLIDATION TRANSACTION','status':'CONFIRMED',
                'claim_scope':'historical_published_transaction_only','service_publication_url':publication['publication_url'],
                'source_published_at':publication['source_published_at'],'timestamp':tx['timestamp'],'source_url':source_url,
                'transaction_hash':tx['transaction_hash'],'transaction_edge':False,'allocation':'UNKNOWN','ownership':'UNKNOWN',
                'endpoint_role':'AMBIGUOUS','service_address_control':'UNKNOWN','inputs':tx['inputs'],'outputs':tx['outputs'],
                'evidence_ids':tx['evidence_ids'],'publication_evidence_ids':[ref],
                'reason':'This exact confirmed native transaction is cited by the operator as a historical consolidation; hot/change output roles and target ownership remain UNKNOWN.'})
        for anchor in anchors:
            if anchor['blockchain']!=tx['blockchain']:continue
            key=anchor['address_key']
            if not ((target in inputs and key in outputs) or (key in inputs and target in outputs)):continue
            ref=_identifier('utxo-address-publication',[anchor['service_id'],key,anchor['capture_sha256']])
            evidence[ref]={'evidence_id':ref,'source':'public_service_address_label','upstream':anchor['service_id'],
                'url':anchor['publication_url'],'observed_at':anchor['observed_at'],'blockchain':tx['blockchain'],
                'address':anchor['address'],'relation':'published_exact_address_label',
                'facts':{name:anchor.get(name) for name in ('role','capture_sha256','claim_scope','source_published_at')}}
            result.append({'relationship_id':_identifier('utxo-participation',[anchor['service_id'],target,key,tx['transaction_hash']]),
                'target_key':target,'service_id':anchor['service_id'],'service':SERVICES[anchor['service_id']],
                'blockchain':tx['blockchain'],'category':'SHARED UTXO TRANSACTION',
                'status':anchor.get('label_status','PROBABLE'),'anchor_label_status':anchor.get('label_status'),
                'service_address':anchor['address'],'service_publication_url':anchor['publication_url'],
                'transaction_hash':tx['transaction_hash'],'timestamp':tx['timestamp'],'source_url':source_url,
                'transaction_edge':False,'allocation':'UNKNOWN','ownership':'UNKNOWN',
                'inputs':tx['inputs'],'outputs':tx['outputs'],'evidence_ids':tx['evidence_ids'],'publication_evidence_ids':[ref],
                'reason':'Target and exact labelled service address occur on opposite sides of one native transaction; input/output allocation is UNKNOWN.'})
    return result

def _validated_ton_native_operation(operation,data):
    """Narrow TON native-coin proof gate, separate from generic normalization.

    TON native messages are sufficient for the verified corpus. Jetton/NFT
    requests, generic DTO amounts and other networks are not reinterpreted here.
    """
    if operation.get('blockchain')!='ton' or operation.get('asset_key')!='ton:native':return False
    if operation.get('success') is not True or not _digest(operation.get('transaction_hash')):return False
    if not _timestamp(operation.get('timestamp')) or not _digest(operation.get('message_hash')):return False
    try:
        amount=Decimal(str(operation.get('amount_decimal')))
        if not amount.is_finite() or amount<=0:return False
    except (InvalidOperation,ValueError):return False
    proofs=data.get('_service_evidence_index')
    if proofs is None:proofs={row.get('evidence_id'):row for row in data.get('evidence',[])}
    for ref in operation.get('evidence_ids',[]):
        proof=proofs.get(ref,{})
        raw_ref=(proof.get('facts') or {}).get('raw_reference') or {}
        raw=(data.get('source_observations',{}).get(raw_ref.get('source_observation_id')) or {}).get('raw') or {}
        native=raw.get('transaction')
        if not isinstance(native,dict):continue
        if any(container.get('emulated') is True or container.get('simulated') is True for container in (raw,native)):continue
        if not source_time_matches(operation,raw):continue
        native_hash=_digest(native.get('hash'))
        if not native_hash or native_hash!=_digest(operation['transaction_hash']):continue
        description=native.get('description') or {}
        if not isinstance(description,dict):continue
        if ton_native_execution(native) is not True:continue
        phases=[container.get(field) for container in (native,description)
                for field in ('compute_phase','compute_ph','action_phase','action')]
        if any(isinstance(phase,dict) and phase.get('success') is False for phase in phases):continue
        account=native.get('account')
        account=account.get('address') if isinstance(account,dict) else account
        account_key=address_id('ton',account)
        outgoing=native.get('out_msgs') or []
        if not isinstance(outgoing,list):continue
        messages=[('in',native.get('in_msg'))]+[('out',row) for row in outgoing[:256]]
        for direction,message in messages:
            if not isinstance(message,dict) or _digest(message.get('hash'))!=operation['message_hash']:continue
            def key(value):
                return address_id('ton',value.get('address') if isinstance(value,dict) else value)
            frm,to=key(message.get('source')),key(message.get('destination'))
            if frm!=operation.get('from_key') or to!=operation.get('to_key'):continue
            if account_key!=(frm if direction=='out' else to):continue
            if message.get('bounced') is True:continue
            # Native execution attachments for token/NFT protocols are not the
            # principal asset and must not become a monetary service route.
            opcode=message.get('op_code',message.get('opcode'))
            try:opcode=int(opcode,16 if opcode.lower().startswith('0x') else 10) if isinstance(opcode,str) else opcode
            except ValueError:continue
            if opcode is not None and type(opcode) is not int:continue
            from .wallet_payload import body_boc
            body=body_boc(message)
            if body:
                from app.ton_nft.protocol import decode_boc
                try:
                    cell=decode_boc(body)
                    actual_opcode=int.from_bytes(cell.data[:4],'big') if cell.bit_length>=32 else None
                except (ValueError,OverflowError,TypeError):continue
                if opcode is not None and actual_opcode is not None and opcode!=actual_opcode:continue
                opcode=actual_opcode if actual_opcode is not None else opcode
            if opcode in {0x5fcc3d14,0x05138d91,0x0f8a7ea5,0x178d4519,0x7362d09c,0x595f07bc,0x7bdd97de,0xd53276db}:continue
            value=message.get('value')
            if isinstance(value,str) and value.isdecimal():value=int(value)
            if type(value) is not int or Decimal(value).scaleb(-9)!=amount:continue
            # Successful source emission is scoped as such; not recipient credit.
            return True
    return False

def _validated_operation(operation,data):
    """Compatibility predicate for the service-only physical proof gates."""
    return _validated_ton_native_operation(operation,data) or bool(validate_account_operation(operation,data))

def attribute_cryptobot_xrocket(report,payload):
    """Attach only two-service findings using existing normalizer and paths.

    The authorized existing correlator invokes this pass after its normal
    inference. Exact labels and operation proofs remain network scoped.
    """
    anchors=_catalogue()
    data=_service_data(report,payload)
    repair=repair_ton_native_observations(report,payload,data)
    data['operations']=list({row['operation_id']:row for row in [*data['operations'],*repair['operations']]}.values())
    data['evidence']=list({row['evidence_id']:row for row in [*data['evidence'],*repair['evidence']]}.values())
    data['source_observations'].update(repair['source_observations'])
    data['coverage']['service_native_observation_repair']=repair['coverage']
    for row in repair['operations']:
        for key in (row['from_key'],row['to_key']):
            data['addresses'].setdefault(key,{'address_key':key,'blockchain':'ton','address':key.split(':',1)[1],
                'attributions':[],'contract':{'kind':'unknown'},'conflicts':[],'evidence_ids':[]})
    data['_service_evidence_index']={row.get('evidence_id'):row for row in data.get('evidence',[])}
    evidence={row['evidence_id']:row for row in payload.get('evidence',[]) if row.get('evidence_id')}
    for row in data.get('evidence',[]):
        if row.get('evidence_id'):evidence[row['evidence_id']]=row
    anchors=_dedupe_anchors([*anchors,*_public_labels(data,payload)])
    valid={}
    for operation in data['operations']:
        proof_kind=('ton_native_message' if _validated_ton_native_operation(operation,data) else
                    validate_account_operation(operation,data))
        if proof_kind and _timestamp(operation.get('timestamp')):
            valid[operation['operation_id']]={**operation,'success':True,'proof_kind':proof_kind,
                'execution_scope':'provider-indexed jetton transfer; source execution, recipient credit not independently verified' if proof_kind=='ton_jetton_transfer' else
                    'successful retained account-side internal-message observation; source account and phase evidence are retained' if proof_kind=='ton_native_message' else 'successful retained chain/provider operation'}
    valid_utxo=[row for row in data['utxo_transactions'] if validate_utxo_observation(row,data)]
    target=payload.get('target_key');addresses=payload.setdefault('addresses',{})
    for key,record in data['addresses'].items():addresses.setdefault(key,record)
    findings=[];seen=set()
    # Repeated application is idempotent; remove only our own prior derivations.
    our_methods={'cryptobot_xrocket_evidence_projection','cryptobot_xrocket_collected_infrastructure_discovery'}
    payload['relationships']=[row for row in payload.get('relationships',[]) if row.get('method') not in our_methods]
    inference=dict(payload.get('inferential_intelligence') or {})
    # If the earlier normalizer exhausted its budget while opening retained
    # neighbor histories, reuse the existing bounded path algorithm on the
    # now-verified physical observations. No new traversal algorithm or edge.
    if not inference.get('paths') and valid:
        from .graph_inference import analyze_graph_inference
        paths=analyze_graph_inference({'operations':list(valid.values()),'addresses':data['addresses'],
            'target_keys':[target],'coverage':data.get('coverage',{})},max_seconds=1.0,max_paths=100)
        inference['paths']=paths.get('paths',[])
        for proof in paths.get('evidence',[]):evidence[proof['evidence_id']]=proof

    inference['relationships']=[row for row in inference.get('relationships',[]) if row.get('method') not in our_methods]
    if payload.get('inferential_intelligence') is not None:payload['inferential_intelligence']['relationships']=inference['relationships']

    def add(anchor,category,rows,*,path=None):
        identity=(anchor['service_id'],category,tuple(row['operation_id'] for row in rows))
        if identity in seen:return
        seen.add(identity)
        anchor_key=anchor['address_key'];service=SERVICES[anchor['service_id']]
        publication=_identifier('publication',[anchor['service_id'],anchor_key,anchor['publication_url'],anchor['capture_sha256']])
        evidence[publication]={'evidence_id':publication,'source':'official_service_publication' if anchor.get('reference_kind')=='official_publication' else 'public_service_address_label','upstream':anchor['service_id'],
            'url':anchor['publication_url'],'observed_at':anchor['observed_at'],'relation':'official_published_address_role' if anchor.get('reference_kind')=='official_publication' else 'published_exact_address_label',
            'blockchain':anchor['blockchain'],'address':anchor['address'],
            'facts':{'entity_id':anchor['service_id'],'label_status':anchor.get('label_status'),'authority':anchor.get('authority'),**{key:anchor.get(key) for key in ('role','source_published_at','capture_sha256','cited_address','claim_scope','cited_transaction_hash','derived_address_basis')}},
            'source_independence':'Address publication/label and chain observation establish separate scoped facts; current controller is not inferred.'}
        record=addresses.setdefault(anchor_key,data['addresses'].get(anchor_key) or {
            'address_key':anchor_key,'blockchain':anchor['blockchain'],'address':anchor['address'],
            'attributions':[],'contract':{'kind':'unknown'},'conflicts':[],'evidence_ids':[]})
        claim_id=_identifier('claim',[publication,anchor_key])
        claim={'attribution_id':claim_id,'blockchain':anchor['blockchain'],'address':anchor['address'],
            'service_id':anchor['service_id'],'name':service,'entity_name':service,'entity_type':'published_service_role' if anchor.get('reference_kind')=='official_publication' else 'public_address_label',
            'category':'published_service_role' if anchor.get('reference_kind')=='official_publication' else 'public_address_label','status':anchor.get('label_status','CONFIRMED'),'relationship':'official_published_address_role' if anchor.get('reference_kind')=='official_publication' else 'publicly_labeled_address',
            'claim_category':'CONFIRMED SERVICE ADDRESS' if anchor.get('label_status')=='CONFIRMED' else 'PUBLICLY LABELLED SERVICE ADDRESS','method':'cryptobot_xrocket_exact_publication' if anchor.get('reference_kind')=='official_publication' else 'cryptobot_xrocket_exact_public_label',
            'reason':'Exact published address reference; scope and confidence are limited to the source authority, not current control or customer assignment.',
            'confidence_rationale':'Exact network/address reference; '+anchor.get('reference_kind','official_publication')+'; current control UNKNOWN.',
            'evidence_ids':[publication],'source_url':anchor['publication_url'],'source_urls':[anchor['publication_url']],
            'observed_at':anchor['observed_at'],'observation_timestamps':[anchor['observed_at']],
            'alternative_explanations':['Role/control may change after the publication.'],
            'coverage_limitations':LIMITATIONS,'current_control':'UNKNOWN','published_role':anchor['role']}
        if not any(row.get('attribution_id')==claim_id for row in record.setdefault('attributions',[])):record['attributions'].append(claim)
        refs=list(dict.fromkeys([publication]+[ref for row in rows for ref in row.get('evidence_ids',[])]))
        if path:refs=list(dict.fromkeys(refs+path.get('evidence_ids',[])))
        label_status=anchor.get('label_status','CONFIRMED')
        name=category+' — '+service
        from_key=target;to_key=anchor_key
        nodes=path.get('nodes') if path else ([rows[0]['from_key'],rows[0]['to_key']] if rows else [target])
        direction='out' if rows and rows[0]['from_key']==target else 'in' if rows and rows[-1]['to_key']==target else 'self'
        row={'relationship_id':_identifier('connection',identity),'blockchain':anchor['blockchain'],
            'from_key':from_key,'to_key':to_key,'members':list(dict.fromkeys(nodes)),
            'type':name,'category':category,'service_id':anchor['service_id'],'service':service,
            'method':'cryptobot_xrocket_evidence_projection','status':label_status if category!='INDIRECT SERVICE CONNECTION' else 'POSSIBLE',
            'anchor_label_status':label_status,'anchor_authority':anchor.get('authority'),'anchor_reference_kind':anchor.get('reference_kind'),
            'claim_scope':('published_address_role' if label_status=='CONFIRMED' else 'published_provider_label_only') if not rows else 'observed_transfer_with_published_address' if len(rows)==1 else 'observed_temporal_same_asset_route_to_published_address',
            'target_address':report.target_address,'direction':direction,'service_address':anchor['address'],
            'published_role':anchor['role'],'anchor_label':anchor.get('label'), 'service_publication_url':anchor['publication_url'],
            'source_published_at':anchor['source_published_at'],'label_temporal_scope':('label_postdates_observed_operation' if rows and _timestamp(anchor.get('source_published_at')) and min(_timestamp(r['timestamp']) for r in rows)<_timestamp(anchor['source_published_at']) else 'label_date_unknown' if not anchor.get('source_published_at') else 'publication_available_before_operation'),'nodes':nodes,'hop_count':len(rows),
            'transaction_hashes':[item['transaction_hash'] for item in rows],
            'edges':[{key:item.get(key) for key in ('operation_id','transaction_hash','message_hash','from_key','to_key','asset_key',
                'amount_decimal','timestamp','success','source_url','evidence_ids','native_value_purpose','proof_kind','execution_scope')} for item in rows],
            'evidence_ids':refs,'reason':name+'. Exact address reference is '+label_status+' at the cited source; movement proof does not establish service ownership or customer assignment.',
            'target_service_control':'UNKNOWN','intermediary_service_control':'UNKNOWN','signing_application':'UNKNOWN',
            'exact_funds_traced':False,'current_anchor_control':'UNKNOWN','history_complete':False,
            'alternative_explanations':ALTERNATIVES,'limitations':LIMITATIONS}
        findings.append(row)

    for anchor in anchors:
        key=anchor['address_key']
        if key==target:add(anchor,'CONFIRMED SERVICE ADDRESS' if anchor.get('label_status')=='CONFIRMED' else 'PUBLICLY LABELLED SERVICE ADDRESS',[])
        for operation in valid.values():
            if {operation['from_key'],operation['to_key']}!={target,key} or target==key:continue
            if anchor.get('reference_kind')=='official_publication' and _timestamp(operation['timestamp'])<_timestamp(anchor['source_published_at']):continue
            add(anchor,'DIRECT SERVICE INTERACTION',[operation])
        for path in inference.get('paths',[])[:100]:
            checked=_eligible_path(path,valid)
            if not checked:continue
            rows,nodes=checked
            if not (nodes[0]==target and nodes[-1]==key or nodes[0]==key and nodes[-1]==target):continue
            if anchor.get('reference_kind')=='official_publication' and any(_timestamp(row['timestamp'])<_timestamp(anchor['source_published_at']) for row in rows):continue
            if not all(ref in evidence for ref in path.get('evidence_ids',[])):continue
            add(anchor,'INDIRECT SERVICE CONNECTION',rows,path={**path,'nodes':nodes})
    candidates,rejected,discovery=_discover_infrastructure(data,valid,inference,[a for a in anchors if a.get('reference_kind')=='official_publication'],target,evidence)
    sequence_candidates,sequence_rejected,sequence_coverage=_service_sequence_candidates(data,valid,anchors,target,evidence)
    sequence_candidates.extend(_service_distribution_candidates(data,valid,anchors,target))
    sequence_subjects={(row['service_id'],row['address_key'],row['asset_key']) for row in sequence_candidates}
    candidates=[row for row in candidates if (row['service_id'],row['address_key'],row['asset_key']) not in sequence_subjects]+sequence_candidates
    rejected.extend(sequence_rejected)
    discovery['observed_sequence_discovery']=sequence_coverage
    for candidate in candidates:
        key=candidate['address_key'];anchor_key=candidate['official_anchor_key']
        anchor=next(row for row in anchors if row['address_key']==anchor_key and row['service_id']==candidate['service_id'])
        publication=_identifier('publication',[anchor['service_id'],anchor_key,anchor['publication_url'],anchor['capture_sha256']])
        evidence.setdefault(publication,{'evidence_id':publication,'source':'official_service_publication' if anchor.get('reference_kind')=='official_publication' else 'public_service_address_label','upstream':anchor['service_id'],
            'url':anchor['publication_url'],'observed_at':anchor['observed_at'],'relation':'official_published_address_role' if anchor.get('reference_kind')=='official_publication' else 'published_exact_address_label',
            'blockchain':anchor['blockchain'],'address':anchor['address'],'facts':{field:anchor.get(field) for field in ('role','source_published_at','capture_sha256','claim_scope')}})
        candidate['evidence_ids']=list(dict.fromkeys([publication]+candidate['evidence_ids']))
        anchor_record=addresses.setdefault(anchor_key,data['addresses'].get(anchor_key) or {'address_key':anchor_key,
            'address':anchor['address'],'blockchain':anchor['blockchain'],'attributions':[],'contract':{'kind':'unknown'},'conflicts':[],'evidence_ids':[]})
        official=anchor.get('reference_kind')=='official_publication'
        if not any(c.get('service_id')==anchor['service_id'] and publication in c.get('evidence_ids',[]) for c in anchor_record.get('attributions',[])):
            anchor_record.setdefault('attributions',[]).append({'attribution_id':_identifier('claim',[publication,anchor_key]),
                'service_id':anchor['service_id'],'blockchain':anchor['blockchain'],'address':anchor['address'],'name':SERVICES[anchor['service_id']],
                'status':'CONFIRMED' if official else 'PROBABLE','method':'cryptobot_xrocket_exact_publication' if official else 'cryptobot_xrocket_exact_public_label',
                'claim_category':'CONFIRMED SERVICE ADDRESS' if official else 'PUBLICLY LABELLED SERVICE ADDRESS',
                'source_url':anchor['publication_url'],'evidence_ids':[publication],'observed_at':anchor['observed_at'],
                'current_control':'UNKNOWN','claim_scope':'Reference label only; not an attribution of the candidate or a new money transfer'})
        # No attribution/owner label is assigned to a candidate or its users.
        addresses.setdefault(key,data['addresses'].get(key) or {'address_key':key,'address':candidate['address'],
            'blockchain':candidate['blockchain'],'attributions':[],'contract':{'kind':'unknown'},'conflicts':[],'evidence_ids':[]})
        evidence_id=_identifier('infrastructure-evidence',[candidate['candidate_id'],candidate['transaction_hashes']])
        evidence[evidence_id]={'evidence_id':evidence_id,'source':'cryptobot_xrocket_role_observations',
            'upstream':'retained_chain_operations','relation':'possible_service_infrastructure_role',
            'blockchain':candidate['blockchain'],'address':candidate['address'],'observed_at':datetime.now(timezone.utc).isoformat(),
            'url':anchor['publication_url'],'facts':{**candidate,'evidence_ids':list(candidate['evidence_ids'])},'evidence_ids':list(candidate['evidence_ids']),
            'source_independence':'Distinct transactions are distinct actions, not independent operator attestations.'}
        candidate['evidence_ids'].append(evidence_id)
        row={'relationship_id':candidate['candidate_id'],'blockchain':candidate['blockchain'],'from_key':key,'to_key':anchor_key,
            'members':list(dict.fromkeys([key,anchor_key]+[node for route in candidate['service_routes'] for node in route['nodes']])),
            'type':'POSSIBLE SERVICE INFRASTRUCTURE — '+candidate['service'],'category':candidate['category'],
            'scope':'service_role_hypothesis','status':'POSSIBLE','service_id':candidate['service_id'],
            'edge_semantics':'analytical_role_association_not_a_transaction_or_direct_transfer','transaction_edge':False,
            'method':'cryptobot_xrocket_collected_infrastructure_discovery','reason':candidate['basis'],
            'roles':candidate['roles'],'candidate_address':candidate['address'],'transaction_hashes':candidate['transaction_hashes'],
            'evidence_ids':candidate['evidence_ids'],'observations':candidate['observations'],
            'routes':candidate['service_routes'],'alternative_explanations':candidate['alternative_explanations'],
            'service_control':'UNKNOWN','exact_funds_traced':False,'history_complete':False,'candidate':candidate}
        findings.append(row)
    payload['relationships'].extend(findings)
    if payload.get('inferential_intelligence') is not None:inference['relationships'].extend(findings)
    utxo_connections=_utxo_connections(valid_utxo,anchors,target,evidence)
    payload['evidence']=list(evidence.values())
    payload.setdefault('source_observations',{}).update(data['source_observations'])
    result={'schema_version':'1.0','services':list(SERVICES),'findings':findings,'status':'OBSERVED' if findings or utxo_connections else 'UNKNOWN',
        'coverage':{'history_complete':False,'eligible_native_operations':sum(r['asset_key'].endswith(':native') for r in valid.values()),
            'eligible_account_operations':len(valid),'eligible_utxo_transactions':len(valid_utxo),
            'networks':_network_coverage(report,data,valid,valid_utxo,anchors),
            'raw_operations':len(data['operations']),'new_graph_algorithms':0,'network_requests':0,
            'inference_paths_available':len(inference.get('paths',[])), 'service_native_observation_repair':repair['coverage'],
            'operation_proof_scope':'Exact native/provider fields; unproven DTO-only amounts and token labels cannot create service transfers',
            'utxo_scope':'Bipartite transaction participation only; no chosen input-to-output allocation' },'limitations':LIMITATIONS,
        'utxo_connections':utxo_connections,
        'possible_service_infrastructure':candidates,'rejected_infrastructure_candidates':rejected,'discovery_coverage':discovery,
        'infrastructure_hypothesis_scope':'Role hypotheses from source-bound repeated service-linked sequences and observed distribution; reference labels do not authenticate operator ownership, candidates never become anchors.'}
    payload['telegram_service_intelligence']=result
    from .service_infrastructure import attach_service_infrastructure
    attach_service_infrastructure(report,payload,data,valid,anchors)
    if 'stats' in payload:
        payload['stats']['evidence']=len(evidence)
        payload['stats']['relationships']=len(payload['relationships'])
    return result

def _service_sequence_candidates(data,valid,anchors,target,evidence):
    """Local ledger sequences around observed service links, not a graph walk.

    Candidates never become reference anchors. Economic sequence, account-state
    conservation and operator identity are separate findings.
    """
    from collections import Counter
    from .service_operations import native_account_state
    from .graph_inference import MAX_ROUTE_DELAY
    from bisect import bisect_left
    started=time.monotonic();incident=defaultdict(list);bindings=defaultdict(int)
    anchor_keys={a['address_key'] for a in anchors};index={(a['service_id'],a['address_key']):a for a in anchors}
    for op in valid.values():
        if op['from_key']==op['to_key'] or not _role_amount(op):continue
        incident[op['from_key']].append(op);incident[op['to_key']].append(op)
    for service,key in index:
        for op in incident.get(key,[]):
            other=op['to_key'] if op['from_key']==key else op['from_key']
            if other not in anchor_keys:bindings[(service,other,key)]+=1
    ordered=sorted(bindings,key=lambda entry:(entry[1]!=target,-bindings[entry],entry))[:64]
    candidates=[];rejected=[]
    def projected(row):
        return {k:row.get(k) for k in ('operation_id','transaction_hash','message_hash','blockchain','from_key','to_key','asset_key',
            'amount_decimal','timestamp','success','source_url','evidence_ids','proof_kind','execution_scope')}
    for service,key,anchor_key in ordered:
        if time.monotonic()-started>2.0:break
        anchor=index[(service,anchor_key)];by_asset=defaultdict(list)
        conflicting=[claim for claim in data['addresses'].get(key,{}).get('attributions',[]) if claim.get('status') in {'PROBABLE','CONFIRMED'}
            and claim.get('service_id') and SERVICE_ALIASES.get(claim['service_id'],claim['service_id'])!=service]
        if conflicting:
            rejected.append({'address_key':key,'service_id':service,'infrastructure_status':'UNKNOWN',
                'reason':'Conflicting published service attribution; retain interactions without inferring this service controls the address.',
                'contradicting_claims':conflicting});continue
        for row in incident[key]:by_asset[row['asset_key']].append(row)
        for asset,items in by_asset.items():
            items=sorted(items,key=lambda row:(row['timestamp'],row['operation_id']));sequences=[];returns=[];used=set()
            for before,after in zip(items,items[1:]):
                if before['to_key']!=key or after['from_key']!=key or after['to_key']!=anchor_key:continue
                if before['transaction_hash']==after['transaction_hash'] or before['operation_id'] in used:continue
                delay=(_timestamp(after['timestamp'])-_timestamp(before['timestamp'])).total_seconds()
                if not 0<delay<=min(MAX_ROUTE_DELAY,3600):continue
                incoming=Decimal(before['amount_decimal']);outgoing=Decimal(after['amount_decimal'])
                state_in=native_account_state(before,key,data);state_out=native_account_state(after,key,data)
                adjacent=False;conserved=None;residual=None;sweep=False
                if asset=='ton:native' and (not state_in or not state_out or state_in['execution_status']!='SUCCESS' or state_out['execution_status']!='SUCCESS'):continue
                if state_in and state_out:
                    adjacent=state_out['prev_transaction_hash']==state_in['transaction_hash'] and state_out['prev_lt']==state_in['lt']
                    if not adjacent:continue
                    if state_in['end_balance_base_units'] is not None and state_out['balance_inputs_complete']:
                        prior=int(state_in['end_balance_base_units']);residual=int(state_out['end_balance_base_units'])
                        spent=sum(int(state_out[f]) for f in ('outgoing_value_base_units','total_fees_base_units','outgoing_forward_fees_base_units','outgoing_ihr_fees_base_units'))
                        conserved=prior==residual+spent
                        sweep=conserved and prior>0 and Decimal(residual)/Decimal(prior)<=Decimal('0.01')
                close=abs(outgoing-incoming)/max(incoming,outgoing)<=Decimal('0.02')
                if not close and not sweep:continue
                refs=list(dict.fromkeys(before['evidence_ids']+after['evidence_ids']+
                    [r for state in (state_in,state_out) if state for r in state['corroborating_evidence_ids']]))
                sequence={'sequence_id':_identifier('observed-sequence',[service,key,before['operation_id'],after['operation_id']]),
                    'kind':'observed_forwarding_sequence','incoming':projected(before),'outgoing':projected(after),'delay_seconds':int(delay),
                    'amount_difference':str(outgoing-incoming),'asset_key':asset,'account_transactions_adjacent':adjacent,
                    'balance_conservation_verified':conserved,'residual_base_units':str(residual) if residual is not None else None,
                    'account_state_in':state_in,'account_state_out':state_out,'exact_funds_traced':False,'evidence_ids':refs,
                    'roundtrip_from_service':before['from_key']==anchor_key}
                used.update((before['operation_id'],after['operation_id']))
                (returns if sequence['roundtrip_from_service'] else sequences).append(sequence)
            dates={s['outgoing']['timestamp'][:10] for s in sequences}
            if len(sequences)<3 or len(dates)<2:
                continue
            selected={r['operation_id']:r for s in sequences for r in (s['incoming'],s['outgoing'])}
            refs=list(dict.fromkeys(r for s in sequences for r in s['evidence_ids']))
            residuals=Counter(s['residual_base_units'] for s in sequences if s['balance_conservation_verified'] and s['residual_base_units'] is not None)
            common=residuals.most_common(1)
            source_keys={s['incoming']['from_key'] for s in sequences};hashes={r['transaction_hash'] for r in selected.values()}
            candidate={'candidate_id':_identifier('infrastructure-sequences',[service,key,asset,anchor_key]),'service_id':service,'service':SERVICES[service],
                'blockchain':anchor['blockchain'],'address':key.split(':',1)[1],'address_key':key,'asset_key':asset,
                'category':'POSSIBLE SERVICE INFRASTRUCTURE','status':'POSSIBLE','roles':['forwarding_or_consolidation_candidate'],
                'method':'cryptobot_xrocket_collected_infrastructure_discovery','service_control':'UNKNOWN','current_control':'UNKNOWN','signing_application':'UNKNOWN',
                'confirmed_anchor':False,'official_anchor_key':anchor_key,'official_anchor_address':anchor['address'],
                'official_publication_url':anchor['publication_url'],'official_publication_date':anchor.get('source_published_at'),
                'anchor_reference_kind':anchor.get('reference_kind'),'anchor_label_status':anchor.get('label_status'),
                'basis':'Repeated distinct incoming→service outgoing sequences; exact source-bound operations and optional consecutive account balance conservation. This supports a role hypothesis, not operator ownership.',
                'observations':{'independent_transaction_count':len(hashes),'physical_operation_count':len(selected),'physical_message_count':sum(bool(r.get('message_hash')) for r in selected.values()),
                    'incoming_counterparties':len(source_keys),'outgoing_counterparties':len({r['to_key'] for r in items if r['from_key']==key}),
                    'independent_service_bound_routes':len(sequences),'independent_sequence_count':len(sequences),'active_utc_dates':sorted(dates),
                    'verified_account_balance_sequences':sum(s['balance_conservation_verified'] is True for s in sequences),
                    'repeated_residual_base_units':common[0][0] if common else None,'repeated_residual_count':common[0][1] if common else 0,
                    'excluded_service_roundtrips':len(returns),'independent_operator_control_confirmations':0,
                    'public_label_sources':1 if anchor.get('reference_kind')=='public_label' else 0},
                'first_observed':min(r['timestamp'] for r in selected.values()),'last_observed':max(r['timestamp'] for r in selected.values()),
                'transaction_hashes':sorted(hashes),'evidence_ids':refs,'role_operations':list(selected.values())[:100],
                'observed_sequences':sequences[:50],'excluded_roundtrip_sequences':returns[:20],
                'role_operations_display_truncated':len(selected)>100,
                'service_routes':[{'nodes':[s['incoming']['from_key'],key,anchor_key],'hop_count':2,
                    'transaction_hashes':[s['incoming']['transaction_hash'],s['outgoing']['transaction_hash']],
                    'edges':[s['incoming'],s['outgoing']],'evidence_ids':s['evidence_ids'],'exact_funds_traced':False,
                    'sequence_id':s['sequence_id'],'status':'POSSIBLE'} for s in sequences[:50]],
                'alternative_explanations':['Personal wallet automatically depositing its receipts into a service account',
                    'Independent merchant/payment forwarder using the service','Automation controlled by an unrelated customer',
                    'Service-owned deposit/sweep infrastructure; operator control remains unconfirmed','Pre-existing balance contributes to outgoing payments'],
                'missing_evidence':['Independent address-specific operator control confirmation','Customer deposit assignment','Complete history beyond retained observations'],
                'history_complete':False,'exact_funds_traced':False,'limitations':LIMITATIONS+
                    ['Provider label date does not authenticate the controller at every earlier transaction date.','Repeated residual is learned from observations, not a hardcoded service fingerprint.']}
            candidates.append(candidate)
    return candidates,rejected,{'status':'PARTIAL','candidate_bindings_examined':len(ordered),'max_candidate_bindings':64,'max_seconds':2.0,
        'elapsed_seconds':time.monotonic()-started,'sequence_window_seconds':min(MAX_ROUTE_DELAY,3600),'minimum_independent_sequences':3,
        'near_amount_relative_tolerance':'0.02','source_dtos_modified':False,'new_http_requests':0,'new_graph_algorithms':0}

def _service_distribution_candidates(data,valid,anchors,target):
    """Repeated payouts after observed service funding; no label propagation."""
    from .graph_inference import MAX_ROUTE_DELAY
    from bisect import bisect_left
    started=time.monotonic();out=[];anchor_keys={a['address_key'] for a in anchors};ops=list(valid.values())
    def dependency(row):
        for ref in row.get('evidence_ids',[]):
            proof=data['_service_evidence_index'].get(ref,{})
            pointer=(proof.get('facts') or {}).get('raw_reference') or {}
            raw=(data['source_observations'].get(pointer.get('source_observation_id')) or {}).get('raw') or {}
            trace=(raw.get('transfer') or {}).get('trace_id') or raw.get('trace_id')
            if _digest(trace):return row['blockchain']+':trace:'+_digest(trace)
        return row['blockchain']+':tx:'+row['transaction_hash']
    def projected(row):return {k:v for k,v in row.items() if not k.startswith('_')}
    for anchor in anchors:
        bindings=defaultdict(list)
        for row in ops:
            if row['from_key']==anchor['address_key'] and row['to_key'] not in anchor_keys:bindings[row['to_key']].append(row)
        for key,funding in sorted(bindings.items(),key=lambda item:(item[0]!=target,-len(item[1]),item[0]))[:32]:
            if time.monotonic()-started>2.0:return out
            if any(claim.get('status') in {'PROBABLE','CONFIRMED'} and claim.get('service_id') and
                SERVICE_ALIASES.get(claim['service_id'],claim['service_id'])!=anchor['service_id']
                for claim in data['addresses'].get(key,{}).get('attributions',[])):continue
            routes=[];used={};source_assets={r['asset_key'] for r in funding};funding_groups={dependency(r) for r in funding}
            funding_by_asset=defaultdict(list)
            for row in funding:funding_by_asset[row['asset_key']].append(row)
            prior_index={asset:sorted(rows,key=lambda row:row['timestamp']) for asset,rows in funding_by_asset.items()}
            prior_times={asset:[_timestamp(row['timestamp']) for row in rows] for asset,rows in prior_index.items()}
            for payout in ops:
                if time.monotonic()-started>2.0:break
                if payout['from_key']!=key or payout['to_key'] in {key,anchor['address_key']} or not _role_amount(payout):continue
                position=bisect_left(prior_times.get(payout['asset_key'],[]),_timestamp(payout['timestamp']))-1
                if position<0:continue
                earlier=prior_index[payout['asset_key']][position]
                if earlier['transaction_hash']==payout['transaction_hash'] or (_timestamp(payout['timestamp'])-_timestamp(earlier['timestamp'])).total_seconds()>MAX_ROUTE_DELAY:continue
                routes.append((earlier,payout));used[payout['operation_id']]=payout
            recipients={r['to_key'] for r in used.values()};payout_groups={dependency(r) for r in used.values()}
            stamps=sorted(r['timestamp'] for r in used.values());dates={s[:10] for s in stamps};payout_assets={r['asset_key'] for r in used.values()}
            span=(_timestamp(stamps[-1])-_timestamp(stamps[0])).total_seconds() if stamps else 0
            repeated=len(dates)>=2 or len(recipients)>=10 and span>=900
            if len(recipients)<5 or len(payout_groups)<5 or not repeated:continue
            if len(funding_groups)<2 and not (len(source_assets)>=3 and len(payout_assets)>=2):continue
            allrows={r['operation_id']:r for pair in routes for r in pair};hashes={r['transaction_hash'] for r in allrows.values()}
            refs=list(dict.fromkeys(ref for r in allrows.values() for ref in r['evidence_ids']))
            incoming=[row for row in ops if row['to_key']==key]
            other_funders=sorted({row['from_key'] for row in incoming if row['from_key']!=anchor['address_key']})
            out.append({'candidate_id':_identifier('service-distribution',[anchor['service_id'],key,anchor['address_key']]),
                'service_id':anchor['service_id'],'service':SERVICES[anchor['service_id']],'blockchain':anchor['blockchain'],
                'address':key.split(':',1)[1],'address_key':key,'asset_key':'multiple_observed_assets' if len(payout_assets)>1 else next(iter(payout_assets)),
                'category':'POSSIBLE SERVICE INFRASTRUCTURE','status':'POSSIBLE','roles':['service_linked_distribution_candidate'],
                'method':'cryptobot_xrocket_collected_infrastructure_discovery','service_control':'UNKNOWN','current_control':'UNKNOWN','signing_application':'UNKNOWN',
                'confirmed_anchor':False,'official_anchor_key':anchor['address_key'],'official_anchor_address':anchor['address'],
                'official_publication_url':anchor['publication_url'],'official_publication_date':anchor.get('source_published_at'),
                'anchor_reference_kind':anchor.get('reference_kind'),'anchor_label_status':anchor.get('label_status'),
                'basis':'Observed exact service funding followed by repeated same-asset payouts to diverse recipients; trace groups, assets and observation periods are distinct from operator confirmations.',
                'observations':{'independent_transaction_count':len(hashes),'physical_operation_count':len(allrows),
                    'incoming_counterparties':len({r['from_key'] for r in incoming}),'service_funding_counterparties':1,
                    'other_observed_funder_keys':other_funders[:64],'other_observed_funders_total':len(other_funders),
                    'other_funders_display_truncated':len(other_funders)>64,'outgoing_counterparties':len(recipients),
                    'funding_physical_operations':len(funding),'funding_independent_trace_groups':len(funding_groups),
                    'payout_independent_trace_groups':len(payout_groups),'funding_asset_keys':sorted(source_assets),'payout_asset_keys':sorted(payout_assets),
                    'active_utc_dates':sorted(dates),'observed_span_seconds':span,'independent_operator_control_confirmations':0},
                'first_observed':min(r['timestamp'] for r in allrows.values()),'last_observed':max(r['timestamp'] for r in allrows.values()),
                'transaction_hashes':sorted(hashes),'evidence_ids':refs,'role_operations':[projected(r) for r in list(allrows.values())[:100]],
                'role_operations_display_truncated':len(allrows)>100,
                'service_routes':[{'nodes':[a['from_key'],key,b['to_key']],'hop_count':2,
                    'transaction_hashes':[a['transaction_hash'],b['transaction_hash']],'edges':[projected(a),projected(b)],
                    'evidence_ids':list(dict.fromkeys(a['evidence_ids']+b['evidence_ids'])),'exact_funds_traced':False,'status':'POSSIBLE'} for a,b in routes[:50]],
                'alternative_explanations':['An unrelated customer/merchant using the service for treasury funding','Independent automated payout operator',
                    'Asset migration/rebalancing rather than a service withdrawal system','Service-controlled distribution; current controller unconfirmed'],
                'missing_evidence':['Address-specific operator confirmation','Customer withdrawal assignment','Complete funding and balance history',
                    'Allocation across intervening customer deposits and treasury balances; later payouts are not traced units of the earlier service funding'],
                'history_complete':False,'exact_funds_traced':False,'limitations':LIMITATIONS+['Several assets or recipients in one trace are not independent operator attestations.']})
    return out
