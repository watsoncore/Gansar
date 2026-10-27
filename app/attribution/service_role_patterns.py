"""Candidate typed projection over Gansar's existing proved observations.

No HTTP, collectors, graph traversal, label propagation or DTO mutations.
The existing service findings remain the authority for their 24 sequences.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime,timezone
from decimal import Decimal,InvalidOperation
from bisect import bisect_left
import hashlib,json,time

METHOD='service_infrastructure_typed_roles'
ROLES=('deposit_candidate','withdrawal_candidate','forwarding_candidate','consolidation_candidate',
       'distribution_candidate','treasury_candidate','migration_candidate')

def _id(kind,value):
    return 'service-role:'+kind+':'+hashlib.sha256(json.dumps(value,sort_keys=True,default=str).encode()).hexdigest()

def _time(value):
    try:
        parsed=datetime.fromisoformat(str(value).replace('Z','+00:00'))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except (TypeError,ValueError,OverflowError):return None

def _project(row):
    return {key:row.get(key) for key in ('operation_id','transaction_hash','message_hash','blockchain','from_key',
        'to_key','asset_key','amount_decimal','timestamp','evidence_ids','source_url','proof_kind','success')}

def discover_roles(data,valid,anchors,existing_candidates,inference,target):
    """Return new typed hypotheses; never rewrite existing service candidates.

    Each role has separate conjunctive qualifications. UNKNOWN assessments stay
    diagnostic rather than turning an unqualified address into infrastructure.
    Funds sent to/from a reference address establish interaction, not control.
    """
    from app.attribution.telegram_services import _eligible_path,_role_amount,_digest
    started=time.monotonic();deadline=started+1.0
    out={name:[] for name in ('candidates','hypotheses','relationships','evidence')}
    evidence_index=dict(data.get('_service_evidence_index') or {})
    evidence_index.update({r['evidence_id']:r for r in data.get('evidence',[]) if r.get('evidence_id')})
    evidence_index.update({r['evidence_id']:r for r in inference.get('evidence',[]) if r.get('evidence_id')})
    anchor_keys={a['address_key'] for a in anchors if a.get('address_key')}
    by_anchor=defaultdict(list)
    for anchor in anchors:
        if anchor.get('address_key') and anchor.get('service_id'):by_anchor[anchor['address_key']].append(anchor)
    incident=defaultdict(list);operation_index={};dependencies={};trace_complete={}
    def dependency(row):
        traces=set()
        for ref in row.get('evidence_ids',[]):
            proof=evidence_index.get(ref,{})
            pointer=(proof.get('facts') or {}).get('raw_reference') or {}
            raw=(data.get('source_observations',{}).get(pointer.get('source_observation_id')) or {}).get('raw') or {}
            trace=_digest((raw.get('transfer') or {}).get('trace_id') or raw.get('trace_id'))
            if trace:traces.add(trace)
        chain=row['blockchain'];is_ton_jetton=chain=='ton' and row.get('proof_kind')=='ton_jetton_transfer'
        trace_complete[row['operation_id']]=not is_ton_jetton or len(traces)==1
        # Same TON root hash has one dependency whether native or jetton.
        if len(traces)==1:return chain+':dependency:'+next(iter(traces))
        tx=_digest(row['transaction_hash']) or row['transaction_hash']
        return chain+':dependency:'+tx
    for row in valid.values():
        if row.get('success') is not True or row.get('from_key')==row.get('to_key'):continue
        if row.get('native_value_purpose')=='jetton_transfer_request':continue
        if row.get('amount_precision')=='display_float' or not _time(row.get('timestamp')):continue
        try:
            if not _role_amount(row):continue
        except (KeyError,TypeError,ValueError,InvalidOperation):continue
        if not all(row.get(k) for k in ('operation_id','transaction_hash','from_key','to_key','asset_key','blockchain','evidence_ids')):continue
        operation_index[row['operation_id']]=row;dependencies[row['operation_id']]=dependency(row)
        incident[row['from_key']].append(row);incident[row['to_key']].append(row)
    group=lambda row:dependencies[row['operation_id']]
    # Existing engine paths are checked and projected; no new paths are built.
    ready_paths=[]
    for path in inference.get('paths',[])[:100]:
        checked=_eligible_path(path,operation_index)
        if checked and all(ref in evidence_index for ref in path.get('evidence_ids',[])):
            ready_paths.append((path,*checked))
    bindings=defaultdict(list)
    for key,ref_anchors in by_anchor.items():
        for anchor in ref_anchors:
            service=anchor['service_id']
            for row in incident.get(key,[]):
                other=row['to_key'] if row['from_key']==key else row['from_key']
                if other not in anchor_keys:bindings[(service,other)].append((anchor,row))
    for path,rows,nodes in ready_paths:
        for endpoint in (nodes[0],nodes[-1]):
            for anchor in by_anchor.get(endpoint,[]):
                for key in nodes:
                    if key not in anchor_keys:bindings[(anchor['service_id'],key)].append((anchor,rows[0]))
    existing_by_key=defaultdict(list)
    for candidate in existing_candidates:
        key=candidate.get('address_key');service=candidate.get('service_id')
        if key and service:
            existing_by_key[(service,key)].append(candidate)
            for anchor in anchors:
                if anchor.get('service_id')==service and anchor.get('address_key')==candidate.get('official_anchor_key'):
                    bindings.setdefault((service,key),[])
    rejected=[];examined=0;truncated=len(bindings)>64
    ordered=sorted(bindings,key=lambda item:(item[1]!=target,-len(bindings[item]),item))[:64]
    for service,key in ordered:
        if time.monotonic()>deadline:truncated=True;break
        examined+=1;rows=incident.get(key,[])
        if not rows:continue
        references=[a for a in anchors if a.get('service_id')==service and any(r['from_key']==a.get('address_key') or r['to_key']==a.get('address_key') for r in rows)]
        if not references:references=[a for a,_ in bindings[(service,key)]]
        if not references:continue
        linked_keys={a['address_key'] for a in references}
        if key in anchor_keys:continue
        incoming=[r for r in rows if r['to_key']==key];outgoing=[r for r in rows if r['from_key']==key]
        funded=[r for r in incoming if r['from_key'] in linked_keys]
        service_out=[r for r in outgoing if r['to_key'] in linked_keys]
        other_funding=[r for r in incoming if any(a['service_id']!=service for a in by_anchor.get(r['from_key'],[]))]
        other_destinations=[r for r in outgoing if any(a['service_id']!=service for a in by_anchor.get(r['to_key'],[]))]
        other_service_routes=[]
        for path,path_rows,nodes in ready_paths:
            if key not in nodes:continue
            other_refs=[a for endpoint in (nodes[0],nodes[-1]) for a in by_anchor.get(endpoint,[]) if a['service_id']!=service]
            if other_refs:
                other_service_routes.append({'path_id':path.get('path_id'),'nodes':nodes,'hop_count':len(path_rows),
                    'operations':[_project(r) for r in path_rows],'reference_services':sorted({a['service_id'] for a in other_refs}),
                    'exact_funds_traced':False,'service_control':'UNKNOWN','transaction_edge':False})
        dates=sorted({r['timestamp'][:10] for r in rows});assets=sorted({r['asset_key'] for r in rows})
        dep_in={group(r) for r in incoming};dep_out={group(r) for r in outgoing}
        service_dep_in={group(r) for r in funded};service_dep_out={group(r) for r in service_out}
        evidence_candidates=existing_by_key.get((service,key),[])
        sequences=[]
        for candidate in evidence_candidates:
            for sequence in candidate.get('observed_sequences',[]):
                a=operation_index.get((sequence.get('incoming') or {}).get('operation_id'))
                b=operation_index.get((sequence.get('outgoing') or {}).get('operation_id'))
                if a and b and a['to_key']==key and b['from_key']==key and b['to_key'] in linked_keys and group(a)!=group(b) and _time(a['timestamp'])<_time(b['timestamp']):
                    sequences.append((sequence,a,b))
        seq_unique={s['sequence_id']:(s,a,b) for s,a,b in sequences if s.get('sequence_id')}
        sequences=list(seq_unique.values())
        sequence_dates={b['timestamp'][:10] for _,a,b in sequences}
        seq_sources={a['from_key'] for _,a,b in sequences if a['from_key'] not in linked_keys}
        conserved=sum(s.get('balance_conservation_verified') is True for s,_,_ in sequences)
        per_asset=defaultdict(list)
        for row in rows:per_asset[row['asset_key']].append(row)
        concentrated_sweep=False
        for subset in per_asset.values():
            outs=[r for r in subset if r['from_key']==key]
            groups={group(r) for r in outs};to_service={group(r) for r in outs if r['to_key'] in linked_keys}
            if groups and len(to_service)*5>=len(groups)*4 and len(to_service)>=3:concentrated_sweep=True
        payout_groups=set();payout_recipients=set();payout_assets=set();funding_assets={r['asset_key'] for r in funded}
        funded_groups=defaultdict(dict)
        for before in funded:
            asset=before['asset_key'];dep=group(before)
            old=funded_groups[asset].get(dep)
            if old is None or _time(before['timestamp'])<_time(old['timestamp']):funded_groups[asset][dep]=before
        funding_index={asset:sorted(values.values(),key=lambda r:_time(r['timestamp'])) for asset,values in funded_groups.items()}
        funding_times={asset:[_time(r['timestamp']) for r in values] for asset,values in funding_index.items()}
        def prior_funding(after):
            asset=after['asset_key'];position=bisect_left(funding_times.get(asset,[]),_time(after['timestamp']))-1
            # At most one deduplicated funding row belongs to this same trace.
            for i in range(position,max(-1,position-2),-1):
                before=funding_index[asset][i]
                delay=(_time(after['timestamp'])-_time(before['timestamp'])).total_seconds()
                if group(before)!=group(after) and 0<delay<=30*86400:return before
            return None
        for row in outgoing:
            if row['to_key'] in linked_keys or row['to_key'] in anchor_keys:continue
            if prior_funding(row):payout_groups.add(group(row));payout_recipients.add(row['to_key']);payout_assets.add(row['asset_key'])
        service_funding_dates={r['timestamp'][:10] for r in funded}
        service_funders={r['from_key'] for r in funded}
        onward=[(p,rs,ns) for p,rs,ns in ready_paths if key in ns[1:-1] and any(n in linked_keys for n in (ns[0],ns[-1]))]
        # Specific staged multiasset treasury movement, not merely many payouts.
        paired_assets=set()
        for after in outgoing:
            if prior_funding(after):paired_assets.add(after['asset_key'])
        traced_tokens=all(trace_complete[r['operation_id']] for r in funded+outgoing)
        conditions={
          'forwarding_candidate':{'three_existing_source_bound_sequences':len(sequences)>=3,'recurs_on_two_utc_dates':len(sequence_dates)>=2},
          'consolidation_candidate':{'three_distinct_external_senders':len(seq_sources)>=3,'three_existing_sequences':len(sequences)>=3,'two_service_outgoing_groups':len(service_dep_out)>=2},
          'deposit_candidate':{'three_existing_sequences':len(sequences)>=3,'two_sequence_dates':len(sequence_dates)>=2,'dominant_single_service_sink':concentrated_sweep,'three_proven_balance_sweeps':conserved>=3},
          'distribution_candidate':{'five_same_asset_payout_groups_after_funding':len(payout_groups)>=5,'three_distinct_recipient_addresses':len(payout_recipients)>=3,'repeated_funding_or_multimaster_bootstrap':len(service_dep_in)>=2 or (len(funding_assets)>=3 and len(payout_assets)>=2),'dependency_grouping_available':traced_tokens},
          'withdrawal_candidate':{'three_service_funding_groups':len(service_dep_in)>=3,'service_majority_of_incoming_groups':bool(dep_in) and len(service_dep_in)*2>=len(dep_in),'five_payout_groups':len(payout_groups)>=5,'three_distinct_payout_recipients':len(payout_recipients)>=3,'two_funding_dates':len(service_funding_dates)>=2,'dependency_grouping_available':traced_tokens},
          'treasury_candidate':{'two_exact_service_reference_funders':len(service_funders)>=2,'two_service_funding_dates':len(service_funding_dates)>=2,'two_asset_identities':len(funding_assets)>=2,'two_onward_groups':len(dep_out)>=2,'dependency_grouping_available':traced_tokens},
          'migration_candidate':{'two_same_service_funding_addresses':len(service_funders)>=2,'two_separate_funding_dates':len(service_funding_dates)>=2,'three_staged_asset_identities':len(paired_assets)>=3,'two_distinct_onward_trace_groups':len(dep_out)>=2,'existing_time_respecting_service_path':bool(onward),'dependency_grouping_available':traced_tokens},
        }
        qualified=[role for role in ROLES if all(conditions[role].values())]
        assessments={role:{'status':'POSSIBLE' if role in qualified else 'UNKNOWN','conditions':checks} for role,checks in conditions.items()}
        if not qualified:
            rejected.append({'service_id':service,'address_key':key,'status':'UNKNOWN','role_assessments':assessments});continue
        ids=sorted({r['operation_id'] for r in rows});refs=sorted({ref for r in rows for ref in r.get('evidence_ids',[])})
        cid=_id('candidate',[service,key,qualified,ids]);eid=_id('evidence',[cid,ids])
        name=references[0].get('service') or references[0].get('name') or service
        competing_claims=[claim for claim in data.get('addresses',{}).get(key,{}).get('attributions',[])
                          if claim.get('service_id') not in {None,service} and claim.get('status') in {'PROBABLE','CONFIRMED'}]
        if competing_claims:
            rejected.append({'service_id':service,'address_key':key,'status':'UNKNOWN','reason':'Competing published address attribution','claims':competing_claims});continue
        candidate={'candidate_id':cid,'service_id':service,'service':name,'blockchain':rows[0]['blockchain'],
          'address_key':key,'address':key.split(':',1)[1],'category':'INFRASTRUCTURE CANDIDATE','status':'POSSIBLE',
          'roles':qualified,'role_assessments':assessments,'method':METHOD,'service_control':'UNKNOWN','current_control':'UNKNOWN',
          'confirmed_anchor':False,'exact_funds_traced':False,'transaction_edge':False,'history_complete':False,
          'source_candidate_ids':[c['candidate_id'] for c in evidence_candidates if c.get('candidate_id')],
          'existing_sequence_count':len(sequences),'existing_sequence_ids':sorted(seq_unique),
          'evidence_ids':refs+[eid],'transaction_hashes':sorted({r['transaction_hash'] for r in rows}),
          'observations':{'physical_operations':len(ids),'distinct_incoming_dependency_groups':len(dep_in),'distinct_outgoing_dependency_groups':len(dep_out),
             'distinct_sender_addresses':len({r['from_key'] for r in incoming}),'distinct_receiver_addresses':len({r['to_key'] for r in outgoing}),
             'service_funding_groups':len(service_dep_in),'service_funder_addresses':len(service_funders),'service_funding_dates':sorted(service_funding_dates),
             'payout_groups_after_same_asset_service_funding':len(payout_groups),'payout_recipient_addresses':len(payout_recipients),
             'asset_keys':assets,'staged_same_asset_keys':sorted(paired_assets),'active_utc_dates':dates,
             'independent_operator_confirmations':0,'addresses_are_independent_persons':False},
          'role_operations':[_project(r) for r in sorted(rows,key=lambda r:(r['timestamp'],r['operation_id']))[:100]],
          'role_operations_display_truncated':len(rows)>100,'first_observed':min(r['timestamp'] for r in rows),'last_observed':max(r['timestamp'] for r in rows),
          'existing_path_ids':[p.get('path_id') for p,_,_ in onward],
          'other_service_funding':[{**_project(r),'reference_services':[a['service_id'] for a in by_anchor.get(r['from_key'],[]) if a['service_id']!=service]} for r in other_funding[:20]],
          'other_service_destinations':[{**_project(r),'reference_services':[a['service_id'] for a in by_anchor.get(r['to_key'],[]) if a['service_id']!=service]} for r in other_destinations[:20]],
          'other_service_routes':other_service_routes[:20],
          'label_temporal_scope':[{'address_key':a['address_key'],'published_at':a.get('source_published_at'),'publication_url':a.get('publication_url'),
             'label_status':a.get('label_status'),'historical_operator_control':'UNKNOWN'} for a in references],
          'existing_profile_ids':[p.get('profile_id') for p in inference.get('profiles',[]) if p.get('address_key')==key],
          'alternatives':['Independent customer/merchant/automated treasury using one or more services.',
             'Exchange withdrawal funding or deposit does not prove exchange ownership of the intermediary.',
             'Temporal multiactive movement can be rebalancing, custody or a settlement; current controller is unconfirmed.'],
          'limitations':['Partial retained history; sampled first/last observations are not lifetime activity boundaries.',
             'Multiple assets in one trace are one dependency group, not independent operator confirmations.',
             'A matching or conserved sum does not identify particular fungible units, a customer account or a physical person.']}
        out['candidates'].append(candidate)
        out['evidence'].append({'evidence_id':eid,'source':METHOD,'upstream':'existing_proven_financial_operations','relation':'possible_typed_infrastructure_roles',
            'address':candidate['address'],'blockchain':candidate['blockchain'],'facts':{k:v for k,v in candidate.items() if k!='evidence_ids'},'evidence_ids':refs})
        for role in qualified:
            hid=_id('hypothesis',[cid,role]);out['hypotheses'].append({'hypothesis_id':hid,'subject':key,'service_id':service,
                'claim_type':'infrastructure_role','role':role,'status':'POSSIBLE','method':METHOD,'evidence_ids':refs+[eid],
                'dependency_groups':sorted(dep_in|dep_out),'role_assessment':assessments[role],'service_control':'UNKNOWN',
                'transaction_edge':False,'exact_funds_traced':False,'source_candidate_ids':candidate['source_candidate_ids']})
        out['relationships'].append({'relationship_id':cid,'from_key':key,'to_key':references[0]['address_key'],
            'members':[key]+sorted(linked_keys),'blockchain':candidate['blockchain'],'service_id':service,'service':name,
            'type':'POSSIBLE INFRASTRUCTURE ROLE — '+name,'category':'INFRASTRUCTURE CANDIDATE','scope':'service_role_hypothesis',
            'status':'POSSIBLE','roles':qualified,'method':METHOD,'transaction_edge':False,
            'edge_semantics':'analytical_role_association_not_a_transaction','evidence_ids':refs+[eid],
            'service_control':'UNKNOWN','exact_funds_traced':False,'candidate':candidate})
    out['coverage']={'status':'TRUNCATED' if truncated else 'PARTIAL','max_seconds':1.0,'elapsed_seconds':time.monotonic()-started,
        'candidate_bindings_available':len(bindings),'candidate_bindings_examined':examined,'candidate_limit':64,
        'existing_paths_checked':len(ready_paths),'existing_candidates_unchanged':True,'source_dtos_modified':False,
        'runtime_http_requests':0,'new_graph_algorithms':0,'label_propagation':False,'promoted_service_anchors':0,
        'role_types':list(ROLES),'unknown_role_assessments':rejected[:64],
        'proof_operations_available':len(operation_index),'history_complete':False}
    return out
