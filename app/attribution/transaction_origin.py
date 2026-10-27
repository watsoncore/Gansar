"""Transaction-scoped attribution inside the existing evidence engine.

Pure projection of collected data; no I/O, clustering or signing-app promotion.
Protocol findings and current code are explicitly distinguished from asset flow.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import time

from app.utils.event_identity import event_identity, canonical_hash, transaction_success
from app.utils.security import sanitize_observation, safe_public_url
from .normalize import address_id, EVM_CHAINS
from .evm_transaction_fingerprints import analyze_evm_transaction
from .utxo_transaction_fingerprints import analyze_utxo_transaction
from .program_transaction_fingerprints import analyze_solana_transaction, analyze_tron_transaction, is_tron_non_monetary

LIMITATIONS = [
    'A labeled direct sender identifies published service infrastructure, not the beneficiary, signing UI or source of earlier hops.',
    'Implementation and construction observations do not authenticate the application used to create, sign or import this account.',
    'Current runtime/state is not historical implementation proof; transaction receipt findings refer to protocol operations, not every projected asset movement.',
    'Collected history and method coverage are partial. Missing sources and absent markers do not exclude applications.',
]

def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,default=str,separators=(',',':')).encode()).hexdigest()

def _services(keys, addresses, role):
    observations=[]
    for key in keys:
        record=addresses.get(key) or {}
        for claim in record.get('attributions',[])[:64]:
            if claim.get('status')=='UNKNOWN':continue
            observations.append({'address_key':key,'address':record.get('address'), 'role':role,
                'service_name':claim.get('entity_name') or claim.get('name'), 'service_id':claim.get('service_id'),
                'status':claim.get('status','UNKNOWN'), 'published_role':claim.get('relationship'),
                'category':claim.get('entity_type') or claim.get('category'),
                'provenance_tier':'PUBLICLY_CLAIMED_SOURCE', 'evidence_ids':claim.get('evidence_ids',[]),
                'source_urls':claim.get('source_urls',[]), 'observed_at':claim.get('observed_at'),
                'conflicts':record.get('conflicts',[]), 'physical_controller_known':False})
    return observations

def _ton_findings(tx, payload):
    result={key:[] for key in ('implementation_observations','construction_fingerprints','investigative_leads','checks','evidence','limitations')}
    # Both transaction and immutable message scope are required when available.
    # Incoming copies of a request cannot borrow an outgoing app marker.
    target=payload.get('addresses',{}).get(payload.get('target_key'),{})
    client=target.get('client_attribution') or {}
    raw=tx.raw or {};message=raw.get('message') or {}
    if not message and raw.get('message_index')=='in':message=(raw.get('transaction') or {}).get('in_msg') or {}
    message_hash=canonical_hash(message.get('hash') or message.get('msg_hash') or raw.get('message_hash'))
    tx_hash=canonical_hash(tx.tx_hash) or tx.tx_hash
    for observation in client.get('observations',[]):
        if observation.get('transaction_hash')!=tx_hash:continue
        if (message_hash or observation.get('message_hash')) and observation.get('message_hash')!=message_hash:continue
        # Observations are bound to a native account request; from/to projected
        # event rows with no matching message keep the account-transaction scope.
        result['construction_fingerprints'].append({**observation,
            'scope':'matching_native_message' if message_hash else 'matching_account_transaction; projected message identity unavailable',
            'signing_application_confirmed':False})
    ids={o.get('observation_id') for o in result['construction_fingerprints']}
    for lead in client.get('investigative_leads',[]):
        refs=[e for e in lead.get('evidence_ids',[]) if e in ids]
        if refs:result['investigative_leads'].append({**lead,'evidence_ids':refs, 'signing_application_confirmed':False})
    result['checks'].append({'method':'ton_existing_native_request_markers',
        'status':'observed' if ids else 'unavailable', 'absence_excludes_application':False,
        'reason':'Only collected observations with the same transaction/message identity are attached.'})
    return result

def attach_transaction_origins(report, payload, *, max_operations=20000, max_seconds=2.5, session_observations=None, analysis_performed_at=None):
    """Attach bounded operation views + one shared proof set per technical scope."""
    started=time.monotonic(); now=analysis_performed_at or datetime.now(timezone.utc).isoformat()
    addresses=payload.get('addresses',{}); rows={r['event_id']:r for r in payload.get('transactions',[])}
    origins={}; findings={}; evidence={r['evidence_id']:r for r in payload.get('evidence',[]) if r.get('evidence_id')}
    errors=[]; seen=set();truncated=False
    for tx in report.transactions:
        if len(origins)>=max_operations or time.monotonic()-started>max_seconds:truncated=True;break
        identity=event_identity(tx)
        if identity in seen or identity not in rows:continue
        seen.add(identity); row=rows[identity];chain=tx.chain
        keys=row.get('sender_service_keys',[]);recipient_keys=row.get('recipient_service_keys',[])
        receipt=next(((tx.raw or {})[k] for k in ('receipt','transaction_receipt','rpc_receipt')
            if isinstance((tx.raw or {}).get(k),dict)),None)
        cache_scope=(chain,tx.tx_hash,tx.from_address,tx.to_address,tx.source,tx.success,
            _digest(receipt) if receipt is not None else None,identity if chain=='ton' or not tx.tx_hash else '')
        technical_ref='transaction-origin:technical:'+_digest(cache_scope)
        if technical_ref not in findings:
            detector=analyze_evm_transaction if chain in EVM_CHAINS else analyze_utxo_transaction if chain in {'btc','doge'} else analyze_solana_transaction if chain=='solana' else analyze_tron_transaction if chain=='tron' else None
            try: result=detector(tx,addresses) if detector else _ton_findings(tx,payload)
            except (ValueError,TypeError,KeyError,IndexError,AttributeError,OverflowError) as exc:
                # Optional fingerprints cannot discard collected data. Failure is
                # retained as unavailable coverage, never a negative finding.
                error={'source':'transaction_origin','blockchain':chain,'transaction_hash':tx.tx_hash,'error_type':type(exc).__name__}
                errors.append(error)
                result={'checks':[{'method':'transaction_fingerprints','status':'unavailable','error':error}], 'limitations':['Detector could not interpret collected fields.']}
            for key in keys:
                subject=addresses.get(key) or {};contract=subject.get('contract') or {}
                if contract.get('kind') not in (None,'unknown'):
                    result.setdefault('implementation_observations',[]).append({
                        'method':'collected_account_implementation_context','subject_address':subject.get('address'),
                        'scope':'collected account state/encoding; not historical transaction implementation',
                        'status':contract.get('status','UNKNOWN'),'evidence_ids':list(contract.get('evidence_ids',[])),
                        'fields':{k:contract[k] for k in ('kind','implementation','code_hash','owner_program') if k in contract},
                        'observed_at':subject.get('observed_at'),'signing_application_confirmed':False})
            for proof in result.get('evidence',[]):
                if proof.get('evidence_id'):evidence[proof['evidence_id']]={**proof,'observed_at':proof.get('observed_at') or now}
            for field in ('implementation_observations','construction_fingerprints','investigative_leads'):
                for observation in result.get(field,[]):
                    observation.setdefault('rule_version','2026-10-20.1')
                    observation.setdefault('analysis_performed_at',now)
                    observation.setdefault('signing_application_confirmed',False)
                    proof_id='transaction-origin:proof:'+_digest([technical_ref,field,observation])
                    refs=list(observation.get('evidence_ids',[]))
                    observation['evidence_ids']=refs
                    url=next((safe_public_url(u) for u in observation.get('source_urls',[]) if safe_public_url(u)), '')
                    evidence[proof_id]={'evidence_id':proof_id,'source':'offline_transaction_fingerprint',
                        'url':url,'observed_at':now,'blockchain':chain,'transaction_hash':tx.tx_hash,
                        'relation':field,'facts':{k:v for k,v in observation.items() if k!='evidence_ids'},
                        'source_independence':'Source count does not establish independent origin confirmation.'}
                    if proof_id not in refs:refs.append(proof_id)
            findings[technical_ref]={k:v for k,v in result.items() if k!='evidence'}
            findings[technical_ref].update(blockchain=chain,transaction_hash=tx.tx_hash,
                scope='collected transaction / current implementation facts; inspect each subject and time scope',
                transaction_source_url=safe_public_url(tx.url) or '',analysis_performed_at=now)
            for observation in result.get('implementation_observations',[]):
                subject=addresses.get(address_id(chain,observation.get('subject_address')))
                if subject:
                    observations=subject.setdefault('contract',{}).setdefault('transaction_implementation_observations',[])
                    if len(observations)<50:observations.append({'technical_ref':technical_ref,
                        'transaction_hash':tx.tx_hash,'scope':observation.get('scope') or observation.get('role'),
                        'facts':observation.get('fields') or observation.get('facts'),
                        'implementation':observation.get('implementation'),'evidence_ids':observation.get('evidence_ids',[])})
        services=_services(keys,addresses,'utxo_input_address' if chain in {'btc','doge'} else 'direct_asset_sender')
        strong={s['service_id'] for s in services if s['status'] in {'PROBABLE','CONFIRMED'}}
        conflicting=any(s.get('conflicts') for s in services)
        status='CONFLICTING' if conflicting or (chain not in {'btc','doge'} and len(strong)>1) else 'OBSERVED' if services else 'UNKNOWN'
        nonmoney=str((tx.raw or {}).get('type') or '').lower() in {'approval','resource','permission_update'}
        nonmoney=nonmoney or is_tron_non_monetary(tx)
        origins[identity]={'schema_version':'1.0','event_id':identity,'blockchain':chain,'transaction_hash':tx.tx_hash,
            'sender_keys':keys,'recipient_keys':recipient_keys,'success':transaction_success(tx),
            'movement_scope':'non_monetary_or_allowance' if nonmoney else 'utxo_inputs_outputs; no allocation or change inferred' if chain in {'btc','doge'} else 'collector_projected_asset_operation',
            'originating_service':{'status':status,'observations':services, 'beneficiary_known':False,
                'scope':'per input label; not entire transaction or recipient attribution' if chain in {'btc','doge'} else 'exact direct sender; no tracing of earlier funding hops'},
            'recipient_services':_services(recipient_keys,addresses,'direct_recipient'),
            'wallet_application':{'status':'UNKNOWN','provenance_tier':'UNKNOWN', 'creation_application':'UNKNOWN',
                'signing_application':'UNKNOWN','import_application':'UNKNOWN',
                'reason':'No independently authenticated signing-application evidence for this operation.'},
            'technical_ref':technical_ref,'evidence_ids':list(row.get('evidence_ids',[])),
            'coverage':{'status':'PARTIAL','history_complete':False},'limitations':LIMITATIONS}
    accepted=0;rejected=0
    for session in (session_observations or [])[:100]:
        if not isinstance(session,dict):rejected+=1;continue
        key=address_id(session.get('blockchain'),session.get('address'))
        artifact=str(session.get('artifact_sha256') or '')
        required=('application_id','observed_at','observer','transaction_hash','protocol')
        if (session.get('consent') is not True or session.get('observer_verified') is not True
                or not all(isinstance(session.get(k),str) and session[k] for k in required)
                or len(artifact)!=64 or any(c not in '0123456789abcdef' for c in artifact.lower())):
            rejected+=1;continue
        matches=[row for row in origins.values() if key in row['sender_keys'] and row['blockchain']==session.get('blockchain')
                 and row['transaction_hash']==session['transaction_hash']]
        if not matches:rejected+=1;continue
        clean={k:session[k] for k in required}
        clean.update(address_key=key,artifact_sha256=artifact,consent=True,
            provenance_tier='PUBLICLY_CLAIMED_SOURCE',public_osint=False,application_binary_authenticated=False,
            limitations=['Voluntary observer assertion bound to address and transaction; no independent binary attestation.',
                         'Session metadata and signed address/domain proofs do not attest the wallet application binary.'])
        for row in matches:row.setdefault('off_chain_observations',[]).append(clean)
        accepted+=1
    payload['transaction_origins']=origins;payload['transaction_fingerprints']=findings
    payload['transaction_origin_coverage']={'status':'TRUNCATED' if truncated else 'PARTIAL',
        'operations_available':len(rows),'operations_analyzed':len(origins),'technical_scopes':len(findings),
        'max_operations':max_operations,'max_seconds':max_seconds,'network_requests':0,
        'independently_confirmed_signing_applications':0,'unknown_signing_applications':len(origins),
        'voluntary_session_observations_accepted':accepted,'voluntary_session_observations_rejected':rejected,
        'elapsed_seconds':time.monotonic()-started,'errors':errors}
    payload['evidence']=list(evidence.values())
    payload.setdefault('errors',[]).extend(errors)
    payload.setdefault('stats',{})['evidence']=len(evidence)
    return payload
