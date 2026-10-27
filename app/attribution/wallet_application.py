"""Evidence-based wallet application checks over the existing report.

This layer does no I/O and never changes transactions. Public implementation,
construction marker, custody label and signing application are separate claims.
An application marker is a reproducible hypothesis, not operator ground truth.
"""
from __future__ import annotations
from collections import Counter
from datetime import datetime,timezone
from functools import lru_cache
import hashlib,json,pathlib,time
from .normalize import address_id,canonical_address,EVM_CHAINS
from .wallet_payload import body_boc,decode_token_header,decode_wallet_body
from .wallet_service_payload import BATTERY_RECEIVER,BATTERY_SOURCES,decode_battery_purchase,decode_subscription_deploy,decode_evm_application_swap
from .wallet_extensions import extension_implementation,decode_extension_install
from app.utils.security import safe_public_url,sanitize_observation
from app.utils.event_identity import transaction_success
from app.ton_nft.analytics import canonical_hash

TON_SDK='https://github.com/ton-org/ton/blob/311dc3313dd31e44781551b398b92256518b2c61/src/wallets/signing/createWalletTransfer.ts'
TONKEEPER_MARKER='https://github.com/tonkeeper/tonkeeper-web/blob/d7ea32150635b53b8bc6fb6c5744434d9370a347/packages/core/src/service/ton-blockchain/utils.ts'
TG_SOURCE='https://github.com/ton-blockchain/tg-wallet-contract/tree/1a29ae5d90e03c3d585d3e42e6ecef691d727a3c'
TG_IMPORT='https://github.com/mytonwallet-org/mytonwallet/blob/bb3f357690633d274e390e799babaf1d642b31de/src/api/chains/ton/contracts/TelegramWallet.ts'
TC_SOURCE='https://github.com/ton-connect/sdk/blob/04f67c7f0a22a01cdadf4cd7a1634945988cb4ec/packages/protocol/src/models/device-info.ts'
MY_FEE_SOURCE='https://github.com/mytonwallet-org/mytonwallet/blob/bb3f357690633d274e390e799babaf1d642b31de/src/api/chains/ton/util/tonCore.ts'
APP_SWAP_SOURCES={
 'metamask':['https://github.com/MetaMask/metamask-extension/blob/14903a14b7d256d9950754cc1141269784a1cbcd/shared/constants/swaps.ts'],
 'rainbow':['https://github.com/rainbow-me/swaps/blob/a31dae44b836dbb4dc75544974542be6866c2477/sdk/src/quotes.ts',
            'https://github.com/rainbow-me/swaps/blob/a31dae44b836dbb4dc75544974542be6866c2477/sdk/src/utils/constants.ts'],
}
APP_SWAP_ROUTERS={
 'metamask':{'eth':'0x881d40237659c251811cec9c364ef91dc08d300c',
    'bsc':'0x1a1ec25dc08e98e5e93f1104b5e5cdd298707d31','polygon':'0x1a1ec25dc08e98e5e93f1104b5e5cdd298707d31',
    'avalanche':'0x1a1ec25dc08e98e5e93f1104b5e5cdd298707d31',
    'optimism':'0x9dda6ef3d919c9bc8885d5560999a3640431e8e6','arbitrum':'0x9dda6ef3d919c9bc8885d5560999a3640431e8e6'},
 'rainbow':{chain:'0x00000000009726632680fb29d3f7a9734e3010e2' for chain in ('eth','bsc','polygon','avalanche','optimism','arbitrum')},
}
TONKEEPER_PRO_RECEIVER='0:b16a061860c9f389d4ef41fdfdaa7914bc09167db9f5377b5ea95c504ed76b77'
TONKEEPER_PRO_SOURCE='https://github.com/tonkeeper/ton-assets/blob/922e01fb5190430cd698d769802b235ce8facb66/accounts/infrastructure.yaml'
TG_HASH='9149ae51c1e4689710cebf7830297b16acfbadb363a920a537893e7ffeeca768'
LIMITS=[
 'Parsing a message does not verify its signature, successful execution, current custody or signing application.',
 'Public contract standards and SDK defaults are reusable by unrelated applications.',
 'The same key/account can be imported into another app; historical and current signing clients can differ.',
 'Provider pages can be incomplete. A missing marker does not exclude an application.',
 'Repeated copies of one marker or one upstream are not independent app confirmations.',
]

@lru_cache(maxsize=1)
def application_catalogue():
    path=pathlib.Path(__file__).with_name('assets')/'wallet_applications.json'
    return json.loads(path.read_text(encoding='utf-8'))

def _construction_rules(catalogue):
    """Declarative, non-executable extension point, always confidence-capped.

    Source presence records provenance; it is not independent corroboration.
    Third-party rule data cannot opt into a CONFIRMED/PROBABLE app conclusion.
    """
    entities={r.get('entity_id'):r for r in catalogue.get('entities',[]) if isinstance(r,dict)}
    accepted=[]
    for row in catalogue.get('construction_rules',[])[:64]:
        if not isinstance(row,dict) or row.get('kind') not in {'query_id_prefix','exact_nested_cell_opcode'}:continue
        if not isinstance(row.get('rule_id'),str) or not 1<=len(row['rule_id'])<=100:continue
        value=row.get('value');entity=entities.get(row.get('entity_id'));sources=row.get('source_urls')
        if not entity or not isinstance(value,str) or len(value)!=10 or not value.startswith('0x'):continue
        try:int(value[2:],16)
        except ValueError:continue
        if not isinstance(sources,list) or not sources or not all(safe_public_url(u) for u in sources):continue
        accepted.append({**row,'value':value.lower(),'name':entity.get('brand',row['entity_id']),'max_status':'POSSIBLE'})
    return accepted

def _address(value):
    if isinstance(value,dict):value=value.get('address')
    return canonical_address('ton',value)

def _base(record):
    return {'status':'UNKNOWN','name':None,'application_id':None,'method':'public_evidence_checks',
      'reason':'Collected public evidence does not uniquely identify the signing application.',
      'evidence_ids':[],'checks':[],'observations':[],'candidates':[],'investigative_leads':[],
      'application_findings':[],
      'rejected_hypotheses':[],'unavailable_methods':[],
      'additional_evidence_needed':['A documented application-specific implementation with independent validation and a role that actually establishes application use.',
         'Optional user-authorized observation of an actual signing session, explicitly marked off-chain; a wallet name supplied in context is insufficient.'],
      'alternatives':['Another compatible client or SDK can construct the same request.','Custodial infrastructure may sign while the customer sees a different interface.'],
      'limitations':list(LIMITS),'coverage':{'network_requests':0,'history_complete':False,'address':record.get('address'),'blockchain':record.get('blockchain')}}

def analyze_wallet_applications(report,payload,*,max_records=100_000,max_observations=1000,max_seconds=3.0,user_verified_observations=None,indicator_catalogue=None):
    """Attach target and per-account checks without requesting private telemetry.

    Explicit off-chain observations are returned in a separate collection. They
    never turn into public-OSINT CONFIRMED application claims or chain evidence.
    No raw provider metadata can opt itself into this method.
    """
    if max_records<0 or max_observations<0 or max_seconds<0:raise ValueError('analysis limits must be nonnegative')
    start=time.monotonic();addresses=payload.get('addresses',{});target_key=payload.get('target_key')
    target=addresses.get(target_key);evidence={e.get('evidence_id'):e for e in payload.get('evidence',[])}
    for key,record in addresses.items():
        result=_base(record);contract=record.get('contract') or {};version=contract.get('wallet_version')
        refs=contract.get('evidence_ids',[])
        result['checks'].append({'method':'contract_implementation','status':'observed' if contract.get('code_hash') or version else 'unavailable',
            'result':{'kind':contract.get('kind'),'version':version,'code_hash':contract.get('code_hash')},
            'source_urls':[TON_SDK] if record.get('blockchain')=='ton' else [],'evidence_ids':refs,
            'limits':['Contract implementation is not a signing-application identity.']})
        result['rejected_hypotheses'].append({'hypothesis':'Standard contract/address encoding determines wallet application',
            'reason':'Multiple apps and shared SDKs support the same implementation or key.','source_urls':[TON_SDK,TG_IMPORT] if record.get('blockchain')=='ton' else []})
        result['checks'].append({'method':'service_vs_signing_application','status':'observed',
            'result':{'published_address_labels':len(record.get('attributions',[]))},'source_urls':[],
            'evidence_ids':list(dict.fromkeys(e for c in record.get('attributions',[]) for e in c.get('evidence_ids',[]))),
            'limits':['Service labels concern this address only; a transfer does not establish the target app, shared controller, custody assignment or physical owner.']})
        implementation=extension_implementation(contract.get('code_hash')) if record.get('blockchain')=='ton' else None
        if implementation:
            result['checks'].append({'method':'documented_wallet_extension_implementation','status':'observed',
                'result':implementation,'source_urls':implementation['source_urls'],'evidence_ids':refs,
                'limits':['Current code identity establishes an implementation, not the deploying operator, active wallet authorization or signing UI.','Library-reference identity does not independently verify the currently resolved library code.']})
            result['investigative_leads'].append({'method':'documented_wallet_extension_implementation','status':'POSSIBLE',
                'scope':'extension_implementation_origin','result':implementation,'source_urls':implementation['source_urls'],
                'evidence_ids':refs,'signing_application_confirmed':False,
                'limitations':['Public extension code can be deployed and operated by other applications.']})
        record.pop('wallet_application',None);record['client_attribution']=result
        record['custodial_service']={'status':'UNKNOWN','name':None,'evidence_ids':[],
            'reason':'Public labels alone do not establish assignment of this address to a customer or its custody role.'}
        record['service_infrastructure']=[{'entity_id':c.get('service_id'),'name':c.get('name') or c.get('entity_name'),
            'status':c.get('status'),'relationship':c.get('relationship'),'evidence_ids':c.get('evidence_ids',[])} for c in record.get('attributions',[])]
    if not target:
        payload['wallet_application']={'status':'UNKNOWN','name':None,'reason':'Target network/account was not resolved.','checks':[]};return payload['wallet_application']
    result=target['client_attribution'];chain=target.get('blockchain');contract=target.get('contract') or {};version=contract.get('wallet_version')
    catalogue=application_catalogue() if indicator_catalogue is None else indicator_catalogue
    result['catalogue_entities_researched']=[r['entity_id'] for r in catalogue['entities']]
    construction_rules=_construction_rules(catalogue);matched_rules={}
    observations=[];observation_proofs={};marker_observation_ids=set()
    seen_messages=set();seen_accounts=set();counts=Counter();markers=[];fee_markers=[];source_families=set();truncated=False
    nft_native_index=None
    service_leads={};seen_service_messages=set();seen_evm_app_calls=set()
    def observation(kind,fields,tx,message,source_url,scope,refs=(),*,application_marker=False):
        nonlocal truncated
        basis={'kind':kind,'transaction_hash':canonical_hash(tx.tx_hash) or tx.tx_hash,'message_hash':canonical_hash(message.get('hash')),'fields':fields,
               'source':tx.source,'source_url':safe_public_url(source_url),'address_key':target_key,'scope':scope}
        oid='wallet-app:observation:'+hashlib.sha256(json.dumps(basis,sort_keys=True,default=str).encode()).hexdigest()
        if len(observations)>=max_observations:
            truncated=True
            # Generic headers must not hide a later application construction
            # marker. Replace only a generic sample, keeping the same hard cap.
            replace=next((i for i,row in enumerate(observations)
                if row['observation_id'] not in marker_observation_ids),None) if application_marker and len(marker_observation_ids)<len(observations) else None
            if replace is None:
                counts['marker_observations_omitted' if application_marker else 'generic_observations_omitted']+=1
                return None
            discarded=observations.pop(replace)
            observation_proofs.pop(discarded['observation_id'],None)
            counts['generic_observations_omitted']+=1
            counts['marker_priority_replacements']+=1
        observed=(tx.raw or {}).get('collected_at') or (tx.raw or {}).get('observed_at')
        timestamps={'transaction_timestamp':tx.timestamp.isoformat() if tx.timestamp else None,
            'observed_at':observed,'analysis_performed_at':datetime.now(timezone.utc).isoformat(),
            'source_observation_time_available':bool(observed)}
        row={**basis,**timestamps,'observation_id':oid,'fields':fields,'evidence_ids':list(refs),'source_urls':[source_url] if safe_public_url(source_url) else [],'limitations':LIMITS[:3]}
        observations.append(row)
        if application_marker:marker_observation_ids.add(oid)
        # A stable proof keeps the original provider URL, hash and observed fields.
        fact={**basis,**timestamps,'evidence_id':oid,'relation':kind,'facts':fields,
              'source_independence':'Provider observations of the same physical message are not independent app confirmations.'}
        # Commit only the retained sample below. Existing report proofs are not
        # removed when a generic sample is replaced by a construction marker.
        observation_proofs[oid]=fact
        return row
    def application_finding(application_id,name,category,method,rows,scope,source_urls,*,limitations=()):
        # This names the observed application service/construction, never the
        # signing client. Existing checks render these records without UI edits.
        rows=[row for row in rows if row and row.get('observation_id')]
        if not rows:return
        finding={'application_id':application_id,'application':name,'category':category,'method':method,
            'status':'OBSERVED','claim_scope':scope,'signing_application':'UNKNOWN',
            'signing_application_confirmed':False,'exclusive_to_signing_client':False,
            'evidence_ids':list(dict.fromkeys(row['observation_id'] for row in rows)),
            'transaction_hashes':list(dict.fromkeys(row['transaction_hash'] for row in rows)),
            'source_urls':list(source_urls),'limitations':list(limitations)+[
                'A different wallet, dApp or script can call this public service or reproduce its construction.',
                'This observation does not authenticate the user-facing signing application.']}
        existing=next((f for f in result['application_findings'] if (f['application_id'],f['category'],f['method'])==(application_id,category,method)),None)
        if existing:
            for field in ('evidence_ids','transaction_hashes'):
                existing[field][:]=list(dict.fromkeys(existing[field]+finding[field]))
            return
        result['application_findings'].append(finding)
        result['checks'].append({'method':category.replace('_',' ')+': '+name,'status':'observed',
            'result':finding,'source_urls':list(source_urls),'evidence_ids':finding['evidence_ids'],'limits':finding['limitations']})
    if chain=='ton':
        # An exact WalletTg hash identifies its public trampoline implementation;
        # MyTonWallet supports importing the same accounts and rotating the key.
        if contract.get('code_hash')==TG_HASH:
            result['checks'].append({'method':'wallet_tg_trampoline','status':'observed',
                'result':{'implementation':'WalletTg','config_index':-123,'signing_app_proved':False},
                'source_urls':[TG_SOURCE,TG_IMPORT],'evidence_ids':contract.get('evidence_ids',[]),
                'limits':['The trampoline is published for Telegram-created wallets, but an external client can import/operate that implementation. Current custody is not established.']})
        if target.get('account_status') in {'uninit','nonexist','uninitialized'}:
            result['unavailable_methods'].append({'method':'deployed_code_and_request_layout','reason':'Current account is undeployed. Address formatting and a deposit interface do not establish deployment code or a service-specific derivation.'})
        for tx in report.transactions:
            if tx.chain!='ton':continue
            if counts['transaction_rows_examined']>=max_records or time.monotonic()-start>max_seconds:truncated=True;break
            counts['transaction_rows_examined']+=1
            raw=tx.raw or {};account_tx=raw.get('transaction') or {}
            reference=raw.get('original_reference') or (raw.get('nft_intelligence') or {}).get('raw_reference')
            if not account_tx and isinstance(reference,dict) and reference.get('collection')=='events':
                if nft_native_index is None:
                    nft_native_index={}
                    events=(report.nft_intelligence or {}).get('events') or []
                    for event in events[:max_records]:
                        if not isinstance(event,dict):continue
                        native=(event.get('raw') or {}).get('transaction_details')
                        if isinstance(native,dict):nft_native_index[event.get('event_id')]=native
                native=nft_native_index.get(reference.get('id'))
                if native:
                    native_id=canonical_hash(native.get('hash') or (native.get('transaction_id') or {}).get('hash'))
                    projected_id=canonical_hash(tx.tx_hash)
                    if native_id and projected_id and native_id==projected_id:
                        account_tx=native;counts['shared_nft_native_references_resolved']+=1
                    else:counts['shared_nft_native_reference_hash_mismatch']+=1
                else:counts['shared_nft_references_without_native_boc']+=1
            native_id=account_tx.get('transaction_id') if isinstance(account_tx,dict) else None
            native_hash=(account_tx.get('hash') or (native_id.get('hash') if isinstance(native_id,dict) else None)) if isinstance(account_tx,dict) else None
            native_digest=canonical_hash(native_hash)
            if native_hash and native_digest!=canonical_hash(tx.tx_hash):
                counts['native_transaction_hash_mismatch']+=1;continue
            messages=[]
            if isinstance(account_tx,dict) and account_tx:
                account=_address(account_tx.get('account') or account_tx.get('address'))
                if not account and isinstance(account_tx.get('in_msg'),dict):account=_address(account_tx['in_msg'].get('destination'))
                akey=(account,str(account_tx.get('hash') or tx.tx_hash),tx.source)
                if akey not in seen_accounts:
                    seen_accounts.add(akey)
                    if isinstance(account_tx.get('in_msg'),dict):messages.append((account_tx['in_msg'],'in',account))
                    outbound=account_tx.get('out_msgs') or []
                    for msg in (outbound if isinstance(outbound,list) else [])[:256]:
                        if isinstance(msg,dict):messages.append((msg,'out',account))
            if isinstance(raw.get('message'),dict):messages.append((raw['message'],'in' if raw.get('message_index')=='in' else 'out',_address(report.target_address)))
            for msg,direction,account in messages:
                if counts['messages_examined']>=max_records or time.monotonic()-start>max_seconds:truncated=True;break
                counts['messages_examined']+=1
                value=body_boc(msg)
                if not value:counts['messages_without_body']+=1;continue
                frm,to=_address(msg.get('source')),_address(msg.get('destination'))
                # Only explicit target-origin output or requests addressed TO the
                # target may inform this account's construction observations.
                originated=frm==target['address'] or (direction=='out' and account==target['address'] and not frm)
                addressed=to==target['address'] or (direction=='in' and account==target['address'] and not to)
                if not originated and not addressed:continue
                mid=canonical_hash(msg.get('hash')) or (canonical_hash(tx.tx_hash) or tx.tx_hash,hashlib.sha256(value.encode()).hexdigest())
                key=(mid,originated,addressed)
                duplicate=key in seen_messages
                if not duplicate:
                    seen_messages.add(key);counts['bodies_examined']+=1;source_families.add(tx.source)
                description=account_tx.get('description') or {}
                failed_native=account_tx.get('aborted') is True or account_tx.get('success') is False or (isinstance(description,dict) and description.get('aborted') is True)
                successful=transaction_success(tx) is True and not failed_native and raw.get('emulated') is not True and account_tx.get('emulated') is not True
                # Recipient receipts and source transactions can contain the
                # same message. Their success flags describe different TVM
                # executions. Require the relevant native account, regardless
                # of which provider copy was encountered first.
                native_account=_address(account_tx.get('account') or account_tx.get('address'))
                native_outbound=account_tx.get('out_msgs') or []
                native_message=isinstance(native_outbound,list) and any(msg is native for native in native_outbound[:256])
                new_service_origin=(originated and direction=='out' and native_account==target['address'] and
                    isinstance(native_digest,str) and len(native_digest)==64 and all(c in '0123456789abcdef' for c in native_digest) and
                    native_message and (mid,'source') not in seen_service_messages)
                if new_service_origin and to==BATTERY_RECEIVER:
                    counts['battery_destination_bodies_examined']+=1
                    try:
                        purchase=decode_battery_purchase(value)
                        if purchase and successful:
                            purchase.update(recipient=to,origin_verification='target_originated_successful_source_transaction',recipient_execution_verified=False)
                            row=observation('battery_purchase_construction',purchase,tx,msg,tx.url,'documented_service_request',application_marker=True)
                            if row:
                                seen_service_messages.add((mid,'source'))
                                service_leads.setdefault('battery_purchase',{'rows':[],'source_urls':BATTERY_SOURCES,'scope':'service_request_construction','name':'Tonkeeper Battery purchase-compatible request'})['rows'].append(row)
                    except (ValueError,OverflowError,TypeError):counts['unsupported_battery_purchase_bodies']+=1
                init=msg.get('init')
                init_boc=init.get('boc') if isinstance(init,dict) else None
                if new_service_origin and successful and init_boc:
                    try:
                        subscription=decode_subscription_deploy(value,state_init=init_boc)
                        if (subscription and subscription.get('initial_state_verified') and
                                subscription.get('deployment_address')==to and subscription.get('initial_wallet')==target['address']):
                            subscription.update(recipient=to,source_execution_verified=True,recipient_execution_verified=False,
                                service_credit_verified=False,publisher_binding_scope='pinned publication; not historical operator or signer proof')
                            row=observation('documented_subscription_v2_deploy_request',subscription,tx,msg,tx.url,
                                'exact_stateinit_and_wallet_bound_request',application_marker=True)
                            if row:
                                service=subscription.get('withdraw_address')==TONKEEPER_PRO_RECEIVER
                                application_finding('tonkeeper','Tonkeeper (Pro subscription)' if service else 'Tonkeeper subscription implementation',
                                    'APPLICATION_INTERACTION' if service else 'APPLICATION_COMPATIBLE_CONSTRUCTION',
                                    'subscription_v2_bound_deploy_request',[row],
                                    'request_with_exact_implementation_wallet_binding_and_published_withdraw_target' if service else 'published_subscription_implementation_construction',
                                    subscription['source_urls']+([TONKEEPER_PRO_SOURCE] if service else []),
                                    limitations=['Source success does not establish recipient execution, current subscription status or off-chain Pro credit.',
                                        'The withdrawal address matches the pinned publisher catalogue; historic operator continuity is not inferred.'])
                    except (ValueError,OverflowError,TypeError):counts['unsupported_subscription_deploy_bodies']+=1
                receiver=addresses.get(address_id('ton',to),{})
                receiver_implementation=extension_implementation((receiver.get('contract') or {}).get('code_hash'))
                if new_service_origin and successful and receiver_implementation:
                    try:
                        install=decode_extension_install(value)
                        if install and install.get('construction_family_hint')==receiver_implementation['implementation_id']:
                            install.update(recipient=to,implementation=receiver_implementation,historical_code_verified=False)
                            row=observation('documented_wallet_extension_install_request',install,tx,msg,tx.url,'request_to_documented_extension',(receiver.get('contract')or{}).get('evidence_ids',[]),application_marker=True)
                            if row:
                                seen_service_messages.add((mid,'source'))
                                service_leads.setdefault('install:'+receiver_implementation['implementation_id'],{'rows':[],'source_urls':receiver_implementation['source_urls'],'scope':'extension_install_request','name':receiver_implementation['family']})['rows'].append(row)
                    except (ValueError,OverflowError,TypeError):counts['unsupported_extension_install_bodies']+=1
                sender=addresses.get(address_id('ton',frm),{})
                sender_implementation=extension_implementation((sender.get('contract')or{}).get('code_hash'))
                if addressed and direction=='in' and native_account==target['address'] and frm and successful and str(version).upper()=='V5R1' and sender_implementation and (mid,'recipient') not in seen_service_messages:
                    try:
                        header=decode_wallet_body(value,version)
                        if header.get('auth_mode')=='extension_authorized':
                            extension_state=(sender.get('contract')or{}).get('extension_state')or{}
                            bound_wallet=extension_state.get('bound_wallet')
                            fields={**header,'extension_address':frm,'implementation':sender_implementation,'historical_extension_membership_verified':False,
                                'current_stored_wallet':bound_wallet,'current_stored_wallet_matches_target':bound_wallet==target['address'] if bound_wallet else None,
                                'request_effect':'not_verified','current_code_does_not_establish_historical_registration':True}
                            row=observation('documented_wallet_extension_extension_request',fields,tx,msg,tx.url,'request_from_documented_extension',(sender.get('contract')or{}).get('evidence_ids',[]),application_marker=True)
                            if row:
                                seen_service_messages.add((mid,'recipient'))
                                service_leads.setdefault('extension:'+sender_implementation['implementation_id'],{'rows':[],'source_urls':sender_implementation['source_urls'],'scope':'extension_request_origin','name':sender_implementation['family']})['rows'].append(row)
                    except (ValueError,OverflowError,TypeError):counts['unsupported_extension_request_bodies']+=1
                if duplicate:counts['duplicate_message_observations']+=1;continue
                if originated:
                    try:
                        header=decode_token_header(value)
                        if header.get('query_id') is not None:
                            description=account_tx.get('description') or {}
                            failed_native=account_tx.get('aborted') is True or account_tx.get('success') is False or (isinstance(description,dict) and description.get('aborted') is True)
                            header['execution_status']='emulated' if raw.get('emulated') is True or account_tx.get('emulated') is True else 'failed' if failed_native or transaction_success(tx) is False else 'success' if transaction_success(tx) is True else 'unknown'
                            counts['token_headers_decoded']+=1
                            # Notifications/excesses echo another party's query
                            # ID. They cannot fingerprint the forwarding contract.
                            request=header.get('kind') in {'jetton_transfer_request','nft_transfer_request','jetton_burn_request'}
                            wallet_context=bool(version) and target.get('account_type') in {'wallet_contract','provider_reported_wallet'}
                            eligible=header['execution_status']=='success' and request and wallet_context
                            counts['eligible_request_headers_examined']+=int(eligible)
                            keeper=eligible and header.get('tonkeeper_query_namespace')
                            fee=eligible and header.get('mywallet_fee_payload_present')
                            rules=[rule for rule in construction_rules if eligible and
                                ((header.get('query_id_prefix')==rule['value']) if rule['kind']=='query_id_prefix'
                                 else rule['value'] in header.get('nested_exact_cell_opcodes',[]))]
                            counts['tonkeeper_marker_messages_decoded']+=int(bool(keeper))
                            counts['mywallet_marker_messages_decoded']+=int(bool(fee))
                            row=observation('ton_token_query_header',header,tx,msg,tx.url,'target_originated_payload',
                                application_marker=bool(keeper or fee or rules))
                            if keeper and row:markers.append(row)
                            if fee and row:fee_markers.append(row)
                            if row:
                                for rule in rules:
                                    matched_rules.setdefault(rule['rule_id'],{'rule':rule,'observations':[]})['observations'].append(row)
                    except (ValueError,OverflowError,TypeError):counts['unsupported_token_bodies']+=1
                message_type=str(msg.get('msg_type') or msg.get('type') or '')
                explicit_external=message_type in {'ext_in_msg','external-in','external_in'} or (direction=='in' and raw.get('external_message') is True)
                explicit_internal=message_type in {'int_msg','internal'} or bool(frm)
                channel='external' if explicit_external else 'internal' if explicit_internal else 'UNKNOWN'
                # A missing source alone is not proof that the message is external.
                if addressed and version and (explicit_external or str(version).upper() in {'V5R1','WALLETTG'}):
                    try:
                        header=decode_wallet_body(value,version)
                        if explicit_external and header.get('authorization','').startswith('internal'):raise ValueError('internal authorization in external message')
                        if explicit_internal and str(version).upper() in {'V5R1','WALLETTG'} and header.get('authorization','').startswith('external'):raise ValueError('external authorization in explicitly internal message')
                        header.update(message_channel=channel,auth_mode_basis='published_contract_body_layout',
                            message_channel_independently_verified=channel!='UNKNOWN')
                        if header.get('valid_until') is not None and tx.timestamp:
                            header['expiry_minus_block_time_seconds']=header['valid_until']-int(tx.timestamp.timestamp())
                            header['not_exact_construction_ttl']=True
                        observation('ton_wallet_request_layout',header,tx,msg,tx.url,'request_to_target_contract',contract.get('evidence_ids',[]))
                        counts['wallet_requests_decoded']+=1
                    except (ValueError,OverflowError,TypeError):counts['unsupported_wallet_bodies']+=1
        for method,lead in service_leads.items():
            result['investigative_leads'].append({'method':method,'name':lead['name'],'status':'POSSIBLE','scope':lead['scope'],
                'evidence_ids':[row['observation_id'] for row in lead['rows']],'source_urls':lead['source_urls'],
                'observed_messages':len(lead['rows']),'signing_application_confirmed':False,
                'limitations':['A public payload or extension can be used by another compatible client.','Source transaction success does not verify recipient execution, historical extension authorization, or off-chain service credit.','Current code context is not historical code verification.']})
            if method=='battery_purchase':
                application_finding('tonkeeper','Tonkeeper (Battery)','APPLICATION_INTERACTION',method,
                    lead['rows'],'successful_source_request_to_officially_published_battery_endpoint',lead['source_urls'],
                    limitations=['Recipient execution and off-chain Battery credit are not verified.'])
        result['checks'].append({'method':'documented_wallet_service_requests','status':'observed' if service_leads else 'unavailable',
            'result':{'matching_leads':len(service_leads),'battery_destination_bodies_examined':counts['battery_destination_bodies_examined'],
                'counterparty_code_required_for_2fa':True},'source_urls':BATTERY_SOURCES,
            'evidence_ids':[row['observation_id'] for lead in service_leads.values() for row in lead['rows']],
            'limits':['Only collected messages and available exact counterparty code observations are tested. Missing source data does not exclude application use.']})
        result['checks'].extend([
          {'method':'signed_request_construction','status':'observed' if counts['wallet_requests_decoded'] else 'unavailable',
           'result':{'decoded_requests':counts['wallet_requests_decoded'],'tested_fields':['authorization','wallet_id','seqno','valid_until','send_modes','batch_count','plugin_extension_flags']},
           'source_urls':[TON_SDK,TG_SOURCE],'evidence_ids':[o['observation_id'] for o in observations if o['kind']=='ton_wallet_request_layout'],
           'limits':['Current contract code is layout context; historical code and Ed25519 signatures are not verified by this parser.','valid_until minus block time includes propagation delay and is not the exact construction TTL.','Mode 3 and TTL60/300/600 are configurable/shared and cannot identify an app.']},
          {'method':'tonkeeper_query_id_namespace','status':'observed' if markers else 'unavailable' if counts['tonkeeper_marker_messages_decoded'] else 'not_found_in_checked_sample' if counts['eligible_request_headers_examined'] else 'unavailable',
           'result':{'namespace':'0x546de4ef','observed_target_originated_messages':len(markers),'distinct_transactions':len({m['transaction_hash'] for m in markers}),
               'decoded_marker_messages':counts['tonkeeper_marker_messages_decoded'],
               'marker_observations_omitted':counts['tonkeeper_marker_messages_decoded']-len(markers),
               'checked_request_headers':counts['eligible_request_headers_examined'],'scope':'eligible_request_headers_in_collected_transactions','absence_excludes_application':False},
           'source_urls':[TONKEEPER_MARKER],'evidence_ids':[o['observation_id'] for o in markers],
           'limits':['Official Tonkeeper code constructs this query prefix, but anyone can copy it, including dApps and imported payloads.','No validated population or exclusive signer identity; absence is not a negative app identification.']},
          {'method':'ton_connect_device_info','status':'unavailable','result':{'blockchain_recoverable':False},
           'source_urls':[TC_SOURCE],'evidence_ids':[],
           'limits':['appName/appVersion/device are connect-session data, not standard transaction fields; ton_proof proves a key relationship, not application binary authenticity.']},
        ])
        result['checks'].append({'method':'mywallet_fee_payload_marker','status':'observed' if fee_markers else 'unavailable' if counts['mywallet_marker_messages_decoded'] else 'not_found_in_checked_sample' if counts['eligible_request_headers_examined'] else 'unavailable',
            'result':{'exact_nested_cell_opcode':'0x4d238543','observed_request_messages':len(fee_markers),
                'decoded_marker_messages':counts['mywallet_marker_messages_decoded'],
                'marker_observations_omitted':counts['mywallet_marker_messages_decoded']-len(fee_markers),
                'checked_request_headers':counts['eligible_request_headers_examined'],'scope':'eligible_request_headers_in_collected_transactions','absence_excludes_application':False},
            'source_urls':[MY_FEE_SOURCE],'evidence_ids':[o['observation_id'] for o in fee_markers],
            'limits':['MyTonWallet code builds this fee payload, but the exact cell can be copied and delegated through another signer.','This is a service-fee construction observation; the recipient/service or application is not independently authenticated.']})
        application_finding('tonkeeper','Tonkeeper','APPLICATION_COMPATIBLE_CONSTRUCTION','tonkeeper_query_id_namespace',
            markers,'successful_target_originated_query_namespace', [TONKEEPER_MARKER],
            limitations=['The namespace is public and copyable; a dApp-supplied payload may use a different signer.'])
        application_finding('mytonwallet','MyTonWallet','APPLICATION_COMPATIBLE_CONSTRUCTION','mywallet_fee_payload_marker',
            fee_markers,'exact_nested_fee_cell_in_successful_target_request',[MY_FEE_SOURCE],
            limitations=['A matching fee cell is not authenticated service credit or signer identity.'])
        for match in matched_rules.values():
            rule=match['rule'];rows=match['observations']
            result['candidates'].append({'application_id':rule['entity_id'],'name':rule['name']+'-compatible construction','status':'POSSIBLE',
                'method':'documented_'+rule['kind'],'scope':'payload_construction_hypothesis',
                'rule_id':rule['rule_id'],'evidence_ids':[o['observation_id'] for o in rows],
                'source_urls':rule['source_urls'],'reason':'A successful target-originated token/NFT request matches the cited construction rule.',
                'alternatives':['A dApp supplied the payload to a different signer.','A copied SDK function, custom script, or imported wallet generated the same marker.'],
                'signing_application_confirmed':False,'independent_confirmation_count':0})
        result['checks'].append({'method':'declarative_construction_catalogue','status':'observed',
            'result':{'valid_rules_checked':len(construction_rules),'matching_rules':len(matched_rules)},
            'source_urls':list(dict.fromkeys(u for r in construction_rules for u in r['source_urls'])),'evidence_ids':[],
            'limits':['Rules are offline data with bounded supported operators; no repository or downloaded code is executed.','Rules cannot override the POSSIBLE construction-hypothesis confidence ceiling.']})
        result['rejected_hypotheses'].extend([
          {'hypothesis':'Send mode / TTL / default subwallet ID proves a brand','reason':'These fields are shared SDK defaults or caller-controlled; observed block delay is not construction time.','source_urls':[TON_SDK,TONKEEPER_MARKER]},
          {'hypothesis':'WalletTg proves the current Telegram signing client or custody','reason':'The public implementation can be operated by MyTonWallet and other compatible clients; key rotation is supported.','source_urls':[TG_SOURCE,TG_IMPORT]},
        ])
    elif chain in EVM_CHAINS:
        fingerprint=contract.get('kind');published=contract.get('manifest_code_match') or contract.get('published_deployment')
        result['checks'].append({'method':'evm_smart_wallet_implementation','status':'observed' if fingerprint and fingerprint!='unknown' else 'unavailable',
            'result':{'runtime_kind':fingerprint,'implementation':contract.get('implementation'),'published_deployment_match':published},
            'source_urls':['https://eips.ethereum.org/EIPS/eip-7702','https://eips.ethereum.org/EIPS/eip-1167','https://github.com/safe-global/safe-deployments'],
            'evidence_ids':contract.get('evidence_ids',[]),'limits':['A Safe implementation or factory is wallet infrastructure; any compatible interface may submit transactions.','EIP-7702 designators identify delegated code, not MetaMask/Trust Wallet.']})
        aa=[]
        # These are protocol selectors, not app names; calls alone do not prove
        # that the target is an ERC-4337 account or that validation succeeded.
        for tx in report.transactions[:max_records]:
            if tx.chain!=chain:continue
            if time.monotonic()-start>max_seconds:truncated=True;break
            raw=tx.raw or {};provider=raw.get('provider_record') or {}
            provider=provider if isinstance(provider,dict) else {}
            bound_provider=not provider.get('hash') or str(provider['hash']).lower()==str(tx.tx_hash).lower()
            data=raw.get('input') or raw.get('data') or (provider.get('input') if bound_provider else None)
            origin=canonical_address(chain,tx.from_address);destination=canonical_address(chain,tx.to_address)
            tx_hash=str(tx.tx_hash).lower()
            provider_consistent=(bound_provider and len(tx_hash)==66 and tx_hash.startswith('0x') and
                all(char in '0123456789abcdef' for char in tx_hash[2:]))
            # Check every supplied native copy. A matching normalized DTO must
            # not hide contradictory native transaction or receipt identities.
            for container in (raw,provider):
                if container.get('hash') and str(container['hash']).lower()!=tx_hash:provider_consistent=False
                if any(field in container and canonical_address(chain,container[field])!=expected
                       for field,expected in [('from',origin),('to',destination)]):provider_consistent=False
                if any(field in container and str(container[field]).lower()!=str(data).lower()
                       for field in ('input','data')):provider_consistent=False
                if 'chainId' in container:
                    wire_chain=container['chainId']
                    try:
                        wire_chain=int(wire_chain,16 if wire_chain.startswith(('0x','0X')) else 10) if isinstance(wire_chain,str) else wire_chain
                        if type(wire_chain) is not int or wire_chain!={'eth':1,'bsc':56,'polygon':137,'arbitrum':42161,'optimism':10,'avalanche':43114}[chain]:provider_consistent=False
                    except (ValueError,TypeError):provider_consistent=False
                if (str(container.get('isError'))=='1' or str(container.get('txreceipt_status'))=='0' or
                    container.get('success') is False or str(container.get('status','')).lower() in {'failed','failure','error','reverted','fail'}):provider_consistent=False
                if container.get('emulated') is True or container.get('simulated') is True:provider_consistent=False
                if 'blockNumber' in container and container['blockNumber'] is None:provider_consistent=False
            receipt_valid=True
            for field in ('receipt','transaction_receipt','rpc_receipt'):
                if field not in raw:continue
                receipt=raw[field]
                if (not isinstance(receipt,dict) or str(receipt.get('transactionHash','')).lower()!=tx_hash or
                    not (receipt.get('status')=='0x1' or type(receipt.get('status')) is int and receipt['status']==1)):
                    receipt_valid=False;continue
                if any(key in receipt and canonical_address(chain,receipt[key])!=expected
                       for key,expected in [('from',origin),('to',destination)]):receipt_valid=False
                if (receipt.get('emulated') is True or receipt.get('simulated') is True or
                    'blockNumber' in receipt and receipt['blockNumber'] is None):receipt_valid=False
                for native in (raw,provider):
                    if any(key in native and key in receipt and str(native[key]).lower()!=str(receipt[key]).lower()
                           for key in ('blockHash','blockNumber')):receipt_valid=False
            if origin==target['address'] and provider_consistent and receipt_valid and transaction_success(tx) is True:
                for application_id,routers in APP_SWAP_ROUTERS.items():
                    if destination!=routers.get(chain):continue
                    physical=(chain,str(tx.tx_hash).lower(),application_id,destination)
                    if physical in seen_evm_app_calls:continue
                    decoded=decode_evm_application_swap(data,application_id)
                    if decoded:
                        decoded.update(blockchain=chain,router=destination,transaction_hash=tx.tx_hash,
                            source_execution_verified=True,publisher_binding_scope='pinned router publication; no historical controller inference')
                        row=observation('published_application_swap_router_call',decoded,tx,{},tx.url,
                            'successful_outer_call_to_published_application_router',application_marker=True)
                        if row:seen_evm_app_calls.add(physical)
                        application_finding(application_id,('MetaMask' if application_id=='metamask' else 'Rainbow')+' (Swaps)',
                            'APPLICATION_INTERACTION','published_swap_router_call',[row],
                            'successful_exact_router_and_abi_call',APP_SWAP_SOURCES[application_id],
                            limitations=['The router is publicly callable; no specific wallet UI or origin of the quote is established.',
                                'Swap amount credited and historical operator control are not independently inferred.'])
            if isinstance(data,str) and data[:10].lower() in {'0x1fad948c','0x765e827f'}:
                aa.append({'transaction_hash':tx.tx_hash,'selector':data[:10].lower(),'source':tx.source,'source_url':safe_public_url(tx.url),'scope':'entrypoint_compatible_call_not_validated_useroperation'})
        result['checks'].append({'method':'erc4337_entrypoint_call_shape','status':'observed' if aa else 'not_observed','result':{'compatible_calls':aa[:50],'observed_count':len(aa)},
            'source_urls':['https://eips.ethereum.org/EIPS/eip-4337'],'evidence_ids':[],
            'limits':['A selector can collide or be copied; EntryPoint address, receipt logs, decoded sender and validation traces are needed before identifying account-abstraction infrastructure.','Bundler/paymaster/factory relationships do not establish the user-facing signing application.']})
        result['unavailable_methods'].append({'method':'wallet_ui_identity','reason':'Standard EOA signatures/calldata carry no authenticated MetaMask/Trust Wallet user-interface name.'})
    elif chain=='solana':
        result['checks'].append({'method':'solana_program_authorities','status':'observed' if (report.solana or {}).get('account') else 'unavailable',
            'result':{'account_kind':target.get('account_type'),'owner_program':contract.get('owner_program'),
                'authority_relationships':sum(r.get('type')=='authority' and r.get('from_key')==target_key for r in payload.get('relationships',[]))},
            'source_urls':['https://solana.com/docs/core/accounts'],'evidence_ids':contract.get('evidence_ids',[]),
            'limits':['Program ownership/authority/signers describe execution or keys; they do not establish Phantom, Solflare or a physical owner.','Smart-wallet instruction decoders require a verified program implementation; none is inferred from an arbitrary account label.']})
    elif chain=='tron':
        result['checks'].append({'method':'tron_account_permissions','status':'observed' if (report.tron or {}).get('permissions') else 'unavailable',
            'result':{'permissions_available':bool((report.tron or {}).get('permissions'))},
            'source_urls':['https://developers.tron.network/docs/account-permission-management'],'evidence_ids':[],
            'limits':['Thresholds and permission keys describe signing authority; they do not establish TronLink, custody or a physical person.']})
    elif chain in {'btc','doge'}:
        result['checks'].append({'method':'utxo_script_and_spend_context','status':'observed',
            'result':{'address_script_type':target.get('account_type'),'co_input_observations':sum(r.get('type')=='co_input_participation' for r in payload.get('relationships',[]))},
            'source_urls':['https://developer.bitcoin.org/devguide/transactions.html'],'evidence_ids':contract.get('evidence_ids',[]),
            'limits':['Script type, input ordering, change guesses and co-spending are shared/caller-controlled.','CoinJoin/PayJoin/multisig and exchange aggregation prevent application or common-owner inference.']})
    # Off-chain records require an explicit caller argument, address binding,
    # consent, observer assertion and artifact hash. They are never auto-imported
    # from untrusted metadata or user-supplied expected-answer context.
    accepted=[];rejected=[]
    for row in (user_verified_observations or [])[:100]:
        if not isinstance(row,dict) or address_id(row.get('blockchain'),row.get('address'))!=target_key:continue
        required=('application_id','observed_at','observer','artifact_sha256')
        if row.get('consent') is not True or row.get('user_verified') is not True or not all(isinstance(row.get(k),str) and row[k] for k in required) or len(row['artifact_sha256'])!=64 or any(c not in '0123456789abcdef' for c in row['artifact_sha256'].lower()):
            rejected.append({'method':'USER_VERIFIED_OFF_CHAIN_OBSERVATION','reason':'Explicit consent, observer verification, address binding, time and artifact SHA256 are required.'});continue
        accepted.append({k:row[k] for k in required}|{'blockchain':chain,'address':target['address'],'method':'USER_VERIFIED_OFF_CHAIN_OBSERVATION',
            'status':'USER_VERIFIED','public_osint':False,'application_binary_authenticated':False,
            'limitations':['Observer-provided evidence; not independently verified by public chain data.','A session self-description alone does not authenticate an application binary or prove all historical transactions used it.']})
    result['off_chain_observations']=accepted;result['off_chain_rejected']=rejected
    if result['application_findings']:
        result['reason']='Signing application remains UNKNOWN. Observed: '+'; '.join(dict.fromkeys(
            finding['category'].replace('_',' ')+': '+finding['application'] for finding in result['application_findings']))+'.'
    result['observations']=observations
    result['evidence_ids']=list(dict.fromkeys(ref for c in result['checks'] for ref in c.get('evidence_ids',[])))
    result['coverage'].update(dict(counts),status='TRUNCATED' if truncated else 'PARTIAL',
        observations_retained=len(observations),max_observations=max_observations,max_records=max_records,
        generic_observations_omitted=counts['generic_observations_omitted'],
        marker_observations_omitted=counts['marker_observations_omitted'],
        marker_priority_replacements=counts['marker_priority_replacements'],
        observation_retention_policy='construction_markers_before_generic_headers',
        observed_provider_names=sorted(source_families),independent_application_confirmations=0,
        elapsed_seconds=time.monotonic()-start)
    result['unavailable_methods'].append({'method':'independent_signing_app_ground_truth','reason':'No independently authenticated application session or exclusive public application evidence was supplied.'})
    payload['wallet_application']={key:result[key] for key in ('status','name','application_id','method','reason')}
    payload['wallet_application'].update(checks_count=len(result['checks']),observations_count=len(observations),
        detail_ref={'address_key':target_key,'field':'client_attribution'})
    evidence.update(observation_proofs)
    payload['evidence']=list(evidence.values())
    return result
