"""Typed financial view over retained observations, without mutating the corpus.

TON uses the existing physical-message normalizer and native/provider proof
gates. Account executions, provider interpretations and context are retained;
only one proved target-incident movement contributes to financial totals.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json

from app.models.report import Transaction
from app.utils.event_identity import canonical_hash, event_identity, decimal_amount, transaction_success
from app.utils.ton_normalize import ton_canonical_address


def _credited_uninitialized_message(op,native):
    """An aborted no-state execution can still credit a non-bouncing payment.

    This is deliberately separate from the service execution proof gate. Exact
    credit and final balance are necessary, and no refund/outgoing message or
    callable protocol body can be hidden by this narrow initial-funding rule.
    """
    if native.get('orig_status') not in {'nonexist','uninit'} or native.get('end_status')!='uninit':return False
    desc=native.get('description') or {}
    compute=native.get('compute_phase') or desc.get('compute_ph') or {}
    if compute.get('skipped') is not True or compute.get('skip_reason',compute.get('reason')) not in {'no_state','cskip_no_state'}:return False
    msg=native.get('in_msg') or {}
    if native.get('out_msgs') or msg.get('bounce') is not False or msg.get('bounced') is not False:return False
    if canonical_hash(msg.get('hash') or msg.get('msg_hash'))!=op.get('message_hash'):return False
    def address(value):return ton_canonical_address(value.get('address') if isinstance(value,dict) else value)
    if address(native.get('account'))!=op['to_key'].split(':',1)[1] or address(msg.get('destination'))!=op['to_key'].split(':',1)[1] or address(msg.get('source'))!=op['from_key'].split(':',1)[1]:return False
    def integer(value):
        if type(value) is int:return value
        return int(value) if isinstance(value,str) and value.isdecimal() and len(value)<120 else None
    phase=native.get('credit_phase') or desc.get('credit_ph') or {}
    credit=phase.get('credit');credit=credit.get('grams') if isinstance(credit,dict) else credit
    amount=integer(msg.get('value'));credit=integer(credit)
    after=integer(native.get('end_balance',(native.get('account_state_after') or {}).get('balance')))
    if amount is None or amount<=0 or credit!=amount or after!=amount or Decimal(amount).scaleb(-9)!=Decimal(op['amount_decimal']):return False
    opcode=msg.get('opcode',msg.get('op_code'))
    if opcode not in (None,0,'0','0x00000000','0x0'):return False
    from app.attribution.wallet_payload import body_boc
    body=body_boc(msg)
    if body:
        from app.ton_nft.protocol import decode_boc
        try:
            cell=decode_boc(body)
            if cell.bit_length>=32 and int.from_bytes(cell.data[:4],'big')!=0:return False
        except (ValueError,TypeError,OverflowError):return False
    return True


def project_financial_operations(report) -> dict:
    # Import lazily: this is a presentation/aggregation view of the existing
    # normalizers, not another collector, inference engine or evidence store.
    from app.attribution.inference import _ton_projections
    from app.attribution.telegram_services import _validated_ton_native_operation
    from app.attribution.service_operations import validate_account_operation, ton_native_execution

    target = ton_canonical_address(report.target_address)
    operations = {}
    physical = {}
    account_hashes = set()
    source_records = set()
    message_rows = defaultdict(set)
    account_to_messages = defaultdict(set)
    technical_messages = set()
    external_messages = set()
    incomplete_messages = set()
    conflicting_messages = set()
    failed_messages = set()
    native_seen = set()
    classifications = {}
    operation_observations = defaultdict(set)
    proof_index = {}
    source_index = {}
    references = {}
    retained_provenance = {}
    non_ton = []

    def classify(identity, category, reason, ids=()):
        classifications[identity] = {'category': category, 'reason': reason,
                                     'economic_operation_ids': list(dict.fromkeys(ids))}

    def proof_data(source_id, raw, source, url):
        source_index[source_id] = {'blockchain':'ton','source':source,'url':url,'raw':raw}
        proof_index[source_id] = {'evidence_id':source_id,'facts':{
            'raw_reference':{'source_observation_id':source_id}}}
        return {'_service_evidence_index':proof_index,'source_observations':source_index}

    def retain(operation, tx, raw, source, url, source_id, *, priority=0):
        identity = operation['operation_id']
        existing = operations.get(identity)
        basis = (operation['from_key'],operation['to_key'],operation['asset_key'],operation['amount_decimal'])
        if existing and existing['basis'] != basis:
            # A conflicting body for an immutable identifier cannot silently
            # determine a principal amount. Preserve it as incomplete evidence.
            incomplete_messages.add(identity);conflicting_messages.add(identity)
            operations.pop(identity,None)
            return
        if identity in conflicting_messages:
            return
        incomplete_messages.discard(identity)
        operation_observations[identity].add(event_identity(tx))
        references.setdefault(identity,{'observation_ids':set(),'account_transaction_hashes':set(),
                                        'source_ids':set(),'sources':set(),'context_observation_ids':set()})
        refs = references[identity]
        refs['context_observation_ids'].add(event_identity(tx));refs['source_ids'].add(source_id);refs['sources'].add(source)
        if canonical_hash(operation['transaction_hash']):refs['account_transaction_hashes'].add(canonical_hash(operation['transaction_hash']))
        if existing and existing['priority'] >= priority:
            return
        amount=Decimal(operation['amount_decimal'])
        frm,to=operation['from_key'].split(':',1)[1],operation['to_key'].split(':',1)[1]
        direction='self' if frm==target==to else 'out' if frm==target else 'in' if to==target else 'unknown'
        copied_raw=dict(raw)
        native=raw.get('transaction') or {}
        if operation.get('message_hash'):
            for index,message in [('in',native.get('in_msg')),*[(f'out:{i}',msg) for i,msg in enumerate(native.get('out_msgs') or [])]]:
                if isinstance(message,dict) and canonical_hash(message.get('hash') or message.get('msg_hash'))==operation['message_hash']:
                    copied_raw['message']=message
                    copied_raw['message_index']=index
                    break
        copied_raw['_economic_projection']={'operation_id':identity,'proof_kind':operation.get('proof_kind'),
            'scope':'target' if direction!='unknown' else 'related_context',
            'execution_scope':'Exact non-bouncing recipient credit and final uninitialized balance; compute was skipped, not a successful contract call.' if operation.get('proof_kind')=='ton_native_credit' else 'Successful retained account-side emission; recipient credit is separate.' if operation['asset_key']=='ton:native' else 'Provider-indexed non-aborted jetton transfer; recipient credit independently unverified.'}
        value=tx.model_copy(update={'event_id':identity,'tx_hash':operation['transaction_hash'],
            'timestamp':datetime.fromisoformat(operation['timestamp'].replace('Z','+00:00')),
            'from_address':frm,'to_address':to,'asset':'TON' if operation['asset_key']=='ton:native' else 'JETTON:'+operation['asset_key'].removeprefix('ton:token:'),
            'amount_decimal':amount,'amount':float(amount),'amount_base_units':None,'decimals':None,
            'direction':direction,'success':True,'source':source,'url':'https://tonviewer.com/transaction/'+operation['transaction_hash'],'raw':copied_raw,
            'provenance':list(tx.provenance or [])})
        operations[identity]={'tx':value,'operation':operation,'basis':basis,'priority':priority}

    for tx in report.transactions:
        identity=event_identity(tx)
        if tx.chain!='ton':
            # Other chains keep their existing semantics and deduplication.
            non_ton.append(tx)
            continue
        raw=tx.raw or {}
        observations=[p for p in tx.provenance if isinstance(p,dict) and isinstance(p.get('raw'),dict)]
        if not observations:observations=[{'source':tx.source,'url':tx.url,'raw':raw}]
        msg=raw.get('message') or {}
        mh=canonical_hash(msg.get('hash') or msg.get('msg_hash'))
        if mh:message_rows['ton:message:'+mh].add(identity)
        for observation in observations:
            observed=observation['raw'];source=observation.get('source') or tx.source;url=observation.get('url') or tx.url
            source_id=observation.get('raw_digest') or hashlib.sha256(json.dumps(observed,sort_keys=True,default=str).encode()).hexdigest()
            source_id=str(source)+':'+source_id
            source_records.add(source_id)
            retained_provenance.setdefault(source_id,observation)
            native=observed.get('transaction')
            if isinstance(native,dict):
                digest=canonical_hash(native.get('hash') or (native.get('transaction_id') or {}).get('hash'))
                account=native.get('account') or native.get('account_addr')
                account=ton_canonical_address(account.get('address') if isinstance(account,dict) else account)
                if not digest or not account:continue
                account_hashes.add(digest)
                key=(digest,source)
                if key in native_seen:continue
                native_seen.add(key)
                # Some providers call the exact account hash transaction_id.
                # This canonical alias is a copy; the original source stays in
                # provenance and is never rewritten.
                canonical_native={**native,'hash':digest,'account':account}
                native_raw={**observed,'transaction':canonical_native}
                data=proof_data(source_id,native_raw,source,url)
                view=tx.model_copy(update={'tx_hash':digest,'raw':native_raw,'source':source,'url':url,
                                           'success':ton_native_execution(canonical_native)})
                for message in [canonical_native.get('in_msg'),*(canonical_native.get('out_msgs') or [])]:
                    if not isinstance(message,dict):continue
                    message_hash=canonical_hash(message.get('hash') or message.get('msg_hash'))
                    if not message_hash:continue
                    mid='ton:message:'+message_hash
                    physical.setdefault(mid,message)
                    account_to_messages[digest].add(mid)
                    frm=message.get('source');to=message.get('destination')
                    frm=ton_canonical_address(frm.get('address') if isinstance(frm,dict) else frm)
                    to=ton_canonical_address(to.get('address') if isinstance(to,dict) else to)
                    if not frm or not to:external_messages.add(mid)
                    elif message.get('value') in (None,0,'0'):technical_messages.add(mid)
                for op in _ton_projections(view):
                    mid=op['operation_id']
                    if not op.get('message_hash'):
                        incomplete_messages.add(mid);continue
                    op['evidence_ids']=[source_id]
                    if _credited_uninitialized_message(op,canonical_native):
                        op['proof_kind']='ton_native_credit'
                        retain(op,tx,native_raw,source,url,source_id,priority=op.get('_priority',0))
                        continue
                    if ton_native_execution(canonical_native) is False:
                        failed_messages.add(mid);continue
                    if not _validated_ton_native_operation(op,data):
                        message=next((m for m in [canonical_native.get('in_msg'),*(canonical_native.get('out_msgs') or [])]
                            if isinstance(m,dict) and canonical_hash(m.get('hash') or m.get('msg_hash'))==op.get('message_hash')),{})
                        opcode=message.get('opcode',message.get('op_code'))
                        try:opcode=int(opcode,16 if opcode.lower().startswith('0x') else 10) if isinstance(opcode,str) else opcode
                        except (ValueError,TypeError):opcode=None
                        if opcode in {0x5fcc3d14,0x05138d91,0x0f8a7ea5,0x178d4519,0x7362d09c,0x595f07bc,0x7bdd97de,0xd53276db} or message.get('bounced') is True:
                            technical_messages.add(mid)
                        elif mid not in operations:incomplete_messages.add(mid)
                        continue
                    op['proof_kind']='ton_native_message'
                    retain(op,tx,native_raw,source,url,source_id,priority=op.get('_priority',0))
            if observed.get('asset_type')=='jetton' and isinstance(observed.get('transfer'),dict):
                transfer=observed['transfer'];master=ton_canonical_address(transfer.get('jetton_master'))
                digest=canonical_hash(transfer.get('transaction_hash'))
                frm,to=ton_canonical_address(transfer.get('source')),ton_canonical_address(transfer.get('destination'))
                amount=decimal_amount(tx)
                if not (digest and master and frm and to and amount is not None):continue
                # A transfer hash plus immutable transfer identifiers are used;
                # equal amount/time alone is never a deduplication criterion.
                key=[digest,str(transfer.get('query_id')),str(transfer.get('transaction_lt')),frm,to,master]
                oid='ton:jetton:'+hashlib.sha256(json.dumps(key,separators=(',',':')).encode()).hexdigest()
                stamp=transfer.get('transaction_now')
                if not isinstance(stamp,int):continue
                op={'operation_id':oid,'blockchain':'ton','transaction_hash':digest,'from_key':'ton:'+frm,
                    'to_key':'ton:'+to,'asset_key':'ton:token:'+master,'amount_decimal':str(amount),
                    'timestamp':datetime.fromtimestamp(stamp,timezone.utc).isoformat(),'success':True,'evidence_ids':[source_id]}
                data=proof_data(source_id,observed,source,url)
                if validate_account_operation(op,data)!='ton_jetton_transfer':continue
                op['proof_kind']='ton_jetton_transfer'
                retain(op,tx,observed,source,url,source_id,priority=1)

    # Associate alternate provider actions only through retained immutable TX
    # references AND exact qualified parties/asset/amount. Ambiguity is retained.
    for tx in report.transactions:
        if tx.chain!='ton':continue
        identity=event_identity(tx);raw=tx.raw or {}
        direct=identity.split(':')
        mid=':'.join(direct[:3]) if identity.startswith('ton:message:') else None
        if mid and mid in operations:
            operation_observations[mid].add(identity)
            references[mid]['observation_ids'].add(identity)
            classify(identity,'economic_operation','Physical message represents one movement.',[mid]);continue
        linked=[]
        if raw.get('asset_type')=='jetton' and isinstance(raw.get('transfer'),dict):
            linked=[oid for oid,record in operations.items() if identity in operation_observations[oid]]
        action=raw.get('action') or {}
        hashes={canonical_hash(h) for h in [tx.tx_hash,*(action.get('transactions') or []),*(action.get('base_transactions') or [])] if canonical_hash(h)}
        from_key=ton_canonical_address(tx.from_address);to_key=ton_canonical_address(tx.to_address)
        amount=decimal_amount(tx)
        master=ton_canonical_address(str(tx.asset).removeprefix('JETTON:')) if str(tx.asset).startswith('JETTON:') else None
        asset='ton:token:'+master if master else 'ton:native' if tx.asset=='TON' else None
        if raw.get('nft_event_id') or raw.get('nft_intelligence') or raw.get('asset_type')=='nft' or str(tx.asset or '').startswith('NFT:'):
            classify(identity,'technical_event','NFT ownership/activity observation; no monetary consideration inferred.');continue
        if raw.get('action_index') is not None or raw.get('asset_type')=='action' or raw.get('provider')=='tonapi_events':
            for oid,record in operations.items():
                op=record['operation'];refs=references[oid]
                if hashes & refs['account_transaction_hashes'] and record['basis'][:3]==('ton:'+str(from_key),'ton:'+str(to_key),asset) and amount is not None and Decimal(op['amount_decimal'])==amount:
                    linked.append(oid)
            linked=list(dict.fromkeys(linked))
            if len(linked)==1:
                oid=linked[0];operation_observations[oid].add(identity);references[oid]['observation_ids'].add(identity)
                classify(identity,'source_representation','Exact underlying account TX and qualified movement match.',linked);continue
            classify(identity,'incomplete_evidence','Provider interpretation has no unambiguous independently retained financial operation.');continue
        if linked:
            for oid in linked:references[oid]['observation_ids'].add(identity)
            classify(identity,'economic_operation','Exact retained jetton transfer.',linked);continue
        if mid in external_messages or mid in technical_messages:
            classify(identity,'technical_event','External/zero-value/protocol execution message.');continue
        if mid in failed_messages or transaction_success(tx) is False:
            classify(identity,'failed_execution','Failed execution retained; not a successful principal transfer.');continue
        classify(identity,'incomplete_evidence','Missing complete immutable financial-operation evidence.')

    ordered=sorted(operations,key=lambda oid:(operations[oid]['tx'].timestamp or datetime.min.replace(tzinfo=timezone.utc),oid),reverse=True)
    financial=[];context=[]
    for oid in ordered:
        record=operations[oid];tx=record['tx'];refs=references[oid]
        tx.raw['_economic_projection'].update({name:sorted(values) for name,values in refs.items()})
        tx.provenance=[retained_provenance[sid] for sid in sorted(refs['source_ids']) if sid in retained_provenance]
        (financial if tx.direction in {'in','out','self'} else context).append(tx)
    # A technical observation is never relabelled as money because it shared
    # a trace. All observations are still returned to the ordinary HTML view.
    target_ids={tx.event_id for tx in financial}
    for identity,row in classifications.items():
        if row['economic_operation_ids'] and not any(oid in target_ids for oid in row['economic_operation_ids']):
            row['category']='related_context'
    categories=Counter(row['category'] for row in classifications.values())
    return {'transactions':[*non_ton,*financial],'related_transactions':context,
        'classification':classifications,'counts':{
            'observation_records':len(report.transactions),'instrumented_raw_provider_records':report.collection_audit.get('stages',{}).get('provider',{}).get('measured_raw_records'),
            'retained_source_representations':len(source_records),'unique_native_account_transactions':len(account_hashes),
            'unique_blockchain_messages':len(physical),'unique_economic_operations':len(financial),
            'related_context_economic_operations':len(context),'technical_message_hashes':len(technical_messages|external_messages),
            'external_message_hashes':len(external_messages),'incomplete_message_hashes':len(incomplete_messages),
            'source_representation_rows':categories.get('source_representation',0),'observation_categories':dict(categories),
            'financial_count_scope':'ton_only','other_chain_rows_with_existing_semantics':len(non_ton)},
        'history_complete':False,'source_observations_modified':False,
        'scope':'Unique proved target-incident financial movements; account executions, provider actions and context remain separate.'}


def financial_transactions(report):
    """Use one shared financial view; never replace report.transactions."""
    return project_financial_operations(report)['transactions']


def project_activity_operations(report, financial_projection=None):
    """Keep source-bound activity distinct from the proved monetary view.

    Strong NFT/account/message IDs suppress alternate representations. Keys
    that identify more than one row in the same provider representation are
    ambiguous and cannot join records. Original observations are never edited.
    """
    financial_projection = financial_projection or project_financial_operations(report)
    target = ton_canonical_address(report.target_address)
    candidates = []
    def address(value):
        return ton_canonical_address(value.get("address") if isinstance(value, dict) else value)
    def mapping(value):
        return value if isinstance(value, dict) else {}
    def strings(value):
        return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []
    def bridge_record(record):
        row = mapping(record)
        result = {key: row[key] for key in ("event_id", "trace_id", "asset_address", "from_address", "to_address")
            if isinstance(row.get(key), str)}
        if type(row.get("action_index")) is int:
            result["action_index"] = row["action_index"]
        return result
    for tx in report.transactions:
        if tx.chain != "ton":
            continue  # Other chains already retain their previous semantics.
        identity = event_identity(tx)
        category = financial_projection["classification"].get(identity, {}).get("category")
        if category in {"economic_operation", "source_representation", "related_context"}:
            continue
        raw = tx.raw or {}
        native = mapping(raw.get("transaction"))
        account = address(native.get("account") or raw.get("account"))
        frm, to = address(tx.from_address), address(tx.to_address)
        if not target or target not in {frm, to, account}:
            continue
        keys = {("observation", identity)}
        nft = address(str(tx.asset or "").removeprefix("NFT:")) if str(tx.asset or "").startswith("NFT:") else None
        detail = mapping(raw.get("nft_intelligence"))
        transfer = mapping(raw.get("transfer"))
        action = mapping(raw.get("action"))
        provider_action = raw.get("action_index") is not None or raw.get("provider") == "tonapi_events" or raw.get("asset_type") == "action"
        if nft:
            from app.ton_nft.service import _nft_bridge_transaction_keys
            corroborating = mapping(detail.get("raw")).get("corroborating_observations")
            corroborating = [row for row in corroborating if isinstance(row, dict)] if isinstance(corroborating, list) else []
            clean_detail = {**bridge_record(detail), "raw": {"corroborating_observations": [bridge_record(row) for row in corroborating]}}
            bridge_raw = {**raw, "nft_intelligence": clean_detail,
                "action_index": raw.get("action_index") if type(raw.get("action_index")) is int else None,
                "event_id": raw.get("event_id") if isinstance(raw.get("event_id"), str) else None}
            keys.update(_nft_bridge_transaction_keys(tx.model_copy(update={"raw": bridge_raw})))
            records = [detail, *corroborating]
            hashes = {canonical_hash(value) for value in [transfer.get("transaction_hash"),
                *strings(action.get("transactions")), *strings(action.get("base_transactions")),
                *(row.get("transaction_hash") for row in records)] if isinstance(value, str) and canonical_hash(value)}
            for digest in hashes:
                keys.add(("nft_transaction_member", digest, nft, frm, to))
            namespace = (tx.source, "indexed_transfer" if transfer.get("nft_address") else "nft_event" if detail else "action")
            rank = 3 if detail.get("verification") == "verified_onchain" else 2 if transfer.get("nft_address") else 1
        else:
            message = mapping(raw.get("message"))
            digest = canonical_hash(message.get("hash") or message.get("msg_hash"))
            if digest:
                keys.add(("native_message", digest))
            namespace = (tx.source, "action" if provider_action else "message")
            rank = 1
        candidates.append({"tx": tx, "keys": keys, "namespace": namespace, "rank": rank,
            "nft": nft, "account": account, "provider_action": provider_action,
            "recurrence": bool(nft or not provider_action)})
    parents = list(range(len(candidates)))
    def find(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index
    keys_to_rows = defaultdict(list)
    ambiguous_indexes = set()
    for index, row in enumerate(candidates):
        for key in row["keys"]:
            keys_to_rows[key].append(index)
    for key, indexes in keys_to_rows.items():
        namespaces = defaultdict(set)
        for index in indexes:
            namespaces[candidates[index]["namespace"]].add(event_identity(candidates[index]["tx"]))
        if any(len(ids) > 1 for ids in namespaces.values()):
            ambiguous_indexes.update(indexes)
            continue
        for index in indexes[1:]:
            parents[find(index)] = find(indexes[0])
    groups = defaultdict(list)
    for index in range(len(candidates)):
        candidates[index]["ambiguous"] = index in ambiguous_indexes
        groups[find(index)].append(candidates[index])
    resolved_groups = []
    for rows in groups.values():
        namespaces = defaultdict(set)
        for row in rows:
            namespaces[row["namespace"]].add(event_identity(row["tx"]))
        if any(len(ids) > 1 for ids in namespaces.values()):
            # Multi-reference bridges must not transitively collapse distinct
            # same-provider events. Keep uncertainty as separate observations.
            for row in rows:
                row["ambiguous"] = True
                row["recurrence"] = row["recurrence"] and not row["provider_action"]
                resolved_groups.append([row])
        else:
            for row in rows:
                if row["ambiguous"] and row["provider_action"]:
                    row["recurrence"] = False
            resolved_groups.append(rows)
    activity = list(financial_projection["transactions"])
    for rows in resolved_groups:
        row = max(rows, key=lambda value: value["rank"])
        tx = row["tx"]
        copied_raw = {**(tx.raw or {}), "_activity_projection": {
            "observation_ids": sorted({event_identity(value["tx"]) for value in rows}),
            "account_context": row["account"], "recurrence_eligible": row["recurrence"],
            "alias_status": "ambiguous" if any(value["ambiguous"] for value in rows) else "matched" if len(rows) > 1 else "single_observation",
            "scope": "target nonfinancial activity; no monetary principal asserted"}}
        activity.append(tx.model_copy(update={"asset": "NFT:" + row["nft"] if row["nft"] else tx.asset,
            "amount": None, "amount_decimal": None, "amount_base_units": None,
            "raw": copied_raw}))
    activity.sort(key=lambda tx: (tx.timestamp or datetime.min.replace(tzinfo=timezone.utc), event_identity(tx)), reverse=True)
    return {"transactions": activity, "nonfinancial_groups": len(resolved_groups),
        "nonfinancial_observations": len(candidates), "source_observations_modified": False}
