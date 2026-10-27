"""Budgeted neighbor-history collection inside the existing investigation.

Only scoped history DTOs enter investigation_context. The target's balances,
transfers, assets and account histories are never extended with neighbor data.
"""
from __future__ import annotations

import asyncio
import copy
import inspect
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

from app.models.report import AddressReport
from app.sources.pagination import pages
from app.aggregator.collection_audit import stream_state
from app.utils.event_identity import event_identity
from app.utils.detect import _base58_decode
from app.utils.http import bounded_request_scope, shared_async_client, RequestBudgetExceeded
from app.utils.security import sanitize_observation
from .inference import build_inference_data, context_for, journal
from .normalize import address_id, canonical_address, normalize_chain

MAX_HOPS = 6
MAX_HISTORIES = 12
MAX_HISTORY_ROWS = 10000
_WHOLE_HISTORY = {'toncenter', 'tronscan', 'blockchair_dogecoin', 'blockchair_ethereum'}
_HUB_CATEGORIES = {'published_service_reference', 'exchange', 'exchange_infrastructure', 'token', 'program', 'bridge', 'router',
                   'dex', 'factory', 'paymaster', 'relayer', 'protocol', 'smart_contract'}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _kind(source):
    name = str(getattr(source, 'name', ''))
    if callable(getattr(source, 'fetch_history', None)):
        return 'history_api'
    if name == 'etherscan_api' or name.startswith('etherscan_api_'):
        return 'etherscan'
    if name == 'bscscan_api':
        return 'bscscan'
    if name in {'blockstream_esplora', 'mempool_space', 'bitcoin_esplora'}:
        return 'esplora'
    if name == 'toncenter_v3':
        return 'toncenter_v3'
    if name == 'tonapi':
        return 'tonapi'
    if name == 'trongrid':
        return 'trongrid'
    if name == 'solana_rpc':
        return 'solana'
    if name == 'ethplorer':
        return 'ethplorer'
    if name.startswith(('blockscout_', 'blockcypher_')) or name in _WHOLE_HISTORY or getattr(source, '_investigation_history_only', False):
        return 'history_source'
    return None


def _clone(source, budget, previous, *, incremental=False):
    clone = copy.copy(source)
    for key, value in vars(source).items():
        if isinstance(value, (dict, list, set, tuple)):
            setattr(clone, key, copy.deepcopy(value))
    for key in list(vars(clone)):
        if key.startswith(('_partial', '_pending', '_known')) or key in {
                '_resume_state', '_request_gate', '_rpc_requests', '_detail_requests', '_tip'}:
            delattr(clone, key)
    clone._timeout = budget
    # One page per typed stream leaves room for other assets and branches. The
    # normal target collectors keep their continuous/deep-history policy.
    clone._continuous = getattr(source, 'name', '') == 'blockchair_dogecoin'
    clone._incremental = incremental
    clone._history_paused = False
    clone._request_gate = asyncio.Semaphore(1)
    clone._resume_state = copy.deepcopy((previous.collection_audit.get('streams') or {}).get(clone.name, {}))
    return clone


async def _collect(source, address, out, kind):
    source._partial_report = out
    if kind == 'history_api':
        # Optional explicit source extension, also useful to deterministic tests.
        parameters = inspect.signature(source.fetch_history).parameters
        result = await source.fetch_history(address, out) if len(parameters) >= 2 else await source.fetch_history(address)
        return result if isinstance(result, AddressReport) else out
    if kind == 'history_source':
        return await source.fetch(address)
    async with shared_async_client(min(source._timeout, 10.0)) as client:
        if kind == 'etherscan':
            key = source._api_key()
            if not key:
                out.warnings.append(source.name + ': api key missing for scoped history')
                return out
            await source._fetch_normal_txs(client, address, key, out)
            await source._fetch_normal_txs(client, address, key, out, action='txlistinternal')
            await source._fetch_token_transfers(client, address, key, out, 'tokentx', 'erc20')
        elif kind == 'bscscan':
            await source._fetch_txs(client, address, out, 'txlist', 'normal')
            if not getattr(source, '_key_required', False):
                await source._fetch_txs(client, address, out, 'txlistinternal', 'internal')
                await source._fetch_token_txs(client, address, out, 'tokentx', 'bep20')
        elif kind == 'esplora':
            source._tip = None
            try:
                await source._address_txs(client, address, out, limit=25)
            finally:
                source._parse_btc_transactions(out, address, getattr(source, '_pending_btc_txs', []), None)
        elif kind == 'toncenter_v3':
            await source._transactions(client, address, out)
            await source._jetton_transfers(client, address, out)
        elif kind == 'tonapi':
            if source._incremental:
                head=stream_state(out,source.name,'account_transactions_refresh',record_type='account_transactions')
                await source._collect_transaction_window(address,out,head)
            state=stream_state(out,source.name,'account_transactions',
                resume=source._resume_state.get('account_transactions'),record_type='account_transactions')
            await source._collect_transaction_window(address,out,state)
        elif kind == 'trongrid':
            async for data in source._history_pages(client, address, out, 'transactions'):
                source._parse_native_transactions(address, out, data.get('data') or [])
            async for data in source._history_pages(client, address, out, 'trc20_transfers'):
                source._parse_trc20_page(address, out, data)
        elif kind == 'ethplorer':
            await source._fetch_transactions(client, address, source._api_key(), out)
        elif kind == 'solana':
            source._rpc_requests = 0
            pending = source._resume_state.get('account_signatures', {}).get('pending_details') or []
            if pending:
                source._continuous = True
                try:
                    await source._parse_transactions(client, address, pending, {}, out)
                finally:
                    source._continuous = False
            async def fetch(cursor):
                options = {'limit': 50}
                if cursor.get('before'):
                    options['before'] = cursor['before']
                return await source._rpc_call(client, 'getSignaturesForAddress', [address, options], out, 'signatures')
            def advance(data, items, cursor):
                return {'before': items[-1].get('signature')} if items else None
            async for response in pages(source, out, 'account_signatures', fetch,
                                        lambda data: data.get('result'), advance, page_size=50):
                source._continuous = True
                try:
                    await source._parse_transactions(client, address, response.get('result') or [], {}, out)
                finally:
                    source._continuous = False
                if source._history_paused:
                    break
    return out


def _merge_history(previous, incoming):
    """Merge within one neighbor DTO only; retain cursor progress and old rows."""
    if not isinstance(incoming, AddressReport) or incoming.target_address != previous.target_address:
        return previous
    result = previous.model_copy(deep=True)
    transactions = {event_identity(tx): tx for tx in result.transactions}
    for tx in incoming.transactions:
        transactions[event_identity(tx)] = tx
    result.transactions = list(transactions.values())[:MAX_HISTORY_ROWS]
    for field in ('labels', 'tokens', 'balances', 'source_health'):
        existing = getattr(result, field)
        keys = {str(row.model_dump(mode='json')) for row in existing}
        for row in getattr(incoming, field):
            key = str(row.model_dump(mode='json'))
            if key not in keys:
                existing.append(row)
                keys.add(key)
    for field in ('errors', 'warnings', 'sources_used'):
        setattr(result, field, list(dict.fromkeys(getattr(result, field) + getattr(incoming, field))))
    for name, streams in (incoming.collection_audit.get('streams') or {}).items():
        result.collection_audit.setdefault('streams', {}).setdefault(name, {}).update(copy.deepcopy(streams))
    result.coverage.update(copy.deepcopy(incoming.coverage))
    if len(transactions) > MAX_HISTORY_ROWS:
        result.coverage['investigation_storage'] = {'status': 'TRUNCATED', 'rows_retained': MAX_HISTORY_ROWS,
                                                   'rows_omitted': len(transactions) - MAX_HISTORY_ROWS}
    return result


def _hub(key, data, pairs):
    row = data['addresses'].get(key, {})
    kind=(row.get('contract') or {}).get('kind')
    ordinary_wallet=kind in {'wallet','smart_wallet','multisig','ton_wallet'} or str(kind or '').startswith(('wallet_v','wallet-'))
    if not ordinary_wallet and kind not in {None, '', 'unknown', 'eoa', 'externally_owned_account'}:
        return 'known_protocol_or_contract'
    for claim in row.get('attributions', []):
        category = str(claim.get('category') or claim.get('entity_type') or '').lower()
        if category in _HUB_CATEGORIES and claim.get('status') not in {None, 'UNKNOWN'}:
            return 'known_service_or_protocol_hub'
    neighbors = {b if a == key else a for a, b in pairs if a == key or b == key}
    return 'high_degree_hub' if len(neighbors) >= 30 else None


def _plan(report, context):
    data = build_inference_data(report, report.attribution_intelligence or {}, max_seconds=.8)
    from .service_infrastructure import source_bound_planning_data
    data=source_bound_planning_data(report,data)
    outgoing = defaultdict(set)
    pairs = defaultdict(set)
    refs = defaultdict(set)
    route_priority=defaultdict(int)
    for op in data['operations']:
        # Weak/unverified projections remain in the analytical payload, but do
        # not spend optional provider requests as if they were native transfers.
        if op.get('success') is not True or op.get('amount_precision')=='display_float':
            continue
        tx_hash=str(op.get('transaction_hash') or '')
        if op.get('blockchain')=='solana':
            if len(_base58_decode(tx_hash) or b'')!=64:continue
        elif not re.fullmatch(r'(?:0x)?[a-fA-F0-9]{64}',tx_hash):
            # Event names and placeholder IDs are not independent physical
            # transaction anchors authorizing further provider expansion.
            continue
        a, b = op.get('from_key'), op.get('to_key')
        if not a or not b or a == b:
            continue
        dep = op.get('dependency_group') or op.get('operation_id')
        pairs[(a, b)].add(dep)
        route_priority[(a,b)]=max(route_priority[(a,b)],op.get('planning_priority',0))
        outgoing[a].add(dep)
        outgoing[b].add(dep)
        refs[(a, b)].update(op.get('evidence_ids') or [])
    # UTXO participants are candidates only. No input-to-output allocation or
    # common-owner inference is introduced by planning this context request.
    for tx in data.get('utxo_transactions', []):
        members = set(tx.get('input_keys', [])) | set(tx.get('output_keys', []))
        for parent in context['target_keys']:
            if parent not in members:
                continue
            for member in members - {parent}:
                pairs[(parent, member)].add(tx['dependency_group'])
                outgoing[parent].add(tx['dependency_group'])
                refs[(parent, member)].update(tx.get('evidence_ids') or [])
    active = set()
    for hypothesis in (report.attribution_intelligence or {}).get('inferential_intelligence', {}).get('hypotheses', []):
        if hypothesis.get('status') in {'CONTRADICTED', 'REJECTED', 'NOT_REOBSERVED_IN_CURRENT_SAMPLE'}:
            continue
        groups = hypothesis.get('dependency_groups') or (hypothesis.get('assessment') or {}).get('dependency_groups') or []
        if len(set(groups)) < 2 or len(hypothesis.get('evidence_ids') or []) < 2:
            continue
        active.update(k for k in (hypothesis.get('members') or hypothesis.get('subjects') or [hypothesis.get('subject')]) if isinstance(k, str))
    known_depth = {key: 0 for key in context['target_keys']}
    known_depth.update({key: value.get('depth', 1) for key, value in context['histories'].items()})
    frontier = {row['address_key']: row for row in context.get('frontier', []) if isinstance(row, dict) and row.get('address_key')}
    for (a, b), deps in pairs.items():
        for parent, key in ((a, b), (b, a)):
            if parent not in known_depth or key in context['target_keys']:
                continue
            depth = known_depth[parent] + 1
            if depth > MAX_HOPS or len(outgoing[parent]) < 3 or (len(deps) < 2 and key not in active):
                continue
            chain, address = key.split(':', 1)
            if address_id(chain, address) != key:
                continue
            blocked = _hub(key, data, pairs)
            score = len(deps) * 3 + (4 if key in active else 0) + route_priority[(a,b)] - depth
            candidate = {'address_key': key, 'blockchain': chain, 'address': address, 'depth': depth,
                         'parent_key': parent, 'priority': score, 'evidence_ids': sorted(refs[(a, b)]),
                         'distinct_edge_operations': len(deps), 'parent_distinct_transactions': len(outgoing[parent]),
                         'reason': 'active_hypothesis' if key in active else 'repeated_directed_operations',
                         'state': 'excluded_hub' if blocked else 'pending', 'exclusion_reason': blocked}
            old = frontier.get(key)
            if old:
                if score > old.get('priority', -1):
                    candidate.update({k: v for k, v in old.items() if k in {'state', 'attempted_sources', 'attempts', 'last_attempt'}})
                    frontier[key] = candidate
            else:
                frontier[key] = candidate
                journal(context, 'frontier.candidate', subject=key, evidence_ids=candidate['evidence_ids'],
                        decision='Exclude shared hub/contract' if blocked else 'Queue narrow neighbor history', result=candidate)
    context['frontier'] = sorted(frontier.values(), key=lambda r: (-r.get('priority', 0), r.get('depth', 1), r['address_key']))[:1000]
    return data


async def run_investigation_planner(report, sources, source_manager, *, semaphore=None, deadline=None,
                                   on_checkpoint=None, context=None, max_http_requests=24,
                                   max_seconds=20, max_neighbors=4, incremental=False):
    """Return and attach a resumable scoped context. Cancellation is propagated.

    HTTP attempts are measured by the existing transport hooks. Source cursors
    and a partial DTO are retained on timeout/cancellation; main financials are
    untouched. Optional investigation limits do not cap main target collection.
    """
    loop = asyncio.get_running_loop()
    started = loop.time()
    seconds = float(max_seconds)
    seconds = seconds if math.isfinite(seconds) and seconds > 0 else 0.0
    stop = min(started + seconds, deadline) if deadline is not None else started + seconds
    max_neighbors = max(0, min(int(max_neighbors), MAX_HISTORIES))
    context = context if context is not None else context_for(report)
    context.setdefault('histories', {})
    context.setdefault('frontier', [])
    context.setdefault('journal', [])
    report.attribution_intelligence = report.attribution_intelligence or {}
    report.attribution_intelligence['investigation_context'] = context
    context['sessions'] = context.get('sessions', 0) + 1
    context.setdefault('target_keys', [address_id(c, report.target_address) for c in report.detected_chains if address_id(c, report.target_address)])
    _plan(report, context)
    if incremental:
        for row in context['frontier']:
            if row.get('state')=='observed':row['state']='pending'
    attempted_neighbors = set()
    attempted_pairs = set()
    rate_limited_sources = set()
    cancelled = False

    async def checkpoint():
        if on_checkpoint is not None:
            result = on_checkpoint(report)
            if inspect.isawaitable(result):
                await result

    with bounded_request_scope(max_http_requests) as ledger:
        try:
            while loop.time() < stop and ledger['attempts'] < ledger['limit'] and len(attempted_neighbors) < max_neighbors:
                candidates = [row for row in context['frontier'] if row.get('state') in {'pending', 'partial', 'unavailable', 'budget_limited', 'deferred_rate_limit'}
                              and row['address_key'] not in attempted_neighbors and row.get('depth', 1) <= MAX_HOPS]
                if not candidates:
                    break
                item = candidates[0]
                key, chain, address = item['address_key'], item['blockchain'], item['address']
                attempted_neighbors.add(key)
                if key not in context['histories'] and len(context['histories']) >= MAX_HISTORIES:
                    item['state'] = 'context_storage_limit'
                    continue
                try:
                    previous = AddressReport.model_validate(context['histories'][key]['report']) if key in context['histories'] else AddressReport(target_address=address, detected_chains=[chain])
                except (ValueError, KeyError, TypeError):
                    previous = AddressReport(target_address=address, detected_chains=[chain])
                if len(previous.transactions) >= MAX_HISTORY_ROWS:
                    item['state'] = 'context_storage_limit'
                    continue
                options = [s for s in sources if normalize_chain(getattr(s, 'chain', '')) == chain and _kind(s)]
                options.sort(key=lambda s: (source_manager.priority(s.name), s.name))
                if not options:
                    item['state'] = 'unavailable'
                    journal(context, 'history.unavailable', subject=key, evidence_ids=item['evidence_ids'],
                            decision='No existing narrow history source for this network', missing_data=['neighbor history'])
                    continue
                for source in options:
                    if source.name in rate_limited_sources:
                        item['state']='deferred_rate_limit'
                        continue
                    if loop.time() >= stop or ledger['attempts'] >= ledger['limit']:
                        item['state'] = 'budget_limited'
                        break
                    if (key, source.name) in attempted_pairs:
                        continue
                    attempted_pairs.add((key, source.name))
                    remaining = stop - loop.time()
                    budget = min(remaining, max(.01, source_manager.timeout(source.name, min(remaining, 8.0))))
                    plan=source_manager.plan(source.name,budget)
                    if plan.fail_count or not source_manager.should_run(source.name, budget):
                        journal(context, 'history.source_gated', subject=key, decision='Existing SourceManager gate disallows source',
                                result={'source': source.name}, missing_data=['neighbor history'])
                        continue
                    clone = _clone(source, budget, previous, incremental=incremental)
                    partial = AddressReport(target_address=address, detected_chains=[chain], sources_used=[source.name])
                    clone._partial_report = partial
                    before = ledger['attempts']
                    before_rate_limits=ledger['statuses'].get('429',0)
                    source_started = loop.time()
                    state = 'partial'
                    incoming = None
                    error = None
                    try:
                        async with asyncio.timeout_at(min(stop, loop.time() + budget)):
                            if semaphore is None:
                                incoming = await _collect(clone, address, partial, _kind(clone))
                            else:
                                async with semaphore:
                                    incoming = await _collect(clone, address, partial, _kind(clone))
                        streams = (incoming.collection_audit.get('streams') or {}).get(source.name, {}) if isinstance(incoming, AddressReport) else {}
                        incomplete = any(not row.get('exhausted', False) for row in streams.values() if isinstance(row, dict))
                        state = ('partial' if incomplete or incoming.errors else 'observed') if isinstance(incoming, AddressReport) and incoming.transactions else 'unavailable'
                    except asyncio.CancelledError:
                        cancelled = True
                        state, error = 'partial', 'cancelled; retained completed observations and cursor'
                        raise
                    except (asyncio.TimeoutError, RequestBudgetExceeded) as exc:
                        state, error = 'budget_limited', type(exc).__name__
                    except Exception as exc:
                        state, error = 'partial', type(exc).__name__ + ': ' + str(exc)[:300]
                    finally:
                        if ledger['statuses'].get('429',0)>before_rate_limits:
                            rate_limited_sources.add(source.name)
                            state='deferred_rate_limit'
                            error=error or 'HTTP429; source deferred for the remaining optional session'
                        incoming = incoming if isinstance(incoming, AddressReport) else getattr(clone, '_partial_report', partial)
                        merged = _merge_history(previous, incoming)
                        if error:
                            merged.warnings.append('investigation: ' + error)
                        # A spent/cancelled optional deadline does not authorize
                        # an extra analysis pass. Raw observations remain useful
                        # to the normalizer and can be correlated next session.
                        if not cancelled and loop.time() < stop:
                            from .engine import correlate_attribution
                            correlate_attribution(merged, include_inference=False, max_transactions=2000,
                                                  max_seconds=min(.5, stop - loop.time()))
                        else:
                            merged.coverage['context_attribution'] = {'status': 'DEFERRED', 'reason': 'optional_deadline_or_cancellation'}
                        # Neighbors have no nested investigation contexts. Raw,
                        # cursor and evidence data remain available in their DTO.
                        merged.attribution_intelligence.pop('investigation_context', None)
                        merged.attribution_intelligence.pop('inferential_intelligence', None)
                        context['histories'][key] = {'blockchain': chain, 'address': address,
                            'depth': item['depth'], 'parent_key': item['parent_key'], 'status': state,
                            'last_observed_at': _now(), 'report': sanitize_observation(merged.model_dump(mode='json'))}
                        item.update(state=state, last_attempt=_now(), attempts=item.get('attempts', 0) + 1)
                        item['attempted_sources'] = list(dict.fromkeys(item.get('attempted_sources', []) + [source.name]))
                        journal(context, 'history.loaded', subject=key, evidence_ids=item['evidence_ids'],
                            decision='Retain separate neighbor DTO; target financials are unchanged',
                            result={'source': source.name, 'mode': _kind(clone), 'status': state, 'transactions': len(merged.transactions),
                                    'error': error, 'retained_cursor_streams': sorted((merged.collection_audit.get('streams') or {}).get(source.name, {}))},
                            cost={'http_requests': ledger['attempts'] - before, 'elapsed_seconds': loop.time() - source_started},
                            missing_data=['Independent role/controller evidence', 'Unobserved alternative history'])
                        previous = merged
                        await checkpoint()
                    if incoming.transactions:
                        # Scoped neighbor responses never clear or multiply the
                        # main collector's authoritative health result.
                        break
                _plan(report, context)
        finally:
            context['total_http_requests'] = context.get('total_http_requests', 0) + ledger['attempts']
            context['coverage'] = {'status': 'PARTIAL', 'history_complete': False, 'cancelled': cancelled,
                'last_session_http_requests': ledger['attempts'], 'last_session_transport': copy.deepcopy(ledger),
                'last_session_neighbors_attempted': len(attempted_neighbors), 'histories_retained': len(context['histories']),
                'frontier_remaining': sum(row.get('state') in {'pending', 'partial', 'budget_limited', 'unavailable', 'deferred_rate_limit'} for row in context['frontier']),
                'rate_limited_sources_deferred': sorted(rate_limited_sources),
                'max_hops_safety_ceiling': MAX_HOPS, 'max_histories_retained': MAX_HISTORIES,
                'elapsed_seconds': loop.time() - started, 'time_limit_reached': loop.time() >= stop,
                'request_limit_reached': ledger['attempts'] >= ledger['limit'],
                'scope': 'Optional separate neighbor histories; no addition to target financials; endpoint exhaustion does not establish complete chain history.'}
            journal(context, 'planner.session', subject=context['target_keys'], decision='Checkpoint bounded optional investigation',
                    result=copy.deepcopy(context['coverage']), cost={'http_requests': ledger['attempts'], 'elapsed_seconds': loop.time() - started})
    await checkpoint()
    return context
