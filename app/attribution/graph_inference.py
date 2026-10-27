"""Bounded, offline, typed graph inference over collected public observations.

Economic paths describe possible time-respecting routes, never identifiable
fungible coins. Candidate clusters overlap; there is deliberately no union-find,
service-label propagation, controller identity, or signing-application inference.
UTXO outpoints link transaction nodes only, without input/output allocation.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import heapq
import json
import math
import time

from .normalize import address_id

VERSION = '2026-10-20.1'
MAX_OPERATIONS = 20000
MAX_TECHNICAL = 20000
MAX_RELATIONSHIPS = 1000
MAX_NEIGHBORS = 40
BEAM_WIDTH = 12
MAX_STATES = 8000
MAX_ROUTE_DELAY = 30 * 86400
MOTIF_WINDOW = 86400
ALTERNATIVES = [
    'Unrelated customers may use the same exchange, payment service, faucet, relayer or public protocol.',
    'Partial history can hide alternative routes, pre-existing balances and unrelated incoming funds.',
    'A structural or temporal match does not establish a common owner, operator or signing application.',
]


def _id(kind, *parts):
    return 'graph-inference:' + kind + ':' + hashlib.sha256(
        json.dumps(parts, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest()


def _decimal(value):
    if isinstance(value, (bool, float)) or value is None:
        return None
    try:
        text = str(value)
        if len(text) > 256:
            return None
        result = Decimal(text)
        # Keep Decimal arithmetic bounded even for hostile exponent strings.
        return result if result.is_finite() and abs(result.adjusted()) <= 128 else None
    except (InvalidOperation, ValueError, TypeError):
        return None


def _sweep_ratio(before, after):
    """Exact inclusive 4/5..1 bound, unaffected by Decimal division precision."""
    incoming, incoming_denominator=before.as_integer_ratio()
    outgoing, outgoing_denominator=after.as_integer_ratio()
    return (4*incoming*outgoing_denominator <= 5*outgoing*incoming_denominator
            and outgoing*incoming_denominator <= incoming*outgoing_denominator)


def _time(value):
    if not isinstance(value, str) or len(value) > 80:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        # A timezone-less string cannot be compared across providers safely.
        return parsed.timestamp() if parsed.tzinfo is not None else None
    except (ValueError, OverflowError, OSError):
        return None


def _refs(rows, field):
    return sorted({v for row in rows for v in row.get(field, []) if isinstance(v, str) and v})


def _first_last(rows):
    times = [(r.get('_time'), r.get('timestamp')) for r in rows if r.get('_time') is not None]
    return {'first_observed': min(times)[1] if times else None,
            'last_observed': max(times)[1] if times else None}


def analyze_graph_inference(data, *, max_seconds=2.0, max_clusters=100, max_paths=100):
    """Analyze the normalizer's network-scoped observations without I/O.

    Input operations contain operation_id, blockchain, transaction_hash,
    from_key/to_key, asset_key, amount_decimal, timestamp, success, kind,
    evidence_ids, dependency_group, source_family and source_url. Optional
    utxo_transactions.inputs/outputs carry real prev_tx_hash/prev_index/index.
    Technical inputs are existing validated transaction_fingerprints records.
    All budgets are local to this optional pass; partial output remains useful.
    """
    started = time.monotonic()
    try:
        seconds = float(max_seconds)
        seconds = seconds if math.isfinite(seconds) and seconds > 0 else 0.0
    except (TypeError, ValueError):
        seconds = 0.0
    deadline = started + seconds
    max_clusters = max(0, min(int(max_clusters), 1000))
    max_paths = max(0, min(int(max_paths), 1000))
    now = data.get('analysis_performed_at') or datetime.now(timezone.utc).isoformat()
    out = {k: [] for k in ('clusters', 'hypotheses', 'relationships', 'paths', 'evidence')}
    counts = Counter()
    evidence = {}
    addresses = data.get('addresses') or {}
    source_coverage = data.get('coverage') or {}
    target_keys = set(data.get('target_keys') or [])
    known = {(str(r.get('blockchain')), r.get('address')): key for key, r in addresses.items()
             if isinstance(r, dict)}

    def expired():
        if time.monotonic() >= deadline:
            counts['time_budget_exhausted'] = 1
            return True
        return False

    def key(value, chain):
        if not isinstance(value, str) or not value:
            return None
        if value.startswith(chain + ':'):
            return value
        return known.get((chain, value)) or address_id(chain, value)

    def dependency(row, chain=None):
        chain = chain or row.get('blockchain') or ''
        tx = row.get('transaction_hash')
        # Different provider/event IDs cannot make one physical transaction
        # independent twice, including logs, internal transfers and batches.
        return f'{chain}:tx:{tx}' if tx else str(row.get('dependency_group') or
                                                        'unestablished:' + _id('observation', row.get('operation_id')))

    def observe(method, rows, facts):
        refs = _refs(rows, 'evidence_ids')
        deps = _refs(rows, 'dependency_groups')
        eid = _id('evidence', method, facts, refs, deps)
        evidence[eid] = {'evidence_id': eid, 'source': 'offline_graph_inference',
                         'relation': method, 'rule_version': VERSION, 'facts': facts,
                         'evidence_ids': refs, 'dependency_groups': deps,
                         'source_families': sorted({r.get('source_family') for r in rows if r.get('source_family')}),
                         'observed_at': now,
                         'source_independence': 'Derived views reuse the physical transaction dependency groups; no independent source is added.'}
        return sorted(set(refs + [eid])), deps

    def hypothesis(subject, claim, rows, method, confidence, *, support=None, missing=None, alternatives=None):
        refs, deps = observe(method, rows, {'subject': subject, 'claim': claim})
        h = {'id': _id('hypothesis', subject, method), 'subject': subject, 'claim': claim,
             'method': method, 'status': confidence, 'confidence': confidence,
             'evidence': refs, 'evidence_ids': refs, 'dependency_groups': deps,
             'support': support or [], 'supporting_observations': support or [],
             'contradictions': [], 'contradicting_observations': [],
             'alternatives': alternatives or list(ALTERNATIVES),
             'coverage': {'status': 'PARTIAL', 'history_complete': False,
                          'physical_transaction_groups': len(deps)},
             'missing': missing or ['Independent evidence of operational purpose and control.', 'Broader history and alternative routes.'],
             'next_experiment': 'Collect earlier and later history of the intermediate members; test alternative routes and independently verify infrastructure roles.',
             **_first_last(rows), 'last_verified': now}
        h['missing_evidence'] = h['missing']
        h['proposed_next_experiment'] = h['next_experiment']
        h['alternative_explanations'] = h['alternatives']
        out['hypotheses'].append(h)
        return h

    def cluster(kind, members, anchors, rows, method, confidence='WEAK_LEAD', **extra):
        if len(out['clusters']) >= max_clusters:
            counts['clusters_omitted_by_limit'] += 1
            return
        members = sorted(set(members))
        anchors = sorted(set(anchors))
        cid = _id('cluster', kind, members, anchors)
        refs, deps = observe(method, rows, {'type': kind, 'members': members, 'anchor_keys': anchors})
        record = {'cluster_id': cid, 'id': cid, 'type': kind, 'members': members,
                  'anchor_keys': anchors, 'method': method, 'status': confidence,
                  'evidence_ids': refs, 'dependency_groups': deps,
                  'alternatives': list(ALTERNATIVES), 'first_last': _first_last(rows),
                  **_first_last(rows), 'last_verified': now, 'ownership_inferred': False, **extra}
        out['clusters'].append(record)
        h = hypothesis(cid, f'{kind}: the members share the observed {method} pattern; common control remains unestablished.',
                   rows, method, confidence, support=[{'members': members, 'anchor_keys': anchors,
                   'physical_transactions': len(deps), 'observed_operations': len(rows)}])
        h.update(members=members, subjects=sorted(set(members + anchors)), anchor_keys=anchors)
        # A sparse, explicitly undirected peer relation exposes the candidate
        # pattern to graph renderers without creating an ownership component.
        scope = extra.get('scope') or 'similar_behavior'
        if extra.get('graph_scope') != 'technical':
            for member in members[1:]:
                if len(out['relationships']) >= MAX_RELATIONSHIPS:
                    counts['relationships_omitted_by_limit'] += 1
                    break
                out['relationships'].append({'relationship_id': _id('relationship', scope, cid, members[0], member),
                    'from_key': members[0], 'to_key': member, 'members': [members[0], member],
                    'blockchain': rows[0].get('blockchain'), 'type': scope, 'scope': scope,
                    'graph_scope': 'candidate_motif', 'directed': False, 'cluster_id': cid,
                    'method': method, 'status': confidence, 'ownership_inferred': False,
                    'evidence_ids': refs, 'dependency_groups': deps, 'alternatives': list(ALTERNATIVES),
                    'first_last': _first_last(rows), **_first_last(rows), 'last_verified': now})

    operations = []
    seen_operations = set()
    supplied_operations = data.get('operations') or []
    for op in supplied_operations:
        if expired(): break
        if len(operations) >= MAX_OPERATIONS:
            counts['operation_limit_reached'] = 1
            break
        if not isinstance(op, dict):
            counts['invalid_operations'] += 1; continue
        chain = op.get('blockchain')
        a, b = op.get('from_key'), op.get('to_key')
        kind = str(op.get('kind') or '').lower()
        if not isinstance(chain, str) or not all(isinstance(v, str) and v.startswith(chain + ':') for v in (a, b)):
            counts['invalid_or_cross_network_edges'] += 1; continue
        if chain in {'btc', 'doge'}:
            counts['utxo_address_edges_suppressed'] += 1; continue
        if op.get('success') is False or any(v in kind for v in ('approval', 'allowance', 'resource', 'permission', 'non_monetary', 'failed')):
            counts['non_movement_operations_excluded'] += 1; continue
        amount = _decimal(op.get('amount_decimal'))
        if amount is not None and amount <= 0:
            counts['non_positive_operations_excluded'] += 1; continue
        oid = op.get('operation_id') or _id('operation', chain, op.get('transaction_hash'), a, b, op.get('asset_key'), op.get('amount_decimal'))
        if oid in seen_operations:
            counts['duplicate_operation_ids'] += 1; continue
        seen_operations.add(oid)
        row = {**op, 'operation_id': oid, '_time': _time(op.get('timestamp')), '_amount': amount,
               'evidence_ids': [r for r in op.get('evidence_ids', []) if isinstance(r, str)],
               'dependency_groups': [dependency(op)]}
        operations.append(row)
        counts['operations_without_timestamp'] += row['_time'] is None
        counts['operations_without_asset_identity'] += not bool(row.get('asset_key'))
        counts['operations_without_exact_amount'] += amount is None
        counts['operations_without_verified_success'] += op.get('success') is not True

    outgoing = defaultdict(list); incoming = defaultdict(list); neighbors = defaultdict(set)
    pairs = defaultdict(list)
    for row in operations:
        a, b = row['from_key'], row['to_key']
        outgoing[a].append(row); incoming[b].append(row)
        neighbors[a].add(b); neighbors[b].add(a)
        pairs[(a, b, row.get('asset_key'))].append(row)
    hubs = {a for a, peers in neighbors.items() if len(peers) > MAX_NEIGHBORS}
    counts['structural_hubs_not_expanded'] = len(hubs)

    # Observed direct interactions are useful even without execution time, exact
    # amount or enough graph coverage for a temporal route hypothesis.
    for (a, b, asset), rows in pairs.items():
        if expired(): break
        if len(out['relationships']) >= MAX_RELATIONSHIPS:
            counts['relationships_omitted_by_limit'] += 1; continue
        refs, deps = observe('directed_observed_asset_operations', rows,
                             {'from_key': a, 'to_key': b, 'asset_key': asset,
                              'operation_ids': sorted(r['operation_id'] for r in rows)})
        out['relationships'].append({'relationship_id': _id('relationship', 'interacts_with', a, b, asset),
            'from_key': a, 'to_key': b, 'members': [a, b], 'blockchain': rows[0]['blockchain'],
            'type': 'interacts_with', 'scope': 'interacts_with', 'graph_scope': 'economic',
            'method': 'directed_observed_asset_operations', 'status': 'OBSERVED', 'asset_key': asset,
            'operation_count': len(rows), 'physical_transaction_count': len(deps),
            'evidence_ids': refs, 'dependency_groups': deps, 'alternatives': list(ALTERNATIVES),
            'first_last': _first_last(rows), **_first_last(rows), 'last_verified': now})

    # Best-first, bounded bidirectional path growth keeps target-containing routes
    # useful in both funding and recipient directions, including a target in the
    # middle. A high-degree node can be an endpoint, never an expansion point.
    frontier = []; queued = set(); retained = []; seq = 0

    def push(path):
        nonlocal seq
        identity = tuple(r['operation_id'] for r in path)
        if identity in queued: return
        if len(queued) >= MAX_STATES:
            counts['path_state_limit_reached'] = 1; return
        queued.add(identity); seq += 1
        # Prefer deeper, newer routes with a small endpoint neighborhood.
        latest = path[-1]['_time'] or 0
        heapq.heappush(frontier, (-len(path), len(neighbors[path[-1]['to_key']]), -latest, seq, path))

    if max_paths:
        for row in operations:
            if expired(): break
            if not target_keys or row['from_key'] in target_keys or row['to_key'] in target_keys:
                push([row])
        while frontier and len(retained) < max_paths and not expired():
            _, _, _, _, path = heapq.heappop(frontier)
            retained.append(path)
            if len(path) == 3: continue
            nodes = {r['from_key'] for r in path} | {path[-1]['to_key']}
            first, last = path[0], path[-1]
            candidates = []
            if first['from_key'] not in hubs:
                for row in incoming[first['from_key']]:
                    candidates.append(('before', row))
            if last['to_key'] not in hubs:
                for row in outgoing[last['to_key']]:
                    candidates.append(('after', row))
            candidates.sort(key=lambda pair: (pair[1]['_time'] is None,
                abs((pair[1]['_time'] or 0) - ((first if pair[0] == 'before' else last)['_time'] or 0)),
                pair[1]['operation_id']))
            accepted = 0
            for direction, row in candidates:
                if expired(): break
                boundary = first if direction == 'before' else last
                if not row.get('asset_key') or row.get('asset_key') != boundary.get('asset_key'):
                    counts['asset_mismatch_extensions_rejected'] += 1; continue
                if row['blockchain'] != boundary['blockchain']: continue
                if row['_time'] is None or boundary['_time'] is None:
                    counts['missing_time_extensions_rejected'] += 1; continue
                delta = boundary['_time'] - row['_time'] if direction == 'before' else row['_time'] - boundary['_time']
                if delta <= 0 or delta > MAX_ROUTE_DELAY:
                    counts['non_forward_or_stale_extensions_rejected'] += 1; continue
                endpoint = row['from_key'] if direction == 'before' else row['to_key']
                if endpoint in nodes: continue
                # Projection ordering inside a batch is not proven by tx time.
                if set(row['dependency_groups']) & set(_refs(path, 'dependency_groups')):
                    counts['same_transaction_extensions_rejected'] += 1; continue
                push([row] + path if direction == 'before' else path + [row])
                accepted += 1
                if accepted >= BEAM_WIDTH:
                    counts['beam_limited_expansions'] += 1; break
        if frontier: counts['paths_omitted_by_limit'] = len(frontier)

    for path in retained:
        nodes = [path[0]['from_key']] + [r['to_key'] for r in path]
        pid = _id('path', [r['operation_id'] for r in path])
        refs, deps = observe('bounded_temporal_asset_route', path,
                             {'nodes': nodes, 'operation_ids': [r['operation_id'] for r in path]})
        needs_balance = any(a['_amount'] is not None and b['_amount'] is not None and
                            b['_amount'] > a['_amount'] for a, b in zip(path, path[1:]))
        temporal = 'STRICTLY_INCREASING' if len(path) > 1 else 'SINGLE_OBSERVATION'
        row = {'path_id': pid, 'id': pid, 'nodes': nodes, 'members': nodes, 'hop_count': len(path),
               'blockchain': path[0]['blockchain'], 'asset_key': path[0].get('asset_key'),
               'type': 'possible_temporal_asset_route' if len(path) > 1 else 'observed_directed_operation',
               'scope': 'interacts_with', 'method': 'bounded_temporal_asset_route',
               'status': 'WEAK_LEAD' if needs_balance or any(r.get('success') is not True or r['_amount'] is None or
                            r.get('amount_precision') == 'display_float' for r in path) else 'POSSIBLE',
               'temporal_status': temporal, 'exact_funds_traced': False,
               'amount_compatibility': 'ADDITIONAL_BALANCE_REQUIRED' if needs_balance else 'NO_ALLOCATION_PROVEN',
               'operation_ids': [r['operation_id'] for r in path],
               'transaction_hashes': [r.get('transaction_hash') for r in path],
               'edges': [{k: r.get(k) for k in ('operation_id', 'transaction_hash', 'from_key', 'to_key',
                          'asset_key', 'amount_decimal', 'timestamp', 'success', 'evidence_ids', 'source_url')} for r in path],
               'evidence_ids': refs, 'dependency_groups': deps, 'alternatives': list(ALTERNATIVES),
               **_first_last(path), 'last_verified': now}
        out['paths'].append(row)

    # Typed, overlapping fan-out and fan-in groups are candidate infrastructure
    # patterns. Even repeated distribution can be unrelated service customers.
    for direction, index, kind in [('out', outgoing, 'FUNDING_CLUSTER'), ('in', incoming, 'CONSOLIDATION_CLUSTER')]:
        for anchor, rows in index.items():
            if expired(): break
            if anchor in hubs: continue
            assets = defaultdict(list)
            for row in rows:
                if row.get('asset_key'): assets[row['asset_key']].append(row)
            for asset, asset_rows in assets.items():
                field = 'to_key' if direction == 'out' else 'from_key'
                members = {r[field] for r in asset_rows if r[field] != anchor}
                deps = _refs(asset_rows, 'dependency_groups')
                if len(members) < 2 or len(deps) < 2: continue
                recurrence = Counter()
                for member in members:
                    recurrence[member] = len({r['dependency_groups'][0] for r in asset_rows if r[field] == member})
                repeated = sum(n >= 2 for n in recurrence.values())
                cluster(kind, members, [anchor], asset_rows, 'shared_funding' if direction == 'out' else 'shared_consolidation',
                        'POSSIBLE' if repeated >= 2 else 'WEAK_LEAD', asset_key=asset,
                        scope='similar_behavior', repeated_member_count=repeated,
                        roles={'anchor': anchor, 'member_role': 'funded_recipient' if direction == 'out' else 'contributing_sender'})

    # Match only the nearest prior same-asset receipt for each outgoing payment.
    # This reduces combinatorial inflation without pretending to allocate coins.
    motifs = defaultdict(list)
    for middle in sorted(set(outgoing) & set(incoming)):
        if expired(): break
        if middle in hubs: continue
        ins = sorted((r for r in incoming[middle] if r['_time'] is not None and r.get('asset_key')),
                     key=lambda r: r['_time'])[-128:]
        outs = sorted((r for r in outgoing[middle] if r['_time'] is not None and r.get('asset_key')),
                      key=lambda r: r['_time'])[-128:]
        for after in outs:
            if expired(): break
            before = next((r for r in reversed(ins) if r['asset_key'] == after['asset_key'] and
                           0 < after['_time'] - r['_time'] <= MOTIF_WINDOW and
                           r['from_key'] != after['to_key'] and
                           r['dependency_groups'] != after['dependency_groups']), None)
            if before:
                motifs[(before['from_key'], after['to_key'], before['asset_key'])].append((middle, before, after))
    for (funder, sink, asset), matches in motifs.items():
        if expired(): break
        members = {m for m, _, _ in matches}
        rows = list({r['operation_id']: r for _, a, b in matches for r in (a, b)}.values())
        if len(members) < 2 or len(_refs(rows, 'dependency_groups')) < 4: continue
        cluster('REPEATED_ROUTING_CLUSTER', members, [funder, sink], rows,
                'shared_funding_and_consolidation_routes', 'POSSIBLE', asset_key=asset,
                scope='shared_infrastructure_supported', roles={'funder': funder, 'consolidation': sink},
                route_count=len(matches))
        sweep = [(m, a, b) for m, a, b in matches if a['_amount'] and b['_amount'] and
                 a.get('native_value_purpose') != 'jetton_transfer_request' and b.get('native_value_purpose') != 'jetton_transfer_request' and
                 a.get('amount_precision') != 'display_float' and b.get('amount_precision') != 'display_float' and
                 _sweep_ratio(a['_amount'],b['_amount']) and
                 b['_time'] - a['_time'] <= 21600]
        if len({m for m, _, _ in sweep}) >= 2:
            sweep_rows = list({r['operation_id']: r for _, a, b in sweep for r in (a, b)}.values())
            cluster('DEPOSIT_SWEEP_CLUSTER', {m for m, _, _ in sweep}, [funder, sink], sweep_rows,
                    'temporal_near_amount_deposit_sweep_candidate', 'POSSIBLE', asset_key=asset,
                    scope='similar_behavior', balance_coverage='UNKNOWN; value similarity does not establish swept balance')

    # Existing validated fingerprints contribute role edges, never value edges.
    technical_groups = defaultdict(list)
    for technical_index, (ref, record) in enumerate((data.get('technical') or {}).items()):
        if expired(): break
        if technical_index >= MAX_TECHNICAL:
            counts['technical_limit_reached'] = 1; break
        if not isinstance(record, dict): continue
        chain = record.get('blockchain')
        if not isinstance(chain, str): continue
        for obs in (record.get('implementation_observations') or [])[:256]:
            if expired(): break
            if not isinstance(obs, dict) or str(obs.get('status', '')).upper() in {'UNKNOWN', 'CONTRADICTED', 'FAILED'}: continue
            subject = key(obs.get('subject_address'), chain)
            if not subject: continue
            fields = obs.get('fields') or {}
            for field, role, ctype in [('factory_address', 'factory', 'SMART_ACCOUNT_FACTORY_CLUSTER'),
                                      ('paymaster_address', 'paymaster', 'SHARED_PROTOCOL_CLUSTER'),
                                      ('program_id', 'program', 'SHARED_PROTOCOL_CLUSTER'),
                                      ('owner_program', 'owner_program', 'SHARED_PROTOCOL_CLUSTER'),
                                      ('singleton_address', 'implementation', 'SHARED_IMPLEMENTATION_CLUSTER'),
                                      ('delegate_address', 'implementation', 'SHARED_IMPLEMENTATION_CLUSTER')]:
                anchor = key(fields.get(field), chain)
                if not anchor or subject == anchor: continue
                rows = [{**obs, 'timestamp': obs.get('observed_at'), '_time': _time(obs.get('observed_at')),
                         'dependency_groups': [dependency(record, chain)], 'technical_ref': ref}]
                technical_groups[(role, anchor, ctype)].append((subject, rows[0]))
                if len(out['relationships']) >= MAX_RELATIONSHIPS: continue
                refs, deps = observe('validated_technical_role', rows, {'subject': subject, 'anchor': anchor, 'role': role})
                rid = _id('relationship', 'shared_protocol', subject, anchor, role)
                existing = next((r for r in out['relationships'] if r['relationship_id'] == rid), None)
                if existing:
                    existing['evidence_ids'] = sorted(set(existing['evidence_ids'] + refs))
                    existing['dependency_groups'] = sorted(set(existing['dependency_groups'] + deps))
                    continue
                out['relationships'].append({'relationship_id': rid, 'from_key': subject, 'to_key': anchor,
                    'members': [subject, anchor], 'blockchain': chain, 'type': 'shared_protocol', 'scope': 'shared_protocol',
                    'graph_scope': 'technical', 'role': role, 'method': 'validated_technical_role', 'status': 'OBSERVED',
                    'evidence_ids': refs, 'dependency_groups': deps, 'alternatives': list(ALTERNATIVES),
                    'first_last': _first_last(rows), **_first_last(rows), 'last_verified': now})
    for (role, anchor, ctype), records in technical_groups.items():
        if expired(): break
        members = {s for s, _ in records}
        if len(members) < 2: continue
        rows = [r for _, r in records]
        cluster(ctype, members, [anchor], rows, 'shared_validated_' + role,
                'WEAK_LEAD' if len(_refs(rows, 'dependency_groups')) < 2 else 'POSSIBLE',
                scope='shared_protocol', graph_scope='technical', role=role)

    _utxo_paths(data.get('utxo_transactions') or [], out, evidence, counts, max_paths, expired, observe, now)
    out['evidence'] = list(evidence.values())
    all_keys = set(neighbors) | set(addresses)
    for row in out['relationships']:
        all_keys.update(row.get('members', []))
    for tx in (data.get('utxo_transactions') or [])[:MAX_OPERATIONS]:
        if isinstance(tx, dict):
            all_keys.update(tx.get('input_keys') or [])
            all_keys.update(tx.get('output_keys') or [])
    out['coverage'] = {'status': 'PARTIAL', 'history_complete': False, 'network_requests': 0,
        'operations_supplied': len(supplied_operations), 'operations_analyzed': len(operations),
        'network_qualified_addresses': len(all_keys), 'economic_network_qualified_addresses': len(neighbors),
        'utxo_transactions_supplied': len(data.get('utxo_transactions') or []),
        'max_depth': 3, 'max_neighbors_expanded': MAX_NEIGHBORS,
        'beam_width': BEAM_WIDTH, 'max_path_states': MAX_STATES, 'max_operations': MAX_OPERATIONS,
        'source_coverage': source_coverage, 'independently_confirmed_clusters': 0,
        'limitations': ['Paths show compatible observations; fungible units and UTXO input/output allocation are not traced.',
                       'Equal or missing timestamps cannot establish a multi-hop order.',
                       'Provider history boundaries and local degrees can hide global hubs and alternative paths.',
                       'Candidate membership overlaps and never unifies ownership or propagates a service label.']}
    out['diagnostics'] = {**dict(counts), 'elapsed_seconds': time.monotonic() - started,
        'max_seconds': seconds, 'max_clusters': max_clusters, 'max_paths': max_paths,
        'algorithm': 'bounded_bidirectional_best_first_temporal_paths_and_typed_motifs', 'version': VERSION,
        'truncated': bool(counts['time_budget_exhausted'] or counts['operation_limit_reached'] or
                          counts['clusters_omitted_by_limit'] or counts['paths_omitted_by_limit'] or
                          counts['path_state_limit_reached'] or counts['technical_limit_reached'])}
    return out


def _utxo_paths(transactions, out, evidence, counts, max_paths, expired, observe, now):
    """Use exact captured prevouts to join transaction nodes, never addresses."""
    txs = {}; outputs = {}
    for tx in transactions[:MAX_OPERATIONS]:
        if expired(): return
        if not isinstance(tx, dict) or tx.get('blockchain') not in {'btc', 'doge'} or tx.get('success') is False: continue
        chain, txid = tx['blockchain'], tx.get('transaction_hash')
        if not txid: continue
        record = {**tx, '_time': _time(tx.get('timestamp')),
                  'dependency_groups': [f'{chain}:tx:{txid}']}
        txs[(chain, txid)] = record
        for item in (tx.get('outputs') or [])[:4096]:
            if isinstance(item, dict) and type(item.get('index')) is int and item['index'] >= 0:
                outputs[(chain, txid, item['index'])] = item
    counts['utxo_transactions_analyzed'] = len(txs)
    next_txs = defaultdict(list)
    for (chain, txid), tx in txs.items():
        if expired(): return
        for item in (tx.get('inputs') or [])[:4096]:
            if not isinstance(item, dict): continue
            prev = item.get('prev_tx_hash'); index = item.get('prev_index')
            if type(index) is not int or not isinstance(prev, str) or prev == txid: continue
            output = outputs.get((chain, prev, index))
            parent = txs.get((chain, prev))
            if output is None or parent is None: continue
            # Captured outpoint value/address conflicts invalidate this join.
            if item.get('address_key') and output.get('address_key') and item['address_key'] != output['address_key']:
                counts['utxo_conflicting_prevout_links_rejected'] += 1; continue
            a, b = _decimal(item.get('value_decimal')), _decimal(output.get('value_decimal'))
            if a is not None and b is not None and a != b:
                counts['utxo_conflicting_prevout_links_rejected'] += 1; continue
            next_txs[(chain, prev)].append((txid, index))
    seen = set()
    for origin in sorted(next_txs):
        if expired(): return
        stack = [(origin, [], [])]
        while stack and len(out['paths']) < max_paths and not expired():
            node, path, links = stack.pop()
            if node in path: continue
            path = path + [node]
            if links:
                identity = tuple(path)
                if identity not in seen:
                    seen.add(identity)
                    rows = [txs[n] for n in path]
                    nodes = [str(txs[n].get('transaction_key') or f'{n[0]}:transaction:{n[1]}') for n in path]
                    refs, deps = observe('captured_utxo_outpoint_spend_link', rows,
                                         {'transaction_nodes': nodes, 'outpoints': links})
                    pid = _id('utxo_path', path)
                    out['paths'].append({'path_id': pid, 'id': pid, 'nodes': nodes, 'members': nodes,
                        'hop_count': len(links), 'blockchain': origin[0], 'asset_key': origin[0] + ':native',
                        'type': 'utxo_transaction_spend_path', 'scope': 'interacts_with', 'graph_scope': 'utxo_transaction',
                        'method': 'captured_utxo_outpoint_spend_link', 'status': 'POSSIBLE',
                        'transaction_hashes': [n[1] for n in path], 'outpoints': links,
                        'evidence_ids': refs, 'dependency_groups': deps, 'exact_funds_traced': False,
                        'allocation': 'UNKNOWN; spending an output does not allocate any input to a later output',
                        'alternatives': list(ALTERNATIVES), **_first_last(rows), 'last_verified': now})
            if len(links) >= 3: continue
            for child, index in next_txs[node][:BEAM_WIDTH]:
                stack.append(((origin[0], child), path, links + [f'{node[1]}:{index}']))
    counts['utxo_verified_outpoint_joins'] = sum(len(v) for v in next_txs.values())
