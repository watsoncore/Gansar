"""Graph inference adversarial/unit controls. Real captures are replayed separately."""
import copy
import unittest

from app.attribution.graph_inference import analyze_graph_inference


def operation(n, a='A', b='B', *, when=None, asset='eth:native', amount='1', tx=None,
              chain='eth', success=True, kind='transfer'):
    return {'operation_id': f'op:{n}', 'blockchain': chain,
            'transaction_hash': tx or f'tx:{n}', 'from_key': f'{chain}:{a}', 'to_key': f'{chain}:{b}',
            'asset_key': asset, 'amount_decimal': amount,
            'timestamp': when if when is not None else f'2026-10-20T12:{n // 60:02}:{n % 60:02}+00:00',
            'success': success, 'kind': kind, 'evidence_ids': [f'ev:{n}'],
            'dependency_group': f'provider_projection:{n}', 'source_family': 'captured_rpc'}


def analyze(ops=(), **kw):
    data = {'operations': list(ops), 'addresses': {}, 'technical': {}, 'utxo_transactions': [],
            'target_keys': [], 'coverage': {'status': 'PARTIAL'}}
    data.update(kw.pop('data', {}))
    return analyze_graph_inference(data, **kw)


class DirectedTemporalGraphTests(unittest.TestCase):
    def test_real_directed_one_two_three_hops(self):
        result = analyze([operation(1, 'A', 'B'), operation(2, 'B', 'C'), operation(3, 'C', 'D')],
                         data={'target_keys': ['eth:B']})
        self.assertEqual({r['hop_count'] for r in result['paths']}, {1, 2, 3})
        self.assertIn(['eth:A', 'eth:B', 'eth:C', 'eth:D'], [p['nodes'] for p in result['paths']])
        self.assertTrue(all('eth:B' in p['nodes'] for p in result['paths']))
        self.assertTrue(all(not p['exact_funds_traced'] for p in result['paths']))

    def test_reverse_time_never_routes(self):
        result = analyze([operation(2, 'A', 'B'), operation(1, 'B', 'C')])
        self.assertTrue(all(p['hop_count'] == 1 for p in result['paths']))

    def test_equal_time_is_not_an_order(self):
        timestamp = '2026-10-20T12:00:00Z'
        result = analyze([operation(1, 'A', 'B', when=timestamp), operation(2, 'B', 'C', when=timestamp)])
        self.assertEqual(max(p['hop_count'] for p in result['paths']), 1)

    def test_missing_and_naive_time_suppress_multihop(self):
        a, b = operation(1), operation(2, 'B', 'C', when='2026-10-20T12:00:02')
        a['timestamp'] = None
        result = analyze([a, b])
        self.assertTrue(all(p['hop_count'] == 1 for p in result['paths']))
        self.assertEqual(result['diagnostics']['operations_without_timestamp'], 2)

    def test_timezone_offsets_compare_in_actual_order(self):
        a = operation(1, when='2026-10-20T17:00:00+05:00')
        b = operation(2, 'B', 'C', when='2026-10-20T12:00:01Z')
        self.assertTrue(any(p['hop_count'] == 2 for p in analyze([a, b])['paths']))

    def test_asset_identity_and_network_are_not_bridged(self):
        ops = [operation(1), operation(2, 'B', 'C', asset='eth:token:OTHER'),
               operation(3, 'C', 'D', chain='bsc', asset='bsc:native')]
        self.assertTrue(all(p['hop_count'] == 1 for p in analyze(ops)['paths']))
        ops[1]['asset_key'] = None
        self.assertTrue(all(p['hop_count'] == 1 for p in analyze(ops)['paths']))

    def test_physical_transaction_not_independent_per_projection(self):
        ops = [operation(1, 'A', 'B', tx='batch'), operation(2, 'A', 'C', tx='batch')]
        result = analyze(ops)
        self.assertFalse(result['clusters'])
        for rel in result['relationships']:
            self.assertEqual(rel['dependency_groups'], ['eth:tx:batch'])

    def test_same_transaction_cannot_be_chained_with_fabricated_timestamps(self):
        result = analyze([operation(1, tx='batch'), operation(2, 'B', 'C', tx='batch')])
        self.assertTrue(all(p['hop_count'] == 1 for p in result['paths']))

    def test_failed_approval_resources_and_zero_amount_are_excluded(self):
        ops = [operation(1, success=False), operation(2, kind='approval'),
               operation(3, kind='delegate_resource'), operation(4, amount='0'), operation(5, amount='-1')]
        result = analyze(ops)
        self.assertFalse(result['paths']); self.assertFalse(result['clusters']); self.assertFalse(result['relationships'])

    def test_zero_time_budget_is_safe_partial_result(self):
        result = analyze([operation(1)], max_seconds=0)
        self.assertFalse(result['paths'])
        self.assertTrue(result['diagnostics']['truncated'])
        self.assertEqual(result['coverage']['network_requests'], 0)

    def test_hubs_are_endpoints_never_intermediate_expansion(self):
        ops = [operation(n, 'Hub', f'R{n}') for n in range(1, 45)]
        ops += [operation(0, 'A', 'Hub')]
        result = analyze(ops, data={'target_keys': ['eth:A']})
        self.assertEqual(result['diagnostics']['structural_hubs_not_expanded'], 1)
        self.assertTrue(all(p['hop_count'] == 1 for p in result['paths']))
        self.assertFalse(result['clusters'])

    def test_amount_growth_requires_additional_balance_is_weak(self):
        result = analyze([operation(1, amount='0.000001'), operation(2, 'B', 'C', amount='1000')])
        two = next(p for p in result['paths'] if p['hop_count'] == 2)
        self.assertEqual(two['amount_compatibility'], 'ADDITIONAL_BALANCE_REQUIRED')
        self.assertEqual(two['status'], 'WEAK_LEAD')

    def test_limits_and_ids_and_input_immutability(self):
        ops = [operation(1), operation(2, 'B', 'C'), operation(3, 'A', 'D')]
        before = copy.deepcopy(ops)
        a, b = analyze(ops, max_clusters=1, max_paths=2), analyze(ops, max_clusters=1, max_paths=2)
        self.assertEqual(ops, before)
        self.assertLessEqual(len(a['clusters']), 1); self.assertLessEqual(len(a['paths']), 2)
        self.assertEqual([r['path_id'] for r in a['paths']], [r['path_id'] for r in b['paths']])

    def test_untrusted_or_inexact_numbers_do_not_crash(self):
        result = analyze([operation(1, amount='NaN'), operation(2, 'B', 'C', amount='1e999999999'),
                          operation(3, 'C', 'D', amount=0.1)])
        self.assertEqual(result['coverage']['operations_analyzed'], 3)

    def test_duplicate_operation_id_does_not_inflate_counts(self):
        row = operation(1)
        result = analyze([row, copy.deepcopy(row)])
        self.assertEqual(result['coverage']['operations_analyzed'], 1)
        self.assertEqual(result['relationships'][0]['operation_count'], 1)

    def test_analysis_time_is_injected_and_dependency_spelling_matches_normalizer(self):
        data = {'analysis_performed_at': '2026-10-20T00:00:00Z'}
        a = analyze([operation(1, 'F', 'A'), operation(2, 'F', 'B')], data=data)
        b = analyze([operation(1, 'F', 'A'), operation(2, 'F', 'B')], data=data)
        self.assertEqual(a['evidence'], b['evidence'])
        self.assertEqual(a['hypotheses'], b['hypotheses'])
        self.assertEqual(a['hypotheses'][0]['dependency_groups'], ['eth:tx:tx:1', 'eth:tx:tx:2'])

    def test_unknown_execution_and_float_precision_never_strengthen_route(self):
        a, b = operation(1), operation(2, 'B', 'C', success=None)
        result = analyze([a, b])
        self.assertEqual(next(p for p in result['paths'] if p['hop_count'] == 2)['status'], 'WEAK_LEAD')
        b['success'] = True; b['amount_precision'] = 'display_float'
        result = analyze([a, b])
        self.assertEqual(next(p for p in result['paths'] if p['hop_count'] == 2)['status'], 'WEAK_LEAD')

    def test_no_service_or_owner_label_propagation(self):
        result = analyze([operation(1), operation(2, 'A', 'C')], data={'addresses': {
            'eth:A': {'blockchain': 'eth', 'address': 'A', 'attributions': [{'entity_name': 'KnownBrand', 'status': 'CONFIRMED'}]}}})
        self.assertNotIn('KnownBrand', str(result))
        self.assertTrue(all(c['ownership_inferred'] is False for c in result['clusters']))
        self.assertTrue(all(r['scope'] in {'interacts_with', 'similar_behavior'} for r in result['relationships']))


class TypedMotifTests(unittest.TestCase):
    def test_sweep_threshold_uses_exact_amount_ratio_beyond_decimal_context(self):
        before='100000000000000000000000000000'
        below='79999999999999999999999999999'
        boundary='80000000000000000000000000000'
        for amount,expected in [(below,False),(boundary,True)]:
            ops=[operation(1,'F','A',amount=before),operation(2,'A','S',amount=amount),
                 operation(3,'F','B',amount=before),operation(4,'B','S',amount=amount)]
            kinds={c['type'] for c in analyze(ops)['clusters']}
            self.assertEqual('DEPOSIT_SWEEP_CLUSTER' in kinds,expected)

    def test_shared_funder_is_weak_lead_with_explicit_alternatives(self):
        result = analyze([operation(1, 'F', 'A'), operation(2, 'F', 'B')])
        c = next(c for c in result['clusters'] if c['type'] == 'FUNDING_CLUSTER')
        self.assertEqual(c['status'], 'WEAK_LEAD')
        self.assertEqual(c['members'], ['eth:A', 'eth:B'])
        self.assertEqual(c['anchor_keys'], ['eth:F'])
        h = result['hypotheses'][0]
        self.assertTrue(h['alternatives']); self.assertTrue(h['missing']); self.assertTrue(h['next_experiment'])
        self.assertEqual(len(h['dependency_groups']), 2)

    def test_overlapping_funding_consolidation_route_and_sweep_candidates(self):
        ops = [operation(1, 'F', 'A', amount='100'), operation(2, 'A', 'S', amount='99'),
               operation(3, 'F', 'B', amount='100'), operation(4, 'B', 'S', amount='99')]
        result = analyze(ops)
        kinds = {c['type'] for c in result['clusters']}
        self.assertTrue({'FUNDING_CLUSTER', 'CONSOLIDATION_CLUSTER', 'REPEATED_ROUTING_CLUSTER', 'DEPOSIT_SWEEP_CLUSTER'} <= kinds)
        self.assertTrue(all(c['members'] == ['eth:A', 'eth:B'] for c in result['clusters']))
        self.assertFalse(any(c['status'] in {'CONFIRMED', 'STRONGLY_SUPPORTED'} for c in result['clusters']))

    def test_near_amount_without_temporal_order_is_not_a_sweep(self):
        ops = [operation(3, 'F', 'A', amount='100'), operation(2, 'A', 'S', amount='99'),
               operation(5, 'F', 'B', amount='100'), operation(4, 'B', 'S', amount='99')]
        self.assertFalse(any(c['type'] == 'DEPOSIT_SWEEP_CLUSTER' for c in analyze(ops)['clusters']))

    def test_technical_shared_factory_is_separate_from_economic_graph(self):
        tech = {}
        factory = '0x' + '99' * 20
        for n in (1, 2):
            tech[str(n)] = {'blockchain': 'eth', 'transaction_hash': 'batch', 'implementation_observations': [{
                'subject_address': '0x' + str(n) * 40, 'status': 'OBSERVED',
                'fields': {'factory_address': factory, 'paymaster_address': '0x' + '88' * 20},
                'evidence_ids': [f'factory:{n}']}]}
        result = analyze(data={'technical': tech})
        self.assertFalse(result['paths'])
        self.assertEqual(len(result['clusters']), 2)
        self.assertTrue(all(c['graph_scope'] == 'technical' and c['status'] == 'WEAK_LEAD' for c in result['clusters']))
        self.assertTrue(all(r['scope'] == 'shared_protocol' for r in result['relationships']))


class UtxoOutpointTests(unittest.TestCase):
    def utxo(self, txid, prev=None, chain='btc'):
        return {'blockchain': chain, 'transaction_hash': txid, 'transaction_key': f'{chain}:transaction:{txid}',
                'input_keys': [f'{chain}:A'], 'output_keys': [f'{chain}:B', f'{chain}:C'],
                'inputs': [{'address_key': f'{chain}:A', 'prev_tx_hash': prev, 'prev_index': 0, 'value_decimal': '1'}] if prev else [],
                'outputs': [{'address_key': f'{chain}:A', 'index': 0, 'value_decimal': '1'}],
                'timestamp': None, 'evidence_ids': ['utxo:' + txid]}

    def test_no_address_cartesian_edges_or_clusters_from_cospending(self):
        tx = self.utxo('tx1')
        result = analyze([operation(1, chain='btc')], data={'utxo_transactions': [tx]})
        self.assertFalse(result['paths']); self.assertFalse(result['relationships']); self.assertFalse(result['clusters'])
        self.assertEqual(result['diagnostics']['utxo_address_edges_suppressed'], 1)

    def test_exact_outpoints_make_transaction_paths_up_to_three_hops(self):
        txs = [self.utxo('a'), self.utxo('b', 'a'), self.utxo('c', 'b'), self.utxo('d', 'c')]
        result = analyze(data={'utxo_transactions': txs})
        self.assertEqual({p['hop_count'] for p in result['paths']}, {1, 2, 3})
        self.assertTrue(all(p['type'] == 'utxo_transaction_spend_path' for p in result['paths']))
        self.assertTrue(all(':transaction:' in n for p in result['paths'] for n in p['nodes']))
        self.assertFalse(result['relationships'])

    def test_conflicting_prevout_address_or_value_prevents_link(self):
        a, b = self.utxo('a'), self.utxo('b', 'a')
        b['inputs'][0]['value_decimal'] = '2'
        result = analyze(data={'utxo_transactions': [a, b]})
        self.assertFalse(result['paths'])
        self.assertEqual(result['diagnostics']['utxo_conflicting_prevout_links_rejected'], 1)

    def test_same_tx_hash_on_other_chain_is_not_joined(self):
        result = analyze(data={'utxo_transactions': [self.utxo('a'), self.utxo('b', 'a', 'doge')]})
        self.assertFalse(result['paths'])


if __name__ == '__main__': unittest.main()
