"""Pure DTO controls for the additive graph layer; no fabricated live evidence."""
import copy
from datetime import datetime, timezone
from decimal import Decimal
import unittest

from app.graph.builder import build_graph_payload, _wallet_node_id
from app.models.report import AddressReport, Transaction

A, B, C = ['0x' + x * 40 for x in ('1', '2', '3')]
AT = '2026-10-20T12:00:00Z'


def record(address, chain='eth'):
    return {'address': address, 'blockchain': chain, 'address_key': chain + ':' + address,
            'account_type': 'unknown', 'attributions': [], 'conflicts': []}


def relationship(n='1', a=B, b=C, scope='similar_behavior', status='WEAK_LEAD', chain='eth'):
    return {'relationship_id': 'relation:' + n, 'from_key': chain + ':' + a, 'to_key': chain + ':' + b,
            'blockchain': chain, 'scope': scope, 'type': scope, 'status': status,
            'method': 'typed_motif_' + n, 'evidence_ids': ['proof:' + n],
            'dependency_groups': [chain + ':tx:' + n], 'first_observed': AT, 'last_observed': AT,
            'directed': False, 'graph_scope': 'candidate_motif'}


def report(inference=None):
    r = AddressReport(target_address=A, detected_chains=['eth'], transactions=[Transaction(
        chain='eth', tx_hash='0x' + 'ab' * 32, from_address=A, to_address=B,
        amount_base_units=10**18, decimals=18, asset='ETH', timestamp=datetime(2026, 10, 20, tzinfo=timezone.utc),
        source='dto_control', success=True)])
    r.attribution_intelligence = {'addresses': {'eth:' + a: record(a) for a in (A, B, C)},
        'evidence': [{'evidence_id': 'proof:' + str(n), 'url': 'https://example.com/proof/' + str(n),
                      'source': 'dto_control'} for n in range(1, 4)], 'relationships': []}
    if inference is not None: r.attribution_intelligence['inferential_intelligence'] = inference
    return r


class AdditiveInferenceGraphTests(unittest.TestCase):
    def test_typed_candidate_cluster_members_never_ownership(self):
        cluster = {'id': 'cluster:one', 'cluster_id': 'cluster:one', 'type': 'FUNDING_CLUSTER',
                   'members': ['eth:' + B, 'eth:' + C], 'status': 'WEAK_LEAD', 'scope': 'similar_behavior',
                   'evidence_ids': ['proof:1'], 'dependency_groups': ['eth:tx:1'],
                   'first_observed': AT, 'last_observed': AT}
        g = build_graph_payload(report({'clusters': [cluster], 'hypotheses': [{'id': 'H1', 'subject': 'cluster:one'}]}))
        node = next(n for n in g['nodes'] if n['kind'] == 'inference_cluster')
        self.assertEqual(node['cluster_id'], 'cluster:one')
        self.assertEqual(node['ownership'], 'UNKNOWN')
        members = [e for e in g['edges'] if e['type'] == 'inference_membership']
        self.assertEqual(len(members), 2)
        self.assertTrue(all(e['analytic'] and e['monetary'] is False for e in members))
        self.assertTrue(all(e['cluster_id'] == 'cluster:one' and e['hypothesis_ids'] == ['H1'] for e in members))
        self.assertTrue(all(e['ownership'] == 'UNKNOWN' and e['confidence'] is None for e in members))
        self.assertFalse(any(e['type'] in {'owns', 'same_entity_confirmed'} for e in members))

    def test_multiple_methods_keep_all_proofs_and_status_records_after_compaction(self):
        a, b = relationship('1'), relationship('2', status='POSSIBLE')
        g = build_graph_payload(report({'relationships': [a, b]}))
        rows = [e for e in g['edges'] if e['type'] == 'inference_association']
        self.assertEqual(len(rows), 1)
        edge = rows[0]
        self.assertEqual(set(edge['evidence_ids']), {'proof:1', 'proof:2'})
        self.assertEqual(set(edge['dependency_groups']), {'eth:tx:1', 'eth:tx:2'})
        self.assertEqual(set(edge['relationship_ids']), {'relation:1', 'relation:2'})
        self.assertEqual(len(edge['observations']), 2)
        self.assertEqual(edge['status'], 'MIXED'); self.assertEqual(edge['confirmation'], 'MIXED')
        self.assertIsNone(edge['confidence'])

    def test_existing_financial_edges_and_reduction_selection_are_preserved(self):
        base_report = report(); base = build_graph_payload(base_report)
        augmented_report = copy.deepcopy(base_report)
        augmented_report.attribution_intelligence['inferential_intelligence'] = {'relationships': [relationship()]}
        augmented = build_graph_payload(augmented_report)
        self.assertEqual([e for e in augmented['edges'] if not e.get('analytic')], base['edges'])
        self.assertTrue({n['id'] for n in base['nodes']} <= {n['id'] for n in augmented['nodes']})
        for original in base['nodes']:
            updated = next(n for n in augmented['nodes'] if n['id'] == original['id'])
            self.assertEqual(updated['tx_count'], original['tx_count'])
        self.assertEqual(augmented['top_by_amount'], base['top_by_amount'])
        self.assertFalse(augmented['inferential_graph']['financial_totals_modified'])

    def test_observed_context_transfers_are_distinct_and_never_summed(self):
        r = relationship(scope='interacts_with'); r['graph_scope'] = 'economic'
        r['amount_decimal'] = '987654321'; r['operation_count'] = 20
        g = build_graph_payload(report({'relationships': [r]}))
        edge = next(e for e in g['edges'] if e['type'] == 'inference_observed_transfer')
        self.assertFalse(edge['monetary']); self.assertFalse(edge['financial_totals_included'])
        self.assertNotIn('total', edge); self.assertNotIn('amount_decimal', edge); self.assertNotIn('amount', edge)
        self.assertEqual(edge['count'], 1)

    def test_canonical_address_keys_and_original_dossier_labels(self):
        r = report({'relationships': [relationship(a=B.upper().replace('0X', '0x'))]})
        r.attribution_intelligence['addresses']['eth:' + B]['attributions'] = [{'entity_name': 'KnownPublishedAnchor', 'status': 'CONFIRMED'}]
        g = build_graph_payload(r)
        edge = next(e for e in g['edges'] if e['type'] == 'inference_association')
        self.assertEqual(edge['from'], _wallet_node_id('eth', B))
        recipient = next(n for n in g['nodes'] if n['id'] == _wallet_node_id('eth', C))
        self.assertNotIn('KnownPublishedAnchor', recipient['label'])
        self.assertFalse(any('KnownPublishedAnchor' in str(e) for e in g['edges'] if e.get('analytic')))

    def test_cross_network_edges_and_invalid_keys_are_not_invented(self):
        a, b = relationship(), relationship('2')
        a['to_key'] = 'bsc:' + C
        b['from_key'] = 'eth:invalid-address'
        g = build_graph_payload(report({'relationships': [a, b]}))
        self.assertFalse(any(e.get('analytic') for e in g['edges']))
        self.assertGreater(g['inferential_graph']['diagnostics']['cross_network_relationships_omitted'], 0)

    def test_hop_paths_have_node_and_edge_ids_for_existing_view_highlight(self):
        path = {'id': 'path:1', 'path_id': 'path:1', 'blockchain': 'eth', 'nodes': ['eth:' + A, 'eth:' + B, 'eth:' + C],
                'hop_count': 2, 'status': 'POSSIBLE', 'type': 'possible_temporal_asset_route', 'evidence_ids': ['proof:1'],
                'first_observed': AT, 'last_observed': AT, 'transaction_hashes': ['tx1', 'tx2']}
        g = build_graph_payload(report({'paths': [path]}))
        view = g['inferential_graph']['paths'][0]
        self.assertEqual(view['nodes'], [_wallet_node_id('eth', a) for a in (A, B, C)])
        self.assertEqual(len(view['edge_ids']), 2)
        self.assertTrue(all(e['path_ids'] == ['path:1'] for e in g['edges'] if e['type'] == 'inference_route_step'))
        self.assertTrue(any(e['type'] == 'inference_route_step' for e in g['edges'] if e['from'] == g['target']))

    def test_utxo_paths_only_join_transaction_nodes(self):
        hashes = ['ab' * 32, 'cd' * 32, 'ef' * 32]
        path = {'id': 'utxo:1', 'blockchain': 'btc', 'nodes': ['btc:transaction:' + h for h in hashes],
                'hop_count': 2, 'status': 'POSSIBLE', 'type': 'utxo_transaction_spend_path', 'evidence_ids': ['proof:1']}
        g = build_graph_payload(report({'paths': [path]}))
        edges = [e for e in g['edges'] if e.get('analytic')]
        self.assertEqual(len(edges), 2)
        self.assertTrue(all(e['type'] == 'inference_utxo_spend' for e in edges))
        self.assertTrue(all(e['from'].startswith('tx:btc:') and e['to'].startswith('tx:btc:') for e in edges))
        self.assertTrue(all('total' not in e and 'amount_decimal' not in e for e in edges))

    def test_broad_cluster_batch_cannot_starve_target_route_overlay(self):
        clusters=[{'id':'cluster:'+str(i),'members':['eth:0x'+f'{i*20+j+100:040x}' for j in range(20)],
            'type':'FUNDING_CLUSTER','status':'WEAK_LEAD','evidence_ids':['proof:1']} for i in range(20)]
        path={'id':'priority:path','blockchain':'eth','nodes':['eth:'+A,'eth:'+B,'eth:'+C],
            'hop_count':2,'status':'POSSIBLE','type':'possible_temporal_asset_route','evidence_ids':['proof:1']}
        g=build_graph_payload(report({'clusters':clusters,'paths':[path]}))
        self.assertEqual(g['inferential_graph']['paths'][0]['path_id'],'priority:path')
        self.assertEqual(len(g['inferential_graph']['paths'][0]['edge_ids']),2)
        self.assertLessEqual(g['inferential_graph']['nodes_added'],100)

    def test_filters_timestamps_and_evidence_refs_are_retained(self):
        g = build_graph_payload(report({'relationships': [relationship()]}))
        edge = next(e for e in g['edges'] if e.get('analytic'))
        self.assertEqual(edge['chain'], 'eth'); self.assertEqual(edge['blockchain'], 'eth')
        self.assertEqual(edge['first_seen'], '2026-10-20T12:00:00+00:00')
        self.assertEqual(edge['last_seen'], edge['first_seen'])
        self.assertEqual(edge['evidence_urls'], ['https://example.com/proof/1'])
        self.assertIn('inference_association', g['filters']['edge_types'])
        self.assertIn(edge['id'], g['views']['inference_edges'])

    def test_graph_overlay_bounds_are_explicit(self):
        rels = [relationship(str(n), a='0x' + f'{n + 100:040x}', b='0x' + f'{n + 2000:040x}') for n in range(500)]
        g = build_graph_payload(report({'relationships': rels}))
        info = g['inferential_graph']
        self.assertLessEqual(info['nodes_added'], 100); self.assertLessEqual(info['edges_added'], 300)
        self.assertTrue(info['diagnostics']['nodes_omitted_by_limit'])
        known = {n['id'] for n in g['nodes']}
        self.assertTrue(all(e['from'] in known and e['to'] in known for e in g['edges']))

    def test_unrecognized_owner_claim_type_is_not_drawn(self):
        g = build_graph_payload(report({'relationships': [relationship(scope='same_entity_confirmed')]}))
        self.assertFalse(any(e.get('analytic') for e in g['edges']))


if __name__ == '__main__': unittest.main()
