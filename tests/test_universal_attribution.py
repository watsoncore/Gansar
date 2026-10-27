"""Network-qualified facts, strict roles and false-positive guards."""
import unittest
from unittest.mock import patch
from app.models.report import AddressReport,Transaction,Balance,Label
from app.attribution.normalize import canonical_address,address_id
from app.attribution.fingerprints import evm_code_fingerprint
from app.attribution.engine import correlate_attribution
from app.graph.builder import build_graph_payload

A='0x'+'1'*40;B='0x'+'2'*40
BTC_A='1BoatSLRHtKNngkdXEeobR76b53LETtpyT';BTC_B='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
SOL='11111111111111111111111111111111';TOKEN='TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
def entry(chain='eth',address=B,entity='fixture_service',name='Fixture Service',**options):
    return {'blockchain':chain,'address':address,'entity_id':entity,'entity_name':name,'entity_type':'exchange_infrastructure',
        'source':'fixture_registry','upstream':'fixture_upstream','source_url':'https://example.com/addresses',
        'observed_at':'2026-10-16T01:02:03Z','license':'MIT',**options}
def report(chain='eth'):
    return AddressReport(target_address=A,detected_chains=[chain],transactions=[Transaction(chain=chain,tx_hash='a'*64,
        from_address=A,to_address=B,amount_base_units=10**18,decimals=18,asset='ETH',source='fixture',success=True,
        url='https://example.com/tx/'+'a'*64)])

class NetworkIdentifiers(unittest.TestCase):
    def test_networks_and_case_are_not_conflated(self):
        self.assertNotEqual(address_id('eth',A),address_id('bsc',A))
        self.assertEqual(canonical_address('eth',A.upper().replace('0X','0x')),A)
        self.assertEqual(canonical_address('btc',BTC_A),BTC_A)
        self.assertIsNone(canonical_address('btc',BTC_A[:-1]+'1'))
        self.assertIsNone(canonical_address('solana','a'*31))
        self.assertIsNone(canonical_address('tron','T'+'1'*33))

class StructuralFingerprints(unittest.TestCase):
    def test_minimal_proxy_and_7702_identify_role_not_application(self):
        proxy=evm_code_fingerprint('0x363d3d373d3d3d363d73'+B[2:]+'5af43d82803e903d91602b57fd5bf3')
        self.assertEqual(proxy['implementation'],B);self.assertEqual(proxy['kind'],'eip1167_minimal_proxy')
        self.assertEqual(evm_code_fingerprint('0xef0100'+B[2:])['kind'],'eip7702_delegation_designator')
        self.assertNotIn('client',proxy);self.assertEqual(evm_code_fingerprint('0xzz'),{})

class EvidenceCorrelation(unittest.TestCase):
    def test_broken_optional_catalogue_keeps_collected_transactions_and_reports_error(self):
        with patch('app.attribution.datasets.lookup_dataset_records',side_effect=ValueError('content hash mismatch')):
            result=correlate_attribution(report())
        self.assertEqual(len(result['transactions']),1)
        self.assertEqual(result['errors'][0]['source'],'attribution_dataset')
        self.assertFalse(result['addresses']['eth:'+A]['attributions'])
    def test_counterparty_service_does_not_become_target_wallet_brand(self):
        r=report();data=correlate_attribution(r,dataset_records=[entry()])
        self.assertFalse(data['addresses']['eth:'+A]['attributions'])
        self.assertEqual(data['addresses']['eth:'+A]['client_attribution']['status'],'UNKNOWN')
        self.assertEqual(data['addresses']['eth:'+B]['attributions'][0]['status'],'PROBABLE')
        self.assertTrue(data['relationships']);self.assertEqual(data['stats']['network_requests'],0)
        evidence={v['evidence_id'] for v in data['evidence']}
        self.assertTrue(all(set(c['evidence_ids'])<=evidence for d in data['addresses'].values() for c in d['attributions']))
        services=[v for v in build_graph_payload(r)['edges'] if v['type']=='service_attribution']
        self.assertTrue(services)
        self.assertTrue(all(v['chain']=='eth' for v in services))
    def test_wrong_chain_label_cannot_match_identical_hex_address(self):
        data=correlate_attribution(report(),dataset_records=[entry(chain='bsc')])
        self.assertFalse(data['addresses']['eth:'+B]['attributions'])
    def test_public_html_css_username_and_page_titles_are_not_service_identity(self):
        r=report();r.labels=[Label(chain='eth',address=A,label=label,source='fixture',confidence=0.5,
            raw={'url':'https://example.com/page',**raw}) for label,raw in (
            ('Telegram marker: @media',{'parser':'public_page_username'}),('Generic explorer title',{'kind':'tonviewer'}),
            ('Service signal: wallet',{'parser':'public_page_service'}),('Contract: WETH9',{'contract_name':'WETH9'}))]
        data=correlate_attribution(r,dataset_records=[])
        self.assertFalse(data['addresses']['eth:'+A]['attributions'])
        self.assertEqual(len(r.labels),4)
    def test_conflicting_entities_are_preserved_without_winner(self):
        data=correlate_attribution(report(),dataset_records=[entry(),entry(entity='other',name='Other',source='second',source_url='https://other.example/address')])
        item=data['addresses']['eth:'+B]
        self.assertEqual(len(item['attributions']),2);self.assertTrue(item['conflicts'])
        self.assertTrue(all(c['status']=='PROBABLE' and c['conflicts'] for c in item['attributions']))
        self.assertTrue(all(c['conflicting_evidence'] for c in item['attributions']))
    def test_missing_publication_date_remains_unknown(self):
        data=correlate_attribution(report(),dataset_records=[entry(observed_at=None)])
        self.assertEqual(data['addresses']['eth:'+B]['attributions'][0]['observation_timestamps'],[])
    def test_approval_allowance_is_not_a_transfer(self):
        r=report('bsc');r.transactions[0].raw={'type':'approval','owner':A,'spender':B,'token_contract':'0x'+'3'*40}
        d=correlate_attribution(r,dataset_records=[entry('bsc')])
        self.assertEqual(len(d['transactions']),1)
        self.assertEqual([v['type'] for v in d['relationships']],['token_allowance_observation'])
        self.assertNotIn('amount_total_decimal',d['relationships'][0])
        graph=build_graph_payload(r)
        self.assertFalse(any(v['type'] in {'sent','received','transfer'} for v in graph['edges']))
        self.assertTrue(all(v['total'] is None for v in graph['edges']))  # absent payment amount is not zero
        r.transactions[0].success=False
        self.assertFalse(correlate_attribution(r,dataset_records=[])['relationships'])
    def test_contract_call_is_identified_as_interaction(self):
        r=report();r.transactions[0].raw={'type':'contract_call'}
        self.assertEqual(correlate_attribution(r,dataset_records=[])['relationships'][0]['type'],'contract_interaction')
    def test_conflicting_runtime_hashes_cannot_confirm_manifest(self):
        r=report();r.balances=[Balance(chain='eth',address=A,asset='ETH',amount=0,source='rpc'+char,
            raw={'contract_fingerprint':{'kind':'smart_contract','code_hash':'0x'+char*64,'status':'CONFIRMED'}}) for char in 'abb']
        d=correlate_attribution(r,dataset_records=[entry(address=A,contract_metadata={'published_code_hash':'0x'+'b'*64})])
        contract=d['addresses']['eth:'+A]['contract']
        self.assertEqual(contract['status'],'POSSIBLE')
        self.assertEqual(contract['manifest_code_match']['status'],'POSSIBLE')
        self.assertTrue(contract['manifest_code_match']['runtime_observation_conflict'])
    def test_ton_history_visible_in_existing_contract_facts_with_sample_limit(self):
        address='0:'+'1'*64
        r=AddressReport(target_address=address,detected_chains=['ton'],ton_service_intelligence={
            'relationship_analysis':{'operations':[{'opcode':'0x00000000'}]*70,'contract_history':[],
                'traces':[],'coverage':{'status':'PARTIAL','history_complete':False}}})
        d=correlate_attribution(r,dataset_records=[])
        history=d['addresses']['ton:'+address]['contract']['historical_analysis']
        self.assertEqual(history['operations']['available'],70)
        self.assertEqual(len(history['operations']['observations']),50)
        self.assertEqual(len(d['ton_relationship_analysis']['operations']),70)
    def test_official_publication_only_confirms_exact_named_relation(self):
        data=correlate_attribution(report(),dataset_records=[entry(authority='official_operator_publication',relationship='official_published_address')])
        claim=data['addresses']['eth:'+B]['attributions'][0]
        self.assertEqual(claim['status'],'CONFIRMED');self.assertEqual(claim['relationship'],'official_published_address')
        self.assertEqual(data['addresses']['eth:'+B]['client_attribution']['status'],'UNKNOWN')
    def test_repeated_routes_cannot_elevate_weak_service_label(self):
        r=report();r.transactions.append(r.transactions[0].model_copy(update={'tx_hash':'b'*64}))
        r.labels=[Label(chain='eth',address=B,label='Scam Tonkeeper support',source='fixture',confidence=0.5,raw={'url':'https://example.com/label'})]
        d=correlate_attribution(r,dataset_records=[])
        self.assertEqual(d['relationships'][0]['status'],'POSSIBLE')
        self.assertTrue(all(c['service_id']!='tonkeeper' for c in d['addresses']['eth:'+B]['attributions']))
    def test_failed_operations_do_not_form_service_routes(self):
        r=report();r.transactions[0].success=False
        d=correlate_attribution(r,dataset_records=[entry()])
        self.assertEqual(d['relationships'],[]);self.assertEqual(len(d['transactions']),1)
    def test_utxo_participants_do_not_create_arbitrary_pairs_or_common_owner(self):
        r=AddressReport(target_address=BTC_A,detected_chains=['btc'],transactions=[Transaction(chain='btc',tx_hash='a'*64,
            inputs=[{'address':BTC_A},{'address':BTC_B}],outputs=[{'address':BTC_B}],source='fixture',asset='BTC')])
        d=correlate_attribution(r,dataset_records=[entry('btc',BTC_B)])
        self.assertEqual(d['transactions'][0]['from_key'],None)
        self.assertEqual(len(d['transactions'][0]['sender_service_keys']),2)
        self.assertEqual(d['relationships'][0]['type'],'co_input_participation')
        self.assertEqual(d['relationships'][0]['status'],'POSSIBLE')
        self.assertFalse(any(r['type']=='direct_transfer' for r in d['relationships']))
    def test_solana_program_owner_is_not_person_or_signing_app(self):
        r=AddressReport(target_address=TOKEN,detected_chains=['solana'],solana={'account':{'owner_program':SOL,'executable':True}})
        d=correlate_attribution(r,dataset_records=[])
        self.assertEqual(d['relationships'][0]['type'],'program_owned_by')
        self.assertEqual(d['addresses']['solana:'+TOKEN]['client_attribution']['status'],'UNKNOWN')
    def test_proxy_bytecode_graph_has_explicit_technical_relation(self):
        fp=evm_code_fingerprint('0x363d3d373d3d3d363d73'+B[2:]+'5af43d82803e903d91602b57fd5bf3')
        r=report();r.balances=[Balance(chain='eth',address=A,asset='ETH',amount=0,source='rpc',raw={'contract_fingerprint':fp,'rpc':'https://example.com/rpc'})]
        d=correlate_attribution(r,dataset_records=[]);graph=build_graph_payload(r)
        self.assertTrue(any(x['type']=='proxy_implementation' for x in d['relationships']))
        self.assertTrue(any(x.get('relationship_type')=='proxy_implementation' for x in graph['edges']))
    def test_eip7702_delegation_is_not_proxy_or_wallet_app(self):
        r=report();r.balances=[Balance(chain='eth',address=A,asset='ETH',amount=0,source='rpc',
            raw={'contract_fingerprint':evm_code_fingerprint('0xef0100'+B[2:])})]
        d=correlate_attribution(r,dataset_records=[])
        self.assertEqual(d['relationships'][0]['type'],'delegation_target')
        self.assertEqual(d['addresses']['eth:'+A]['client_attribution']['status'],'UNKNOWN')
        self.assertTrue(any(v.get('relationship_type')=='delegation_target' for v in build_graph_payload(r)['edges']))
    def test_record_caps_are_explicit(self):
        d=correlate_attribution(report(),dataset_records=[],max_transactions=0)
        self.assertFalse(d['coverage']['history_complete']);self.assertEqual(d['coverage']['transactions_correlated'],0)
        self.assertEqual(d['coverage']['status'],'TRUNCATED')
        d=correlate_attribution(report(),dataset_records=[],max_addresses=1)
        self.assertEqual(d['coverage']['status'],'TRUNCATED')
