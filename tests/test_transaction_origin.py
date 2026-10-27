import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from app.models.report import AddressReport, Transaction
from app.attribution.engine import correlate_attribution
from app.attribution.transaction_origin import attach_transaction_origins
from app.attribution.transaction_origin import _ton_findings
from app.exporters.html_exporter import _attribution_views, _transaction_views, render_html_report
from app.graph.builder import build_graph_payload

A='0x'+'1'*40; B='0x'+'2'*40

def report():
    return AddressReport(target_address=B,detected_chains=['eth'],transactions=[Transaction(
        chain='eth',tx_hash='0x'+'a'*64,from_address=A,to_address=B,asset='ETH',source='fixture',
        success=True,url='https://etherscan.io/tx/0x'+'a'*64)])

def label(chain='eth',address=A,name='Service'):
    return {'blockchain':chain,'address':address,'entity_id':name.lower(),'entity_name':name,
        'entity_type':'exchange_infrastructure','source':'fixture','source_url':'https://example.org/public-addresses',
        'authority':'official_operator_publication','relationship':'official_published_address'}

class TransactionOrigin(unittest.TestCase):
    def test_published_dogecoin_p2sh_prefix_nine_is_supported(self):
        from app.attribution.normalize import canonical_address
        from app.attribution.fingerprints import utxo_address_type
        address='9xEP9voiNLw7Y7DS87M8QRqKM43r6r5KM5'
        self.assertEqual(canonical_address('doge',address),address)
        self.assertEqual(utxo_address_type('doge',address),'p2sh_address')
    def test_resource_classification_requires_matching_native_hash(self):
        r=AddressReport(target_address='TJRabPrwbZy45sbavfcjinPJC18kjpRTv8',detected_chains=['tron'],transactions=[
            Transaction(chain='tron',tx_hash='a'*64,from_address='TJRabPrwbZy45sbavfcjinPJC18kjpRTv8',
            to_address='TJRabPrwbZy45sbavfcjinPJC18kjpRTv8',amount=10,source='fixture',raw={'type':'transfer',
            'provider_record':{'txID':'b'*64,'raw_data':{'contract':[{'type':'DelegateResourceContract'}]}}})])
        d=correlate_attribution(r,dataset_records=[])
        self.assertNotEqual(next(iter(d['transaction_origins'].values()))['movement_scope'],'non_monetary_or_allowance')
    def test_richer_receipt_projection_is_not_hidden_by_empty_first_row(self):
        r=report();r.transactions.append(r.transactions[0].model_copy(deep=True,update={'asset':'USDT','raw':{'log_index':1,'receipt':{'transactionHash':r.transactions[0].tx_hash,'status':'0x1','logs':[]}}}))
        d=correlate_attribution(r,dataset_records=[])
        self.assertEqual(len(d['transaction_fingerprints']),2)
    def test_ton_message_hash_fallback_and_mismatch_cannot_copy_marker(self):
        tx=Transaction(chain='ton',tx_hash='a'*64,source='fixture',raw={'message_hash':'b'*64})
        client={'observations':[{'transaction_hash':'a'*64,'message_hash':'c'*64,'observation_id':'native-proof'}],
            'investigative_leads':[{'evidence_ids':['native-proof']}]}
        payload={'target_key':'ton:target','addresses':{'ton:target':{'client_attribution':client}}}
        self.assertFalse(_ton_findings(tx,payload)['investigative_leads'])
        tx.raw['message_hash']='c'*64;before=copy.deepcopy(payload)
        self.assertEqual(len(_ton_findings(tx,payload)['investigative_leads']),1)
        self.assertEqual(payload,before)
    def test_direct_service_separate_from_application(self):
        r=report();d=correlate_attribution(r,dataset_records=[label()]);origin=next(iter(d['transaction_origins'].values()))
        observation=origin['originating_service']['observations'][0]
        self.assertEqual(observation['service_name'],'Service');self.assertEqual(observation['status'],'CONFIRMED')
        self.assertFalse(observation['physical_controller_known']);self.assertEqual(origin['wallet_application']['status'],'UNKNOWN')
    def test_recipient_service_is_not_source(self):
        d=correlate_attribution(report(),dataset_records=[label(address=B)])
        origin=next(iter(d['transaction_origins'].values()))
        self.assertEqual(origin['originating_service']['status'],'UNKNOWN');self.assertTrue(origin['recipient_services'])
    def test_conflicting_source_does_not_select_winner(self):
        d=correlate_attribution(report(),dataset_records=[label(),label(name='Other')])
        self.assertEqual(next(iter(d['transaction_origins'].values()))['originating_service']['status'],'CONFLICTING')
    def test_network_and_operation_identities_are_preserved(self):
        r=report();r.transactions.append(r.transactions[0].model_copy(update={'chain':'bsc'}))
        r.transactions.append(r.transactions[0].model_copy(update={'asset':'USDT','raw':{'log_index':4}}))
        d=correlate_attribution(r,dataset_records=[label()]);self.assertEqual(len(d['transaction_origins']),3)
        bsc=next(row for row in d['transaction_origins'].values() if row['blockchain']=='bsc')
        self.assertEqual(bsc['originating_service']['status'],'UNKNOWN')
    def test_details_use_reference_not_duplicate_payload(self):
        r=report();correlate_attribution(r,dataset_records=[]);views=_attribution_views(r);tx=_transaction_views(r,'ru',views)[0]
        self.assertIn(tx['transaction_origin_ref'],views['transaction_origins']);self.assertNotIn('transaction_fingerprints',tx)
    def test_optional_detector_failure_visible_and_raw_preserved(self):
        r=report();snapshot=copy.deepcopy(r.transactions[0].raw)
        with patch('app.attribution.transaction_origin.analyze_evm_transaction',side_effect=ValueError('invalid')):
            d=correlate_attribution(r,dataset_records=[])
        self.assertEqual(len(d['transaction_origins']),1);self.assertTrue(d['transaction_origin_coverage']['errors'])
        self.assertEqual(r.transactions[0].raw,snapshot)
    def test_budget_is_explicit_and_does_not_discard_transactions(self):
        r=report();d=correlate_attribution(r,dataset_records=[])
        attach_transaction_origins(r,d,max_operations=0)
        self.assertEqual(d['transaction_origin_coverage']['status'],'TRUNCATED');self.assertEqual(len(r.transactions),1)
    def test_voluntary_session_requires_consent_hash_and_sender_binding(self):
        r=report();session={'blockchain':'eth','address':A,'transaction_hash':r.transactions[0].tx_hash,
            'application_id':'claimed-app','protocol':'walletconnect','observer':'test','observed_at':'2026-10-20',
            'artifact_sha256':'b'*64,'consent':True,'observer_verified':True}
        d=correlate_attribution(r,dataset_records=[],session_observations=[session,{**session,'consent':False},{**session,'address':B}])
        origin=next(iter(d['transaction_origins'].values()));observation=origin['off_chain_observations'][0]
        self.assertFalse(observation['application_binary_authenticated']);self.assertEqual(origin['wallet_application']['status'],'UNKNOWN')
        self.assertEqual(d['transaction_origin_coverage']['voluntary_session_observations_rejected'],2)
    def test_html_reuses_original_template_and_safe_source_links(self):
        r=report();correlate_attribution(r,dataset_records=[label()])
        with tempfile.TemporaryDirectory() as tmp:html=render_html_report(r,build_graph_payload(r),Path(tmp))
        self.assertIn('TRANSACTION ORIGIN INTELLIGENCE',html);self.assertIn('transaction_origin_ref',html)
        self.assertIn('data-transaction-origin-ref="eth:event:',html)
        self.assertIn('signing application UNKNOWN',html);self.assertNotIn('href="javascript:',html)
