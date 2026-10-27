"""Contract tests for the production inference adapter, not live-source claims."""
from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal
import unittest

from app.models.report import AddressReport, Transaction, Balance
from app.attribution.engine import correlate_attribution
from app.attribution.inference import build_inference_data, context_for, _dependency_score

A='0:'+'1'*64
B='0:'+'2'*64
C='0:'+'3'*64
STAMP=datetime(2026,10,20,tzinfo=timezone.utc)

def report(*txs):
    return AddressReport(target_address=A,detected_chains=['ton'],transactions=list(txs))

class InferenceIntegrationTests(unittest.TestCase):
    def test_native_ton_varuint_amount_remains_exact_beyond_default_decimal_precision(self):
        amount=2**120-1
        native={'account':A,'out_msgs':[{'hash':'b'*64,'source':A,'destination':B,'value':str(amount)}],'success':True}
        data=build_inference_data(report(Transaction(chain='ton',tx_hash='a'*64,source='capture',raw={'transaction':native})),{})
        from decimal import localcontext
        with localcontext() as ctx:
            ctx.prec=100
            self.assertEqual(Decimal(data['operations'][0]['amount_decimal'])*10**9,Decimal(amount))

    def test_native_evm_provider_integer_and_explicit_execution_status_are_retained(self):
        a,b='0x'+'1'*40,'0x'+'2'*40
        tx=Transaction(chain='eth',tx_hash='0x'+'a'*64,source='etherscan_api',from_address=a,to_address=b,
            asset='ETH',amount=0.000000000000000001,raw={'provider_record':{
                'hash':'0x'+'a'*64,'isError':'0','value':'1'}})
        data=build_inference_data(AddressReport(target_address=a,detected_chains=['eth'],transactions=[tx]),{})
        self.assertEqual(Decimal(data['operations'][0]['amount_decimal']),Decimal('1e-18'))
        self.assertEqual(data['operations'][0]['amount_precision'],'native_base_units')
        self.assertTrue(data['operations'][0]['success'])

    def test_nft_ids_are_distinct_assets_instead_of_fungible_symbol_merge(self):
        txs=[Transaction(chain='eth',tx_hash='0x'+f'{i:064x}',source='capture',from_address='0x'+'1'*40,to_address='0x'+'2'*40,
            asset='SAME',amount_base_units=1,decimals=0,raw={'asset_type':'erc721','token_contract':'0x'+'3'*40,'token_id':str(i)}) for i in (1,2)]
        data=build_inference_data(AddressReport(target_address=txs[0].from_address,detected_chains=['eth'],transactions=txs),{})
        self.assertEqual(len({r['asset_key'] for r in data['operations']}),2)

    def test_scoped_context_round_trips_existing_sqlite_owner_snapshot(self):
        import tempfile
        from pathlib import Path
        from app.ton_nft.storage import InvestigationStore
        from app.ton_nft.models import NFTIntelligenceReport
        value=report();context=context_for(value)
        context['frontier']=[{'address_key':'ton:'+B,'state':'partial'}]
        context['histories']['ton:'+B]={'report':AddressReport(target_address=B,detected_chains=['ton']).model_dump(mode='json')}
        value.attribution_intelligence={'investigation_context':context}
        snapshot=NFTIntelligenceReport(investigation_id='inference-context-regression',query=A,mode='deep',scope='wallet',owner_analysis_snapshot=value.model_dump(mode='json'))
        with tempfile.TemporaryDirectory() as directory:
            store=InvestigationStore(Path(directory)/'snapshot.sqlite3')
            try:
                store.save_snapshot(snapshot)
                restored=store.load_snapshot(snapshot.investigation_id).owner_analysis_snapshot
                self.assertEqual(restored['attribution_intelligence']['investigation_context'],context)
            finally:store.close()
    def test_native_and_outgoing_projection_are_one_physical_message_in_either_order(self):
        message={'hash':'b'*64,'source':A,'destination':B,'value':'1234567890'}
        parent=Transaction(chain='ton',tx_hash='a'*64,source='capture',from_address=A,to_address=B,
            timestamp=STAMP,asset='TON',amount=1.23456789,
            raw={'transaction':{'account':A,'utime':int(STAMP.timestamp()),'success':True,'out_msgs':[message]}})
        projection=parent.model_copy(deep=True)
        projection.raw={'provider':'tonapi_out_msg','message':message}
        for rows in [(parent,projection),(projection,parent)]:
            data=build_inference_data(report(*rows),{})
            self.assertEqual(len(data['operations']),1)
            self.assertEqual(data['operations'][0]['amount_decimal'],'1.23456789')
            self.assertTrue(data['operations'][0]['success'])
            self.assertEqual(data['operations'][0]['operation_id'],'ton:message:'+'b'*64)

    def test_trc10_cannot_be_interpreted_as_trx_from_collector_display_symbol(self):
        tx=Transaction(chain='tron',tx_hash='a'*64,source='capture',asset='TRX',amount=42,
            raw={'provider_record':{'txID':'a'*64,'raw_data':{'contract':[{'type':'TransferAssetContract'}]}}})
        data=build_inference_data(AddressReport(target_address='TQ86CG22555c2xDZvQHLNGevh7fdQwNGdq',detected_chains=['tron'],transactions=[tx]),{})
        self.assertFalse(data['operations'])

    def test_native_symbol_token_without_contract_is_not_native_asset(self):
        tx=Transaction(chain='eth',tx_hash='0x'+'a'*64,source='capture',asset='ETH',amount=2,
            from_address='0x'+'1'*40,to_address='0x'+'2'*40,raw={'token_info':{'symbol':'ETH'}})
        data=build_inference_data(AddressReport(target_address=tx.from_address,detected_chains=['eth'],transactions=[tx]),{})
        self.assertFalse(data['operations'])

    def test_real_tronscan_native_contract_shape_is_trx_despite_trc10_metadata(self):
        a,b='TVzBq6oXa1GGiJCMxGyxNvrSQGLFwCUHsw','TG2xGS8nVxmx6hk2bx54xUzKkQE4h5jr3w'
        tx=Transaction(chain='tron',tx_hash='a'*64,source='tronscan',from_address=a,to_address=b,asset='TRX',amount=1500,
            raw={'native_contract_type':'TransferContract','token_info':{'tokenId':'_','tokenType':'trc10'},
                'provider_record':{'hash':'a'*64,'contractType':1,'contractData':{'amount':1500000000}}})
        data=build_inference_data(AddressReport(target_address=a,detected_chains=['tron'],transactions=[tx]),{})
        self.assertEqual(data['operations'][0]['asset_key'],'tron:native')
        self.assertEqual(data['operations'][0]['amount_decimal'],'1500')
        self.assertEqual(data['operations'][0]['amount_precision'],'native_base_units')

    def test_dependency_alias_is_one_observation(self):
        assessment=_dependency_score({'confidence':'POSSIBLE','evidence_ids':['proof'],
            'dependency_groups':['ton:physical_tx:a']},{'proof':'ton:tx:a'},{})
        self.assertEqual(assessment['independent_physical_observation_groups'],1)
        self.assertEqual(assessment['category'],'WEAK_LEAD')

    def test_neighbor_context_is_scoped_and_target_financials_are_unchanged(self):
        target=report(Transaction(chain='ton',tx_hash='a'*64,source='capture',from_address=A,to_address=B,
            amount_decimal=Decimal(1),asset='TON',timestamp=STAMP,success=True))
        target.balances=[Balance(chain='ton',address=A,asset='TON',amount=5,source='capture')]
        neighbor=AddressReport(target_address=B,detected_chains=['ton'],transactions=[
            Transaction(chain='ton',tx_hash='b'*64,source='capture',from_address=B,to_address=C,
                amount_decimal=Decimal(1),asset='TON',timestamp=STAMP,success=True)])
        context=context_for(target);context['histories']['ton:'+B]={'report':neighbor.model_dump(mode='json')}
        target.attribution_intelligence={'investigation_context':context}
        before=deepcopy((target.balances,target.transactions))
        payload=correlate_attribution(target,dataset_records=[])
        self.assertEqual((target.balances,target.transactions),before)
        self.assertEqual(payload['inferential_intelligence']['coverage']['scoped_neighbor_histories'],1)
        self.assertEqual(payload['inferential_intelligence']['coverage']['operations'],2)
        self.assertEqual(payload['investigation_context']['histories']['ton:'+B]['report']['target_address'],B)

    def test_context_survives_chain_order_and_wrong_neighbor_binding_is_rejected(self):
        value=AddressReport(target_address='0x'+'1'*40,detected_chains=['polygon','eth'])
        ctx=context_for(value);ctx['sessions']=4
        value.attribution_intelligence={'investigation_context':ctx}
        value.detected_chains.reverse()
        self.assertEqual(context_for(value)['sessions'],4)
        ctx['histories']['ton:'+B]={'report':report().model_dump(mode='json')}
        self.assertEqual(build_inference_data(value,{})['coverage']['scoped_neighbor_histories'],0)

    def test_malformed_raw_optional_shapes_do_not_crash_main_analysis(self):
        for chain,raw in [('btc',{'provider_record':['bad']}),('btc',{'provider_record':{'transaction':'bad'}}),
                ('solana',{'provider_record':{'transaction':{'signatures':[]}}})]:
            target=AddressReport(target_address='bad',detected_chains=[chain],transactions=[
                Transaction(chain=chain,tx_hash='bad',source='capture',raw=raw)])
            data=build_inference_data(target,{})
            self.assertFalse(data['operations'])

    def test_explicit_no_inference_neighbor_mode_has_no_recursive_context(self):
        value=report()
        payload=correlate_attribution(value,dataset_records=[],include_inference=False)
        self.assertNotIn('inferential_intelligence',payload)

    def test_retained_native_raw_resolves_from_normalized_evidence_without_financial_merge(self):
        message={'hash':'b'*64,'source':A,'destination':B,'value':'42'}
        native={'account':A,'out_msgs':[message],'success':True,'utime':int(STAMP.timestamp()),'public_marker':'kept'}
        value=report(Transaction(chain='ton',tx_hash='a'*64,source='capture',raw={'transaction':native}))
        payload=correlate_attribution(value,dataset_records=[])
        proof=next(p for p in payload['evidence'] if p.get('relation')=='inference_operation_observation')
        key=proof['facts']['raw_reference']['source_observation_id']
        self.assertEqual(payload['source_observations'][key]['raw']['transaction'],native)

if __name__=='__main__':unittest.main()
