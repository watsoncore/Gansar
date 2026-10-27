"""Synthetic protocol layouts explicitly test observations, never live claims."""
import base64,copy,unittest
from datetime import datetime,timezone
from app.models.report import AddressReport,Transaction
from app.attribution.engine import correlate_attribution
from app.attribution.wallet_application import analyze_wallet_applications,TG_HASH,application_catalogue
from app.attribution.wallet_payload import decode_wallet_body,decode_token_header

A='0:'+'1'*64;B='0:'+'2'*64
def boc(bits,refs=0,ref_bits=None):
    # Non-byte aligned top-up bit per TON BOC; optional empty ref cells.
    n=len(bits);top=bits+('1' if n%8 else '')
    top+='0'*((-len(top))%8);data=int(top or '0',2).to_bytes(len(top)//8,'big')
    cell=bytes([refs,n//8+(n+7)//8])+data+bytes(range(1,refs+1));empty=b'\x00\x00'*refs
    if ref_bits is not None:
        assert refs==1 and len(ref_bits)%8==0
        empty=bytes([0,len(ref_bits)//4])+int(ref_bits,2).to_bytes(len(ref_bits)//8,'big')
    size=len(cell+empty)
    blob=bytes.fromhex('b5ee9c72')+bytes([1,2,refs+1,1,0])+size.to_bytes(2,'big')+bytes([0])+cell+empty
    return base64.b64encode(blob).decode()
def u(value,width):return f'{value:0{width}b}'
def token(query=(0x546de4ef<<32)|123):return boc(u(0x5fcc3d14,32)+u(query,64))
def tonreport(version='V4R2',code_hash=None,status='active'):
    return AddressReport(target_address=A,detected_chains=['ton'],ton_service_intelligence={'addresses':{A:{'address':A,
       'account_status':status,'account_type':'wallet_contract','contract':{'kind':'standard_wallet','wallet_version':version,
       'code_hash':code_hash,'evidence_ids':[]},'attributions':[],'conflicts':[],'evidence_ids':[]}},'evidence':[]})
def tx(body=None,source=A,destination=B,hash='a'*64,kind='int_msg'):
    return Transaction(chain='ton',tx_hash=hash,from_address=source,to_address=destination,source='synthetic_protocol',success=True,
       timestamp=datetime(2026,10,16,tzinfo=timezone.utc),url='https://example.org/tx/'+hash,
       raw={'message_index':0,'message':{'hash':hash,'source':source,'destination':destination,'raw_body':body or token(),'msg_type':kind}})

class PayloadLayouts(unittest.TestCase):
    def test_v3_and_v4_layouts_extract_modes_without_inferring_app(self):
        header='0'*512+u(698983191,32)+u(1800000000,32)+u(7,32)
        for version,extra in [('V3R2',''),('V4R2',u(0,8))]:
            result=decode_wallet_body(boc(header+extra+u(3,8),1),version)
            self.assertEqual(result['wallet_id'],698983191);self.assertEqual(result['seqno'],7)
            self.assertEqual(result['send_modes'],[3]);self.assertFalse(result['signature_verified'])
            self.assertNotIn('application',result)
    def test_v5_authorization_and_tail_signature(self):
        raw=u(0x7369676e,32)+u(0x7fffff11,32)+u(1800000000,32)+u(4,32)+'00'+'0'*512
        data=decode_wallet_body(boc(raw),'V5R1')
        self.assertEqual(data['authorization'],'external_signed');self.assertEqual(data['seqno'],4)
        self.assertEqual(data['message_count'],0)
        with self.assertRaises(ValueError):decode_wallet_body(boc(raw[:-512]),'V5R1')
    def test_v5_extension_query_is_not_signature_or_signer(self):
        data=decode_wallet_body(boc(u(0x6578746e,32)+u(42,64)+'00'),'V5R1')
        self.assertEqual(data['query_id'],'42');self.assertEqual(data['authorization'],'extension_authorized')
    def test_wallet_tg_layout_and_key_rotation(self):
        raw='0'*512+u(0xfbba99c8,32)+u(0x7fff7f11,32)+u(1800000000,32)+u(7,32)+'0'*256
        result=decode_wallet_body(boc(raw),'WalletTg')
        self.assertEqual(result['authorization'],'external_key_rotation');self.assertEqual(result['config_indirection'],-123)
    def test_untrusted_or_truncated_body_is_rejected(self):
        with self.assertRaises(ValueError):decode_wallet_body(boc('0'*90),'V4R2')
        with self.assertRaises(ValueError):decode_wallet_body(boc('0'*608+u(3,8)),'V3R2')
        with self.assertRaises(ValueError):decode_wallet_body('not base64','V5R1')
    def test_token_query_namespace_is_a_copyable_field(self):
        data=decode_token_header(token());self.assertTrue(data['tonkeeper_query_namespace'])
        self.assertFalse(decode_token_header(token(123))['tonkeeper_query_namespace'])

class ApplicationChecks(unittest.TestCase):
    def test_same_v5_contract_never_becomes_tonkeeper(self):
        for version in ['V3R1','V4R2','V5R1']:
            r=tonreport(version);data=correlate_attribution(r,dataset_records=[]);app=data['addresses']['ton:'+A]['client_attribution']
            self.assertEqual(app['status'],'UNKNOWN');self.assertIsNone(app['name']);self.assertFalse(app['candidates'])
            self.assertTrue(app['checks']);self.assertTrue(app['rejected_hypotheses'])
    def test_target_originated_namespace_creates_hypothesis_only(self):
        r=tonreport();r.transactions=[tx()];app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+A]['client_attribution']
        self.assertEqual(app['status'],'UNKNOWN');self.assertEqual(app['candidates'][0]['status'],'POSSIBLE')
        self.assertFalse(app['candidates'][0]['signing_application_confirmed'])
        self.assertIn('dApp',app['candidates'][0]['alternatives'][0])
    def test_incoming_payload_does_not_fingerprint_recipient(self):
        r=tonreport();r.transactions=[tx(source=B,destination=A)]
        app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+A]['client_attribution'];self.assertFalse(app['candidates'])
    def test_failed_and_emulated_payloads_do_not_create_app_hypothesis(self):
        for field in ('failed','emulated'):
            r=tonreport();r.transactions=[tx()]
            if field=='failed':r.transactions[0].success=False
            else:r.transactions[0].raw['emulated']=True
            app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+A]['client_attribution']
            self.assertFalse(app['candidates']);self.assertEqual(len(app['observations']),1)
    def test_echoed_notification_query_cannot_fingerprint_forwarder(self):
        r=tonreport();r.transactions=[tx(boc(u(0x7362d09c,32)+u((0x546de4ef<<32)|12,64)))]
        app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+A]['client_attribution']
        self.assertFalse(app['candidates']);self.assertTrue(app['observations'][0]['fields']['tonkeeper_query_namespace'])
    def test_contract_without_wallet_context_is_not_a_signing_app(self):
        r=tonreport(None);r.ton_service_intelligence['addresses'][A]['account_type']='smart_contract';r.transactions=[tx()]
        app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+A]['client_attribution']
        self.assertFalse(app['candidates'])
    def test_full_application_details_are_serialized_once_in_address_record(self):
        r=tonreport();r.transactions=[tx()];data=correlate_attribution(r,dataset_records=[])
        self.assertNotIn('wallet_application',data['addresses']['ton:'+A])
        self.assertNotIn('observations',data['wallet_application'])
        self.assertEqual(data['wallet_application']['detail_ref'],{'address_key':'ton:'+A,'field':'client_attribution'})
    def test_declarative_new_app_rule_is_extensible_but_cannot_elevate_confidence(self):
        r=tonreport();r.transactions=[tx(token((0xabcdef01<<32)|123))];data=correlate_attribution(r,dataset_records=[])
        custom={'entities':[{'entity_id':'new_app','brand':'New App'}],'construction_rules':[{'rule_id':'new-rule','entity_id':'new_app',
           'kind':'query_id_prefix','value':'0xabcdef01','source_urls':['https://example.org/official-spec'],'confidence_ceiling':'CONFIRMED'}]}
        app=analyze_wallet_applications(r,data,indicator_catalogue=custom)
        self.assertEqual(app['candidates'][0]['application_id'],'new_app')
        self.assertEqual(app['candidates'][0]['status'],'POSSIBLE');self.assertEqual(app['status'],'UNKNOWN')
    def test_mywallet_exact_fee_cell_is_observed_not_a_signer_identity(self):
        r=tonreport();r.transactions=[tx(boc(u(0x0f8a7ea5,32)+u(0,64),1,u(0x4d238543,32)))]
        app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+A]['client_attribution']
        self.assertEqual(app['candidates'][0]['application_id'],'mytonwallet')
        self.assertEqual(app['status'],'UNKNOWN');self.assertTrue(app['observations'][0]['fields']['mywallet_fee_payload_present'])
    def test_shared_nft_native_reference_is_read_without_expanding_projected_raw(self):
        r=tonreport();item=tx();native_message=item.raw['message'];item.raw={'nft_intelligence':{'raw_reference':{'collection':'events','id':'nft-event'}}};r.transactions=[item]
        r.nft_intelligence={'events':[{'event_id':'nft-event','raw':{'transaction_details':{'hash':item.tx_hash,'account':B,'in_msg':native_message}}}]}
        before=copy.deepcopy(item.raw);app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+A]['client_attribution']
        self.assertEqual(len(app['candidates']),1);self.assertEqual(app['coverage']['shared_nft_native_references_resolved'],1)
        self.assertEqual(item.raw,before);self.assertNotIn('transaction_details',str(item.raw))
    def test_mismatched_shared_nft_native_hash_cannot_produce_marker(self):
        r=tonreport();item=tx();native_message=item.raw['message'];item.raw={'original_reference':{'collection':'events','id':'nft-event'}};r.transactions=[item]
        r.nft_intelligence={'events':[{'event_id':'nft-event','raw':{'transaction_details':{'hash':'b'*64,'account':B,'in_msg':native_message}}}]}
        app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+A]['client_attribution']
        self.assertFalse(app['candidates']);self.assertEqual(app['coverage']['shared_nft_native_reference_hash_mismatch'],1)
    def test_physical_message_duplicates_are_not_independent_confirmations(self):
        r=tonreport();r.transactions=[tx(),tx()];r.transactions[1].source='other_provider'
        app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+A]['client_attribution']
        self.assertEqual(len(app['candidates'][0]['evidence_ids']),1)
        self.assertEqual(app['coverage']['independent_application_confirmations'],0)
        self.assertEqual(app['coverage']['duplicate_message_observations'],1)
    def test_base64_and_hex_message_hashes_are_one_physical_observation(self):
        r=tonreport();r.transactions=[tx(),tx()];r.transactions[1].source='second_provider'
        r.transactions[1].raw['message']['hash']=base64.b64encode(bytes.fromhex('a'*64)).decode()
        app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+A]['client_attribution']
        self.assertEqual(len(app['candidates'][0]['evidence_ids']),1)
    def test_transaction_time_is_not_invented_as_source_observation_time(self):
        r=tonreport();r.transactions=[tx()]
        app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+A]['client_attribution']
        row=app['observations'][0]
        self.assertIsNone(row['observed_at']);self.assertTrue(row['transaction_timestamp']);self.assertTrue(row['analysis_performed_at'])
    def test_public_auth_mode_survives_secret_header_sanitizer(self):
        raw=u(0x7369676e,32)+u(0x7fffff11,32)+u(1800000000,32)+u(4,32)+'00'+'0'*512
        r=tonreport('V5R1');r.transactions=[tx(boc(raw),source=None,destination=A,kind='ext_in_msg')]
        r.transactions[0].raw['message_index']='in'
        app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+A]['client_attribution']
        fields=app['observations'][0]['fields']
        self.assertEqual(fields['auth_mode'],'external_signed')
        self.assertEqual(fields['authorization'],'[REDACTED]')
    def test_sealed_genuine_toncenter_boc_unknown_channel_is_not_internal(self):
        # Genuine prior HTTP response captured in an earlier live run; replay
        # here is explicitly a sealed unit regression, not a new live test.
        raw='te6cckEBBAEAlgABoXNpZ25///8RarJaPwAAACedHC1RDehc5j6l2LmtTSJ5pOBxa7Djo+80isFqksLKJ5CJn41rR6IEWgZmztoBZD54ZJgBAP0dEPUHxDV0n+4A4AECCg7DyG2CAgMAAABqQgAhZfv7WAlr8R8ruzrzeKrscvvd10EZjvCEzw/odgARNqgKbC28iAAAAAAAAAAAAAAAAAD/homh'
        r=tonreport('V5R1');r.transactions=[tx(raw,source=None,destination=A,hash='ae247f71487e4c1de2226e57bd5d8a3293239b985fe2f20027a3eb8d5dcb3984')]
        item=r.transactions[0];item.raw['message_index']='in';item.raw['message'].pop('msg_type');item.raw['message']['decoded_opcode']='w5_external_signed_request'
        app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+A]['client_attribution']
        fields=app['observations'][0]['fields'];self.assertEqual(fields['auth_mode'],'external_signed')
        self.assertEqual(fields['message_channel'],'UNKNOWN');self.assertFalse(fields['signature_verified'])
        self.assertEqual(fields['send_modes'],[130]);self.assertEqual(app['status'],'UNKNOWN')
    def test_explicit_internal_channel_rejects_external_authorization(self):
        raw=u(0x7369676e,32)+u(0x7fffff11,32)+u(1800000000,32)+u(4,32)+'00'+'0'*512
        r=tonreport('V5R1');r.transactions=[tx(boc(raw),source=B,destination=A,kind='int_msg')]
        r.transactions[0].raw['message_index']='in';app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+A]['client_attribution']
        self.assertFalse(any(o['kind']=='ton_wallet_request_layout' for o in app['observations']))
    def test_code_import_prevents_wallet_tg_signer_or_custody_claim(self):
        app=correlate_attribution(tonreport('WalletTg',TG_HASH),dataset_records=[])['addresses']['ton:'+A]['client_attribution']
        self.assertEqual(app['status'],'UNKNOWN')
        self.assertTrue(any(c['method']=='wallet_tg_trampoline' for c in app['checks']))
    def test_uninit_does_not_identify_custodial_deposit_derivation(self):
        app=correlate_attribution(tonreport(None,status='uninit'),dataset_records=[])['addresses']['ton:'+A]['client_attribution']
        self.assertEqual(app['status'],'UNKNOWN');self.assertTrue(app['unavailable_methods'])
    def test_raw_appname_is_not_a_user_verified_observation(self):
        r=tonreport();r.transactions=[tx()];r.transactions[0].raw['appName']='Tonkeeper'
        app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+A]['client_attribution']
        self.assertFalse(app['off_chain_observations']);self.assertIsNone(app['name'])
    def test_explicit_off_chain_evidence_is_separate_not_public_osint(self):
        r=tonreport();data=correlate_attribution(r,dataset_records=[])
        app=analyze_wallet_applications(r,data,user_verified_observations=[{'blockchain':'ton','address':A,'application_id':'tonkeeper',
           'observed_at':'2026-10-16T00:00:00Z','observer':'consenting investigator','artifact_sha256':'a'*64,'consent':True,'user_verified':True}])
        self.assertEqual(app['status'],'UNKNOWN');self.assertFalse(app['off_chain_observations'][0]['public_osint'])
        self.assertEqual(app['off_chain_observations'][0]['status'],'USER_VERIFIED')
    def test_limits_do_not_mutate_or_remove_transactions(self):
        r=tonreport();r.transactions=[tx(),tx(hash='b'*64)];before=copy.deepcopy(r.transactions)
        data=correlate_attribution(r,dataset_records=[]);app=analyze_wallet_applications(r,data,max_records=1)
        self.assertEqual(r.transactions,before);self.assertEqual(app['coverage']['status'],'TRUNCATED')
    def test_evm_contract_protocol_is_not_metamask(self):
        r=AddressReport(target_address='0x'+'1'*40,detected_chains=['eth']);app=correlate_attribution(r,dataset_records=[])['addresses']['eth:'+r.target_address]['client_attribution']
        self.assertEqual(app['status'],'UNKNOWN');self.assertTrue(any(c['method']=='erc4337_entrypoint_call_shape' for c in app['checks']))
    def test_catalogue_has_pinned_primary_sources_and_rights(self):
        rows=application_catalogue()['entities'];self.assertGreaterEqual(len(rows),12)
        for row in rows:
            self.assertIn('confidence_rules',row);self.assertIn('licence',row)
        keeper=next(r for r in rows if r['entity_id']=='tonkeeper')
        self.assertEqual(len(keeper['source_commit']),40);self.assertTrue(all('sha256'in s for s in keeper['evidence_sources']))

if __name__=='__main__':unittest.main()
