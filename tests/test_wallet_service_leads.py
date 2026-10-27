"""Synthetic negative controls for new leads; not live efficacy evidence."""
import copy
import unittest
from test_wallet_application import A,B,boc,u,tonreport,tx
from app.attribution.engine import correlate_attribution
from app.attribution.wallet_application import analyze_wallet_applications
from app.attribution.wallet_service_payload import BATTERY_RECEIVER,decode_battery_purchase

TK_HASH='c5ef19df22aee8b707bd7a181174e400a4225223c5ae40d8320f5ddd707d34a1'
MTW_HASH='14dbe27de307b26faf75361dc5429d1a14b5288f9a82ce08727513c02835e4f7'

def purchase():return boc(u(0xb7b2515f,32)+'00')
def native(body,*,source=A,destination=BATTERY_RECEIVER,account=A,direction='out',success=True):
    item=tx(body,source=source,destination=destination)
    message=item.raw['message'];item.success=success
    item.raw={'transaction':{'hash':item.tx_hash,'account':account,'success':success,
        'in_msg':message if direction=='in' else {},'out_msgs':[message] if direction=='out' else []}}
    return item
def application(report):return correlate_attribution(report,dataset_records=[])['addresses']['ton:'+A]['client_attribution']
def extension_record(digest):return {'address':B,'account_status':'active','account_type':'smart_contract',
    'contract':{'kind':'contract','code_hash':digest,'evidence_ids':[]},'attributions':[],'conflicts':[],'evidence_ids':[]}

class BatteryPayloadTests(unittest.TestCase):
    def test_exact_flags_gift_and_promo(self):
        plain=decode_battery_purchase(purchase())
        self.assertEqual(plain['body_bits'],34);self.assertFalse(plain['purchase_credit_verified'])
        gift=boc(u(0xb7b2515f,32)+'1'+'100'+u(0,8)+u(7,256)+'0')
        self.assertEqual(decode_battery_purchase(gift)['gift_recipient'],'0:'+f'{7:064x}')
        promo=boc(u(0xb7b2515f,32)+'01'+''.join(u(v,8) for v in b'promo'))
        self.assertEqual(decode_battery_purchase(promo)['promo_bytes'],5)
    def test_prefix_truncation_trailing_data_refs_and_invalid_utf8_rejected(self):
        for body in [boc(u(0xb7b2515f,32)),boc(u(0xb7b2515f,32)+'00'+'0'*8),
                     boc(u(0xb7b2515f,32)+'00',1),boc(u(0xb7b2515f,32)+'01'+u(255,8))]:
            with self.assertRaises(ValueError):decode_battery_purchase(body)
        self.assertIsNone(decode_battery_purchase(boc(u(17,32))))

class WalletServiceLeadTests(unittest.TestCase):
    def test_leads_render_in_original_static_and_inspector_views_with_safe_links(self):
        from test_wallet_application_presentation import fixture,render,payload
        lead={'status':'POSSIBLE','name':'</pre><script>alert(1)</script>',
            'source_urls':['https://example.com/lead','http://127.0.0.1/private']}
        html=render(fixture(client={'status':'UNKNOWN','investigative_leads':[lead]}));data=payload(html)
        client=data['services']['addresses']['ton:'+A]['client_attribution']
        self.assertEqual(client['investigative_leads'][0]['source_urls'],['https://example.com/lead'])
        self.assertIn('https://example.com/lead',data['public_urls'])
        self.assertIn('POSSIBLE / INVESTIGATIVE LEADS',html)
        self.assertIn('client.investigative_leads',html)
        self.assertNotIn('</pre><script>alert(1)</script>',html)
    def test_battery_origin_native_success_creates_separate_possible_lead(self):
        r=tonreport();r.transactions=[native(purchase())];before=copy.deepcopy(r.transactions)
        app=application(r)
        self.assertEqual(app['status'],'UNKNOWN');self.assertFalse(app['candidates'])
        self.assertEqual(app['investigative_leads'][0]['method'],'battery_purchase')
        self.assertEqual(app['investigative_leads'][0]['status'],'POSSIBLE')
        self.assertFalse(app['investigative_leads'][0]['signing_application_confirmed'])
        self.assertEqual(r.transactions,before)
    def test_wrong_receiver_incoming_failed_emulated_and_unknown_do_not_create_lead(self):
        for mode in ('wrong_receiver','incoming','failed','emulated','unknown'):
            r=tonreport();item=native(purchase())
            if mode=='wrong_receiver':item=native(purchase(),destination=B)
            if mode=='incoming':item=native(purchase(),source=B,destination=A,account=A,direction='in')
            if mode=='failed':item=native(purchase(),success=False)
            if mode=='unknown':item=native(purchase(),success=None)
            if mode=='emulated':item.raw['emulated']=True
            r.transactions=[item];self.assertFalse(application(r)['investigative_leads'],mode)
    def test_projected_message_without_native_account_does_not_prove_source_execution(self):
        r=tonreport();r.transactions=[tx(purchase(),destination=BATTERY_RECEIVER)]
        self.assertFalse(application(r)['investigative_leads'])
    def test_recipient_receipt_before_source_cannot_suppress_source_evidence(self):
        r=tonreport();receipt=native(purchase(),account=BATTERY_RECEIVER,direction='in')
        source=native(purchase());source.source='other_provider'
        r.transactions=[receipt,source]
        self.assertEqual(application(r)['investigative_leads'][0]['observed_messages'],1)
    def test_unavailable_first_copy_cannot_suppress_qualifying_native_success(self):
        for first in ('unknown','failed','emulated'):
            r=tonreport();item=native(purchase(),success=None if first=='unknown' else first!='failed')
            if first=='emulated':item.raw['emulated']=True
            good=native(purchase());good.source='other_provider';r.transactions=[item,good]
            self.assertEqual(application(r)['investigative_leads'][0]['observed_messages'],1,first)
    def test_provider_duplicates_do_not_multiply_service_evidence(self):
        r=tonreport();a=native(purchase());b=copy.deepcopy(a);b.source='other_provider'
        r.transactions=[a,b];self.assertEqual(application(r)['investigative_leads'][0]['observed_messages'],1)
    def test_notification_only_sample_does_not_claim_application_marker_was_checked(self):
        r=tonreport();r.transactions=[tx(boc(u(0x7362d09c,32)+u(12,64)))]
        app=application(r)
        checks=[v for v in app['checks'] if v['method'] in ('tonkeeper_query_id_namespace','mywallet_fee_payload_marker')]
        self.assertEqual(len(checks),2)
        self.assertTrue(all(v['status']=='unavailable' for v in checks))
    def test_2fa_requires_exact_available_sender_code_and_native_recipient(self):
        body=boc(u(0x6578746e,32)+u(42,64)+'00')
        for digest in (TK_HASH,MTW_HASH,'f'*64,None):
            r=tonreport('V5R1');r.ton_service_intelligence['addresses'][B]=extension_record(digest)
            r.transactions=[native(body,source=B,destination=A,account=A,direction='in')]
            app=application(r);leads=app['investigative_leads']
            if digest in (TK_HASH,MTW_HASH):
                self.assertEqual(leads[0]['scope'],'extension_request_origin')
                fields=next(o['fields'] for o in app['observations'] if o['kind']=='documented_wallet_extension_extension_request')
                self.assertFalse(fields['historical_extension_membership_verified'])
                self.assertEqual(fields['request_effect'],'not_verified')
            else:self.assertFalse(leads)
            self.assertEqual(app['status'],'UNKNOWN')
    def test_install_shape_must_match_available_receiver_implementation(self):
        for digest,bits,expected in ((MTW_HASH,32,True),(TK_HASH,32,False),(TK_HASH,544,True)):
            r=tonreport('V5R1');r.ton_service_intelligence['addresses'][B]=extension_record(digest)
            body=boc(u(0x43563174,32)+'0'*(bits-32));r.transactions=[native(body,destination=B)]
            self.assertEqual(bool(application(r)['investigative_leads']),expected)
    def test_observation_budget_never_leaves_dangling_service_proofs(self):
        r=tonreport();r.transactions=[native(purchase())];payload=correlate_attribution(r,dataset_records=[])
        app=analyze_wallet_applications(r,payload,max_observations=0)
        self.assertFalse(app['investigative_leads']);self.assertEqual(app['coverage']['marker_observations_omitted'],1)

if __name__=='__main__':unittest.main()
