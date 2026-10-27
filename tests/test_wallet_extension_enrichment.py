"""Synthetic transport tests of bounded collection; live results are separate."""
import asyncio
import unittest
from test_ton_attribution import ADDRESS,OTHER,clients,boc
from test_wallet_application import boc as bits_boc,u
from app.models.report import AddressReport,Transaction
from app.ton_attribution.service import enrich_ton_service_intelligence
from app.attribution.engine import correlate_attribution

LIBRARY='b5ee9c7201010101002300084202701eede652337f699550cc51cb15263259aae6fc6eba976237945f142dda982d'

def setup():
    message={'hash':'a'*64,'source':OTHER,'destination':ADDRESS,'msg_type':'int_msg',
        'raw_body':bits_boc(u(0x6578746e,32)+u(0,64)+'00')}
    r=AddressReport(target_address=ADDRESS,detected_chains=['ton'],transactions=[Transaction(chain='ton',tx_hash='b'*64,
        from_address=OTHER,to_address=ADDRESS,success=True,source='synthetic_transport',raw={'transaction':{
            'hash':'b'*64,'account':ADDRESS,'success':True,'in_msg':message,'out_msgs':[]}})])
    providers=clients();ta=providers['tonapi']
    ta.responses['/accounts/'+OTHER]={'address':OTHER,'status':'active','interfaces':[]}
    ta.responses['/blockchain/accounts/'+OTHER]={'address':OTHER,'status':'active','code':LIBRARY}
    initial={'address':ADDRESS,'descriptor':{'address':ADDRESS,'account_status':'active','account_type':'wallet_contract',
        'contract':{'kind':'standard_wallet','wallet_version':'V5R1','evidence_ids':[]},'attributions':[],'conflicts':[],'evidence_ids':[]},
        'stats':{'requests':0},'observations':[],'evidence':[],'errors':[]}
    return r,providers,initial

class WalletExtensionCollection(unittest.IsolatedAsyncioTestCase):
    async def test_direct_request_with_empty_interfaces_fetches_code_under_same_budget(self):
        r,providers,initial=setup()
        result=await enrich_ton_service_intelligence(r,deadline=asyncio.get_running_loop().time()+3,
            max_requests=2,providers=providers,initial_account=initial)
        self.assertEqual(result['coverage']['extension_code_queried'],1)
        self.assertEqual(len(providers['tonapi'].calls),2)
        self.assertEqual(result['addresses'][OTHER]['contract']['code_hash'],'14dbe27de307b26faf75361dc5429d1a14b5288f9a82ce08727513c02835e4f7')
        app=correlate_attribution(r,dataset_records=[])['addresses']['ton:'+ADDRESS]['client_attribution']
        self.assertEqual(app['investigative_leads'][0]['method'],'extension:mytonwallet_tg2fa')
        self.assertEqual(app['status'],'UNKNOWN')
    async def test_metadata_budget_exhaustion_never_adds_request_or_guesses_code(self):
        r,providers,initial=setup()
        result=await enrich_ton_service_intelligence(r,deadline=asyncio.get_running_loop().time()+3,
            max_requests=1,providers=providers,initial_account=initial)
        self.assertEqual(len(providers['tonapi'].calls),1)
        self.assertEqual(result['coverage']['extension_code_queried'],0)
        self.assertIsNone(result['addresses'][OTHER]['contract']['code_hash'])
        self.assertFalse(correlate_attribution(r,dataset_records=[])['addresses']['ton:'+ADDRESS]['client_attribution']['investigative_leads'])
    async def test_provider_interface_is_discovery_hint_and_wrong_code_never_identifies_family(self):
        r,providers,initial=setup()
        providers['tonapi'].responses['/accounts/'+OTHER]['interfaces']=['tonkeeper_2fa']
        providers['tonapi'].responses['/blockchain/accounts/'+OTHER]['code']=boc(b'arbitrary')
        result=await enrich_ton_service_intelligence(r,deadline=asyncio.get_running_loop().time()+3,
            max_requests=2,providers=providers,initial_account=initial)
        self.assertEqual(result['coverage']['extension_code_queried'],1)
        self.assertFalse(correlate_attribution(r,dataset_records=[])['addresses']['ton:'+ADDRESS]['client_attribution']['investigative_leads'])
    async def test_malformed_metadata_interfaces_do_not_crash_research(self):
        r,providers,initial=setup()
        providers['tonapi'].responses['/accounts/'+OTHER]['interfaces']=None
        result=await enrich_ton_service_intelligence(r,deadline=asyncio.get_running_loop().time()+3,
            max_requests=2,providers=providers,initial_account=initial)
        self.assertEqual(result['coverage']['extension_code_queried'],1)

if __name__=='__main__':unittest.main()
