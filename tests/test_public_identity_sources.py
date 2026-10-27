"""Replay real Lens/Base captures; no assertion that mocks are live checks."""
from copy import deepcopy
import json
from pathlib import Path
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock,patch

import httpx
from app.sources.basenames import BaseNamesSource
from app.sources.web3_identity import LensPublicSource

FIXTURE=json.loads((Path(__file__).parent/'fixtures/public_identity_capture.json').read_text())


class IdentitySourceTests(IsolatedAsyncioTestCase):
    async def lens(self,payload=None):
        capture=FIXTURE['lens'];payload=payload or capture['response']
        with patch('app.sources.web3_identity.public_json',new=AsyncMock(return_value=(deepcopy(payload),capture['transport']))),patch('app.sources.web3_identity._profile_thumbnail',new=AsyncMock(return_value=None)):
            return await LensPublicSource(2).fetch(capture['input'])

    async def test_lens_exact_controller_username_owner_and_virtual_account_are_separate(self):
        out=await self.lens();outcome=out.public_address_context['outcomes'][0]
        self.assertEqual(outcome['status'],'ok');self.assertEqual(len(outcome['claims']),1)
        claim=outcome['claims'][0];value=claim['value']
        self.assertEqual(claim['claim_status'],'provider_reported_account_role')
        self.assertEqual(value['username'],'lens/vitalik')
        self.assertNotEqual(value['controller_address'],value['username_record']['ownedBy'])
        self.assertEqual(value['metadata_claim_status'],'self_published_profile_record')
        self.assertFalse(out.transactions);self.assertFalse(out.ens_profile);self.assertEqual(out.risk_score,0)

    async def test_lens_query_result_with_mismatching_controller_is_not_linked(self):
        payload=deepcopy(FIXTURE['lens']['response'])
        payload['data']['owned'][0]['owner']=payload['data']['owned'][0]['username']['ownedBy']
        out=await self.lens(payload)
        self.assertFalse(out.public_address_context['outcomes'][0]['claims'])

    async def test_lens_graphql_error_is_unavailable_not_absence(self):
        out=await self.lens({'errors':[{'message':'controlled protocol error'}],'data':None})
        self.assertEqual(out.public_address_context['outcomes'][0]['status'],'unavailable')
        self.assertFalse(out.transactions)

    async def test_lens_deadline_after_exact_profile_retains_partial_claim(self):
        capture=FIXTURE['lens']
        with patch('app.sources.web3_identity.public_json',new=AsyncMock(return_value=(deepcopy(capture['response']),capture['transport']))),patch('app.sources.web3_identity._profile_thumbnail',new=AsyncMock(side_effect=TimeoutError)):
            out=await LensPublicSource(1).fetch(capture['input'])
        self.assertEqual(len(out.public_address_context['outcomes'][0]['claims']),1)

    async def base(self,wrong_chain=False):
        records={json.dumps([request['method'],request['params']],sort_keys=True):response
            for batch in FIXTURE['base']['batches']for request,response in zip(batch['requests'],batch['responses'])}
        async def replay(client,method,url,*,json,**kwargs):
            replies=[]
            for request in json:
                key=__import__('json').dumps([request['method'],request['params']],sort_keys=True)
                self.assertIn(key,records)
                response=deepcopy(records[key]);response['id']=request['id']
                if wrong_chain and request['method']=='eth_chainId':response['result']='0x1'
                replies.append(response)
            return replies,{'retrieved_at':'2026-10-26T06:56:36.000000+00:00','cache_hit':True,'transport_requests':0}
        with patch('app.sources.basenames.public_json',new=replay),patch('app.sources.basenames._profile_thumbnail',new=AsyncMock(return_value=None)):
            return await BaseNamesSource(2).fetch(FIXTURE['base']['input'])

    async def test_base_real_reverse_is_forward_verified_and_chain_is_explicit(self):
        out=await self.base();result=out.public_address_context['outcomes'][0];value=result['claims'][0]['value']
        self.assertEqual(value['name'],'jesse.base.eth');self.assertTrue(value['primary_verified'])
        self.assertTrue(value['forward_verified']);self.assertEqual(value['chain_id'],8453)
        self.assertEqual(result['chain'],'base');self.assertEqual(value['records']['com.github'],'jessepollak')
        self.assertFalse(out.transactions);self.assertFalse(out.ens_profile);self.assertFalse(out.detected_chains)

    async def test_base_wrong_rpc_chain_cannot_supply_a_name(self):
        out=await self.base(wrong_chain=True)
        self.assertFalse(out.public_address_context['outcomes'][0]['claims'])
        self.assertEqual(out.public_address_context['outcomes'][0]['status'],'unavailable')

    async def test_invalid_input_does_not_trigger_identity_http(self):
        with patch('app.sources.web3_identity.public_json',new=AsyncMock(side_effect=AssertionError('HTTP'))),patch('app.sources.basenames.public_json',new=AsyncMock(side_effect=AssertionError('HTTP'))):
            for source in [LensPublicSource(1),BaseNamesSource(1)]:
                out=await source.fetch('invalid identifier')
                self.assertEqual(out.public_address_context['outcomes'][0]['status'],'skipped')
