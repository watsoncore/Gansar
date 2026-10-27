"""Provider schema/identity/failure boundaries; fixtures are never live evidence."""
import unittest
from unittest.mock import AsyncMock,patch
import httpx
from app.attribution.network import VerifiedContractSource,TronContractEvidenceSource
from app.utils.http import close_shared_clients

A='0x'+'1'*40;B='0x'+'2'*40;TRON='TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
META={'retrieved_at':'2026-10-26T00:00:00+00:00','cache_hit':False,'transport_requests':1}
def runtime_gate(code='0x6000',chain='0x1'):
    return AsyncMock(side_effect=[{'jsonrpc':'2.0','id':1,'result':chain},{'jsonrpc':'2.0','id':2,'result':code}])
class AttributionNetworkTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):await close_shared_clients()
    async def test_sourcify_requests_supported_selectors_and_rejects_identity_mismatch(self):
        request=AsyncMock(return_value=({'chainId':'1','address':B,'compilation':{'name':'UntrustedName'}},META))
        with patch('app.attribution.network.request_json',runtime_gate()),patch('app.attribution.network.public_json',request):r=await VerifiedContractSource('eth',1).fetch(A)
        self.assertFalse(r.contract_observations);self.assertTrue(r.errors)
        self.assertEqual(request.call_args.kwargs['params']['fields'],'compilation,deployment,proxyResolution')
    async def test_sourcify_metadata_is_retained_without_wallet_app_inference(self):
        data={'chainId':'1','address':A,'match':'exact_match','compilation':{'name':'Example'},'deployment':{'deployer':B}}
        with patch('app.attribution.network.request_json',runtime_gate()),patch('app.attribution.network.public_json',AsyncMock(return_value=(data,META))):r=await VerifiedContractSource('eth',1).fetch(A)
        self.assertEqual(r.contract_observations[0]['raw']['deployment']['deployer'],B)
        self.assertEqual(r.attribution_intelligence,{})
        self.assertEqual(r.contract_observations[0]['claim_status'],'provider_reported_verification')
    async def test_429_is_not_an_empty_success(self):
        response=httpx.Response(429,request=httpx.Request('GET','https://sourcify.dev/server'))
        error=httpx.HTTPStatusError('rate limit',request=response.request,response=response)
        with patch('app.attribution.network.request_json',runtime_gate()),patch('app.attribution.network.public_json',AsyncMock(side_effect=error)):r=await VerifiedContractSource('eth',1).fetch(A)
        self.assertEqual(r.source_health[0].status,'rate_limited');self.assertTrue(r.errors)
    async def test_404_uses_supported_health_status_and_preserves_failure(self):
        for source,address in ((VerifiedContractSource('eth',1),A),(TronContractEvidenceSource(1),TRON)):
            response=httpx.Response(404,request=httpx.Request('GET','https://example.com/not-found'))
            error=httpx.HTTPStatusError('404 Not Found',request=response.request,response=response)
            if isinstance(source,VerifiedContractSource):
                with patch('app.attribution.network.request_json',runtime_gate()),patch('app.attribution.network.public_json',AsyncMock(side_effect=error)):r=await source.fetch(address)
            else:
                with patch('app.attribution.network.request_json',AsyncMock(side_effect=error)):r=await source.fetch(address)
            self.assertEqual(r.source_health[0].status,'unavailable')
            self.assertFalse(r.contract_observations);self.assertIn('404',r.errors[0])
    async def test_tron_contract_identity_and_creator_preserved(self):
        data={'data':[{'address':TRON,'name':'TetherToken','creator':{'address':'THPvaUhoh2Qn2y9THCZML3H815hhFhn5YC','txHash':'a'*64}}]}
        with patch('app.attribution.network.request_json',AsyncMock(return_value=data)):r=await TronContractEvidenceSource(1).fetch(TRON)
        self.assertEqual(r.contract_observations[0]['raw']['compilation']['name'],'TetherToken')
        self.assertTrue(r.contract_observations[0]['raw']['deployment']['deployer'])
        self.assertFalse(r.labels)
    async def test_malformed_tron_response_does_not_create_contract(self):
        with patch('app.attribution.network.request_json',AsyncMock(return_value={'data':{}})):r=await TronContractEvidenceSource(1).fetch(TRON)
        self.assertFalse(r.contract_observations);self.assertEqual(r.source_health[0].status,'error')

    async def test_no_runtime_code_skips_sourcify_and_preserves_exact_rpc_basis(self):
        rpc=runtime_gate('0x');metadata=AsyncMock()
        with patch('app.attribution.network.request_json',rpc),patch('app.attribution.network.public_json',metadata):
            r=await VerifiedContractSource('eth',1).fetch(A)
        metadata.assert_not_awaited();self.assertEqual(r.source_health[0].status,'skipped')
        self.assertFalse(r.errors);self.assertFalse(r.contract_observations);self.assertFalse(r.transactions)
        self.assertEqual(r.coverage['sourcify_eth']['runtime_gate']['raw_code'],'0x')
        self.assertEqual(r.coverage['sourcify_eth']['runtime_gate']['chain_id'],1)
        self.assertEqual(rpc.call_args_list[-1].kwargs['json']['params'],[A,'latest'])
        self.assertTrue(all(call.kwargs['cache_ttl']==0 and call.kwargs['retries']==0 for call in rpc.call_args_list))

    async def test_eip7702_eoa_indicator_is_not_a_deployed_contract_or_automatic_follow(self):
        code='0xef0100'+B[2:];rpc=runtime_gate(code);metadata=AsyncMock()
        with patch('app.attribution.network.request_json',rpc),patch('app.attribution.network.public_json',metadata):
            r=await VerifiedContractSource('eth',1).fetch(A)
        metadata.assert_not_awaited();self.assertEqual(rpc.await_count,2)
        self.assertEqual(r.source_health[0].status,'skipped');self.assertFalse(r.contract_observations)
        self.assertEqual(r.coverage['sourcify_eth']['runtime_gate']['delegated_address'],B)
        self.assertFalse(r.coverage['sourcify_eth']['runtime_gate']['state_proof_verified'])

    async def test_wrong_chain_and_bad_code_never_query_sourcify(self):
        for code,chain in [('0x6000','0x38'),('0x0','0x1'),(None,'0x1')]:
            with self.subTest(code=code,chain=chain):
                metadata=AsyncMock()
                with patch('app.attribution.network.request_json',runtime_gate(code,chain)),patch('app.attribution.network.public_json',metadata):
                    r=await VerifiedContractSource('eth',1).fetch(A)
                metadata.assert_not_awaited();self.assertEqual(r.source_health[0].status,'error');self.assertFalse(r.contract_observations)

    async def test_invalid_address_makes_no_upstream_request(self):
        rpc=AsyncMock();metadata=AsyncMock()
        with patch('app.attribution.network.request_json',rpc),patch('app.attribution.network.public_json',metadata):
            r=await VerifiedContractSource('eth',1).fetch('not-an-address')
        rpc.assert_not_awaited();metadata.assert_not_awaited();self.assertEqual(r.source_health[0].status,'error')

    async def test_cached_metadata_keeps_original_observed_time_and_fresh_runtime_basis(self):
        data={'chainId':'1','address':A,'match':'exact_match','compilation':{'name':'Example'}}
        cached={**META,'cache_hit':True,'transport_requests':0};request=AsyncMock(return_value=(data,cached))
        with patch('app.attribution.network.request_json',runtime_gate()),patch('app.attribution.network.public_json',request):
            r=await VerifiedContractSource('eth',99).fetch(A)
        row=r.contract_observations[0]
        self.assertEqual(row['observed_at'],META['retrieved_at']);self.assertTrue(row['cache_hit']);self.assertEqual(row['requests'],2)
        self.assertNotEqual(row['runtime_gate']['observed_at'],META['retrieved_at'])
        self.assertEqual(request.call_args.kwargs['cache_ttl'],300)
        self.assertEqual(request.call_args.kwargs['max_bytes'],2_000_000)
        self.assertEqual(r.source_health[0].timeout_seconds,5)
