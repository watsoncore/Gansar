"""Normal-pipeline receipt enrichment stays bounded, optional and observable."""
import asyncio
from contextlib import asynccontextmanager
import json
import unittest
from unittest.mock import patch

import httpx

from app.attribution.evm_receipt_enrichment import enrich_evm_receipts
from app.attribution.evm_transaction_fingerprints import USER_OPERATION, analyze_evm_transaction
from app.models.report import AddressReport, Transaction
from app.sources.evm_rpc import EthereumRpcSource
from app.sources.manager import build_default_source_manager

A = '0x' + '11' * 20
B = '0x' + '22' * 20
EP = '0x0000000071727de22e5e9d8baf0edac6f37da032'


def make_report(count=1):
    return AddressReport(target_address=A, detected_chains=['eth'], transactions=[
        Transaction(chain='eth', tx_hash='0x' + f'{i + 1:064x}', from_address=A,
                    to_address=EP, success=True, source='existing_collector')
        for i in range(count)])


def good_reply(request, chain_id='0x1'):
    body = json.loads(request.content)
    rows = [{'jsonrpc': '2.0', 'id': 0, 'result': chain_id}]
    for item in body[1:]:
        rows.append({'jsonrpc': '2.0', 'id': item['id'], 'result': {
            'transactionHash': item['params'][0], 'status': '0x1', 'logs': [{
                'address': EP, 'topics': [USER_OPERATION, '0x' + 'aa' * 32,
                    '0x' + B[2:].rjust(64, '0'), '0x' + '00' * 32],
                'data': '0x' + ''.join(f'{v:064x}' for v in (0, 1, 7, 5))}]}})
    return httpx.Response(200, json=rows)


class ReceiptEnrichment(unittest.IsolatedAsyncioTestCase):
    async def run_with_transport(self, report, handler, **kwargs):
        @asynccontextmanager
        async def client(_timeout):
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as result:
                yield result
        with patch('app.attribution.evm_receipt_enrichment.shared_async_client', client):
            return await enrich_evm_receipts(report, [EthereumRpcSource(4)],
                kwargs.pop('manager', None) or build_default_source_manager(), **kwargs)

    async def test_real_pipeline_shape_hydrates_receipt_and_detector_observes_inner_account(self):
        report = make_report()
        requests = []
        def handler(request):
            requests.append(request)
            return good_reply(request)
        coverage = await self.run_with_transport(report, handler)
        self.assertEqual(coverage['loaded_transactions'], 1)
        self.assertEqual(coverage['network_requests'], 1)
        self.assertEqual(str(requests[0].url), EthereumRpcSource.rpc_url)
        self.assertEqual(len(json.loads(requests[0].content)), 2)
        tx = report.transactions[0]
        result = analyze_evm_transaction(tx)
        row = result['implementation_observations'][0]
        self.assertEqual(row['subject_address'], B)
        self.assertFalse(row['signing_application_confirmed'])
        self.assertEqual(len(tx.raw['receipt_provenance']['response_sha256']), 64)
        self.assertEqual(result['evidence'][0]['source'], 'ethereum_rpc')
        self.assertEqual(result['evidence'][0]['observed_at'], tx.raw['receipt_provenance']['observed_at'])
        self.assertEqual(tx.source, 'existing_collector')

    async def test_only_known_recipients_and_at_most_eight_distinct_hashes(self):
        report = make_report(12)
        report.transactions.insert(0, Transaction(chain='eth', tx_hash='0x' + 'ee' * 32,
            from_address=A, to_address=B, source='ordinary_transfer'))
        report.transactions.append(report.transactions[1].model_copy(deep=True))
        coverage = await self.run_with_transport(report, good_reply, max_transactions=999)
        self.assertEqual(coverage['selected_transactions'], 8)
        self.assertEqual(coverage['eligible_transactions'], 12)
        self.assertEqual(coverage['requested_transactions'], 8)
        self.assertNotIn('receipt', report.transactions[0].raw)
        self.assertTrue(coverage['truncated'])
        self.assertIn('receipt', report.transactions[-1].raw)

    async def test_wrong_chain_hash_and_failed_receipt_never_attach(self):
        for failure_kind in ('chain', 'hash', 'status', 'duplicate_id'):
            report = make_report()
            def handler(request):
                response = good_reply(request)
                rows = response.json()
                if failure_kind == 'chain':
                    rows[0]['result'] = '0x89'
                elif failure_kind == 'hash':
                    rows[1]['result']['transactionHash'] = '0x' + 'ff' * 32
                elif failure_kind == 'status':
                    rows[1]['result']['status'] = '0x0'
                else:
                    rows[1]['id'] = 0
                return httpx.Response(200, json=rows)
            coverage = await self.run_with_transport(report, handler)
            self.assertFalse(coverage['loaded_transactions'])
            self.assertNotIn('receipt', report.transactions[0].raw)
            self.assertTrue(report.errors)
            self.assertTrue(report.source_health[-1].partial)

    async def test_disabled_source_is_visible_without_network_or_global_health_mutation(self):
        report = make_report()
        manager = build_default_source_manager()
        manager.plan('ethereum_rpc', 4).enabled = False
        def handler(request):
            self.fail('disabled RPC source was called')
        coverage = await self.run_with_transport(report, handler, manager=manager)
        self.assertEqual(coverage['network_requests'], 0)
        self.assertTrue(coverage['failures'])
        self.assertEqual(manager.plan('ethereum_rpc', 4).fail_count, 0)

    async def test_timeout_and_response_byte_cap_leave_collected_data_intact(self):
        report = make_report()
        async def slow(request):
            await asyncio.sleep(1)
            return good_reply(request)
        coverage = await self.run_with_transport(report, slow, max_seconds=0.01)
        self.assertEqual(coverage['status'], 'unavailable')
        self.assertEqual(len(report.transactions), 1)
        self.assertEqual(report.transactions[0].source, 'existing_collector')
        self.assertNotIn('receipt', report.transactions[0].raw)
        report = make_report()
        with patch('app.attribution.evm_receipt_enrichment.MAX_RESPONSE_BYTES', 100):
            coverage = await self.run_with_transport(report, good_reply)
        self.assertEqual(coverage['loaded_transactions'], 0)
        self.assertIn('response byte limit', coverage['failures'][0]['error'])

    async def test_ordinary_transfer_missing_rpc_and_existing_receipt_need_no_requests(self):
        report = make_report()
        report.transactions[0].to_address = B
        def handler(request):
            self.fail('unnecessary network request')
        coverage = await self.run_with_transport(report, handler)
        self.assertEqual(coverage['status'], 'not_needed')
        report = make_report()
        report.transactions[0].raw['receipt'] = {'retained': 'previous_observation'}
        coverage = await self.run_with_transport(report, handler)
        self.assertEqual(coverage['network_requests'], 0)
        self.assertEqual(report.transactions[0].raw['receipt'], {'retained': 'previous_observation'})


if __name__ == '__main__':
    unittest.main()
