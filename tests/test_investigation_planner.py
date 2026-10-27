"""Scoped planner execution with real HTTP hook accounting and no live network."""
import asyncio
import copy
from contextlib import asynccontextmanager
import unittest
from unittest.mock import patch

import httpx

from app.attribution.investigation_planner import run_investigation_planner
from app.models.report import AddressReport, Balance, Transaction
from app.sources.manager import SourceManager, SourcePlan
from app.utils import http as http_utils

A, B, C, D = ['0x' + c * 40 for c in '1234']


def transfers(address, target, count=3):
    return [Transaction(chain='eth', tx_hash='0x' + address[-1] * 61 + f'{i:03x}',
            from_address=address, to_address=target, amount_base_units=100 + i, decimals=18,
            asset='ETH', source='fixture_history', success=True) for i in range(count)]


def main_report(count=3):
    return AddressReport(target_address=A, detected_chains=['eth'], transactions=transfers(A, B, count),
                         balances=[Balance(chain='eth', address=A, asset='ETH', amount=7, source='fixture')])


class HistorySource:
    name = 'fixture_history'
    chain = 'eth'

    def __init__(self, *, two_requests=False, delay=0, cursor=False):
        self._timeout = 1
        self.two_requests = two_requests
        self.delay = delay
        self.cursor = cursor
        self._partial_report = 'original-source-state'
        self._resume_state = {'original': {'value': 1}}

    async def fetch(self, address):
        raise AssertionError('Whole source fetch must not be used when narrow history exists')

    async def fetch_history(self, address, out):
        async with http_utils.create_async_client(1) as client:
            await client.get('https://history.example/observed/' + address)
            out.transactions.extend(transfers(address, C if address == B else D))
            out.collection_audit['streams'] = {self.name: {'account_transactions': {
                'next_cursor': {'page': 2}, 'exhausted': not self.cursor,
                'resume_received': copy.deepcopy(self._resume_state)}}}
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.two_requests:
                await client.get('https://history.example/second/' + address)
        return out


class PlannerBoundaries(unittest.IsolatedAsyncioTestCase):
    def test_standard_wallet_contract_is_not_excluded_as_protocol_hub(self):
        from app.attribution.investigation_planner import _hub
        for kind in ['wallet','wallet_v4r2','smart_wallet','multisig']:
            self.assertIsNone(_hub('ton:test',{'addresses':{'ton:test':{'contract':{'kind':kind}}}},{}))

    async def test_rate_limited_source_is_deferred_for_other_branches(self):
        def client(seconds):
            def handler(request):
                self.seen.append(str(request.url))
                return httpx.Response(429)
            return http_utils._ensure_ton_transport_hooks(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        report=main_report();report.transactions+=transfers(A,C)
        with patch('app.utils.http.create_async_client',side_effect=client):
            context=await run_investigation_planner(report,[HistorySource()],self.manager(),max_neighbors=4)
        self.assertEqual(context['coverage']['last_session_http_requests'],1)
        self.assertEqual(context['coverage']['rate_limited_sources_deferred'],['fixture_history'])
        self.assertTrue(any(row['state']=='deferred_rate_limit' for row in context['frontier']))

    async def test_unknown_success_or_display_float_does_not_spend_neighbor_requests(self):
        for field in ['success','precision']:
            report=main_report()
            for tx in report.transactions:
                if field=='success':tx.success=None
                else:tx.amount_base_units=None;tx.decimals=None;tx.amount_decimal=None;tx.amount=1.0
            context=await run_investigation_planner(report,[HistorySource()],self.manager())
            self.assertEqual(context['total_http_requests'],0)

    async def test_incremental_refresh_reopens_observed_branch_and_preserves_history(self):
        class IncrementalSource(HistorySource):
            async def fetch_history(source,address,out):
                result=await super().fetch_history(address,out)
                result.coverage['incremental_clone']=source._incremental
                return result
        report=main_report();source=IncrementalSource()
        context=await run_investigation_planner(report,[source],self.manager(),max_neighbors=1)
        self.assertEqual(context['frontier'][0]['state'],'observed')
        context=await run_investigation_planner(report,[source],self.manager(),max_neighbors=1,incremental=True)
        saved=context['histories']['eth:'+B]['report']
        self.assertTrue(saved['coverage']['incremental_clone'])
        self.assertEqual(len(saved['transactions']),3)
        self.assertEqual(context['total_http_requests'],2)

    async def test_neighbor_probe_cannot_clear_main_source_failure(self):
        manager=self.manager();manager.record_fail('fixture_history')
        context=await run_investigation_planner(main_report(),[HistorySource()],manager)
        self.assertEqual(manager.plan('fixture_history',1).fail_count,1)
        self.assertEqual(context['total_http_requests'],0)
        self.assertTrue(any(j['trigger']=='history.source_gated' for j in context['journal']))

    async def test_placeholder_event_names_cannot_trigger_network_expansion(self):
        report=main_report()
        for i,tx in enumerate(report.transactions):tx.tx_hash='placeholder:'+str(i)
        context=await run_investigation_planner(report,[HistorySource()],self.manager())
        self.assertEqual(context['total_http_requests'],0)

    def setUp(self):
        self.seen = []
        def handler(request):
            self.seen.append(str(request.url))
            return httpx.Response(200, json={'observed': True})
        def client(seconds):
            return http_utils._ensure_ton_transport_hooks(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        self.client_patch = patch('app.utils.http.create_async_client', side_effect=client)
        self.client_patch.start()
        self.addCleanup(self.client_patch.stop)

    def manager(self, *, enabled=True):
        return SourceManager({'fixture_history': SourcePlan('fixture_history', 1, 1, enabled=enabled)})

    async def test_repeated_branch_expands_two_hops_with_separate_financials(self):
        report, source = main_report(), HistorySource()
        txs, balances = report.transactions.copy(), report.balances.copy()
        context = await run_investigation_planner(report, [source], self.manager(), max_neighbors=2)
        self.assertEqual(set(context['histories']), {'eth:' + B, 'eth:' + C})
        self.assertEqual(context['histories']['eth:' + C]['depth'], 2)
        self.assertEqual(report.transactions, txs)
        self.assertEqual(report.balances, balances)
        self.assertEqual(context['coverage']['last_session_http_requests'], 2)
        self.assertEqual(context['total_http_requests'], 2)
        self.assertEqual(source._partial_report, 'original-source-state')
        self.assertEqual(source._resume_state, {'original': {'value': 1}})
        self.assertFalse(context['coverage']['history_complete'])

    async def test_single_or_two_transactions_do_not_trigger_optional_http(self):
        for count in (1, 2):
            context = await run_investigation_planner(main_report(count), [HistorySource()], self.manager())
            self.assertFalse(context['histories'])
            self.assertEqual(context['total_http_requests'], 0)
        self.assertFalse(self.seen)

    async def test_duplicate_projections_do_not_create_repeated_evidence(self):
        report = main_report(1)
        report.transactions *= 5
        context = await run_investigation_planner(report, [HistorySource()], self.manager())
        self.assertFalse(context['histories'])
        self.assertFalse(self.seen)

    async def test_actual_request_budget_retains_partial_dto_and_cursor(self):
        context = await run_investigation_planner(main_report(), [HistorySource(two_requests=True, cursor=True)],
                    self.manager(), max_http_requests=1)
        self.assertEqual(len(self.seen), 1)
        self.assertEqual(context['coverage']['last_session_http_requests'], 1)
        self.assertTrue(context['coverage']['request_limit_reached'])
        neighbor = context['histories']['eth:' + B]
        self.assertEqual(len(neighbor['report']['transactions']), 3)
        self.assertEqual(neighbor['status'], 'budget_limited')
        self.assertEqual(neighbor['report']['collection_audit']['streams']['fixture_history']['account_transactions']['next_cursor'], {'page': 2})
        loaded = [j for j in context['journal'] if j['trigger'] == 'history.loaded']
        self.assertEqual(loaded[0]['cost']['http_requests'], 1)

    async def test_zero_budgets_and_expired_deadline_do_not_request(self):
        options = [{'max_http_requests': 0}, {'max_seconds': 0}, {'max_neighbors': 0},
                   {'deadline': asyncio.get_running_loop().time() - 1}]
        for extra in options:
            await run_investigation_planner(main_report(), [HistorySource()], self.manager(), **extra)
        self.assertFalse(self.seen)

    async def test_manager_gate_and_protocol_hub_are_respected(self):
        context = await run_investigation_planner(main_report(), [HistorySource()], self.manager(enabled=False))
        self.assertFalse(context['histories'])
        report = main_report()
        report.attribution_intelligence = {'addresses': {'eth:' + B: {'contract': {'kind': 'smart_contract'}, 'attributions': []}}}
        context = await run_investigation_planner(report, [HistorySource()], self.manager())
        self.assertEqual(context['frontier'][0]['state'], 'excluded_hub')
        self.assertFalse(self.seen)

    async def test_timeout_retains_completed_pages_without_main_changes(self):
        report = main_report()
        context = await run_investigation_planner(report, [HistorySource(delay=.3, cursor=True)], self.manager(), max_seconds=.03)
        self.assertEqual(len(context['histories']['eth:' + B]['report']['transactions']), 3)
        self.assertTrue(context['coverage']['time_limit_reached'])
        self.assertEqual(len(report.transactions), 3)
        self.assertEqual(context['histories']['eth:' + B]['report']['coverage']['context_attribution']['status'], 'DEFERRED')

    async def test_external_cancellation_preserves_context_and_propagates(self):
        report = main_report()
        task = asyncio.create_task(run_investigation_planner(report, [HistorySource(delay=10, cursor=True)], self.manager()))
        for _ in range(100):
            if self.seen:
                break
            await asyncio.sleep(.001)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        context = report.attribution_intelligence['investigation_context']
        self.assertTrue(context['coverage']['cancelled'])
        self.assertEqual(len(context['histories']['eth:' + B]['report']['transactions']), 3)

    async def test_resume_passes_only_neighbor_cursor_and_deduplicates_rows(self):
        report = main_report()
        context = await run_investigation_planner(report, [HistorySource(cursor=True)], self.manager(), max_neighbors=1)
        context = await run_investigation_planner(report, [HistorySource(cursor=True)], self.manager(), context=context, max_neighbors=1)
        entry = context['histories']['eth:' + B]
        state = entry['report']['collection_audit']['streams']['fixture_history']['account_transactions']
        self.assertEqual(state['resume_received']['account_transactions']['next_cursor'], {'page': 2})
        self.assertNotIn('original', state['resume_received'])
        self.assertEqual(len(entry['report']['transactions']), 3)
        self.assertEqual(context['sessions'], 2)
        self.assertEqual(context['total_http_requests'], 2)

    async def test_unsupported_balance_source_cannot_recurse_or_fetch_assets(self):
        class BalanceSource:
            name = 'ethereum_rpc'
            chain = 'eth'
            async def fetch(self, address):
                raise AssertionError('Balance-only source has no address history')
        context = await run_investigation_planner(main_report(), [BalanceSource()], self.manager())
        self.assertFalse(context['histories'])
        self.assertEqual(context['frontier'][0]['state'], 'unavailable')
        self.assertFalse(self.seen)

    async def test_existing_etherscan_collects_only_native_internal_and_token_history(self):
        from app.sources.ethereum_etherscan_api import EthereumEtherscanApiSource
        actions = []
        def response(request):
            action = request.url.params['action']
            actions.append(action)
            rows = [{'hash': '0x' + '9' * 64, 'from': B, 'to': C, 'value': '1000000000000000000',
                     'isError': '0', 'timeStamp': '1700000000', 'blockNumber': '18000000'}] if action == 'txlist' else []
            return httpx.Response(200, json={'status': '1', 'message': 'OK', 'result': rows})
        @asynccontextmanager
        async def client(seconds):
            async with http_utils._ensure_ton_transport_hooks(httpx.AsyncClient(transport=httpx.MockTransport(response))) as value:
                yield value
        source = EthereumEtherscanApiSource(1)
        with patch('app.attribution.investigation_planner.shared_async_client', client), patch.object(source, '_api_key', return_value='fixture-key'):
            context = await run_investigation_planner(main_report(), [source], self.manager(), max_neighbors=1)
        self.assertEqual(actions, ['txlist', 'txlistinternal', 'tokentx'])
        self.assertEqual(context['coverage']['last_session_http_requests'], 3)
        self.assertEqual(len(context['histories']['eth:' + B]['report']['transactions']), 1)
        self.assertFalse(hasattr(source, '_partial_report'))


if __name__ == '__main__':
    unittest.main()
