"""ENS input/presentation boundaries; deterministic fixtures are not live data."""
import io
import contextlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from rich.console import Console

from app.models.report import AddressReport, Transaction
from app.nft_cli import analyze_search_input
from app.exporters.html_exporter import _ens_summary, _ens_wallet_identities
from test_ethereum_ens import ProtocolSource, ADDRESS, NAME


class EnsDisplayBindingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.report = await ProtocolSource().resolve_name(NAME)

    async def test_verified_wallet_identity_is_metadata_and_preserves_source_report(self):
        self.report.transactions = [Transaction(chain='eth', tx_hash='fixture-operation',
            from_address=ADDRESS, to_address='0x'+'b'*40, value=1, asset='ETH', source='boundary_fixture')]
        before = self.report.model_dump(mode='json')
        summary = _ens_summary(self.report, 'ru')
        records = summary['wallet_identities']
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['address'], ADDRESS)
        self.assertEqual(records[0]['name'], NAME)
        self.assertTrue(records[0]['forward_verified'])
        self.assertTrue(records[0]['primary_verified'])
        self.assertFalse(records[0]['ownership_claim'])
        self.assertEqual(records[0]['provenance']['block_number'], 0x1234)
        self.assertEqual(self.report.model_dump(mode='json'), before)
        self.assertEqual(len(self.report.transactions), 1)

    async def test_transaction_search_uses_verified_alias_without_changing_operations(self):
        from app.exporters.html_exporter import _transaction_views
        self.report.transactions=[Transaction(chain='eth',tx_hash='0x'+'1'*64,from_address=ADDRESS,to_address='0x'+'b'*40,amount=1,asset='ETH',source='fixture')]
        before=self.report.model_dump()
        views=_transaction_views(self.report,'en',{})
        self.assertEqual(len(views),1);self.assertIn(NAME,views[0]['q'])
        self.assertEqual(self.report.model_dump(),before)
        self.report.ens_profile['forward_verified']=False
        self.assertNotIn(NAME,_transaction_views(self.report,'en',{})[0]['q'])

    async def test_mismatched_address_or_unverified_reverse_never_annotates_a_wallet(self):
        cases = []
        for key, value in [('forward_verified', False), ('resolved_address', '0x'+'b'*40),
                           ('source_address', '0x'+'b'*40), ('source', 'metadata'),
                           ('name', 'different.eth')]:
            value_report = self.report.model_copy(deep=True)
            value_report.ens_profile[key] = value
            cases.append((key, value_report))
        for key, value in [('chain_id', 8453), ('network', 'bsc')]:
            value_report = self.report.model_copy(deep=True)
            value_report.ens_profile['provenance'][key] = value
            cases.append((key, value_report))
        for chains in (['bsc'], ['ton']):
            value_report = self.report.model_copy(deep=True)
            value_report.detected_chains = chains
            cases.append(('wrong_chain', value_report))
        for case, value_report in cases:
            with self.subTest(case=case):
                self.assertEqual(_ens_wallet_identities(value_report), [])
        reverse = await ProtocolSource(forward='0x'+'b'*40).fetch(ADDRESS)
        self.assertFalse(reverse.ens_reverse_valid)
        self.assertEqual(_ens_wallet_identities(reverse), [])

    async def test_queried_forward_alias_is_not_misrepresented_as_verified_primary(self):
        report = await ProtocolSource(reverse='another-primary.eth').resolve_name(NAME)
        identity = _ens_wallet_identities(report)[0]
        self.assertEqual(identity['name'], NAME)
        self.assertTrue(identity['forward_verified'])
        self.assertFalse(identity['primary_verified'])

    async def test_optional_profile_timeout_preserves_verified_resolution(self):
        source = ProtocolSource()
        source._text_records = AsyncMock(side_effect=httpx.ReadTimeout('boundary optional timeout'))
        report = await source.resolve_name(NAME)
        self.assertEqual(report.target_address, ADDRESS)
        self.assertEqual(report.ens_resolved_address, ADDRESS)
        self.assertTrue(report.ens_profile['forward_verified'])
        self.assertEqual(report.ens_profile['provenance']['chain_id'], 1)
        self.assertEqual(report.ens_profile['lookup_status'], 'timeout')
        self.assertEqual(_ens_wallet_identities(report)[0]['name'], NAME)
        self.assertFalse(report.transactions)

    async def test_name_handoff_preserves_normalized_input_resolution_and_provenance(self):
        seed = self.report
        calls = []
        async def analyzer(address, *, ens_seed, **kwargs):
            calls.append((address, kwargs))
            self.assertEqual(ens_seed.target_address, ADDRESS)
            return AddressReport(target_address=address, detected_chains=['eth']), {'nodes': [], 'edges': []}
        events = []
        with patch('app.sources.ethereum_ens.EthereumEnsSource.resolve_name', AsyncMock(return_value=seed)):
            report, graph = await analyze_search_input('ExAmPlE.EtH', address_analyzer=analyzer, progress=events.append)
        self.assertEqual(calls[0][0], ADDRESS)
        self.assertEqual(calls[0][1]['selected_chains'], ['eth'])
        self.assertEqual(report.input_resolution['original_query'], 'ExAmPlE.EtH')
        self.assertEqual(report.input_resolution['normalized_query'], NAME)
        self.assertEqual(report.input_resolution['status'], 'resolved')
        self.assertEqual(report.input_resolution['provenance']['block_number'], 0x1234)
        self.assertFalse(report.transactions)
        event = next(row for row in events if row['stage'] == 'ens.resolve.complete')
        self.assertEqual(event['resolved_address'], ADDRESS)

    async def test_missing_or_unavailable_name_never_calls_wallet_analyzer(self):
        for response in (AddressReport(target_address='missing.eth'),
                         AddressReport(target_address='missing.eth', ens_resolved_address=ADDRESS,
                                       ens_profile={'forward_verified': False})):
            analyzer = AsyncMock()
            with self.subTest(response=response.ens_profile), patch('app.sources.ethereum_ens.EthereumEnsSource.resolve_name', AsyncMock(return_value=response)):
                with self.assertRaisesRegex(ValueError, 'could not be resolved'):
                    await analyze_search_input('missing.eth', address_analyzer=analyzer)
                analyzer.assert_not_called()

    async def test_resolution_timeout_reports_error_without_wallet_assumption(self):
        analyzer = AsyncMock()
        with patch('app.sources.ethereum_ens.EthereumEnsSource.resolve_name', AsyncMock(side_effect=TimeoutError)):
            with self.assertRaisesRegex(ValueError, 'resolution timed out'):
                await analyze_search_input(NAME, address_analyzer=analyzer)
        analyzer.assert_not_called()


class EnsCliProgressTests(unittest.TestCase):
    def test_live_and_command_progress_show_resolved_wallet_after_immediate_start(self):
        import app.main as main
        event = {'stage': 'ens.resolve.complete', 'source': 'ethereum_ens', 'name': NAME,
                 'target': ADDRESS, 'resolved_address': ADDRESS, 'forward_verified': True}
        state = main.InvestigationState(address=NAME, source_states={})
        main._search_progress(state, event)
        self.assertIn(ADDRESS, state.feed[-1])
        self.assertIn(NAME, state.feed[-1])
        self.assertEqual(state.source_states['ethereum_ens'].status, 'online')
        output = io.StringIO()
        with patch.object(main, 'console', Console(file=output, force_terminal=False, width=160)):
            progress = main._command_progress()
            progress({'stage': 'ens.resolve.start', 'source': 'ethereum_ens', 'query': NAME})
            progress(event)
        self.assertIn(ADDRESS, output.getvalue())
        self.assertIn('ens.resolve.complete', output.getvalue())


class EnsSupervisedWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def run_worker(self, query, seed):
        from app import main, search_worker
        from app.search_runtime import load_result
        calls = []
        writes = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            session = root / 'session'
            session.mkdir()
            output = root / 'output'
            output.mkdir()
            async def writer(report, graph, destination, *args, **kwargs):
                writes.append(report.model_copy(deep=True))
                # This isolated checkpoint stub is not an HTML investigation.
                path = destination / 'fixture.checkpoint'
                path.write_text('isolated worker checkpoint fixture', encoding='utf8')
                return path
            async def wallet(address, *, ens_seed, **kwargs):
                calls.append((address, kwargs.get('selected_chains')))
                return ens_seed.model_copy(deep=True), {'nodes': [], 'edges': []}
            async def analysis(text, destination, **kwargs):
                result, graph = await analyze_search_input(text, address_analyzer=wallet,
                    progress=kwargs.get('progress'))
                return result, await writer(result, graph, destination), None
            resolver = AsyncMock(return_value=seed)
            request = {'language': 'en', 'session': str(session), 'collection_seconds': 60,
                'jobs': [{'query': query, 'output': str(output),
                          'nft_options': {'store_path': str(root / 'snapshot.sqlite3')}}]}
            with patch.object(main, '_write_search_html', writer), \
                 patch.object(main, '_analyze_quiet', analysis), \
                 patch('app.sources.ethereum_ens.EthereumEnsSource.resolve_name', resolver), \
                 contextlib.redirect_stdout(io.StringIO()) as stdout:
                await search_worker.execute(request)
            error = session / 'job_0_error.json'
            result = load_result(session / 'job_0.pickle') if (session / 'job_0.pickle').exists() else None
            return {'calls': calls, 'writes': writes, 'result': result,
                'error': json.loads(error.read_text(encoding='utf8')) if error.exists() else None,
                'resolver_calls': resolver.await_count,
                'events': [json.loads(line)['event'] for line in stdout.getvalue().splitlines()]}

    async def test_supervised_worker_admits_normalized_ens_then_resolves_before_wallet_analysis(self):
        seed = await ProtocolSource().resolve_name(NAME)
        result = await self.run_worker('ExAmPlE.EtH', seed)
        self.assertIsNone(result['error'])
        self.assertEqual(result['resolver_calls'], 1)
        self.assertEqual(result['calls'], [(ADDRESS, ['eth'])])
        self.assertEqual(result['writes'][0].detected_chains, ['eth'])
        self.assertEqual(result['result'][0].target_address, ADDRESS)
        self.assertTrue(result['result'][3])
        self.assertEqual(result['result'][0].input_resolution['original_query'], 'ExAmPlE.EtH')
        self.assertTrue(any(row['stage'] == 'ens.resolve.complete' for row in result['events']))

    async def test_supervised_missing_ens_never_invokes_wallet_analysis(self):
        result = await self.run_worker('missing.eth', AddressReport(target_address='missing.eth'))
        self.assertEqual(result['resolver_calls'], 1)
        self.assertEqual(result['calls'], [])
        self.assertIn('could not be resolved', result['error']['error'])

    async def test_supervised_invalid_name_is_rejected_before_resolver_or_bootstrap(self):
        for query in ('foo..eth', 'unsupported identifier'):
            with self.subTest(query=query):
                result = await self.run_worker(query, AddressReport(target_address=query))
                self.assertEqual(result['resolver_calls'], 0)
                self.assertEqual(result['calls'], [])
                self.assertEqual(result['writes'], [])
                self.assertIn('Unknown input format', result['error']['error'])


if __name__ == '__main__':
    unittest.main()
