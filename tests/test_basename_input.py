"""Main-input replay of a real Base name capture, not a fresh source query."""
from pathlib import Path
from copy import deepcopy
import json
import unittest
from unittest.mock import patch, AsyncMock
from app.models.report import AddressReport
from app.nft_cli import analyze_search_input

ROOT=Path(__file__).resolve().parents[1]
CAPTURE=ROOT/'validation/typography_osint_20261026/identity/base_jesse.json'


class BasenameInputTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_alias_resolves_once_then_existing_pipeline_receives_correct_seed(self):
        if not CAPTURE.exists():self.skipTest('Actual saved Base name capture unavailable')
        seed=AddressReport.model_validate_json(CAPTURE.read_text(encoding='utf8'))
        original=deepcopy(seed.public_address_context)
        invoked=[]
        async def analyze(address, *, public_context_seed, **kwargs):
            invoked.append((address,kwargs))
            self.assertEqual(address,seed.target_address)
            self.assertEqual(kwargs['selected_chains'],['eth'])
            self.assertFalse(public_context_seed.ens_profile)
            value=public_context_seed.public_address_context['outcomes'][0]['claims'][0]['value']
            self.assertEqual(value['name'],'jessepollak.base.eth')
            self.assertEqual(value['primary_name'],'jesse.base.eth')
            self.assertFalse(value['primary_verified'])
            self.assertEqual(value['chain_id'],8453)
            return public_context_seed,{'target':address,'nodes':[],'edges':[]}
        resolved=AsyncMock(return_value=seed)
        with patch('app.sources.basenames.BaseNamesSource.resolve_name',resolved),patch('app.sources.ethereum_ens.EthereumEnsSource.resolve_name',side_effect=AssertionError('Mainnet ENS must not handle a Base-native name')):
            out,_=await analyze_search_input('jessepollak.base.eth',address_analyzer=analyze)
        self.assertEqual(len(invoked),1);resolved.assert_awaited_once_with('jessepollak.base.eth')
        self.assertEqual(out.input_resolution['identity_chain'],'base')
        self.assertIn('not implemented',out.input_resolution['notes'][0])
        self.assertEqual(out.public_address_context['outcomes'][0]['claims'],original['outcomes'][0]['claims'])

    async def test_unresolved_name_stops_without_guessing_a_target(self):
        async def forbidden(*args,**kwargs):self.fail('Unresolved name cannot start wallet analysis')
        with patch('app.sources.basenames.BaseNamesSource.resolve_name',AsyncMock(return_value=AddressReport(target_address='unresolved.base.eth'))):
            with self.assertRaisesRegex(ValueError,'could not be resolved'):
                await analyze_search_input('unresolved.base.eth',address_analyzer=forbidden)
