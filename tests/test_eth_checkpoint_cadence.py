"""Measured preview coalescing retains every raw checkpoint and final record."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from app.models.report import AddressReport,Transaction
from app.nft_cli import analyze_search_input
A='0x'+'1'*40

class EthPreviewCadence(unittest.IsolatedAsyncioTestCase):
    async def test_expensive_preview_is_coalesced_without_losing_durable_records(self):
        clock=[0.0];durable=[];rendered=[]
        def report(n):return AddressReport(target_address=A,detected_chains=['eth'],transactions=[Transaction(chain='eth',tx_hash='0x'+f'{i:064x}',source='fixture',asset='ETH',amount=1) for i in range(n)])
        async def keep(value):durable.append(len(value.transactions))
        async def ready(value,graph):rendered.append(len(value.transactions));clock[0]+=2
        async def analyze(address,**kwargs):
            await kwargs['on_checkpoint'](report(1))
            clock[0]=3;await kwargs['on_checkpoint'](report(2))
            clock[0]=10;await kwargs['on_checkpoint'](report(3))
            return report(3),{}
        with patch('app.nft_cli.time',SimpleNamespace(monotonic=lambda:clock[0])),patch('app.attribution.engine.correlate_attribution'),patch('app.graph.builder.build_graph_payload',return_value={}):
            result,_=await analyze_search_input(A,address_analyzer=analyze,continuous=True,on_report_ready=ready,on_model_ready=keep)
        self.assertEqual(durable,[1,2,3])
        self.assertEqual(rendered,[1,3])
        self.assertEqual(len(result.transactions),3)
        self.assertEqual(result.target_address,A)

if __name__=='__main__':unittest.main()
