"""A late Esplora timeout must preserve prior pages, including UTXO structure."""
import asyncio
import unittest
from unittest.mock import patch
from app.sources.bitcoin_blockstream import BitcoinBlockstreamSource

ADDRESS='1BoatSLRHtKNngkdXEeobR76b53LETtpyT'

class BtcPartialDeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_before_account_data_does_not_invent_zero_balance(self):
        source=BitcoinBlockstreamSource(1);blocked=asyncio.Event()
        async def get(client,path):
            blocked.set();await asyncio.Future()
        with patch.object(source,'_get_json',get):
            task=asyncio.create_task(source.fetch(ADDRESS));await asyncio.wait_for(blocked.wait(),2);task.cancel()
            with self.assertRaises(asyncio.CancelledError):await task
        self.assertEqual(source._partial_report.balances,[])
        self.assertEqual(source._partial_report.bitcoin,{})

    async def test_cancelled_later_page_keeps_account_and_first_page(self):
        source=BitcoinBlockstreamSource(1)
        blocked=asyncio.Event()
        async def get(client,path):
            if path=='/blocks/tip/height':return 100
            if path==f'/address/{ADDRESS}':return {'chain_stats':{'funded_txo_sum':200000000,'spent_txo_sum':100000000,'tx_count':50}}
            if path==f'/address/{ADDRESS}/txs':
                return [{'txid':f'{i:064x}','vin':[], 'vout':[{'scriptpubkey_address':ADDRESS,'value':1000}],
                    'status':{'confirmed':True,'block_height':90,'block_time':1700000000}} for i in range(25)]
            blocked.set()
            await asyncio.Future()
        with patch.object(source,'_get_json',get):
            task=asyncio.create_task(source.fetch(ADDRESS))
            await asyncio.wait_for(blocked.wait(),2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):await task
        report=source._partial_report
        self.assertEqual(len(report.transactions),25)
        self.assertEqual(report.balances[0].raw['sats'],100000000)
        self.assertEqual(report.transactions[0].outputs[0]['value_sats'],1000)
        self.assertEqual(report.bitcoin['tx_count'],50)
        self.assertTrue(report.bitcoin['partial'])
        self.assertEqual(report.source_health[0].status,'partial')

    async def test_cancelled_utxo_request_keeps_completed_history(self):
        source=BitcoinBlockstreamSource(1);blocked=asyncio.Event()
        async def get(client,path):
            if path=='/blocks/tip/height':return 100
            if path==f'/address/{ADDRESS}':return {'chain_stats':{'funded_txo_sum':50,'tx_count':1}}
            if path==f'/address/{ADDRESS}/txs':return [{'txid':'a'*64,'vin':[],'vout':[{'scriptpubkey_address':ADDRESS,'value':50}]}]
            blocked.set();await asyncio.Future()
        with patch.object(source,'_get_json',get):
            task=asyncio.create_task(source.fetch(ADDRESS));await asyncio.wait_for(blocked.wait(),2);task.cancel()
            with self.assertRaises(asyncio.CancelledError):await task
        self.assertEqual(len(source._partial_report.transactions),1)
        self.assertEqual(source._partial_report.balances[0].raw['sats'],50)
