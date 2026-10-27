"""Measured preview cadence coalesces views while retaining the newest model."""
import asyncio
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from app import nft_cli
from app.models.report import AddressReport,Transaction
from app.ton_nft.models import NFTIntelligenceReport


class CheckpointCadenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_measured_full_preview_cost_coalesces_rapid_updates_but_not_forced_owner_finish(self):
        target="0:"+"1"*64;clock=[0.0];rendered=[]
        rapid=asyncio.Event();allow_owner=asyncio.Event();forced=asyncio.Event()
        def model(count):
            return AddressReport(target_address=target,transactions=[Transaction(chain="ton",tx_hash=f"{i:064x}",source="fixture") for i in range(count)])
        async def ready(report,graph):
            rendered.append({tx.tx_hash for tx in report.transactions})
            # Includes the whole original renderer callback, not provider time.
            clock[0]+=20
            await asyncio.sleep(0)
            if len(rendered)==3:forced.set()
        async def collect(address,**kwargs):
            await kwargs["on_checkpoint"](model(1))  # completed at t=20
            clock[0]=21;await kwargs["on_checkpoint"](model(2))
            clock[0]=30;await kwargs["on_checkpoint"](model(3))
            self.assertEqual(len(rendered),1)
            rapid.set();await allow_owner.wait()
            return model(3),{}
        async def investigate(query,**kwargs):
            value=NFTIntelligenceReport(investigation_id="preview-cadence",query=target,scope="wallet")
            await kwargs["on_target_resolved"]({"scope":"wallet","analysis_address":target},value)
            await asyncio.wait_for(rapid.wait(),timeout=3)
            clock[0]=79;await kwargs["on_checkpoint"](value)
            self.assertEqual(len(rendered),1)  # below 3*20 after prior finish
            clock[0]=81;await kwargs["on_checkpoint"](value)
            self.assertEqual(len(rendered),2)
            self.assertEqual(len(rendered[-1]),3)  # newest coalesced model
            allow_owner.set()
            await asyncio.wait_for(forced.wait(),timeout=3)
            return value
        with tempfile.TemporaryDirectory() as directory,patch.object(nft_cli,"time",SimpleNamespace(monotonic=lambda:clock[0])), \
                patch("app.ton_nft.service.investigate_ton_nft",investigate):
            report,_=await nft_cli.analyze_search_input(target,continuous=True,address_analyzer=collect,
                on_report_ready=ready,nft_options={"store_path":Path(directory)/"snapshot.sqlite3"})
        self.assertEqual([len(rows) for rows in rendered],[1,3,3])
        self.assertEqual({tx.tx_hash for tx in report.transactions},rendered[-1])


if __name__=="__main__":unittest.main()
