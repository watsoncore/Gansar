"""Parent projection excludes only an internal duplicate; full owner is durable."""
from collections import Counter
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock,patch

from app.models.report import AddressReport,Balance,Transaction
from app.ton_nft.models import NFTIntelligenceReport,NFTEvent
from app.ton_nft.service import report_to_address_report,attach_nft_intelligence
from app.ton_nft.storage import InvestigationStore
from app.utils.event_identity import event_identity
from app.utils.security import portable_observation
from app.exporters.nft_exporter import export_nft_machine_data

OWNER="0:"+"1"*64
ITEM="0:"+"2"*64


class OwnerProjectionReferenceTests(unittest.TestCase):
    def test_parent_projection_matches_all_facts_and_retains_full_owner_in_original_sqlite_and_machine_export(self):
        wallet=AddressReport(target_address=OWNER,detected_chains=["ton"],
            balances=[Balance(chain="ton",address=OWNER,asset="TON",amount=8,source="fixture")],
            transactions=[Transaction(chain="ton",tx_hash="a"*64,source="fixture",
                raw={"public_unknown_field":{"marker":"complete-owner-raw","value":42}})])
        nft=NFTIntelligenceReport(investigation_id="owner-projection",query=ITEM,
            owner_analysis_snapshot=wallet.model_dump(mode="json"),events=[NFTEvent(event_id="nft-event",asset_address=ITEM,
                transaction_hash="b"*64,event_type="transfer",from_address=ITEM,to_address=OWNER,status="success",
                raw={"unknown_provider_field":"complete-event-raw"})])
        original=json.loads(nft.model_dump_json())
        default=report_to_address_report(nft)
        compact=report_to_address_report(nft,include_owner_snapshot=False)
        self.assertEqual(default.nft_intelligence["owner_analysis_snapshot"],original["owner_analysis_snapshot"])
        self.assertNotIn("owner_analysis_snapshot",compact.nft_intelligence)
        self.assertEqual(Counter(event_identity(tx) for tx in default.transactions),Counter(event_identity(tx) for tx in compact.transactions))
        self.assertEqual(default.transactions,compact.transactions)
        self.assertEqual(default.ton_assets,compact.ton_assets)
        self.assertEqual(default.nft_intelligence["events"],compact.nft_intelligence["events"])
        # Verify attach asks to omit the duplicate before the AddressReport
        # validator ever traverses it, rather than dropping it after validation.
        with patch("app.models.report.portable_observation",wraps=portable_observation) as protect:
            attach_nft_intelligence(wallet,nft)
        guarded_roots=[call.args[0] for call in protect.call_args_list
            if isinstance(call.args[0],dict) and "nft_intelligence" in call.args[0]]
        self.assertTrue(guarded_roots)
        self.assertTrue(all("owner_analysis_snapshot" not in root["nft_intelligence"] for root in guarded_roots))
        self.assertNotIn("owner_analysis_snapshot",wallet.nft_intelligence)
        self.assertEqual(wallet.nft_intelligence["owner_analysis_reference"]["location"],"parent_address_report")
        self.assertEqual(len(wallet.transactions),2)
        self.assertEqual(wallet.balances[0].amount,8)
        self.assertEqual(nft.owner_analysis_snapshot,original["owner_analysis_snapshot"])
        with tempfile.TemporaryDirectory() as directory,patch("httpx.AsyncClient.send",new=AsyncMock(side_effect=AssertionError("No API"))):
            path=Path(directory)/"snapshot.sqlite3"
            store=InvestigationStore(path)
            try:
                store.save_snapshot(nft)
                self.assertEqual(store.load_snapshot("owner-projection").owner_analysis_snapshot,original["owner_analysis_snapshot"])
            finally:store.close()
            exported=export_nft_machine_data(nft,Path(directory)/"machine")
            data=json.loads(exported["json"].read_text(encoding="utf-8"))
            self.assertEqual(data["owner_analysis_snapshot"],original["owner_analysis_snapshot"])
            self.assertEqual(data["events"],original["events"])

    def test_different_unsaved_historical_owner_keeps_its_unique_dossier(self):
        historical="0:"+"3"*64
        report=NFTIntelligenceReport(investigation_id="different-owner",query=ITEM,
            owner_analysis_snapshot={"target_address":historical,"public_observation":"retained"})
        parent=AddressReport(target_address=OWNER)
        attach_nft_intelligence(parent,report)
        self.assertNotIn("owner_analysis_reference",parent.nft_intelligence)
        self.assertEqual(parent.nft_intelligence["owner_analysis_snapshot"],report.owner_analysis_snapshot)
        self.assertEqual(report.owner_analysis_snapshot["public_observation"],"retained")


if __name__=="__main__":unittest.main()
