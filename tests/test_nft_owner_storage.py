"""Owner snapshots remain lossless without per-page duplicate serialization."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from app.ton_nft.models import NFTIntelligenceReport
from app.ton_nft.storage import InvestigationStore
from app.utils.security import sanitize_observation

class OwnerStorageTests(unittest.TestCase):
    def test_owner_round_trip_page_updates_and_nested_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            store=InvestigationStore(Path(directory)/"snapshots.sqlite3")
            try:
                owner={"target_address":"public-owner","transactions":[{"raw":{"unknown":{"value":1}}}]}
                report=NFTIntelligenceReport(investigation_id="owner-fixture",query="fixture.ton",owner_analysis_snapshot=owner)
                traces=[];store.db.set_trace_callback(traces.append)
                with patch("app.ton_nft.storage.sanitize_observation",wraps=sanitize_observation) as clean:
                    store.save_snapshot(report)
                    first_calls=sum(call.args[0] is owner for call in clean.call_args_list)
                    report.stats["pages"]=2;store.save_snapshot(report)
                    self.assertEqual(len([sql for sql in traces if sql.startswith("INSERT OR REPLACE INTO owner_snapshots")]),1)
                    owner_writes=len([sql for sql in traces if sql.startswith("INSERT OR REPLACE INTO owner_snapshots")])
                    report.owner_analysis_snapshot["transactions"][0]["raw"]["unknown"]["value"]=2
                    store.save_snapshot(report)
                    self.assertEqual(len([sql for sql in traces if sql.startswith("INSERT OR REPLACE INTO owner_snapshots")]),owner_writes+1)
                saved=store.load_snapshot(report.investigation_id)
                self.assertEqual(saved.owner_analysis_snapshot["transactions"][0]["raw"]["unknown"]["value"],2)
                serialized=json.loads(store.db.execute("SELECT report_json FROM investigations").fetchone()[0])
                self.assertNotIn("owner_analysis_snapshot",serialized)
                self.assertEqual(serialized["owner_snapshot_reference"]["kind"],"sqlite_owner_snapshot")
                light=store.load_snapshot(report.investigation_id,include_owner=False)
                self.assertIsNone(light.owner_analysis_snapshot)
                store.save_snapshot(light)
                self.assertEqual(store.load_snapshot(report.investigation_id).owner_analysis_snapshot,saved.owner_analysis_snapshot)
            finally:store.close()

    def test_legacy_inline_read_and_explicit_detachment_preserve_all_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            store=InvestigationStore(Path(directory)/"snapshots.sqlite3")
            try:
                report=NFTIntelligenceReport(investigation_id="legacy-fixture",query="fixture.ton",
                    owner_analysis_snapshot={"target_address":"owner","transactions":[{"hash":"one"}],"attribution_intelligence":{"raw":{"unknown":7}}})
                legacy=report.model_dump_json()
                store.db.execute("INSERT INTO investigations VALUES(?,?,?,?,?)",(report.investigation_id,report.query,"1.0","2026-10-17",legacy));store.db.commit()
                self.assertEqual(store.load_snapshot(report.investigation_id).owner_analysis_snapshot,report.owner_analysis_snapshot)
                self.assertEqual(store.db.execute("SELECT COUNT(*) FROM owner_snapshots").fetchone()[0],0)
                resume=store.load_snapshot(report.investigation_id,owner_exclude={"attribution_intelligence"},detach_owner=True)
                self.assertNotIn("attribution_intelligence",resume.owner_analysis_snapshot)
                resume.owner_analysis_snapshot=None
                store.save_snapshot(resume)
                self.assertEqual(store.load_snapshot(report.investigation_id).owner_analysis_snapshot,report.owner_analysis_snapshot)
            finally:store.close()

    def test_sanitized_owner_is_reused_after_reopening_and_corruption_is_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"snapshots.sqlite3"
            store=InvestigationStore(path)
            report=NFTIntelligenceReport(investigation_id="redaction-fixture",query="fixture.ton",owner_analysis_snapshot={"authorization":"Bearer fixture_secret","public":{"value":3}})
            store.save_snapshot(report);store.close()
            store=InvestigationStore(path)
            try:
                loaded=store.load_snapshot(report.investigation_id)
                self.assertNotIn("fixture_secret",loaded.model_dump_json())
                report.stats["next_page"]=2
                queries=[];store.db.set_trace_callback(queries.append);store.save_snapshot(report)
                self.assertFalse(any(sql.startswith("INSERT OR REPLACE INTO owner_snapshots") for sql in queries))
                store.db.execute("UPDATE owner_snapshots SET owner_json=?",('{"changed":true}',));store.db.commit()
                with self.assertRaisesRegex(ValueError,"checksum mismatch"):store.load_snapshot(report.investigation_id)
            finally:store.close()

    def test_owner_update_and_report_replacement_are_atomic_on_sql_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            store=InvestigationStore(Path(directory)/"snapshots.sqlite3")
            try:
                report=NFTIntelligenceReport(investigation_id="atomic-fixture",query="fixture.ton",owner_analysis_snapshot={"value":1})
                store.save_snapshot(report)
                store.db.execute("CREATE TRIGGER fail_report BEFORE INSERT ON investigations BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
                report.owner_analysis_snapshot["value"]=2
                with self.assertRaises(sqlite3.IntegrityError):store.save_snapshot(report)
                self.assertEqual(store.load_snapshot(report.investigation_id).owner_analysis_snapshot["value"],1)
                store.db.execute("DROP TRIGGER fail_report");store.db.commit();store.save_snapshot(report)
                self.assertEqual(store.load_snapshot(report.investigation_id).owner_analysis_snapshot["value"],2)
            finally:store.close()
