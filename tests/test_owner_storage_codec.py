"""Lossless bounded large-owner storage codec; no live provider calls."""
import base64,hashlib,json
from pathlib import Path
import sqlite3,tempfile,unittest,zlib
from unittest.mock import patch
from app.ton_nft import storage
from app.ton_nft.models import NFTIntelligenceReport
from app.utils.security import sanitize_observation


class OwnerStorageCodecTests(unittest.TestCase):
    def owner(self):
        return {"target_address":"synthetic-owner","transactions":[{"tx_hash":"one","raw":{
            "public":"Полный Unicode 你好 \u0000"*20,"unknown":{"unabridged":[1,2,3]},
            "authorization":"Bearer synthetic_private_marker"}}]}

    def encoded(self):
        owner=sanitize_observation(self.owner())
        with patch.object(storage,"OWNER_COMPRESSION_THRESHOLD",32):
            text,digest=storage._encode_owner_snapshot(owner)
        return owner,text,digest

    def test_codec_exact_legacy_sha_full_public_raw_and_redaction_round_trip(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(storage,"OWNER_COMPRESSION_THRESHOLD",32):
            store=storage.InvestigationStore(Path(directory)/"snapshot.sqlite3")
            try:
                report=NFTIntelligenceReport(investigation_id="codec-fixture",query="fixture.ton",owner_analysis_snapshot=self.owner())
                store.save_snapshot(report)
                digest,text=store.db.execute("SELECT content_sha256,owner_json FROM owner_snapshots").fetchone()
                clean=sanitize_observation(self.owner())
                expected=json.dumps(clean,ensure_ascii=False,separators=(",",":")).encode()
                self.assertEqual(digest,hashlib.sha256(expected).hexdigest())
                wrapper=json.loads(text)
                self.assertEqual(wrapper["_gansar_encoding"],"zlib_json")
                self.assertEqual(wrapper["uncompressed_bytes"],len(expected))
                self.assertEqual(wrapper["transaction_count"],1)
                self.assertEqual(store.load_snapshot(report.investigation_id).owner_analysis_snapshot,clean)
                self.assertNotIn("synthetic_private_marker",text)
            finally:store.close()

    def test_ownerless_header_verifies_compressed_bytes_without_inflating(self):
        _,text,digest=self.encoded()
        with patch.object(storage.zlib,"decompressobj",side_effect=AssertionError("Header must not inflate")):
            self.assertIsNone(storage.decode_owner_snapshot(text,digest,include_owner=False))
            wrapper=json.loads(text);wrapper["data"]=base64.b64encode(b"changed").decode()
            with self.assertRaisesRegex(ValueError,"compressed checksum"):
                storage.decode_owner_snapshot(json.dumps(wrapper),digest,include_owner=False)

    def test_codec_corruption_length_count_type_and_hash_are_visible(self):
        _,text,digest=self.encoded()
        mutations=(
            {"_gansar_encoding":"gzip_json"},{"version":True},{"uncompressed_bytes":True},
            {"uncompressed_bytes":storage.MAX_OWNER_SNAPSHOT_BYTES+1},{"uncompressed_bytes":2},
            {"sha256":"0"*64},{"compressed_sha256":"0"*64},{"transaction_count":2},
            {"data":"invalid base64!"})
        for mutation in mutations:
            wrapper=json.loads(text);wrapper.update(mutation)
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                storage.decode_owner_snapshot(json.dumps(wrapper),digest)

    def test_truncated_extra_and_oversized_deflate_streams_are_rejected(self):
        _,text,digest=self.encoded()
        for kind in ("truncated","trailing","wrong_length"):
            wrapper=json.loads(text);compressed=base64.b64decode(wrapper["data"])
            if kind=="truncated":compressed=compressed[:-2]
            elif kind=="trailing":compressed+=b"not-another-stream"
            else:wrapper["uncompressed_bytes"]-=1
            wrapper["data"]=base64.b64encode(compressed).decode()
            wrapper["compressed_sha256"]=hashlib.sha256(compressed).hexdigest()
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,"length or checksum"):
                storage.decode_owner_snapshot(json.dumps(wrapper),digest)

    def test_legacy_plain_text_remains_exact_and_malformed_non_object_is_visible(self):
        owner={"public":{"value":"retained"}}
        text=json.dumps(owner,ensure_ascii=False,separators=(",",":"));digest=hashlib.sha256(text.encode()).hexdigest()
        self.assertEqual(storage.decode_owner_snapshot(text,digest),owner)
        text="[]";digest=hashlib.sha256(text.encode()).hexdigest()
        with self.assertRaisesRegex(ValueError,"dossier object"):storage.decode_owner_snapshot(text,digest)

    def test_codec_owner_update_rollback_and_nested_secret_mutation(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(storage,"OWNER_COMPRESSION_THRESHOLD",32):
            store=storage.InvestigationStore(Path(directory)/"snapshot.sqlite3")
            try:
                report=NFTIntelligenceReport(investigation_id="codec-atomic",query="fixture.ton",owner_analysis_snapshot=self.owner())
                store.save_snapshot(report);old=store.load_snapshot(report.investigation_id).owner_analysis_snapshot
                store.db.execute("CREATE TRIGGER fail_report BEFORE INSERT ON investigations BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
                report.owner_analysis_snapshot["transactions"][0]["raw"]["public"]="nested-public-change"*30
                report.owner_analysis_snapshot["transactions"][0]["raw"]["secret"]="nested_secret_marker"
                with self.assertRaises(sqlite3.IntegrityError):store.save_snapshot(report)
                self.assertEqual(store.load_snapshot(report.investigation_id).owner_analysis_snapshot,old)
                store.db.execute("DROP TRIGGER fail_report");store.db.commit();store.save_snapshot(report)
                updated=store.load_snapshot(report.investigation_id).owner_analysis_snapshot
                self.assertEqual(updated["transactions"][0]["raw"]["public"],"nested-public-change"*30)
                self.assertEqual(updated["transactions"][0]["raw"]["secret"],"[REDACTED]")
            finally:store.close()

    def test_resource_size_guard_retains_old_committed_owner(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(storage,"OWNER_COMPRESSION_THRESHOLD",16):
            store=storage.InvestigationStore(Path(directory)/"snapshot.sqlite3")
            try:
                report=NFTIntelligenceReport(investigation_id="bounded",query="fixture.ton",owner_analysis_snapshot={"value":1})
                store.save_snapshot(report)
                report.owner_analysis_snapshot={"public":"large"*100}
                with patch.object(storage,"MAX_OWNER_SNAPSHOT_BYTES",64),self.assertRaisesRegex(ValueError,"bounded storage size"):
                    store.save_snapshot(report)
                self.assertEqual(store.load_snapshot(report.investigation_id).owner_analysis_snapshot,{"value":1})
            finally:store.close()


if __name__=="__main__":unittest.main()
