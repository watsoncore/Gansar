"""Deterministic import/update security, provenance, and atomicity regressions."""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx

from app.attribution.datasets import (DEFAULT_SNAPSHOT, load_dataset_records, lookup_dataset_records, normalize_dataset,
    update_datasets, write_snapshot)
from app.utils.security import safe_public_url

A = "0x" + "1" * 40
B = "0x" + "2" * 40
OBSERVED = "2026-10-16T00:00:00+00:00"


def source(name="fixture", **values):
    return {"id": name, "url": "https://example.com/" + name + ".json", "format": "json", "adapter": "records",
        "license": "MIT", "license_url": "https://example.com/LICENSE", **values}


def payload(address=A, entity="Example"):
    return json.dumps([{"blockchain": "eth", "address": address, "entity_name": entity}]).encode()


async def public_only(url):
    if not safe_public_url(url): raise ValueError("non-public dataset target")
    return url


class DatasetImportTests(unittest.TestCase):
    def test_network_scope_conflicting_labels_and_upstream_remain_distinct(self):
        data = json.dumps([{"blockchain": "eth", "address": A, "entity_name": "One", "source": "https://provider.example/label"},
            {"blockchain": "bsc", "address": A, "entity_name": "One", "source": "https://provider.example/label"},
            {"blockchain": "eth", "address": A, "entity_name": "Other", "source": "https://other.example/label"}]).encode()
        item = normalize_dataset(data, source(), observed_at=OBSERVED)
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "snapshot.json"; write_snapshot([item], file)
            rows = load_dataset_records(file)
        self.assertEqual(len(rows), 3)
        self.assertEqual({row["blockchain"] for row in rows}, {"eth", "bsc"})
        self.assertEqual({row["entity_name"] for row in rows if row["blockchain"] == "eth"}, {"One", "Other"})
        self.assertEqual({row["upstream"] for row in rows}, {"provider.example", "other.example"})
        self.assertTrue(all(row["status"] == "PROBABLE" for row in rows))
        self.assertTrue(all(row["content_hash"] == hashlib.sha256(data).hexdigest() for row in rows))

    def test_safe_yaml_inheritance_and_no_cluster_ownership_promotion(self):
        data = ("currency: ETH\nactor: example\nlabel: Example\nlastmod: 2022-11-16\n"
            "source: https://example.com/reserves\nis_cluster_definer: true\ntags:\n- address: " + A + "\n").encode()
        # Quotes prevent YAML from interpreting a hexadecimal address as an int.
        data = data.replace(A.encode(), ('"' + A + '"').encode())
        item = normalize_dataset(data, source(format="yaml", adapter="graphsense"), observed_at=OBSERVED)
        self.assertEqual(item["coverage"]["retained_records"], 1)
        row = {**item["defaults"], **item["records"][0]}
        self.assertEqual(row["entity_id"], "example")
        self.assertEqual(row["source_published_at"], "2022-11-16")
        self.assertEqual(row["status"], "PROBABLE")
        self.assertEqual(row["relationship"], "publicly_labeled_address")
        self.assertTrue(row["coverage_limitations"])

    def test_data_only_import_rejects_python_tags_aliases_and_javascript(self):
        for data in (b'!!python/object/apply:os.system ["echo unsafe"]', b'a: &x [*x]'):
            with self.subTest(data=data), self.assertRaises(Exception):
                normalize_dataset(data, source(format="yaml"))
        with self.assertRaises(ValueError):
            normalize_dataset(b'[{"address":"x"}]', source(format="javascript"))

    def test_snapshot_digest_nonmutation_and_immutable_history(self):
        item = normalize_dataset(payload(), source(), observed_at=OBSERVED)
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "snapshot.json"
            first = write_snapshot([item], file)
            archive = Path(folder) / "versions" / (first["version"] + ".json")
            original_archive = archive.read_bytes()
            rows = load_dataset_records(file)
            rows[0]["coverage_limitations"].append("caller mutation")
            self.assertNotIn("caller mutation", load_dataset_records(file)[0]["coverage_limitations"])
            write_snapshot([item], file)
            self.assertEqual(archive.read_bytes(), original_archive)
            tampered = json.loads(file.read_text()); tampered["datasets"][0]["defaults"]["entity_name"] = "tampered"
            file.write_text(json.dumps(tampered))
            with self.assertRaisesRegex(ValueError, "hash mismatch"): load_dataset_records(file)

    def test_packaged_snapshot_real_source_coverage_and_no_user_expected_rules(self):
        rows = load_dataset_records(DEFAULT_SNAPSHOT)
        self.assertGreater(len(rows), 50_000)
        self.assertTrue({"btc", "doge", "eth", "bsc", "polygon", "avalanche", "arbitrum", "optimism", "tron", "solana", "ton"} <= {row["blockchain"] for row in rows})
        self.assertEqual(sum(row["blockchain"] == "ton" for row in rows), 536)
        self.assertTrue(all(row["source_url"].startswith("https://") for row in rows))
        self.assertTrue(all(row["status"] == "PROBABLE" for row in rows))

    def test_safe_official_manifest_retains_six_chain_scopes_and_published_code_hash(self):
        row = {"address": A, "codeHash": "0x" + "a" * 64}
        body = json.dumps({"contractName": "Safe", "version": "1.4.1", "deployments": {"canonical": row},
            "networkAddresses": {str(value): "canonical" for value in (1, 56, 137, 42161, 10, 43114, 8453)}}).encode()
        item = normalize_dataset(body, source(adapter="safe_deployments", entity_id="safe",
            authority="official_operator_publication", relationship="published_deployment"), observed_at=OBSERVED)
        rows = [{**item["defaults"], **row} for row in item["records"]]
        self.assertEqual(len(rows), 6)
        self.assertEqual({row["blockchain"] for row in rows}, {"eth", "bsc", "polygon", "arbitrum", "optimism", "avalanche"})
        self.assertTrue(all(row["contract_metadata"]["published_code_hash"] == "0x" + "a" * 64 for row in rows))
        self.assertTrue(all(row["status"] == "PROBABLE" and row["relationship"] == "published_deployment" for row in rows))

    def test_user_selected_store_is_loaded_offline_and_explicit_path_takes_precedence(self):
        with tempfile.TemporaryDirectory() as folder:
            selected = Path(folder) / "selected.json"; explicit = Path(folder) / "explicit.json"
            write_snapshot([normalize_dataset(payload(entity="Selected"), source(), observed_at=OBSERVED)], selected)
            write_snapshot([normalize_dataset(payload(entity="Explicit"), source(), observed_at=OBSERVED)], explicit)
            with patch.dict("os.environ", {"GANSAR_ATTRIBUTION_DATASET": str(selected)}):
                self.assertEqual(load_dataset_records()[0]["entity_name"], "Selected")
                self.assertEqual(load_dataset_records(explicit)[0]["entity_name"], "Explicit")

    def test_default_local_catalogue_is_used_and_corruption_does_not_silently_fall_back(self):
        with tempfile.TemporaryDirectory() as folder:
            local = Path(folder) / "attribution_catalogue.json"
            write_snapshot([normalize_dataset(payload(entity="Locally updated"), source(), observed_at=OBSERVED)], local)
            with patch.dict("os.environ", {"GANSAR_ATTRIBUTION_DATASET": ""}), patch(
                    "app.attribution.datasets.DEFAULT_LOCAL_SNAPSHOT", local):
                self.assertEqual(load_dataset_records()[0]["entity_name"], "Locally updated")
                modified = json.loads(local.read_text())
                modified["datasets"][0]["defaults"]["entity_name"] = "corrupted"
                local.write_text(json.dumps(modified))
                with self.assertRaisesRegex(ValueError, "hash mismatch"): load_dataset_records()

    def test_indexed_lookup_matches_full_filter_and_never_mutates_cached_records(self):
        data = json.dumps([{"blockchain": "eth", "address": A, "entity_name": "One"},
            {"blockchain": "bsc", "address": A, "entity_name": "Two"},
            {"blockchain": "eth", "address": A, "entity_name": "Conflicting"},
            {"blockchain": "eth", "address": B, "entity_name": "Other"}]).encode()
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "snapshot.json"
            write_snapshot([normalize_dataset(data, source(), observed_at=OBSERVED)], file)
            keys = {"eth:" + A, "eth:" + B}
            actual = lookup_dataset_records(keys, file)
            self.assertEqual(actual, [row for row in load_dataset_records(file) if row["blockchain"] + ":" + row["address"] in keys])
            self.assertEqual([row["entity_name"] for row in actual], ["One", "Conflicting", "Other"])
            actual[0]["coverage_limitations"].append("caller mutation")
            self.assertNotIn("caller mutation", lookup_dataset_records(keys, file)[0]["coverage_limitations"])
            self.assertEqual(lookup_dataset_records({"solana:unknown"}, file), [])

    def test_index_version_change_is_observed_and_corrupt_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "snapshot.json"
            write_snapshot([normalize_dataset(payload(entity="First"), source(), observed_at=OBSERVED)], file)
            self.assertEqual(lookup_dataset_records({"eth:" + A}, file)[0]["entity_name"], "First")
            write_snapshot([normalize_dataset(payload(entity="Second"), source(), observed_at=OBSERVED)], file)
            self.assertEqual(lookup_dataset_records({"eth:" + A}, file)[0]["entity_name"], "Second")
            changed = json.loads(file.read_text()); changed["version"] = "wrong"
            file.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "hash mismatch"): lookup_dataset_records({"eth:" + A}, file)


class DatasetUpdateTests(unittest.IsolatedAsyncioTestCase):
    async def run_update(self, sources, handler, folder, **kwargs):
        registry = Path(folder) / "sources.json"
        registry.write_text(json.dumps({"sources": sources}))
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with patch("app.attribution.datasets.validate_public_url", side_effect=public_only):
                return await update_datasets(store_path=Path(folder) / "snapshot.json", sources_path=registry,
                    client=client, **kwargs)

    async def test_first_update_retains_disabled_bundled_source_without_new_observation(self):
        calls = []
        disabled = source("tonkeeper_existing_registry", update_enabled=False, license="unresolved")
        original = normalize_dataset(payload(entity="Retained historical label"), disabled, observed_at=OBSERVED)
        def handler(request):
            calls.append(request)
            return httpx.Response(500)
        with tempfile.TemporaryDirectory() as folder:
            packaged = Path(folder) / "bundled.json"
            write_snapshot([original], packaged)
            with patch("app.attribution.datasets.DEFAULT_SNAPSHOT", packaged):
                result = await self.run_update([disabled], handler, folder)
            current = json.loads((Path(folder) / "snapshot.json").read_text())
            self.assertEqual(current["datasets"], [original])
            self.assertEqual(load_dataset_records(Path(folder) / "snapshot.json")[0]["observed_at"], OBSERVED)
            self.assertEqual(result["records"], 1)
            self.assertEqual(result["sources"], [{"id": disabled["id"], "status": "disabled",
                "retained_previous": True, "retained_from": "bundled_snapshot", "retained_observed_at": OBSERVED}])
            self.assertFalse(result["errors"])
        self.assertFalse(calls)

    async def test_corrupt_existing_store_never_falls_back_to_bundled_or_downloads(self):
        calls = []
        def handler(request):
            calls.append(request)
            return httpx.Response(200, content=payload())
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "snapshot.json"
            for datasets in ([], [{"id": "broken"}]):
                corrupt = json.dumps({"version": "invalid", "datasets": datasets})
                target.write_text(corrupt)
                with self.subTest(datasets=datasets), self.assertRaisesRegex(ValueError, "hash mismatch"):
                    await self.run_update([source()], handler, folder)
                self.assertEqual(target.read_text(), corrupt)
        self.assertFalse(calls)

    async def test_403_and_network_error_keep_prior_records_while_other_source_updates(self):
        calls = []
        def handler(request):
            calls.append(request.url.path)
            if request.url.path == "/old.json": return httpx.Response(403)
            return httpx.Response(200, content=payload(B, "New"))
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "snapshot.json"
            write_snapshot([normalize_dataset(payload(), source("old"), observed_at=OBSERVED)], target)
            result = await self.run_update([source("old"), source("new")], handler, folder, force=True)
            self.assertEqual(result["status"], "partial")
            self.assertTrue(result["errors"][0]["retained_previous"])
            self.assertEqual({row["entity_name"] for row in load_dataset_records(target)}, {"Example", "New"})
            self.assertEqual(calls.count("/old.json"), 1)

    async def test_limit_private_redirect_and_unresolved_license_are_not_ingested(self):
        calls = []
        def handler(request):
            calls.append(request.url.path)
            if request.url.path == "/redirect.json": return httpx.Response(302, headers={"Location": "http://127.0.0.1/private"})
            return httpx.Response(200, content=b"x" * 101)
        with tempfile.TemporaryDirectory() as folder:
            result = await self.run_update([source("large"), source("redirect"), source("unknown", license="unresolved")], handler, folder, max_response_bytes=100)
            self.assertEqual(result["records"], 0)
            self.assertEqual(len(result["errors"]), 2)
            self.assertNotIn("/private", calls)
            self.assertNotIn("/unknown.json", calls)
            self.assertEqual(result["sources"][0]["status"], "license_unresolved")

    async def test_deadline_cancels_pending_http_and_preserves_prior_snapshot(self):
        pending = set()
        async def handler(request):
            pending.add(request.url.path)
            try: await asyncio.sleep(10)
            finally: pending.remove(request.url.path)
            return httpx.Response(200, content=payload())
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "snapshot.json"
            write_snapshot([normalize_dataset(payload(), source("old"), observed_at=OBSERVED)], target)
            started = asyncio.get_running_loop().time()
            result = await self.run_update([source("old"), source("other")], handler, folder,
                force=True, deadline=started + .04)
            self.assertLess(asyncio.get_running_loop().time() - started, .5)
            self.assertFalse(pending)
            self.assertEqual(len(result["errors"]), 2)
            self.assertEqual(load_dataset_records(target)[0]["entity_name"], "Example")

    async def test_caller_cancellation_drains_all_download_tasks_and_leaves_no_temp_file(self):
        pending = set(); entered = asyncio.Event()
        async def handler(request):
            pending.add(request.url.path)
            if len(pending) == 2: entered.set()
            try: await asyncio.sleep(10)
            finally:
                await asyncio.sleep(.01)
                pending.remove(request.url.path)
            return httpx.Response(200, content=payload())
        with tempfile.TemporaryDirectory() as folder:
            task = asyncio.create_task(self.run_update([source("a"), source("b")], handler, folder, force=True))
            await entered.wait(); task.cancel()
            with self.assertRaises(asyncio.CancelledError): await task
            self.assertFalse(pending)
            self.assertFalse((Path(folder) / "snapshot.json").exists())
            self.assertFalse(list(Path(folder).glob("*.tmp")))

    async def test_public_dataset_update_refuses_authenticated_clients_before_requests(self):
        calls = []
        def handler(request):
            calls.append(request)
            return httpx.Response(200, content=payload())
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "sources.json"
            config.write_text(json.dumps({"sources": [source()]}))
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler), headers={"Authorization": "Bearer fixture_secret"}) as client:
                with self.assertRaisesRegex(ValueError, "without credentials"):
                    await update_datasets(store_path=Path(folder) / "snapshot.json", sources_path=config, client=client)
        self.assertFalse(calls)

    async def test_changed_license_blocks_new_data_and_shared_license_is_checked_once(self):
        calls = []
        def handler(request):
            calls.append(request.url.path)
            return httpx.Response(200, content=b"changed license")
        kwargs = {"license_sha256": hashlib.sha256(b"reviewed license").hexdigest(),
            "license_download_url": "https://example.com/LICENSE"}
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "snapshot.json"
            write_snapshot([normalize_dataset(payload(), source("a"), observed_at=OBSERVED)], target)
            result = await self.run_update([source("a", **kwargs), source("b", **kwargs)], handler, folder, force=True)
            self.assertEqual(len(result["errors"]), 2)
            self.assertEqual(calls, ["/LICENSE"])
            self.assertEqual(load_dataset_records(target)[0]["entity_name"], "Example")


if __name__ == "__main__": unittest.main()
