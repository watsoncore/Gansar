from __future__ import annotations

import argparse
import asyncio
import io
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from pydantic import ValidationError
from rich.console import Console

from app.nft_cli import (analyze_and_export_ton_nft, budget_from_args,
                         command_parser, enrich_ton_address_report,
                         looks_like_nft_input, print_nft_summary,
                         run_nft_command)
from app.ton_nft.models import NFTIntelligenceReport


class NftCliTests(unittest.TestCase):
    def test_explicit_inputs_autoroute(self):
        for query in ["solvnox.ton", "example.ton", "@username", "username.t.me",
                      "t.me/username", "https://t.me/nft/FixtureGift-123",
                      "https://getgems.io/nft/fixture", "https://fragment.com/username/fixture"]:
            with self.subTest(query=query):
                self.assertTrue(looks_like_nft_input(query))

    def test_addresses_and_arbitrary_urls_keep_legacy_route(self):
        for query in ["0x" + "1" * 40, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                      "https://localhost/nft", "https://evil.example/asset", "", "plain title"]:
            with self.subTest(query=query):
                self.assertFalse(looks_like_nft_input(query))

    def test_user_search_always_uses_full_supported_mode(self):
        from app.ton_nft.models import InvestigationBudget
        maximum = InvestigationBudget.for_mode("deep")
        for old_option in ([], ["--mode", "standard"], ["--mode", "deep"]):
            selected = budget_from_args(command_parser().parse_args(["--address", "example.ton"] + old_option))
            self.assertEqual(selected, maximum)
        self.assertNotIn("--mode", command_parser().format_help())

    def test_budget_overrides_are_validated(self):
        args = command_parser().parse_args(["--ton-nft", "example.ton", "--max-pages", "3", "--deadline", "15"])
        budget = budget_from_args(args)
        self.assertEqual(budget.max_pages, 3)
        self.assertEqual(budget.max_seconds, 15)
        args.max_pages = 0
        with self.assertRaises(ValidationError):
            budget_from_args(args)

    def test_summary_does_not_claim_complete_history(self):
        result = NFTIntelligenceReport(investigation_id="fixture-cli", query="fixture.ton", status="unresolved")
        output = io.StringIO()
        print_nft_summary(result, {"html": Path("fixture.html"), "json": Path("fixture.json")}, Console(file=output, width=200), "en")
        self.assertIn("does not imply full history", output.getvalue())
        self.assertIn("unresolved", output.getvalue())
        self.assertIn("fixture.html", output.getvalue())
        self.assertNotIn("fixture.json", output.getvalue())

    def test_main_menu_retains_original_six_choices(self):
        from app import main
        for language in ("ru", "en"):
            self.assertEqual([entry[0] for entry in main.UI[language]["menu"]], ["1", "2", "3", "4", "5", "6"])

    def test_outputs_are_explicit_opt_ins(self):
        defaults = command_parser().parse_args(["--address", "wallet.ton"])
        self.assertFalse(defaults.pdf)
        self.assertFalse(defaults.machine_exports)
        explicit = command_parser().parse_args(["--address", "wallet.ton", "--pdf", "--machine-exports"])
        self.assertTrue(explicit.pdf)
        self.assertTrue(explicit.machine_exports)

    def test_portable_raw_export_streams_snapshot_and_redacts_secrets(self):
        import json
        from app.nft_cli import _add_raw_observations
        from app.ton_nft.models import SourceObservation
        from app.ton_nft.storage import InvestigationStore
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            observation = SourceObservation(observation_id="fixture-observation", source="fixture", upstream="fixture",
                endpoint="https://example.com", content_hash="fixture-hash", status="ok",
                raw={"records": [{"arbitrary_provider_field": "retained"}], "Authorization": "fixture_secret"})
            result = NFTIntelligenceReport(investigation_id="fixture-cli", query="fixture.ton", observations=[observation])
            store = InvestigationStore(directory / "snapshot.sqlite3")
            try:
                store.save_observation(result.investigation_id, observation)
                store.save_snapshot(result)
            finally:
                store.close()
            paths = {}
            _add_raw_observations(result, paths, directory, directory / "snapshot.sqlite3")
            raw = json.loads(paths["observations"].read_text(encoding="utf-8"))
            self.assertEqual(raw["raw"]["records"][0]["arbitrary_provider_field"], "retained")
            self.assertNotIn("fixture_secret", paths["observations"].read_text(encoding="utf-8"))

    def test_older_observation_missing_method_remains_unknown(self):
        from app.ton_nft.models import SourceObservation
        old = SourceObservation.model_validate({"observation_id": "old-fixture", "source": "fixture", "upstream": "fixture",
            "endpoint": "https://example.com/api/v2/runGetMethod", "content_hash": "old-hash", "raw": {"stack": []}})
        self.assertIsNone(old.request_method)
        self.assertIsNone(old.request_body)


class NftCliAsyncTests(unittest.IsolatedAsyncioTestCase):
    def modules(self, result):
        service = types.ModuleType("app.ton_nft.service")
        service.investigate_ton_nft = AsyncMock(return_value=result)
        service.load_investigation = Mock(return_value=result)
        exporter = types.ModuleType("app.exporters.nft_exporter")
        exporter.export_nft_dossier = Mock(side_effect=lambda *args, **kwargs: {"html": Path("fixture.html")} |
            ({"json": Path("fixture.json")} if kwargs.get("machine_exports") else {}))
        exporter.export_nft_pdf = AsyncMock(return_value=Path("fixture.pdf"))
        return service, exporter

    async def test_explicit_query_defaults_to_one_original_html(self):
        result = NFTIntelligenceReport(investigation_id="fixture-cli", query="fixture.ton")
        service, exporter = self.modules(result)
        with patch.dict(sys.modules, {service.__name__: service, exporter.__name__: exporter}):
            actual, paths = await analyze_and_export_ton_nft("fixture.ton", mode="deep", scope="trace", pdf=False)
        self.assertIs(actual, result)
        self.assertEqual(set(paths), {"html"})
        self.assertNotIn("pdf", paths)
        self.assertEqual(service.investigate_ton_nft.await_args.kwargs["mode"], "deep")
        self.assertEqual(service.investigate_ton_nft.await_args.kwargs["scope"], "trace")
        exporter.export_nft_pdf.assert_not_awaited()
        self.assertEqual(exporter.export_nft_dossier.call_args.args[1], Path("output"))
        self.assertFalse(exporter.export_nft_dossier.call_args.kwargs["machine_exports"])

    async def test_machine_exports_require_explicit_option(self):
        result = NFTIntelligenceReport(investigation_id="fixture-cli", query="fixture.ton")
        service, exporter = self.modules(result)
        with patch.dict(sys.modules, {service.__name__: service, exporter.__name__: exporter}):
            actual, paths = await analyze_and_export_ton_nft("fixture.ton", machine_exports=True)
        self.assertEqual(set(paths), {"html", "json"})
        exporter.export_nft_pdf.assert_not_awaited()

    async def test_reexport_never_calls_provider(self):
        result = NFTIntelligenceReport(investigation_id="fixture-cli", query="fixture.ton")
        service, exporter = self.modules(result)
        args = command_parser().parse_args(["--reexport", "fixture-cli", "--no-pdf"])
        with patch.dict(sys.modules, {service.__name__: service, exporter.__name__: exporter}):
            actual, paths = await run_nft_command(args)
        self.assertIs(actual, result)
        service.investigate_ton_nft.assert_not_awaited()
        service.load_investigation.assert_called_once()
        self.assertIn("html", paths)

    async def test_incremental_requires_existing_id(self):
        result = NFTIntelligenceReport(investigation_id="fixture-cli", query="fixture.ton")
        service, exporter = self.modules(result)
        args = command_parser().parse_args(["--ton-nft", "fixture.ton", "--incremental"])
        with patch.dict(sys.modules, {service.__name__: service, exporter.__name__: exporter}):
            with self.assertRaises(ValueError):
                await run_nft_command(args)
        service.investigate_ton_nft.assert_not_awaited()

    async def test_pdf_failure_retains_dossier_and_reports_renderer_status(self):
        import json
        result = NFTIntelligenceReport(investigation_id="fixture-cli", query="fixture.ton")
        service, exporter = self.modules(result)
        exporter.export_nft_pdf.side_effect = RuntimeError("Chromium unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            with patch.dict(sys.modules, {service.__name__: service, exporter.__name__: exporter}):
                actual, paths = await analyze_and_export_ton_nft("fixture.ton", destination, pdf=True)
            self.assertIs(actual, result)
            self.assertIn("html", paths)
            self.assertNotIn("pdf", paths)
            self.assertEqual(json.loads(paths["pdf_status"].read_text(encoding="utf-8"))["status"], "unavailable")

    async def test_non_ton_report_never_enriches(self):
        from app.models.report import AddressReport
        result = NFTIntelligenceReport(investigation_id="fixture-cli", query="fixture.ton")
        service, exporter = self.modules(result)
        report = AddressReport(target_address="0x" + "1" * 40, detected_chains=["eth"])
        with patch.dict(sys.modules, {service.__name__: service}):
            actual = await enrich_ton_address_report(report)
        self.assertIs(actual, report)
        service.investigate_ton_nft.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
