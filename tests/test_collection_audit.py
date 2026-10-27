from __future__ import annotations

import asyncio
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from app.aggregator import analyzer
from app.aggregator.collection_audit import identity_counts, refresh_audit, transaction_digest
from app.models.report import AddressReport, Transaction
from app.sources.ton_tonapi import TonApiSource
from app.sources.ton_toncenter_v3 import TonCenterV3Source

A, B = (f"0:{n:064x}" for n in (1, 2))


def operation(i=0, **changes):
    return Transaction(**{**dict(chain="ton", tx_hash=f"{i:064x}", from_address=A, to_address=B,
        asset="TON", amount=1, source="tonapi", raw={"lt": i, "message_index": "in"}), **changes})


class AuditIdentityTests(unittest.TestCase):
    def test_physical_message_is_not_two_payments_on_different_accounts(self):
        rows = [operation(1, raw={"message_index": 0, "message": {"hash": "a" * 64}}),
                operation(2, source="toncenter_v3", raw={"message_index": "in", "transaction": {"in_msg": {"hash": "a" * 64}}})]
        report = analyzer._dedupe_report(AddressReport(target_address=A, transactions=rows))
        self.assertEqual(len(report.transactions), 1)
        self.assertEqual({p["source"] for p in report.transactions[0].provenance}, {"tonapi", "toncenter_v3"})
        self.assertEqual(report.collection_audit["duplicates"][0]["observations"], 2)
        self.assertIn("ton:message:" + "a" * 64, report.collection_audit["duplicates"][0]["identity"])

    def test_identical_amounts_different_message_hashes_remain(self):
        rows = [operation(1, raw={"message_index": index, "message": {"hash": value * 64}}) for index, value in enumerate("ab")]
        self.assertEqual(len(analyzer._dedupe_report(AddressReport(target_address=A, transactions=rows)).transactions), 2)

    def test_undecoded_observation_retained_without_inventing_parties(self):
        report = analyzer._dedupe_report(AddressReport(target_address=A, transactions=[operation(from_address=None, to_address=None)]))
        self.assertEqual(len(report.transactions), 1)
        self.assertIsNone(report.transactions[0].from_address)

    def test_typed_counts_do_not_call_nft_history_wallet_transactions(self):
        rows = [operation(1, raw={"message_index": "in", "transaction": {"in_msg": {"hash": "a" * 64}}}),
                operation(2, raw={"nft_event_id": "event1", "nft_intelligence": {"event_type": "transfer"}}),
                operation(3, raw={"action_index": 0, "provider": "tonapi_events"})]
        counts = identity_counts(rows)
        self.assertEqual(counts["operation_records"], 3)
        self.assertEqual(counts["unique_account_transactions"], 1)
        self.assertEqual(counts["referenced_transaction_hashes_from_actions"], 2)
        self.assertEqual(counts["nft_history_events"], 1)

    def test_digest_survives_snapshot_round_trip_and_reordering(self):
        report = AddressReport(target_address=A, transactions=[operation(i) for i in range(3)])
        refresh_audit(report, "snapshot")
        restored = AddressReport.model_validate_json(report.model_dump_json())
        restored.transactions.reverse()
        self.assertEqual(transaction_digest(restored.transactions), report.collection_audit["stages"]["snapshot"]["event_ids_sha256"])

    def test_parser_preserves_batch_with_more_than_twelve_messages(self):
        source, report = TonApiSource(1), AddressReport(target_address=A)
        source._parse_transactions(A, report, [{"hash": "1" * 64, "lt": 1, "in_msg": {"destination": A},
            "out_msgs": [{"destination": B, "value": str(i), "hash": f"{i+20:064x}"} for i in range(30)]}])
        self.assertEqual(len(report.transactions), 31)

    def test_action_identity_does_not_depend_on_page_position(self):
        from app.utils.event_identity import event_identity, address_key
        rows = [operation(1, raw={"asset_type": "action", "action_index": i, "action": {"action_id": "stable-action"}}) for i in (0, 49)]
        self.assertEqual(event_identity(rows[0]), event_identity(rows[1]))
        self.assertEqual(address_key("ton", A), A)


class AuditCollectionTests(unittest.IsolatedAsyncioTestCase):
    def collector_patches(self, fetch):
        stack = ExitStack()
        async def empty(self, address):
            return AddressReport(target_address=address)
        for name, cls in vars(analyzer).items():
            if isinstance(cls, type) and name.endswith("Source") and hasattr(cls, "fetch"):
                stack.enter_context(patch.object(cls, "fetch", fetch if cls is analyzer.TonApiSource else empty))
        return stack

    async def test_display_hint_never_truncates_collected_model(self):
        async def collected(self, address):
            return AddressReport(target_address=address, transactions=[operation(i) for i in range(40)])
        with self.collector_patches(collected):
            report, graph = await analyzer.analyze_address(A, selected_chains=["ton"], max_txs=3)
        self.assertEqual(len(report.transactions), 40)
        self.assertEqual(report.coverage["transactions"]["discarded_by_display_limit"], 0)
        self.assertEqual(report.collection_audit["stages"]["model"]["records"], 40)

    async def test_checkpoint_while_collector_still_running_and_final_superset(self):
        snapshots = []
        async def progressive(self, address):
            self._partial_report = AddressReport(target_address=address, transactions=[operation(1)])
            await asyncio.sleep(.08)
            self._partial_report.transactions.append(operation(2))
            return self._partial_report
        async def save(report):
            snapshots.append(report)
        with self.collector_patches(progressive):
            report, _ = await analyzer.analyze_address(A, selected_chains=["ton"], continuous=True, on_checkpoint=save, checkpoint_interval=.02)
        self.assertTrue(any(len(r.transactions) == 1 for r in snapshots))
        self.assertEqual(len(report.transactions), 2)
        self.assertTrue(all(set(t.event_id for t in r.transactions) <= set(t.event_id for t in report.transactions) for r in snapshots))

    async def test_cooperative_cancel_retains_current_source_records(self):
        started = asyncio.Event()
        async def progressive(self, address):
            self._partial_report = AddressReport(target_address=address, transactions=[operation(1)])
            started.set()
            await asyncio.sleep(60)
        with self.collector_patches(progressive):
            task = asyncio.create_task(analyzer.analyze_address(A, selected_chains=["ton"], continuous=True))
            await started.wait()
            task.cancel()
            report, _ = await asyncio.wait_for(task, 2)
        self.assertEqual(len(report.transactions), 1)
        self.assertTrue(any("stopped" in warning for warning in report.warnings))

    async def test_toncenter_resumes_saved_page_offset_instead_of_first_page(self):
        source, report = TonCenterV3Source(1), AddressReport(target_address=A)
        source._continuous = True
        source._resume_state = {"account_transactions": {"pages": 2, "raw_records": 100, "next_cursor": {"offset": 100}, "exhausted": False}}
        row = {"hash": "a" * 64, "lt": "100", "in_msg": {"source": B, "destination": A, "value": "1"}}
        with patch.object(source, "_get", AsyncMock(return_value={"transactions": [row]})) as request:
            await source._transactions(None, A, report)
        self.assertEqual(request.await_args.args[2]["offset"], 100)
        state = report.collection_audit["streams"][source.name]["account_transactions"]
        self.assertEqual(state["pages"], 3)
        self.assertEqual(state["raw_records"], 101)
        self.assertTrue(state["exhausted"])
        self.assertEqual(len(report.transactions), 1)

    async def test_repeated_provider_page_preserves_cursor_and_does_not_loop(self):
        source, report = TonCenterV3Source(1), AddressReport(target_address=A)
        source._continuous = True
        rows = [{"hash": f"{i:064x}", "lt": str(i), "in_msg": {"source": B, "destination": A}} for i in range(50)]
        with patch.object(source, "_get", AsyncMock(return_value={"transactions": rows})) as request:
            await source._transactions(None, A, report)
        self.assertEqual(request.await_count, 2)
        self.assertEqual(len(report.transactions), 50)
        state = report.collection_audit["streams"][source.name]["account_transactions"]
        self.assertFalse(state["exhausted"])
        self.assertEqual(state["stop_reason"], "repeated_page")

    async def test_malformed_page_does_not_claim_endpoint_exhaustion(self):
        source, report = TonCenterV3Source(1), AddressReport(target_address=A)
        with patch.object(source, "_get", AsyncMock(return_value={"error": "upstream malformed"})):
            await source._transactions(None, A, report)
        state = report.collection_audit["streams"][source.name]["account_transactions"]
        self.assertFalse(state["exhausted"])
        self.assertEqual(state["stop_reason"], "malformed_page")

    async def test_incremental_toncenter_head_joins_history_and_keeps_tail(self):
        source, report = TonCenterV3Source(1), AddressReport(target_address=A)
        source._continuous = source._incremental = True
        source._known_records = {"account_transactions": {"a" * 64}}
        source._known_boundaries = {"account_transactions": 100}
        source._resume_state = {"account_transactions": {"pages": 2, "raw_records": 100, "next_cursor": {"offset": 100}, "exhausted": False}}
        def row(digest, lt):
            return {"hash": digest * 64, "lt": lt, "in_msg": {"source": B, "destination": A, "value": "1"}}
        with patch.object(source, "_get", AsyncMock(side_effect=[{"transactions": [row("b", 101), row("a", 100)]}, {"transactions": [row("c", 1)]}])) as request:
            await source._transactions(None, A, report)
        self.assertEqual([call.args[2]["offset"] for call in request.await_args_list], [0, 101])
        self.assertEqual(len(report.transactions), 3)
        streams = report.collection_audit["streams"][source.name]
        self.assertEqual(streams["account_transactions_refresh"]["stop_reason"], "overlap_stored_history")
        self.assertTrue(streams["account_transactions"]["exhausted"])

    async def test_real_analyzer_collector_path_with_initial_snapshot_and_incremental(self):
        # Production parser + collector + analyzer + model, with only network
        # transport replaced. This is a regression test, never a live claim.
        actual_fetch = TonApiSource.fetch
        old = {"hash": "a" * 64, "lt": 100, "in_msg": {"source": B, "destination": A, "value": "1"}}
        new = {"hash": "b" * 64, "lt": 101, "in_msg": {"source": B, "destination": A, "value": "2"}}
        tail = {"hash": "c" * 64, "lt": 49, "in_msg": {"source": B, "destination": A, "value": "3"}}
        initial = AddressReport(target_address=A)
        TonApiSource(1)._parse_transactions(A, initial, [old])
        initial.collection_audit = {"streams": {"tonapi": {"account_transactions": {"pages": 1, "raw_records": 50, "next_cursor": "50", "exhausted": False}, "account_events": {"pages": 1, "raw_records": 0, "exhausted": True}}}}
        calls, checkpoints = [], []
        async def transport(self, client, url, out, label, params=None, retries=2):
            if label == "txs":
                calls.append((params or {}).get("before_lt"))
                await asyncio.sleep(.03)
                return {"transactions": [tail] if params.get("before_lt") == "50" else [new, old]}
            return {"account": {"balance": 0}, "nfts": {"nft_items": []}, "jettons": {"balances": []}, "events": {"events": []}, "dns": {"domains": []}}[label]
        with self.collector_patches(actual_fetch), patch.object(TonApiSource, "_get_json", transport):
            report, graph = await analyzer.analyze_address(A, selected_chains=["ton"], continuous=True, incremental=True,
                initial_report=initial, max_txs=1, on_checkpoint=lambda value: checkpoints.append(value), checkpoint_interval=.02)
        self.assertEqual(calls, [None, "50"])
        self.assertEqual(len(initial.transactions), 1)
        self.assertEqual(len(report.transactions), 3)
        self.assertTrue(checkpoints)
        self.assertEqual(report.collection_audit["streams"]["tonapi"]["account_transactions_refresh"]["stop_reason"], "overlap_stored_history")


if __name__ == "__main__":
    unittest.main()
