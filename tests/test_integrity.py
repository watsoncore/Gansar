from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import unittest
from unittest.mock import AsyncMock, patch

from app.aggregator.analyzer import _address_key, _build_counterparties, _dedupe_report, _transaction_sort_key
from app.models.report import AddressReport, TelegramEvidence, TelegramIdentity, TonAsset, TonAssetEvent, Transaction
from app.risk.scoring import score_risk
from app.sources.evm_rpc import EthereumRpcSource
from app.sources.manager import SourceManager, SourcePlan
from app.sources.ton_tonapi import TonApiSource
from app.utils.detect import detect_candidates
from app.utils.event_identity import event_identity
from app.utils.security import safe_public_url, sanitize_observation
from app.utils.telegram_identity import merge_identity
from app.utils.ton_assets import add_asset_event, merge_asset
from app.utils.ton_normalize import parse_ton_address, ton_amount_decimal, ton_canonical_address
from app.utils.ton_normalize import ton_direction

A, B, NFT1, NFT2 = [f"0:{number:064x}" for number in range(1, 5)]


def friendly(number=1, tag=0x11, wc=0):
    body = bytes([tag, wc & 255]) + number.to_bytes(32, "big")
    return base64.urlsafe_b64encode(body + binascii.crc_hqx(body, 0).to_bytes(2, "big")).decode()


def transaction(**changes):
    fields = dict(chain="ton", tx_hash="tx", from_address=A, to_address=B, asset="TON", amount=1, source="one")
    fields.update(changes)
    return Transaction(**fields)


class IntegrityTests(unittest.TestCase):
    def test_ton_crc_flags_workchain(self):
        for tag in (0x11, 0x51, 0x91, 0xd1):
            parsed = parse_ton_address(friendly(tag=tag, wc=-1))
            self.assertEqual(parsed["workchain"], -1)
            self.assertEqual(parsed["test_only"], bool(tag & 0x80))
            self.assertEqual(parsed["bounceable"], tag & 0x7f == 0x11)
        self.assertEqual(ton_canonical_address(friendly()), A)

    def test_ton_bad_crc_tag_length(self):
        valid = friendly()
        self.assertIsNone(parse_ton_address(valid[:-1] + ("A" if valid[-1] != "A" else "B")))
        self.assertIsNone(parse_ton_address(friendly(tag=0x12)))
        self.assertIsNone(parse_ton_address(valid + "A"))
        self.assertNotIn("ton", detect_candidates(friendly(tag=0x12)))

    def test_detector_legacy_chains(self):
        self.assertIn("btc", detect_candidates("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
        self.assertEqual(detect_candidates("0x" + "1" * 40), ["eth"])
        self.assertEqual(detect_candidates(friendly()), ["ton"])

    def test_base58_case_preserved(self):
        self.assertNotEqual(_address_key("solana", "AbC"), _address_key("solana", "abc"))
        self.assertEqual(_address_key("eth", "0xAB"), "0xab")

    def test_multiple_actions_same_hash_remain(self):
        report = AddressReport(target_address=A, transactions=[transaction(raw={"action_index": i, "type": "NftItemTransfer"}) for i in range(2)])
        _dedupe_report(report)
        self.assertEqual(len(report.transactions), 2)
        self.assertNotEqual(report.transactions[0].event_id, report.transactions[1].event_id)

    def test_same_hash_different_contracts_remain(self):
        report = AddressReport(target_address=A, transactions=[transaction(chain="bsc", raw={"type": "bep20_transfer", "contract": f"0x{i:040x}"}) for i in range(2)])
        self.assertEqual(len(_dedupe_report(report).transactions), 2)

    def test_same_event_merges_all_source_raw(self):
        report = AddressReport(target_address=A, transactions=[transaction(raw={"action_index": 0, "provider_only": 1}), transaction(source="two", raw={"action_index": 0, "provider_only": 2, "extra": True})])
        _dedupe_report(report)
        self.assertEqual(len(report.transactions), 1)
        self.assertEqual({p["source"] for p in report.transactions[0].provenance}, {"one", "two"})
        self.assertEqual({p["raw"]["provider_only"] for p in report.transactions[0].provenance}, {1, 2})

    def test_nft_title_is_not_identity(self):
        report = AddressReport(target_address=A, ton_assets=[TonAsset(asset_id=nft, type="gift", title="Same title", source="provider") for nft in (NFT1, NFT2)])
        self.assertEqual(len(_dedupe_report(report).ton_assets), 2)

    def test_current_owner_not_replaced_by_historical_hint(self):
        report = AddressReport(target_address=A)
        merge_asset(report, TonAsset(asset_id=NFT1, type="nft", owner_address=B, ownership_status="current", source="state"))
        merge_asset(report, TonAsset(asset_id=NFT1, type="nft", owner_address=A, ownership_status="historical", source="history"))
        self.assertEqual(report.ton_assets[0].owner_address, B)
        self.assertEqual(report.ton_assets[0].ownership_status, "current")
        self.assertEqual({p["source"] for p in report.ton_assets[0].provenance}, {"state", "history"})

    def test_asset_action_identity_and_provenance(self):
        asset = TonAsset(asset_id=NFT1, type="nft", source="state")
        for index in range(2):
            add_asset_event(asset, TonAssetEvent(event_type="transfer", tx_hash="same", action_index=index, from_address=A, to_address=B, source="one", success=True))
        add_asset_event(asset, TonAssetEvent(event_type="transfer", tx_hash="same", action_index=0, from_address=A, to_address=B, source="two", success=True))
        self.assertEqual(len(asset.history_events), 2)
        self.assertEqual(len(asset.history_events[0].provenance), 2)

    def test_failed_sale_listing_are_not_completed_sale(self):
        asset = TonAsset(asset_id=NFT1, type="nft", source="state")
        add_asset_event(asset, TonAssetEvent(event_type="listing", tx_hash="listing", price=4, source="page"))
        add_asset_event(asset, TonAssetEvent(event_type="sale", tx_hash="failed", price=5, success=False, from_address=A, source="api"))
        self.assertIsNone(asset.last_sale_price)
        self.assertEqual(asset.previous_owners, [])
        self.assertEqual(asset.sale_history, [])
        self.assertEqual(len(asset.history_events), 2)

    def test_identity_metadata_never_confirms_person(self):
        evidence = TelegramEvidence(source="page", confidence="confirmed")
        identity = TelegramIdentity(wallet_address=A, username="example", confidence="confirmed", source="page", evidence=[evidence])
        self.assertEqual(evidence.confidence, "weak")
        self.assertEqual(identity.confidence, "weak")
        self.assertFalse(identity.identity_verified)

    def test_repeated_upstream_does_not_upgrade_identity(self):
        report = AddressReport(target_address=A)
        for parser in ("tonapi", "tonviewer"):
            merge_identity(report, TelegramIdentity(wallet_address=A, username="example", confidence="weak", source=parser, evidence=[TelegramEvidence(source=parser, upstream="tonapi", confidence="weak")]))
        _dedupe_report(report)
        self.assertEqual(report.telegram_identities[0].confidence, "weak")

    def test_financial_summaries_do_not_sum_token_units(self):
        report = AddressReport(target_address=A, transactions=[transaction(asset="TON", amount=2, direction="out"), transaction(asset="USDT", amount=3, direction="out", raw={"contract": NFT1})])
        counterparty = _build_counterparties(report)[0]
        self.assertFalse(counterparty.aggregate_amount_valid)
        self.assertEqual(counterparty.total_out, 0)
        self.assertEqual(sum(v["out"] for v in counterparty.amounts_by_asset.values()), Decimal(5))
        self.assertEqual(len(counterparty.amounts_by_asset), 2)

    def test_decimal_sums_and_base_units(self):
        report = AddressReport(target_address=A, transactions=[transaction(amount_decimal=Decimal("0.1")), transaction(tx_hash="two", amount_decimal=Decimal("0.2"))])
        self.assertEqual(next(iter(_build_counterparties(report)[0].amounts_by_asset.values()))["out"], Decimal("0.3"))
        self.assertEqual(ton_amount_decimal("123456789012345678901", 9), Decimal("123456789012.345678901"))
        enormous = 2**256 - 1
        exact = ton_amount_decimal(str(enormous), 18)
        self.assertEqual(exact.as_tuple().digits, tuple(int(c) for c in str(enormous)))
        self.assertEqual(exact.as_tuple().exponent, -18)

    def test_hash_representation_normalization(self):
        digest = bytes(range(32))
        self.assertEqual(event_identity(transaction(tx_hash=digest.hex())), event_identity(transaction(tx_hash=base64.b64encode(digest).decode())))

    def test_failed_and_approval_rows_not_money(self):
        report = AddressReport(target_address=A, transactions=[transaction(success=False), transaction(raw={"type": "approval"})])
        self.assertEqual(_build_counterparties(report), [])

    def test_undated_sort_last_and_lt_tiebreak(self):
        now = datetime.now(timezone.utc)
        rows = [transaction(timestamp=None), transaction(timestamp=now, raw={"lt": 2}), transaction(timestamp=now, raw={"lt": 1})]
        rows.sort(key=_transaction_sort_key, reverse=True)
        self.assertIsNone(rows[-1].timestamp)
        self.assertEqual(rows[0].raw["lt"], 2)

    def test_circuit_breaker_recovers(self):
        manager = SourceManager({"test": SourcePlan("test", 1, 1)})
        for _ in range(3):
            manager.record_fail("test")
        self.assertFalse(manager.should_run("test", 1))
        manager.plan("test", 1).last_fail -= timedelta(seconds=61)
        self.assertTrue(manager.should_run("test", 1))
        self.assertFalse(manager.should_run("test", 1))
        manager.record_success("test")
        self.assertTrue(manager.should_run("test", 1))

    def test_secret_and_url_boundaries(self):
        raw = sanitize_observation({"Authorization": "Bearer fixture_secret", "nested": {"api_key": "fixture_secret"}, "url": "https://user:fixture_secret@example.org/a?apikey=fixture_secret&q=nft"})
        self.assertNotIn("fixture_secret", str(raw))
        for url in ("javascript:alert(1)", "data:text/html,test", "http://127.0.0.1/a", "http://[::1]", "https://localhost/a", "https://user:pass@example.org", "http://0177.0.0.1", "http://0x7f.0.0.1", "http://127.1", "http://%31%32%37.0.0.1", "http://１２７.０.０.１"):
            self.assertIsNone(safe_public_url(url))
        self.assertEqual(safe_public_url("https://example.org/nft"), "https://example.org/nft")

    def test_report_model_redacts_credentials(self):
        row = transaction(raw={"authClientToken": "fixture_secret"}, url="https://example.org?api_key=fixture_secret")
        self.assertNotIn("fixture_secret", row.model_dump_json())


class ProviderIntegrityTests(unittest.IsolatedAsyncioTestCase):
    async def test_tonapi_two_actions_shadowing_regression(self):
        source, report = TonApiSource(1), AddressReport(target_address=A)
        actions = [{"type": "NftItemTransfer", "status": "ok", "NftItemTransfer": {"sender": {"address": A}, "recipient": {"address": B}, "nft": nft}} for nft in (NFT1, NFT2)]
        source._parse_events(A, report, [{"event_id": "same", "lt": 1, "timestamp": 1700000000, "actions": actions}], "https://tonapi.io/events")
        _dedupe_report(report)
        self.assertEqual(len(report.transactions), 2)
        self.assertEqual(len(report.ton_assets), 2)
        self.assertEqual(report.errors, [])
        self.assertTrue(all(a.ownership_status == "historical" and not a.owner_address for a in report.ton_assets))

    async def test_auction_bid_is_not_sale(self):
        source, report = TonApiSource(1), AddressReport(target_address=A)
        source._parse_events(A, report, [{"event_id": "bid", "actions": [{"type": "AuctionBid", "status": "ok", "AuctionBid": {"nft": NFT1, "sender": A, "recipient": B, "amount": "5000000000"}}]}], "https://tonapi.io/events")
        self.assertEqual(report.ton_assets[0].history_events[0].event_type, "interaction")
        self.assertEqual(report.ton_assets[0].sale_history, [])

    async def test_tonapi_page_failure_retains_previous_records(self):
        source, report = TonApiSource(1), AddressReport(target_address=A)
        event = {"event_id": "one", "lt": 1, "actions": [{"type": "TonTransfer", "status": "ok", "TonTransfer": {"sender": A, "recipient": B, "amount": 1}}]}
        with patch.object(source, "_get_json", AsyncMock(side_effect=[{"events": [event] * 100, "next_from": "1"}, {}])):
            await source._fetch_events(A, report)
        self.assertEqual(len(report.transactions), 100)

    async def test_jsonrpc_error_not_zero_balance(self):
        with patch("app.sources.evm_rpc.request_json", AsyncMock(return_value={"jsonrpc": "2.0", "error": {"code": -32000}})):
            report = await EthereumRpcSource(1).fetch("0x" + "1" * 40)
        self.assertEqual(report.balances, [])
        self.assertTrue(any("JSON-RPC" in e for e in report.errors))

    async def test_native_ton_messages_same_hash_remain_distinct(self):
        source, report = TonApiSource(1), AddressReport(target_address=A)
        source._parse_transactions(A, report, [{"hash": "native", "lt": "100", "account": A, "in_msg": {"source": B, "destination": A, "value": "10"}, "out_msgs": [{"destination": B, "value": "20"}, {"destination": B, "value": "20"}]}])
        _dedupe_report(report)
        self.assertEqual(len(report.transactions), 3)
        self.assertEqual({t.tx_hash for t in report.transactions}, {"native"})
        self.assertEqual(len({t.event_id for t in report.transactions}), 3)

    async def test_deadline_preserves_partial_source_records(self):
        import app.aggregator.analyzer as analyzer
        classes = [analyzer.TonApiSource, analyzer.TonviewerPublicSource, analyzer.TonCenterSource, analyzer.TonCenterV3Source, analyzer.TonscanPublicSource, analyzer.DtonPublicSource, analyzer.TelegramIdentitySource, analyzer.FragmentPublicSource, analyzer.GetgemsPublicSource]
        async def empty(self, address):
            return AddressReport(target_address=address)
        async def slow(self, address):
            self._partial_report = AddressReport(target_address=address, transactions=[transaction(direction="out", raw={"message_index": 0})])
            await __import__('asyncio').sleep(1)
            return self._partial_report
        from contextlib import ExitStack
        with ExitStack() as stack:
            for cls in classes:
                stack.enter_context(patch.object(cls, "fetch", slow if cls is analyzer.TonApiSource else empty))
            stack.enter_context(patch.object(analyzer, "_source_budget", return_value=0.015))
            stack.enter_context(patch.object(analyzer, "_tonconsole_available", return_value=False))
            stack.enter_context(patch.object(analyzer, "SOURCE_MANAGER", __import__('app.sources.manager', fromlist=['build_default_source_manager']).build_default_source_manager()))
            report, graph = await analyzer.analyze_address(A, selected_chains=["ton"])
        self.assertEqual(len(report.transactions), 1)
        self.assertTrue(any("retained" in error for error in report.errors))
        self.assertTrue(any(h.source == "tonapi" and h.status == "partial" for h in report.source_health))

    async def test_jetton_zero_decimals_preserved(self):
        source, report = TonApiSource(1), AddressReport(target_address=A)
        payload = {"balances": [{"balance": "5", "jetton": {"address": NFT1, "symbol": "UNIT", "decimals": 0}}]}
        with patch.object(source, "_get_json", AsyncMock(return_value=payload)):
            await source._fetch_jettons(A, report)
        self.assertEqual(report.tokens[0].amount_decimal, Decimal(5))
        self.assertEqual(report.tokens[0].amount, 5)


if __name__ == "__main__":
    unittest.main()
