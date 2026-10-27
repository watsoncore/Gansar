"""Deterministic provider fixtures. These tests do not contact any network."""
from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest

from app.ton_nft.analytics import (analyze_report, canonical_hash, event_identity,
                                  event_sort_key, money_from_price)
from app.ton_nft.discovery import (KNOWN_COLLECTIONS, is_nft_query, normalize_nft_query,
                                  registry_entry)
from app.ton_nft.models import *
from app.ton_nft.protocol import (collection_data, content_uri, nft_data, stack_address,
                                 ton_dns_item_index)
from app.ton_nft.providers import (Payload, ProviderError, TelegramPublicProvider,
                                  TonAPIProvider, ToncenterProvider)
from app.ton_nft.service import (NFTInvestigator, investigate_ton_nft, report_to_address_report,
                                 resolve_verified_nft_owner)
from app.ton_nft.storage import InvestigationStore, load_investigation
from app.ton_nft.storage import validate_investigation_id
from app.utils.ton_normalize import ton_canonical_address


ITEM = "0:" + "a1"*32
ITEM2 = "0:" + "a2"*32
OWNER = "0:" + "b1"*32
OLD = "0:" + "b2"*32
OTHER = "0:" + "b3"*32
COLLECTION = ton_canonical_address(KNOWN_COLLECTIONS["domain"]["address"])
USERNAME_COLLECTION = ton_canonical_address(KNOWN_COLLECTIONS["username"]["address"])
TX = "c1"*32
TRACE = "c2"*32


def cell_boc(bits: str) -> str:
    bitlen = len(bits)
    padded = bits + ("1" + "0" * ((-bitlen-1) % 8) if bitlen % 8 else "")
    data = int(padded or "0", 2).to_bytes(len(padded)//8, "big") if padded else b""
    cell = bytes([0, bitlen//8 + (bitlen+7)//8]) + data
    return base64.b64encode(bytes.fromhex("b5ee9c72") + bytes([1, 1, 1, 1, 0, len(cell), 0]) + cell).decode()


def address_cell(address: str | None) -> dict:
    if address is None:
        return {"bytes": cell_boc("00")}
    wc, raw = address.split(":")
    bits = "100" + f"{int(wc) & 255:08b}" + f"{int(raw,16):0256b}"
    return {"bytes": cell_boc(bits)}


def getter(index=1, collection=COLLECTION, owner=OWNER, initialized=True):
    return {"exit_code": 0, "stack": [["num", "-0x1" if initialized else "0x0"], ["num", hex(index)],
            ["cell", address_cell(collection)], ["cell", address_cell(owner)],
            ["cell", {"bytes": cell_boc("")}]], "block_id": {"seqno": 123}}


def indexed_item(address=ITEM, owner=OWNER, collection=COLLECTION, index=None, name="fixture.ton"):
    if index is None:
        index = ton_dns_item_index(name) if name.endswith(".ton") and name.count(".") == 1 else 1
    return {"address": address, "owner_address": owner, "collection_address": collection, "index": str(index),
            "init": True, "content": {"name": name, "unknown_fixture_field": {"preserved": True}},
            "code_hash": "fixture-code-hash", "unknown_provider_field": {"value": 42}}


def transfer(address=ITEM, old=OLD, new=OWNER, lt=100, tx=TX, query_id="7", aborted=False):
    return {"nft_address": address, "nft_collection": COLLECTION, "old_owner": old, "new_owner": new,
            "transaction_hash": tx, "transaction_lt": str(lt), "transaction_now": 1700000000+lt,
            "transaction_aborted": aborted, "query_id": query_id, "forward_amount": "1", "trace_id": TRACE}


def action_event(actions, lt=100, trace=TRACE):
    return {"event_id": trace, "lt": lt, "timestamp": 1700000000+lt, "in_progress": False, "actions": actions}


def transfer_action(address=ITEM, old=OLD, new=OWNER, tx=TX):
    return {"type": "NftItemTransfer", "status": "ok", "NftItemTransfer": {"nft": address,
        "sender": {"address": old}, "recipient": {"address": new}}, "base_transactions": [tx]}


class FakeToncenter(ToncenterProvider):
    public_rate_limit = 20
    def __init__(self, items=None, transfers=None, domains=None, *, fail_offset=None, mismatch=False, getter_error=False):
        super().__init__()
        self.items_data = items if items is not None else [indexed_item()]
        self.transfers_data = transfers if transfers is not None else [transfer()]
        self.domains = domains if domains is not None else {"fixture.ton": ITEM}
        self.fail_offset, self.mismatch, self.getter_error = fail_offset, mismatch, getter_error
        self.calls = []

    async def request(self, path, *, params, body, timeout, retries, fresh):
        self.calls.append((path, params, body))
        if path.endswith("dns/records"):
            item = self.domains.get(params["domain"])
            return {"records": [{"domain": params["domain"], "nft_item_address": item, "dns_wallet": OTHER}] if item else []}
        if path.endswith("nft/items"):
            rows = self.items_data
            if "address" in params:
                rows = [r for r in rows if r["address"] == params["address"]]
            if "owner_address" in params:
                rows = [r for r in rows if r["owner_address"] == params["owner_address"] or r.get("real_owner") == params["owner_address"]]
            if "collection_address" in params:
                rows = [r for r in rows if r["collection_address"] == params["collection_address"]]
            offset = params.get("offset", 0)
            return {"nft_items": rows[offset:offset+params["limit"]]}
        if path.endswith("nft/collections"):
            col = params["collection_address"]
            return {"nft_collections": [{"address": col, "next_item_index": "2", "collection_content": {"name": "Fixture collection"}}]}
        if path.endswith("nft/transfers"):
            offset = params["offset"]
            if offset == self.fail_offset:
                raise RuntimeError("fixture transport failure")
            rows = self.transfers_data
            if "item_address" in params:
                rows = [r for r in rows if r["nft_address"] == params["item_address"]]
            if "owner_address" in params:
                rows = [r for r in rows if params["owner_address"] in (r["old_owner"], r["new_owner"])]
            return {"nft_transfers": rows[offset:offset+params["limit"]]}
        if path.endswith("/transactions"):
            row = next((r for r in self.transfers_data if canonical_hash(r["transaction_hash"]) == params["hash"]), None)
            return {"transactions": [{"hash": params["hash"], "account": row["nft_address"],
                "lt": row["transaction_lt"], "total_fees": "12345", "description": {"aborted": row["transaction_aborted"]},
                "emulated": False, "block_ref": {"seqno": 123, "workchain": 0}, "out_msgs": [],
                "in_msg": {"hash": "ef"*32, "opcode": 0x5fcc3d14}}] if row else []}
        if path.endswith("nft/sales"):
            return {"nft_sales": [{"address": params["address"], "nft_address": ITEM,
                "nft_owner_address": OWNER, "marketplace_address": OLD, "type": "sale", "details": {"fixture_field": "preserved"}}]}
        if path.endswith("runGetMethod"):
            method, address = body["method"], body["address"]
            row = next((r for r in self.items_data if r["address"] == address), None)
            if method == "get_nft_data":
                if row is None or self.getter_error:
                    return {"ok": True, "result": {"exit_code": -13, "stack": []}}
                return {"ok": True, "result": getter(int(row["index"]), row["collection_address"], row["owner_address"])}
            if method == "get_collection_data":
                return {"ok": True, "result": {"exit_code": 0, "stack": [["num", "0x2"], ["cell", {"bytes": cell_boc("")}], ["cell", address_cell(None)]]}}
            if method == "get_nft_address_by_index":
                index = int(body["stack"][0][1])
                resolved = next((r["address"] for r in self.items_data if int(r["index"]) == index and r["collection_address"] == address), ITEM2)
                return {"ok": True, "result": {"exit_code": 0, "stack": [["cell", address_cell(ITEM2 if self.mismatch else resolved)]]}}
            if method == "get_nft_content":
                return {"ok": True, "result": {"exit_code": 0, "stack": [["cell", {"bytes": cell_boc("")}]]}}
        raise AssertionError("unexpected fixture endpoint " + path)


class FakeTonAPI(TonAPIProvider):
    public_rate_limit = 20
    def __init__(self, items=None, events=None, operations=None):
        super().__init__()
        self.items_data = items if items is not None else [indexed_item()]
        self.events_data = events if events is not None else []
        self.operations_data = operations if operations is not None else []

    async def request(self, path, *, params, body, timeout, retries, fresh):
        if path.startswith("/blockchain/accounts/") and "/methods/" in path:
            return {"success": False, "exit_code": -13, "stack": []}
        if path.startswith("/dns/"):
            return {"name": path.split("/")[-1]}
        if path.startswith("/accounts/") and path.count("/") == 2:
            return {"address": path.split("/")[-1], "status": "active", "is_wallet": True, "interfaces": ["wallet_v4r2"]}
        if path.endswith("/nfts/history"):
            rows = [r for r in self.operations_data if not params.get("before_lt") or r["lt"] < params["before_lt"]]
            selected = rows[:params["limit"]]
            return {"operations": selected, "next_from": selected[-1]["lt"] if len(selected) == params["limit"] else 0}
        if path.endswith("/events"):
            rows = [r for r in self.events_data if not params.get("before_lt") or r["lt"] < params["before_lt"]]
            selected = rows[:params["limit"]]
            return {"events": selected, "next_from": selected[-1]["lt"] if len(selected) == params["limit"] else 0}
        if path.startswith("/nfts/collections/") and not path.endswith("/items"):
            return {"address": path.split("/")[-1], "metadata": {"name": "Fixture collection"}}
        if path.endswith("/items") or path.endswith("/nfts"):
            rows = self.items_data
            return {"nft_items": [self.as_tonapi(r) for r in rows[params["offset"]:params["offset"]+params["limit"]]]}
        if path.startswith("/nfts/"):
            row = next((r for r in self.items_data if r["address"] == path.split("/")[-1]), None)
            return self.as_tonapi(row) if row else {}
        raise AssertionError("unexpected fixture endpoint " + path)

    @staticmethod
    def as_tonapi(row):
        return {"address": row["address"], "index": int(row["index"]), "owner": {"address": row["owner_address"]},
                "collection": {"address": row["collection_address"]}, "metadata": row["content"], "verified": True}


class FakeTelegram(TelegramPublicProvider):
    public_rate_limit = 20
    def __init__(self, html=""):
        super().__init__()
        self.html = html

    async def request(self, *args, **kwargs):
        return {"html": self.html}


def budget(**kwargs):
    return InvestigationBudget(requests_per_second=20, retries=0, max_seconds=30, **kwargs)


class ProtocolTests(unittest.TestCase):
    def test_domain_is_nft_input(self):
        query = normalize_nft_query("solvnox.ton")
        self.assertEqual((query.kind, query.scope), ("domain", "item"))

    def test_usernames_normalize_exactly(self):
        for value in ("@Fixture", "fixture.t.me", "https://t.me/fixture", "https://fragment.com/username/fixture"):
            self.assertEqual(normalize_nft_query(value).value, "fixture.t.me")

    def test_gift_url_is_distinct(self):
        query = normalize_nft_query("https://t.me/nft/LolPops-42")
        self.assertEqual((query.kind, query.gift_slug, query.gift_number), ("gift", "lolpops", "42"))

    def test_gram_address_formats_validate_exact_contract_without_assuming_wallet(self):
        for prefix in ("https://gram.org/address/", "gram.org/address/", "https://www.gram.org/address/"):
            query = normalize_nft_query(prefix + ITEM)
            self.assertEqual((query.kind, query.scope, query.value), ("address", "auto", ITEM))
        for suffix in ("not-an-address", ITEM + "/" + ITEM2):
            with self.assertRaises(ValueError):
                normalize_nft_query("https://gram.org/address/" + suffix)

    def test_exact_bare_gift_identifier_normalizes_without_fuzzy_name_match(self):
        query = normalize_nft_query("LolPop-123")
        self.assertEqual((query.kind, query.gift_slug, query.gift_number), ("gift", "lolpop", "123"))
        self.assertEqual(query.public_url, "https://t.me/nft/LolPop-123")
        self.assertEqual(normalize_nft_query("Some similar NFT").kind, "name")

    def test_reject_unsupported_host(self):
        with self.assertRaises(ValueError):
            normalize_nft_query("https://127.0.0.1/nft/abc")

    def test_address_decode(self):
        self.assertEqual(stack_address(["cell", address_cell(OWNER)]), OWNER)

    def test_getter_preserves_256bit_index(self):
        index = 2**255+12345678
        self.assertEqual(nft_data(getter(index=index))["index"], index)

    def test_collection_non_enumerable_index(self):
        result = {"stack": [["num", "-0x1"], ["cell", {"bytes": cell_boc("")}], ["cell", address_cell(None)]]}
        self.assertEqual(collection_data(result)["next_item_index"], -1)

    def test_dns_index_matches_public_getter_fixture(self):
        self.assertEqual(hex(ton_dns_item_index("wallet.ton")), "0xffcac07fcb7837c008ad903aa407cd70646f26b24d5d4b469a8105330545d564")

    def test_dns_subdomain_not_guessed(self):
        with self.assertRaises(ValueError):
            ton_dns_item_index("some.custom.ton")

    def test_decimal_preserves_base_units(self):
        amount = 10**50+123
        money = money_from_price(str(amount), default_currency="TON", default_decimals=9)
        self.assertEqual(money.base_units, amount)
        self.assertEqual(str(money.amount), "100000000000000000000000000000000000000000.000000123")

    def test_unknown_decimals_not_invented(self):
        self.assertIsNone(money_from_price({"currency": "JETTON", "value": "123"}).amount)

    def test_tx_hash_formats_canonical(self):
        self.assertEqual(canonical_hash(base64.b64encode(bytes.fromhex(TX)).decode()), TX)

    def test_event_ids_preserve_same_hash_actions(self):
        a = event_identity("tonapi", ITEM, "transfer", transaction_hash=TX, action_index=0)
        b = event_identity("tonapi", ITEM, "transfer", transaction_hash=TX, action_index=1)
        self.assertNotEqual(a, b)

    def test_event_ids_namespace_assets(self):
        self.assertNotEqual(event_identity("x", ITEM, "transfer", transaction_hash=TX), event_identity("x", ITEM2, "transfer", transaction_hash=TX))

    def test_no_name_fuzzy_resolution(self):
        self.assertEqual(normalize_nft_query("A similar NFT name").kind, "name")

    def test_chain_native_order_undated_last(self):
        events = [NFTEvent(event_id=str(i), asset_address=ITEM, event_type="transfer", logical_time=lt) for i, lt in enumerate([None, 50, 3])]
        self.assertEqual([e.logical_time for e in sorted(events, key=event_sort_key)], [3, 50, None])

    def test_investigation_path_names_rejected(self):
        for value in (".", "..", "CON", "nul.txt", "COM1", "LPT9", "fixture."):
            with self.assertRaises(ValueError):
                validate_investigation_id(value)

    def test_bad_boc_does_not_decode_address(self):
        with self.assertRaises(ValueError):
            stack_address(["cell", {"bytes": "not-a-boc"}])


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)/"fixture.sqlite3"

    def tearDown(self):
        self.temp.cleanup()

    async def investigate(self, query="fixture.ton", *, tc=None, ta=None, **kwargs):
        return await investigate_ton_nft(query, store_path=self.path,
            providers={"toncenter": tc or FakeToncenter(), "tonapi": ta or FakeTonAPI(), "telegram_public": FakeTelegram()},
            budget=kwargs.pop("budget", budget()), **kwargs)

    async def test_priority_history_fair_pages_preserve_all_three_resume_cursors(self):
        rows = [transfer(lt=200), transfer(lt=100, tx="d1"*32)]
        actions = [action_event([transfer_action()], lt=200), action_event([transfer_action()], lt=100, trace="d2"*32)]
        operations = [{"item": indexed_item(), "operation": "transfer", "lt": lt,
                       "transaction_hash": TX, "source": OLD, "destination": OWNER} for lt in (200, 100)]
        providers = {"toncenter": FakeToncenter(transfers=rows), "tonapi": FakeTonAPI(events=actions, operations=operations)}
        store = InvestigationStore(self.path)
        try:
            report = NFTIntelligenceReport(investigation_id="fair-pages", query=ITEM, budget=budget(page_size=1, max_pages=10))
            investigator = NFTInvestigator(report, store, providers, priority_scheduling=True, checkpoint_interval_seconds=2)
            await investigator.history(ITEM, "item")
            self.assertEqual(len(report.coverage), 3)
            self.assertTrue(all(c.pages == 1 and c.records == 1 and c.coverage_status == "TRUNCATED" for c in report.coverage))
            self.assertTrue(all("time slice" in c.gap_reason for c in report.coverage))
            self.assertTrue(all(not checkpoint["exhausted"] for checkpoint in report.checkpoints.values()))
            investigator.snapshot(force=True)
            saved = store.load_snapshot("fair-pages")
            self.assertEqual(saved.checkpoints[f"history:item:{ITEM}:toncenter"]["cursor"], 1)
            self.assertEqual(saved.checkpoints[f"history:item:{ITEM}:tonapi_events"]["cursor"], 200)
            resumed = NFTInvestigator(saved, store, providers, priority_scheduling=True, checkpoint_interval_seconds=2)
            await resumed.history(ITEM, "item")
            self.assertTrue(all(c.pages == 2 and c.records == 2 for c in saved.coverage))
            self.assertEqual(saved.checkpoints[f"history:item:{ITEM}:toncenter"]["cursor"], 2)
            self.assertEqual(saved.checkpoints[f"history:item:{ITEM}:tonapi_events"]["cursor"], 100)
            self.assertEqual(saved.checkpoints[f"history:item:{ITEM}:tonapi_operations"]["cursor"], 100)
        finally:
            store.close()

    async def test_snapshot_coalesces_store_writes_but_refreshes_report_and_force_flushes(self):
        from unittest.mock import patch
        store = InvestigationStore(self.path)
        try:
            report = NFTIntelligenceReport(investigation_id="coalesced-snapshot", query=ITEM, budget=budget())
            investigator = NFTInvestigator(report, store, checkpoint_interval_seconds=2)
            clock = [100.0]
            with patch("app.ton_nft.service.time.monotonic", side_effect=lambda: clock[0]), \
                 patch.object(store, "save_snapshot", wraps=store.save_snapshot) as save:
                investigator.snapshot()
                investigator.assets[ITEM] = NFTAsset(asset_id="fixture", address=ITEM, name="First")
                investigator.events["fixture-event"] = NFTEvent(event_id="fixture-event", asset_address=ITEM, event_type="transfer")
                clock[0] = 101
                investigator.snapshot()
                self.assertEqual(save.call_count, 1)
                self.assertEqual(report.assets[0].name, "First")
                self.assertEqual(report.events[0].event_id, "fixture-event")
                clock[0] = 102.01
                investigator.snapshot()
                self.assertEqual(save.call_count, 2)
                investigator.assets[ITEM].name = "Final"
                investigator.snapshot(force=True)
                self.assertEqual(save.call_count, 3)
            self.assertEqual(store.load_snapshot("coalesced-snapshot").assets[0].name, "Final")
        finally:
            store.close()

    async def test_domain_resolves_item_not_dns_wallet(self):
        report = await self.investigate()
        self.assertEqual(report.discovery.candidates[0].address, ITEM)
        self.assertNotEqual(report.assets[0].address, OTHER)

    async def test_wrong_domain_index_in_official_collection_cannot_select_owner(self):
        # Both indexers agree on a real item in the official collection and its
        # membership getter succeeds; it nevertheless represents another name.
        wrong = indexed_item(index=ton_dns_item_index("another.ton"))
        report = await self.investigate(tc=FakeToncenter(items=[wrong]), ta=FakeTonAPI(items=[wrong]))
        self.assertEqual(report.assets[0].collection_status, VerificationStatus.VERIFIED_ONCHAIN)
        self.assertEqual(report.assets[0].current_owner_status, VerificationStatus.VERIFIED_ONCHAIN)
        self.assertEqual(report.discovery.status, "unresolved")
        self.assertEqual(report.discovery.candidates[0].verification, VerificationStatus.CONFLICT)
        self.assertEqual(report.assets[0].raw["input_name_binding"]["status"], "conflict")
        self.assertFalse(report.input_resolution)
        self.assertIsNone(resolve_verified_nft_owner(report))
        # The helper repeats this check itself, even before named post-validation
        # could run (e.g. a budget interruption during owner classification).
        report.discovery.status = "resolved"
        self.assertIsNone(resolve_verified_nft_owner(report))

    async def test_matching_domain_cell_hash_index_proves_exact_name_binding(self):
        report = await self.investigate()
        self.assertEqual(report.assets[0].index, ton_dns_item_index("fixture.ton"))
        self.assertEqual(report.assets[0].raw["input_name_binding"]["status"], "verified_onchain")
        self.assertEqual(resolve_verified_nft_owner(report)["owner_address"], OWNER)

    async def test_delegated_subdomain_binding_stays_unknown(self):
        item = indexed_item(name="some.fixture.ton")
        report = await self.investigate("some.fixture.ton", tc=FakeToncenter(items=[item], domains={"some.fixture.ton": ITEM}),
            ta=FakeTonAPI(items=[item]))
        self.assertEqual(report.discovery.status, "unresolved")
        self.assertEqual(report.assets[0].raw["input_name_binding"]["status"], "unknown")
        self.assertFalse(report.input_resolution)
        self.assertIsNone(resolve_verified_nft_owner(report))

    async def test_owner_and_membership_verified_onchain(self):
        report = await self.investigate()
        self.assertEqual(report.assets[0].current_owner, OWNER)
        self.assertEqual(report.assets[0].current_owner_status, VerificationStatus.VERIFIED_ONCHAIN)
        self.assertEqual(report.assets[0].collection_status, VerificationStatus.VERIFIED_ONCHAIN)

    async def test_verified_owner_helper_requires_exact_fresh_getter_and_evidence(self):
        report = await self.investigate()
        resolution = resolve_verified_nft_owner(report)
        self.assertEqual((resolution["nft_address"], resolution["owner_address"]), (ITEM, OWNER))
        self.assertEqual(resolution["owner_corroboration"]["independent_upstream_count"], 2)
        self.assertEqual(resolution["owner_account"]["account_type"], "wallet")
        self.assertEqual(resolution["owner_account"]["classification_status"], "provider_reported")
        self.assertEqual(report.assets[0].raw["owner_account"], report.assets[0].owner_account)
        report.evidence = [e for e in report.evidence if e.relation != "onchain_current_owner"]
        self.assertIsNone(resolve_verified_nft_owner(report))

    async def test_ambiguous_candidate_and_metadata_owner_never_select_owner(self):
        report = await self.investigate()
        report.discovery.candidates.append(DiscoveryCandidate(address=ITEM2, reason="Fixture ambiguity"))
        self.assertIsNone(resolve_verified_nft_owner(report))
        report.discovery.candidates.pop()
        report.assets[0].current_owner_status = VerificationStatus.PROVIDER_REPORTED
        self.assertIsNone(resolve_verified_nft_owner(report))

    async def test_domain_in_other_collection_is_not_accepted_as_official_domain(self):
        item = indexed_item(collection=USERNAME_COLLECTION)
        report = await self.investigate(tc=FakeToncenter(items=[item]), ta=FakeTonAPI(items=[item]))
        self.assertEqual(report.discovery.status, "unresolved")
        self.assertIsNone(resolve_verified_nft_owner(report))
        self.assertFalse(report.input_resolution)

    async def test_deep_exact_item_shares_owner_inventory_budget_snapshot_and_portfolio(self):
        tc = FakeToncenter(items=[indexed_item(), indexed_item(ITEM2, index=2)])
        report = await self.investigate(mode="deep", tc=tc,
            ta=FakeTonAPI(items=tc.items_data), budget=budget(max_requests=60, trace_depth=0))
        self.assertEqual(report.input_resolution["owner_address"], OWNER)
        self.assertEqual(report.portfolio.wallet_address, OWNER)
        self.assertIn(ITEM2, report.portfolio.current_holdings)
        self.assertTrue(any(params and params.get("owner_address") == OWNER for _, params, _ in tc.calls))
        self.assertEqual(report_to_address_report(report).target_address, OWNER)
        loaded = load_investigation(report.investigation_id, self.path)
        self.assertEqual(loaded.input_resolution["owner_address"], OWNER)
        primary_history = next(i for i, (path, params, _) in enumerate(tc.calls)
            if path.endswith("nft/transfers") and params.get("item_address") == ITEM)
        owner_inventory = next(i for i, (path, params, _) in enumerate(tc.calls)
            if path.endswith("nft/items") and params.get("owner_address") == OWNER)
        self.assertLess(primary_history, owner_inventory)

    async def test_deep_traces_related_wallets_after_essential_history_and_transaction_details(self):
        tc = FakeToncenter()
        report = await self.investigate(mode="deep", tc=tc, budget=budget(max_requests=70, max_wallets=2, trace_depth=1))
        self.assertIn(OLD, report.checkpoints.get("trace:visited", []))
        detail = next(i for i, (path, _, _) in enumerate(tc.calls) if path.endswith("/transactions"))
        related = next(i for i, (path, params, _) in enumerate(tc.calls)
            if path.endswith("nft/transfers") and params.get("owner_address") == OLD)
        self.assertLess(detail, related)
        self.assertEqual(report.portfolio.wallet_address, OWNER)

    async def test_target_callback_fires_once_before_blocked_deep_history_and_inventory(self):
        callback_ran, history_waiting, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        marks, progress = [], []
        loop = asyncio.get_running_loop()
        started = loop.time()
        class BlockedHistory(FakeToncenter):
            async def request(self, path, **kwargs):
                if path.endswith("nft/transfers") and kwargs["params"].get("item_address") == ITEM:
                    marks.append(("primary_history", loop.time()-started))
                    history_waiting.set()
                    await release.wait()
                return await super().request(path, **kwargs)
        async def resolved(target, report):
            marks.append(("owner_callback", loop.time()-started))
            self.assertEqual(target["analysis_address"], OWNER)
            self.assertEqual(target["scope"], "item")
            self.assertEqual(resolve_verified_nft_owner(report)["owner_address"], OWNER)
            saved = load_investigation(report.investigation_id, self.path)
            self.assertEqual(saved.input_resolution["owner_address"], OWNER)
            callback_ran.set()
        task = asyncio.create_task(self.investigate(mode="deep", tc=BlockedHistory(),
            on_target_resolved=resolved, on_progress=progress.append,
            budget=budget(max_requests=60, trace_depth=0)))
        try:
            await asyncio.wait_for(history_waiting.wait(), 5)
            self.assertTrue(callback_ran.is_set())
            self.assertFalse(task.done())
            self.assertLess(marks[0][1], marks[1][1])
        finally:
            release.set()
            report = await task
        self.assertEqual([name for name, _ in marks].count("owner_callback"), 1)
        self.assertEqual(report.portfolio.wallet_address, OWNER)
        stages = [event["stage"] for event in progress]
        self.assertLess(stages.index("nft.target_resolved"), stages.index("nft.primary_history"))
        self.assertTrue(any(event["stage"] == "nft.page_collected" and event["records"] >= 1 for event in progress))
        self.assertEqual(sum(event["stage"] == "nft.request_started" for event in progress), report.stats["requests_this_run"])
        self.assertTrue(all(event.get("timestamp") and event["elapsed_seconds"] >= 0 for event in progress))

    async def test_wallet_target_callback_precedes_inventory_without_claiming_nft_owner(self):
        called = []
        class CheckedInventory(FakeToncenter):
            async def request(self, path, **kwargs):
                if path.endswith("nft/items") and "owner_address" in (kwargs.get("params") or {}):
                    self_test.assertTrue(called)
                return await super().request(path, **kwargs)
        self_test = self
        def resolved(target, report):
            called.append(target)
            self.assertEqual(report.scope, "wallet")
            self.assertIsNone(resolve_verified_nft_owner(report))
        report = await self.investigate(OWNER, scope="wallet", mode="deep", tc=CheckedInventory(),
            on_target_resolved=resolved, budget=budget(max_requests=60, trace_depth=0))
        self.assertEqual(len(called), 1)
        self.assertEqual(called[0]["analysis_address"], OWNER)
        self.assertEqual(called[0]["scope"], "wallet")
        self.assertNotIn("ownership_status", called[0])
        self.assertEqual(report.portfolio.wallet_address, OWNER)

    async def test_unverified_owner_never_invokes_target_callback(self):
        targets = []
        report = await self.investigate(tc=FakeToncenter(getter_error=True),
            on_target_resolved=lambda target, report: targets.append(target))
        self.assertFalse(targets)
        self.assertIsNone(resolve_verified_nft_owner(report))

    async def test_target_callback_failure_propagates_instead_of_provider_partial_success(self):
        failure = RuntimeError("fixture target callback failed")
        def resolved(target, report):
            raise failure
        with self.assertRaises(RuntimeError) as caught:
            await self.investigate(on_target_resolved=resolved)
        self.assertIs(caught.exception, failure)

    async def test_progress_records_terminal_rate_limit_and_real_retry_requests(self):
        import httpx
        from app.ton_nft.providers import RequestController
        progress, observations = [], []
        class OnceLimited(FakeToncenter):
            first = True
            async def request(self, path, **kwargs):
                if self.first:
                    self.first = False
                    response = httpx.Response(429, headers={"Retry-After": "0"}, request=httpx.Request("GET", "https://example.org/fixture"))
                    raise httpx.HTTPStatusError("fixture 429", request=response.request, response=response)
                return {"nft_items": []}
        provider = OnceLimited()
        provider.controller = RequestController(InvestigationBudget(requests_per_second=20, retries=1), observations.append, progress=progress.append)
        await provider.item(ITEM)
        self.assertEqual(provider.controller.requests, 2)
        self.assertEqual([event["status"] for event in progress if event["stage"] == "nft.request_completed"], ["rate_limited", "ok"])
        self.assertTrue(any(event["stage"] == "nft.request_retry" for event in progress))
        self.assertEqual([observation.status for observation in observations], ["rate_limited", "ok"])

    async def test_independent_getter_fallback_preserves_fresh_owner_and_typed_stack_evidence(self):
        class NoGetters(FakeToncenter):
            async def request(self, path, **kwargs):
                if path.endswith("runGetMethod"):
                    return {"ok": True, "result": {"exit_code": -13, "stack": []}}
                return await super().request(path, **kwargs)
        class TypedGetters(FakeTonAPI):
            seen_args = []
            async def request(self, path, **kwargs):
                if "/methods/" not in path:
                    return await super().request(path, **kwargs)
                method = path.rsplit("/", 1)[-1]
                self.seen_args.append((method, kwargs.get("params")))
                if method == "get_nft_data":
                    stack = getter(index=ton_dns_item_index("fixture.ton"), owner=OTHER)["stack"]
                elif method == "get_collection_data":
                    stack = [["num", "-0x1"], ["cell", {"bytes": cell_boc("")}], ["cell", address_cell(None)]]
                elif method == "get_nft_address_by_index":
                    self_test.assertEqual(int(kwargs["params"]["args"][0], 16), ton_dns_item_index("fixture.ton"))
                    stack = [["cell", address_cell(ITEM)]]
                else:
                    self_test.assertEqual(base64.b64decode(kwargs["params"]["args"][1])[:4], bytes.fromhex("b5ee9c72"))
                    stack = [["cell", {"bytes": cell_boc("")}]]
                typed = [{"type": kind, "num": value} if kind == "num" else {
                    "type": "cell", "cell": base64.b64decode(value["bytes"]).hex()} for kind, value in stack]
                return {"success": True, "exit_code": 0, "stack": typed}
        self_test = self
        targets = []
        report = await self.investigate(tc=NoGetters(), ta=TypedGetters(),
            on_target_resolved=lambda target, report: targets.append(target))
        self.assertEqual(resolve_verified_nft_owner(report)["owner_address"], OTHER)
        self.assertEqual(report.assets[0].current_owner_status, VerificationStatus.VERIFIED_ONCHAIN)
        self.assertEqual(report.assets[0].collection_status, VerificationStatus.VERIFIED_ONCHAIN)
        self.assertEqual(report.assets[0].owner_corroboration["status"], "conflict")
        owner_proof = next(e for e in report.evidence if e.relation == "onchain_current_owner")
        self.assertEqual((owner_proof.source, owner_proof.upstream), ("tonapi_nft", "tonapi.io"))
        self.assertEqual(len(targets), 1)
        raw = InvestigationStore(self.path)
        try:
            observation = raw.observation(report.investigation_id, owner_proof.observation_id)
            self.assertEqual(observation.raw["stack"][2]["type"], "cell")
            self.assertTrue(observation.raw["stack"][2]["cell"].startswith("b5ee9c72"))
        finally:
            raw.close()

    async def test_failed_independent_getter_never_promotes_indexed_owner(self):
        targets = []
        report = await self.investigate(tc=FakeToncenter(getter_error=True),
            on_target_resolved=lambda target, report: targets.append(target))
        self.assertFalse(targets)
        self.assertEqual(report.assets[0].current_owner_status, VerificationStatus.PROVIDER_REPORTED)
        self.assertIsNone(resolve_verified_nft_owner(report))

    async def test_deterministic_dns_uses_independent_getter_when_primary_provider_unavailable(self):
        import httpx
        class PrimaryUnavailable(FakeToncenter):
            async def request(self, path, **kwargs):
                if path.endswith("dns/records") or path.endswith("runGetMethod"):
                    raise httpx.ConnectError("fixture primary unavailable")
                return await super().request(path, **kwargs)
        class IndependentDNSGetters(FakeTonAPI):
            async def request(self, path, **kwargs):
                if "/methods/" not in path:
                    return await super().request(path, **kwargs)
                method = path.rsplit("/", 1)[-1]
                if method == "get_nft_data":
                    stack = getter(index=ton_dns_item_index("fixture.ton"))["stack"]
                elif method == "get_collection_data":
                    stack = [["num", "-0x1"], ["cell", {"bytes": cell_boc("")}], ["cell", address_cell(None)]]
                elif method == "get_nft_address_by_index":
                    stack = [["cell", address_cell(ITEM)]]
                else:
                    stack = [["cell", {"bytes": cell_boc("")}]]
                return {"success": True, "exit_code": 0, "stack": stack}
        targets = []
        report = await self.investigate(tc=PrimaryUnavailable(), ta=IndependentDNSGetters(),
            on_target_resolved=lambda target, report: targets.append(target))
        self.assertEqual(report.discovery.status, "resolved")
        self.assertEqual(report.discovery.candidates[0].address, ITEM)
        self.assertEqual(resolve_verified_nft_owner(report)["owner_address"], OWNER)
        derived = next(e for e in report.evidence if e.relation == "specialized_dns_candidate")
        self.assertEqual((derived.source, derived.upstream), ("tonapi_nft", "tonapi.io"))
        self.assertEqual(len(targets), 1)
        self.assertEqual(report.assets[0].raw["input_name_binding"]["status"], "verified_onchain")

    async def test_deterministic_dns_both_getter_providers_unavailable_stays_unresolved(self):
        class BothUnavailable(FakeToncenter):
            async def request(self, path, **kwargs):
                if path.endswith("runGetMethod"):
                    return {"ok": True, "result": {"exit_code": -13, "stack": []}}
                return await super().request(path, **kwargs)
        targets = []
        report = await self.investigate(tc=BothUnavailable(items=[], domains={}), ta=FakeTonAPI(items=[]),
            on_target_resolved=lambda target, report: targets.append(target))
        self.assertEqual(report.discovery.status, "unresolved")
        self.assertEqual(report.assets, [])
        self.assertEqual(report.events, [])
        self.assertFalse(report.input_resolution)
        self.assertFalse(targets)

    async def test_missing_direct_item_stops_before_generic_ton_history_or_owner_fanout(self):
        tc = FakeToncenter(items=[], transfers=[])
        actions = [action_event([{"type": "TonTransfer", "status": "ok", "TonTransfer": {
            "sender": {"address": OLD}, "recipient": {"address": ITEM}, "amount": "1000000000"}}])]
        report = await self.investigate(ITEM, scope="item", mode="deep", tc=tc,
            ta=FakeTonAPI(items=[], events=actions), budget=budget(max_requests=40, max_wallets=2))
        self.assertEqual(report.discovery.status, "unresolved")
        self.assertEqual(report.status, "unresolved")
        self.assertEqual(report.assets, [])
        self.assertEqual(report.events, [])
        self.assertIsNone(report.portfolio)
        self.assertFalse(report.input_resolution)
        self.assertFalse(any(path.endswith("nft/transfers") for path, _, _ in tc.calls))
        self.assertFalse(any(params and "owner_address" in params for _, params, _ in tc.calls))

    async def test_contract_interaction_cannot_seed_nft_related_wallet_tracing(self):
        tc = FakeToncenter(transfers=[])
        actions = [action_event([{"type": "TonTransfer", "status": "ok", "TonTransfer": {
            "sender": {"address": OLD}, "recipient": {"address": ITEM}, "amount": "1000000000"}}])]
        report = await self.investigate(ITEM, scope="trace", tc=tc,
            ta=FakeTonAPI(events=actions), budget=budget(max_requests=40, max_wallets=2))
        self.assertTrue(any(event.event_type == "contract_interaction" for event in report.events))
        self.assertFalse(report.checkpoints.get("trace:visited"))
        self.assertFalse(any(path.endswith("nft/transfers") and params.get("owner_address") in {OLD, ITEM}
            for path, params, _ in tc.calls))

    async def test_conflicting_independent_exact_domain_candidates_remain_ambiguous(self):
        class ConflictingDomain(FakeTonAPI):
            async def request(self, path, **kwargs):
                if path.startswith("/dns/"):
                    return {"name": "fixture.ton", "item": {"address": ITEM2}}
                return await super().request(path, **kwargs)
        report = await self.investigate(ta=ConflictingDomain())
        self.assertEqual(report.discovery.status, "ambiguous")
        self.assertEqual({c.address for c in report.discovery.candidates}, {ITEM, ITEM2})
        self.assertIsNone(resolve_verified_nft_owner(report))
        self.assertFalse(report.input_resolution)

    async def test_truncated_gift_name_search_cannot_assert_unique_owner(self):
        items = [indexed_item(name="Lol Pops #1"), indexed_item(ITEM2, index=2, name="Other collectible")]
        registry = {**KNOWN_COLLECTIONS, "gift:lolpops": {"address": COLLECTION, "name": "Lol Pops", "source": "https://example.org/fixture-registry"}}
        report = await self.investigate("LolPop-1", registry=registry,
            tc=FakeToncenter(items=items), ta=FakeTonAPI(items=items), budget=budget(max_pages=1, page_size=1))
        self.assertEqual(report.discovery.status, "unresolved")
        self.assertEqual([candidate.address for candidate in report.discovery.candidates], [ITEM])
        self.assertTrue(report.discovery.candidates[0].evidence_ids)
        self.assertIsNone(resolve_verified_nft_owner(report))
        self.assertFalse(report.input_resolution)
        self.assertEqual(report.assets, [])
        # The same exact match is usable once the bounded source scan actually
        # exhausts; the empty final page establishes uniqueness within this index.
        complete = await self.investigate("LolPop-1", registry=registry,
            tc=FakeToncenter(items=items), ta=FakeTonAPI(items=items), budget=budget(max_pages=3, page_size=1))
        self.assertEqual(complete.discovery.status, "resolved")
        self.assertEqual(resolve_verified_nft_owner(complete)["owner_address"], OWNER)

    async def test_truncated_gift_multiple_exact_matches_remain_ambiguous(self):
        items = [indexed_item(name="Lol Pops #1"), indexed_item(ITEM2, index=2, name="Lol Pops #1")]
        registry = {**KNOWN_COLLECTIONS, "gift:lolpops": {"address": COLLECTION, "name": "Lol Pops", "source": "https://example.org/fixture-registry"}}
        report = await self.investigate("LolPop-1", registry=registry,
            tc=FakeToncenter(items=items), ta=FakeTonAPI(items=items), budget=budget(max_pages=1, page_size=2))
        self.assertEqual(report.discovery.status, "ambiguous")
        self.assertEqual({candidate.address for candidate in report.discovery.candidates}, {ITEM, ITEM2})
        self.assertIsNone(resolve_verified_nft_owner(report))

    async def test_indexed_owner_conflict_is_preserved_without_replacing_fresh_getter(self):
        report = await self.investigate(ta=FakeTonAPI(items=[indexed_item(owner=OTHER)]))
        resolution = resolve_verified_nft_owner(report)
        self.assertEqual(resolution["owner_address"], OWNER)
        self.assertEqual(resolution["owner_corroboration"]["status"], "conflict")
        self.assertEqual(resolution["owner_corroboration"]["conflicting_claims"][0]["owner_address"], OTHER)

    async def test_deep_budget_after_verification_retains_resolution_and_portfolio(self):
        report = await self.investigate(mode="deep", budget=budget(max_requests=10, trace_depth=0))
        self.assertEqual(report.status, "partial")
        self.assertEqual(report.input_resolution["owner_address"], OWNER)
        self.assertEqual(report.portfolio.wallet_address, OWNER)

    async def test_resume_clears_saved_owner_analysis_and_owner_resolution(self):
        report = await self.investigate()
        report.owner_analysis_snapshot = {"target_address": OWNER, "balances": [{"amount": 1}]}
        store = InvestigationStore(self.path)
        store.save_snapshot(report)
        store.close()
        resumed = await self.investigate(resume=True, investigation_id=report.investigation_id,
            budget=budget(max_requests=1), tc=FakeToncenter(getter_error=True))
        self.assertIsNone(resumed.owner_analysis_snapshot)
        self.assertFalse(resumed.input_resolution)
        self.assertIsNone(resolve_verified_nft_owner(resumed))

    async def test_collection_conflict_not_confirmed(self):
        report = await self.investigate(tc=FakeToncenter(mismatch=True))
        self.assertEqual(report.assets[0].collection_status, VerificationStatus.CONFLICT)

    async def test_two_same_titles_not_merged(self):
        items = [indexed_item(), indexed_item(ITEM2, index=2)]
        report = await self.investigate(COLLECTION, scope="collection", tc=FakeToncenter(items=items), ta=FakeTonAPI(items=items))
        self.assertEqual({a.address for a in report.assets}, {ITEM, ITEM2})

    async def test_current_and_historical_owner_distinct(self):
        report = await self.investigate()
        asset = report.assets[0]
        self.assertEqual(asset.current_owner, OWNER)
        self.assertIn(OLD, [x["address"] for x in asset.historical_owners])

    async def test_raw_unknown_fields_preserved(self):
        report = await self.investigate()
        self.assertTrue(any("unknown_provider_field" in raw for raw in report.assets[0].raw.values()))
        store = InvestigationStore(self.path)
        try:
            raw = store.observation(report.investigation_id, report.observations[0].observation_id)
            self.assertIsNotNone(raw.raw)
        finally:
            store.close()

    async def test_indexer_empty_not_complete(self):
        report = await self.investigate(tc=FakeToncenter(transfers=[]))
        self.assertTrue(all(not c.complete and c.coverage_status != "COMPLETE" for c in report.coverage))
        self.assertFalse(report.assets[0].ownership_summary["is_genesis_proven"])

    async def test_missing_history_is_not_no_previous_owner(self):
        report = await self.investigate(tc=FakeToncenter(transfers=[], fail_offset=0))
        self.assertEqual(report.assets[0].ownership_summary["history_status"], "partial")

    async def test_pagination_and_partial_failure(self):
        rows = [transfer(lt=3, query_id="3"), transfer(lt=2, query_id="2"), transfer(lt=1, query_id="1")]
        report = await self.investigate(tc=FakeToncenter(transfers=rows, fail_offset=2), budget=budget(page_size=1, max_pages=10))
        self.assertEqual(len([e for e in report.events if e.raw.get("transaction_aborted") is False]), 2)
        self.assertTrue(any(c.status == "error" and c.records == 2 for c in report.coverage))

    async def test_resume_continues_saved_cursor(self):
        rows = [transfer(lt=i, query_id=str(i)) for i in [3, 2, 1]]
        first = await self.investigate(tc=FakeToncenter(transfers=rows), budget=budget(page_size=1, max_pages=1), investigation_id="resume-fixture")
        second = await self.investigate(tc=FakeToncenter(transfers=rows), budget=budget(page_size=1, max_pages=10), investigation_id="resume-fixture", resume=True)
        self.assertGreater(len(second.events), len(first.events))
        self.assertEqual(len(second.events), 3)

    async def test_deep_collects_more_pages(self):
        rows = [transfer(lt=i, query_id=str(i)) for i in [3, 2, 1]]
        normal = await self.investigate(tc=FakeToncenter(transfers=rows), budget=budget(page_size=1, max_pages=1))
        deep = await self.investigate(tc=FakeToncenter(transfers=rows), budget=budget(page_size=1, max_pages=10), mode="deep")
        self.assertGreater(len(deep.events), len(normal.events))

    async def test_multi_action_hash_preserved(self):
        events = [action_event([transfer_action(), transfer_action(new=OTHER)])]
        report = await self.investigate(tc=FakeToncenter(transfers=[]), ta=FakeTonAPI(events=events))
        self.assertEqual(len(report.events), 2)
        self.assertEqual({e.action_index for e in report.events}, {0, 1})

    async def test_observations_merge_without_false_repeat_signal(self):
        events = [action_event([transfer_action()])]
        report = await self.investigate(ta=FakeTonAPI(events=events))
        self.assertEqual(len(report.events), 1)
        self.assertGreaterEqual(len(report.events[0].observation_ids), 2)
        self.assertFalse(any(s["type"] == "rapid_nft_transfers" for s in report.signals))

    async def test_unrelated_actions_do_not_become_nft_sale(self):
        action = {"type": "TonTransfer", "status": "ok", "TonTransfer": {"sender": {"address": OLD}, "recipient": {"address": OWNER}, "amount": "100000000000"}}
        report = await self.investigate(ta=FakeTonAPI(events=[action_event([action])]))
        self.assertTrue(all(e.event_type != "sale" for e in report.events))
        self.assertIsNone(report.assets[0].last_confirmed_sale)

    async def test_contract_interactions_retained(self):
        action = {"type": "TonTransfer", "status": "ok", "TonTransfer": {"sender": {"address": OLD}, "recipient": {"address": ITEM}, "amount": "1000000000"}}
        report = await self.investigate(ta=FakeTonAPI(events=[action_event([action])]))
        self.assertIn("contract_interaction", [e.event_type for e in report.events])

    async def test_sold_asset_not_current_portfolio(self):
        item = indexed_item(owner=OTHER)
        report = await self.investigate(OWNER, scope="wallet", tc=FakeToncenter(items=[item], transfers=[transfer(old=OWNER, new=OTHER)]), ta=FakeTonAPI(items=[item]))
        self.assertNotIn(ITEM, report.portfolio.current_holdings)
        self.assertIn(ITEM, report.portfolio.historical_holdings)

    async def test_username_metadata_not_identity(self):
        item = indexed_item(name="@person")
        report = await self.investigate(tc=FakeToncenter(items=[item]), ta=FakeTonAPI(items=[item]))
        self.assertIsNone(report.assets[0].telegram)

    async def test_collectible_username_no_person_assignment(self):
        item = indexed_item(collection=USERNAME_COLLECTION, name="fixture")
        report = await self.investigate("@fixture", tc=FakeToncenter(items=[item], domains={"fixture.t.me": ITEM}), ta=FakeTonAPI(items=[item]))
        collectible = report.assets[0].telegram
        self.assertEqual(collectible.kind, "username")
        self.assertEqual(collectible.assignment_status, "unknown")
        self.assertEqual(collectible.identity_status, "unknown")

    async def test_ordinary_username_unresolved_no_contract(self):
        report = await self.investigate("@ordinary", tc=FakeToncenter(domains={}))
        self.assertEqual(report.status, "unresolved")
        self.assertFalse(report.assets)

    async def test_snapshot_reexport_without_network(self):
        report = await self.investigate(investigation_id="saved-fixture")
        loaded = load_investigation("saved-fixture", self.path)
        self.assertEqual(report.model_dump(mode="json"), loaded.model_dump(mode="json"))

    async def test_legacy_bridge_preserves_evidence_and_no_fake_balance(self):
        report = await self.investigate()
        legacy = report_to_address_report(report)
        self.assertEqual(legacy.nft_intelligence["evidence"], report.model_dump(mode="json")["evidence"])
        self.assertFalse(legacy.balances)

    async def test_getter_failure_not_confirmed_owner(self):
        report = await self.investigate(tc=FakeToncenter(getter_error=True))
        self.assertEqual(report.assets[0].current_owner_status, "provider_reported")

    async def test_request_budget_preserves_partial(self):
        report = await self.investigate(budget=budget(max_requests=5))
        self.assertEqual(report.status, "partial")
        self.assertLessEqual(report.stats["requests_this_run"], 5)
        self.assertTrue(report.observations)

    async def test_failed_transfer_not_historical_owner(self):
        report = await self.investigate(tc=FakeToncenter(transfers=[transfer(new=OTHER, aborted=True)]))
        self.assertFalse(report.assets[0].historical_owners)

    async def test_refresh_low_budget_invalidates_all_old_current_owners(self):
        first = await self.investigate(OWNER, scope="wallet", investigation_id="refresh-fixture")
        self.assertIn(ITEM, first.portfolio.current_holdings)
        second = await self.investigate(OWNER, scope="wallet", investigation_id="refresh-fixture", incremental=True,
            budget=budget(max_requests=1), tc=FakeToncenter(items=[indexed_item(owner=OTHER)]))
        self.assertNotIn(ITEM, second.portfolio.current_holdings)
        self.assertNotEqual(second.assets[0].current_owner_status, "verified_onchain")

    async def test_resume_failed_getter_not_stale_verified_owner(self):
        await self.investigate(OWNER, scope="wallet", investigation_id="resume-owner-fixture")
        second = await self.investigate(OWNER, scope="wallet", investigation_id="resume-owner-fixture", resume=True,
                                       tc=FakeToncenter(getter_error=True))
        self.assertNotIn(ITEM, second.portfolio.current_holdings)
        self.assertNotEqual(second.assets[0].current_owner_status, "verified_onchain")

    async def test_query_secret_never_stored_in_snapshot(self):
        query = "https://getgems.io/nft/" + ITEM + "?apikey=fixture_secret"
        report = await self.investigate(query)
        self.assertNotIn("fixture_secret", report.model_dump_json())
        self.assertNotIn("fixture_secret", load_investigation(report.investigation_id, self.path).model_dump_json())

    async def test_storage_sanitizes_mutated_extra_fields(self):
        report = await self.investigate()
        report.__pydantic_extra__["fixture_extra"] = {"Authorization": "Bearer fixture_secret"}
        store = InvestigationStore(self.path)
        try:
            store.save_snapshot(report)
            self.assertNotIn("fixture_secret", store.load_snapshot(report.investigation_id).model_dump_json())
        finally:
            store.close()

    async def test_predicted_uninitialized_domain_not_reported_existing(self):
        report = await self.investigate("unindexed.ton", tc=FakeToncenter(domains={}))
        self.assertEqual(report.discovery.status, "unresolved")
        self.assertFalse(report.assets)
        self.assertTrue(report.discovery.candidates)

    async def test_listing_price_distinct_from_successful_sale(self):
        row = indexed_item()
        class ListingAPI(FakeTonAPI):
            def as_tonapi(self, item):
                out = super().as_tonapi(item)
                out["sale"] = {"address": OTHER, "market": {"address": OLD, "name": "Fixture market"},
                    "price": {"currency_type": "ton", "value": "9000000000", "decimals": 9}}
                return out
        purchase = {"type": "NftPurchase", "status": "ok", "NftPurchase": {"nft": FakeTonAPI.as_tonapi(row),
            "seller": {"address": OLD}, "buyer": {"address": OWNER}, "auction_type": "getgems",
            "amount": {"currency_type": "ton", "value": "5000000000", "decimals": 9}}}
        report = await self.investigate(ta=ListingAPI(events=[action_event([purchase])]))
        asset = report.assets[0]
        self.assertEqual(asset.listings[0].price.amount, Decimal(9))
        self.assertEqual(asset.last_confirmed_sale.amount, Decimal(5))

    async def test_public_gift_profile_not_onchain_owner(self):
        html = '<table class="tgme_gift_table"><tr><th>Owner</th><td>Fixture Profile</td></tr><tr><th>Model</th><td>Model 3%</td></tr></table>'
        report = await investigate_ton_nft("https://t.me/nft/UnknownGift-1", store_path=self.path,
            budget=budget(), providers={"toncenter": FakeToncenter(), "tonapi": FakeTonAPI(), "telegram_public": FakeTelegram(html)})
        self.assertFalse(report.assets)
        self.assertEqual(report.public_collectibles[0]["identity_status"], "unverified")
        self.assertEqual(report.public_collectibles[0]["public_profile_mentions"], ["Fixture Profile"])

    async def test_incremental_fresh_getter_removes_sold_holding(self):
        await self.investigate(OWNER, scope="wallet", investigation_id="incremental-fixture")
        row = indexed_item(owner=OTHER)
        report = await self.investigate(OWNER, scope="wallet", investigation_id="incremental-fixture", incremental=True,
                                      tc=FakeToncenter(items=[row]), ta=FakeTonAPI(items=[row]))
        self.assertEqual(report.assets[0].current_owner, OTHER)
        self.assertNotIn(ITEM, report.portfolio.current_holdings)

    async def test_identical_transfer_observations_merge_provenance(self):
        store = InvestigationStore(self.path)
        try:
            report = NFTIntelligenceReport(investigation_id="merge-fixture", query=ITEM, budget=budget())
            investigator = NFTInvestigator(report, store, {"toncenter": FakeToncenter(), "tonapi": FakeTonAPI()})
            first = Payload({}, "obs:one", "toncenter_nft", "toncenter.com", "https://toncenter.com/api/v3/nft/transfers")
            second = Payload({}, "obs:two", "toncenter_nft", "toncenter.com", first.endpoint)
            investigator.parse_transfer(transfer(), first)
            investigator.parse_transfer(transfer(), second)
            self.assertEqual(len(investigator.events), 1)
            event = next(iter(investigator.events.values()))
            self.assertEqual(event.observation_ids, ["obs:one", "obs:two"])
            self.assertEqual(len(event.evidence_ids), 2)
        finally:
            store.close()

    async def test_distinct_transfers_same_tx_survive(self):
        rows = [transfer(new=OWNER, query_id="1"), transfer(new=OTHER, query_id="2")]
        report = await self.investigate(tc=FakeToncenter(transfers=rows))
        self.assertEqual(len(report.events), 2)

    async def test_batch_controllers_share_public_limiter(self):
        from app.ton_nft.providers import RequestController
        import time
        seen = []
        class TimedProvider(FakeToncenter):
            upstream = "fixture.shared-limiter"
            public_rate_limit = 20
            async def request(self, *args, **kwargs):
                seen.append(time.monotonic())
                return {}
        first, second = TimedProvider(), TimedProvider()
        first.controller = RequestController(budget(), lambda observation: None)
        second.controller = RequestController(budget(), lambda observation: None)
        await asyncio.gather(first.call("/fixture"), second.call("/fixture"))
        self.assertGreaterEqual(abs(seen[1]-seen[0]), .045)

    async def test_tracing_fetches_real_related_wallet_history(self):
        rows = [transfer(old=OLD, new=OWNER), transfer(address=ITEM2, old=OWNER, new=OTHER, tx="dd"*32)]
        items = [indexed_item(), indexed_item(ITEM2, owner=OTHER, index=2)]
        report = await self.investigate(ITEM, scope="trace", tc=FakeToncenter(items=items, transfers=rows), ta=FakeTonAPI(items=items),
                                      budget=budget(max_wallets=2, trace_depth=1))
        self.assertTrue(report.checkpoints.get("trace:visited"))
        self.assertTrue(any(e.asset_address == ITEM2 for e in report.events))

    async def test_transaction_fee_block_and_message_evidence_collected(self):
        report = await self.investigate()
        event = next(e for e in report.events if e.event_type == "transfer")
        self.assertEqual(event.fee.base_units, 12345)
        self.assertEqual(event.raw["block_reference"]["seqno"], 123)
        self.assertIn("transaction_details", event.raw)
        self.assertGreaterEqual(len(event.evidence_ids), 2)

    async def test_emulated_transaction_not_verified_ownership_transition(self):
        class EmulatedProvider(FakeToncenter):
            async def request(self, path, **kwargs):
                result = await super().request(path, **kwargs)
                if path.endswith("/transactions"):
                    for row in result["transactions"]:
                        row["emulated"] = True
                return result
        report = await self.investigate(tc=EmulatedProvider())
        self.assertTrue(all(e.verification != "verified_onchain" for e in report.events))
        self.assertFalse(report.assets[0].historical_owners)

    async def test_current_listing_custody_not_beneficial_wallet_ownership(self):
        item = indexed_item(owner=OTHER)
        item.update({"on_sale": True, "real_owner": OWNER, "sale_contract_address": OTHER})
        report = await self.investigate(OWNER, scope="wallet", tc=FakeToncenter(items=[item]), ta=FakeTonAPI(items=[item]))
        asset = report.assets[0]
        self.assertNotIn(ITEM, report.portfolio.current_holdings)
        self.assertIn(ITEM, report.portfolio.reported_holdings)
        self.assertTrue(asset.listings)
        self.assertEqual(asset.listings[0].status, "active")
        self.assertIsNone(asset.last_confirmed_sale)
        self.assertTrue(asset.market_observations)

    async def test_rpc_request_body_preserved_without_secrets(self):
        from app.ton_nft.providers import RequestController
        observations = []
        provider = FakeToncenter()
        provider.controller = RequestController(budget(), observations.append)
        await provider.call("/api/v2/runGetMethod", body={"address": ITEM, "method": "get_nft_data",
                            "stack": [], "Authorization": "Bearer fixture_secret"})
        observation = observations[0]
        self.assertEqual(observation.request_method, "POST")
        self.assertEqual(observation.request_body["address"], ITEM)
        self.assertEqual(observation.request_body["method"], "get_nft_data")
        self.assertNotIn("fixture_secret", observation.model_dump_json())
        self.assertLessEqual(observation.requested_at, observation.collected_at)


if __name__ == "__main__":
    unittest.main()
