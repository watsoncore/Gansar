from __future__ import annotations

import asyncio
import base64
from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import httpx

from app.models.report import AddressReport, Balance, Transaction
from app.ton_attribution.fingerprints import ordinary_code_hash
from app.ton_attribution.registry import service_identity
from app.ton_attribution.service import _descriptor, enrich_ton_service_intelligence, probe_ton_account
from app.ton_nft.providers import NFTProvider, Payload

ADDRESS = "0:" + "11" * 32
OTHER = "0:" + "22" * 32
THIRD = "0:" + "33" * 32


def boc(data: bytes) -> str:
    cell = bytes([0, len(data)*2]) + data
    return base64.b64encode(bytes.fromhex("b5ee9c720101010100") + bytes([len(cell), 0]) + cell).decode()


class FakeProvider(NFTProvider):
    base_url = "https://fixture.invalid"
    public_rate_limit = 1

    def __init__(self, name, responses, *, block=None):
        super().__init__()
        self.name = name; self.responses = responses; self.calls = []; self.block = block
        self.cancelled = False
        self._counter = 0

    @property
    def upstream(self):
        # Separate synthetic sources keep tests independent from real upstream pacing.
        self._counter += 1
        return f"fixture-{id(self)}-{self._counter}"

    async def request(self, path, *, params, body, timeout, retries, fresh):
        self.calls.append((path, params, fresh))
        if self.block:
            try:
                await self.block.wait()
            except asyncio.CancelledError:
                self.cancelled = True
                raise
        value = self.responses.get(path, {})
        if isinstance(value, Exception):
            raise value
        return deepcopy(value)


def clients(account=None, raw=None, center=None, transactions=None):
    ta = FakeProvider("tonapi_fixture", {
        f"/accounts/{ADDRESS}": account or {"status": "active", "is_wallet": True, "balance": 123},
        f"/blockchain/accounts/{ADDRESS}": raw or {"code": boc(b"code")},
        f"/blockchain/accounts/{ADDRESS}/transactions": {"transactions": transactions or []},
        f"/accounts/{OTHER}": {"status": "active", "name": "Crypto Bot", "interfaces": ["wallet_v4r2"]},
        f"/accounts/{THIRD}": {"status": "active", "name": "xRocket Bot"},
    })
    tc = FakeProvider("toncenter_fixture", {"/api/v3/addressInformation": center or {"status": "active", "balance": "123", "code": boc(b"code")}})
    return {"tonapi": ta, "toncenter": tc}


def report():
    return AddressReport(target_address=ADDRESS, detected_chains=["ton"], transactions=[
        Transaction(chain="ton", tx_hash="aa"*32, from_address=OTHER, to_address=ADDRESS,
                    amount_base_units=1234567891, decimals=9, amount=1.234567891, asset="TON", source="fixture", success=True),
        Transaction(chain="ton", tx_hash="bb"*32, from_address=ADDRESS, to_address=THIRD,
                    amount_decimal=Decimal("2"), amount=2, asset="TON", source="fixture", success=True),
    ])


class FingerprintTests(unittest.TestCase):
    def test_real_standard_code_matches_across_hex_and_base64_without_client_claim(self):
        # Public V3R1 code observed in both upstream representations, not a
        # supplied-address/service mapping. Fingerprint is published by TON.
        code = "b5ee9c720101010100620000c0ff0020dd2082014c97ba9730ed44d0d70b1fe0a4f2608308d71820d31fd31fd31ff82313bbf263ed44d0d31fd31fd3ffd15132baf2a15144baf2a204f901541055f910f2a3f8009320d74a96d307d402fb00e8d101a4c8cb1fcb1fcbffc9ed54"
        raw = Payload({"status": "active", "code": code}, "obs:ta", "tonapi", "tonapi.io", "https://tonapi.io/v2/blockchain/accounts/fixture")
        center = Payload({"status": "active", "code": base64.b64encode(bytes.fromhex(code)).decode()}, "obs:tc", "toncenter", "toncenter.com", "https://toncenter.com/api/v3/addressInformation")
        facts = []
        descriptor = _descriptor(ADDRESS, {"raw_contract": raw, "address_information": center}, [], facts)
        self.assertEqual(descriptor["contract"]["wallet_version"], "V3R1")
        self.assertEqual(descriptor["contract"]["status"], "CONFIRMED")
        self.assertEqual(len(set(descriptor["contract"]["code_hashes"].values())), 1)
        self.assertEqual(len(descriptor["contract"]["code_hashes"]), 2)
        self.assertEqual(descriptor["client_attribution"]["status"], "UNKNOWN")
        self.assertFalse(descriptor["attributions"])
        self.assertTrue(any(f["relation"] == "published_wallet_code_fingerprint" for f in facts))

    def test_provider_title_substring_does_not_become_known_service(self):
        self.assertTrue(service_identity("Tonkeeper support scam")[0].startswith("registry:"))
        self.assertTrue(service_identity("My xRocket Bot clone")[0].startswith("registry:"))

    def test_ordinary_hash_is_representation_hash_not_boc_file_hash(self):
        import hashlib
        encoded = boc(b"test")
        self.assertEqual(ordinary_code_hash(encoded), hashlib.sha256(bytes([0, 8])+b"test").hexdigest())
        self.assertNotEqual(ordinary_code_hash(encoded), hashlib.sha256(base64.b64decode(encoded)).hexdigest())

    def test_invalid_or_exotic_cell_does_not_match_fingerprint(self):
        with self.assertRaises(ValueError):
            ordinary_code_hash("invalid")

    def test_provider_interface_never_identifies_client(self):
        payload = Payload({"status": "active", "is_wallet": True, "interfaces": ["wallet_v5r1"]}, "obs:fixture", "tonapi", "tonapi.io", "https://tonapi.io/v2/accounts/fixture")
        descriptor = _descriptor(ADDRESS, {"account": payload}, [], [])
        self.assertEqual(descriptor["contract"]["wallet_version"], "V5R1")
        self.assertEqual(descriptor["contract"]["status"], "PROBABLE")
        self.assertEqual(descriptor["client_attribution"]["status"], "UNKNOWN")
        self.assertEqual(descriptor["attributions"], [])

    def test_conflicting_code_hashes_do_not_select_wallet(self):
        source = lambda name, code: Payload({"status": "active", "code": boc(code)}, "obs:"+name, name, name, "https://example.org/"+name)
        descriptor = _descriptor(ADDRESS, {"raw_contract": source("a", b"a"), "address_information": source("b", b"b")}, [], [])
        self.assertIsNone(descriptor["contract"]["code_hash"])
        self.assertEqual(descriptor["contract"]["status"], "POSSIBLE")
        self.assertTrue(descriptor["conflicts"])

    def test_registry_and_provider_are_not_independent_confirmation(self):
        payload = Payload({"status": "active", "name": "Crypto Bot"}, "obs:a", "tonapi", "tonapi.io", "https://tonapi.io/v2/accounts/fixture")
        with patch("app.ton_attribution.service.exact_registry_labels", return_value=[{"address": ADDRESS, "name": "Crypto Bot"}]):
            descriptor = _descriptor(ADDRESS, {"account": payload}, [], [])
        attribution = descriptor["attributions"][0]
        self.assertEqual(attribution["service_id"], "cryptobot")
        self.assertEqual(attribution["status"], "PROBABLE")
        self.assertIn("share an upstream", attribution["reason"])
        self.assertEqual(descriptor["client_attribution"]["status"], "UNKNOWN")

    def test_conflicting_service_labels_preserve_both(self):
        payload = Payload({"status": "active", "name": "Crypto Bot"}, "obs:a", "tonapi", "tonapi.io", "https://tonapi.io/v2/accounts/fixture")
        with patch("app.ton_attribution.service.exact_registry_labels", return_value=[{"address": ADDRESS, "name": "xRocket Bot"}]):
            descriptor = _descriptor(ADDRESS, {"account": payload}, [], [])
        self.assertEqual({a["service_id"] for a in descriptor["attributions"]}, {"cryptobot", "xrocket"})
        self.assertEqual({a["status"] for a in descriptor["attributions"]}, {"POSSIBLE"})
        self.assertTrue(descriptor["conflicts"])


class AttributionAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_zero_request_budget_performs_no_network(self):
        providers = clients()
        result = await probe_ton_account(ADDRESS, deadline=asyncio.get_running_loop().time()+2, providers=providers, max_requests=0)
        self.assertFalse(providers["tonapi"].calls)
        self.assertFalse(providers["toncenter"].calls)
        self.assertEqual(result["coverage"]["status"], "TRUNCATED")
        self.assertEqual(result["stats"]["requests"], 0)
        self.assertEqual(result["descriptor"]["contract"]["status"], "UNKNOWN")

    async def test_probe_preserves_exact_balance_failed_tx_and_raw_evidence(self):
        now = datetime.now(timezone.utc)
        providers = clients(transactions=[{"hash": "cc"*32, "lt": 987, "utime": int(now.timestamp()), "success": False,
            "total_fees": "1", "in_msg": {"source": {"address": OTHER}, "destination": {"address": ADDRESS}, "value": "1000000001"},
            "out_msgs": []}])
        result = await probe_ton_account(ADDRESS, deadline=asyncio.get_running_loop().time()+2, providers=providers)
        fragment = AddressReport.model_validate(result["report_fragment"])
        self.assertEqual(fragment.balances[0].amount_decimal, Decimal("0.000000123"))
        self.assertEqual(fragment.transactions[0].amount_decimal, Decimal("1.000000001"))
        self.assertFalse(fragment.transactions[0].success)
        self.assertTrue(fragment.transactions[0].event_id)
        self.assertEqual(len(result["observations"]), 4)
        self.assertEqual(result["descriptor"]["client_attribution"]["status"], "UNKNOWN")
        self.assertFalse(result["coverage"]["history_complete"])

    async def test_uninitialized_account_is_not_wallet_even_is_wallet_true(self):
        providers = clients(account={"status": "nonexist", "is_wallet": True, "balance": 0},
                            raw={"status": "nonexist"}, center={"status": "uninit", "balance": "0"})
        result = await probe_ton_account(ADDRESS, deadline=asyncio.get_running_loop().time()+2, providers=providers)
        self.assertEqual(result["descriptor"]["account_type"], "uninitialized_account")
        self.assertIsNone(result["descriptor"]["contract"]["wallet_version"])
        self.assertEqual(result["descriptor"]["client_attribution"]["status"], "UNKNOWN")

    async def test_malformed_or_wrong_account_payloads_stay_unknown_with_raw_evidence(self):
        providers = clients()
        providers['tonapi'].responses[f'/accounts/{ADDRESS}']={'address':OTHER,'status':'active','name':'Crypto Bot'}
        providers['tonapi'].responses[f'/blockchain/accounts/{ADDRESS}']={}
        providers['tonapi'].responses[f'/blockchain/accounts/{ADDRESS}/transactions']={'transactions':'invalid'}
        providers['toncenter'].responses['/api/v3/addressInformation']={}
        result=await probe_ton_account(ADDRESS,deadline=asyncio.get_running_loop().time()+2,providers=providers)
        self.assertEqual(result['coverage']['status'],'PARTIAL')
        self.assertEqual(result['descriptor']['contract']['status'],'UNKNOWN')
        self.assertEqual(result['descriptor']['attributions'],[])
        self.assertEqual(len(result['errors']),4)
        self.assertEqual(len(result['observations']),4)
        self.assertEqual(result['report_fragment']['transactions'],[])

    async def test_p0_and_existing_ton_collector_share_native_message_identity(self):
        from app.aggregator.analyzer import _dedupe_report, _merge
        from app.sources.ton_tonapi import TonApiSource
        row = {"hash": "dd"*32, "lt": 987, "utime": 1789999999, "success": False,
            "in_msg": {"source": {"address": OTHER}, "destination": {"address": ADDRESS}, "value": "1000000001"},
            "out_msgs": []}
        result = await probe_ton_account(ADDRESS, deadline=asyncio.get_running_loop().time()+2,
                                        providers=clients(transactions=[row]))
        initial = AddressReport.model_validate(result['report_fragment'])
        legacy = AddressReport(target_address=ADDRESS)
        TonApiSource(1)._parse_transactions(ADDRESS, legacy, [row])
        merged = _dedupe_report(_merge(initial, legacy))
        self.assertEqual(len(merged.transactions), 1)
        self.assertFalse(merged.transactions[0].success)
        self.assertGreaterEqual(len(merged.transactions[0].provenance), 2)

    async def test_initial_probe_reused_and_both_transaction_sides_attached(self):
        providers = clients()
        initial = await probe_ton_account(ADDRESS, deadline=asyncio.get_running_loop().time()+2, providers=providers)
        original = report(); before = original.model_dump(mode="json")
        payload = await enrich_ton_service_intelligence(original, deadline=asyncio.get_running_loop().time()+2,
                                                       providers=providers, initial_account=initial)
        self.assertEqual(len(providers["tonapi"].calls), 5)  # three P0 + two counterparties
        self.assertEqual(payload["stats"]["requests"], 6)
        self.assertEqual(payload["addresses"][OTHER]["attributions"][0]["service_id"], "cryptobot")
        self.assertEqual(payload["addresses"][THIRD]["attributions"][0]["service_id"], "xrocket")
        self.assertTrue(payload["transactions"][0]["sender_attribution_ids"])
        self.assertTrue(payload["transactions"][1]["recipient_attribution_ids"])
        self.assertEqual(original.transactions[0].amount_decimal, Decimal("1.234567891"))
        self.assertEqual(original.model_dump(mode="json", exclude={"ton_service_intelligence"}),
                         {k: v for k, v in before.items() if k != "ton_service_intelligence"})

    async def test_deadline_cancels_pending_provider_calls_and_keeps_partial(self):
        release = asyncio.Event()
        providers = clients(); providers["tonapi"].block = release
        result = await probe_ton_account(ADDRESS, deadline=asyncio.get_running_loop().time()+.04, providers=providers)
        self.assertEqual(result["coverage"]["status"], "TRUNCATED")
        self.assertTrue(providers["tonapi"].cancelled)
        calls_after_return = len(providers["tonapi"].calls)
        release.set(); await asyncio.sleep(.01)
        self.assertEqual(len(providers["tonapi"].calls), calls_after_return)
        self.assertEqual(result["descriptor"]["account_status"], "active")  # independent completed source retained

    async def test_failed_transaction_does_not_expand_counterparty_queries(self):
        providers = clients(); original = report()
        for tx in original.transactions:
            tx.success = False
        initial = await probe_ton_account(ADDRESS, deadline=asyncio.get_running_loop().time()+2, providers=providers)
        payload = await enrich_ton_service_intelligence(original, deadline=asyncio.get_running_loop().time()+2,
                                                       providers=providers, initial_account=initial)
        self.assertEqual(payload["coverage"]["counterparties_queried"], 0)
        self.assertEqual(len(payload["transactions"]), 2)
        self.assertEqual(payload["addresses"][OTHER]["client_attribution"]["status"], "UNKNOWN")

    async def test_mismatched_reused_probe_rejected(self):
        with self.assertRaises(ValueError):
            await enrich_ton_service_intelligence(report(), deadline=asyncio.get_running_loop().time()+1,
                                                  initial_account={"address": OTHER})

    async def test_request_budget_not_reset_after_reused_probe(self):
        providers = clients()
        initial = await probe_ton_account(ADDRESS, deadline=asyncio.get_running_loop().time()+2, providers=providers)
        payload = await enrich_ton_service_intelligence(report(), deadline=asyncio.get_running_loop().time()+2,
            max_requests=4, providers=providers, initial_account=initial)
        self.assertEqual(payload["stats"]["requests"], 4)
        self.assertEqual(payload["coverage"]["counterparties_queried"], 0)
        self.assertEqual(payload["coverage"]["status"], "TRUNCATED")

    async def test_429_observation_and_status_are_preserved(self):
        providers = clients()
        response = httpx.Response(429, request=httpx.Request("GET", "https://fixture.invalid/account"))
        providers["tonapi"].responses[f"/accounts/{ADDRESS}"] = httpx.HTTPStatusError("rate limit", request=response.request, response=response)
        result = await probe_ton_account(ADDRESS, deadline=asyncio.get_running_loop().time()+2, providers=providers)
        self.assertTrue(any(row["status"] == "rate_limited" for row in result["observations"]))
        self.assertEqual(result["coverage"]["status"], "PARTIAL")
        self.assertTrue(any(row["status"] == "rate_limited" for row in result["errors"]))


if __name__ == "__main__":
    unittest.main()
