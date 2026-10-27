from __future__ import annotations

import asyncio
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from app.models.report import AddressReport
from app.sources.bitcoin_blockstream import BitcoinBlockstreamSource
from app.sources.ethereum_etherscan_api import EthereumEtherscanApiSource
from app.sources.bsc import BscScanApiSource
from app.sources.tron_trongrid import TronGridSource
from app.sources.solana import SolanaRpcSource
from app.sources.dogecoin import DogecoinBlockchairSource
from app.sources.pagination import pages, operation_key

BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
EVM = "0x" + "1" * 40
SOL = "So11111111111111111111111111111111111111112"


class NonTonPaginationTests(unittest.IsolatedAsyncioTestCase):
    async def test_incremental_token_stream_does_not_join_normal_transaction_hash(self):
        source = SimpleNamespace(name="provider", _continuous=True, _incremental=True,
            _known_transaction_hashes={"same-transaction"},
            _resume_state={"txlist": {"observed_record_keys": [operation_key("txlist", {"hash": "same-transaction"})]}})
        report = AddressReport(target_address=EVM)
        calls = []
        async def fetch(cursor):
            calls.append(cursor)
            return {"rows": [{"hash": "same-transaction", "logIndex": index} for index in (1, 2)]} if len(calls) == 1 else {"rows": []}
        records = [row for data in [data async for data in pages(source, report, "tokentx", fetch, lambda data: data["rows"],
            lambda data, rows, cursor: {"offset": cursor.get("offset", 0) + len(rows)}, page_size=2)] for row in data["rows"]]
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(records), 2)
        self.assertEqual(report.collection_audit["streams"][source.name]["tokentx_refresh"]["stop_reason"], "endpoint_exhausted")

    async def test_incremental_internal_stream_joins_exact_trace_not_same_transaction(self):
        old = {"hash": "same-transaction", "traceId": "0_1"}
        source = SimpleNamespace(name="provider", _continuous=True, _incremental=True,
            _resume_state={"txlistinternal": {"next_cursor": {"offset": 4}, "exhausted": False,
                "observed_record_keys": [operation_key("txlistinternal", old)]}})
        report = AddressReport(target_address=EVM)
        calls = []
        async def fetch(cursor):
            calls.append(cursor.get("offset", 0))
            if len(calls) == 1:
                return {"rows": [{"hash": "same-transaction", "traceId": "0_0"}, old]}
            return {"rows": []}
        values = [value async for value in pages(source, report, "txlistinternal", fetch, lambda data: data["rows"],
            lambda data, rows, cursor: {"offset": cursor.get("offset", 0)+len(rows)}, page_size=2, adjust_offset=True)]
        self.assertEqual(calls, [0, 5])
        self.assertEqual(len(values[0]["rows"]), 2)
        head = report.collection_audit["streams"][source.name]["txlistinternal_refresh"]
        self.assertEqual(head["stop_reason"], "overlap_stored_history")
        self.assertEqual(head["fresh_records"], 1)

    async def test_btc_advances_real_txid_and_preserves_every_page(self):
        source, report = BitcoinBlockstreamSource(1), AddressReport(target_address=BTC)
        source._continuous = True
        rows = [{"txid": f"{i:064x}", "vin": [], "vout": [], "status": {"confirmed": True}} for i in range(26)]
        with patch.object(source, "_get_json", AsyncMock(side_effect=[rows[:25], rows[25:]])) as request:
            collected = await source._address_txs(None, BTC, report)
        self.assertEqual(len(collected), 26)
        self.assertEqual(len(report.transactions), 26)
        self.assertEqual(request.await_args_list[1].args[1], f"/address/{BTC}/txs/chain/{24:064x}")
        self.assertTrue(report.collection_audit["streams"][source.name]["account_transactions"]["exhausted"])

    async def test_btc_resume_starts_at_saved_txid(self):
        source, report = BitcoinBlockstreamSource(1), AddressReport(target_address=BTC)
        source._continuous = True
        source._resume_state = {"account_transactions": {"next_cursor": {"last_txid": "saved"}, "exhausted": False}}
        with patch.object(source, "_get_json", AsyncMock(return_value=[])) as request:
            await source._address_txs(None, BTC, report)
        self.assertTrue(request.await_args.args[1].endswith("/chain/saved"))

    async def test_etherscan_more_than_one_hundred_preserves_block_anchor(self):
        source, report = EthereumEtherscanApiSource(1), AddressReport(target_address=EVM)
        source._continuous = True
        rows = [{"hash": f"0x{i:064x}", "blockNumber": str(1000-i), "from": EVM, "to": "0x" + "2" * 40, "value": "1"} for i in range(101)]
        with patch.object(source, "_request", AsyncMock(side_effect=[{"result": rows[:100]}, {"result": rows[100:]}])) as request:
            await source._fetch_normal_txs(None, EVM, "fixture-key", report)
        self.assertEqual(len(report.transactions), 101)
        second = request.await_args_list[1].args[1]
        self.assertEqual(second["page"], "2")
        self.assertEqual(second["endblock"], "1000")
        self.assertEqual(report.transactions[100].raw["provider_record"]["hash"], rows[100]["hash"])

    async def test_same_etherscan_collector_supports_all_six_chain_ids(self):
        for chain, network_id in {"eth": "1", "bsc": "56", "polygon": "137", "arbitrum": "42161", "optimism": "10", "avalanche": "43114"}.items():
            source, report = EthereumEtherscanApiSource(1, chain), AddressReport(target_address=EVM)
            seen = []
            def serve(request):
                seen.append(request.url.params["chainid"])
                return httpx.Response(200, json={"status": "1", "result": []})
            async with httpx.AsyncClient(transport=httpx.MockTransport(serve)) as client:
                await source._request(client, {"module": "account", "action": "txlist"}, report)
            self.assertEqual(seen, [network_id])

    async def test_bsc_internal_and_normal_paginate_without_replacing_parser(self):
        source, report = BscScanApiSource(1), AddressReport(target_address=EVM)
        source._continuous = True
        rows = [{"hash": f"0x{i:064x}", "blockNumber": "10", "from": EVM, "to": "0x"+"2"*40, "value": "1", "traceId": str(i)} for i in range(101)]
        with patch.object(source, "_request", AsyncMock(side_effect=[{"result": rows[:100]}, {"result": rows[100:]}])):
            await source._fetch_txs(None, EVM, report, "txlistinternal", "internal")
        self.assertEqual(len(report.transactions), 101)
        self.assertEqual(report.transactions[-1].raw["trace_id"], "100")

    async def test_trongrid_uses_fingerprint_not_untrusted_next_url(self):
        source, report = TronGridSource(1), AddressReport(target_address="target")
        source._continuous = True
        seen = []
        def serve(request):
            seen.append(dict(request.url.params))
            if len(seen) == 1:
                return httpx.Response(200, json={"data": [{"txID": str(i)} for i in range(50)], "meta": {"fingerprint": "public-cursor", "links": {"next": "http://127.0.0.1/unsafe"}}})
            return httpx.Response(200, json={"data": [{"txID": "tail"}], "meta": {}})
        async with httpx.AsyncClient(transport=httpx.MockTransport(serve)) as client:
            batches = [value async for value in source._history_pages(client, "target", report, "transactions")]
        self.assertEqual(sum(len(value["data"]) for value in batches), 51)
        self.assertEqual(seen[1]["fingerprint"], "public-cursor")

    async def test_solana_decodes_more_than_fifteen_and_saves_pending_before_cancel(self):
        source, report = SolanaRpcSource(1), AddressReport(target_address=SOL)
        source._continuous = True
        entered = asyncio.Event()
        async def rpc(client, method, parameters, out, label):
            entered.set()
            await asyncio.sleep(60)
        rows = [{"signature": str(i), "slot": i} for i in range(51)]
        with patch.object(source, "_rpc_call", rpc):
            task = asyncio.create_task(source._parse_transactions(None, SOL, rows, {}, report))
            await entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        pending = report.collection_audit["streams"][source.name]["account_signatures"]["pending_details"]
        self.assertEqual(len(pending), 51)

    async def test_solana_all_fifty_one_signatures_are_retained(self):
        source, report = SolanaRpcSource(1), AddressReport(target_address=SOL)
        source._continuous = True
        rows = [{"signature": str(i), "slot": i} for i in range(51)]
        with patch.object(source, "_rpc_call", AsyncMock(return_value={"result": {"meta": {"err": None}, "transaction": {"message": {"instructions": []}}}})):
            await source._parse_transactions(None, SOL, rows, {}, report)
        self.assertEqual(len(report.transactions), 51)
        self.assertEqual(report.collection_audit["streams"][source.name]["account_signatures"]["pending_details"], [])

    async def test_real_solana_fetch_advances_before_signature(self):
        source = SolanaRpcSource(1)
        source._continuous = True
        seen = []
        async def rpc(client, method, parameters, out, label):
            if method == "getSignaturesForAddress":
                seen.append(parameters[1])
                return {"result": [{"signature": str(i), "slot": i} for i in range(50)] if len(seen) == 1 else [{"signature": "tail", "slot": 1}]}
            if method == "getTransaction":
                return {"result": {"meta": {}, "transaction": {"message": {"instructions": []}}}}
            return {"result": {"value": 0} if method == "getBalance" else {"value": []} if method == "getTokenAccountsByOwner" else {"value": None}}
        with patch.object(source, "_rpc_call", rpc):
            report = await source.fetch(SOL)
        self.assertEqual(len(report.transactions), 51)
        self.assertEqual(seen[1]["before"], "49")
        self.assertIs(source._partial_report, report)

    async def test_same_solana_signature_identical_transfers_stay_distinct(self):
        from app.aggregator.analyzer import _dedupe_report
        source, report = SolanaRpcSource(1), AddressReport(target_address=SOL)
        source._continuous = True
        instruction = {"program": "system", "parsed": {"type": "transfer", "info": {"source": SOL, "destination": "destination", "lamports": 1}}}
        payload = {"result": {"meta": {}, "transaction": {"message": {"instructions": [instruction, instruction]}}}}
        with patch.object(source, "_rpc_call", AsyncMock(return_value=payload)):
            await source._parse_transactions(None, SOL, [{"signature": "sig"}], {}, report)
        self.assertEqual(len(_dedupe_report(report).transactions), 2)

    async def test_identical_internal_calls_have_distinct_trace_ids(self):
        from app.aggregator.analyzer import _dedupe_report
        source, report = BscScanApiSource(1), AddressReport(target_address=EVM)
        row = {"hash": "0x" + "a" * 64, "blockNumber": "10", "from": EVM, "to": "0x"+"2"*40, "value": "1"}
        with patch.object(source, "_request", AsyncMock(return_value={"result": [{**row, "traceId": index} for index in ("0_0", "0_1")]})):
            await source._fetch_txs(None, EVM, report, "txlistinternal", "internal")
        self.assertEqual(len(_dedupe_report(report).transactions), 2)

    async def test_doge_continuous_fetch_keeps_failed_detail_reference_and_cursor(self):
        source, report = DogecoinBlockchairSource(1), AddressReport(target_address="target")
        source._continuous = True
        dashboard = {"address": {"balance": 0, "transaction_count": 1}, "transactions": ["tx"], "utxo": []}
        with patch.object(source, "_stats", AsyncMock(return_value={})), patch.object(source, "_address_dashboard", AsyncMock(return_value=dashboard)), patch.object(source, "_transaction_detail", AsyncMock(return_value={})):
            await source._fetch_continuous("target", report)
        self.assertEqual(len(report.transactions), 1)
        self.assertEqual(report.transactions[0].tx_hash, "tx")
        self.assertEqual(report.collection_audit["streams"][source.name]["account_transactions"]["pending_details"], ["tx"])
        self.assertEqual(report.source_health[-1].status, "partial")

    async def test_doge_details_limit_no_longer_drops_after_thirty(self):
        source, report = DogecoinBlockchairSource(1), AddressReport(target_address="target")
        source._continuous = True
        retained = []
        with patch.object(source, "_transaction_detail", AsyncMock(return_value={"transaction": {}})):
            result = await source._transaction_details(None, [str(i) for i in range(101)], report, on_detail=lambda tx, payload: retained.append(tx))
        self.assertEqual(len(result), 101)
        self.assertEqual(len(retained), 101)

    async def test_rate_limit_does_not_claim_exhausted_history(self):
        source, report = SimpleNamespace(name="provider", _continuous=True), AddressReport(target_address="target")
        calls = []
        async def fetch(cursor):
            calls.append(cursor)
            if len(calls) == 1:
                return {"rows": [{"hash": str(i)} for i in range(2)]}
            raise httpx.HTTPStatusError("limited", request=httpx.Request("GET", "https://example.com"), response=httpx.Response(429))
        result = [data async for data in pages(source, report, "history", fetch, lambda data: data.get("rows"), lambda data, rows, cursor: {"offset": cursor.get("offset", 0) + len(rows)}, page_size=2)]
        self.assertEqual(len(result), 1)
        state = report.collection_audit["streams"][source.name]["history"]
        self.assertFalse(state["exhausted"])
        self.assertEqual(state["next_cursor"], {"offset": 2})
        self.assertEqual(state["stop_reason"], "provider_error")


if __name__ == "__main__":
    unittest.main()
