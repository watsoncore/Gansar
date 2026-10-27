"""ENS protocol/security checks. Synthetic transports are not live evidence."""
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from app.models.report import AddressReport
from app.utils.http import request_public_json
from app.sources.ethereum_ens import (
    EthereumEnsSource, ENS_REGISTRY, _Lookup, _abi_dynamic, _dynamic_bytes,
    _public_image_bytes, _thumbnail_png, _word, media_url, namehash, normalize_name,
)

ADDRESS = "0x" + "a" * 40
OTHER = "0x" + "b" * 40
RESOLVER = "0x" + "c" * 40
NAME = "example.eth"


def address_abi(value):
    return "0x" + value[2:].zfill(64)


def bytes_abi(value):
    return "0x" + _abi_dynamic(value).hex()


class ProtocolSource(EthereumEnsSource):
    def __init__(self, *, reverse=NAME, forward=ADDRESS, empty=False, wildcard=False):
        super().__init__(24)
        self.reverse, self.forward, self.empty, self.wildcard = reverse, forward, empty, wildcard
        self.calls = []

    async def _rpc(self, lookup, method, params):
        lookup.rpc_calls += 1
        if method == "eth_chainId":
            return {"result": "0x1"}
        if method == "eth_blockNumber":
            return {"result": "0x1234"}
        call, block = params
        self.calls.append((call, block))
        data = call["data"]
        selector = data[:10]
        if call["to"].lower() == ENS_REGISTRY.lower():
            node = data[10:74]
            if selector == "0x02571be3":
                return {"result": address_abi(OTHER)}
            empty = self.empty or self.wildcard and node == namehash("sub.example.eth")
            return {"result": address_abi("0x" + "0" * 40 if empty else RESOLVER)}
        if selector == "0x01ffc9a7":
            return {"result": "0x" + f"{int(self.wildcard):064x}"}
        if selector == "0x9061b923":
            args = bytes.fromhex(data[10:])
            inner = _dynamic_bytes(args, _word(args, 32))
            inner_result = self.record("0x" + inner.hex())
            return {"result": bytes_abi(bytes.fromhex(inner_result[2:]))}
        return {"result": self.record(data)}

    def record(self, data):
        if data.startswith("0x691f3431"):
            return bytes_abi(self.reverse.encode()) if self.reverse else bytes_abi(b"")
        if data.startswith("0x3b3b57de"):
            return address_abi(self.forward)
        if data.startswith("0x59d1d43c"):
            args = bytes.fromhex(data[10:])
            key = _dynamic_bytes(args, _word(args, 32)).decode()
            # Reverse avatar is deliberately absent: ENSIP-12 falls back to a
            # forward profile only after reverse+forward verification.
            is_reverse = data[10:74] == namehash(ADDRESS[2:] + ".addr.reverse")
            values = {} if is_reverse else {"description": "<script>untrusted</script>", "com.github": "example", "header": "https://images.example.com/banner.png"}
            return bytes_abi(values.get(key, "").encode())
        if data.startswith("0xf1cb7e06"):
            coin = int(data[74:], 16)
            return bytes_abi(bytes.fromhex(self.forward[2:]) if coin == 60 else b"")
        return "0x"


class EnsNames(unittest.TestCase):
    def test_ensip15_case_unicode_and_invalid_names(self):
        self.assertEqual(normalize_name("ExAmPlE.EtH"), NAME)
        self.assertEqual(normalize_name("RaFFY🚴‍♂️.eTh"), "raffy🚴‍♂.eth")
        for value in ("foo..eth", "foo\x00.eth", ".eth", "a." * 17 + "eth"):
            with self.assertRaises(ValueError):
                normalize_name(value)
        self.assertEqual(namehash("eth"), "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae")

    def test_media_scheme_size_and_private_host_rejection(self):
        self.assertEqual(media_url("ipfs://QmPublic/image.png"), "https://ipfs.io/ipfs/QmPublic/image.png")
        for value in ("javascript:alert(1)", "http://example.com/a.png", "https://127.0.0.1/a.png", "https://localhost/a.png", "data:text/html;base64,PHNjcmlwdD4=", "data:image/svg+xml;base64,PHN2Zz4=", "ipfs://QmPublic/../secret", "https://user:secret@example.com/a.png"):
            self.assertIsNone(media_url(value), value)
        with self.assertRaises((OSError, ValueError)):
            _thumbnail_png(b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>')


class EnsProtocol(unittest.IsolatedAsyncioTestCase):
    async def test_public_metadata_https_mode_blocks_redirect_downgrade(self):
        requests = []
        def transport(request):
            requests.append(request)
            if len(requests) == 1:
                return httpx.Response(302, headers={"location": "http://metadata.example.com/public.json"})
            return httpx.Response(200, json={"image": "https://images.example.com/public.png"})
        async def public_url(url):
            return url
        import asyncio
        loop = asyncio.get_running_loop()
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
            with patch("app.utils.http.validate_public_url", public_url), patch.object(loop, "getaddrinfo", AsyncMock(return_value=[(2, 1, 6, "", ("8.8.8.8", 443))])):
                with self.assertRaisesRegex(ValueError, "HTTPS"):
                    await request_public_json(client, "https://metadata.example.com/start", https_only=True)
                self.assertEqual(len(requests), 1)
                requests.clear()
                payload = await request_public_json(client, "https://metadata.example.com/start")
                self.assertEqual([request.url.scheme for request in requests], ["https", "http"])
                self.assertEqual(payload["image"], "https://images.example.com/public.png")

    async def test_forward_reverse_records_and_pinned_snapshot(self):
        source = ProtocolSource()
        report = await source.fetch(ADDRESS)
        self.assertEqual(report.ens_name, NAME)
        self.assertTrue(report.ens_reverse_valid)
        self.assertTrue(report.ens_profile["primary_verified"])
        self.assertEqual(report.ens_owner, OTHER)
        self.assertNotEqual(report.ens_owner, report.ens_resolved_address)
        self.assertEqual(report.text_records["description"], "<script>untrusted</script>")
        self.assertNotIn("org.telegram", report.text_records)
        self.assertIsNone(report.avatar)
        self.assertEqual(len(report.ens_profile["addresses"]), 1)
        self.assertFalse(report.ens_profile["addresses"][0]["ownership_claim"])
        self.assertTrue(all(block == "0x1234" for _, block in source.calls))
        self.assertFalse(report.transactions)

    async def test_unverified_reverse_does_not_import_someone_elses_profile(self):
        report = await ProtocolSource(forward=OTHER).fetch(ADDRESS)
        self.assertIsNone(report.ens_name)
        self.assertEqual(report.reverse_ens, NAME)
        self.assertFalse(report.ens_reverse_valid)
        self.assertFalse(report.text_records)
        self.assertIsNone(report.avatar)
        self.assertNotIn("name", report.ens_profile)

    async def test_name_input_keeps_queried_name_when_primary_is_different(self):
        report = await ProtocolSource(reverse="primary.eth").resolve_name("ExAmPlE.EtH")
        self.assertEqual(report.target_address, ADDRESS)
        self.assertEqual(report.ens_name, NAME)
        self.assertEqual(report.ens_profile["input_name"], NAME)
        self.assertEqual(report.ens_profile["name"], NAME)
        self.assertEqual(report.ens_profile["primary_name"], "primary.eth")
        self.assertFalse(report.ens_profile["primary_verified"])

    async def test_no_resolver_produces_status_without_fake_profile(self):
        report = await ProtocolSource(empty=True).fetch(ADDRESS)
        self.assertEqual(report.ens_profile["lookup_status"], "empty")
        self.assertNotIn("name", report.ens_profile)
        self.assertFalse(report.text_records)
        self.assertIsNone(report.ens_name)

    async def test_wildcard_uses_extended_resolve_not_legacy_child_calls(self):
        source = ProtocolSource(reverse="sub.example.eth", wildcard=True)
        report = await source.resolve_name("sub.example.eth")
        self.assertEqual(report.ens_resolved_address, ADDRESS)
        self.assertEqual(report.ens_profile["resolver_name"], NAME)
        self.assertEqual(report.ens_profile["resolution_method"], "ensip10")
        resolver_calls = [call["data"] for call, _ in source.calls if call["to"] == RESOLVER]
        self.assertTrue(any(data.startswith("0x9061b923") for data in resolver_calls))
        self.assertFalse(any(data.startswith("0x3b3b57de") for data in resolver_calls))

    async def test_nft_avatar_requires_owner_and_reads_real_metadata_image(self):
        source = EthereumEnsSource(24)
        report = AddressReport(target_address=ADDRESS)
        async with httpx.AsyncClient() as client:
            lookup = _Lookup(client, "https://rpc.example.com", report)
            record = "eip155:1/erc721:" + RESOLVER + "/7"
            with patch.object(source, "_eth_call", AsyncMock(return_value=address_abi(OTHER))) as call, patch("app.sources.ethereum_ens.request_public_json", AsyncMock()) as metadata:
                avatar = await source._avatar(lookup, record, ADDRESS)
                self.assertFalse(avatar["ownership_verified"])
                self.assertNotIn("url", avatar)
                self.assertEqual(call.await_count, 1)
                metadata.assert_not_awaited()
            calls = [address_abi(ADDRESS), bytes_abi(b"https://metadata.example.com/7.json")]
            with patch.object(source, "_eth_call", AsyncMock(side_effect=calls)), patch("app.sources.ethereum_ens.request_public_json", AsyncMock(return_value={"image": "ipfs://QmPublic/7.png"})):
                avatar = await source._avatar(lookup, record, ADDRESS)
                self.assertTrue(avatar["ownership_verified"])
                self.assertEqual(avatar["url"], "https://ipfs.io/ipfs/QmPublic/7.png")

    async def test_erc1155_avatar_requires_balance_and_expands_token_id(self):
        source = EthereumEnsSource(24)
        report = AddressReport(target_address=ADDRESS)
        async with httpx.AsyncClient() as client:
            lookup = _Lookup(client, "https://rpc.example.com", report)
            record = "eip155:1/erc1155:" + RESOLVER + "/7"
            calls = ["0x" + f"{2:064x}", bytes_abi(b"ipfs://QmMetadata/{id}.json")]
            with patch.object(source, "_eth_call", AsyncMock(side_effect=calls)), patch("app.sources.ethereum_ens.request_public_json", AsyncMock(return_value={"image": "https://images.example.com/7.png"})) as metadata:
                avatar = await source._avatar(lookup, record, ADDRESS)
                self.assertTrue(avatar["ownership_verified"])
                self.assertEqual(avatar["url"], "https://images.example.com/7.png")
                self.assertEqual(metadata.call_args.args[1], "https://ipfs.io/ipfs/QmMetadata/" + f"{7:064x}" + ".json")

    async def test_avatar_image_transport_rejects_private_uri_and_svg_response(self):
        source = EthereumEnsSource(24)
        report = AddressReport(target_address=ADDRESS)
        requests = []
        def transport(request):
            requests.append(request)
            return httpx.Response(200, headers={"content-type": "image/svg+xml"}, content=b'<svg onload="alert(1)"/>')
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
            lookup = _Lookup(client, "https://rpc.example.com", report)
            with patch("app.sources.ethereum_ens.validate_public_url", AsyncMock()) as validate:
                avatar = {"url": "https://127.0.0.1/avatar.png"}
                await source._avatar_thumbnail(lookup, avatar)
                self.assertEqual(avatar["thumbnail_status"], "unavailable")
                self.assertNotIn("thumbnail", avatar)
                validate.assert_not_awaited()
            import asyncio
            loop = asyncio.get_running_loop()
            with patch("app.sources.ethereum_ens.validate_public_url", AsyncMock(return_value="https://images.example.com/avatar.svg")), patch.object(loop, "getaddrinfo", AsyncMock(return_value=[(2, 1, 6, "", ("8.8.8.8", 443))])):
                with self.assertRaises(ValueError):
                    await _public_image_bytes(client, "https://images.example.com/avatar.svg")
                self.assertEqual(len(requests), 1)

    async def test_name_avatar_uses_forward_record_even_if_address_has_reverse_avatar(self):
        source = ProtocolSource()
        original = source.record
        reverse_node = namehash(ADDRESS[2:] + ".addr.reverse")
        def record(data):
            if data.startswith("0x59d1d43c"):
                args = bytes.fromhex(data[10:])
                if _dynamic_bytes(args, _word(args, 32)) == b"avatar":
                    return bytes_abi(("https://images.example.com/reverse.png" if data[10:74] == reverse_node else "https://images.example.com/forward.png").encode())
            return original(data)
        source.record = record
        with patch.object(source, "_avatar_thumbnail", AsyncMock()):
            report = await source.resolve_name(NAME)
        self.assertEqual(report.avatar, "https://images.example.com/forward.png")
        self.assertEqual(report.ens_profile["avatar"]["record_source"], "forward")

    async def test_rate_limit_stops_queued_record_calls_without_retry(self):
        source = EthereumEnsSource(24)
        report = AddressReport(target_address=ADDRESS)
        request = httpx.Request("POST", "https://rpc.example.com")
        error = httpx.HTTPStatusError("limited", request=request, response=httpx.Response(429, request=request))
        async with httpx.AsyncClient() as client:
            lookup = _Lookup(client, "https://rpc.example.com", report)
            with patch("app.sources.ethereum_ens.request_json", AsyncMock(side_effect=error)) as transport:
                records = await source._text_records(lookup, NAME, (RESOLVER, NAME, False))
                self.assertEqual(records, {})
                self.assertEqual(lookup.failure_status, "rate_limited")
                self.assertLessEqual(transport.await_count, 4)

    async def test_ccip_sender_and_callback_validation(self):
        source = EthereumEnsSource(24)
        report = AddressReport(target_address=ADDRESS)
        url = b"https://gateway.example.com/{sender}/{data}"
        urls = (1).to_bytes(32, "big") + _abi_dynamic(url)
        call_data = (2).to_bytes(32, "big") + b"\x12\x34" + b"\0" * 30
        extra = b"\0" * 32
        def offchain(sender):
            head = bytes.fromhex(sender[2:].zfill(64)) + (160).to_bytes(32, "big")
            head += (160 + len(urls)).to_bytes(32, "big") + bytes.fromhex("deadbeef".ljust(64, "0"))
            head += (160 + len(urls) + len(call_data)).to_bytes(32, "big")
            return "0x556f1830" + (head + urls + call_data + extra).hex()
        async with httpx.AsyncClient() as client:
            lookup = _Lookup(client, "https://rpc.example.com", report)
            with patch("app.sources.ethereum_ens.request_public_json", AsyncMock(return_value={"data": "0x1234"})) as gateway, patch.object(source, "_eth_call", AsyncMock(return_value=address_abi(ADDRESS))) as callback:
                invalid = await source._ccip_read(lookup, RESOLVER, offchain(OTHER), "addr", 0)
                self.assertIsNone(invalid)
                gateway.assert_not_awaited()
                valid = await source._ccip_read(lookup, RESOLVER, offchain(RESOLVER), "addr", 0)
                self.assertEqual(valid, address_abi(ADDRESS))
                self.assertEqual(lookup.ccip_verified, 1)
                self.assertTrue(callback.call_args.args[2].startswith("0xdeadbeef"))
                self.assertIsNone(await source._ccip_read(lookup, RESOLVER, offchain(RESOLVER), "addr", 2))


if __name__ == "__main__":
    unittest.main()
