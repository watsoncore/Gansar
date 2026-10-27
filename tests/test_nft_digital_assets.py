"""Metadata presentation must retain the NFT engine's proof boundary."""
from pathlib import Path
import asyncio
import tempfile
import unittest

from app.ton_nft.discovery import KNOWN_COLLECTIONS
from app.ton_nft.models import NFTIntelligenceReport, VerificationStatus
from app.ton_nft.providers import Payload, TonAPIProvider, ToncenterProvider
from app.ton_nft.service import NFTInvestigator
from app.ton_nft.storage import InvestigationStore
from app.utils.ton_normalize import ton_canonical_address


ITEM = "0:" + "71" * 32
OWNER = "0:" + "72" * 32
COLLECTION = "0:" + "73" * 32


class MediaTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = InvestigationStore(Path(self.directory.name) / "nft.sqlite3")
        self.engine = NFTInvestigator(NFTIntelligenceReport(investigation_id="metadata-test", query=OWNER), self.store)
        self.payload = Payload({}, "obs:metadata-test", "tonapi_nft", "tonapi.io", "https://tonapi.io/v2/nfts/" + ITEM)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def row(self, metadata=None, **extra):
        return {"address": ITEM, "owner_address": OWNER, "collection_address": COLLECTION,
            "metadata": metadata or {}, **extra}

    def test_item_media_keeps_original_and_small_real_thumbnail_with_provenance(self):
        row = self.row({"name": "Real item", "image": "https://example.org/item.webp",
            "lottie": "https://example.org/item.lottie.json"}, previews=[
                {"resolution": "1500x1500", "url": "https://example.org/large.webp"},
                {"resolution": "5x5", "url": "https://example.org/tiny.webp"},
                {"resolution": "100x100", "url": "https://example.org/small.webp"}])
        asset = self.engine.upsert_item(row, self.payload)
        self.assertEqual(asset.image_url, "https://example.org/item.webp")
        self.assertEqual(asset.thumbnail_url, "https://example.org/small.webp")
        self.assertEqual(asset.animation_url, "https://example.org/item.lottie.json")
        self.assertTrue(all(m["observation_id"] == self.payload.observation_id for m in asset.image_sources))
        self.engine.upsert_item(row, self.payload)
        self.assertEqual(len(asset.image_sources), 4)
        self.assertEqual(asset.current_owner_status, VerificationStatus.PROVIDER_REPORTED)

    def test_dns_item_rendition_fallback_does_not_borrow_collection_image(self):
        asset = self.engine.upsert_item(self.row({"name": "real.ton"}, dns="real.ton",
            collection={"image": "https://example.org/collection.webp"}, previews=[
                {"resolution": "100x100", "url": "https://example.org/domain-small.webp"},
                {"resolution": "1500x1500", "url": "https://example.org/domain-large.webp"},
                {"resolution": "100x100", "url": "javascript:alert(1)"}]), self.payload)
        self.assertEqual(asset.image_url, "https://example.org/domain-large.webp")
        self.assertEqual(asset.thumbnail_url, "https://example.org/domain-small.webp")
        self.assertEqual(asset.dns["name"], "real.ton")
        self.assertNotIn("resolution", asset.dns)

    def test_gift_appearance_and_host_do_not_prove_category_or_wallet_identity(self):
        asset = self.engine.upsert_item(self.row({"name": "Gift #123", "host_id": 123,
            "image": "https://nft.fragment.com/gift/item-123.webp",
            "attributes": [{"trait_type": "Model", "value": "Golden"}]}), self.payload)
        self.engine.classify_collectible(asset)
        self.assertEqual(asset.kind, "nft")
        self.assertIsNone(asset.telegram)
        self.assertEqual(asset.current_owner, OWNER)
        self.assertEqual(asset.current_owner_status, "provider_reported")

    def test_dns_destination_is_not_attached_to_a_different_item(self):
        asset = self.engine.upsert_item(self.row({"name": "different.ton"}), self.payload)
        called = []

        async def domain(name):
            return Payload({"item": {"address": COLLECTION}, "expiring_at": 123},
                "obs:different", "tonapi_nft", "tonapi.io", "https://tonapi.io/v2/dns/" + name)

        async def resolve(name):
            called.append(name)

        self.engine.tonapi.domain = domain
        self.engine.tonapi.resolve_domain = resolve
        asyncio.run(self.engine.enrich_domain_metadata(asset))
        self.assertFalse(called)
        self.assertNotIn("resolution", asset.dns)
        self.assertNotIn("expiring_at", asset.dns)
        self.assertEqual(asset.current_owner_status, "provider_reported")

    def test_trusted_gift_still_requires_membership_and_exact_public_link(self):
        address = ton_canonical_address(KNOWN_COLLECTIONS["gift:lolpops"]["address"])
        asset = self.engine.upsert_item(self.row({"name": "Lol Pop #123", "external_url": "https://evil.example/t.me/nft/LolPop-123",
            "attributes": [{"trait_type": "Model", "value": "Golden"}, {"trait_type": "Absent"}]},
            collection_address=address), self.payload)
        self.engine.classify_collectible(asset)
        self.assertEqual(asset.kind, "nft")
        asset.collection_status = VerificationStatus.VERIFIED_ONCHAIN
        self.engine.classify_collectible(asset)
        self.assertEqual(asset.kind, "gift")
        self.assertIsNone(asset.telegram.public_url)
        self.assertEqual(asset.telegram.gift_number, 123)
        self.assertEqual(asset.telegram.gift_attributes, {"Model": "Golden"})
        self.assertEqual(asset.telegram.identity_status, "unknown")
        self.assertEqual(asset.telegram.assignment_status, "unknown")
        self.assertEqual(asset.category_provenance["registry_source"], KNOWN_COLLECTIONS["gift:lolpops"]["source"])


class FreshInventoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_current_inventory_and_dns_bypass_shared_history_cache(self):
        for cls in (TonAPIProvider, ToncenterProvider):
            provider = cls()
            calls = []

            async def record(path, params=None, body=None, *, fresh=False):
                calls.append((path, fresh))
                return Payload({}, "obs:request", provider.name, provider.upstream, provider.base_url + path)

            provider.call = record
            await provider.items(OWNER, scope="wallet", offset=100, limit=100)
            await provider.domain("real.ton")
            if isinstance(provider, TonAPIProvider):
                await provider.resolve_domain("real.ton")
            self.assertTrue(all(fresh for _, fresh in calls))


if __name__ == "__main__":
    unittest.main()
