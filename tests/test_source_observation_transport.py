"""Lossless bounded raw transport and real browser lazy-disclosure contracts."""
from __future__ import annotations

import asyncio
from copy import deepcopy
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from playwright.async_api import async_playwright

from app.exporters import html_exporter, source_transport
from app.graph.builder import build_graph_payload
from app.models.report import AddressReport


class SourceTransportTests(unittest.TestCase):
    def test_small_pool_keeps_exact_original_format_and_objects(self):
        pool = {"id": {"raw": {"value": "Привет 💎", "n": 123}}}
        inline, descriptor, chunks = source_transport.prepare_source_observations(pool)
        self.assertIs(inline, pool)
        self.assertIsNone(descriptor)
        self.assertEqual(chunks, [])

    def test_byte_and_record_bounds_preserve_every_key_and_detach_containers(self):
        pool = {f"id-{i}": {"raw": "x" * (500 if i == 4 else 4)} for i in range(11)}
        before = deepcopy(pool)
        with patch.object(source_transport, "SOURCE_POOL_INLINE_BYTES", 1), \
                patch.object(source_transport, "SOURCE_CHUNK_BYTES", 180), \
                patch.object(source_transport, "SOURCE_CHUNK_RECORDS", 3):
            inline, index, chunks = source_transport.prepare_source_observations(pool)
        self.assertEqual(inline, {})
        self.assertEqual(index["records"], len(pool))
        restored = {}
        for descriptor, chunk in zip(index["chunks"], chunks):
            self.assertEqual(descriptor["id"], chunk["id"])
            self.assertEqual(descriptor["keys"], list(chunk["records"]))
            self.assertLessEqual(len(chunk["records"]), 3)
            if len(chunk["records"]) > 1:
                self.assertLessEqual(len(html_exporter._browser_json(chunk["records"]).encode()), 180)
            for key, value in chunk["records"].items():
                self.assertNotIn(key, restored)
                self.assertIs(value, pool[key])
                restored[key] = value
        self.assertEqual(restored, pool)
        self.assertEqual(pool, before)
        oversized = next(c for c in chunks if "id-4" in c["records"])
        self.assertEqual(list(oversized["records"]), ["id-4"])

    def test_conservative_hint_covers_browser_escapes_and_large_numbers(self):
        values = [{"\"<&💎": ["\n\\\"<>💎", 2**100, None, True]}, ["中文", {}]]
        for value in values:
            self.assertGreaterEqual(source_transport._size_hint(value, 10**9),
                len(html_exporter._browser_json(value).encode("ascii")))


class LazySourceBrowserTests(unittest.TestCase):
    def test_real_original_report_keeps_all_raw_and_loads_only_requested_chunk(self):
        asyncio.run(self._browser_roundtrip())

    async def _browser_roundtrip(self):
        address = "0:" + "1" * 64
        pool = {"__proto__": {"source": "fixture", "raw": {"value": "Привет 💎 </script>&", "api_key": "do-not-render"}},
            "constructor": {"source": "fixture", "raw": {"n": 2**70}},
            **{f"source-{i}": {"source": "fixture", "raw": {"index": i, "text": "payload" * 30}} for i in range(5)}}
        report = AddressReport(target_address=address, detected_chains=["ton"])
        report.attribution_intelligence = {"target_address": address, "target_chain": "ton",
            "source_observations": pool, "addresses": {address: {"blockchain": "ton", "address": address,
                "evidence_ids": ["proof-1"]}}, "evidence": [{"evidence_id": "proof-1", "source": "fixture",
                "facts": {"source_provenance_refs": ["constructor", "__proto__", "constructor"]}}]}
        original = deepcopy(report.attribution_intelligence)
        with tempfile.TemporaryDirectory() as directory, patch.object(source_transport, "SOURCE_POOL_INLINE_BYTES", 1), \
                patch.object(source_transport, "SOURCE_CHUNK_RECORDS", 1):
            path = html_exporter.export_html_report(report, build_graph_payload(report), Path(directory)).output_path
            html = path.read_text(encoding="utf-8")
            self.assertNotIn("do-not-render", html)
            self.assertEqual(report.attribution_intelligence, original)
            main = json.loads(re.search(r'<script id="nft-payload" type="application/json">(.*?)</script>', html, re.S).group(1))
            self.assertEqual(main["services"]["source_observations"], {})
            self.assertEqual(main["_source_observation_transport"]["records"], len(pool))
            async with async_playwright() as runtime:
                browser = await runtime.chromium.launch(args=["--disable-background-networking"])
                try:
                    page = await browser.new_page()
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    await page.route("**/*", lambda route: route.continue_() if route.request.url.startswith(("file:", "data:", "blob:")) else route.abort())
                    await page.goto(path.as_uri())
                    result = await page.evaluate("""() => {
                      const p=serviceSourceObservations,d=serviceSourceTransport;
                      const count=()=>d.chunks.filter(c=>document.getElementById(c.id).textContent==='').length;
                      const before=count(),keys=Object.keys(p),afterMembership=count();
                      const a=p.__proto__,afterOne=count(),same=p.__proto__===a;
                      const facts=fullServiceFacts(serviceEvidenceById.get('proof-1').facts);
                      return {before,afterMembership,afterOne,keys,same,nullPrototype:Object.getPrototypeOf(p)===null,
                        original:a.raw.value,redacted:a.raw.api_key,integer:facts.source_provenance[0].raw.n,
                        ordered: facts.source_provenance[0]===p.constructor&&facts.source_provenance[1]===a&&facts.source_provenance[2]===p.constructor,
                        loaded:count(),pollution:({}).source===undefined};
                    }""")
                    self.assertEqual(result["before"], 0)
                    self.assertEqual(result["afterMembership"], 0)
                    self.assertEqual(result["afterOne"], 1)
                    self.assertEqual(result["loaded"], 2)
                    self.assertEqual(result["keys"], list(pool))
                    self.assertEqual(result["original"], "Привет 💎 </script>&")
                    self.assertEqual(result["redacted"], "[REDACTED]")
                    self.assertEqual(result["integer"], str(2**70))
                    self.assertTrue(all(result[k] for k in ("same", "nullPrototype", "ordered", "pollution")))
                    await page.evaluate("""() => {const host=document.createElement('div');host.id='proof-test';
                      host.innerHTML=serviceEvidenceMarkup(integratedNftPayload.services.target_key,'Owner');document.body.append(host);}
                    """)
                    proof = page.locator('#proof-test details[data-service-proof-id="proof-1"]')
                    self.assertEqual(await proof.locator('[data-service-proof-target]').text_content(), '')
                    await proof.evaluate('el=>el.open=true')
                    await page.wait_for_function("document.querySelector('#proof-test [data-service-proof-target]')?.textContent.length>0")
                    disclosed = json.loads(await page.locator('#proof-test [data-service-proof-target]').text_content())
                    self.assertEqual(disclosed['source_provenance'][1]['raw']['value'], 'Привет 💎 </script>&')
                    self.assertEqual(disclosed['source_provenance'][0]['raw']['n'], str(2**70))
                    await page.locator("#serviceSourceObservations").evaluate("el=>el.open=true")
                    await page.wait_for_function("document.querySelector('#serviceSourceObservationsData')?.dataset.sourceIndexReady==='1'")
                    self.assertLessEqual(await page.locator("#serviceSourceObservations details").count(), 128)
                    # Explicitly request the remaining raw values. Every value is
                    # still present offline, including arbitrary provider keys.
                    # Return entries because the browser automation protocol's
                    # object copier treats __proto__ specially. The HTML's own
                    # null-prototype map is tested above, without that copier.
                    restored = dict(await page.evaluate("() => Object.entries(JSON.parse(JSON.stringify(serviceSourceObservations)))"))
                    self.assertEqual(set(restored), set(pool))
                    self.assertEqual(restored["source-4"]["raw"], pool["source-4"]["raw"])
                    self.assertEqual(errors, [])
                    validation = await page.evaluate("""() => {
                      const entry={id:'gansar-source-chunk-999',keys:['a','a']};
                      try {restoreServiceSourceObservations({_source_observation_transport:{version:1,records:2,chunks:[entry]},services:{source_observations:{}}});return false;}catch{return true;}
                    }""")
                    self.assertTrue(validation)
                finally:
                    await browser.close()


if __name__ == "__main__":
    unittest.main()
