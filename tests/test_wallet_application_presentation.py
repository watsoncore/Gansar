"""Presentation role separation and loss accounting, using marked fixtures."""
import hashlib
import asyncio
import json
from pathlib import Path
import re
import tempfile
import unittest
import copy

from app.exporters.html_exporter import export_html_report
from app.graph.builder import build_graph_payload
from app.models.report import AddressReport, Transaction

A='0:'+'1'*64

def fixture(count=1,client=None):
    return AddressReport(target_address=A,detected_chains=['ton'],transactions=[Transaction(chain='ton',
        tx_hash=f'{i:064x}',event_id=f'fixture:{i}',source='synthetic_ui_fixture',asset='TON') for i in range(count)],
        attribution_intelligence={'target_chain':'ton','target_key':'ton:'+A,'addresses':{'ton:'+A:{
            'address':A,'blockchain':'ton','contract':{'wallet_version':'V5R1'},'attributions':[],
            'client_attribution':client or {'status':'UNKNOWN','name':'Tonkeeper','application_id':'tonkeeper',
                'reason':'Standard V5 is shared','checks':[{'method':'standard_contract','status':'observed',
                    'result':'V5 shared by independent apps','source_urls':['https://example.com/spec','http://127.0.0.1/private']}],
                'candidates':[{'name':'Tonkeeper-compatible construction','status':'POSSIBLE'}]}}},
            'evidence':[{'evidence_id':'fixture:proof','source':'synthetic_fixture','url':'https://example.com/fixture','facts':{'synthetic':True}}]})

def render(report):
    with tempfile.TemporaryDirectory() as directory:
        return export_html_report(report,build_graph_payload(report),Path(directory)).output_path.read_text(encoding='utf-8')

def payload(html):return json.loads(re.search(r'<script id="nft-payload" type="application/json">(.*?)</script>',html,re.S).group(1))

class WalletApplicationPresentation(unittest.TestCase):
    def test_unknown_application_does_not_borrow_contract_or_service_logo(self):
        html=render(fixture());data=payload(html);client=data['services']['addresses']['ton:'+A]['client_attribution']
        self.assertEqual(client['name'],'UNKNOWN');self.assertEqual(client['logo'],'')
        self.assertIn('Wallet Application / Signing client',html)
        self.assertIn('Custodial service / control',html)
        self.assertIn('Unverified application hypotheses',html)
        self.assertEqual(client['checks'][0]['source_urls'],['https://example.com/spec'])
        self.assertIn('https://example.com/spec',data['public_urls'])
        self.assertNotIn('href="http://127.',html)
    def test_app_logo_requires_scoped_evidence_and_embeds_original_license(self):
        client={'status':'PROBABLE','name':'OpenMask','application_id':'openmask','evidence_ids':['fixture:proof'],
            'method':'synthetic_presentation_only','reason':'Fixture only, no live app claim'}
        html=render(fixture(client=client));data=payload(html)
        self.assertTrue(data['services']['addresses']['ton:'+A]['client_attribution']['logo'].startswith('data:image/png;base64,'))
        self.assertIn('GNU GENERAL PUBLIC LICENSE',html)
        self.assertIn('9150d57d530296f8b27ae59e4dfce865be81550e',html)
        client['evidence_ids']=[]
        self.assertEqual(payload(render(fixture(client=client)))['services']['addresses']['ton:'+A]['client_attribution']['logo'],'')
    def test_all_1201_operations_are_embedded_and_pagination_is_only_a_view(self):
        report=fixture(1201);html=render(report);data=payload(html)
        stage=data['collection_audit']['stages']['html']
        self.assertEqual(len(data['transaction_views']),1201)
        self.assertEqual(stage['initial_dom_rows'],260)
        self.assertEqual(stage['normalized_model_records'],1201)
        self.assertEqual(stage['model_event_ids_sha256'],stage['browser_operation_ids_sha256'])
        self.assertFalse(stage['ui_page_limit_is_collection_limit'])
        self.assertIn('collectionAudit',html)
        self.assertEqual(report.collection_audit,{}) # exporter keeps caller snapshot immutable
    def test_original_css_and_navigation_survive_app_checks(self):
        template=(Path(__file__).resolve().parents[1]/'app/exporters/investigation_template.html').read_text(encoding='utf-8')
        for pattern,expected in ((r'<style>(.*?)</style>','617e933a0973854d1fafb1a2501c9ce3aeae224553e733e742595e293b7801d7'),
            (r'<section class="panel nav">(.*?)</section>','fe74b164f088dad4d80a0491f6d7cdebf10027ee8e1039798ffd51a04e9fc959')):
            content=re.search(pattern,template,re.S).group(1)
            if pattern.startswith('<section'):
                extension=r"(?m)^[ \t]*<!-- GANSAR_INFERENTIAL_BEGIN -->\n.*?^[ \t]*<!-- GANSAR_INFERENTIAL_END -->\n"
                self.assertEqual(len(list(re.finditer(extension,content,re.S))),1)
                content=re.sub(extension,'',content,flags=re.S|re.M)
            self.assertEqual(hashlib.sha256(content.encode()).hexdigest(),expected)


class WalletApplicationBrowser(unittest.IsolatedAsyncioTestCase):
    async def test_retained_real_nft_aliases_resolve_exact_old_bodies_on_both_pages(self):
        """Sealed genuine two-alias regression; this makes no live data claim."""
        from playwright.async_api import async_playwright
        sealed=json.loads((Path(__file__).parent/'fixtures/nft_retained_aliases.json').read_text(encoding='utf-8'))
        report=fixture(270)
        report.nft_intelligence={'events':sealed['canonical_events'],'assets':[],'coverage':[],'evidence':[]}
        aliases=sealed['previous_full_events']
        for tx,alias in zip((report.transactions[0],report.transactions[-1]),aliases):
            tx.raw={'nft_intelligence':{'event_id':alias['event_id'],'event_type':alias['event_type'],
                'raw_reference':{'collection':'events','id':alias['event_id']}}}
        with tempfile.TemporaryDirectory() as directory:
            path=export_html_report(report,build_graph_payload(report),Path(directory)).output_path
            async with async_playwright() as p:
                browser=await p.chromium.launch()
                try:
                    page=await browser.new_page();errors=[]
                    page.on('pageerror',lambda error:errors.append(str(error)))
                    await page.route('**/*',lambda route:route.continue_() if route.request.url.startswith(('file:','data:','blob:')) else route.abort())
                    await page.goto(path.as_uri(),wait_until='load')
                    for index,alias in enumerate(aliases):
                        if index:await page.locator('#txPageNext').click()
                        disclosure=page.locator(f'details[data-nft-raw-id="{alias["event_id"]}"]')
                        target=await disclosure.locator('[data-nft-raw-target]').element_handle()
                        await disclosure.evaluate('el=>el.open=true')
                        await page.wait_for_function('(el)=>!!el.textContent',arg=target)
                        self.assertEqual(json.loads(await target.text_content()),alias)
                    self.assertEqual(await page.evaluate('integratedNftPayload.transaction_views.length'),270)
                    self.assertEqual(await page.evaluate('nftAliasIndexCoverage.truncated'),False)
                    self.assertEqual(errors,[])
                finally:await browser.close()

    async def test_nft_alias_index_keeps_current_ids_and_rejects_unlinked_or_wrong_asset(self):
        from playwright.async_api import async_playwright
        def event(key,asset='0:'+'3'*64,tx='a'*64):
            return {'event_id':key,'asset_address':asset,'transaction_hash':tx,'event_type':'transfer',
                'status':'unknown','verification':'provider_reported','evidence_ids':['synthetic:proof'],
                'observation_ids':['synthetic:observation'],'raw':{'marker':key,'untrusted':'<img src=x onerror=alert(1)>'}}
        old=event('old');nested=event('nested',tx=None);old['raw']['corroborating_observations']=[nested]
        collision=event('direct');direct=copy.deepcopy(collision);direct['raw']['marker']='current-canonical-wins'
        wrong=event('wrong-asset',asset='0:'+'4'*64)
        unlinked=event('unlinked',tx='b'*64);unlinked['evidence_ids']=[];unlinked['observation_ids']=[]
        root=event('canonical');root['raw']['corroborating_observations']=[old,collision,wrong,unlinked,{'event_id':'metadata-name-only'}]
        chain=event('depth-root');cursor=chain
        for index in range(40):
            child=event(f'depth-{index}');cursor['raw']['corroborating_observations']=[child];cursor=child
        report=fixture();report.nft_intelligence={'events':[root,direct,chain],'assets':[],'coverage':[],'evidence':[]}
        report.transactions[0].raw={'nft_intelligence':{'event_id':'old','event_type':'transfer','raw_reference':{'collection':'events','id':'old'}}}
        with tempfile.TemporaryDirectory() as directory:
            path=export_html_report(report,build_graph_payload(report),Path(directory)).output_path
            async with async_playwright() as p:
                browser=await p.chromium.launch()
                try:
                    page=await browser.new_page();dialogs=[];errors=[]
                    async def dismiss(dialog):dialogs.append(dialog.message);await dialog.dismiss()
                    page.on('dialog',dismiss);page.on('pageerror',lambda error:errors.append(str(error)))
                    await page.route('**/*',lambda route:route.continue_() if route.request.url.startswith(('file:','data:','blob:')) else route.abort())
                    await page.goto(path.as_uri(),wait_until='load')
                    state=await page.evaluate("""()=>({old:canonicalNftRecords.events.get('old'),nested:canonicalNftRecords.events.get('nested'),direct:canonicalNftRecords.events.get('direct'),wrong:canonicalNftRecords.events.has('wrong-asset'),unlinked:canonicalNftRecords.events.has('unlinked'),metadata:canonicalNftRecords.events.has('metadata-name-only'),tooDeep:canonicalNftRecords.events.has('depth-39'),coverage:nftAliasIndexCoverage})""")
                    self.assertEqual(state['old'],old);self.assertEqual(state['nested'],nested);self.assertEqual(state['direct'],direct)
                    self.assertFalse(state['wrong']);self.assertFalse(state['unlinked']);self.assertFalse(state['metadata']);self.assertFalse(state['tooDeep'])
                    # Export redaction can bound a deep source tree before the
                    # browser reaches its own guard. Do not pretend that the
                    # browser necessarily saw all40nested source records.
                    self.assertLessEqual(state['coverage']['visited'],state['coverage']['limit'])
                    disclosure=page.locator('details[data-nft-raw-id="old"]');target=await disclosure.locator('[data-nft-raw-target]').element_handle()
                    await disclosure.evaluate('el=>el.open=true');await page.wait_for_function('(el)=>!!el.textContent',arg=target)
                    self.assertEqual(json.loads(await target.text_content()),old)
                    self.assertEqual(await page.locator('img[src="x"]').count(),0);self.assertEqual(dialogs,[]);self.assertEqual(errors,[])
                finally:await browser.close()

    async def test_structured_application_check_renders_in_inspector_as_escaped_json(self):
        from playwright.async_api import async_playwright
        report=fixture(client={'status':'UNKNOWN','checks':[{'method':'structured_fixture','status':'checked',
            'result':{'implementation':'V5R1','untrusted':'<img src=x onerror=alert(1)>'}}]})
        with tempfile.TemporaryDirectory() as directory:
            path=export_html_report(report,build_graph_payload(report),Path(directory)).output_path
            async with async_playwright() as p:
                browser=await p.chromium.launch()
                page=await browser.new_page()
                errors=[];dialogs=[]
                page.on('pageerror',lambda error:errors.append(str(error)))
                async def dismiss(dialog):
                    dialogs.append(dialog.message);await dialog.dismiss()
                page.on('dialog',dismiss)
                await page.goto(path.as_uri(),wait_until='load')
                await page.evaluate('key=>inspectNode(graphData.nodes.find(n=>n.service_key===key))','ton:'+A)
                await page.locator('#inspector details').evaluate_all('nodes=>nodes.forEach(node=>node.open=true)')
                text=await page.locator('#inspector').inner_text()
                self.assertIn('"implementation": "V5R1"',text)
                self.assertIn('<img src=x onerror=alert(1)>',text)
                self.assertNotIn('[object Object]',text)
                self.assertEqual(await page.locator('#inspector img[src="x"]').count(),0)
                self.assertEqual(errors,[]);self.assertEqual(dialogs,[])
                await browser.close()

    async def test_shared_full_nft_raw_resolves_on_both_transaction_pages_offline(self):
        from playwright.async_api import async_playwright
        report=fixture(270)
        ref={'collection':'events','id':'synthetic-nft-event'}
        report.nft_intelligence={'events':[{'event_id':ref['id'],'asset_address':'0:'+'3'*64,
            'event_type':'transfer','raw':{'full_proof_marker':'SYNTHETIC_SHARED_RAW_42','untrusted':'<img src=x onerror=alert(1)>'}}],
            'assets':[],'coverage':[],'evidence':[]}
        for tx in (report.transactions[0],report.transactions[-1]):
            tx.raw={'nft_intelligence':{'event_id':ref['id'],'event_type':'transfer','raw_reference':ref}}
        with tempfile.TemporaryDirectory() as directory:
            path=export_html_report(report,build_graph_payload(report),Path(directory)).output_path
            async with async_playwright() as p:
                browser=await p.chromium.launch()
                page=await browser.new_page(viewport={'width':390,'height':850})
                page.set_default_timeout(10000)
                errors=[];dialogs=[]
                page.on('pageerror',lambda error:errors.append(str(error)))
                async def dismiss(dialog):
                    dialogs.append(dialog.message);await dialog.dismiss()
                page.on('dialog',dismiss)
                await page.route('**/*',lambda route:route.continue_() if route.request.url.startswith(('file:','data:','blob:')) else route.abort())
                await page.goto(path.as_uri(),wait_until='load')
                await page.wait_for_function("typeof collectedTransactionViews !== 'undefined'")
                for turn in range(2):
                    details=page.locator('details[data-nft-raw-id]').first
                    target=await details.locator('[data-nft-raw-target]').element_handle()
                    self.assertEqual(await target.text_content(),'')
                    await details.evaluate('(element)=>{element.open=true;}')
                    await page.wait_for_function("document.querySelector('[data-nft-raw-target]')?.textContent.includes('SYNTHETIC_SHARED_RAW_42')")
                    self.assertIn('SYNTHETIC_SHARED_RAW_42',await target.text_content())
                    if turn==0:await page.locator('#txPageNext').click()
                self.assertEqual(errors,[]);self.assertEqual(dialogs,[])
                self.assertEqual(await page.evaluate('document.documentElement.scrollWidth'),390)
                await browser.close()
