"""Presentation contracts and installed Chromium checks; synthetic UI controls."""
import hashlib,json,re,tempfile,unittest
from pathlib import Path
from app.models.report import AddressReport,Transaction
from app.attribution.engine import correlate_attribution
from app.graph.builder import build_graph_payload
from app.exporters.html_exporter import export_html_report,_inferential_service_projection

def fixture():
    a,b,c=['0x'+x*40 for x in '123']
    report=AddressReport(target_address=a,detected_chains=['eth'],transactions=[Transaction(
        chain='eth',tx_hash='0x'+f'{i:064x}',from_address=a,to_address=b if i%2 else c,
        amount_base_units=10**18,decimals=18,asset='ETH',success=True,source='synthetic_ui_control') for i in range(8)])
    payload=correlate_attribution(report,dataset_records=[])
    inference=payload['inferential_intelligence']
    inference['hypotheses']=[{'id':f'ui:{i}','claim':'<img src=x onerror=alert(1)>',
        'subject':'eth:'+a,'confidence':'WEAK_LEAD','evidence_ids':[payload['evidence'][0]['evidence_id']],
        'alternative_explanations':['Unrelated payment'],'assessment':{'independent_physical_observation_groups':1},
        'missing_evidence':['Independent controller proof']} for i in range(25)]
    return report

class PresentationContracts(unittest.TestCase):
    def test_lean_context_retains_frontier_and_journal_without_raw_report_duplication(self):
        original={'investigation_context':{'histories':{'key':{'report':{'raw':'large_marker'}}},
            'frontier':[{'address_key':'key'}],'journal':[{'trigger':'test'}],'coverage':{'status':'PARTIAL'}}}
        result=_inferential_service_projection(original)['investigation_context']
        self.assertEqual(result['retained_history_count'],1)
        self.assertNotIn('histories',result)
        self.assertEqual(result['journal'],original['investigation_context']['journal'])
        self.assertIn('histories',original['investigation_context'])

    def test_original_css_and_approved_friendly_js_after_explicit_extensions(self):
        template=(Path(__file__).resolve().parents[1]/'app/exporters/investigation_template.html').read_text(encoding='utf-8')
        css=re.search(r'<style>(.*?)</style>',template,re.S).group(1)
        self.assertEqual(hashlib.sha256(css.encode()).hexdigest(),'617e933a0973854d1fafb1a2501c9ce3aeae224553e733e742595e293b7801d7')
        script=next(part for part in re.findall(r'<script>(.*?)</script>',template,re.S) if 'const graphData =' in part)
        blocks=r'(?m)^[ \t]*// GANSAR_INFERENTIAL_BEGIN\n.*?^[ \t]*// GANSAR_INFERENTIAL_END\n'
        self.assertEqual(len(re.findall(blocks,script,re.S)),4)
        script=re.sub(blocks,'',script,flags=re.S|re.M)
        for name in ('','_INSPECTOR'):
            script=re.sub(r'(?m)^[ \t]*// GANSAR_TRANSACTION_ORIGIN'+name+r'_BEGIN\n.*?^[ \t]*// GANSAR_TRANSACTION_ORIGIN'+name+r'_END\n','',script,flags=re.S|re.M)
        script=script.replace('${transactionOriginMarkup(tx)}','').replace("${detail('POSSIBLE / INVESTIGATIVE LEADS · signing client unconfirmed',client.investigative_leads)}",'')
        # Approved 2026-10-23 3D patch; original CSS is still checked above.
        # The current template is byte-identical to that saved approved file.
        self.assertEqual(hashlib.sha256(script.encode()).hexdigest(),'20b00dff4ecdd4c40c92bf93173cf362f553ac6665a242c98059f705a7e92d1d')

class InferentialBrowser(unittest.IsolatedAsyncioTestCase):
    async def test_lazy_paging_proofs_escaping_and_graph_inspector(self):
        from playwright.async_api import async_playwright
        report=fixture();graph=build_graph_payload(report)
        with tempfile.TemporaryDirectory() as directory:
            path=export_html_report(report,graph,Path(directory),language='en').output_path
            async with async_playwright() as runtime:
                browser=await runtime.chromium.launch(args=['--disable-background-networking','--enable-unsafe-swiftshader'])
                try:
                    page=await browser.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
                    await page.route('**/*',lambda route:route.continue_() if route.request.url.startswith(('file:','data:','blob:')) else route.abort())
                    await page.goto(path.as_uri(),wait_until='load')
                    category=page.locator('[data-inference-category="hypotheses"]')
                    self.assertEqual(await category.locator('[data-inference-record-kind]').count(),0)
                    await category.evaluate('e=>e.open=true')
                    await page.wait_for_function("document.querySelectorAll('[data-inference-record-kind=hypotheses]').length===20")
                    self.assertEqual(await category.locator('img').count(),0)
                    await category.locator('[data-inference-next]').click()
                    self.assertEqual(await category.locator('[data-inference-record-kind]').count(),5)
                    await category.locator('[data-inference-record-kind]').first.evaluate('e=>e.open=true')
                    proof=category.locator('[data-inference-proof-id]').first
                    await proof.evaluate('e=>{e.parentElement.open=true;e.open=true}')
                    await page.wait_for_function('document.querySelector("[data-inference-proof-body]")?.textContent.length>0')
                    self.assertIn('evidence_id',await proof.inner_text())
                    state=await page.evaluate('''() => {const edge=graphData.edges.find(e=>e.analytic);if(!edge)return {edge:false};inspectEdge(edge);return {edge:true,text:inspector.textContent,dash:inferenceIsAnalytic(edge)};}''')
                    self.assertTrue(state['edge']);self.assertTrue(state['dash']);self.assertIn('INFERENTIAL INTELLIGENCE',state['text'])
                    await page.set_viewport_size({'width':390,'height':844})
                    self.assertEqual(errors,[])
                finally:await browser.close()

if __name__=='__main__':unittest.main()
