"""Execute production graph state/projection functions in Node, without a browser.

Fixtures are local boundary inputs only. No report or blockchain capture is made.
Canvas/WebGL layout and visual fidelity require a permitted browser separately.
"""
import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "app/exporters/investigation_template.html"


def function_source(name):
    source = TEMPLATE.read_text(encoding="utf8")
    start = source.index("      function " + name + "(")
    # Production declarations use this indentation; nested closures are deeper.
    first_line = source[start:source.index("\n", start)]
    if first_line.rstrip().endswith("}"):
        return first_line
    return source[start:source.index("\n      }", start) + len("\n      }")]


FUNCTIONS = ["graphCategoryMatches", "graphComparableUsd", "graphRoute", "graphFilterScene",
    "graphLegendKey", "transactionKinds", "walletKinds", "tokenKinds", "graph3dFinancialEdge",
    "walletEnsIdentity", "graphWalletAddress", "transactionGraphAddressNode", "transactionGraphAddressKey",
    "transactionGraphKnownNode", "shortValue", "shortNodeLabel", "normalizeSearch", "compactSearch",
    "buildSearchEntry", "ensureSearchIndex", "searchEntryMatches", "searchEntryScore", "searchResultsForQuery",
    "graphModeTitle", "passEdge", "refreshActive", "applyFilters", "renderGraphSummary", "renderGraphLegend",
    "graphLegendGroups", "graphGroupLabel", "graph3dClusterKind", "graph3dPresentationProjection", "graph2dProjection",
    "graph2dRoute", "transactionGraphTraceSelected", "transactionGraphSearchMatch", "transactionGraphRecordSearch",
    "transactionGraphSearch", "transactionTreeRow", "transactionTreeData", "transactionTreeAddress",
    "transactionTreeCompact", "transactionTreeText", "transactionGraphField", "walletIdentityMarkup", "esc",
    "resetGraphView", "changeGraphInvestigationMode", "bindGraphFilterControls", "transactionTreeReset"]
FUNCTIONS += ["graph2dEntityKey", "graph2dEntityIndex", "graph2dEntityPresentation"]
FUNCTIONS += ["transactionGraphSnapshot", "transactionGraphPush", "transactionGraphBack",
    "transactionGraphCollapse", "transactionGraphAction", "transactionGraphIsolateSelected", "selectSearchResult"]


HARNESS = r"""
const vm=require('vm'),assert=require('assert'),input=JSON.parse(require('fs').readFileSync(0,'utf8'));
const context=vm.createContext({console,assert,performance:{now:()=>0}});
vm.runInContext(input.functions.join('\n')+`\n
let lang='en',integratedNftPayload={ens:{wallet_identities:[]}},graphData={nodes:[],edges:[]},reportTargetAddress='';
let target='t',nodes=[],edges=[],visibleIds=new Set(),visibleNodes=[],visibleEdges=[],filteredEdgeIds=null;
let selected=null,selectedEdge=null,hoveredNode=null,hoveredEdge=null,searchFocusId='',searchIndex=[],isolated=null,pathIds=new Set(),hiddenLegendGroups=new Set(),graphIsolationDepth=1,graphFilterNotice='';
let edgeFilterType='',edgeThreshold=1,simulationHeat=0,searchActiveIndex=-1;
let graph3dState={active:false,focusScoreCutoffs:new Map(),focusDegrees:new Map(),groupPages:new Map()},transactionTreeState={active:false};
let graph2dState={signature:'',positions:new Map(),pages:new Map(),all:new Set()},transactionGraphState={query:'',searchIndex:new Map(),componentSearch:new Map(),objectSearch:new Map(),searchRecordIds:new Set(),expanded:new Set(),limits:new Map(),history:[],camera:{x:0,y:0,k:1},width:1000,height:600,nodeById:new Map(),edgeById:new Map(),view:'overview',overviewLimit:6,selected:null,isolate:null};
const control=()=>({value:'',textContent:'',title:'',innerHTML:'',hidden:true,style:{},dataset:{},listeners:new Map(),addEventListener(type,handler){if(!this.listeners.has(type))this.listeners.set(type,[]);this.listeners.get(type).push(handler);},dispatch(type){for(const handler of this.listeners.get(type)||[])handler({target:this,currentTarget:this});}});
const nodeTypeSelect=control(),edgeTypeSelect=control(),thresholdInput=control(),graphInvestigationModeSelect=control(),searchInput=control(),count=control(),mode=control(),graphSummary=control(),graphLegend=control(),tip=control(),inspector=control();
const document={getElementById:()=>control()};
let last2d=null,last3d=null,draws=0,refreshes=0,searchResultsRendered=[],inspectedId='',centeredId='';
const window={setTimeout:callback=>callback()};
function uiLabel(ru,en){return en;} function uiText(v){return String(v??'');}function uiAddress(v){return String(v??'');}function uiShort(v){return shortValue(v,10,7);}function text(v){return v;}
function graph2dActive(){return !graph3dState.active&&!transactionTreeState.active;}function graph2dFilterBefore(){}function graph2dFilterAfter(){}
function graph3dServiceInfo(node){return node?.serviceClaim||null;}function sourceText(){return '';}function graphNodeLabel(v){return v;}function nodeEntityLabel(v){return v.kind;}function graphEdgeLabel(v){return v;}
function nodeIconKind(node){return node.kind;}function web3Media(value){return value||'';}function nodeImageUrl(node){return node.image_url||'';}function nodeEvidenceUrl(node){return node.evidence_url||'';}
function graph2dEntitySearch(){return [];}function graph3dWeb3SearchResults(){return [];}function searchFieldValues(node){return Object.values(node).filter(v=>typeof v==='string');}
function firstCardValue(node,keys){return keys.map(k=>node[k]).find(Boolean)||'';}function cleanNodeName(node){return String(node.label||node.id);}function nodePrimaryValue(node){return node.address||node.id;}
function graph2dLane(node){return 'context:'+node.kind;}function graph2dLaneLabel(v){return v;}function graph2dTopology(){return new Map();}
function graph2dNetworkLayout(list){list.forEach((n,i)=>{n.x=i*100;n.y=0;graph2dState.positions.set(n.id,{x:n.x,y:n.y});});}
function graph3dTopologyLayout(ns){return new Map(ns.map((n,i)=>[n.id,{lane:'incoming:'+n.kind,side:'incoming',family:n.kind,rank:i,x:i,y:0,z:0}]));}
function graph3dLinkScore(){return 1;}let web3Context={nodes:[],edges:[]};function web3ContextProjection(){return web3Context;}
function draw(){draws++;if(graph2dActive())last2d=graph2dProjection();}function refreshGraph3dData(){refreshes++;if(graph3dState.active)last3d=graph3dPresentationProjection();}
function renderSearchResults(q,r){searchResultsRendered=r;}function syncCustomSelects(){}function web3Link(url,title){return url?'<a href="'+esc(url)+'">'+esc(title)+'</a>':'';}
function transactionGraphRawDetails(label,value){return '<pre>'+esc(JSON.stringify(value))+'</pre>';}function transactionGraphLabel(ru,en){return en;}
function fit(){}function graph3dZoomToFit(){}function focusGraph3dNode(id){centeredId=id;}function focus(id){centeredId=id;}function syncCustomSelect(){}
function inspectNode(node){inspectedId=node.id;}function graph2dPush(){}function hideSearchResults(){}function graph3dRevealWeb3Result(){return false;}
function transactionGraphRender(){transactionGraphState.projection={nodes:[],edges:[]};}function transactionGraphFocusSearch(){}function web3Search(){return false;}
function neighbors(id){const ids=new Set([id]);for(const edge of edges)if(edge.from===id||edge.to===id){ids.add(edge.from);ids.add(edge.to);}return ids;}
function fixture(){
 nodes=[{id:'t',kind:'ethereum_wallet',chain:'eth',address:'0x'+'1'.repeat(40)},{id:'a',kind:'ethereum_wallet',chain:'eth',address:'0x'+'2'.repeat(40)},{id:'b',kind:'ethereum_wallet',chain:'eth',address:'0x'+'3'.repeat(40)},{id:'z',kind:'ethereum_wallet',chain:'eth',address:'0x'+'4'.repeat(40)},
 {id:'n',kind:'nft',chain:'ton'},{id:'g',kind:'gift',chain:'ton'},{id:'j',kind:'jetton',chain:'ton'},{id:'c',kind:'token',chain:'eth'},{id:'tel',kind:'telegram_id',chain:'ton'},{id:'ens',kind:'ens_identity',chain:'eth'},{id:'m',kind:'marketplace',chain:'ton'},{id:'dex',kind:'dex_router',chain:'eth'},{id:'e',kind:'exchange',chain:'eth'}];
 const relation=(id,from,to,type='sent',extra={})=>({id,from,to,type,count:1,chain:'eth',asset:'ETH',amount:'1',tx_hash:id,source:'test',...extra});
 edges=[relation('ta','t','a','sent',{amount_usd:100}),relation('ab','a','b','sent',{amount_usd:1000}),relation('tb','t','b','association',{transaction_edge:false}),relation('tn','t','n','owns',{transaction_edge:false}),relation('tg','t','g','owns',{transaction_edge:false}),relation('tj','t','j','holds',{transaction_edge:false}),relation('tc','t','c','sent',{amount_usd:500}),relation('tt','t','tel','identity',{transaction_edge:false}),relation('te','t','ens','ens_resolution',{transaction_edge:false}),relation('nm','n','m','marketplace_interaction',{transaction_edge:false}),relation('td','t','dex','interacted_with',{transaction_edge:false}),relation('tx','t','e','sent',{amount:'999999999999999999999999'})];
 graphData={target,nodes:JSON.parse(JSON.stringify(nodes)),edges:JSON.parse(JSON.stringify(edges))};reportTargetAddress=nodes[0].address;
 nodeById=new Map(nodes.map(n=>[n.id,n]));edgeById=new Map(edges.map(e=>[e.id,e]));
 nodeTypeSelect.value='';edgeTypeSelect.value='';thresholdInput.value='1';graphInvestigationModeSelect.value='all';searchInput.value='';hiddenLegendGroups.clear();isolated=null;selected=null;selectedEdge=null;searchFocusId='';filteredEdgeIds=null;graph2dState.signature='';searchIndex=[];
}
let nodeById=new Map(),edgeById=new Map();
fixture();
`+'\n(function(){'+input.test+'\n})()',context);
process.stdout.write('ok');
"""


@unittest.skipUnless(shutil.which("node"), "Node.js is required for graph state execution")
class GraphControlsTests(unittest.TestCase):
    def execute(self, test):
        result = subprocess.run([shutil.which("node"), "-e", HARNESS],
            input=json.dumps({"functions": [function_source(name) for name in FUNCTIONS], "test": test}),
            text=True, encoding="utf8", capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ok")

    def test_complete_inline_javascript_compiles(self):
        source = TEMPLATE.read_text(encoding="utf8")
        scripts = [body for attributes, body in re.findall(r"<script\b([^>]*)>(.*?)</script>", source, re.S)
            if "application/json" not in attributes and "text/plain" not in attributes]
        script = re.sub(r"{{.*?}}", "null", max(scripts, key=len), flags=re.S)
        result = subprocess.run([shutil.which("node"), "-e",
            "new (require('vm').Script)(require('fs').readFileSync(0,'utf8'));"],
            input=script, text=True, encoding="utf8", capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_mode_filters_real_node_and_edge_ids(self):
        self.execute(r"""
const plain=JSON.stringify(graphData),ids=x=>x.nodes.map(n=>n.id).sort().join(','),links=x=>x.edges.map(e=>e.id).sort().join(',');
assert.equal(ids(graphFilterScene(nodes,edges,{mode:'gift'})),'g,t');
assert.equal(links(graphFilterScene(nodes,edges,{mode:'gift'})),'tg');
assert.equal(ids(graphFilterScene(nodes,edges,{mode:'nft'})),'g,m,n,t');
assert.equal(ids(graphFilterScene(nodes,edges,{mode:'jetton'})),'j,t');
assert.equal(ids(graphFilterScene(nodes,edges,{mode:'telegram'})),'g,t,tel');
assert.equal(ids(graphFilterScene(nodes,edges,{mode:'marketplace'})),'m,n');
const direct=graphFilterScene(nodes,edges,{mode:'direct',target:'t'});assert(!direct.edges.some(e=>e.id==='ab'||e.id==='nm'));
assert.equal(links(graphFilterScene(nodes,edges,{mode:'major'})),'ab');
assert.equal(ids(graphFilterScene(nodes,edges,{nodeType:'ethereum_wallet'})),'a,b,t,z');
assert.equal(links(graphFilterScene(nodes,edges,{nodeType:'ethereum_wallet',edgeType:'sent'})),'ab,ta');
assert.equal(ids(graphFilterScene(nodes,edges,{mode:'gift',nodeType:'ethereum_wallet'})),'');
assert.equal(ids(graphFilterScene(nodes,edges,{mode:'gift',edgeType:'sent'})),'g');
assert.equal(graphFilterScene(nodes,edges,{threshold:2}).edges.length,0);
assert.equal(graphFilterScene(nodes,edges,{mode:'gift',hiddenGroups:new Set(['gift'])}).nodes.length,0);
assert.equal(JSON.stringify(graphData),plain);
""")

    def test_path_isolation_combinations_and_missing_path(self):
        self.execute(r"""
const route=graphFilterScene(nodes,edges,{mode:'path',target:'t',focus:'b',edgeType:'sent'});
assert.equal(route.path.join(','),'t,a,b');assert.equal(route.edges.map(e=>e.id).sort().join(','),'ab,ta');
assert.equal(graphFilterScene(nodes,edges,{mode:'path',target:'t',focus:'z'}).notice,'no_path');
assert.equal(graphFilterScene(nodes,edges,{mode:'path',target:'t',focus:'b',edgeType:'owns'}).nodes.length,0);
const isolated=graphFilterScene(nodes,edges,{mode:'isolate',focus:'a',edgeType:'sent'});assert.equal(isolated.nodes.map(n=>n.id).sort().join(','),'a,b,t');
assert.equal(graphFilterScene(nodes,edges,{mode:'isolate',focus:'a',searchIds:new Set(['b'])}).nodes.map(n=>n.id).join(','),'b');
assert.equal(graphFilterScene(nodes,edges,{mode:'all'}).nodes.length,nodes.length);
""")

    def test_events_apply_projection_counters_selection_and_empty_3d_context(self):
        self.execute(r"""
selected=nodeById.get('a');applyFilters();assert.equal(visibleNodes.length,nodes.length);assert.equal(last2d.sourceNodes,nodes.length);
graphInvestigationModeSelect.value='gift';applyFilters();assert.equal(visibleNodes.map(n=>n.id).sort().join(','),'g,t');assert.equal(visibleEdges.map(e=>e.id).join(','),'tg');assert.equal(selected,null);assert.equal(count.textContent,'2 / 13');assert(graphSummary.innerHTML.includes('2/13'));
assert(!last2d.nodes.some(n=>n.id==='a'));graph3dState.active=true;selected=nodeById.get('a');applyFilters();assert.equal(selected,null);assert(!last3d.nodes.some(n=>n.id==='a'));
web3Context={nodes:[{id:'t',kind:'ethereum_wallet',chain:'eth'},{id:'web3:ens',kind:'ens',sourceKind:'ens_name'}],edges:[{id:'we',from:'t',to:'web3:ens',type:'ens_resolution'}]};
nodes=nodes.filter(n=>n.kind!=='gift');nodeById=new Map(nodes.map(n=>[n.id,n]));applyFilters();assert.equal(visibleNodes.length,0);assert.equal(last3d.nodes.length,0);assert.equal(last3d.edges.length,0);assert(mode.textContent.includes('No objects'));
graphInvestigationModeSelect.value='all';applyFilters();assert(visibleNodes.length>0);assert(last3d.nodes.length>0);assert(draws>=5&&refreshes>=5);
""")

    def test_verified_ens_labels_search_and_provenance_do_not_create_nodes(self):
        self.execute(r"""
const address=nodes[0].address;integratedNftPayload.ens.wallet_identities=[{chain:'eth',address,name:'vitalik.eth',source:'ethereum_ens',source_url:'https://example.com/resolver',forward_verified:true,primary_verified:false,provenance:{chain_id:1,block_number:123}}];
const before=JSON.stringify(graphData);assert.equal(shortNodeLabel(nodes[0]),'vitalik.eth');assert.equal(walletEnsIdentity('bsc',address),null);assert.equal(walletEnsIdentity('eth',nodes[1].address),null);
assert.equal(graph2dEntityPresentation(nodes[0]).displayName,'vitalik.eth');assert.equal(graph2dEntityPresentation(nodes[0]).entityType,'wallet');assert.equal(graph2dEntityPresentation(nodes[0]).address,address);
const tree=transactionGraphAddressNode('eth',address,'tree-wallet',0,0,true);assert.equal(tree.label,'vitalik.eth');assert(tree.sublabel.includes('0x'));assert.equal(tree.address,address);
assert.equal(searchResultsForQuery('vitalik.eth')[0].node.id,'t');assert(walletIdentityMarkup('eth',address).includes('block_number'));assert(walletIdentityMarkup('eth',address).includes('not established'));
nodes[0].serviceClaim={name:'Known exchange',status:'CONFIRMED'};graphData.nodes[0].serviceClaim=nodes[0].serviceClaim;assert.equal(shortNodeLabel(nodes[0]),'Known exchange');assert.equal(transactionGraphAddressNode('eth',address,'tree-wallet',0,0).label,'Known exchange');delete graphData.nodes[0].serviceClaim;
integratedNftPayload.ens.wallet_identities[0].forward_verified=false;searchIndex=[];assert.equal(walletEnsIdentity('eth',address),null);assert(!searchResultsForQuery('vitalik.eth').length);assert.equal(JSON.stringify(graphData),before);
""")

    def test_nft_media_and_status_survive_scene_filtering(self):
        self.execute(r"""
const item='0:'+'a'.repeat(64);nodes.find(n=>n.id==='g').address=item;
integratedNftPayload.report={assets:[{asset_id:item,address:item,kind:'gift',name:'Retained gift',image_url:'https://example.com/actual-source-image.png',thumbnail_url:'https://example.com/actual-source-thumb.png',collection_status:'verified_onchain',category_provenance:{collection_status:'verified_onchain',kind:'gift'},current_owner_status:'provider_reported',current_owner:'0:'+'b'.repeat(64),evidence_ids:['existing-proof']}],evidence:[{evidence_id:'existing-proof',source:'retained-test-observation'}]};
const before=JSON.stringify(integratedNftPayload);graphInvestigationModeSelect.value='gift';applyFilters();const view=graph2dEntityPresentation(nodeById.get('g'));assert.equal(view.entityType,'gift');assert.equal(view.imageUrl,'https://example.com/actual-source-thumb.png');assert.equal(view.fallbackUrl,'https://example.com/actual-source-image.png');assert.equal(view.ownershipStatus,'provider_reported');assert.equal(view.evidenceIds.join(','),'existing-proof');assert.equal(JSON.stringify(integratedNftPayload),before);
""")

    def test_native_change_and_input_events_reset_all_filters_and_3d_isolation(self):
        self.execute(r"""
bindGraphFilterControls();bindGraphFilterControls();assert.equal(graphInvestigationModeSelect.listeners.get('change').length,1);
graphInvestigationModeSelect.value='gift';graphInvestigationModeSelect.dispatch('change');assert.equal(visibleNodes.map(n=>n.id).sort().join(','),'g,t');
transactionTreeState.active=true;const priorDraws=draws;nodeTypeSelect.value='ethereum_wallet';nodeTypeSelect.dispatch('change');assert.equal(draws,priorDraws);transactionTreeState.active=false;
nodeTypeSelect.value='ethereum_wallet';nodeTypeSelect.dispatch('input');assert.equal(visibleNodes.length,0);assert.equal(count.textContent,'0 / 13');
graph3dState.active=true;graph3dState.contextIsolate='old-hidden-object';transactionGraphState.query='old';transactionGraphState.expanded.add('old');hiddenLegendGroups.add('wallet');
resetGraphView();assert.equal(visibleNodes.length,nodes.length);assert.equal(visibleEdges.length,edges.length);assert.equal(graphInvestigationModeSelect.value,'all');assert.equal(nodeTypeSelect.value,'');assert.equal(edgeTypeSelect.value,'');assert.equal(thresholdInput.value,'1');assert.equal(graph3dState.contextIsolate,'');assert.equal(transactionGraphState.query,'');assert.equal(transactionGraphState.expanded.size,0);assert.equal(selected,null);assert.equal(hiddenLegendGroups.size,0);assert(last3d.nodes.length>0);
""")

    def test_tree_ens_search_selects_existing_wallet_rows_and_path_has_real_edges(self):
        self.execute(r"""
const address=nodes[0].address,peer=nodes[1].address;
integratedNftPayload.ens.wallet_identities=[{chain:'eth',address,name:'vitalik.eth',source:'ethereum_ens',forward_verified:true,provenance:{chain_id:1}}];
integratedNftPayload.transaction_views=[{from:address,to:peer,hash:'real-retained-id',chain_raw:'eth'}];integratedNftPayload.observation_views=[];
integratedNftPayload.transaction_tree={target:address,records:{r:{view:'financial',row_index:0}},groups:[{kind:'financial',record_ids:['r']}],accounts:{},messages:{},components:{}};
const before=JSON.stringify(integratedNftPayload.transaction_views);transactionGraphSearch('vitalik.eth');assert.equal(transactionGraphState.view,'overview');assert.equal(transactionGraphState.recordIds.join(','),'r');assert.equal(transactionGraphState.searchFocus.address,address);assert.equal(transactionGraphState.isolate.address,address);assert.equal(JSON.stringify(integratedNftPayload.transaction_views),before);
transactionGraphState.projection={nodes:[{id:'root',kind:'target'},{id:'middle'},{id:'end'}],edges:[{id:'e1',from:'root',to:'middle'},{id:'e2',from:'middle',to:'end'}]};transactionGraphState.selected={kind:'node',id:'end'};transactionGraphState.edgeById=new Map();
transactionGraphTraceSelected();assert.equal(transactionGraphState.isolate.pathIds.join(','),'root,middle,end');
transactionTreeReset();assert.equal(transactionGraphState.query,'');assert.equal(transactionGraphState.isolate,null);assert.equal(transactionGraphState.recordIds,null);assert.equal(transactionGraphState.expanded.size,0);
""")

    def test_dynamic_type_selectors_project_exact_scene_for_each_available_type(self):
        self.execute(r"""
bindGraphFilterControls();graph3dState.active=true;
for(const kind of new Set(nodes.map(node=>node.kind))){nodeTypeSelect.value=kind;nodeTypeSelect.dispatch('change');assert.equal(visibleNodes.map(node=>node.id).sort().join(','),nodes.filter(node=>node.kind===kind).map(node=>node.id).sort().join(','));assert(visibleEdges.every(edge=>visibleIds.has(edge.from)&&visibleIds.has(edge.to)));assert(last3d.nodes.every(node=>node.__g3d_group||node.kind===kind));}
nodeTypeSelect.value='';nodeTypeSelect.dispatch('change');
for(const kind of new Set(edges.map(edge=>edge.type))){edgeTypeSelect.value=kind;edgeTypeSelect.dispatch('change');assert.equal(visibleEdges.map(edge=>edge.id).sort().join(','),edges.filter(edge=>edge.type===kind).map(edge=>edge.id).sort().join(','));assert(last3d.edges.every(edge=>edge.type===kind));}
edgeTypeSelect.value='';edgeTypeSelect.dispatch('change');assert.equal(visibleEdges.length,edges.length);assert.equal(visibleNodes.length,nodes.length);
""")

    def test_tree_branch_collapse_back_and_isolation_execute_saved_state(self):
        self.execute(r"""
transactionGraphState.view='detail';transactionGraphState.recordId='r1';
transactionGraphAction({type:'expand',key:'existing-branch'});assert(transactionGraphState.expanded.has('existing-branch'));assert.equal(transactionGraphState.history.length,1);
transactionGraphCollapse();assert.equal(transactionGraphState.expanded.size,0);assert.equal(transactionGraphState.history.length,2);
transactionGraphBack();assert(transactionGraphState.expanded.has('existing-branch'));assert.equal(transactionGraphState.view,'detail');
transactionGraphState.projection={nodes:[{id:'selected-record',sourceKind:'account',sourceId:'existing-account'}],edges:[]};transactionGraphState.selected={kind:'node',id:'selected-record'};
transactionGraphIsolateSelected();assert.equal(transactionGraphState.isolate.sourceId,'existing-account');assert.equal(transactionGraphState.isolate.id,'selected-record');
transactionGraphBack();assert.equal(transactionGraphState.isolate,null);assert(transactionGraphState.expanded.has('existing-branch'));
transactionGraphAction({type:'reveal-overview',nextLimit:30});assert.equal(transactionGraphState.overviewLimit,30);transactionGraphCollapse();assert.equal(transactionGraphState.overviewLimit,6);
""")

    def test_ens_search_result_selection_keeps_real_wallet_in_both_scenes(self):
        self.execute(r"""
const address=nodes[0].address;integratedNftPayload.ens.wallet_identities=[{chain:'eth',address,name:'vitalik.eth',source:'ethereum_ens',forward_verified:true,provenance:{chain_id:1}}];searchInput.value='vitalik.eth';
const before=JSON.stringify(graphData),found=searchResultsForQuery(searchInput.value)[0];assert.equal(found.node.id,'t');
selectSearchResult(found.node.id);assert.equal(selected.id,'t');assert.equal(inspectedId,'t');assert.equal(centeredId,'t');assert(last2d.nodes.some(node=>node.id==='t'));
graph3dState.active=true;selected=null;inspectedId='';centeredId='';selectSearchResult(found.node.id);assert.equal(selected.id,'t');assert.equal(inspectedId,'t');assert.equal(centeredId,'t');assert(last3d.nodes.some(node=>node.id==='t'));assert.equal(JSON.stringify(graphData),before);
""")


if __name__ == "__main__":
    unittest.main()
