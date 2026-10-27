"""Base-native ENS identity context using the existing ENS ABI/resolver code.

No Ethereum financial support, primary-name rules or ENS verification logic is
replaced. Base block/registry context and directory roles remain explicit.
"""
from __future__ import annotations

import asyncio
import os
import re
from urllib.parse import quote

import httpx

from app.models.report import AddressReport
from app.sources.ethereum_ens import EthereumEnsSource,_Lookup,ETH_RE,namehash,normalize_name,media_url
from app.sources.public_context_http import public_json
from app.sources.web3_identity import _outcome,_claim,_finish,_profile_thumbnail
from app.utils.http import shared_async_client
from app.utils.keccak import keccak_256

BASE_REGISTRY='0xb94704422c2a1e396835a571837aa5ae53285a95'
BASE_REVERSE_REGISTRAR='0x79ea96012eea67a83431f1701b3dff7e37f9e282'
BASE_TEXT_KEYS=('avatar','description','url','com.github','com.twitter','org.telegram')


class BaseNamesSource(EthereumEnsSource):
    name='basenames'
    chain='multi'
    context_chain='base'
    public_context_only=True

    def _rpc_url(self):return (os.getenv('GANSAR_BASE_RPC_URL')or'https://mainnet.base.org').strip()

    async def _find_resolver(self,lookup,name):
        # Base's documented native resolver exposes ordinary ENS addr/text
        # getters for exact registered nodes. No L1 CCIP/wildcard probe is
        # required, and absent exact nodes are not guessed from similar names.
        if name not in lookup.resolutions:
            resolver=await self._registry_address(lookup,'resolver',namehash(name))
            lookup.resolutions[name]=(resolver,name,False)if resolver else None
        return lookup.resolutions[name]

    async def _registry_address(self,lookup,method,node):
        selector='0178b8bf'if method=='resolver'else'02571be3'
        return self._decode_address(await self._eth_call(lookup,BASE_REGISTRY,'0x'+selector+node,method),lookup.out,method)

    async def _rpc(self,lookup,method,params):
        state=getattr(lookup,'_base_context_state',None)
        if state is None:
            state={'pending':[],'task':None,'http_requests':0,'batches':[]};lookup._base_context_state=state
        if lookup.failure_status:return {'result':'0x'}
        if lookup.rpc_calls>=28:
            lookup.failure_status='partial';return {'result':'0x'}
        lookup.rpc_calls+=1
        future=asyncio.get_running_loop().create_future()
        state['pending'].append(({'jsonrpc':'2.0','id':lookup.rpc_calls,'method':method,'params':params},future))
        if state['task']is None or state['task'].done():state['task']=asyncio.create_task(self._flush(lookup,state))
        return await future

    async def _flush(self,lookup,state):
        await asyncio.sleep(0)
        while state['pending']:
            batch,state['pending']=state['pending'],[]
            try:
                if state['http_requests']>=10:raise ValueError('Base context HTTP budget')
                state['http_requests']+=1
                payload,meta=await public_json(lookup.client,'POST',lookup.rpc_url,json=[body for body,_ in batch],
                    with_metadata=True,allow_list=True,max_bytes=262144,cache_ttl=45)
                if not isinstance(payload,list)or len(payload)!=len(batch):raise ValueError('Invalid Base RPC batch')
                byid={row.get('id'):row for row in payload if isinstance(row,dict)}
                if len(byid)!=len(batch)or any(body['id']not in byid for body,_ in batch):raise ValueError('Base RPC IDs differ')
                state['batches'].append({'requests':[body for body,_ in batch],'responses':payload,'transport':meta})
                for body,future in batch:
                    if not future.done():future.set_result(byid[body['id']])
            except asyncio.CancelledError:
                for _,future in batch:
                    if not future.done():future.cancel()
                raise
            except (httpx.HTTPError,ValueError)as exc:
                lookup.failure_status='rate_limited'if isinstance(exc,httpx.HTTPStatusError)and exc.response.status_code==429 else'unavailable'
                for _,future in batch:
                    if not future.done():future.set_result({'result':'0x'})

    async def _reverse_name(self,lookup,address):
        # Ask the deployed registrar for its reverse node instead of guessing
        # an addr.reverse versus coin-specific namespace.
        selector=keccak_256(b'node(address)')[:4].hex()
        node=await self._eth_call(lookup,BASE_REVERSE_REGISTRAR,'0x'+selector+address[2:].lower().rjust(64,'0'),'reverse node')
        if not node or not re.fullmatch(r'0x[0-9a-fA-F]{64}',node):return None
        resolver=await self._registry_address(lookup,'resolver',node[2:])
        if not resolver:return None
        result=self._decode_string(await self._eth_call(lookup,resolver,'0x691f3431'+node[2:],'reverse name'),lookup.out,'reverse name')
        candidate=self._clean_name(result)
        return candidate if candidate and candidate.endswith('.base.eth')else None

    async def resolve_name(self,name):return await self.fetch(name)

    async def fetch(self,address):
        query=address.strip();out=AddressReport(target_address=query,sources_used=[self.name])
        result=_outcome(self.name,'base',query,'https://www.base.org/names')
        out.public_address_context={'version':1,'outcomes':[result]};self._partial_report=out
        result['source_type']='public_rpc'
        result['coverage']={'target_only':True,'chain_id':8453,'max_rpc_calls':28,'max_http_batches':10,
            'known_text_keys':list(BASE_TEXT_KEYS),'cache_ttl_seconds':45,'financial_collection':False,
            'proof':'block-pinned eth_call via provider; no Merkle-state proof verification'}
        input_name=None;lookup=None
        if not ETH_RE.fullmatch(query):
            try:
                input_name=normalize_name(query)
                if not input_name.endswith('.base.eth'):raise ValueError('Base namespace required')
            except ValueError:return _finish(out,result,self._timeout,'skipped','EVM address or exact .base.eth name required')
        try:
            async with asyncio.timeout(self._timeout):
                async with shared_async_client(min(self._timeout,8))as client:
                    lookup=_Lookup(client,self._rpc_url(),out)
                    chain,block=await asyncio.gather(self._rpc(lookup,'eth_chainId',[]),self._rpc(lookup,'eth_blockNumber',[]))
                    if chain.get('result')!='0x2105':raise ValueError('Base provider chain mismatch')
                    block=block.get('result')
                    if not isinstance(block,str)or not re.fullmatch(r'0x[0-9a-fA-F]+',block):raise ValueError('No Base snapshot block')
                    lookup.block=block
                    target=query if ETH_RE.fullmatch(query)else await self._forward(lookup,input_name)
                    profile_name=input_name;primary_name=None;primary_verified=False
                    if target and ETH_RE.fullmatch(target):
                        candidate=await self._reverse_name(lookup,target)
                        if candidate:
                            forward=target if input_name==candidate else await self._forward(lookup,candidate)
                            primary_verified=bool(forward and forward.lower()==target.lower())
                            primary_name=candidate if primary_verified else None
                            if not input_name:profile_name=primary_name
                    if profile_name and target and ETH_RE.fullmatch(target):
                        context=await self._find_resolver(lookup,profile_name)
                        if context:
                            owner,*texts=await asyncio.gather(self._registry_address(lookup,'owner',namehash(profile_name)),
                                *(self._record_string(lookup,profile_name,context,'text',key)for key in BASE_TEXT_KEYS))
                            records={key:value for key,value in zip(BASE_TEXT_KEYS,texts)if value}
                            stamps=[batch['transport']['retrieved_at']for batch in lookup._base_context_state['batches']]
                            if stamps:result['retrieved_at']=max(stamps)
                            url='https://www.base.org/name/'+quote(profile_name[:-9],safe='')
                            value={'name':profile_name,'username':profile_name,'resolved_address':target,
                                'registry':BASE_REGISTRY,'registry_owner':owner,'resolver':context[0],
                                'registry_owner_role':'registry owner/controller; not a claim of registrar NFT ownership',
                                'primary_name':primary_name,'primary_verified':primary_verified and primary_name==profile_name,
                                'forward_verified':True,'chain_id':8453,'block_number':int(block,16),
                                'block_tag':block,'input_name':input_name,'records':records,
                                'record_claim_status':'self_published_profile_record'}
                            claim=_claim(self.name,'base',target,profile_name,'basename','basename_resolution',
                                'basename_resolves_to',value,'onchain_resolution',url,result['retrieved_at'])
                            result['claims'].append(claim);out.target_address=target
                            avatar=media_url(records.get('avatar'))
                            if avatar:
                                try:thumb=await _profile_thumbnail(client,avatar,self._timeout)
                                except (TimeoutError,httpx.HTTPError,ValueError,OSError,ImportError):thumb=None
                                if thumb:value.update(avatar=thumb,avatar_thumbnail=thumb['image_url'],avatar_url=thumb['source_url'])
                    state=getattr(lookup,'_base_context_state',{})
                    result['evidence']={'rpc_batches':state.get('batches',[])}
                    result['coverage'].update(rpc_calls=lookup.rpc_calls,http_batches=state.get('http_requests',0),
                        transport_requests=sum(row['transport']['transport_requests']for row in state.get('batches',[])),
                        cache_hit_batches=sum(row['transport']['cache_hit']for row in state.get('batches',[])),
                        unavailable_methods=lookup.unavailable_methods,block_tag=lookup.block)
                    status='partial'if lookup.failure_status or out.ens_warnings else'ok'if result['claims']else'empty'
                    return _finish(out,result,self._timeout,status,'Base name/address relation; text records are separate self-published assertions')
        except asyncio.CancelledError:raise
        except TimeoutError:status='partial'if result['claims']else'timeout'
        except (httpx.HTTPError,ValueError):status=lookup.failure_status if lookup and lookup.failure_status else'unavailable'
        finally:
            if lookup is not None:
                state=getattr(lookup,'_base_context_state',{})
                result['evidence']={'rpc_batches':state.get('batches',[])}
                result['coverage'].update(rpc_calls=lookup.rpc_calls,http_batches=state.get('http_requests',0),block_tag=lookup.block)
                pending=state.get('task')
                if pending is not None and not pending.done():
                    pending.cancel()
                    await asyncio.gather(pending,return_exceptions=True)
        return _finish(out,result,self._timeout,status,'Base context unavailable or partial; no guessed resolution')
