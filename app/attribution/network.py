"""Bounded public verification collector, scheduled by existing SourceManager."""
import asyncio
from datetime import datetime,timezone
import hashlib
import json
import re
from app.models.report import AddressReport,SourceHealth
from app.sources.base import Source
from app.utils.http import shared_async_client,request_json
from app.utils.security import sanitize_observation
from app.sources.public_context_http import public_json
from .normalize import CHAIN_IDS,canonical_address

class VerifiedContractSource(Source):
    """Fresh runtime gate, then one cached target-only public v2 lookup."""
    def __init__(self,chain,timeout_seconds):
        self.chain=chain;self.name=f'sourcify_{chain}';self._timeout=min(5,timeout_seconds)
        from app.sources.evm_rpc import EthereumRpcSource,BscRpcSource,PolygonRpcSource,ArbitrumRpcSource,OptimismRpcSource,AvalancheRpcSource
        self._rpc_url={'eth':EthereumRpcSource,'bsc':BscRpcSource,'polygon':PolygonRpcSource,
            'arbitrum':ArbitrumRpcSource,'optimism':OptimismRpcSource,'avalanche':AvalancheRpcSource}[chain].rpc_url
    async def fetch(self,address):
        out=AddressReport(target_address=address,detected_chains=[self.chain],sources_used=[self.name]);self._partial_report=out
        original=address
        address=canonical_address(self.chain,address)
        url=f'https://sourcify.dev/server/v2/contract/{CHAIN_IDS[self.chain]}/{address}'
        start=asyncio.get_running_loop().time();status='partial';details='Runtime gate not completed'
        coverage={'source':self.name,'source_type':'contract_verification','chain':self.chain,'input':original,
            'address':address,'chain_id':CHAIN_IDS[self.chain],'source_url':url,'status':status,
            'rpc_requests':0,'metadata_transport_requests':0,'metadata_cache_hit':False,
            'history_complete':False,'scope':'Target-only verified contract metadata; no financial rows'}
        out.coverage[self.name]=coverage
        try:
            async with asyncio.timeout(min(5,self._timeout)),shared_async_client(min(4,self._timeout)) as client:
                if address is None:raise ValueError('Invalid EVM address for contract verification')
                coverage['rpc_requests']+=1
                chain_data=await request_json(client,'POST',self._rpc_url,json={'jsonrpc':'2.0','id':1,'method':'eth_chainId','params':[]},retries=0,cache_ttl=0)
                chain_result=chain_data.get('result')if isinstance(chain_data,dict)and not chain_data.get('error')else None
                if not isinstance(chain_result,str)or not re.fullmatch(r'0x[0-9a-fA-F]+',chain_result)or int(chain_result,16)!=CHAIN_IDS[self.chain]:
                    raise ValueError('Runtime gate RPC chain mismatch or missing chain identity')
                coverage['rpc_requests']+=1
                code_data=await request_json(client,'POST',self._rpc_url,json={'jsonrpc':'2.0','id':2,'method':'eth_getCode','params':[address,'latest']},retries=0,cache_ttl=0)
                code=code_data.get('result')if isinstance(code_data,dict)and not code_data.get('error')else None
                if not isinstance(code,str)or not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*',code):
                    raise ValueError('Runtime gate RPC returned malformed or missing bytecode')
                runtime={'method':'eth_chainId + eth_getCode','source_url':self._rpc_url,'chain_id':CHAIN_IDS[self.chain],
                    'address':address,'block_tag':'latest','observed_at':datetime.now(timezone.utc).isoformat(),
                    'runtime_code_bytes':(len(code)-2)//2,'runtime_code_sha256':hashlib.sha256(bytes.fromhex(code[2:])).hexdigest(),
                    'raw_chain_id':chain_result,'raw_code':code,'state_proof_verified':False}
                coverage['runtime_gate']=runtime
                if code=='0x':
                    status='skipped';runtime['kind']='no_runtime_code';details='No current runtime code; Sourcify was not queried'
                elif len(code)==48 and code.lower().startswith('0xef0100'):
                    status='skipped';runtime.update(kind='eip7702_delegation_indicator',delegated_address='0x'+code[8:].lower())
                    details='EIP-7702 EOA delegation indicator; no deployed source is inferred and delegate is not followed'
                else:
                    runtime['kind']='deployed_runtime_code'
                    data,metadata=await public_json(client,'GET',url,params={'fields':'compilation,deployment,proxyResolution'},
                        max_bytes=2_000_000,cache_ttl=300,with_metadata=True,user_agent='Gansar/0.3.1 (+https://t.me/solvnox_project)')
                    coverage.update(metadata_transport_requests=metadata['transport_requests'],metadata_cache_hit=metadata['cache_hit'],metadata_retrieved_at=metadata['retrieved_at'])
                    if not isinstance(data,dict) or canonical_address(self.chain,data.get('address'))!=address or str(data.get('chainId'))!=str(CHAIN_IDS[self.chain]):
                        raise ValueError('Verification response chain/address mismatch or missing identity')
                    obs={'blockchain':self.chain,'address':address,'source':self.name,'upstream':'sourcify',
                        'source_url':url+'?fields=compilation%2Cdeployment%2CproxyResolution','url':url,
                        'observed_at':metadata['retrieved_at'],'method':'public_contract_verification','claim_type':'verified_contract_metadata',
                        'claim_status':'provider_reported_verification','runtime_gate':runtime,'cache_hit':metadata['cache_hit'],
                        'raw':sanitize_observation(data),'requests':coverage['rpc_requests']+metadata['transport_requests'],
                        'elapsed_seconds':asyncio.get_running_loop().time()-start}
                    out.contract_observations.append(obs);status='ok';details='Fresh runtime gate plus bounded cached public v2 metadata; verification does not establish operator ownership'
        except asyncio.CancelledError:raise
        except Exception as exc:
            response=getattr(exc,'response',None);code=getattr(response,'status_code',None)
            status='unavailable' if code==404 else 'rate_limited' if code==429 else 'timeout' if isinstance(exc,(TimeoutError,asyncio.TimeoutError)) else 'error'
            out.errors.append(f'{self.name}: {status}: '+str(sanitize_observation(str(exc)))[:600])
            details='Contract gate or public metadata unavailable; no verification claim created'
        coverage.update(status=status,details=details,elapsed_seconds=asyncio.get_running_loop().time()-start)
        out.source_health.append(SourceHealth(source=self.name,status=status,partial=status not in {'ok','skipped'},
            timeout_seconds=min(5,self._timeout),retry_strategy='fresh RPC runtime gate; metadata cache 300s; shared provider pacing/cooldown; no retries',details=details))
        return out

class TronContractEvidenceSource(Source):
    name='tron_contract_metadata'
    chain='tron'
    def __init__(self,timeout_seconds):self._timeout=min(5,timeout_seconds)
    async def fetch(self,address):
        out=AddressReport(target_address=address,detected_chains=['tron'],sources_used=[self.name]);self._partial_report=out
        url='https://apilist.tronscanapi.com/api/contract';status='partial'
        try:
            async with asyncio.timeout(min(5,self._timeout)),shared_async_client(min(4,self._timeout)) as client:
                data=await request_json(client,'GET',url,params={'contract':address},retries=0,cache_ttl=0)
            if not isinstance(data,dict) or not isinstance(data.get('data'),list):raise ValueError('Unsupported contract response schema')
            rows=data['data']
            if rows:
                row=rows[0]
                if canonical_address('tron',row.get('address'))!=canonical_address('tron',address):raise ValueError('Contract response address mismatch')
                creator=row.get('creator') or {}
                out.contract_observations.append({'blockchain':'tron','address':address,'source':self.name,'upstream':'tronscan',
                    'source_url':url+'?contract='+address,'observed_at':datetime.now(timezone.utc).isoformat(),
                    'raw':{'compilation':{'name':row.get('name')},'deployment':{'deployer':creator.get('address'),'transactionHash':creator.get('txHash')},
                        'proxyResolution':{'isProxy':row.get('is_proxy'),'implementations':[{'address':row['proxy_implementation']}] if row.get('proxy_implementation') else []},
                        'provider_metadata':row},'requests':1})
                status='ok'
        except asyncio.CancelledError:raise
        except Exception as exc:
            response=getattr(exc,'response',None);code=getattr(response,'status_code',None)
            status='rate_limited' if code==429 else 'unavailable' if code==404 else 'timeout' if isinstance(exc,TimeoutError) else 'error'
            out.errors.append(f'{self.name}: {status}: '+str(sanitize_observation(str(exc)))[:600])
        out.source_health.append(SourceHealth(source=self.name,status=status,partial=True,timeout_seconds=min(5,self._timeout),
            retry_strategy='one bounded public metadata lookup',details='Provider contract labels and creator are not service control proof'))
        return out
