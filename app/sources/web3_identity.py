"""Public wallet-linked identity context, separate from financial collection."""
from __future__ import annotations

import asyncio
from datetime import datetime,timezone
import hashlib
import json
from typing import Any

import httpx

from app.models.report import AddressReport,SourceHealth
from app.sources.base import Source
from app.sources.ethereum_ens import ETH_RE,_public_image_bytes,_thumbnail_png,media_url
from app.sources.public_context_http import public_json
from app.utils.http import shared_async_client
from app.utils.security import safe_public_url

LENS_ENDPOINT='https://api.lens.xyz/graphql'
LENS_FIELDS='address owner createdAt username { value localName namespace linkedTo ownedBy } metadata { name bio picture }'
LENS_QUERY='query GansarWalletProfiles($address:EvmAddress!){owned:accountsBulk(request:{ownedBy:[$address]}){'+LENS_FIELDS+'} account:account(request:{address:$address}){'+LENS_FIELDS+'}}'


def _stamp():return datetime.now(timezone.utc).isoformat()


def _outcome(source,chain,target,url):
    return {'source':source,'source_type':'public_api','chain':chain,'input':target,
        'status':'empty','retrieved_at':_stamp(),'source_url':url,'coverage':{},'claims':[],'evidence':{}}


def _claim(source,chain,target,object_id,object_type,kind,relation,value,status,url,when):
    identity=json.dumps([source,chain,target.lower(),object_id,kind,relation],separators=(',',':'))
    return {'id':source+':'+hashlib.sha256(identity.encode()).hexdigest(),'object_id':object_id,
        'object_type':object_type,'subject_address':target,'claim_type':kind,'relation':relation,
        'value':value,'claim_status':status,'source_url':url,'retrieved_at':when}


def _finish(out,outcome,timeout,status,details):
    outcome['status']=status
    out.public_address_context={'version':1,'outcomes':[outcome]}
    out.source_health.append(SourceHealth(source=outcome['source'],status=status,timeout_seconds=timeout,
        retry_strategy='target-only bounded public context; cached successful responses; no immediate retries',
        details=details,partial=status=='partial'))
    return out


async def _profile_thumbnail(client,url,timeout):
    url=media_url(url,allow_data=False)
    if not url or not url.startswith('https://')or not safe_public_url(url):return None
    async with asyncio.timeout(min(4.0,timeout)):
        raw,kind=await _public_image_bytes(client,url)
        thumbnail=await asyncio.to_thread(_thumbnail_png,raw)
        return {'image_url':thumbnail,'source_url':url,'source_bytes':len(raw),'content_type':kind,
            'source_sha256':hashlib.sha256(raw).hexdigest(),'retrieved_at':_stamp(),
            'transformation':'Actual public raster resized within192px PNG; no generated replacement'}


class LensPublicSource(Source):
    """Exact account owner/address matches from the public Lens indexer.

    Account controller, Lens account and username owner are intentionally
    separate fields. The API report is not a local cryptographic proof.
    """
    name='lens_public'
    chain='multi'
    public_context_only=True
    context_chain='lens'

    def __init__(self,timeout_seconds:float):self._timeout=timeout_seconds

    async def fetch(self,address:str)->AddressReport:
        target=address.strip()
        out=AddressReport(target_address=target,sources_used=[self.name])
        result=_outcome(self.name,'lens',target,LENS_ENDPOINT)
        out.public_address_context={'version':1,'outcomes':[result]};self._partial_report=out
        result['coverage']={'target_only':True,'max_profiles':12,'max_response_bytes':1_000_000,
            'request_count':1,'cache_ttl_seconds':300,'manager_lookup':'not queried',
            'verification':'public Lens API role report; no local signature or onchain state verification'}
        if not ETH_RE.fullmatch(target):return _finish(out,result,self._timeout,'skipped','EVM address required')
        try:
            async with asyncio.timeout(self._timeout):
                async with shared_async_client(min(self._timeout,8))as client:
                    body={'query':LENS_QUERY,'variables':{'address':target}}
                    payload,meta=await public_json(client,'POST',LENS_ENDPOINT,json=body,with_metadata=True)
                    result['retrieved_at']=meta['retrieved_at'];result['coverage'].update(meta)
                    data=payload.get('data')
                    if not isinstance(data,dict):
                        result['evidence']={'request':body,'response':payload}
                        return _finish(out,result,self._timeout,'unavailable','Lens returned no usable GraphQL data')
                    owned=data.get('owned')or[]
                    if not isinstance(owned,list):raise ValueError('Lens accounts response must be a list')
                    entries=[*owned,*([data['account']]if isinstance(data.get('account'),dict)else[])]
                    retained,seen=[],set()
                    for row in entries:
                        if not isinstance(row,dict):continue
                        object_id=row.get('address');owner=row.get('owner')
                        if not isinstance(object_id,str)or not ETH_RE.fullmatch(object_id)or not isinstance(owner,str)or not ETH_RE.fullmatch(owner):continue
                        if owner.lower()!=target.lower()and object_id.lower()!=target.lower():continue
                        # The API also returns virtual EOA Account wrappers
                        # without any Lens profile. Keep them in raw evidence,
                        # not as an invented public identity node.
                        if not row.get('username')and not row.get('metadata'):continue
                        if object_id.lower()in seen:continue
                        seen.add(object_id.lower());retained.append(row)
                    over=len(retained)>12;retained=retained[:12]
                    result['evidence']={'request':body,'response':payload}
                    for row in retained:
                        metadata=row.get('metadata')if isinstance(row.get('metadata'),dict)else{}
                        username=row.get('username')if isinstance(row.get('username'),dict)else{}
                        value={'account_address':row['address'],'controller_address':row['owner'],
                            'created_at':row.get('createdAt'),'username':username.get('value'),
                            'username_record':username,'name':metadata.get('name')or username.get('value')or row['address'],
                            'metadata':metadata,'metadata_claim_status':'self_published_profile_record','manager_role':'not queried',
                            'relation_role':'account_owner'if row['owner'].lower()==target.lower()else'account_address'}
                        result['claims'].append(_claim(self.name,'lens',target,row['address'],'profile',
                            'lens_account_role','lens_account_owner'if value['relation_role']=='account_owner'else'lens_account_address',
                            value,'provider_reported_account_role',LENS_ENDPOINT,result['retrieved_at']))
                    # Three actual avatars at most. Unavailable media cannot
                    # erase an already obtained exact profile/address match.
                    for claim in result['claims'][:3]:
                        url=(claim['value'].get('metadata')or{}).get('picture')
                        if not url:continue
                        try:thumb=await _profile_thumbnail(client,url,self._timeout)
                        except (TimeoutError,httpx.HTTPError,ValueError,OSError,ImportError):thumb=None
                        if thumb:
                            claim['value']['avatar']=thumb
                            claim['value']['avatar_thumbnail']=thumb['image_url']
                            claim['value']['avatar_url']=thumb['source_url']
                        else:claim['value']['avatar_status']='unavailable_or_unsafe'
                    status='partial'if over or payload.get('errors')else'ok'if result['claims']else'empty'
                    result['coverage'].update(returned_profiles=len(result['claims']),profiles_truncated=over,
                        username_ownership='separate username.ownedBy; never inferred from Account.owner')
                    return _finish(out,result,self._timeout,status,'Exact Lens roles retained; profile metadata is self-published')
        except asyncio.CancelledError:raise
        except TimeoutError:return _finish(out,result,self._timeout,'partial'if result['claims']else'timeout','Lens context deadline; retained exact profiles kept')
        except httpx.HTTPStatusError as exc:return _finish(out,result,self._timeout,'rate_limited'if exc.response.status_code==429 else'unavailable','Lens public API unavailable; no retry')
        except (httpx.HTTPError,ValueError):return _finish(out,result,self._timeout,'unavailable','Lens public response unavailable or malformed')
