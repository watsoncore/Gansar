"""Optional bounded receipt hydration inside the ordinary collection pipeline."""
from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json

from app.models.report import SourceHealth
from app.sources.evm_rpc import EvmRpcBalanceSource
from app.utils.http import shared_async_client
from app.utils.security import sanitize_observation
from .evm_transaction_fingerprints import ENTRYPOINTS, SAFE_FACTORIES, _hex, _integer
from .normalize import CHAIN_IDS, canonical_address
from .cross_chain import receipt_targets

MAX_RESPONSE_BYTES = 2_000_000


async def enrich_evm_receipts(report, sources, source_manager, *, deadline=None,
                              max_transactions=8, max_seconds=3.0, concurrency=2):
    """Hydrate at most eight known infrastructure transactions, without retries.

    Uses only existing RPC source endpoints and their SourceManager gates. A
    failure of this optional evidence pass never disables another collector or
    invalidates already collected dossier data. No global log/history scan.
    """
    loop = asyncio.get_running_loop()
    started = loop.time()
    seconds = max(0.0, min(3.0, float(max_seconds)))
    stop = min(started + seconds, deadline) if deadline is not None else started + seconds
    cap = max(0, min(8, int(max_transactions)))
    available = {s.chain: s for s in sources if isinstance(s, EvmRpcBalanceSource)}
    from .telegram_services import service_receipt_targets
    service_targets={chain:service_receipt_targets(chain) for chain in available}
    from .service_infrastructure import exchange_receipt_targets
    for chain in available: service_targets[chain] |= exchange_receipt_targets(report, chain)
    service_candidates=set()
    candidates = {}
    seen_eligible = set()
    eligible = 0
    for tx in report.transactions:
        chain = tx.chain
        tx_hash = _hex(tx.tx_hash, 32)
        recipient = canonical_address(chain, tx.to_address)
        participants={canonical_address(chain,a) for a in (tx.from_address,tx.to_address)}
        infrastructure=set(SAFE_FACTORIES)|set(ENTRYPOINTS)|set(receipt_targets(chain))|service_targets.get(chain,set())
        if chain not in available or not participants.intersection(infrastructure) or not tx_hash or tx.success is False or tx.raw.get('emulated') is True:
            continue
        if any(isinstance(tx.raw.get(key), dict) for key in ('receipt', 'transaction_receipt', 'rpc_receipt')):
            continue
        key = (chain, tx_hash)
        if participants.intersection(service_targets.get(chain,set())):service_candidates.add(key)
        if key in candidates:
            candidates[key].append(tx)
            continue
        if key not in seen_eligible:
            eligible += 1
            seen_eligible.add(key)
        if len(candidates) < cap:
            candidates[key] = [tx]
    coverage = {'eligible_transactions': eligible, 'selected_transactions': len(candidates),
                'requested_transactions': 0, 'loaded_transactions': 0, 'network_requests': 0,
                'max_transactions': cap, 'max_seconds': seconds, 'response_byte_limit': MAX_RESPONSE_BYTES,
                'status': 'not_needed', 'failures': [], 'limitations': [
                    'Only already collected transactions with published Safe factory, EntryPoint pinned Wormhole or exact published service-label participants are considered; unobserved internal calls can be missed.',
                    'This bounded evidence pass does not recover missing transaction history or authenticate a signing UI.']}
    if available:
        report.coverage['evm_receipt_evidence'] = coverage
    if not candidates:
        return coverage
    grouped = defaultdict(list)
    for (chain, tx_hash), copies in candidates.items():
        grouped[chain].append((tx_hash, copies))
    semaphore = asyncio.Semaphore(max(1, min(2, int(concurrency))))

    def failure(chain, message):
        detail = str(sanitize_observation(str(message)))[:400]
        coverage['failures'].append({'blockchain': chain, 'error': detail})
        report.errors.append(f'evm_receipt_evidence:{chain}: {detail}')

    async def hydrate(chain, rows):
        source = available[chain]
        budget = min(seconds, source_manager.timeout(source.name, seconds))
        if not source_manager.should_run(source.name, budget):
            failure(chain, 'Existing RPC source is disabled by SourceManager; receipt enrichment skipped')
            return
        if loop.time() >= stop:
            failure(chain, 'Collection deadline reached before receipt enrichment')
            return
        body = [{'jsonrpc': '2.0', 'id': 0, 'method': 'eth_chainId', 'params': []}]
        body += [{'jsonrpc': '2.0', 'id': i, 'method': 'eth_getTransactionReceipt', 'params': [tx_hash]}
                 for i, (tx_hash, _) in enumerate(rows, 1)]
        transaction_ids={i:len(rows)+i for i,(tx_hash,_) in enumerate(rows,1) if (chain,tx_hash) in service_candidates}
        body += [{'jsonrpc':'2.0','id':transaction_ids[i],'method':'eth_getTransactionByHash','params':[tx_hash]}
                 for i,(tx_hash,_) in enumerate(rows,1) if i in transaction_ids]
        try:
            async with asyncio.timeout_at(stop):
                async with semaphore:
                    remaining = min(budget, stop - loop.time())
                    if remaining <= 0:
                        raise TimeoutError('Receipt enrichment time budget exhausted')
                    coverage['network_requests'] += 1
                    coverage['requested_transactions'] += len(rows)
                    async with asyncio.timeout(remaining), shared_async_client(remaining) as client:
                        async with client.stream('POST', source.rpc_url, json=body,
                                                 headers={'Cache-Control': 'no-cache'}) as response:
                            response.raise_for_status()
                            content = bytearray()
                            async for chunk in response.aiter_bytes():
                                if len(content) + len(chunk) > MAX_RESPONSE_BYTES:
                                    raise ValueError('Receipt batch exceeded response byte limit')
                                content.extend(chunk)
                    data = json.loads(content)
                    if not isinstance(data, list) or len(data) != len(body) or not all(isinstance(r, dict) for r in data):
                        raise ValueError('Unsupported receipt batch response envelope')
                    by_id = {r.get('id'): r for r in data if isinstance(r.get('id'), int) and not isinstance(r.get('id'), bool)}
                    if len(by_id) != len(body) or set(by_id) != {row['id'] for row in body}:
                        raise ValueError('Receipt batch IDs are missing, duplicated or unexpected')
                    if by_id[0].get('error') or _integer(by_id[0].get('result')) != CHAIN_IDS[chain]:
                        raise ValueError('Receipt RPC chain ID mismatch or unavailable')
                    block_hashes=list(dict.fromkeys(_hex(_dict_reply.get('result',{}).get('blockHash'),32)
                        for i in transaction_ids for _dict_reply in [by_id[i]] if isinstance(_dict_reply.get('result'),dict)))
                    block_hashes=[value for value in block_hashes if value]
                    blocks={};block_digest=None
                    if block_hashes:
                        try:
                            async with asyncio.timeout(max(.01,stop-loop.time()-.05)):
                                block_body=[{'jsonrpc':'2.0','id':0,'method':'eth_chainId','params':[]}]+[
                                    {'jsonrpc':'2.0','id':i,'method':'eth_getBlockByHash','params':[value,False]} for i,value in enumerate(block_hashes,1)]
                                coverage['network_requests']+=1
                                async with shared_async_client(max(.05,stop-loop.time())) as block_client:
                                    async with block_client.stream('POST',source.rpc_url,json=block_body,headers={'Cache-Control':'no-cache'}) as block_response:
                                        block_response.raise_for_status();block_content=bytearray()
                                        async for chunk in block_response.aiter_bytes():
                                            if len(block_content)+len(chunk)>MAX_RESPONSE_BYTES:raise ValueError('Block-header batch exceeded response byte limit')
                                            block_content.extend(chunk)
                                block_data=json.loads(block_content)
                                if not isinstance(block_data,list) or len(block_data)!=len(block_body) or not all(isinstance(row,dict) for row in block_data):raise ValueError('Invalid block-header batch envelope')
                                block_by_id={row.get('id'):row for row in block_data if type(row.get('id')) is int}
                                if set(block_by_id)!=set(range(len(block_body))) or _integer(block_by_id[0].get('result'))!=CHAIN_IDS[chain]:raise ValueError('Block-header RPC IDs/chain mismatch')
                                block_digest=hashlib.sha256(block_content).hexdigest()
                                blocks={value:block_by_id[i].get('result') for i,value in enumerate(block_hashes,1)
                                    if isinstance(block_by_id[i].get('result'),dict) and not block_by_id[i].get('error') and _hex(block_by_id[i]['result'].get('hash'),32)==value}
                        except asyncio.CancelledError:raise
                        except Exception as exc:failure(chain,f'Optional block-header evidence unavailable: {type(exc).__name__}: {exc}; receipts retained')
                    observed = datetime.now(timezone.utc).isoformat()
                    digest = hashlib.sha256(content).hexdigest()
                    for i, (tx_hash, copies) in enumerate(rows, 1):
                        reply = by_id[i]
                        receipt = reply.get('result')
                        if reply.get('error') or not isinstance(receipt, dict):
                            failure(chain, f'Receipt unavailable for {tx_hash}')
                            continue
                        if _hex(receipt.get('transactionHash'), 32) != tx_hash or _integer(receipt.get('status')) != 1:
                            failure(chain, f'Receipt hash/status mismatch or failed execution for {tx_hash}')
                            continue
                        if not isinstance(receipt.get('logs'), list):
                            failure(chain, f'Receipt logs missing for {tx_hash}')
                            continue
                        provenance = {'source': source.name, 'source_url': source.rpc_url,
                                      'method': 'eth_getTransactionReceipt', 'chain_id': CHAIN_IDS[chain],
                                      'observed_at': observed, 'response_sha256': digest,
                                      'response_hash_scope': 'complete_json_rpc_batch_response',
                                      'network_requests': 1, 'historical_runtime_verified': False,'block_response_sha256':block_digest}
                        native_reply=by_id.get(transaction_ids.get(i),{})
                        native=native_reply.get('result')
                        native_ok=isinstance(native,dict) and _hex(native.get('hash'),32)==tx_hash and not native_reply.get('error')
                        if i in transaction_ids and not native_ok:
                            failure(chain,f'Native transaction unavailable or hash mismatch for {tx_hash}; receipt retained')
                        block=blocks.get(_hex(receipt.get('blockHash'),32))
                        block_ok=isinstance(block,dict) and _integer(block.get('number'))==_integer(receipt.get('blockNumber')) and _integer(block.get('timestamp')) is not None
                        for tx in copies:
                            tx.raw = {**tx.raw, 'receipt': receipt, 'receipt_provenance': provenance,
                                **({'rpc_transaction':native} if native_ok else {}),**({'rpc_block':block} if block_ok else {})}
                        coverage['loaded_transactions'] += 1
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            failure(chain, f'{type(exc).__name__}: {exc}')

    await asyncio.gather(*(hydrate(chain, rows) for chain, rows in grouped.items()))
    coverage['elapsed_seconds'] = loop.time() - started
    coverage['status'] = 'ok' if coverage['loaded_transactions'] == len(candidates) and not coverage['failures'] else 'partial' if coverage['loaded_transactions'] else 'unavailable'
    coverage['truncated'] = eligible > len(candidates) or loop.time() >= stop
    for chain in grouped:
        source = available[chain]
        failed = any(f['blockchain'] == chain for f in coverage['failures'])
        report.source_health.append(SourceHealth(source=source.name, status='partial' if failed else 'ok',
            timeout_seconds=seconds, partial=failed,
            retry_strategy='optional bounded receipt evidence; no retries',
            details=f'Receipt enrichment: {chain}; failures={sum(f["blockchain"] == chain for f in coverage["failures"])}; source health gate preserved'))
    return coverage
