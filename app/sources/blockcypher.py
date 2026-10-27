"""Bounded public BTC/DOGE fallback using the existing UTXO model contract.

Provider endpoint exhaustion never proves complete blockchain history.
Read-only API and limits: https://www.blockcypher.com/dev/bitcoin/
"""
from __future__ import annotations
import asyncio
import time
import hashlib
import json
import re
from decimal import Decimal
from weakref import WeakKeyDictionary
from app.models.report import AddressReport, Balance, SourceHealth
from app.sources.base import Source
from app.sources.pagination import operation_key
from app.aggregator.collection_audit import stream_state, observe_page
from app.sources.bitcoin_mempool import BitcoinEsploraSource
from app.sources.dogecoin import DogecoinBlockchairSource
from app.utils.event_identity import event_identity
from app.utils.http import create_async_client, request_json, http_error_message, _retry_after_seconds
import httpx

_GATES = WeakKeyDictionary()
_HOUR = {'epoch': -1, 'attempts': 0, 'cooldown': 0.0}
_HASH = re.compile(r'[0-9a-fA-F]{64}\Z')

def tx_hash(value):
    return value.lower() if isinstance(value, str) and _HASH.fullmatch(value) else None

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def integer(x):
    return x if type(x) is int and x >= 0 else None

def single_address(row):
    addresses = row.get('addresses', [])
    return addresses[0] if isinstance(addresses, list) and len(addresses) == 1 and isinstance(addresses[0], str) and addresses[0] else ''

def as_esplora(tx):
    return {'txid': tx['hash'], 'version': tx.get('ver'), 'locktime': tx.get('lock_time'),
        'size': tx.get('size'), 'weight': tx.get('weight'), 'fee': tx.get('fees'),
        'vin': [{'txid': i.get('prev_hash'), 'vout': i.get('output_index'),
                 'prevout': {'scriptpubkey_address': single_address(i), 'value': i.get('output_value')},
                 'sequence': i.get('sequence'), 'scriptsig': i.get('script'),
                 'witness': i.get('witness'), 'is_coinbase': i.get('prev_hash') == '0'*64}
                for i in tx['inputs']],
        'vout': [{'scriptpubkey_address': single_address(o), 'value': o.get('value'),
                  'scriptpubkey': o.get('script'), 'scriptpubkey_type': o.get('script_type')}
                 for o in tx['outputs']],
        'status': {'confirmed': integer(tx.get('block_height')) is not None and tx.get('block_height', -1) >= 0,
                   'block_height': tx.get('block_height'), 'block_hash': tx.get('block_hash'),
                   'block_time': None}}

def as_blockchair(tx):
    return {'transaction': {'time': tx.get('confirmed'), 'block_id': tx.get('block_height'),
                             'fee': tx.get('fees'), 'input_count': tx.get('vin_sz'),
                             'output_count': tx.get('vout_sz')},
            'inputs': [{'recipient': single_address(i), 'value': i.get('output_value'),
                        'transaction_hash': i.get('prev_hash'), 'index': i.get('output_index')}
                       for i in tx['inputs']],
            'outputs': [{'recipient': single_address(o), 'value': o.get('value'), 'index': n,
                         'is_spent': True if tx_hash(o.get('spent_by')) else None, 'spending_transaction_hash': o.get('spent_by')}
                        for n, o in enumerate(tx['outputs'])]}

class BlockCypherPublicSource(Source):
    """One normalization path for two already-supported UTXO chains."""
    name = 'blockcypher_public'
    chain = 'doge'
    PAGE_SIZE = 20
    MAX_REQUESTS = 20
    MAX_IO = 4000

    def __init__(self, timeout_seconds=12, *, chain='doge'):
        if chain not in {'btc', 'doge'}:
            raise ValueError('BlockCypher scope is existing BTC/DOGE only')
        self.chain = chain
        self.name = f'blockcypher_{chain}'
        self._timeout = timeout_seconds
        self._contexts, self._io_progress = [], {}

    async def _get(self, client, path, params=None):
        if self._requests >= self.MAX_REQUESTS:
            raise RuntimeError('BlockCypher source request safety ceiling reached')
        lock, state = _GATES.setdefault(asyncio.get_running_loop(), (asyncio.Lock(), {'last': 0.0}))
        async with lock:
            epoch = int(time.time() // 3600)
            if _HOUR['epoch'] != epoch:
                _HOUR.update(epoch=epoch, attempts=0)
            if _HOUR['attempts'] >= 100 or _HOUR['cooldown'] > time.monotonic():
                raise RuntimeError('BlockCypher free-tier hourly budget/cooldown active')
            await asyncio.sleep(max(0, state['last'] + .4 - time.monotonic()))
            if _HOUR['cooldown'] > time.monotonic():
                raise RuntimeError('BlockCypher Retry-After cooldown active')
            state['last'] = time.monotonic()
            _HOUR['attempts'] += 1
            self._requests += 1
        try:
            # Existing cache/coalescing, no generic retry shortening Retry-After.
            return await request_json(client, 'GET', f'https://api.blockcypher.com/v1/{self.chain}/main{path}',
                                      params=params, retries=0)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                _HOUR['cooldown'] = max(_HOUR['cooldown'], time.monotonic() + (_retry_after_seconds(e.response) if _retry_after_seconds(e.response) is not None else 60))
            raise

    async def _complete_io(self, client, tx):
        original = tx
        tx = dict(tx)
        tx['hash'] = tx_hash(tx.get('hash'))
        if not tx['hash']:
            raise ValueError('Invalid TX hash')
        if not isinstance(tx.get('inputs'), list) or not isinstance(tx.get('outputs'), list):
            raise ValueError('Missing TX IO arrays')
        ins, outs = list(tx['inputs']), list(tx['outputs'])
        ni, no = integer(tx.get('vin_sz')), integer(tx.get('vout_sz'))
        if ni is None or no is None or ni < 1 or no < 1 or ni + no > self.MAX_IO:
            return None
        observations = [original]
        self._io_progress[tx['hash']] = []
        seen_io = {'inputs': {digest(ins)} if ins else set(), 'outputs': {digest(outs)} if outs else set()}
        for step in range(5):
            if len(ins) == ni and len(outs) == no:
                tx.update(inputs=ins, outputs=outs)
                return tx, observations
            if len(ins) > ni or len(outs) > no:
                return None
            if step == 4:
                return None
            page = await self._get(client, f"/txs/{tx['hash']}",
                                   {'limit': 1000, 'instart': len(ins), 'outstart': len(outs)})
            if not isinstance(page, dict) or tx_hash(page.get('hash')) != tx_hash(tx['hash']) or page.get('vin_sz') != ni or page.get('vout_sz') != no:
                raise ValueError('TX IO continuation changed transaction/counts')
            new_in, new_out = page.get('inputs'), page.get('outputs')
            if not isinstance(new_in, list) or not isinstance(new_out, list):
                raise ValueError('Malformed TX IO continuation')
            for field, rows in (('inputs', new_in), ('outputs', new_out)):
                if rows:
                    mark = digest(rows)
                    if mark in seen_io[field]:
                        raise ValueError('Repeated IO page; continuation not established')
                    seen_io[field].add(mark)
            if not new_in and not new_out:
                return None
            observations.append(page)
            self._io_progress[tx['hash']] = observations[1:]
            ins.extend(new_in)
            outs.extend(new_out)
        return None

    async def _decode_pending(self, out, client, address, pending, completed):
        for record in list(pending):
            row, identifier = record['provider_record'], record['tx_hash']
            try:
                if not identifier:
                    raise ValueError('Invalid transaction hash; original record retained')
                if identifier not in self._emitted:
                    complete = await self._complete_io(client, row)
                    if complete is None:
                        raise ValueError('TX IO incomplete within bounded detail budget')
                    self._normalize(out, address, *complete)
                    self._emitted.add(identifier)
                completed.append(operation_key('account_transactions', row))
                pending.remove(record)
            except asyncio.CancelledError:
                record['io_observations'] = self._io_progress.get(identifier, record.get('io_observations', []))
                raise
            except Exception as exc:
                record['io_observations'] = self._io_progress.get(identifier, record.get('io_observations', []))
                record['reason'] = http_error_message(exc)
                out.errors.append(f"{self.name}: detail {identifier or 'invalid hash'}: {record['reason']}")

    def _normalize(self, out, address, tx, observations):
        if not tx_hash(tx.get('hash')):
            raise ValueError('Invalid transaction hash')
        for i in tx['inputs']:
            if not isinstance(i, dict) or integer(i.get('output_value')) is None:
                raise ValueError('Missing input value; cannot compute target UTXO net')
        for o in tx['outputs']:
            if not isinstance(o, dict) or integer(o.get('value')) is None:
                raise ValueError('Missing output value; cannot compute target UTXO net')
        for row in tx['inputs']:
            if not tx_hash(row.get('prev_hash')) or integer(row.get('output_index')) is None:
                raise ValueError('Input outpoint is unknown')
        fees = tx.get('fees')
        if fees is not None and integer(fees) is None:
            raise ValueError('Malformed transaction fee')
        input_total = sum(row['output_value'] for row in tx['inputs'])
        output_total = sum(row['value'] for row in tx['outputs'])
        coinbase = any(row.get('prev_hash') == '0'*64 for row in tx['inputs'])
        if not coinbase and (input_total < output_total or (fees is not None and input_total != output_total + fees)):
            raise ValueError('IO values do not conserve transaction value')
        for row in tx['inputs'] + tx['outputs']:
            parties = row.get('addresses')
            if isinstance(parties, list) and any(isinstance(party, str) and party.lower() == address.lower() and party != address for party in parties):
                raise ValueError('Address case mismatch; no case-folded UTXO assignment emitted')
            if isinstance(parties, list) and address in parties and len(parties) != 1:
                self._contexts.append({'tx_hash': tx['hash'], 'status': 'UNKNOWN',
                    'reason': 'Target is a multi-address script participant; unique owner/net amount unresolved',
                    'provider_record': observations[0]})
                return
        parsed = AddressReport(target_address=address, detected_chains=[self.chain])
        # Reuse exactly the existing chain presentation/party contract.
        if self.chain == 'doge':
            converted = as_blockchair(tx)
            height = tx.get('block_height', -1)
            confirmations = tx.get('confirmations')
            tip = height + confirmations - 1 if type(height) is int and height >= 0 and type(confirmations) is int and confirmations > 0 else None
            DogecoinBlockchairSource._parse_detail_rows(self, address, parsed, [(tx['hash'], converted)], tip)
        else:
            converted = as_esplora(tx)
            from datetime import datetime
            try:
                converted['status']['block_time'] = int(datetime.fromisoformat(tx['confirmed'].replace('Z', '+00:00')).timestamp())
            except (KeyError, TypeError, ValueError):
                pass
            BitcoinEsploraSource._parse_btc_transactions(self, parsed, address, [converted], None)
        if len(parsed.transactions) != 1:
            raise ValueError('Existing UTXO view did not emit exactly one transaction')
        item = parsed.transactions[0]
        for row in item.inputs:
            row.pop('spent', None)
        for index, row in enumerate(item.outputs):
            if not tx_hash(tx['outputs'][index].get('spent_by')):
                row.pop('spent', None)
                row.pop('spending_tx_hash', None)
        if item.tx_hash != tx['hash']:
            raise ValueError('Existing normalizer did not emit expected TX')
        # Stable compatibility identity is established before adding higher-precision fields.
        # Existing models currently infer identity from the pre-decimal float view.
        item.event_id = event_identity(item)
        if item.amount is not None:
            base = abs(sum(i['output_value'] for i in tx['inputs'] if single_address(i) == address)
                       - sum(o['value'] for o in tx['outputs'] if single_address(o) == address))
            item.amount_base_units = base
            item.decimals = 8
            item.amount_decimal = Decimal(base).scaleb(-8)
        item.confirmations = integer(tx.get('confirmations'))
        item.url = f'https://api.blockcypher.com/v1/{self.chain}/main/txs/{item.tx_hash}'
        item.raw.update(provider=self.name, provider_record=observations[0], provider_io_observations=observations[1:],
                        io_complete=True, amount_semantics='target_address_utxo_net; no per-input-output allocation',
                        normalization_schema='existing_chain_utxo_view')
        out.transactions.append(item)


    def _account(self, out, address, data):
        if out.balances:
            return
        units = integer(data.get('final_balance'))
        metadata = {key:value for key,value in data.items() if key != 'txs'}
        if units is not None:
            out.balances.append(Balance(chain=self.chain, address=address, asset=self.chain.upper(),
                amount=units/100_000_000, amount_base_units=units, decimals=8,
                amount_decimal=Decimal(units).scaleb(-8), source=self.name,
                url=f'https://api.blockcypher.com/v1/{self.chain}/main/addrs/{address}',
                raw={'provider_record': metadata, 'balance_scope': 'final_balance_includes_unconfirmed',
                     'aggregate_totals_policy': 'provider-scoped; not combined with other explorers'}))
        summary = {'address': address, 'chain': 'dogecoin' if self.chain == 'doge' else 'bitcoin',
            'balance_sats': units, 'balance': units/100_000_000 if units is not None else None,
            'tx_count': integer(data.get('final_n_tx')), 'sources': [self.name], 'partial': True,
            'warnings': ['Bounded public history; aggregate gross totals are provider-scoped'],
            'explorer_links': {'blockcypher': f'https://live.blockcypher.com/{self.chain}/address/{address}/'}}
        if self.chain == 'doge':
            out.dogecoin = summary
        else:
            out.bitcoin = summary

    async def _window(self, out, client, address, state, known=None):
        if state.get('exhausted'):
            return
        cursor = dict(state.get('next_cursor') or {})
        seen_pages = set()
        for _ in range(1000 if getattr(self, '_continuous', False) else 2):
            rows, completed, counted = None, [], False
            pending = list(state.get('pending_details', []))
            try:
                if pending:
                    # Retry retained real records before fetching a changing head.
                    # No cursor can pass an unresolved IO record on resume.
                    state['pending_details'] = pending
                    await self._decode_pending(out, client, address, pending, completed)
                    state['observed_record_keys'] = list(dict.fromkeys(state.get('observed_record_keys', []) + completed))
                    if pending:
                        state.update(exhausted=False, stop_reason='pending_details_on_current_page')
                        return
                before = cursor.get('before')
                if before is not None and integer(before) is None:
                    raise ValueError('Malformed source before-height cursor')
                params = {'limit': self.PAGE_SIZE, 'txlimit': 1000}
                if before is not None:
                    params['before'] = before
                data = await self._get(client, f'/addrs/{address}/full', params)
                if not isinstance(data, dict) or data.get('address') != address or not isinstance(data.get('txs'), list):
                    raise ValueError('Malformed BlockCypher address response')
                if 'hasMore' in data and type(data['hasMore']) is not bool:
                    raise ValueError('Malformed provider hasMore flag')
                rows = data['txs']
                mark = digest(rows)
                if rows and mark in seen_pages:
                    raise ValueError('Repeated provider page')
                seen_pages.add(mark)
                self._account(out, address, data)
                pending = [{'tx_hash': tx_hash(row.get('hash')) if isinstance(row, dict) else None,
                            'provider_record': row, 'reason': 'Not decoded yet'} for row in rows]
                state['pending_details'] = pending
                await self._decode_pending(out, client, address, pending, completed)
                state['observed_record_keys'] = list(dict.fromkeys(state.get('observed_record_keys', []) + completed))
                if pending:
                    observe_page(state, rows, cursor, exhausted=False, stop_reason='pending_details_on_current_page')
                    counted = True
                    return
                # BlockCypher documents absent hasMore as EOF. A short page or
                # safety ceiling alone is never treated as exhaustion.
                eof = not data.get('hasMore', False)
                overlap = known is not None and any(key in known for key in completed)
                heights = [row['block_height'] for row in rows if isinstance(row, dict) and integer(row.get('block_height')) is not None]
                next_cursor = {'before': min(heights)} if heights else None
                if not eof and (not next_cursor or (before is not None and next_cursor['before'] >= before)):
                    observe_page(state, rows, cursor, exhausted=False, stop_reason='missing_or_nonadvancing_confirmed_height')
                    counted = True
                    out.errors.append(f'{self.name}: hasMore without safe confirmed-height cursor')
                    return
                observe_page(state, rows, None if eof else next_cursor, exhausted=eof or overlap,
                    stop_reason='endpoint_exhausted' if eof else 'overlap_stored_history' if overlap else None)
                counted = True
                if eof or overlap:
                    return
                cursor = next_cursor
            except asyncio.CancelledError:
                state['observed_record_keys'] = list(dict.fromkeys(state.get('observed_record_keys', []) + completed))
                if rows is not None and not counted:
                    observe_page(state, rows, cursor, exhausted=False, stop_reason='session_stopped_or_deadline')
                state.update(next_cursor=cursor, exhausted=False, stop_reason='session_stopped_or_deadline', pending_details=pending)
                raise
            except Exception as exc:
                if rows is not None and not counted:
                    observe_page(state, rows, cursor, exhausted=False, stop_reason='provider_error')
                state.update(next_cursor=cursor, exhausted=False, stop_reason='provider_error')
                out.errors.append(f'{self.name}: account_transactions: {http_error_message(exc)}')
                return
        state.update(exhausted=False, stop_reason='page_safety_ceiling')

    async def fetch(self, address):
        self._requests, self._contexts, self._emitted, self._io_progress = 0, [], set(), {}
        out = AddressReport(target_address=address, detected_chains=[self.chain], sources_used=[self.name])
        self._partial_report = out
        resume = getattr(self, '_resume_state', {})
        main = stream_state(out, self.name, 'account_transactions', resume=resume.get('account_transactions'), record_type='account_transactions')
        cancelled = False
        try:
            async with create_async_client(self._timeout) as client:
                old_head = resume.get('account_transactions_refresh', {})
                if getattr(self, '_incremental', False) or (old_head and not old_head.get('exhausted')):
                    head = stream_state(out, self.name, 'account_transactions_refresh',
                        resume=old_head if old_head and not old_head.get('exhausted') else {}, record_type='account_transactions')
                    await self._window(out, client, address, head, set(main.get('observed_record_keys', [])))
                    if not head.get('exhausted'):
                        return out
                    main['observed_record_keys'] = list(dict.fromkeys(main.get('observed_record_keys', []) + head.get('observed_record_keys', [])))
                    if head.get('stop_reason') == 'endpoint_exhausted':
                        main.update(exhausted=True, stop_reason='fresh_history_endpoint_exhausted')
                await self._window(out, client, address, main)
        except asyncio.CancelledError:
            cancelled = True
            raise
        finally:
            streams = out.collection_audit.get('streams', {}).get(self.name, {})
            pending_count = sum(len(state.get('pending_details', [])) for state in streams.values())
            reasons = sorted({state.get('stop_reason', 'unknown') for state in streams.values()})
            out.coverage[self.name] = {'history_complete': False, 'partial': True,
                'requests_admitted': self._requests, 'pending_detail_count': pending_count,
                'stop_reasons': reasons, 'cancelled': cancelled, 'unresolved_address_contexts': self._contexts,
                'provider_history_limit': 'bounded public pages; endpoint exhaustion is not full-chain completeness',
                'same_block_pagination': 'documented full endpoint includes entire boundary block; cursor=min confirmed height',
                'rate_limit_scope': 'process admission guard; remote 429 authoritative, no quota shared across processes assumed',
                'aggregate_totals': 'provider-scoped; no merging gross received/sent totals'}
            status = 'error' if out.errors and not (out.transactions or out.balances) else 'partial'
            out.source_health.append(SourceHealth(source=self.name, status=status, timeout_seconds=self._timeout,
                retry_strategy='replay unresolved source page, bounded free-tier admission and Retry-After',
                details=f'{len(out.transactions)} decoded TX; {pending_count} pending details; partial public coverage'))
        return out


class BitcoinBlockCypherSource(BlockCypherPublicSource):
    def __init__(self, timeout_seconds):
        super().__init__(timeout_seconds, chain='btc')


class DogecoinBlockCypherSource(BlockCypherPublicSource):
    def __init__(self, timeout_seconds):
        super().__init__(timeout_seconds, chain='doge')
