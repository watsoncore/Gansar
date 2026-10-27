"""Two verified public Blockscout instances; no ownership inference or new chain.

Original wire rows remain provider_record. Internal calls are retained as scoped
context until a cross-provider trace identity is established, never as extra TXs.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal, localcontext
import hashlib
import json
import re
import time
from weakref import WeakKeyDictionary

import httpx

from app.aggregator.collection_audit import observe_page, stream_state
from app.attribution.normalize import canonical_address
from app.models.report import AddressReport, SourceHealth, Transaction
from app.sources.base import Source
from app.utils.http import _retry_after_seconds, http_error_message, request_json, shared_async_client
from app.utils.event_identity import merge_provenance


_INSTANCES = {"eth": ("https://eth.blockscout.com", "ETH"),
              "optimism": ("https://explorer.optimism.io", "ETH")}
_GATES = WeakKeyDictionary()
_HASH = re.compile(r"0x[0-9a-fA-F]{64}\Z")
_CURSOR_FIELDS = {"index", "value", "hash", "inserted_at", "block_number", "fee", "items_count",
                  "transaction_index", "transaction_hash", "log_index"}


def _uint(value, *, maximum=None):
    if type(value) is int:
        result = value
    elif isinstance(value, str) and len(value) <= 100 and value.isascii() and value.isdecimal():
        result = int(value)
    else:
        raise ValueError("Missing or invalid unsigned base-unit/index value")
    if result < 0 or maximum is not None and result > maximum:
        raise ValueError("Unsigned base-unit/index value exceeds bound")
    return result


def _stamp(value):
    if not isinstance(value, str) or len(value) > 80:
        raise ValueError("Source timestamp missing")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Source timestamp has no timezone")
    return result


def _account(value, chain):
    return canonical_address(chain, value.get("hash") if isinstance(value, dict) else value)


def _next_cursor(value):
    if value is None:
        return None
    if not isinstance(value, dict) or not value or not set(value) <= _CURSOR_FIELDS:
        raise ValueError("Unsupported Blockscout next_page_params")
    for key, item in value.items():
        if key in {"hash", "transaction_hash"}:
            if not isinstance(item, str) or not _HASH.fullmatch(item):
                raise ValueError("Invalid cursor hash")
        elif key == "inserted_at":
            _stamp(item)
        else:
            _uint(item, maximum=100 if key == "items_count" else None)
    return dict(value)


def _row_key(kind, row):
    tx_hash = row.get("hash") if kind == "transactions" else row.get("transaction_hash")
    if not isinstance(tx_hash, str) or not _HASH.fullmatch(tx_hash):
        return ""
    if kind == "transactions":
        return tx_hash.lower()
    try:
        return tx_hash.lower() + ":log:" + str(_uint(row.get("log_index")))
    except ValueError:
        return ""


class EvmBlockscoutSource(Source):
    def __init__(self, timeout_seconds: float, chain: str = "eth"):
        if chain not in _INSTANCES:
            raise ValueError("Only separately verified Ethereum and OP Mainnet instances are supported")
        self.chain = chain
        self.name = "blockscout_" + chain
        self._host, self._asset = _INSTANCES[chain]
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=[self.chain], sources_used=[self.name])
        self._partial_report = out
        self._blocked = False
        target = canonical_address(self.chain, address)
        if target is None:
            out.errors.append(f"{self.name}: invalid EVM address")
            return out
        out.warnings.append(f"{self.name}: public legacy instance; API migration and indexer limits may restrict history; no completeness guarantee")
        try:
            async with shared_async_client(min(self._timeout, 12.0)) as client:
                await asyncio.gather(self._history(client, target, out, "transactions"),
                                     self._history(client, target, out, "token-transfers"),
                                     self._internal_context(client, target, out))
        except asyncio.CancelledError:
            self._health(out, "partial", "Collection deadline or cancellation; existing cursors and records retained")
            raise
        self._health(out, "partial" if out.transactions else "unavailable" if out.errors else "empty",
                     "Only returned indexed rows retained; native and ERC20 separate; internal calls are context only")
        return out

    def _health(self, out, status, detail):
        out.source_health.append(SourceHealth(source=self.name, status=status, timeout_seconds=self._timeout,
            retry_strategy="shared cache; host serialized; >=0.35s; bounded Retry-After; existing global deadline", details=detail, partial=True))

    async def _get(self, client, endpoint, out, params=None):
        gates = _GATES.setdefault(asyncio.get_running_loop(), {})
        gate = gates.setdefault(self._host, {"lock": asyncio.Lock(), "ready": 0.0})
        for attempt in range(2):
            async with gate["lock"]:
                if self._blocked:
                    return None
                delay = gate["ready"] - time.monotonic()
                if delay > self._timeout:
                    self._health(out,"rate_limited","Provider cooldown exceeds this request budget; no early retry issued")
                    return None
                if delay > 0:
                    await asyncio.sleep(delay)
                try:
                    gate["ready"] = time.monotonic() + .35
                    data = await request_json(client, "GET", self._host + endpoint, params=params, retries=0)
                    if not isinstance(data, dict):
                        raise ValueError("Blockscout response is not an object")
                    if data.get("error") or data.get("message") == "Forbidden":
                        raise ValueError("Blockscout returned an API error")
                    return data
                except asyncio.CancelledError:
                    raise
                except httpx.HTTPStatusError as exc:
                    status = exc.response.status_code
                    if status == 429:
                        wait = _retry_after_seconds(exc.response)
                        gate["ready"] = max(gate["ready"], time.monotonic() + (wait if wait is not None else 5.0))
                        self._health(out, "rate_limited", "HTTP 429; provider Retry-After retained; available sources remain usable")
                        if gate["ready"]-time.monotonic()>self._timeout:
                            self._blocked=True
                            out.errors.append(f"{self.name}: rate_limited: Retry-After exceeds this request budget")
                            return None
                        if attempt == 0:
                            continue
                    if status in {401, 402, 403, 429}:
                        self._blocked = True
                    out.errors.append(f"{self.name}: {http_error_message(exc)}")
                    return None
                except (httpx.HTTPError, ValueError) as exc:
                    out.errors.append(f"{self.name}: {http_error_message(exc)}")
                    return None
        return None

    async def _history(self, client, address, out, kind):
        resume = getattr(self, "_resume_state", {})
        state = stream_state(out, self.name, kind, resume=resume.get(kind), record_type=kind)
        state.update(history_complete=False, completeness_scope="Provider cursor exhaustion only, not independently established complete chain history")
        known = set(state.get("observed_record_keys", []))
        head_name = kind + "_refresh"
        old_head = resume.get(head_name, {})
        if getattr(self, "_incremental", False) or old_head and not old_head.get("exhausted"):
            head = stream_state(out, self.name, head_name,
                                resume=old_head if old_head and not old_head.get("exhausted") else {}, record_type=kind)
            await self._window(client, address, out, kind, head, known)
            state["observed_record_keys"] = list(dict.fromkeys(state.get("observed_record_keys", []) + head.get("observed_record_keys", [])))
        if not state.get("exhausted"):
            await self._window(client, address, out, kind, state)

    async def _window(self, client, address, out, kind, state, known=None):
        cursor = state.get("next_cursor") or {}
        seen_pages, seen_cursors = set(), set()
        recorded = set(state.get("observed_record_keys", []))
        for _ in range(1000 if getattr(self, "_continuous", False) else 1):
            if len(out.transactions) >= 100_000:
                state["stop_reason"] = "operation_memory_safety_ceiling"
                return
            params = {"type": "ERC-20", **cursor} if kind == "token-transfers" else cursor
            try:
                response = await self._get(client, f"/api/v2/addresses/{address}/{kind}", out, params)
                if response is None:
                    state["stop_reason"] = "provider_error"
                    return
                rows = response.get("items")
                if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                    raise ValueError("Blockscout items is missing or malformed")
                next_cursor = _next_cursor(response.get("next_page_params"))
            except asyncio.CancelledError:
                state["stop_reason"] = "session_stopped_or_deadline"
                raise
            except (ValueError, TypeError) as exc:
                state["stop_reason"] = "malformed_page"
                if isinstance(locals().get("response"), dict):
                    state["pending_provider_page"] = response
                out.errors.append(f"{self.name}: {kind}: {exc}")
                return
            digest = hashlib.sha256(json.dumps(rows, sort_keys=True, default=str).encode()).hexdigest()
            if rows and digest in seen_pages:
                state["stop_reason"] = "repeated_page"
                return
            seen_pages.add(digest)
            keys = [_row_key(kind, row) for row in rows]
            overlap = known is not None and any(key and key in known for key in keys)
            observe_page(state, rows, next_cursor, exhausted=next_cursor is None or overlap,
                         stop_reason="overlap_stored_history" if overlap else None)
            for key in keys:
                if key and key not in recorded:
                    state.setdefault("observed_record_keys", []).append(key)
                    recorded.add(key)
            unparsed = []
            for row in rows:
                try:
                    tx = self._native(row, address) if kind == "transactions" else self._token(row, address)
                    if tx is not None:
                        out.transactions.append(tx)
                except (ValueError, TypeError, OverflowError, KeyError) as exc:
                    unparsed.append({"provider_record":row,"error":str(exc)})
                    out.errors.append(f"{self.name}: {kind}_parse: {exc}")
            if unparsed:
                state.update(exhausted=False,next_cursor=cursor,stop_reason="unparsed_provider_records",
                             pending_provider_page=response,unparsed_provider_records=unparsed)
                return
            state.pop("pending_provider_page",None)
            state.pop("unparsed_provider_records",None)
            if next_cursor is None or overlap:
                return
            encoded = json.dumps(next_cursor, sort_keys=True)
            if not rows or encoded in seen_cursors or next_cursor == cursor:
                state.update(exhausted=False, stop_reason="repeated_or_missing_cursor")
                return
            seen_cursors.add(encoded)
            cursor = next_cursor
        state["stop_reason"] = "page_safety_ceiling" if getattr(self, "_continuous", False) else "legacy_page_limit"

    def _direction(self, target, frm, to):
        return "self" if target == frm == to else "out" if target == frm else "in" if target == to else "unknown"

    def _native(self, row, address):
        tx_hash = row.get("hash")
        if not isinstance(tx_hash, str) or not _HASH.fullmatch(tx_hash):
            raise ValueError("Native transaction hash missing")
        frm, to = _account(row.get("from"), self.chain), _account(row.get("to"), self.chain)
        if address not in {frm, to}:
            raise ValueError("Native transaction does not involve the target")
        units = _uint(row.get("value"))
        success = True if row.get("status") == "ok" else False if row.get("status") in {"error", "reverted"} else None
        kind = "contract_call" if row.get("raw_input") not in {None, "", "0x"} or units == 0 else "transfer"
        return Transaction(chain=self.chain, tx_hash=tx_hash, timestamp=_stamp(row.get("timestamp")),
            from_address=frm, to_address=to, amount_base_units=units, decimals=18,
            amount=float(Decimal(units).scaleb(-18)), asset=self._asset, success=success,
            direction=self._direction(address, frm, to), source=self.name, url=f"{self._host}/tx/{tx_hash}",
            raw={"provider":self.name, "provider_record":row, "type":kind, "input":row.get("raw_input"),
                 "status":row.get("status"), "block_number":row.get("block_number"), "source_amount_unit":"wei"})

    def _token(self, row, address):
        token, total = row.get("token"), row.get("total")
        if not isinstance(token, dict) or token.get("type") != "ERC-20":
            return None
        if not isinstance(total, dict):
            raise ValueError("ERC20 source amount missing")
        tx_hash = row.get("transaction_hash")
        if not isinstance(tx_hash, str) or not _HASH.fullmatch(tx_hash):
            raise ValueError("ERC20 transaction hash missing")
        frm, to = _account(row.get("from"), self.chain), _account(row.get("to"), self.chain)
        contract = canonical_address(self.chain, token.get("address_hash"))
        if not frm or not to or not contract or address not in {frm, to}:
            raise ValueError("ERC20 source parties/contract missing or not scoped to target")
        units, decimals = _uint(total.get("value")), _uint(token.get("decimals"), maximum=36)
        if total.get("decimals") is not None and _uint(total["decimals"], maximum=36) != decimals:
            raise ValueError("ERC20 source decimal fields disagree")
        index = _uint(row.get("log_index"))
        with localcontext() as ctx:
            ctx.prec=max(100,len(str(units))+decimals+2)
            exact=Decimal(units).scaleb(-decimals)
        return Transaction(chain=self.chain, tx_hash=tx_hash, timestamp=_stamp(row.get("timestamp")),
            from_address=frm, to_address=to, amount_base_units=units, decimals=decimals, amount=float(exact),
            asset=str(token.get("symbol") or "ERC20"), direction=self._direction(address, frm, to), source=self.name,
            url=f"{self._host}/tx/{tx_hash}", success=None,
            raw={"provider":self.name,"provider_record":row,"type":"erc20_transfer","asset_type":"erc20",
                 "token_contract":contract,"token_info":token,"raw_value":str(units),"decimals":decimals,
                 "log_index":str(index),"source_amount_unit":"token_base_units",
                 "execution_confirmation":"Indexed token row alone does not establish receipt execution success"})

    async def _internal_context(self, client, address, out):
        state = stream_state(out, self.name, "internal_call_observations", record_type="contract_call_context")
        state.update(history_complete=False, status="unavailable", transaction_edge=False,
                     limitation="One returned page only; call/delegatecall/value are context, not additional financial transactions")
        response = await self._get(client, f"/api/v2/addresses/{address}/internal-transactions", out)
        if response is None:
            state["stop_reason"]="provider_error"
            return
        rows=response.get("items")
        if not isinstance(rows,list) or not all(isinstance(row,dict) for row in rows):
            state["stop_reason"]="malformed_page"
            out.errors.append(f"{self.name}: internal call context: items missing")
            return
        try:cursor=_next_cursor(response.get("next_page_params"))
        except ValueError as exc:
            state["stop_reason"]="unsupported_cursor"
            out.errors.append(f"{self.name}: internal call context: {exc}")
            return
        observe_page(state,rows[:50],cursor,exhausted=cursor is None)
        state.update(status="partial", records=rows[:50], row_limit=50, source_rows=len(rows),
                     records_truncated=len(rows)>50, transaction_edge=False,
                     source_url=f"{self._host}/api/v2/addresses/{address}/internal-transactions")


def _kind(tx):
    raw=tx.raw or {}
    if tx.chain not in _INSTANCES:
        return None
    if raw.get("type") in {"internal_transfer","internal_transaction","nft_transfer"}:
        return None
    if raw.get("asset_type") == "erc20" or raw.get("token_contract"):
        return "token"
    if tx.asset == "ETH" and raw.get("type") in {"transfer","contract_call"}:
        return "native"
    return None


def _coarse_key(tx):
    if not _HASH.fullmatch(str(tx.tx_hash)):
        return None
    frm=canonical_address(tx.chain,tx.from_address)
    to=canonical_address(tx.chain,tx.to_address)
    if not frm or not to:
        return None
    raw=tx.raw or {}
    contract=canonical_address(tx.chain,raw.get("token_contract")) if _kind(tx)=="token" else None
    if _kind(tx)=="token" and not contract:
        return None
    return tx.chain,tx.tx_hash.lower(),frm,to,contract


def _token_wire(tx):
    """Exact quantity only when an original provider row independently binds it."""
    raw=tx.raw or {}; row=raw.get("provider_record")
    if not isinstance(row,dict):
        return None
    key=_coarse_key(tx)
    if not key:
        return None
    try:
        if str(tx.source).startswith("blockscout_"):
            token=row.get("token") or {};total=row.get("total") or {}
            wire=(tx.chain,str(row.get("transaction_hash","")).lower(),_account(row.get("from"),tx.chain),
                  _account(row.get("to"),tx.chain),canonical_address(tx.chain,token.get("address_hash")))
            units=_uint(total.get("value"));decimals=_uint(token.get("decimals"),maximum=36)
        elif isinstance(row.get("tokenInfo"),dict):
            token=row["tokenInfo"]
            wire=(tx.chain,str(row.get("transactionHash","")).lower(),canonical_address(tx.chain,row.get("from")),
                  canonical_address(tx.chain,row.get("to")),canonical_address(tx.chain,token.get("address")))
            units=_uint(row.get("value"));decimals=_uint(token.get("decimals"),maximum=36)
        elif row.get("contractAddress"):
            wire=(tx.chain,str(row.get("hash","")).lower(),canonical_address(tx.chain,row.get("from")),
                  canonical_address(tx.chain,row.get("to")),canonical_address(tx.chain,row.get("contractAddress")))
            units=_uint(row.get("value"));decimals=_uint(row.get("tokenDecimal"),maximum=36)
        else:
            return None
        if wire != key or tx.amount_base_units != units or tx.decimals != decimals:
            return None
        return key+(units,decimals)
    except (ValueError,TypeError):
        return None


def _known_log(tx):
    value=(tx.raw or {}).get("log_index")
    if value is None and isinstance((tx.raw or {}).get("provider_record"),dict):
        value=tx.raw["provider_record"].get("logIndex")
    try:return _uint(value)
    except ValueError:return None


def _receipt_log(tx):
    """An unindexed legacy token row joins only a unique successful retained log."""
    key=_token_wire(tx)
    if not key:
        return None
    raw=tx.raw or {};receipt=raw.get("receipt") or raw.get("rpc_receipt") or raw.get("transaction_receipt")
    if not isinstance(receipt,dict) or str(receipt.get("transactionHash","")).lower()!=key[1] or receipt.get("status") not in (1,"0x1"):
        return None
    if not isinstance(receipt.get("logs"),list):
        return None
    matches=[]
    topic="0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    for row in receipt.get("logs",[]):
        if not isinstance(row,dict) or row.get("removed") is True:
            continue
        topics=row.get("topics") or []
        if not isinstance(topics,list) or len(topics)!=3 or str(topics[0]).lower()!=topic:
            continue
        if canonical_address(tx.chain,row.get("address"))!=key[4] or str(row.get("transactionHash","")).lower()!=key[1]:
            continue
        if canonical_address(tx.chain,"0x"+str(topics[1])[-40:])!=key[2] or canonical_address(tx.chain,"0x"+str(topics[2])[-40:])!=key[3]:
            continue
        try:
            if int(row.get("data",""),16)!=key[5]:
                continue
            index=row.get("logIndex")
            matches.append(int(index,16) if isinstance(index,str) and index.startswith("0x") else _uint(index))
        except (ValueError,TypeError):
            continue
    return matches[0] if len(matches)==1 else None


def reconcile_blockscout_observations(report):
    """Source-specific overlap reconciliation before existing shared deduplication.

    Native outer transactions join by chain/hash/parties, with precise new wire
    quantity as representative. ERC20 joins require source-bound units/master/
    parties and a unique concrete log. Unresolved overlaps remain retained raw
    context and never inflate the financial operation list.
    """
    def retain_unique(previous, rows):
        seen={hashlib.sha256(json.dumps(row,sort_keys=True,default=str).encode()).hexdigest() for row in previous}
        for row in rows:
            fingerprint=hashlib.sha256(json.dumps(row,sort_keys=True,default=str).encode()).hexdigest()
            if fingerprint not in seen:
                previous.append(row)
                seen.add(fingerprint)
    original=list(report.transactions)
    positions={id(tx):index for index,tx in enumerate(original)}
    old=[tx for tx in report.transactions if not str(tx.source).startswith("blockscout_")]
    new=[tx for tx in report.transactions if str(tx.source).startswith("blockscout_")]
    if not new:
        return {"status":"not_needed"}
    by_coarse={}
    for tx in old:
        if key:=_coarse_key(tx):
            by_coarse.setdefault(key,[]).append(tx)
    consumed=set(); kept=[]; placements={}; pending={}; legacy_views=[]; counts={"source_rows":len(new),"native_observations_joined":0,
        "erc20_observations_joined":0,"contextual_overlaps":0,"new_financial_records":0}
    grouped={}
    for tx in new:
        key=_coarse_key(tx)
        # An unknown/missing party is not a common physical identity: preserve
        # distinct genuine contract-creation TXs instead of grouping None keys.
        physical=(key if key is not None else ("unresolved",tx.chain,tx.tx_hash,tx.from_address,tx.to_address),_kind(tx),_known_log(tx))
        grouped.setdefault(physical,[]).append(tx)
    for (key,kind,index),observations in grouped.items():
        tx=observations[0]
        legacy=[row for row in by_coarse.get(key,[]) if id(row) not in consumed and _kind(row)==kind]
        exact=_token_wire(tx) if kind=="token" else None
        quantity_conflict=any((other.amount_base_units,other.decimals,other.success)!=(tx.amount_base_units,tx.decimals,tx.success) for other in observations)
        joins=[];reason=None
        if quantity_conflict:
            reason="Conflicting quantities for the same Blockscout physical identity; no representative selected"
        elif kind=="native":
            if any(row.amount_base_units is not None and row.amount_base_units!=tx.amount_base_units for row in legacy):
                reason="Native quantity conflicts with retained exact base-unit observation"
            elif any(row.success is not None and tx.success is not None and row.success != tx.success for row in legacy):
                reason="Native execution status conflicts with retained observation"
            else:
                joins=legacy
        elif kind=="token" and legacy:
            same_wire=[row for row in legacy if _token_wire(row)==exact and exact is not None]
            for row in same_wire:
                legacy_index=_known_log(row)
                if legacy_index is None:
                    legacy_index=_receipt_log(row)
                if legacy_index==index:
                    joins.append(row)
            unresolved=[row for row in legacy if row not in joins and _known_log(row) is None]
            if unresolved:
                reason="Legacy ERC20 observation lacks an unambiguous concrete log; new exact log retained as context"
                joins=[]
            elif not joins and any(_known_log(row)==index for row in legacy):
                reason="ERC20 same-index source quantity/contract conflict"
        if reason:
            state=pending.setdefault(tx.source,[])
            state.extend({"reason":reason,"transaction_edge":False,"observation":row.model_dump(mode="json")} for row in observations)
            counts["contextual_overlaps"]+=len(observations)
            continue
        representative=joins[0] if kind=="token" and joins else tx
        # Existing inference intentionally consumes the representative raw, not
        # every provenance entry. A receipt-bound legacy ERC20 record remains
        # representative so its already established service proofs are preserved.
        for other in joins:
            legacy_views.append({"kind":"retained_legacy_normalized_view","transaction_edge":False,
                "source":other.source,"tx_hash":other.tx_hash,"event_id":other.event_id,"asset":other.asset,
                "raw":deepcopy(other.raw),"note":"Original normalized source union, not asserted to be a separate wire response"})
        for other in [*observations,*joins]:
            if other is not representative:
                merge_provenance(representative,other)
        for other in joins:
            consumed.add(id(other))
        counts["native_observations_joined" if kind=="native" else "erc20_observations_joined"]+=len(joins)
        counts["new_financial_records"]+=not joins
        kept.append(representative)
        placements[min(positions[id(row)] for row in [*observations,*joins])]=representative
    new_ids={id(tx) for tx in new}
    report.transactions=[]
    for index,tx in enumerate(original):
        if index in placements:
            report.transactions.append(placements[index])
        if id(tx) not in consumed and id(tx) not in new_ids:
            report.transactions.append(tx)
    for source,rows in pending.items():
        state=stream_state(report,source,"unresolved_overlap_context",record_type="source_observation_context")
        previous=state.get("records",[])
        retain_unique(previous,rows)
        state.update(status="partial",history_complete=False,transaction_edge=False,records=previous,stop_reason="unresolved_cross_provider_identity")
        warning=f"{source}: overlapping observations retained as context because a concrete cross-provider identity could not be established"
        if warning not in report.warnings:
            report.warnings.append(warning)
    if legacy_views:
        state=stream_state(report,"blockscout_reconciliation","legacy_normalized_views",record_type="normalized_view_context")
        retain_unique(state.setdefault("records",[]),legacy_views)
        state.update(transaction_edge=False,history_complete=False)
    contextual_total=sum(len(states.get("unresolved_overlap_context",{}).get("records",[]))
        for source,states in report.collection_audit.get("streams",{}).items() if str(source).startswith("blockscout_"))
    counts.update(status="partial" if contextual_total else "ok",financial_records_after=len(report.transactions),contextual_overlaps_total=contextual_total,
                  limitation="Contextual rows retain genuine operations; unresolved source identity is not evidence of no transfer")
    state=stream_state(report,"blockscout_reconciliation","summary",record_type="source_overlap_reconciliation")
    state.update(counts)
    return counts
