from __future__ import annotations

from app.sources.pagination import pages
from app.aggregator.collection_audit import stream_state

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from app.models.report import AddressReport, Balance, SourceHealth, TokenHolding, Transaction
from app.sources.base import Source
from app.utils.detect import is_solana_address, looks_like_solana_address
from app.utils.http import create_async_client, http_error_message, json_list, json_object

logger = logging.getLogger(__name__)

LAMPORTS_PER_SOL = 1_000_000_000
SPL_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
SOLANA_EXPLORER_ACCOUNT = "https://solscan.io/account/{address}"
SOLANA_EXPLORER_TX = "https://solscan.io/tx/{signature}"


def _dt(value: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc) if value else None
    except Exception:
        return None


def _float(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except Exception:
        return None


def _amount(raw_amount: Any, decimals: Any, ui_amount: Any = None) -> float | None:
    ui = _float(ui_amount)
    if ui is not None:
        return ui
    try:
        dec = int(decimals or 0)
        return float(raw_amount or 0) / (10 ** dec)
    except Exception:
        return None


def _rpc_result(payload: dict) -> Any:
    if not isinstance(payload, dict):
        return None
    return payload.get("result")


def _short_list(values: list[str], limit: int = 16) -> list[str]:
    return list(dict.fromkeys([str(item) for item in values if item]))[:limit]


def _message(tx: dict) -> dict:
    return json_object(json_object(tx.get("transaction")).get("message"))


def _account_key_value(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("pubkey") or "")
    return str(item or "")


def _account_keys(tx: dict) -> list[str]:
    return [_account_key_value(item) for item in json_list(_message(tx).get("accountKeys")) if _account_key_value(item)]


def _signers(tx: dict) -> list[str]:
    out = []
    for item in json_list(_message(tx).get("accountKeys")):
        if isinstance(item, dict) and item.get("signer"):
            out.append(str(item.get("pubkey") or ""))
    return _short_list(out)


def _iter_instructions(tx: dict) -> list[dict]:
    result = []
    msg = _message(tx)
    result.extend([item for item in json_list(msg.get("instructions")) if isinstance(item, dict)])
    for inner in json_list(json_object(tx.get("meta")).get("innerInstructions")):
        result.extend([item for item in json_list(json_object(inner).get("instructions")) if isinstance(item, dict)])
    return result


def _program_ids(tx: dict) -> list[str]:
    out = []
    keys = _account_keys(tx)
    for item in _iter_instructions(tx):
        program_id = str(item.get("programId") or "")
        if not program_id and item.get("programIdIndex") is not None:
            try:
                program_id = keys[int(item.get("programIdIndex"))]
            except Exception:
                program_id = ""
        if program_id:
            out.append(program_id)
    return _short_list(out, 24)


def _instruction_summary(tx: dict) -> list[str]:
    out = []
    for item in _iter_instructions(tx):
        parsed = item.get("parsed") if isinstance(item.get("parsed"), dict) else {}
        program = str(item.get("program") or "")
        typ = str(parsed.get("type") or item.get("type") or "")
        label = ":".join(part for part in (program, typ) if part)
        if label:
            out.append(label)
    return _short_list(out, 12)


def _token_balance_owners(tx: dict) -> dict[tuple[str, str], str]:
    owners: dict[tuple[str, str], str] = {}
    keys = _account_keys(tx)
    meta = json_object(tx.get("meta"))
    for section in ("preTokenBalances", "postTokenBalances"):
        for item in json_list(meta.get(section)):
            item = json_object(item)
            owner = str(item.get("owner") or "")
            mint = str(item.get("mint") or "")
            account_index = item.get("accountIndex")
            account = ""
            try:
                account = keys[int(account_index)]
            except Exception:
                account = ""
            if owner and account and mint:
                owners[(account, mint)] = owner
    return owners


def _extract_transfers(tx: dict, address: str) -> list[dict]:
    transfers = []
    token_owners = _token_balance_owners(tx)
    for instruction_index, item in enumerate(_iter_instructions(tx)):
        parsed = item.get("parsed") if isinstance(item.get("parsed"), dict) else {}
        info = json_object(parsed.get("info"))
        typ = str(parsed.get("type") or "").lower()
        program = str(item.get("program") or "").lower()
        if program == "system" and typ in {"transfer", "transferwithseed"}:
            source = str(info.get("source") or "")
            destination = str(info.get("destination") or "")
            lamports = _float(info.get("lamports"))
            if not source and not destination:
                continue
            direction = "unknown"
            if source == address and destination == address:
                direction = "self"
            elif source == address:
                direction = "out"
            elif destination == address:
                direction = "in"
            transfers.append(
                {
                    "type": "sol_transfer",
                    "from": source or None,
                    "to": destination or None,
                    "amount": (lamports / LAMPORTS_PER_SOL) if lamports is not None else None,
                    "asset": "SOL",
                    "direction": direction,
                    "raw": {"instruction_index": instruction_index, "instruction": parsed, "program": program},
                }
            )
            continue
        if program in {"spl-token", "spl-token-2022"} and typ in {"transfer", "transferchecked"}:
            mint = str(info.get("mint") or "")
            token_amount = json_object(info.get("tokenAmount"))
            amount = _amount(token_amount.get("amount") or info.get("amount"), token_amount.get("decimals") or info.get("decimals"), token_amount.get("uiAmount") or token_amount.get("uiAmountString"))
            source_account = str(info.get("source") or "")
            destination_account = str(info.get("destination") or "")
            source_owner = str(info.get("authority") or info.get("owner") or token_owners.get((source_account, mint), "") or source_account)
            destination_owner = str(token_owners.get((destination_account, mint), "") or destination_account)
            direction = "unknown"
            if source_owner == address and destination_owner == address:
                direction = "self"
            elif source_owner == address:
                direction = "out"
            elif destination_owner == address:
                direction = "in"
            transfers.append(
                {
                    "type": "spl_transfer",
                    "from": source_owner or source_account or None,
                    "to": destination_owner or destination_account or None,
                    "amount": amount,
                    "asset": mint or "SPL",
                    "direction": direction,
                    "mint": mint,
                    "raw": {"instruction_index": instruction_index, "instruction": parsed, "program": program, "source_account": source_account, "destination_account": destination_account},
                }
            )
    return transfers


class SolscanPublicApiSource(Source):
    name = "solscan_public_api"
    chain = "solana"

    def __init__(self, timeout_seconds: float):
        self._timeout = timeout_seconds

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["solana"], sources_used=[self.name])
        self._partial_report = out
        self._history_paused = False
        self._rpc_requests = 0
        if not looks_like_solana_address(address) or not is_solana_address(address):
            out.warnings.append("solana: invalid address")
            out.source_health.append(SourceHealth(source=self.name, status="error", timeout_seconds=self._timeout, retry_strategy="format validation", details="invalid address"))
            return out
        out.solana = {
            "address": address,
            "explorer_links": {
                "solscan": SOLANA_EXPLORER_ACCOUNT.format(address=address),
                "solana_explorer": f"https://explorer.solana.com/address/{address}",
            },
            "sources": [self.name],
            "warnings": [f"{self.name}: public api unavailable; explorer link available"],
            "partial": True,
        }
        out.warnings.append(f"{self.name}: public api unavailable; explorer link available")
        out.source_health.append(SourceHealth(source=self.name, status="skipped", timeout_seconds=self._timeout, retry_strategy="manual explorer fallback", details="public api unavailable; explorer link available"))
        return out


class SolanaRpcSource(Source):
    name = "solana_rpc"
    chain = "solana"

    def __init__(self, timeout_seconds: float, rpc_url: str = "https://api.mainnet-beta.solana.com"):
        self._timeout = timeout_seconds
        self._rpc = rpc_url

    async def fetch(self, address: str) -> AddressReport:
        out = AddressReport(target_address=address, detected_chains=["solana"], sources_used=[self.name])
        self._partial_report = out
        self._history_paused = False
        self._rpc_requests = 0
        if not looks_like_solana_address(address) or not is_solana_address(address):
            out.warnings.append("solana: invalid address")
            self._health(out, "error", "invalid address")
            return out
        async with create_async_client(min(self._timeout, 10.0)) as client:
            balance = await self._rpc_call(client, "getBalance", [address], out, "balance")
            account = await self._rpc_call(client, "getAccountInfo", [address, {"encoding": "jsonParsed", "commitment": "confirmed"}], out, "account_info")
            token_accounts = await self._rpc_call(
                client,
                "getTokenAccountsByOwner",
                [address, {"programId": SPL_TOKEN_PROGRAM}, {"encoding": "jsonParsed", "commitment": "confirmed"}],
                out,
                "token_accounts",
            )
            token_map = self._parse_token_accounts(address, token_accounts, out)
            self._parse_account(address, balance, account, [], out)
            pending = getattr(self, "_resume_state", {}).get("account_signatures", {}).get("pending_details", [])
            if pending:
                await self._parse_transactions(client, address, pending, token_map, out)
            async def fetch(cursor):
                options = {"limit": 50}
                if cursor.get("before"):
                    options["before"] = cursor["before"]
                return await self._rpc_call(client, "getSignaturesForAddress", [address, options], out, "signatures")
            def advance(data, items, cursor):
                return {"before": items[-1].get("signature")} if items else None
            async for signatures in pages(self, out, "account_signatures", fetch, lambda data: _rpc_result(data), advance, page_size=50):
                sig_items = json_list(_rpc_result(signatures))
                await self._parse_transactions(client, address, sig_items, token_map, out)
                if self._history_paused:
                    break
        self._refresh_state(out)
        if not any(item.source == self.name for item in out.source_health):
            produced = bool(out.balances or out.transactions or out.tokens or out.solana.get("account"))
            self._health(out, "partial" if out.errors or out.warnings else "ok" if produced else "partial", "partial data collected" if out.errors or out.warnings or not produced else "address data collected")
        return out

    async def _rpc_call(self, client: httpx.AsyncClient, method: str, params: list, out: AddressReport, label: str) -> dict:
        self._rpc_requests = getattr(self, "_rpc_requests", 0) + 1
        if self._rpc_requests > 1500:
            self._history_paused = True
            out.warnings.append(f"{self.name}: request safety ceiling; pending signatures retained")
            return {}
        try:
            response = await client.post(self._rpc, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
            if response.status_code == 429:
                self._history_paused = True
                out.warnings.append(f"{self.name}: {label}: rate_limited: http 429")
                self._health(out, "rate_limited", f"{label}: http 429")
                return {}
            if response.status_code >= 400:
                out.errors.append(f"{self.name}: {label}: http {response.status_code}")
                return {}
            payload = json_object(response.json())
            rpc_error = json_object(payload.get("error"))
            if rpc_error:
                code = rpc_error.get("code")
                message = str(rpc_error.get("message") or "rpc error")
                if code == 429 or "too many requests" in message.lower():
                    out.warnings.append(f"{self.name}: {label}: rate_limited")
                    self._health(out, "rate_limited", f"{label}: rate_limited")
                else:
                    out.warnings.append(f"{self.name}: {label}: {message[:120]}")
                return {}
            return payload
        except httpx.TimeoutException:
            out.errors.append(f"{self.name}: {label}: timeout")
            self._health(out, "timeout", f"{label}: timeout")
            return {}
        except Exception as exc:
            out.errors.append(f"{self.name}: {label}: {http_error_message(exc)}")
            return {}

    def _parse_account(self, address: str, balance_payload: dict, account_payload: dict, sig_items: list, out: AddressReport) -> None:
        balance_result = json_object(_rpc_result(balance_payload))
        lamports = balance_result.get("value")
        lamports_float = _float(lamports)
        if lamports_float is not None:
            out.balances.append(
                Balance(
                    chain="solana",
                    address=address,
                    asset="SOL",
                    amount=lamports_float / LAMPORTS_PER_SOL,
                    source=self.name,
                    url=SOLANA_EXPLORER_ACCOUNT.format(address=address),
                    raw={"lamports": int(lamports_float), "rpc": self._rpc},
                )
            )
        account = json_object(json_object(_rpc_result(account_payload)).get("value"))
        parsed_data = json_object(account.get("data"))
        account_data = {
            "lamports": lamports,
            "balance": None if lamports_float is None else lamports_float / LAMPORTS_PER_SOL,
            "owner_program": account.get("owner"),
            "parsed_info": json_object(json_object(parsed_data.get("parsed")).get("info")),
            "rpc": self._rpc,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "executable": account.get("executable"),
            "rent_epoch": account.get("rentEpoch"),
            "space": account.get("space") or parsed_data.get("space"),
            "account_type": json_object(parsed_data.get("parsed")).get("type") or parsed_data.get("program") or "system" if account else "not_found",
        }
        timestamps = [_dt(item.get("blockTime")) for item in sig_items if isinstance(item, dict)]
        timestamps = [item for item in timestamps if item]
        data = dict(out.solana or {})
        data.update(
            {
                "address": address,
                "lamports": lamports,
                "balance": account_data["balance"],
                "account": account_data,
                "tx_count": len(sig_items),
                "signature_count": len(sig_items),
                "tx_count_sample": True,
                "first_seen": min(timestamps) if timestamps else None,
                "last_seen": max(timestamps) if timestamps else None,
                "explorer_links": {
                    **dict(data.get("explorer_links") or {}),
                    "solscan": SOLANA_EXPLORER_ACCOUNT.format(address=address),
                    "solana_explorer": f"https://explorer.solana.com/address/{address}",
                },
                "sources": list(dict.fromkeys(list(data.get("sources") or []) + [self.name])),
            }
        )
        out.solana = data

    def _parse_token_accounts(self, address: str, payload: dict, out: AddressReport) -> dict[str, dict]:
        token_accounts: dict[str, dict] = {}
        values = json_list(json_object(_rpc_result(payload)).get("value"))
        for item in values:
            item = json_object(item)
            pubkey = str(item.get("pubkey") or "")
            account = json_object(item.get("account"))
            data = json_object(account.get("data"))
            parsed = json_object(data.get("parsed"))
            info = json_object(parsed.get("info"))
            token_amount = json_object(info.get("tokenAmount"))
            mint = str(info.get("mint") or "")
            decimals = token_amount.get("decimals")
            raw_amount = token_amount.get("amount")
            amount = _amount(raw_amount, decimals, token_amount.get("uiAmount") or token_amount.get("uiAmountString"))
            if not mint:
                continue
            token_accounts[pubkey] = {"mint": mint, "owner": info.get("owner") or address, "amount": amount, "decimals": decimals}
            if amount in (None, 0):
                continue
            asset_type = "solana_nft" if str(raw_amount) == "1" and int(decimals or 0) == 0 else "spl_token"
            out.tokens.append(
                TokenHolding(
                    chain="solana",
                    address=address,
                    contract=mint,
                    symbol=None,
                    name=None,
                    amount=amount,
                    source=self.name,
                    url=f"https://solscan.io/token/{mint}",
                    raw={
                        "asset_type": asset_type,
                        "mint": mint,
                        "token_account": pubkey,
                        "owner": info.get("owner") or address,
                        "decimals": decimals,
                        "amount_raw": raw_amount,
                        "state": info.get("state"),
                        "program": data.get("program") or "spl-token",
                        "metadata_source": "solana_rpc",
                    },
                )
            )
        data = dict(out.solana or {})
        data["token_accounts"] = len(values)
        data["spl_token_count"] = sum(1 for token in out.tokens if token.chain == "solana" and token.raw.get("asset_type") == "spl_token")
        data["nft_count"] = sum(1 for token in out.tokens if token.chain == "solana" and token.raw.get("asset_type") == "solana_nft")
        out.solana = data
        return token_accounts

    async def _parse_transactions(self, client: httpx.AsyncClient, address: str, sig_items: list, token_map: dict[str, dict], out: AddressReport) -> None:
        if not sig_items:
            return
        if getattr(self, "_continuous", False):
            state = stream_state(out, self.name, "account_signatures", resume=getattr(self, "_resume_state", {}).get("account_signatures"), record_type="account_signatures")
            pending = {row["signature"]: row for row in state.get("pending_details", []) if row.get("signature")}
            pending.update({row["signature"]: row for row in sig_items if isinstance(row, dict) and row.get("signature")})
            state["pending_details"] = list(pending.values())
        for item in (sig_items if getattr(self, "_continuous", False) else sig_items[:15]):
            item = json_object(item)
            signature = str(item.get("signature") or "")
            if not signature:
                continue
            tx_detail = {} if getattr(self, "_history_paused", False) else await self._rpc_call(client, "getTransaction", [signature, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 1, "commitment": "confirmed"}], out, "transaction")
            tx = json_object(_rpc_result(tx_detail))
            if getattr(self, "_continuous", False):
                state = stream_state(out, self.name, "account_signatures", resume=getattr(self, "_resume_state", {}).get("account_signatures"), record_type="account_signatures")
                pending = {row["signature"]: row for row in state.get("pending_details", []) if row.get("signature")}
                if tx:
                    pending.pop(signature, None)
                else:
                    pending[signature] = item
                state["pending_details"] = list(pending.values())
            meta = json_object(tx.get("meta"))
            dt = _dt(item.get("blockTime") or tx.get("blockTime"))
            fee_lamports = _float(meta.get("fee"))
            status = "failed" if item.get("err") or meta.get("err") else str(item.get("confirmationStatus") or "confirmed")
            signers = _signers(tx)
            keys = _account_keys(tx)
            programs = _program_ids(tx)
            summary = _instruction_summary(tx)
            base_raw = {
                "type": "solana_signature",
                "slot": item.get("slot") or tx.get("slot"),
                "status": status,
                "fee": None if fee_lamports is None else fee_lamports / LAMPORTS_PER_SOL,
                "fee_lamports": fee_lamports,
                "signers": signers,
                "account_keys": _short_list(keys, 32),
                "program_ids": programs,
                "instructions_summary": summary,
                "method": ", ".join(summary[:3]),
                "source_signature_status": item, "provider_record": tx if tx else item,
                "decoded": bool(tx),
            }
            transfers = _extract_transfers(tx, address) if tx else []
            if not transfers:
                out.transactions.append(
                    Transaction(
                        chain="solana",
                        tx_hash=signature,
                        timestamp=dt,
                        from_address=None,
                        to_address=None,
                        amount=None,
                        asset="SOL",
                        direction="unknown",
                        fee=None if fee_lamports is None else fee_lamports / LAMPORTS_PER_SOL,
                        source=self.name,
                        url=SOLANA_EXPLORER_TX.format(signature=signature),
                        raw=base_raw,
                    )
                )
                continue
            for transfer in transfers:
                raw = dict(base_raw)
                raw.update(json_object(transfer.get("raw")))
                raw["type"] = transfer.get("type")
                if transfer.get("mint"):
                    raw["mint"] = transfer.get("mint")
                    raw["contract"] = transfer.get("mint")
                    if transfer.get("asset") == transfer.get("mint"):
                        token_meta = next((value for value in token_map.values() if value.get("mint") == transfer.get("mint")), {})
                        if token_meta:
                            raw["token_account_owner"] = token_meta.get("owner")
                out.transactions.append(
                    Transaction(
                        chain="solana",
                        tx_hash=signature,
                        timestamp=dt,
                        from_address=transfer.get("from"),
                        to_address=transfer.get("to"),
                        amount=transfer.get("amount"),
                        asset=transfer.get("asset") or "SOL",
                        direction=transfer.get("direction") or "unknown",
                        fee=None if fee_lamports is None else fee_lamports / LAMPORTS_PER_SOL,
                        source=self.name,
                        url=SOLANA_EXPLORER_TX.format(signature=signature),
                        raw=raw,
                    )
                )

    def _refresh_state(self, out: AddressReport) -> None:
        data = dict(out.solana or {})
        data["warnings"] = list(dict.fromkeys(list(data.get("warnings") or []) + [item for item in out.warnings if str(item).startswith(("solana:", self.name, "solscan_public_api:"))]))
        data["partial"] = bool(out.errors or out.warnings or data.get("partial"))
        data["sources"] = list(dict.fromkeys(list(data.get("sources") or []) + [self.name]))
        out.solana = data

    def _health(self, out: AddressReport, status: str, details: str) -> None:
        if any(item.source == self.name and item.status == status and item.details == details for item in out.source_health):
            return
        out.source_health.append(
            SourceHealth(
                source=self.name,
                status=status,
                timeout_seconds=self._timeout,
                retry_strategy="bounded JSON-RPC calls",
                details=details,
                partial=status != "ok",
            )
        )


__all__ = ["SolanaRpcSource", "SolscanPublicApiSource"]
