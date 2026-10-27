"""Evidence enrichment attached to AddressReport, with one caller-owned deadline.

Public upstream request limits and cancellation lifecycle are shared with the
existing providers. This module submits no messages and never loads metadata URLs.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import time
from typing import Any, Callable
from urllib.parse import quote

from app.models.report import AddressReport, Balance, SourceHealth, Transaction
from app.ton_nft.models import InvestigationBudget
from app.ton_nft.providers import BudgetExceeded, Payload, ProviderError, RequestController, TonAPIProvider, ToncenterProvider
from app.utils.event_identity import event_identity, transaction_success
from app.utils.security import sanitize_observation
from app.utils.ton_normalize import ton_canonical_address, ton_datetime
from .fingerprints import WALLET_HASHES, WALLET_SOURCE, ordinary_code_hash
from .models import AddressAttribution, AttributionEvidence, AttributionStatus, ContractDescriptor, ServiceAttribution
from .registry import OBSERVED_AT, SOURCE_SHA256, SOURCE_URL, exact_registry_labels, service_identity
from .relationships import analyze_ton_relationships
from app.attribution.provenance import compact_service_provenance
from app.attribution.wallet_extensions import (
    extension_implementation, extension_implementation_from_code, extension_wallet_from_data, decode_extension_install,
)
from app.attribution.wallet_payload import body_boc, decode_wallet_body

Progress = Callable[[dict[str, Any]], None]
LIMITATIONS = [
    "Standard wallet versions and code hashes do not identify the wallet application, device, or person.",
    "TonAPI and the Tonkeeper-maintained registry share an upstream; matching labels are not independent corroboration.",
    "Public indexer state is not a locally verified block proof. Registry labels can be stale or incorrect.",
    "Only the existing direct transaction sample and bounded counterparties are covered; absence of a label is not absence of a service relationship.",
    "No universal wallet-client identifier is present in ordinary TON transfers; TON Connect session identity is off-chain.",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id(prefix: str, value: Any) -> str:
    return prefix + hashlib.sha256(json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()


def _address(value: Any) -> str | None:
    return ton_canonical_address(value.get("address", "") if isinstance(value, dict) else value or "")


def _emit(progress: Progress | None, stage: str, **facts: Any) -> None:
    if progress:
        progress(sanitize_observation({"stage": "attribution." + stage, "timestamp": _now(), **facts}))


def _evidence(source: str, upstream: str, url: str, observed_at: str, relation: str, *,
              address: str | None = None, observation_id: str | None = None,
              transaction_hash: str | None = None, facts: dict | None = None) -> dict:
    basis = {"source": source, "url": url, "at": observed_at, "relation": relation,
             "address": address, "observation_id": observation_id, "transaction_hash": transaction_hash,
             "facts": facts or {}}
    return AttributionEvidence(evidence_id=_id("ton:evidence:", basis), source=source, upstream=upstream,
        url=url, observed_at=observed_at, relation=relation, address=address, observation_id=observation_id,
        transaction_hash=transaction_hash, facts=facts or {}).model_dump(mode="json")


def _payload_evidence(payload: Payload, observations: dict[str, dict], relation: str, address: str, facts: dict) -> dict:
    obs = observations.get(payload.observation_id, {})
    return _evidence(payload.source, payload.upstream, payload.endpoint, obs.get("collected_at") or _now(),
                     relation, address=address, observation_id=payload.observation_id, facts=facts)


def _providers(deadline: float, max_requests: int, observations: list[dict], progress: Progress | None,
               supplied: dict | None = None):
    remaining = deadline - asyncio.get_running_loop().time()
    budget = InvestigationBudget(max_requests=max(1, max_requests), max_seconds=max(1, remaining),
        request_timeout=max(1, min(7, remaining)), concurrency=2, requests_per_second=1, retries=0)
    def forward(row: dict):
        if progress:
            progress({**row, "stage": str(row["stage"]).replace("nft.", "attribution.", 1)})
    controller = RequestController(budget, lambda obs: observations.append(obs.model_dump(mode="json")), progress=forward)
    providers = supplied or {"tonapi": TonAPIProvider(use_api_keys=False), "toncenter": ToncenterProvider(use_api_keys=False)}
    for provider in providers.values():
        provider.controller = controller
    return controller, providers


async def _run_calls(calls: list[tuple[str, Any]], results: dict[str, Payload], errors: list[dict], deadline: float) -> bool:
    """Await every child, including cancellation cleanup; source errors stay observable."""
    async def one(name, callback):
        try:
            results[name] = await callback()
        except (ProviderError, BudgetExceeded) as exc:
            errors.append({"scope": name, "error": str(exc), "status": getattr(exc, "status", "budget_limit"),
                           "observation_id": getattr(exc, "observation_id", None)})
    try:
        async with asyncio.timeout_at(deadline):
            async with asyncio.TaskGroup() as group:
                for name, callback in calls:
                    group.create_task(one(name, callback))
        return False
    except TimeoutError:
        errors.append({"scope": "attribution", "status": "deadline", "error": "Caller deadline reached; pending requests cancelled and awaited."})
        return True


def _descriptor(address: str, results: dict[str, Payload], observations: list[dict], evidence: list[dict]) -> dict:
    obs = {row["observation_id"]: row for row in observations}
    account = results.get("account")
    raw = results.get("raw_contract")
    center = results.get("address_information")
    descriptor = AddressAttribution(address=address)
    states: dict[str, str] = {}
    verified_code_hashes: dict[int, str] = {}
    extension_state = None
    if account:
        data = account.data
        states[account.source] = str(data.get("status") or "unknown").lower()
        interfaces=data.get('interfaces')
        descriptor.contract.interfaces = [value for value in interfaces if isinstance(value,str)] if isinstance(interfaces,list) else []
        fact = _payload_evidence(account, obs, "account_state", address,
            {key: data.get(key) for key in ("status", "is_wallet", "interfaces", "balance", "name", "last_activity")})
        evidence.append(fact); descriptor.evidence_ids.append(fact["evidence_id"])
        descriptor.observed_at = fact["observed_at"]
    if center:
        states[center.source] = str(center.data.get("status") or "unknown").lower()
        fact = _payload_evidence(center, obs, "account_state", address,
            {key: center.data.get(key) for key in ("status", "balance", "last_transaction_lt", "last_transaction_hash")})
        evidence.append(fact); descriptor.evidence_ids.append(fact["evidence_id"])
        descriptor.observed_at = max(descriptor.observed_at or "", fact["observed_at"])
    if raw and raw.data.get("status"):
        states[raw.source] = str(raw.data["status"]).lower()
    normalized = {"uninit" if value in {"nonexist", "uninitialized", "uninit"} else value for value in states.values() if value != "unknown"}
    descriptor.account_status = next(iter(normalized)) if len(normalized) == 1 else "unknown"
    if len(normalized) > 1:
        descriptor.conflicts.append("Current account states differ across providers: " + json.dumps(states, sort_keys=True))
    for payload in (raw, center):
        if not payload or not payload.data.get("code"):
            continue
        try:
            code_hash = ordinary_code_hash(payload.data["code"])
            hash_facts = {"code_hash": code_hash, "algorithm": "TON ordinary level-zero cell representation SHA256"}
        except (ValueError, TypeError, OverflowError) as exc:
            # Keep the ordinary reader strict. Only this independently pinned,
            # exact exotic library reference has a separate bounded decoder.
            extension = extension_implementation_from_code(payload.data["code"])
            if extension is None:
                descriptor.conflicts.append(f"{payload.source}: code cell hash unavailable ({type(exc).__name__}).")
                continue
            code_hash = extension["code_hash"]
            hash_facts = {
                "code_hash": code_hash,
                "algorithm": "TON exotic library-reference level-zero cell representation SHA256",
                "code_representation": "library_reference",
                "library_code_hash": extension["library_code_hash"],
                "library_resolution_verified": False,
                "source_urls": extension["source_urls"],
                "client_application_inference": False,
            }
        descriptor.contract.code_hashes[payload.source] = code_hash
        verified_code_hashes[id(payload)] = code_hash
        fact = _payload_evidence(payload, obs, "computed_contract_code_hash", address, hash_facts)
        evidence.append(fact); descriptor.contract.evidence_ids.append(fact["evidence_id"])
    hashes = set(descriptor.contract.code_hashes.values())
    if len(hashes) == 1 and descriptor.account_status != "uninit":
        descriptor.contract.code_hash = next(iter(hashes))
        version = WALLET_HASHES.get(descriptor.contract.code_hash)
        descriptor.contract.wallet_version = version
        descriptor.contract.kind = "standard_wallet" if version else "contract"
        descriptor.contract.status = AttributionStatus.CONFIRMED
        extension = extension_implementation(descriptor.contract.code_hash)
        if extension and extension["implementation_id"] in {"mytonwallet_tg2fa", "tonkeeper_2fa"}:
            bound_wallets = set()
            for payload in (raw, center):
                if not payload or verified_code_hashes.get(id(payload)) != descriptor.contract.code_hash:
                    continue
                owner = extension_wallet_from_data(payload.data.get("data"), extension["implementation_id"])
                if owner is None:
                    continue
                bound_wallets.add(owner)
                fact = _payload_evidence(payload, obs, "computed_extension_wallet_binding", address, {
                    "bound_wallet": owner,
                    "implementation_id": extension["implementation_id"],
                    "code_hash": descriptor.contract.code_hash,
                    "current_state_only": True,
                    "historical_registration_verified": False,
                    "active_v5_membership_verified": False,
                    "client_application_inference": False,
                    "source_urls": extension["source_urls"],
                })
                evidence.append(fact); descriptor.contract.evidence_ids.append(fact["evidence_id"])
            if len(bound_wallets) == 1:
                extension_state = {
                    "bound_wallet": next(iter(bound_wallets)),
                    "implementation_id": extension["implementation_id"],
                    "current_state_only": True,
                    "historical_registration_verified": False,
                    "source_urls": extension["source_urls"],
                }
            elif len(bound_wallets) > 1:
                descriptor.conflicts.append("Extension owner bindings differ across public providers; no agreed bound wallet selected.")
        if version:
            fact = _evidence("ton_wallet_specification", "docs.ton.org", WALLET_SOURCE, _now(), "published_wallet_code_fingerprint",
                address=address, facts={"wallet_version": version, "code_hash": descriptor.contract.code_hash,
                    "client_application_inference": False})
            evidence.append(fact); descriptor.contract.evidence_ids.append(fact["evidence_id"])
    elif len(hashes) > 1:
        descriptor.conflicts.append("Code hashes differ across public providers; no single contract version selected.")
        descriptor.contract.status = AttributionStatus.POSSIBLE
    elif descriptor.account_status != "uninit":
        versions = [value.removeprefix("wallet_").upper() for value in descriptor.contract.interfaces if value.startswith("wallet_v")]
        if len(set(versions)) == 1:
            descriptor.contract.wallet_version = versions[0]
            descriptor.contract.kind = "provider_reported_wallet"
            descriptor.contract.status = AttributionStatus.PROBABLE
            descriptor.contract.evidence_ids.extend(descriptor.evidence_ids)
    if descriptor.account_status == "uninit":
        descriptor.account_type = "uninitialized_account"
        # Address format and is_wallet=true cannot prove an undeployed wallet's code.
        descriptor.contract = ContractDescriptor()
    elif descriptor.contract.wallet_version:
        descriptor.account_type = "wallet_contract"
    elif descriptor.contract.code_hash:
        descriptor.account_type = "smart_contract"
    elif account and account.data.get("is_wallet") is True and descriptor.account_status == "active":
        descriptor.account_type = "provider_reported_wallet"
    if descriptor.conflicts and descriptor.contract.status == "CONFIRMED":
        descriptor.contract.status = AttributionStatus.POSSIBLE
    _apply_labels(descriptor, account, obs, evidence)
    result = descriptor.model_dump(mode="json")
    if extension_state is not None:
        result["contract"]["extension_state"] = extension_state
    return result


def _validate_results(address: str, results: dict[str, Payload], errors: list[dict]) -> None:
    """A returned object is not proof that a supported provider schema matched."""
    states = {"active", "uninit", "nonexist", "uninitialized", "frozen"}
    for name, payload in list(results.items()):
        row = payload.data
        reason = None
        if row.get("address") and _address(row["address"]) != address:
            reason = "Provider returned a different account address"
        elif name in {"account", "address_information"} and str(row.get("status", "")).lower() not in states:
            reason = "Account response lacks a supported state"
        elif name == "transactions" and not isinstance(row.get("transactions"), list):
            reason = "Transaction response lacks a transactions array"
        elif name == "raw_contract" and not (row.get("code") or str(row.get("status", "")).lower() in states):
            reason = "Raw account response has neither state nor code"
        if reason:
            errors.append({"scope": name, "status": "malformed_response", "error": reason,
                           "observation_id": payload.observation_id, "source": payload.source})
            results.pop(name)


def _apply_labels(descriptor: AddressAttribution, account: Payload | None, observations: dict, evidence: list[dict]) -> None:
    registry_labels = exact_registry_labels(descriptor.address)
    attributed: dict[str, ServiceAttribution] = {}
    for row in registry_labels:
        service_id, category = service_identity(row["name"])
        fact = _evidence("tonkeeper_public_registry", "tonkeeper", SOURCE_URL, OBSERVED_AT,
            "published_exact_address_label", address=descriptor.address,
            facts={"label": row["name"], "registry_sha256": SOURCE_SHA256, "registry_is_service_operator_proof": False})
        evidence.append(fact)
        item = ServiceAttribution(attribution_id=_id("ton:attribution:", [descriptor.address, service_id]),
            service_id=service_id, name=row["name"], category=category, status="PROBABLE",
            method="published_exact_address_registry", reason="Exact address is listed in a maintained public registry; operator ownership and user client remain unverified.",
            evidence_ids=[fact["evidence_id"]], source_url=SOURCE_URL, observed_at=OBSERVED_AT)
        if service_id in attributed:
            attributed[service_id].evidence_ids.append(fact["evidence_id"])
        else:
            attributed[service_id] = item
    label = account.data.get("name") if account else None
    if isinstance(label, str) and label.strip():
        service_id, category = service_identity(label)
        fact = _payload_evidence(account, observations, "provider_account_label", descriptor.address, {"label": label})
        evidence.append(fact)
        if service_id in attributed:
            attributed[service_id].evidence_ids.append(fact["evidence_id"])
            attributed[service_id].reason += " TonAPI also reports this label; these sources share an upstream and do not provide independent confirmation."
        else:
            attributed[service_id] = ServiceAttribution(attribution_id=_id("ton:attribution:", [descriptor.address, service_id]),
                service_id=service_id, name=label, category=category, status="POSSIBLE", method="provider_exact_account_label",
                reason="Indexer-reported account label only; not independent proof of service control or wallet application.",
                evidence_ids=[fact["evidence_id"]], source_url=account.endpoint, observed_at=fact["observed_at"])
    service_ids = {item.service_id for item in attributed.values()}
    if len(service_ids) > 1:
        conflict = "Different exact-address service labels were observed: " + ", ".join(sorted(service_ids))
        descriptor.conflicts.append(conflict)
        for item in attributed.values():
            item.status = AttributionStatus.POSSIBLE; item.conflicts.append(conflict)
    descriptor.attributions = list(attributed.values())


def _fragment(address: str, results: dict[str, Payload], observations: list[dict]) -> dict:
    report = AddressReport(target_address=address, detected_chains=["ton"])
    payload = results.get("account") or results.get("address_information")
    if payload:
        value = payload.data.get("balance")
        try:
            units = int(value)
        except (ValueError, TypeError):
            units = None
        if units is not None and units >= 0:
            report.balances.append(Balance(chain="ton", address=address, asset="TON", amount=float(Decimal(units).scaleb(-9)),
                amount_decimal=Decimal(units).scaleb(-9), amount_base_units=units, decimals=9,
                source=payload.source, url=payload.endpoint, raw={"observation_id": payload.observation_id, "current_state": True}))
    payload = results.get("transactions")
    if payload:
        for row in payload.data.get("transactions", [])[:20]:
            if not isinstance(row, dict):
                continue
            tx_hash = str(row.get("hash") or row.get("transaction_id", {}).get("hash") or "")
            if not tx_hash:
                continue
            success = row.get("success") if isinstance(row.get("success"), bool) else None
            if row.get("aborted") is True:
                success = False
            messages = [("in", row.get("in_msg"))] + list(enumerate((row.get("out_msgs") or [])[:256]))
            for index, message in messages:
                if not isinstance(message, dict):
                    continue
                frm, to = _address(message.get("source")), _address(message.get("destination"))
                if index != "in":
                    frm = frm or address
                to = to or (address if index == "in" else None)
                try:
                    units = int(message.get("value"))
                except (ValueError, TypeError):
                    units = None
                fee = row.get("total_fees")
                tx = Transaction(chain="ton", tx_hash=tx_hash, timestamp=ton_datetime(row.get("utime")),
                    from_address=frm, to_address=to, success=success,
                    amount_base_units=units, amount_decimal=Decimal(units).scaleb(-9) if units is not None else None,
                    decimals=9, amount=float(Decimal(units).scaleb(-9)) if units is not None else None, asset="TON",
                    direction="self" if frm == to == address else "out" if frm == address else "in" if to == address else "unknown",
                    fee=float(Decimal(str(fee)).scaleb(-9)) if index == "in" and str(fee or "").isdigit() else None,
                    source=payload.source, url=payload.endpoint,
                    provenance=[{"source": payload.source, "url": payload.endpoint, "observation_id": payload.observation_id}],
                    raw={"lt": row.get("lt"), "message_index": index, "message_hash": message.get("hash"),
                         "message": message, "success": success, "aborted": row.get("aborted"),
                         "total_fees_base_units": fee, "trace_id": row.get("trace_id"), "observation_id": payload.observation_id,
                         "external_message": frm is None})
                tx.event_id = event_identity(tx)
                report.transactions.append(tx)
    for obs in observations:
        report.source_health.append(SourceHealth(source=obs["source"], status="ok" if obs["status"] == "ok" else "error",
            partial=True, details=f"P0 public {obs['endpoint']}; direct transaction sample is bounded to 20 account transactions."))
    return report.model_dump(mode="json")


async def probe_ton_account(address: str, *, deadline: float, progress: Progress | None = None,
                            providers: dict | None = None, max_requests: int = 4) -> dict:
    """Fresh P0 state + raw contract + first direct transactions, bounded by caller time.

    ``deadline`` is absolute ``asyncio.get_running_loop().time()``. Returned
    ``report_fragment`` is an AddressReport JSON dict, reusable without refetching.
    """
    canonical = _address(address)
    if not canonical:
        raise ValueError("valid TON address required")
    if max_requests < 0:
        raise ValueError("max_requests must be nonnegative")
    started = time.monotonic(); observations: list[dict] = []; evidence: list[dict] = []; errors: list[dict] = []
    results: dict[str, Payload] = {}
    controller, clients = _providers(deadline, max_requests, observations, progress, providers)
    _emit(progress, "p0_started", address=canonical)
    escaped = quote(canonical, safe=":")
    ta, tc = clients.get("tonapi"), clients.get("toncenter")
    calls = []
    if ta:
        calls.extend([("account", lambda: ta.call(f"/accounts/{escaped}", fresh=True)),
                      ("transactions", lambda: ta.call(f"/blockchain/accounts/{escaped}/transactions", {"limit": 20})),
                      ("raw_contract", lambda: ta.call(f"/blockchain/accounts/{escaped}", fresh=True))])
    if tc:
        calls.insert(1, ("address_information", lambda: tc.call("/api/v3/addressInformation", {"address": canonical}, fresh=True)))
    expired = await _run_calls(calls, results, errors, deadline) if max_requests and deadline > asyncio.get_running_loop().time() else True
    if expired and not errors:
        errors.append({"scope": "attribution", "status": "budget_limit", "error": "No caller request/time budget remained for P0."})
    _validate_results(canonical, results, errors)
    descriptor = _descriptor(canonical, results, observations, evidence)
    result = {"address": canonical, "descriptor": descriptor, "evidence": evidence, "observations": observations,
        "errors": errors, "report_fragment": _fragment(canonical, results, observations),
        "coverage": {"status": "TRUNCATED" if expired else "PARTIAL" if errors else "COMPLETE",
                     "scope": "current_account_descriptor_and_first_transaction_page", "history_complete": False,
                     "sample_transactions": len(results["transactions"].data.get("transactions", [])) if "transactions" in results else 0},
        "stats": {"requests": controller.requests, "elapsed_seconds": time.monotonic() - started}}
    _emit(progress, "p0_completed", address=canonical, requests=controller.requests, status=result["coverage"]["status"])
    return sanitize_observation(result)


def _extension_code_candidates(report, address, selected, results, deadline):
    """Discovery hints select bounded direct accounts; only code verifies family."""
    selected=set(selected)
    candidates=set()
    for cp in selected:
        data=results[cp].data if cp in results else {}
        interfaces=data.get('interfaces') if isinstance(data,dict) else None
        if isinstance(interfaces,list) and any(isinstance(v,str) and v in
                {'tonkeeper_2fa','subscription_v2','tonkeeper_subscription_v2'} for v in interfaces[:64]):candidates.add(cp)
    loop=asyncio.get_running_loop()
    for tx in report.transactions:
        if loop.time()>=deadline or candidates==selected:break
        if tx.chain!='ton' or transaction_success(tx) is False:continue
        raw=tx.raw or {};native=raw.get('transaction') or {}
        if not isinstance(native,dict):native={}
        outgoing=native.get('out_msgs')
        messages=[raw.get('message'),native.get('in_msg'),*(outgoing[:256] if isinstance(outgoing,list) else [])]
        for message in messages:
            if not isinstance(message,dict):continue
            frm,to=_address(message.get('source')),_address(message.get('destination'))
            if not ((frm in selected and to==address) or (frm==address and to in selected)):continue
            body=body_boc(message)
            if not body:continue
            try:
                if frm in selected and to==address and decode_wallet_body(body,'V5R1').get('auth_mode')=='extension_authorized':
                    candidates.add(frm)
            except (ValueError,TypeError,OverflowError):pass
            try:
                if frm==address and to in selected and decode_extension_install(body):candidates.add(to)
            except (ValueError,TypeError,OverflowError):pass
    return candidates


async def enrich_ton_service_intelligence(report: AddressReport, *, deadline: float,
        max_counterparties: int = 6, max_requests: int = 20, progress: Progress | None = None,
        providers: dict | None = None, initial_account: dict | None = None) -> dict:
    """Enrich existing report in place, retaining original balances/transactions.

    No address expansion beyond the target and top direct counterparties, and no
    detached work. Unknown/unqueried participants receive explicit UNKNOWN rows.
    ``initial_account`` must be the matching result of ``probe_ton_account``.
    """
    if "ton" not in report.detected_chains and not _address(report.target_address):
        return {}
    address = _address(report.target_address)
    if not address:
        raise ValueError("valid TON report address required")
    if max_requests < 0 or max_counterparties < 0:
        raise ValueError("attribution budgets must be nonnegative")
    started = time.monotonic()
    if initial_account is not None and _address(initial_account.get("address")) != address:
        raise ValueError("initial_account belongs to a different TON address")
    initial = sanitize_observation(initial_account) if initial_account is not None else await probe_ton_account(
        address, deadline=deadline, progress=progress, providers=providers, max_requests=min(4, max_requests))
    observations = list(initial.get("observations", [])); evidence = list(initial.get("evidence", [])); errors = list(initial.get("errors", []))
    addresses = {address: initial.get("descriptor") or AddressAttribution(address=address).model_dump(mode="json")}
    counts: Counter[str] = Counter()
    transactions: list[dict] = []; seen: set[str] = set()
    # Coverage follows the existing report sample, not a second transaction scan.
    for tx in report.transactions:
        if tx.chain != "ton":
            continue
        eid = event_identity(tx)
        if eid in seen:
            continue
        seen.add(eid)
        frm, to = _address(tx.from_address), _address(tx.to_address)
        for participant in (frm, to):
            if participant:
                addresses.setdefault(participant, AddressAttribution(address=participant).model_dump(mode="json"))
                if participant != address and transaction_success(tx) is not False and address in (frm, to):
                    counts[participant] += 1
        fact = _evidence(tx.source, "existing_report:" + tx.source, tx.url or "https://tonviewer.com/" + address,
            _now(), "direct_transaction_observation", transaction_hash=tx.tx_hash,
            facts={"event_id": eid, "from_address": frm, "to_address": to, "success": transaction_success(tx),
                   "amount_decimal": str(tx.amount_decimal) if tx.amount_decimal is not None else None,
                   "asset": tx.asset, "logical_time": tx.raw.get("lt"), "message_index": tx.raw.get("message_index"),
                   "source_provenance": tx.provenance})
        evidence.append(fact)
        transactions.append({"event_id": eid, "tx_hash": tx.tx_hash, "trace_id": tx.raw.get("trace_id"),
            "from_address": frm, "to_address": to, "sender_attribution_ids": [], "recipient_attribution_ids": [],
            "amount_decimal": str(tx.amount_decimal) if tx.amount_decimal is not None else None, "asset": tx.asset,
            "timestamp": tx.timestamp.isoformat() if tx.timestamp else None, "success": transaction_success(tx),
            "evidence_ids": [fact["evidence_id"]]})
    selected = [counterparty for counterparty, _ in counts.most_common(max(0, min(50, max_counterparties)))]
    used = int(initial.get("stats", {}).get("requests", 0))
    remaining_requests = max(0, max_requests - used)
    new_observations: list[dict] = []
    controller, clients = _providers(deadline, max(1, remaining_requests), new_observations, progress, providers)
    results: dict[str, Payload] = {}
    _emit(progress, "counterparties_started", selected=len(selected), remaining_requests=remaining_requests)
    calls = [(cp, lambda cp=cp: clients["tonapi"].call(f"/accounts/{quote(cp, safe=':')}", fresh=True)) for cp in selected] if "tonapi" in clients else []
    expired = False
    if calls and remaining_requests and deadline > asyncio.get_running_loop().time():
        expired = await _run_calls(calls, results, errors, deadline)
    elif calls:
        expired = True
    # Metadata endpoints do not return code/storage. Fetch them only for
    # selected direct extension hints, using the same controller and deadline.
    candidates=_extension_code_candidates(report,address,selected,results,deadline)
    code_selected=[cp for cp in selected if cp in candidates][:max(0,remaining_requests-controller.requests)]
    raw_results: dict[str, Payload] = {}
    if code_selected and 'tonapi' in clients and deadline>asyncio.get_running_loop().time():
        _emit(progress,'extension_code_started',selected=len(code_selected))
        code_calls=[(cp,lambda cp=cp:clients['tonapi'].call(f'/blockchain/accounts/{quote(cp,safe=":")}',fresh=True)) for cp in code_selected]
        expired=await _run_calls(code_calls,raw_results,errors,deadline) or expired
    observations.extend(new_observations)
    for cp in addresses:
        if cp == address:
            continue
        cp_results = {"account": results[cp]} if cp in results else {}
        if cp in raw_results:cp_results['raw_contract']=raw_results[cp]
        _validate_results(cp, cp_results, errors)
        addresses[cp] = _descriptor(cp, cp_results, new_observations, evidence)
    for tx in transactions:
        tx["sender_attribution_ids"] = [item["attribution_id"] for item in addresses.get(tx["from_address"], {}).get("attributions", [])]
        tx["recipient_attribution_ids"] = [item["attribution_id"] for item in addresses.get(tx["to_address"], {}).get("attributions", [])]
    # Same-upstream labels never become independent sources simply by duplication.
    evidence = list({row["evidence_id"]: row for row in evidence}.values())
    payload = {"schema_version": "1.0", "target_address": address, "addresses": addresses,
        "transactions": transactions, "evidence": evidence, "observations": observations,
        "coverage": {"status": "TRUNCATED" if expired else "PARTIAL", "history_complete": False,
            "current_descriptor_status": initial.get("coverage", {}).get("status", "UNKNOWN"),
            "counterparties_available": len(counts), "counterparties_selected": len(selected),
            "counterparties_queried": len(results), "counterparties_unqueried": max(0, len(counts)-len(results)),
            "extension_code_candidates":len(candidates),"extension_code_queried":len(raw_results),
            "max_counterparties": max_counterparties, "max_requests": max_requests,
            "limits": LIMITATIONS},
        "stats": {"requests": used + controller.requests, "transactions": len(transactions), "addresses": len(addresses),
            "elapsed_seconds": time.monotonic()-started}, "errors": errors, "warnings": LIMITATIONS}
    payload["relationship_analysis"] = analyze_ton_relationships(report, payload, deadline=deadline)
    report.ton_service_intelligence = sanitize_observation(compact_service_provenance(payload))
    _emit(progress, "completed", address=address, requests=payload["stats"]["requests"], status=payload["coverage"]["status"])
    return report.ton_service_intelligence
