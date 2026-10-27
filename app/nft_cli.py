"""CLI integration for persisted, evidence-based TON NFT investigations.

Imports of collectors and exporters stay lazy so the original address CLI and
``--help`` do not require an initialized investigation or network access.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import inspect
import re
import time
from datetime import datetime, timezone
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.utils.async_tasks import owned_thread_call

from rich.console import Console
from rich.text import Text


SEARCH_MODE = "deep"
# This is a retained-event safety ceiling, not a collector page/request limit.
SEARCH_MAX_TRANSACTIONS = 100000
SEARCH_CHECKPOINT_SECONDS = 12.0


def looks_like_nft_input(query: str) -> bool:
    """Recognize explicit asset names/links, never guess NFT identity by title.

    Raw TON addresses are resolved by the shared search before wallet analysis.
    URL and name syntax is validated by the existing discovery normalizer.
    """
    text = query.strip()
    if not text:
        return False
    if re.fullmatch(r"@?[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:ton|t\.me)", text, re.I):
        return True
    if re.fullmatch(r"@[A-Za-z0-9_]{4,32}", text):
        return True
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9]*-\d+", text):
        return True
    if text.lower().startswith(("t.me/", "telegram.me/", "fragment.com/", "getgems.io/", "tonviewer.com/", "tonscan.org/", "gram.org/")):
        text = "https://" + text
    try:
        parsed = urlsplit(text)
        if parsed.scheme not in {"https", "http"}:
            return False
        if (parsed.hostname or "").lower().removeprefix("www.") in {
                "t.me", "telegram.me", "fragment.com", "getgems.io",
                "tonviewer.com", "tonscan.org", "gram.org"}:
            # Routing is not an identity assertion. Discovery validates the
            # actual path/address and returns UNKNOWN for unsupported objects.
            return True
        from app.ton_nft.discovery import normalize_nft_query
        return normalize_nft_query(text).kind in {"address", "domain", "username", "gift"}
    except ValueError:
        return False


def _load_resume_state(investigation_id: str, store_path):
    """Read/upgrade a saved dossier in one thread that owns its SQLite handle."""
    from app.models.report import AddressReport
    from app.ton_nft.storage import InvestigationStore
    refreshed = {"balances", "tokens", "ton_assets", "telegram_identities", "source_health", "contract_observations",
        "nft_intelligence", "ton_service_intelligence", "attribution_intelligence", "errors", "warnings", "input_resolution"}
    saved_store = InvestigationStore(store_path)
    try:
        old_nft = saved_store.load_snapshot(investigation_id, owner_exclude=refreshed, detach_owner=True)
        retained = (AddressReport.model_validate({key: value for key, value in old_nft.owner_analysis_snapshot.items()
            if key not in refreshed}) if old_nft.owner_analysis_snapshot else None)
        # Full historical owner remains durable in SQLite; current state and
        # NFT ownership will be checked afresh by the ordinary pipeline.
        old_nft.owner_analysis_snapshot = None
        return old_nft, retained
    finally:
        saved_store.close()


def _load_resume_header(investigation_id: str, store_path):
    """Read a detached NFT header without hydrating its historical owner."""
    from app.ton_nft.storage import InvestigationStore, validate_investigation_id
    validate_investigation_id(investigation_id)
    store = InvestigationStore(store_path)
    try:
        # C-level JSON extraction avoids decoding a large legacy inline owner
        # just to decide that its original single full-load path is necessary.
        row = store.db.execute("SELECT json_extract(report_json,'$.owner_snapshot_reference') FROM investigations WHERE id=?",
            (investigation_id,)).fetchone()
        if row is None:
            raise KeyError(f"investigation not found: {investigation_id}")
        return store.load_snapshot(investigation_id, include_owner=False) if row[0] is not None else None
    finally:
        store.close()


async def _owned_resume_load(loader, investigation_id: str, store_path):
    # A large legacy dossier must not prevent unrelated batch queries from
    # resolving inputs or publishing P0. No SQLite connection crosses threads.
    loading = asyncio.create_task(asyncio.to_thread(loader, investigation_id, store_path))
    try:
        return await asyncio.shield(loading)
    except asyncio.CancelledError:
        # Cancelling to_thread's await cannot stop its synchronous migration.
        # Drain it, including commit/rollback and close, before leaving session.
        while not loading.done():
            try:
                await asyncio.shield(loading)
            except asyncio.CancelledError:
                continue
        loading.result()  # Retrieve a load/transaction failure before cleanup ends.
        raise


async def _load_resume_state_async(investigation_id: str, store_path):
    return await _owned_resume_load(_load_resume_state, investigation_id, store_path)


async def _load_resume_header_async(investigation_id: str, store_path):
    return await _owned_resume_load(_load_resume_header, investigation_id, store_path)


async def analyze_search_input(
    query: str, *, timeout: float = 18.0,
    max_txs: int = SEARCH_MAX_TRANSACTIONS,
    selected_chains: list[str] | None = None,
    nft_options: dict | None = None, address_analyzer: Any = None,
    progress: Any = None, on_report_ready: Any = None, on_model_ready: Any = None,
    deadline: float | None = None, continuous: bool = False,
) -> tuple[Any, dict]:
    """Resolve NFT identity/ownership, then use the existing address pipeline.

    Both interactive and batch search call this function. One NFT investigation
    retains its own budget, observations and checkpoints; analysis never follows
    DNS wallet records or unverified metadata owners.
    """
    from app.models.report import AddressReport, SourceHealth
    from app.graph.builder import build_graph_payload
    from app.utils.detect import detect_candidates, looks_like_bitcoin_address, looks_like_dogecoin_address
    from app.utils.ton_normalize import ton_canonical_address
    from app.utils.security import sanitize_observation

    text = query.strip()
    started = time.monotonic()
    diagnostics = []
    def emit(stage, **details):
        event = {"timestamp": datetime.now(timezone.utc).isoformat(), "elapsed_seconds": round(time.monotonic()-started, 3),
                 "component": "search", "stage": stage, **details}
        diagnostics.append(event)
        if progress:
            progress(event)
    def relay(event):
        emit(event["stage"], **{key: value for key, value in event.items() if key not in {"stage", "timestamp", "elapsed_seconds", "component"}})
    async def retain_model(report):
        from app.aggregator.collection_audit import refresh_audit
        refresh_audit(report, "model", nft_projection_included=bool(report.nft_intelligence))
        if isinstance(report.coverage.get("transactions"), dict):
            report.coverage["transactions"].update({"collected_events": len(report.transactions),
                "retained_records": len(report.transactions)})
        if on_model_ready:
            saved = on_model_ready(report)
            if inspect.isawaitable(saved):
                await saved

    emit("input.start", query=sanitize_observation(text))
    if not text:
        raise ValueError("A search identifier is required")
    if address_analyzer is None:
        from app.aggregator.analyzer import analyze_address
        address_analyzer = analyze_address
    parameters = inspect.signature(address_analyzer).parameters
    accepts_progress = "progress" in parameters or any(
        value.kind == inspect.Parameter.VAR_KEYWORD for value in parameters.values())
    accepts_options = any(value.kind == inspect.Parameter.VAR_KEYWORD for value in parameters.values())
    def supports(name):
        return name in parameters or accepts_options
    # The analyzer exposes a synchronous commit after collection and before its
    # CPU-heavy analytics/graph. Persist that last page independently of HTML.
    if continuous and on_model_ready and supports("on_collected"):
        collected_callback = on_model_ready
    else:
        collected_callback = None
    ens_seed = None
    public_context_seed = None
    original_query = text
    if text.lower().rstrip(".").endswith(".base.eth"):
        # Base-native identity resolution reuses the ordinary address pipeline;
        # it does not claim that Gansar collects Base financial history.
        from app.sources.basenames import BaseNamesSource
        if selected_chains and not any(chain in {"eth", "bsc", "polygon", "arbitrum", "optimism", "avalanche"} for chain in selected_chains):
            raise ValueError("Basenames require a supported EVM address investigation")
        identity_timeout = min(14.0, max(0.1, float(timeout)))
        if deadline is not None:
            identity_timeout = min(identity_timeout, max(0.001, deadline - time.monotonic()))
        emit("basename.resolve.start", source="basenames", query=sanitize_observation(text))
        try:
            async with asyncio.timeout(identity_timeout):
                public_context_seed = await BaseNamesSource(identity_timeout).resolve_name(text)
        except TimeoutError as exc:
            raise ValueError("Base name resolution timed out; no wallet address was assumed") from exc
        claims = [claim for row in public_context_seed.public_address_context.get("outcomes", [])
                  for claim in row.get("claims", []) if claim.get("claim_type") == "basename_resolution"
                  and claim.get("value", {}).get("forward_verified") is True]
        resolved = claims[0].get("value", {}).get("resolved_address") if len(claims) == 1 else None
        if not resolved or not re.fullmatch(r"0x[a-fA-F0-9]{40}", resolved):
            raise ValueError("Base name could not be resolved from available sources; no wallet address was assumed")
        text = resolved
        for outcome in public_context_seed.public_address_context.get("outcomes", []):
            outcome["target_address"] = resolved
        public_context_seed.input_resolution = {"query": sanitize_observation(original_query),
            "original_query": sanitize_observation(original_query), "normalized_query": claims[0]["value"]["name"],
            "input_kind": "basename_name", "object_type": "basename_name", "status": "resolved",
            "resolved_address": resolved, "analysis_address": resolved, "forward_verified": True,
            "source": "basenames", "identity_chain": "base", "chain_id": 8453,
            "notes": ["Base-native name resolution. Financial coverage remains limited to the selected supported networks; Base financial collection is not implemented."]}
        emit("basename.resolve.complete", source="basenames", resolved_address=resolved)
    elif text.lower().rstrip(".").endswith(".eth"):
        if selected_chains and "eth" not in selected_chains:
            raise ValueError("ENS names require Ethereum analysis")
        from app.sources.ethereum_ens import EthereumEnsSource
        identity_timeout = min(24.0, max(0.1, float(timeout)))
        if deadline is not None:
            identity_timeout = min(identity_timeout, max(0.001, deadline - time.monotonic()))
        emit("ens.resolve.start", source="ethereum_ens", query=sanitize_observation(text))
        try:
            async with asyncio.timeout(identity_timeout):
                ens_seed = await EthereumEnsSource(identity_timeout).resolve_name(text)
        except TimeoutError as exc:
            emit("ens.resolve.error", source="ethereum_ens", status="timeout")
            raise ValueError("ENS input resolution timed out; no wallet analysis was started") from exc
        profile = getattr(ens_seed, "ens_profile", {}) or {}
        resolved = ens_seed.ens_resolved_address or profile.get("resolved_address")
        if not profile.get("forward_verified") or not resolved or not re.fullmatch(r"0x[a-fA-F0-9]{40}", resolved):
            emit("ens.resolve.error", source="ethereum_ens", status=profile.get("lookup_status", "unavailable"))
            raise ValueError("ENS name could not be resolved from available sources; no wallet address was assumed")
        text = resolved
        ens_seed.input_resolution = {"query": sanitize_observation(original_query), "original_query": sanitize_observation(original_query),
            "normalized_query": profile.get("name") or original_query, "input_kind": "ens_name", "object_type": "ens_name",
            "status": "resolved", "resolved_address": resolved, "analysis_address": resolved, "forward_verified": True,
            "source": "ethereum_ens", "identity_chain": "eth", "chain_id": 1,
            "retrieved_at": profile.get("retrieved_at"), "provenance": dict(profile.get("provenance") or {})}
        emit("ens.resolve.complete", source="ethereum_ens", target=text, resolved_address=text,
             name=profile.get("name"), forward_verified=True, chain="eth")
    chains = selected_chains or (["eth"] if ens_seed is not None or public_context_seed is not None else detect_candidates(text))
    ton_address = ton_canonical_address(text)
    explicit_nft = looks_like_nft_input(text)
    if not (ton_address or explicit_nft):
        if not chains and not looks_like_bitcoin_address(text) and not looks_like_dogecoin_address(text):
            emit("input.error", reason="unsupported identifier; no collectors scheduled")
            raise ValueError("Unknown input format. Enter a supported blockchain address, .eth or .ton domain, collectible username, exact gift identifier or supported NFT URL.")
        emit("input.classified", kind="basename_name" if public_context_seed is not None else "ens_name" if ens_seed is not None else "address", chains=chains)
        kwargs = dict(timeout_seconds=timeout, max_txs=max_txs, selected_chains=chains if ens_seed is not None or public_context_seed is not None else selected_chains, include_experimental=True)
        if ens_seed is not None and supports("ens_seed"):
            kwargs["ens_seed"] = ens_seed
        if public_context_seed is not None and supports("public_context_seed"):
            kwargs["public_context_seed"] = public_context_seed
        if collected_callback:
            kwargs["on_collected"] = collected_callback
        if progress and accepts_progress:
            kwargs["progress"] = relay
        if deadline is not None and supports("deadline"):
            kwargs["deadline"] = deadline
        if continuous and supports("continuous"):
            kwargs["continuous"] = True
        if continuous and on_report_ready and supports("on_checkpoint"):
            last_preview_at = float("-inf")
            last_preview_seconds = 0.0
            async def address_checkpoint(partial):
                nonlocal last_preview_at, last_preview_seconds
                partial.coverage["search_execution"] = {"status": "running", "data_complete": False,
                    "partial_checkpoint": True}
                if time.monotonic() - last_preview_at < 3 * last_preview_seconds:
                    # Retain every collected observation durably. Only an
                    # expensive intermediate presentation is coalesced; final
                    # analysis/HTML still runs on the entire collected history.
                    await retain_model(partial)
                    emit("checkpoint.deferred", reason="measured_preview_cost",
                         checkpoint="intermediate_html", transactions=len(partial.transactions))
                    return
                preview_started = time.monotonic()
                from app.attribution.engine import correlate_attribution
                await owned_thread_call(correlate_attribution, partial)
                partial.coverage["search_execution"] = {"status": "running", "data_complete": False,
                    "partial_checkpoint": True}
                await retain_model(partial)
                graph = await asyncio.to_thread(build_graph_payload, partial)
                saved = on_report_ready(partial, graph)
                if inspect.isawaitable(saved):
                    await saved
                last_preview_at = time.monotonic()
                last_preview_seconds = max(0.0, last_preview_at - preview_started)
            kwargs["on_checkpoint"] = address_checkpoint
        emit("address.start", target=text, chains=chains)
        result = await address_analyzer(text, **kwargs)
        if public_context_seed is not None:
            if not supports("public_context_seed"):
                from app.aggregator.analyzer import _merge
                _merge(result[0], public_context_seed)
                result = (result[0], await asyncio.to_thread(build_graph_payload, result[0]))
            result[0].input_resolution = dict(public_context_seed.input_resolution)
        if ens_seed is not None:
            if not supports("ens_seed"):
                from app.aggregator.analyzer import _merge
                _merge(result[0], ens_seed)
                result = (result[0], await asyncio.to_thread(build_graph_payload, result[0]))
            result[0].input_resolution = dict(ens_seed.input_resolution)
        if continuous and asyncio.current_task().cancelling():
            result[0].coverage["search_execution"] = {"status": "stopped", "data_complete": False,
                "reason": "user_stop", "checkpoint_retained": True}
        emit("address.complete", transactions=len(result[0].transactions))
        result[0].coverage["pipeline_diagnostics"] = diagnostics
        return result

    from app.ton_nft.models import InvestigationBudget
    from app.ton_nft.service import (investigate_ton_nft, report_to_address_report,
                                    attach_nft_intelligence, resolve_verified_nft_owner)
    options = dict(nft_options or {})
    options["mode"] = SEARCH_MODE
    supplied_budget = options.get("budget")
    options["budget"] = (InvestigationBudget.model_validate(supplied_budget)
                         if supplied_budget is not None else InvestigationBudget.for_mode(SEARCH_MODE))
    if deadline is not None:
        # Resource ceilings retain every deep capability; wall time is shared
        # with P0/P1 and the caller reserves graph/export time separately.
        options["budget"] = InvestigationBudget.model_validate({**options["budget"].model_dump(),
            "max_seconds": max(1, min(options["budget"].max_seconds, deadline-asyncio.get_running_loop().time())),
            "request_timeout": min(options["budget"].request_timeout, 5), "retries": 1})
        options["priority_scheduling"] = True
        options["checkpoint_interval_seconds"] = 15.0 if continuous else 2.0
    retained_owner_report = None
    retained_owner_pending = False
    if continuous and (options.get("resume") or options.get("incremental")) and options.get("investigation_id"):
        emit("history.resume.load.start", investigation_id=options["investigation_id"])
        old_nft = await _load_resume_header_async(options["investigation_id"], options.get("store_path"))
        if old_nft is None:
            old_nft, retained_owner_report = await _load_resume_state_async(options["investigation_id"], options.get("store_path"))
        else:
            retained_owner_pending = True
        # The service validates snapshot ID/query before reusing this report.
        options["_resume_report"] = old_nft
        emit("history.resume.load.complete", investigation_id=options["investigation_id"],
            transactions=len(retained_owner_report.transactions) if retained_owner_report else 0,
            owner_hydration_pending=retained_owner_pending)
    emit("input.classified", kind="ton_object", chains=["ton"])
    owner_task = None
    ready_task = None
    analysis_target = None
    owner_failed = False
    enrichment_finished = False
    probes = {}
    verified_input = None
    running_nft_report = None
    latest_wallet = None
    last_checkpoint_at = float("-inf")
    last_checkpoint_duration = 0.0
    last_owner_snapshot_at = float("-inf")
    checkpoint_lock = asyncio.Lock()
    retained_operation_ids = None
    retained_owner_target = None

    def can_replace_owner(base):
        if retained_owner_pending:
            return False
        if retained_owner_report is None and retained_operation_ids is None:
            return True
        if retained_operation_ids is None or not retained_owner_target or retained_owner_target != ton_canonical_address(base.target_address):
            return False
        # A delayed P0 checkpoint or error fallback must not replace the durable
        # historical dossier merely because hydration has now completed.
        from app.utils.event_identity import event_identity
        return retained_operation_ids.issubset({event_identity(tx) for tx in base.transactions})

    def can_join_final_without_preview(base, nft_report):
        # The collection deadline ends previews, not the final joined dossier.
        # Stop/error recovery still owns its forced publication boundary.
        task = asyncio.current_task()
        return bool(continuous and deadline is not None
            and asyncio.get_running_loop().time() >= deadline
            and not owner_failed and not (task and task.cancelling())
            and base.coverage.get("search_execution", {}).get("status") != "stopped"
            and not (nft_report and nft_report.stats.get("stopped"))
            and analysis_target
            and ton_canonical_address(base.target_address) == ton_canonical_address(analysis_target)
            and can_replace_owner(base))

    async def publish_checkpoint(base, nft_report=None, *, force=False):
        nonlocal latest_wallet, last_checkpoint_at, last_owner_snapshot_at, last_checkpoint_duration
        if not (retained_operation_ids is not None and not can_replace_owner(base)
                and latest_wallet is not None and can_replace_owner(latest_wallet)):
            latest_wallet = base
        if not on_report_ready:
            return
        checkpoint_gap = max(SEARCH_CHECKPOINT_SECONDS, 3*last_checkpoint_duration)
        if not force and (checkpoint_lock.locked() or time.monotonic()-last_checkpoint_at < checkpoint_gap):
            return
        # Only one intermediate model freeze/graph/export is active. Sources
        # and raw SQLite observations continue while redundant views coalesce.
        # Final/forced checkpoints wait and then freeze their current model.
        async with checkpoint_lock:
            if not force and time.monotonic()-last_checkpoint_at < checkpoint_gap:
                return
            if (retained_operation_ids is not None and not can_replace_owner(base)
                    and latest_wallet is not None and can_replace_owner(latest_wallet)):
                base = latest_wallet
            checkpoint_started = time.monotonic()
            try:
                partial = base.model_copy(deep=True)
                if nft_report is not None:
                    from app.ton_nft.models import NFTIntelligenceReport
                    frozen = NFTIntelligenceReport.model_validate(nft_report.model_dump(mode="json", exclude={"owner_analysis_snapshot"}))
                    attach_nft_intelligence(partial, frozen)
                    if continuous and can_replace_owner(base) and time.monotonic()-last_owner_snapshot_at >= 30:
                        from app.ton_nft.storage import InvestigationStore
                        # The atomic owner-table write sanitizes the full tree.
                        # Do not walk this same large dossier twice here.
                        nft_report.owner_analysis_snapshot = base.model_dump(mode="json", exclude={"nft_intelligence"})
                        snapshot_store = InvestigationStore(options.get("store_path"))
                        try:
                            snapshot_store.save_snapshot(nft_report)
                        finally:
                            snapshot_store.close()
                        # Parent AddressReport and the committed sibling own
                        # the full dossier. Later NFT pages need its reference.
                        nft_report.owner_analysis_snapshot = None
                        last_owner_snapshot_at = time.monotonic()
                partial.input_resolution = {**partial.input_resolution, **(verified_input or {}),
                    "original_query": sanitize_observation(text),
                    "owner_analysis_address": analysis_target if verified_input else None,
                    "onchain_owner_address": (verified_input or {}).get("owner_address"),
                    "owner_analysis_status": "running" if verified_input else "not_started"}
                partial.coverage["search_execution"] = {"status": "running", "data_complete": False,
                    "partial_checkpoint": True}
                partial.coverage["pipeline_diagnostics"] = list(diagnostics)
                from app.attribution.engine import correlate_attribution
                await owned_thread_call(correlate_attribution, partial)
                await retain_model(partial)
                if continuous and enrichment_finished and not force:
                    # The final joined report now owns publication. Keep the
                    # durable model, coalescing this already obsolete preview.
                    emit("checkpoint.deferred", reason="completed_sources_final_join",
                        checkpoint="intermediate_html", transactions=len(partial.transactions))
                    return
                graph = await asyncio.to_thread(build_graph_payload, partial)
                saved = on_report_ready(partial, graph)
                if inspect.isawaitable(saved):
                    await saved
            finally:
                last_checkpoint_at = time.monotonic()
                last_checkpoint_duration = max(0.0, last_checkpoint_at-checkpoint_started)

    async def owner_checkpoint(partial):
        await publish_checkpoint(partial, running_nft_report)

    async def nft_checkpoint(partial_nft):
        if latest_wallet is not None:
            if can_join_final_without_preview(latest_wallet, partial_nft):
                emit("checkpoint.deferred", reason="collection_deadline_final_join",
                    checkpoint="nft_preview", transactions=len(latest_wallet.transactions))
                return
            await publish_checkpoint(latest_wallet, partial_nft)

    async def probe(target):
        nonlocal latest_wallet
        from app.ton_attribution import probe_ton_account
        if target not in probes:
            emit("priority.p0.start", target=target)
            probes[target] = await probe_ton_account(target,
                deadline=min(deadline-7, asyncio.get_running_loop().time()+10), progress=relay)
            emit("priority.p0.complete", target=target)
            if on_report_ready:
                fact = probes[target]
                partial = AddressReport.model_validate(fact["report_fragment"])
                partial.ton_service_intelligence = {"schema_version": "1.0", "target_address": target,
                    "addresses": {target: fact["descriptor"]}, "evidence": fact["evidence"],
                    "observations": fact["observations"], "transactions": [], "coverage": fact.get("coverage", {})}
                partial.input_resolution = {**(verified_input or {}), "original_query": text,
                    "object_type": (verified_input or {}).get("object_type") or fact["descriptor"].get("account_type", "unknown"),
                    "owner_analysis_address": target if verified_input else None,
                    "onchain_owner_address": (verified_input or {}).get("owner_address"),
                    "owner_analysis_status": "pending" if verified_input else "not_started"}
                partial.warnings.append("Priority P0 checkpoint: available observations only; further analysis may be unfinished. History is partial.")
                partial.coverage["search_execution"] = {"status": "partial", "priority": "P0", "data_complete": False}
                latest_wallet = partial
                from app.attribution.engine import correlate_attribution
                await owned_thread_call(correlate_attribution, partial)
                await retain_model(partial)
                graph = await asyncio.to_thread(build_graph_payload, partial)
                saved = on_report_ready(partial, graph)
                if inspect.isawaitable(saved):
                    await saved
        return probes[target]

    if deadline is not None and ton_address:
        initial = await probe(ton_address)
        descriptor = initial.get("descriptor") or {}
        # Fresh standard code/state evidence avoids expensive negative NFT
        # getter probing for an ordinary or undeployed account.
        if options.get("scope", "auto") == "auto" and (
                descriptor.get("account_type") in {"wallet_contract", "provider_reported_wallet"}
                or descriptor.get("account_status") == "uninit"):
            options["scope"] = "wallet"

    async def analyze_target(target):
        nonlocal owner_failed, latest_wallet, retained_owner_report, retained_owner_pending, retained_operation_ids, retained_owner_target
        emit("address.start", target=target, chains=["ton"])
        kwargs = dict(timeout_seconds=timeout, max_txs=max_txs, selected_chains=["ton"], include_experimental=True)
        if collected_callback:
            kwargs["on_collected"] = collected_callback
        if progress and accepts_progress:
            kwargs["progress"] = relay
        try:
            initial = await probe(target) if deadline is not None else None
            if retained_owner_pending:
                # Fresh ownership and the useful P0 HTML precede expensive
                # historical hydration. NFT streams continue while this owned
                # SQLite thread loads; their snapshots preserve the owner ref.
                emit("history.owner.load.start", investigation_id=options["investigation_id"])
                _, retained_owner_report = await _load_resume_state_async(options["investigation_id"], options.get("store_path"))
                emit("history.owner.load.complete", transactions=len(retained_owner_report.transactions) if retained_owner_report else 0)
            independent_owner_ready = False
            if supports("initial_report"):
                fresh_initial = AddressReport.model_validate(initial["report_fragment"]) if initial else None
                if retained_owner_report is not None and ton_canonical_address(retained_owner_report.target_address) == ton_canonical_address(target):
                    from app.aggregator.analyzer import _merge
                    prior = retained_owner_report.model_copy(deep=True)
                    kwargs["initial_report"] = _merge(prior, fresh_initial) if fresh_initial is not None else prior
                    independent_owner_ready = True
                    emit("history.resumed", target=target, transactions=len(prior.transactions),
                        streams=len(prior.collection_audit.get("streams", {})))
                elif fresh_initial is not None:
                    kwargs["initial_report"] = fresh_initial
            if retained_owner_report is not None:
                from app.utils.event_identity import event_identity
                retained_operation_ids = {event_identity(tx) for tx in retained_owner_report.transactions}
                retained_owner_target = ton_canonical_address(retained_owner_report.target_address)
                if independent_owner_ready:
                    # The independent initial model now owns every historical
                    # fact. Keep the target/ID replacement guard, not another
                    # full dossier through analysis, persistence and graph.
                    retained_owner_report = None
            if retained_owner_pending:
                # No await between publishing the merged historical/current
                # base and permitting replacement of the persisted owner.
                # Concurrent NFT callbacks therefore never revert to P0.
                if "initial_report" in kwargs:
                    latest_wallet = kwargs["initial_report"]
                retained_owner_pending = False
            if continuous and supports("incremental"):
                kwargs["incremental"] = bool(options.get("incremental"))
            if deadline is not None and supports("deadline"):
                kwargs["deadline"] = deadline-7 if continuous else min(deadline-7, asyncio.get_running_loop().time()+18)
            if continuous and supports("continuous"):
                kwargs["continuous"] = True
            if continuous and supports("on_checkpoint"):
                kwargs["on_checkpoint"] = owner_checkpoint
            if continuous and supports("defer_graph"):
                kwargs["defer_graph"] = True
            result = await address_analyzer(target, **kwargs)
            latest_wallet = result[0]
            if continuous and asyncio.current_task().cancelling():
                result[0].coverage["search_execution"] = {"status": "stopped", "data_complete": False,
                    "reason": "user_stop", "checkpoint_retained": True}
            if deadline is not None and result[0].coverage.get("search_execution", {}).get("status") != "stopped":
                from app.ton_attribution import enrich_ton_service_intelligence
                emit("priority.p1.start", target=target)
                await enrich_ton_service_intelligence(result[0], initial_account=initial,
                    deadline=min(deadline, asyncio.get_running_loop().time()+7), progress=relay)
                if not continuous:
                    from app.attribution.engine import correlate_attribution
                    await owned_thread_call(correlate_attribution, result[0])
                emit("priority.p1.complete", target=target)
            emit("address.complete", target=target, transactions=len(result[0].transactions))
            if continuous and not enrichment_finished:
                if can_join_final_without_preview(result[0], running_nft_report):
                    # Keep a complete recovery model before joining the NFT
                    # service. A second full copy/store/graph/HTML here would
                    # block that service from finishing after its deadline.
                    if running_nft_report is not None:
                        attach_nft_intelligence(result[0], running_nft_report)
                    result[0].input_resolution = {**result[0].input_resolution, **(verified_input or {}),
                        "original_query": sanitize_observation(text),
                        "owner_analysis_address": analysis_target if verified_input else None,
                        "onchain_owner_address": (verified_input or {}).get("owner_address"),
                        "owner_analysis_status": "running" if verified_input else "not_started"}
                    result[0].coverage["search_execution"] = {"status": "running", "data_complete": False,
                        "phase": "final_join_pending", "html_pending_update": True}
                    await retain_model(result[0])
                    emit("checkpoint.deferred", reason="collection_deadline_final_join",
                        checkpoint="owner_finish", transactions=len(result[0].transactions))
                else:
                    # Successful completion follows the same existing preview
                    # coalescing as source checkpoints; errors/stops stay forced.
                    await publish_checkpoint(result[0], running_nft_report, force=False)
            return result[0]
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            owner_failed = True
            import traceback
            emit("address.error", target=target, error=str(sanitize_observation(str(exc))),
                 traceback=sanitize_observation(traceback.format_exc()))
            fact = probes.get(target)
            partial = AddressReport.model_validate(fact["report_fragment"]) if fact else AddressReport(target_address=target, detected_chains=["ton"])
            if fact:
                partial.ton_service_intelligence = {"schema_version": "1.0", "target_address": target,
                    "addresses": {target: fact["descriptor"]}, "evidence": fact["evidence"],
                    "observations": fact["observations"], "transactions": [], "coverage": fact.get("coverage", {})}
            partial.errors.append("owner_analysis: " + str(sanitize_observation(str(exc))))
            partial.source_health.append(SourceHealth(source="owner_analysis", status="error", details="Wallet pipeline failed; priority observations and NFT evidence retained"))
            latest_wallet = partial
            if continuous and not enrichment_finished:
                await publish_checkpoint(partial, running_nft_report, force=True)
            return partial

    async def checkpoint(target_info, running_nft):
        base = await owner_task
        if not on_report_ready or enrichment_finished:
            return
        # Independent copies prevent the continuing collector from changing the
        # snapshot while the original renderer writes it in a worker thread.
        from app.ton_nft.models import NFTIntelligenceReport
        partial_nft = NFTIntelligenceReport.model_validate(running_nft.model_dump(mode="json"))
        partial = base.model_copy(deep=True)
        attach_nft_intelligence(partial, partial_nft)
        partial.input_resolution = {**target_info, "original_query": sanitize_observation(text),
            "onchain_owner_address": target_info.get("owner_address"),
            "owner_analysis_address": analysis_target if target_info.get("owner_address") else None,
            "owner_analysis_status": (("failed" if owner_failed else "partial" if base.errors or base.warnings else "completed")
                                      if target_info.get("owner_address") else "not_started"),
            "discovery_status": "resolved", "search_mode": SEARCH_MODE}
        notice = ("Preliminary checkpoint: this managed investigation continues automatically; source coverage is partial."
                  if continuous else "Bounded search partial checkpoint: captured observations only. Incomplete enrichment can be continued explicitly from saved checkpoints."
                  if deadline is not None else "NFT enrichment is still running. This is a partial checkpoint, not the completed investigation.")
        partial.warnings = list(dict.fromkeys(partial.warnings + [notice]))
        partial.coverage["search_execution"] = {"status": "running" if continuous or deadline is None else "partial", "partial_checkpoint": True}
        partial.coverage["pipeline_diagnostics"] = list(diagnostics)
        await retain_model(partial)
        emit("checkpoint.graph.start")
        graph = await asyncio.to_thread(build_graph_payload, partial)
        emit("checkpoint.graph.complete", nodes=len(graph.get("nodes", [])))
        result = on_report_ready(partial, graph)
        if inspect.isawaitable(result):
            await result
        emit("checkpoint.ready", status="partial", enrichment="running")

    async def target_resolved(target_info, running_nft):
        nonlocal owner_task, ready_task, analysis_target, verified_input, running_nft_report
        proof = resolve_verified_nft_owner(running_nft)
        target = proof["owner_address"] if proof else ton_address if target_info.get("scope") == "wallet" else None
        if not target or owner_task:
            return
        analysis_target = target
        verified_input = proof
        running_nft_report = running_nft
        emit("target.resolved", target=target, object_type=target_info.get("object_type"), ownership_status="verified_onchain" if proof else "not_applicable")
        owner_task = asyncio.create_task(analyze_target(target))
        if on_report_ready and not continuous:
            # Continuous mode already publishes owner/NFT stream checkpoints.
            # This legacy waiter would build a duplicate owner-finish HTML.
            ready_task = asyncio.create_task(checkpoint(target_info, running_nft))
        if deadline is not None and not continuous:
            # P0/P1 precede the optional inventory/history sweep. The NFT
            # controller keeps the same absolute budget while this is awaited.
            await owner_task
            emit("priority.p2.start", remaining_seconds=max(0, deadline-asyncio.get_running_loop().time()))
        else:
            await asyncio.sleep(0)

    options["on_target_resolved"] = target_resolved
    options["on_progress"] = relay
    if continuous:
        options["continuous"] = True
        options["on_checkpoint"] = nft_checkpoint
    try:
        if deadline is not None:
            options["budget"] = InvestigationBudget.model_validate({**options["budget"].model_dump(),
                "max_seconds": max(1, min(options["budget"].max_seconds, deadline-asyncio.get_running_loop().time()))})
        emit("nft.start", budget=options["budget"].model_dump(mode="json"))
        nft = await investigate_ton_nft(text, **options)
        enrichment_finished = True
        if continuous and nft.stats.get("stopped") and owner_task and not owner_task.done():
            owner_task.cancel()
        emit("nft.complete", status=nft.status, assets=len(nft.assets), events=len(nft.events))
    except asyncio.CancelledError:
        enrichment_finished = True
        for task in (ready_task, owner_task):
            if task:
                task.cancel()
        await asyncio.gather(*(task for task in (ready_task, owner_task) if task), return_exceptions=True)
        raise
    except Exception as exc:
        enrichment_finished = True
        if owner_task:
            # A resolved NFT must never be reinterpreted as the original TON
            # account after a later orchestration/callback failure. Provider
            # failures already become evidence-bearing partial NFT reports in
            # the service; unexpected failures remain visible to the caller.
            for task in (ready_task, owner_task):
                if task and not task.done():
                    task.cancel()
            await asyncio.gather(*(task for task in (ready_task, owner_task) if task), return_exceptions=True)
            raise
        if not ton_address:
            raise
        # A discovery outage must not prevent a normal address dossier.
        emit("nft.error", error=str(sanitize_observation(str(exc))))
        emit("address.start", target=text, chains=["ton"], reason="discovery_unavailable")
        kwargs = dict(timeout_seconds=timeout, max_txs=max_txs, selected_chains=["ton"], include_experimental=True)
        if progress and accepts_progress:
            kwargs["progress"] = relay
        if deadline is not None and supports("deadline"):
            kwargs["deadline"] = deadline
        if continuous and supports("continuous"):
            kwargs["continuous"] = True
        if continuous and supports("on_checkpoint"):
            kwargs["on_checkpoint"] = owner_checkpoint
        report, graph = await address_analyzer(text, **kwargs)
        emit("address.complete", target=text, transactions=len(report.transactions))
        report.warnings.append("ton_nft: input discovery unavailable: " + str(sanitize_observation(str(exc))))
        report.input_resolution = {"original_query": sanitize_observation(text), "object_type": "unknown_ton_account",
                                   "discovery_status": "unavailable", "owner_analysis_status": "not_started"}
        report.coverage["pipeline_diagnostics"] = diagnostics
        return report, graph

    resolution = resolve_verified_nft_owner(nft)
    primary = nft.discovery
    target = resolution.get("owner_address") if resolution else None
    wallet_input = ton_address and nft.scope == "wallet"
    if not target and wallet_input:
        target = ton_address
    if target:
        report = await owner_task if owner_task and target == analysis_target else await analyze_target(target)
        attach_nft_intelligence(report, nft)
        report.target_address = target
    else:
        if owner_task:
            await owner_task
        report = report_to_address_report(nft)
    if ready_task:
        await ready_task
    info = dict(resolution or getattr(nft, "input_resolution", {}) or {})
    info.update({"original_query": sanitize_observation(text),
                 "normalized_query": primary.normalized_query if primary else ton_address,
                 "input_kind": primary.query_kind if primary else "unknown",
                 "object_type": info.get("object_type") or ("ton_account" if wallet_input else nft.scope if primary and primary.status == "resolved" else "unknown"),
                 "discovery_status": primary.status if primary else "unresolved",
                 "owner_analysis_address": target if resolution else None,
                 "owner_analysis_status": ("failed" if owner_failed else "partial" if report.errors or report.warnings else "completed") if resolution else "not_started",
                 "search_mode": SEARCH_MODE})
    if resolution:
        info["onchain_owner_address"] = resolution["owner_address"]
        info["nft_item_address"] = resolution.get("nft_item_address") or resolution.get("nft_address")
        account = resolution.get("owner_account") or {}
        info["owner_account_type"] = resolution.get("owner_account_type") or account.get("account_type") or "unknown"
        info["owner_account_evidence"] = account
        info["notes"] = list(dict.fromkeys(info.get("notes", []) + [
            "The on-chain owner may be a marketplace, escrow or other contract; ownership does not identify a physical person."]))
    report.input_resolution = info
    await retain_model(report)
    from app.attribution.engine import correlate_attribution
    await owned_thread_call(correlate_attribution, report)
    emit("graph.start")
    was_stopped = (nft.stats.get("stopped") or report.coverage.get("search_execution", {}).get("status") == "stopped")
    report.coverage["search_execution"] = {
        "status": "stopped" if was_stopped else "failed" if owner_failed else "completed", "data_complete": False,
        "note": "Execution finished; source coverage and retained subsets do not establish complete on-chain history."}
    report.coverage["pipeline_diagnostics"] = diagnostics
    # Store the owner's ordinary dossier alongside the existing NFT snapshot so
    # offline re-export retains balances/analytics without another network run.
    # Excluding the attached payload prevents recursive snapshots.
    if target:
        from app.ton_nft.storage import InvestigationStore
        nft.input_resolution = info
        owner_snapshot_current = can_replace_owner(report)
        if owner_snapshot_current:
            nft.owner_analysis_snapshot = report.model_dump(mode="json", exclude={"nft_intelligence"})
        # NFT, owner and ready tasks have all joined before this final stage.
        # Save the same read-only nested data through a private top-level model;
        # the worker owns its SQLite connection and is drained on cancellation.
        snapshot = nft.model_copy()
        snapshot_saved = False
        def save_final_snapshot():
            nonlocal snapshot_saved
            store = InvestigationStore(options.get("store_path"))
            try:
                store.save_snapshot(snapshot)
            finally:
                store.close()
            snapshot_saved = True
        try:
            await owned_thread_call(save_final_snapshot)
        finally:
            # Publish only the storage function's existing mutable metadata.
            nft.updated_at = snapshot.updated_at
            nft.owner_snapshot_reference = snapshot.owner_snapshot_reference
            if snapshot_saved:
                nft.owner_analysis_snapshot = None
        scoped_ownership = report.nft_intelligence.get("ownership_scope", {})
        scoped_items = {item["address"]: item.get("wallet_relationship", {})
            for item in report.nft_intelligence.get("assets", [])}
        report.nft_intelligence = nft.model_dump(mode="json", exclude={"owner_analysis_snapshot"})
        report.nft_intelligence["ownership_scope"] = scoped_ownership
        for item in report.nft_intelligence.get("assets", []):
            item["wallet_relationship"] = scoped_items.get(item["address"], {})
        report.nft_intelligence["owner_analysis_reference"] = {"location": "parent_address_report" if owner_snapshot_current else "snapshot_store",
            "exclude": ["nft_intelligence"], "snapshot_store": str(Path(options.get("store_path") or "output/investigations.sqlite3").resolve()),
            "investigation_id": nft.investigation_id}
    graph = await asyncio.to_thread(build_graph_payload, report)
    emit("graph.complete", nodes=len(graph.get("nodes", [])), edges=len(graph.get("edges", [])))
    return report, graph


def _value(value: Any) -> str:
    return str(getattr(value, "value", value))


def print_nft_summary(result: Any, paths: dict[str, Path], console: Console,
                      language: str = "ru") -> None:
    """Report saved artifacts separately from discovery/coverage success."""
    from app.utils.security import sanitize_observation
    ru = language != "en"
    console.print(Text("[+] GANSAR report saved" if not ru else "[+] Отчёт GANSAR сохранён", style="green"))
    fields = [
        ("ID", result.investigation_id),
        ("Запрос" if ru else "Query", sanitize_observation(result.query)),
        ("Статус исследования" if ru else "Investigation status", result.status),
        ("Поиск" if ru else "Discovery", getattr(result.discovery, "status", "unknown")),
        ("NFT", str(len(result.assets))),
        ("Владелец проверен get-методом" if ru else "Owner verified by get method",
         str(sum(_value(a.current_owner_status) == "verified_onchain" for a in result.assets))),
        ("События" if ru else "Events", str(len(result.events))),
        ("Evidence", str(len(result.evidence))),
        ("Coverage", ", ".join(f"{k}: {v}" for k, v in Counter(_value(getattr(c, "coverage_status", c.status)) for c in result.coverage).items()) or "UNKNOWN"),
    ]
    for label, value in fields:
        console.print(Text(f"  {label}: {value}"))
    if result.portfolio:
        console.print(Text(f"  Current holdings: {len(result.portfolio.current_holdings)}; "
                           f"reported: {len(result.portfolio.reported_holdings)}; "
                           f"historical: {len(result.portfolio.historical_holdings)}"))
    for label in ("html", "pdf"):
        if label in paths:
            console.print(Text(f"  {label.upper()}: {paths[label].resolve()}"))
    if any(label not in {"html", "pdf", "pdf_status", "pdf_notice"} for label in paths):
        console.print(Text("  Technical exports requested." if not ru else "  Технические экспорты сохранены по явному запросу."))
    if "pdf_status" in paths:
        status = json.loads(paths["pdf_status"].read_text(encoding="utf-8"))
        console.print(Text(f"  PDF renderer: {status['status']}" + (f" ({status['error']})" if status.get("error") else ""),
                           style="yellow" if status["status"] != "rendered" else "green"))
    for message in (list(result.errors) + list(result.warnings))[:4]:
        console.print(Text("  [!] " + str(sanitize_observation(message)), style="yellow"))
    console.print(Text(
        "Полнота определяется coverage; файл досье не означает полную историю."
        if ru else "Completeness is defined by coverage; a saved dossier does not imply full history.",
        style="grey62"))


async def analyze_and_export_ton_nft(
    query: str,
    output_dir: Path | None = None,
    *, mode: str = SEARCH_MODE, scope: str = "auto", budget: Any = None,
    investigation_id: str | None = None, resume: bool = False,
    incremental: bool = False, store_path: Path | None = None,
    language: str = "ru", pdf: bool = False, providers: Any = None,
    machine_exports: bool = False,
) -> tuple[Any, dict[str, Path]]:
    from app.ton_nft.service import investigate_ton_nft
    from app.exporters.nft_exporter import export_nft_dossier
    result = await investigate_ton_nft(
        query, mode=SEARCH_MODE, scope=scope, budget=budget,
        investigation_id=investigation_id, resume=resume,
        incremental=incremental, store_path=store_path, providers=providers,
    )
    destination = output_dir or Path("output")
    paths = export_nft_dossier(result, destination, language=language, machine_exports=machine_exports)
    if machine_exports:
        _add_raw_observations(result, paths, destination, store_path)
    if pdf:
        await _add_pdf_export(paths, destination)
    return result, paths


def _add_raw_observations(result: Any, paths: dict[str, Path], destination: Path,
                          store_path: Path | None) -> None:
    """Stream persisted responses into a portable evidence file, without HTTP."""
    from app.ton_nft.storage import InvestigationStore
    from app.utils.security import sanitize_observation
    if not result.observations:
        return
    store = InvestigationStore(store_path)
    path = destination / "raw_observations.jsonl"
    temporary = path.with_suffix(".jsonl.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            for reference in result.observations:
                raw = store.observation(result.investigation_id, reference.observation_id)
                stream.write(json.dumps(sanitize_observation(raw.model_dump(mode="json")), ensure_ascii=False) + "\n")
        temporary.replace(path)
        paths["observations"] = path
    finally:
        store.close()


async def _add_pdf_export(paths: dict[str, Path], destination: Path) -> None:
    """Keep the completed dossier available when a local PDF renderer fails."""
    from app.exporters.nft_exporter import export_nft_pdf
    from app.utils.security import sanitize_observation
    try:
        paths["pdf"] = await export_nft_pdf(paths["html"], destination / "report.pdf")
        status = {"status": "rendered", "scope": "static visual excerpt; full collected records remain in machine exports"}
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        status = {"status": "unavailable", "error": str(sanitize_observation(str(exc)))}
        notice = destination / "report.pdf"
        if notice.exists():
            paths["pdf_notice"] = notice
    status_path = destination / "pdf_status.json"
    status_path.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")
    paths["pdf_status"] = status_path


async def enrich_ton_address_report(report: Any, *, store_path: Path | None = None,
                                    budget: Any = None, mode: str = SEARCH_MODE, scope: str = "auto",
                                    investigation_id: str | None = None, resume: bool = False,
                                    incremental: bool = False) -> Any:
    """Preserve legacy wallet fields; attach full versioned NFT report additively."""
    from app.ton_nft.models import InvestigationBudget
    from app.utils.ton_normalize import ton_canonical_address
    if "ton" not in report.detected_chains or not ton_canonical_address(report.target_address):
        return report
    from app.ton_nft.service import investigate_ton_nft, attach_nft_intelligence
    try:
        nft = await investigate_ton_nft(
            report.target_address, scope=scope, mode=SEARCH_MODE, store_path=store_path,
            budget=budget or InvestigationBudget.for_mode(SEARCH_MODE), investigation_id=investigation_id,
            resume=resume, incremental=incremental,
        )
        attach_nft_intelligence(report, nft)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        from app.utils.security import sanitize_observation
        report.warnings.append("ton_nft: enrichment unavailable: " + str(sanitize_observation(str(exc))))
    return report


def command_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GANSAR: address and TON NFT intelligence")
    command = parser.add_mutually_exclusive_group()
    command.add_argument("--ton-nft", metavar="QUERY", help=argparse.SUPPRESS)
    command.add_argument("--reexport", metavar="ID", help="Export a saved investigation with no provider calls")
    command.add_argument("--address", "--query", metavar="QUERY", help="Investigate an address, .ton domain, collectible username or gift")
    command.add_argument("--update-attribution-datasets", action="store_true", help="Explicit bounded refresh of public attribution catalogues; no address search")
    parser.add_argument("--attribution-store", type=Path, help="Local attribution snapshot path (also GANSAR_ATTRIBUTION_DATASET)")
    parser.add_argument("--attribution-sources", type=Path, help="Reviewed source configuration for explicit catalogue update")
    parser.add_argument("--scope", choices=["auto", "item", "collection", "wallet", "trace"], default="auto")
    # Accepted for old command lines; all user searches use SEARCH_MODE.
    parser.add_argument("--mode", choices=["standard", "deep"], default=SEARCH_MODE, help=argparse.SUPPRESS)
    parser.add_argument("--resume", metavar="ID", help="Resume the same persisted query and checkpoint")
    parser.add_argument("--incremental", action="store_true", help="Refresh state and fetch new data into a saved investigation")
    parser.add_argument("--snapshot", type=Path, help="SQLite snapshot store path")
    parser.add_argument("--output", type=Path, help="Output directory (default: output)")
    parser.add_argument("--language", choices=["ru", "en"], default="ru")
    parser.add_argument("--pdf", action="store_true", help="Also create an optional PDF")
    parser.add_argument("--no-pdf", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--machine-exports", action="store_true", help="Explicitly export technical JSON/JSONL/CSV/graph/raw files")
    parser.add_argument("--max-pages", type=int)
    parser.add_argument("--max-events", type=int)
    parser.add_argument("--max-requests", type=int)
    parser.add_argument("--max-items", type=int)
    parser.add_argument("--max-wallets", type=int)
    parser.add_argument("--max-transaction-details", type=int, help="Bound full transaction enrichment (0 disables)")
    parser.add_argument("--trace-depth", type=int)
    parser.add_argument("--deadline", type=float, help="NFT provider sub-budget in seconds; the managed investigation continues after its first HTML")
    parser.add_argument("--page-size", type=int)
    parser.add_argument("--request-timeout", type=float)
    parser.add_argument("--requests-per-second", type=float)
    return parser


def budget_from_args(args: argparse.Namespace) -> Any:
    from app.ton_nft.models import InvestigationBudget
    overrides = {
        name: getattr(args, name, None) for name in
        ["max_pages", "max_events", "max_requests", "max_items", "max_wallets", "max_transaction_details", "trace_depth",
         "page_size", "request_timeout", "requests_per_second"]
        if getattr(args, name, None) is not None
    }
    if args.deadline is not None:
        overrides["max_seconds"] = args.deadline
    # model_validate enforces bounds; model_copy(update=...) does not validate.
    return InvestigationBudget.model_validate({**InvestigationBudget.for_mode(SEARCH_MODE).model_dump(), **overrides})


async def run_nft_command(args: argparse.Namespace) -> tuple[Any, dict[str, Path]]:
    from app.ton_nft.service import load_investigation
    if args.reexport:
        from app.exporters.nft_exporter import export_nft_dossier
        result = load_investigation(args.reexport, store_path=args.snapshot)
        destination = args.output or Path("output")
        paths = export_nft_dossier(result, destination, language=args.language, machine_exports=args.machine_exports)
        if args.machine_exports:
            _add_raw_observations(result, paths, destination, args.snapshot)
        if args.pdf and not args.no_pdf:
            await _add_pdf_export(paths, destination)
        return result, paths
    query = args.ton_nft or args.address
    if not query:
        raise ValueError("--address QUERY or --reexport ID is required")
    if args.incremental and not args.resume:
        raise ValueError("--incremental requires --resume ID")
    return await analyze_and_export_ton_nft(
        query, args.output, mode=args.mode, scope=args.scope,
        budget=budget_from_args(args), investigation_id=args.resume, resume=bool(args.resume),
        incremental=args.incremental, store_path=args.snapshot, language=args.language,
        pdf=args.pdf and not args.no_pdf, machine_exports=args.machine_exports,
    )
