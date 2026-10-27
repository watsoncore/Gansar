"""Owned continuous session for the existing GANSAR pipeline; no user menu."""
from __future__ import annotations
import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import shutil
import sys
import time


def _parent_alive(pid):
    if not pid:
        return True
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x100000, False, pid)
        if not handle:
            return False
        try:
            return kernel.WaitForSingleObject(handle, 0) == 258
        finally:
            kernel.CloseHandle(handle)
    return os.getppid() == pid


async def execute(request):
    from app import main
    from app.models.report import AddressReport
    from app.graph.builder import build_graph_payload
    from app.search_runtime import atomic_pickle
    from app.utils.detect import detect_candidates
    from app.nft_cli import looks_like_nft_input
    from app.utils.http import close_shared_clients
    from app.utils.public_history_cache import history_cache
    from app.utils.security import sanitize_observation
    main.LANGUAGE = request["language"]
    started = asyncio.get_running_loop().time()
    deadline = started + request["collection_seconds"]
    session = Path(request["session"])
    stop_reason = None

    async def job(index, item):
        query, output = item["query"], Path(item["output"])
        record = session / f"job_{index}.pickle"
        latest = None
        model_generation = 0
        initial_ready = False
        sequence = 0
        def progress(event):
            # A closed owner pipe is handled by the parent-liveness monitor;
            # it must not interrupt saving observations already obtained.
            try:
                sys.stdout.write(json.dumps({"job": index, "event": sanitize_observation(event)}, ensure_ascii=False, default=str)+"\n")
                sys.stdout.flush()
            except (BrokenPipeError, OSError):
                pass
        def saved(report, html, pdf=None, complete=False):
            nonlocal latest
            generation = report.coverage.get("checkpoint_generation", {}).get("sequence", 0)
            if not complete and generation < model_generation:
                # An earlier renderer can finish after a newer collection
                # model was atomically committed. Its HTML remains a partial
                # view; never replace the newer durable model with that view.
                progress({"stage": "checkpoint.render.superseded", "generation": generation,
                    "latest_model_generation": model_generation, "transactions": len(report.transactions)})
                return False
            from app.aggregator.collection_audit import refresh_audit
            refresh_audit(report, "snapshot", location=str(record), atomic_commit=True)
            latest = (report, html, pdf, complete)
            atomic_pickle(record, latest)
            return True
        def retain_model(report):
            nonlocal model_generation
            model_generation += 1
            report.coverage["checkpoint_generation"] = {"sequence": model_generation}
            if latest:
                report.coverage.setdefault("search_execution", {}).update({"data_complete": False,
                    "phase": "rendering", "retained_model_records": len(report.transactions),
                    "html_pending_update": True})
                saved(report, latest[1], latest[2], False)
                progress({"stage": "checkpoint.model.saved", "transactions": len(report.transactions),
                    "html_pending_update": True})

        async def on_checkpoint(report, graph, path):
            nonlocal initial_ready, sequence
            sequence += 1
            report.coverage["investigation_lifecycle"] = {"phase": "deep_running", "checkpoint": sequence,
                "elapsed_seconds": asyncio.get_running_loop().time()-started, "data_complete": False,
                "first_result_target_seconds": request.get("first_result_seconds", 60)}
            durable = saved(report, path)
            meaningful = bool(report.transactions or report.balances or report.ton_service_intelligence
                or report.input_resolution.get("owner_analysis_address"))
            phase = "intermediate"
            if meaningful and not initial_ready:
                initial_ready = True
                phase = "first"
                atomic_pickle(session / f"job_{index}_first.pickle", (report, path, None, False))
                progress({"stage": "initial_html.ready", "path": str(path),
                    "elapsed_seconds": asyncio.get_running_loop().time()-started,
                    "transactions": len(report.transactions), "status": "preliminary"})
                progress({"stage": "investigation.deep", "status": "running",
                    "message": "First HTML ready; the same investigation continues automatically"})
            elif meaningful:
                progress({"stage": "investigation.checkpoint", "path": str(path),
                    "transactions": len(report.transactions), "assets": len(report.ton_assets),
                    "checkpoint": sequence, "status": "running"})
            if meaningful:
                shutil.copyfile(path, session / f"job_{index}_{phase}.html")
            with (session / f"job_{index}_checkpoints.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"sequence": sequence, "phase": phase,
                    "elapsed_seconds": asyncio.get_running_loop().time()-started,
                    "transactions": len(report.transactions), "assets": len(report.ton_assets),
                    "model_generation": report.coverage.get("checkpoint_generation", {}).get("sequence", 0),
                    "durable_model_updated": durable,
                    "nft_events": len((report.nft_intelligence or {}).get("events", [])),
                    "counterparties": len(report.counterparties), "html_bytes": Path(path).stat().st_size,
                    "saved_at": datetime.now(timezone.utc).isoformat()}, ensure_ascii=False)+"\n")
        try:
            chains = detect_candidates(query)
            if not chains:
                # The worker bootstraps the same name input handled by the
                # main resolver. Syntax classification schedules no RPC and
                # never supplies a wallet address before forward resolution.
                from app.sources.ethereum_ens import normalize_name
                try:
                    normalized_name = normalize_name(query)
                except ValueError:
                    normalized_name = ""
                if normalized_name.endswith(".eth"):
                    chains = ["eth"]
            if not chains and not looks_like_nft_input(query):
                raise ValueError("Unknown input format; no collectors scheduled")
            fallback = AddressReport(target_address=query, detected_chains=chains or ["ton"],
                warnings=["Initial recovery checkpoint: collection is running. History and attribution are UNKNOWN until supported by evidence."],
                coverage={"search_execution": {"status": "running", "data_complete": False, "reason": "bootstrap"},
                    "investigation_lifecycle": {"phase": "resolving", "data_complete": False}})
            path = await main._write_search_html(fallback, build_graph_payload(fallback), output, progress, checkpoint=True)
            saved(fallback, path)
            options = dict(item.get("nft_options") or {})
            if options.get("store_path"):
                options["store_path"] = Path(options["store_path"])
            with history_cache(Path(options.get("store_path") or "output/investigations.sqlite3").parent / "public_history_cache.sqlite3", progress):
                report, html, pdf = await main._analyze_quiet(query, output,
                    timeout=item.get("timeout", 18.0), max_txs=item.get("max_txs", main.SEARCH_MAX_TRANSACTIONS),
                    selected_chains=item.get("selected_chains"), nft_options=options,
                    pdf=item.get("pdf", False), machine_exports=item.get("machine_exports", False),
                    progress=progress, close_clients=False, deadline=deadline,
                    continuous=True, checkpoint_callback=on_checkpoint, model_callback=retain_model)
            report.coverage["investigation_lifecycle"] = {"phase": "stopped" if stop_reason else "finished",
                "reason": stop_reason or "available_streams_finished", "data_complete": False,
                "elapsed_seconds": asyncio.get_running_loop().time()-started,
                "first_html_ready": initial_ready, "checkpoints": sequence}
            if stop_reason:
                report.coverage["search_execution"] = {"status": "stopped", "data_complete": False,
                    "reason": stop_reason, "checkpoint_retained": True}
            # Normal completion was already exported once by the pipeline.
            # A stop arriving during its final export needs a visible update.
            if stop_reason:
                html = await main._write_search_html(report, build_graph_payload(report), output, progress)
            saved(report, html, pdf, True)
            if not initial_ready and (report.transactions or report.balances or report.input_resolution.get("owner_analysis_address")):
                initial_ready = True
                atomic_pickle(session / f"job_{index}_first.pickle", (report, html, pdf, True))
                shutil.copyfile(html, session / f"job_{index}_first.html")
                progress({"stage": "initial_html.ready", "path": str(html), "status": "final",
                    "elapsed_seconds": asyncio.get_running_loop().time()-started,
                    "transactions": len(report.transactions)})
            progress({"stage": "investigation.stopped" if stop_reason else "investigation.complete",
                "status": "stopped" if stop_reason else "finished", "transactions": len(report.transactions),
                "path": str(html), "data_complete": False})
        except asyncio.CancelledError:
            # Individual stages normally return retained data on cancellation.
            # If cancellation interrupts CPU/export orchestration, the last
            # atomic checkpoint still receives an explicit stopped lifecycle.
            if latest:
                report, html, pdf, _ = latest
                report.coverage["search_execution"] = {"status": "stopped", "data_complete": False,
                    "reason": stop_reason or "cancelled", "checkpoint_retained": True}
                report.coverage["investigation_lifecycle"] = {"phase": "stopped", "reason": stop_reason or "cancelled"}
                html = await main._write_search_html(report, build_graph_payload(report), output, progress, checkpoint=True)
                saved(report, html, pdf, True)
                progress({"stage": "investigation.stopped", "path": str(html), "status": "stopped"})
        except Exception as exc:
            (session / f"job_{index}_error.json").write_text(json.dumps({"error": sanitize_observation(str(exc)),
                "exception_type": type(exc).__name__}, ensure_ascii=False), encoding="utf-8")
            progress({"stage": "search.error", "error": sanitize_observation(str(exc))})
    semaphore = asyncio.Semaphore(4)
    async def bounded_job(index, item):
        async with semaphore:
            await job(index, item)
    tasks = [asyncio.create_task(bounded_job(index, item)) for index, item in enumerate(request["jobs"])]
    async def watch_owner():
        nonlocal stop_reason
        while any(not task.done() for task in tasks):
            stop = session / "stop.json"
            if stop.exists():
                try:
                    stop_reason = json.loads(stop.read_text(encoding="utf-8")).get("reason", "user_stop")
                except (ValueError, OSError):
                    stop_reason = "user_stop"
            elif not _parent_alive(request.get("parent_pid")):
                stop_reason = "parent_closed"
            if stop_reason:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                return
            await asyncio.sleep(.25)
    monitor = asyncio.create_task(watch_owner())
    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        monitor.cancel()
        await asyncio.gather(monitor, return_exceptions=True)
        await close_shared_clients()
        from app.utils.http import ton_public_rate_metrics
        (session / "provider_rate_metrics.json").write_text(json.dumps(ton_public_rate_metrics(),
            ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    asyncio.run(execute(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))))
