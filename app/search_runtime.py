"""Manage one continuous invocation of the existing investigation pipeline.

The first useful HTML is a checkpoint, never a reason to terminate collection.
The child and all batch jobs belong to this foreground session. Stop requests
are cooperative; killing is reserved for a worker that cannot finish cleanup.
"""
from __future__ import annotations
import asyncio
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import pickle
import sys
import time
import uuid
from typing import Any

FIRST_RESULT_SECONDS = 60.0
SEARCH_SECONDS = 600.0
WORKER_SECONDS = SEARCH_SECONDS
COLLECTION_SECONDS = SEARCH_SECONDS - 25.0
SHUTDOWN_GRACE_SECONDS = 30.0
FINALIZATION_GRACE_SECONDS = 180.0
MAX_FINALIZATION_GRACE_SECONDS = 900.0


class _ExportDurations:
    """Measure actual renderer wall time independently for every batch job."""
    def __init__(self):
        self.started = {}
        self.started_rows = {}
        self.large_completed_seconds = {}
        self.final_started = {}
        self.final_graph_started = {}
        self.model_rows = {}
        self.max_completed_seconds = 0.0
        self.max_model_rows = 0

    def observe(self, index, event, *, now=None):
        now = time.monotonic() if now is None else now
        stage = event.get("stage", "")
        if stage in {"html.start", "checkpoint.html.start"}:
            # Duplicate progress must not restart an in-flight export's clock.
            key = (index, stage.removesuffix(".start"))
            if key not in self.started:
                self.started[key] = now
                rows = event.get("transactions")
                self.started_rows[key] = (max(0, int(rows))
                    if isinstance(rows, (int, float)) and math.isfinite(rows)
                    else 0)
            if stage == "html.start":
                self.final_started.setdefault(index, now)
        elif stage in {"html.complete", "checkpoint.html.complete"}:
            key = (index, stage.removesuffix(".complete"))
            began = self.started.pop(key, None)
            rows = self.started_rows.pop(key, 0)
            if began is not None:
                elapsed = max(0.0, now-began)
                self.max_completed_seconds = max(self.max_completed_seconds, elapsed)
                if rows >= 1000:
                    self.large_completed_seconds[index] = max(self.large_completed_seconds.get(index, 0.0), elapsed)
        elif stage == "graph.start":
            # The final graph phase also owns the preceding durable owner
            # snapshot. Checkpoint graphs use a different stage entirely.
            self.final_graph_started.setdefault(index, now)
        elif stage in {"investigation.complete", "investigation.stopped", "search.error"}:
            # html.complete precedes the final atomic model commit. Keep its
            # original bounded reservation until the worker confirms the job.
            self.final_started.pop(index, None)
            self.final_graph_started.pop(index, None)
            self.large_completed_seconds.pop(index, None)
            for render_stage in ("html", "checkpoint.html"):
                self.started.pop((index, render_stage), None)
                self.started_rows.pop((index, render_stage), None)
        rows = event.get("transactions")
        if isinstance(rows, (int, float)) and math.isfinite(rows):
            self.max_model_rows = max(self.max_model_rows, max(0, int(rows)))
            self.model_rows[index] = max(self.model_rows.get(index, 0), max(0, int(rows)))


def _finalization_grace(reason, observed_export_seconds=0.0, *, large_model=False):
    """Bound final CPU/atomic IO using measured render cost, never API time.

    The shutdown ratio preserves short fault-test clocks and remains finite
    even when an unresponsive worker has never completed an export.
    """
    ceiling = min(MAX_FINALIZATION_GRACE_SECONDS, 30*SHUTDOWN_GRACE_SECONDS)
    final_base = min(FINALIZATION_GRACE_SECONDS, 6*SHUTDOWN_GRACE_SECONDS)
    observed = (max(0.0, float(observed_export_seconds))
        if isinstance(observed_export_seconds, (int, float)) and math.isfinite(observed_export_seconds) else 0.0)
    if reason == "session_budget":
        requested = final_base + 4*observed
    elif large_model or 4*observed > SHUTDOWN_GRACE_SECONDS:
        requested = max(SHUTDOWN_GRACE_SECONDS, final_base + 4*observed)
    else:
        requested = SHUTDOWN_GRACE_SECONDS
    return min(ceiling, requested)


def _late_final_export_deadline(reason, exports, *, finish_started, initial_deadline):
    """Give actual final model/graph/export work one finite shared remainder.

    This is evaluated once when the ordinary drain expires. Checkpoint stage
    names alone cannot reserve final work or renew the absolute hard bound.
    """
    if reason != "session_budget" or exports.max_completed_seconds <= 0:
        return initial_deadline
    ceiling = min(MAX_FINALIZATION_GRACE_SECONDS, 30*SHUTDOWN_GRACE_SECONDS)
    if any(exports.model_rows.get(index, 0) >= 1000 for index in exports.final_graph_started):
        # A real final graph.start follows collection/analysis; TON also joins
        # P1 and saves the owner snapshot in this phase. Share the unused
        # existing ceiling across that CPU/IO, HTML and final atomic commit.
        # The caller evaluates this once; later progress cannot renew it.
        return finish_started + ceiling
    active = list(exports.final_started.values())
    if not active:
        return initial_deadline
    allowance = max(SHUTDOWN_GRACE_SECONDS, 2*exports.max_completed_seconds)
    return min(finish_started + ceiling, max(initial_deadline, max(active) + allowance))


def _late_render_cost_deadline(reason, exports, *, finish_started, initial_deadline, now):
    """Use actual large checkpoint/final render cost once, inside the same cap.

    A start must declare its own frozen model size. Generic progress, later
    model growth and duplicate starts cannot turn a thin render into a large
    one or renew its original measured clock.
    """
    if reason != "session_budget":
        return initial_deadline
    costs = list(exports.large_completed_seconds.values())
    costs.extend(max(0.0, now-began) for key, began in exports.started.items()
        if exports.started_rows.get(key, 0) >= 1000)
    if not costs:
        return initial_deadline
    cost = max(costs)
    ceiling = min(MAX_FINALIZATION_GRACE_SECONDS, 30*SHUTDOWN_GRACE_SECONDS)
    recalibrated = finish_started + _finalization_grace(reason, cost)
    return min(finish_started + ceiling, max(initial_deadline, recalibrated))


def _json(value):
    if isinstance(value, Path):
        return str(value.resolve())
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    raise TypeError(f"Unsupported search option: {type(value).__name__}")


def atomic_pickle(path: Path, value: Any) -> None:
    temporary = path.with_suffix(".writing")
    with temporary.open("wb") as stream:
        pickle.dump(value, stream, protocol=pickle.HIGHEST_PROTOCOL)
    temporary.replace(path)


def load_result(path: Path):
    # Only the just-spawned trusted worker writes this UUID session. Provider
    # data and imported snapshots are never unpickled.
    with path.open("rb") as stream:
        return pickle.load(stream)


class _WindowsWorkerLease:
    """OS fallback: abrupt closure of the owner cannot orphan its child."""
    def __init__(self, pid):
        self.handle = None
        self.error = None
        if os.name != "nt":
            return
        import ctypes
        from ctypes import wintypes
        class Basic(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]
        class Extended(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel = kernel
        handle = kernel.CreateJobObjectW(None, None)
        child = kernel.OpenProcess(0x0101, False, pid)  # SET_QUOTA | TERMINATE
        limits = Extended()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
        try:
            if not handle or not child or not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)) or not kernel.AssignProcessToJobObject(handle, child):
                self.error = ctypes.get_last_error()
                if handle:
                    kernel.CloseHandle(handle)
            else:
                self.handle = handle
        finally:
            if child:
                kernel.CloseHandle(child)

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


async def run_bounded_jobs(jobs: list[dict], *, language="ru", progress=None,
                           deadline: float | None = None, cancel_event=None,
                           return_on_cancel: bool = False) -> list[dict]:
    """Run fast checkpoints and continuous deep work in one owned session.

    ``deadline`` is an optional caller stop boundary, not the first-HTML target.
    Cancellation requests a final save and drains the worker before returning
    or re-raising. An external caller may also set ``cancel_event`` safely.
    """
    from app.utils.security import sanitize_observation
    if not jobs:
        return []
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat()
    limit = min(SEARCH_SECONDS, WORKER_SECONDS)
    stop = min(deadline if deadline is not None else started + limit, started + limit)
    duration = max(.05, stop-started)
    reserve = min(25.0, max(.5, duration * .1))
    collection_seconds = min(COLLECTION_SECONDS, max(.05, duration-reserve))
    session = Path(jobs[0]["output"]).resolve().parent / ".search_sessions" / uuid.uuid4().hex
    session.mkdir(parents=True)
    request = session / "request.json"
    request.write_text(json.dumps({"jobs": jobs, "language": language,
        "collection_seconds": collection_seconds, "first_result_seconds": FIRST_RESULT_SECONDS,
        "session_seconds": duration, "parent_pid": os.getpid(), "session": str(session)},
        default=_json, ensure_ascii=False), encoding="utf-8")
    env = dict(os.environ)
    root = str(Path(__file__).resolve().parents[1])
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    process = await asyncio.create_subprocess_exec(sys.executable, "-B", "-m", "app.search_worker", str(request),
        cwd=root, env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        creationflags=0x08000000 if os.name == "nt" else 0)
    lease = _WindowsWorkerLease(process.pid)
    events = []
    first_results = {}
    reason = None
    emergency_killed = False
    cancelled = False
    callback_error = None
    export_durations = _ExportDurations()

    def deliver(message):
        nonlocal callback_error
        events.append(message)
        event = message.get("event", {})
        index = int(message.get("job", 0))
        export_durations.observe(index, event)
        if event.get("stage") == "initial_html.ready":
            first_results.setdefault(index, time.monotonic()-started)
        if progress and callback_error is None:
            try:
                progress(index, event)
            except Exception as exc:
                callback_error = exc

    async def read_events():
        while True:
            line = await process.stdout.readline()
            if not line:
                return
            try:
                message = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            if isinstance(message, dict) and isinstance(message.get("event", {}), dict):
                deliver(message)

    reader = asyncio.create_task(read_events())
    waiter = asyncio.create_task(process.wait())
    try:
        while not waiter.done():
            if callback_error is not None or (reader.done() and not reader.cancelled() and reader.exception() is not None):
                reason = "progress_callback_error"
                break
            if time.monotonic() >= stop:
                reason = "session_budget"
                break
            if cancel_event is not None and cancel_event.is_set():
                reason = "user_stop"
                break
            await asyncio.wait({waiter}, timeout=min(.15, max(.01, stop-time.monotonic())))
    except asyncio.CancelledError:
        cancelled = True
        reason = "user_stop"
    finally:
        stop_requested = bool(reason and reason != "session_budget")
        if process.returncode is None and stop_requested:
            stop_file = session / "stop.json"
            temporary = session / "stop.writing"
            temporary.write_text(json.dumps({"reason": reason,
                "requested_at": datetime.now(timezone.utc).isoformat()}), encoding="utf-8")
            temporary.replace(stop_file)
            if progress and callback_error is None:
                try:
                    progress(0, {"stage": "investigation.stopping", "status": reason,
                        "session": str(session), "message": "Saving observations and stopping managed streams"})
                except Exception as exc:
                    callback_error = exc
        # Collection already owns its absolute 575-second deadline. Reaching
        # the foreground session budget is a bounded drain, not cancellation
        # of an active atomic export followed by a second fallback export.
        # Large saved dossiers need bounded CPU/IO time proportional to an
        # actually measured export. Provider deadlines remain unchanged.
        finish_grace = _finalization_grace(reason, export_durations.max_completed_seconds,
            large_model=export_durations.max_model_rows >= 1000)
        late_final_export_seconds = 0.0
        late_finalization_phase = None
        if process.returncode is None and reason == "session_budget" and progress and callback_error is None:
            try:
                progress(0, {"stage": "investigation.finalizing", "status": "draining",
                    "session": str(session), "finalization_grace_seconds": finish_grace,
                    "max_completed_export_seconds": export_durations.max_completed_seconds,
                    "message": "Collection budget finished; saving the same final report without extending provider deadlines"})
            except Exception as exc:
                callback_error = exc
        async def finish():
            nonlocal emergency_killed, late_final_export_seconds, late_finalization_phase
            finish_started = time.monotonic()
            try:
                await asyncio.wait_for(asyncio.shield(waiter), timeout=finish_grace)
            except asyncio.TimeoutError:
                initial_deadline = finish_started + finish_grace
                measured_now = time.monotonic()
                final_deadline = _late_final_export_deadline(reason, export_durations,
                    finish_started=finish_started, initial_deadline=initial_deadline)
                render_deadline = _late_render_cost_deadline(reason, export_durations,
                    finish_started=finish_started, initial_deadline=initial_deadline, now=measured_now)
                final_deadline = max(final_deadline, render_deadline)
                remaining = max(0.0, final_deadline-measured_now)
                if remaining:
                    late_final_export_seconds = max(0.0, final_deadline-initial_deadline)
                    late_finalization_phase = ("measured_large_render_cost" if render_deadline > initial_deadline
                        and render_deadline >= final_deadline else "final_graph_owner_store" if any(
                        export_durations.model_rows.get(index, 0) >= 1000
                        for index in export_durations.final_graph_started) else "final_html_atomic_commit")
                    deliver({"job": 0, "event": {"stage": "investigation.final_export_draining",
                        "remaining_seconds": remaining,
                        "additional_grace_seconds": late_final_export_seconds,
                        "reservation_phase": late_finalization_phase,
                        "message": "Finishing final model, graph, HTML and atomic commit within the existing absolute drain ceiling"}})
                    # Render-cost calibration can expire before a later final
                    # graph has finished. It is a measured checkpoint budget,
                    # not a reservation for that not-yet-started final phase.
                    await asyncio.wait({waiter}, timeout=remaining)
                    if (not waiter.done() and late_finalization_phase == "measured_large_render_cost"
                            and any(export_durations.model_rows.get(index, 0) >= 1000
                                for index in export_durations.final_graph_started)):
                        reserved = _late_final_export_deadline(reason, export_durations,
                            finish_started=finish_started, initial_deadline=final_deadline)
                        remainder = max(0.0, reserved-time.monotonic())
                        if reserved > final_deadline and remainder:
                            late_final_export_seconds = max(0.0, reserved-initial_deadline)
                            late_finalization_phase = "final_graph_owner_store"
                            deliver({"job": 0, "event": {"stage": "investigation.final_export_draining",
                                "remaining_seconds": remainder,
                                "additional_grace_seconds": late_final_export_seconds,
                                "reservation_phase": late_finalization_phase,
                                "previous_reservation_phase": "measured_large_render_cost",
                                "message": "Final graph began after render-cost calibration; using only the remainder of the original absolute ceiling"}})
                            # One final fixed reservation. Repeated graph/HTML
                            # progress cannot renew it or restart its clock.
                            await asyncio.wait({waiter}, timeout=remainder)
                if not waiter.done():
                    emergency_killed = True
                    process.kill()
                    await waiter
            await reader
        cleanup = asyncio.create_task(finish())
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            # A second Ctrl+C does not strand the child or interrupt atomic IO.
            cancelled = True
            await cleanup
        finally:
            lease.close()
            if not reader.done():
                reader.cancel()
                await asyncio.gather(reader, return_exceptions=True)
    results = []
    for index, job in enumerate(jobs):
        record = session / f"job_{index}.pickle"
        failure = session / f"job_{index}_error.json"
        if not record.exists():
            detail = json.loads(failure.read_text(encoding="utf-8")) if failure.exists() else {
                "error": "Worker stopped before a usable original HTML checkpoint was saved"}
            results.append({"error": detail.get("error"), "status": "failed"})
            continue
        report, html, pdf, complete = load_result(record)
        if not complete:
            report.coverage["search_execution"] = {"status": "stopped" if reason == "user_stop" else "partial",
                "data_complete": False, "reason": reason or "worker_exit", "checkpoint_retained": True}
        partial = not complete or report.coverage.get("search_execution", {}).get("data_complete") is False
        status = "stopped" if reason == "user_stop" else "partial" if partial else "saved"
        result = {"report": report, "html": html, "pdf": pdf, "status": status}
        if failure.exists():
            detail = json.loads(failure.read_text(encoding="utf-8"))
            result.update({"error": detail.get("error"), "status": "failed"})
        results.append(result)
    timing = {"started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
        "total_seconds": time.monotonic()-started, "first_result_target_seconds": FIRST_RESULT_SECONDS,
        "initial_html_seconds": {str(index): value for index, value in first_results.items()},
        "limit_seconds": duration, "collection_seconds": collection_seconds,
        "shutdown_reason": reason or "natural_completion", "worker_exit_code": process.returncode,
        "worker_terminated": emergency_killed, "cooperative_stop": bool(stop_requested and not emergency_killed),
        "collection_deadline_extended": False, "finalization_grace_seconds": finish_grace,
        "late_final_export_grace_seconds": late_final_export_seconds,
        "late_finalization_reservation_phase": late_finalization_phase,
        "finalization_hard_ceiling_seconds": min(MAX_FINALIZATION_GRACE_SECONDS, 30*SHUTDOWN_GRACE_SECONDS),
        "max_completed_export_seconds": export_durations.max_completed_seconds,
        "max_observed_model_rows": export_durations.max_model_rows,
        "session_budget_reached": reason == "session_budget",
        "parent_death_os_lease": bool(lease.handle) if os.name != "nt" else lease.error is None,
        "session": str(session), "jobs": [{"query": job["query"], "status": result["status"],
            "html": str(result.get("html", ""))} for job, result in zip(jobs, results)],
        "events": sanitize_observation(events)}
    (session / "timing.json").write_text(json.dumps(timing, default=str, ensure_ascii=False), encoding="utf-8")
    for result in results:
        result["runtime"] = {key: value for key, value in timing.items() if key != "events"}
    if callback_error is not None:
        raise callback_error
    if cancelled and not return_on_cancel:
        raise asyncio.CancelledError()
    return results


async def run_bounded_search(query, output, *, progress=None, language="ru", **options):
    results = await run_bounded_jobs([{"query": query, "output": str(Path(output).resolve()), **options}],
        language=language, progress=(lambda index, event: progress(event)) if progress else None,
        return_on_cancel=True)
    result = results[0]
    if result.get("error"):
        raise ValueError(result["error"])
    report = result["report"]
    report.coverage["wall_clock"] = result["runtime"]
    return report, result["html"], result["pdf"]
