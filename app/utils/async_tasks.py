"""Await one synchronous stage while retaining ownership through cancellation."""
from __future__ import annotations
import asyncio


async def owned_thread_call(function, /, *args, **kwargs):
    """Do not leave a model-mutating thread running after its caller exits.

    This is the same shield/drain ownership used by managed HTML writes and
    resume loads. Calls are awaited, never queued as background enrichment.
    The existing investigation/checkpoint lifetimes bound the number of jobs.
    """
    working = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    try:
        return await asyncio.shield(working)
    except asyncio.CancelledError:
        # Cancelling an asyncio wrapper cannot interrupt synchronous Python.
        # Keep the same task owned and retrieve its result before propagating
        # cancellation; a second stop request cannot orphan this stage.
        while not working.done():
            try:
                await asyncio.shield(working)
            except asyncio.CancelledError:
                continue
        working.result()
        raise
