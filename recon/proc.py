"""
Subprocess lifecycle helpers — kill the whole process TREE on timeout or
cancellation, then reap it, so a stopped/timed-out scan never leaves orphaned
tool processes (httpx/ffuf/nuclei/…) still hitting the target.

Why a tree, not just `proc.kill()`: some tools spawn children; killing only the
direct child orphans the grandchildren. On POSIX we put each tool in its own
session (`start_new_session=True`) and `killpg` the group; on Windows we
`taskkill /T` the tree. Always followed by a bounded `wait()` to reap the
zombie.

Limitation (documented, honest): if the *Python* process itself is hard-killed
(SIGKILL / external `taskkill /F` of the interpreter), no in-process handler can
run, so children can still orphan — that needs an OS job object and is out of
scope here. These helpers cover the in-process cases: internal timeouts and
task cancellation (Ctrl-C / scan teardown).
"""

from __future__ import annotations

import asyncio
import logging
import sys

log = logging.getLogger("recon.proc")


def new_session_kwargs() -> dict:
    """Spawn kwargs that isolate a child into its own process group/session so
    the whole tree can be killed together. No-op kwargs on Windows (taskkill /T
    walks the tree by PID instead)."""
    if sys.platform != "win32":
        return {"start_new_session": True}
    return {}


async def terminate_tree(proc) -> None:
    """Kill `proc` and its descendants, then reap. Idempotent; never raises."""
    if proc is None or proc.returncode is not None:
        return
    try:
        if sys.platform == "win32":
            try:
                killer = await asyncio.create_subprocess_exec(
                    "taskkill", "/F", "/T", "/PID", str(proc.pid),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(killer.wait(), timeout=5)
            except Exception:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
        else:
            import os
            import signal
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
    except Exception as exc:  # never let cleanup raise
        log.debug("terminate_tree(pid=%s): %s", getattr(proc, "pid", "?"), exc)
    # Reap so the process table doesn't fill with zombies.
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except Exception:
        pass


async def communicate(proc, *, timeout: float | None = None, input: bytes | None = None):
    """`proc.communicate()` under a timeout that kills the whole tree on expiry
    or cancellation before propagating. Returns (stdout, stderr).

    Raises asyncio.TimeoutError on timeout (the tree is already terminated) and
    re-raises CancelledError after terminating — so the caller decides how to
    report it, but the child is always cleaned up.
    """
    try:
        return await asyncio.wait_for(proc.communicate(input=input), timeout=timeout)
    except asyncio.TimeoutError:
        await terminate_tree(proc)
        raise
    except asyncio.CancelledError:
        await terminate_tree(proc)
        raise
