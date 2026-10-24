"""
recon/proc.py — process-tree termination on timeout/cancellation (real procs).

Proves a timed-out or cancelled tool is actually killed and reaped (no orphan
left hitting the target), and that normal completion is unaffected.
"""

from __future__ import annotations

import asyncio
import sys

import pytest

from recon.proc import communicate, new_session_kwargs, terminate_tree


async def _sleeper(secs: int = 30):
    return await asyncio.create_subprocess_exec(
        sys.executable, "-c", f"import time; time.sleep({secs})",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        **new_session_kwargs(),
    )


async def test_timeout_kills_and_reaps():
    proc = await _sleeper()
    with pytest.raises(asyncio.TimeoutError):
        await communicate(proc, timeout=0.5)
    # Already terminated + reaped by communicate().
    await asyncio.wait_for(proc.wait(), timeout=5)
    assert proc.returncode is not None   # dead, not orphaned


async def test_cancellation_kills_and_reaps():
    proc = await _sleeper()
    task = asyncio.ensure_future(communicate(proc, timeout=30))
    await asyncio.sleep(0.3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.wait_for(proc.wait(), timeout=5)
    assert proc.returncode is not None   # killed on cancel, not left running


async def test_normal_completion_unaffected():
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-c", "print('hi')",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        **new_session_kwargs(),
    )
    out, _ = await communicate(proc, timeout=10)
    assert b"hi" in out and proc.returncode == 0


async def test_terminate_tree_idempotent_on_dead_proc():
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-c", "pass",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        **new_session_kwargs(),
    )
    await asyncio.wait_for(proc.wait(), timeout=5)
    await terminate_tree(proc)   # must not raise on an already-dead process


def test_new_session_kwargs_shape():
    kw = new_session_kwargs()
    if sys.platform == "win32":
        assert kw == {}
    else:
        assert kw == {"start_new_session": True}
