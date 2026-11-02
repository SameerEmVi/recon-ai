"""
Tests for scheduler.pool.WorkerPool: worker cap + safety ceiling, bounded queue
backpressure, task priority + FIFO fairness, job dedup, graceful shutdown, hard
cancellation, counters — and the spec's hard proof that N workers cannot exceed
the configured aggregate request rate (pool + shared RateLimiter together).
"""

from __future__ import annotations

import asyncio
import time
import uuid

import pytest

from ratelimit import RateLimiter
from scheduler.jobs import Job, JobKind, JobState
from scheduler.pool import WorkerPool

SCAN = uuid.uuid4()


def _job(target, *, priority=100, module=None, timeout=None):
    return Job(
        target=target, scan_id=SCAN, priority=priority, timeout=timeout,
        kind=JobKind.MODULE if module else JobKind.TARGET, module=module,
    )


# ── worker cap + ceiling ───────────────────────────────────────────────────────

def test_worker_count_clamped_to_ceiling_and_floor():
    assert WorkerPool(lambda j: None, max_workers=10).max_workers == 10
    assert WorkerPool(lambda j: None, max_workers=1000).max_workers == WorkerPool.SAFETY_CEILING
    assert WorkerPool(lambda j: None, max_workers=0).max_workers == 1
    assert WorkerPool(lambda j: None, max_workers=-5).max_workers == 1


async def test_never_exceeds_configured_workers():
    peak = 0
    active = 0

    async def runner(job):
        nonlocal peak, active
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.03)
        active -= 1
        return JobState.COMPLETED

    pool = WorkerPool(runner, max_workers=3)
    pool.start()
    for i in range(12):
        await pool.submit(_job(f"h{i}.com"))
    await pool.shutdown()
    assert peak <= 3, f"ran {peak} concurrently with a 3-worker cap"
    assert pool.stats()["terminal"].get("COMPLETED") == 12


# ── dedup ──────────────────────────────────────────────────────────────────────

async def test_duplicate_jobs_run_once():
    seen = []

    async def runner(job):
        seen.append(job.dedup_key)
        return JobState.COMPLETED

    pool = WorkerPool(runner, max_workers=2)
    pool.start()
    assert await pool.submit(_job("a.com")) is True
    assert await pool.submit(_job("a.com")) is False      # same dedup_key → rejected
    assert await pool.submit(_job("a.com", module="ffuf")) is True   # different kind/module → ok
    await pool.shutdown()
    assert sorted(seen) == ["module:a.com:ffuf", "target:a.com"]
    assert pool.stats()["deduped"] == 1


# ── priority + fairness (single worker makes ordering deterministic) ────────────

async def test_priority_order_then_fifo():
    order = []

    async def runner(job):
        order.append((job.priority, job.target))
        return JobState.COMPLETED

    pool = WorkerPool(runner, max_workers=1)
    # submit low-priority-number LAST; it must still run first
    await pool.submit(_job("c.com", priority=100))
    await pool.submit(_job("a.com", priority=100))   # same priority → FIFO after c
    await pool.submit(_job("hi.com", priority=1))    # highest priority
    pool.start()
    await pool.shutdown()
    assert order[0] == (1, "hi.com")                 # priority wins
    assert order[1:] == [(100, "c.com"), (100, "a.com")]  # equal priority stays FIFO


# ── bounded queue / backpressure ────────────────────────────────────────────────

async def test_bounded_queue_applies_backpressure():
    release = asyncio.Event()

    async def runner(job):
        await release.wait()                         # hold the one worker busy
        return JobState.COMPLETED

    pool = WorkerPool(runner, max_workers=1, max_queue=2)
    pool.start()
    await pool.submit(_job("a.com"))                 # pulled by the worker (now busy)
    await pool.submit(_job("b.com"))                 # fills queue slot 1
    await pool.submit(_job("c.com"))                 # fills queue slot 2
    # queue is full now; a 4th submit must BLOCK (backpressure), not accept instantly
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(pool.submit(_job("d.com")), timeout=0.1)
    release.set()
    await pool.shutdown()


# ── graceful shutdown + hard cancellation ───────────────────────────────────────

async def test_graceful_shutdown_drains_all():
    done = []

    async def runner(job):
        await asyncio.sleep(0.01)
        done.append(job.target)
        return JobState.COMPLETED

    pool = WorkerPool(runner, max_workers=4)
    pool.start()
    for i in range(10):
        await pool.submit(_job(f"h{i}.com"))
    await pool.join()                                # wait for everything
    assert len(done) == 10
    await pool.shutdown()


async def test_hard_cancel_marks_jobs_cancelled():
    started = asyncio.Event()

    async def runner(job):
        started.set()
        await asyncio.sleep(10)                      # long — will be cancelled
        return JobState.COMPLETED

    cancelled = []

    async def on_update(job):
        if job.state is JobState.CANCELLED:
            cancelled.append(job.target)

    pool = WorkerPool(runner, max_workers=1, on_update=on_update)
    pool.start()
    await pool.submit(_job("a.com"))                 # starts running
    await pool.submit(_job("b.com"))                 # stays queued
    await started.wait()
    await pool.shutdown(cancel=True)                 # cancel in-flight + drain queued
    assert "a.com" in cancelled                      # in-flight cancelled
    assert "b.com" in cancelled                      # queued-but-unrun cancelled
    assert pool.stats()["running"] == 0


# ── failure isolation + timeout ──────────────────────────────────────────────────

async def test_failing_job_isolated_and_recorded():
    async def runner(job):
        if job.target == "bad.com":
            raise RuntimeError("boom")
        return JobState.COMPLETED

    pool = WorkerPool(runner, max_workers=2)
    pool.start()
    await pool.submit(_job("good.com"))
    await pool.submit(_job("bad.com"))
    await pool.shutdown()
    term = pool.stats()["terminal"]
    assert term.get("COMPLETED") == 1 and term.get("FAILED") == 1


async def test_per_job_timeout_fails_the_job():
    async def runner(job):
        await asyncio.sleep(5)
        return JobState.COMPLETED

    pool = WorkerPool(runner, max_workers=1)
    pool.start()
    await pool.submit(_job("slow.com", timeout=0.05))
    await pool.shutdown()
    assert pool.stats()["terminal"].get("FAILED") == 1


# ── THE spec proof: workers don't multiply the request rate ──────────────────────

async def test_workers_cannot_exceed_aggregate_request_rate():
    """10 workers, but a shared RateLimiter capped at 20 req/s global: firing one
    'request' per job across distinct hosts must still obey the aggregate rate —
    worker count must NOT multiply the budget."""
    rate, burst, n = 20.0, 1, 40
    limiter = RateLimiter(global_rate_per_sec=rate, burst=burst)

    async def runner(job):
        async with limiter.guard(bucket=job.target):   # one request per job
            pass
        return JobState.COMPLETED

    pool = WorkerPool(runner, max_workers=10)
    pool.start()
    t0 = time.monotonic()
    for i in range(n):
        await pool.submit(_job(f"host{i}.com"))
    await pool.shutdown()
    elapsed = time.monotonic() - t0
    floor = (n - burst) / rate                         # ~1.95s regardless of 10 workers
    assert elapsed >= floor * 0.9, (
        f"10 workers exceeded the 20 req/s aggregate: {elapsed:.2f}s < {floor:.2f}s")
    assert pool.stats()["terminal"].get("COMPLETED") == n
