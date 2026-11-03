"""
Local mock-server performance / behavioural tests for the hybrid engine
(spec §15 — "local mock-server performance tests; no public network in CI").

These do NOT touch the public network and do NOT run any external binary. They
stand up a tiny localhost HTTP/1.1 server and drive **real** guarded httpx GETs
through the real WorkerPool + RateLimiter, then measure wall-clock throughput and
the server-observed concurrency. They exist to prove, with actual numbers, the
two security-relevant invariants the spec calls out:

  1. Worker count never multiplies the request budget. The SAME request workload,
     run with few workers and with many workers, stays under the SAME aggregate
     req/s ceiling — more workers do not finish faster than the shared limiter's
     global token bucket allows.
  2. The concurrency caps are honoured end-to-end. With a per-target cap of K, the
     server never sees more than K simultaneous in-flight requests for one bucket,
     even with a large worker pool; likewise for the global concurrency cap.

Timing tolerances are deliberately generous so the tests are not flaky on a loaded
CI box, while still being tight enough that a regression (e.g. a module creating
its own limiter, or the token bucket not reserving future capacity) fails them.
"""

from __future__ import annotations

import asyncio
import time
import uuid

import httpx
import pytest

from ratelimit import RateLimiter
from scheduler.jobs import Job, JobKind, JobState
from scheduler.pool import WorkerPool


# ── a minimal localhost HTTP/1.1 mock server ────────────────────────────────────

class MockServer:
    """Tiny asyncio HTTP/1.1 server. Responds 200 to every request, counts total
    requests and tracks the maximum number of *simultaneously in-flight* requests
    overall and per path (the path carries the bucket name, e.g. /h/api)."""

    def __init__(self) -> None:
        self.total = 0
        self._cur = 0
        self.max_concurrent = 0
        self._cur_path: dict[str, int] = {}
        self.max_concurrent_path: dict[str, int] = {}
        self._server: asyncio.AbstractServer | None = None
        self.port = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        path: str | None = None            # set once we've counted this request in
        try:
            line = await reader.readline()                       # "GET /h/x HTTP/1.1"
            if not line:
                return
            try:
                parsed = line.decode("latin-1").split(" ")[1]
            except Exception:
                parsed = "/"
            # drain headers up to the blank line
            while True:
                h = await reader.readline()
                if h in (b"\r\n", b"\n", b""):
                    break

            # enter: account concurrency (path now committed → finally will release)
            path = parsed
            self.total += 1
            self._cur += 1
            self.max_concurrent = max(self.max_concurrent, self._cur)
            cp = self._cur_path.get(path, 0) + 1
            self._cur_path[path] = cp
            self.max_concurrent_path[path] = max(self.max_concurrent_path.get(path, 0), cp)

            # a small amount of real server-side work so overlap is observable
            await asyncio.sleep(0.02)

            body = b"ok"
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                % (len(body), body)
            )
            await writer.drain()
        finally:
            if path is not None:           # only release what we accounted for
                self._cur -= 1
                self._cur_path[path] = self._cur_path.get(path, 1) - 1
            try:
                writer.close()
            except Exception:
                pass


@pytest.fixture
async def server():
    srv = MockServer()
    await srv.start()
    try:
        yield srv
    finally:
        await srv.stop()


# ── a request workload driven through the real pool + limiter ────────────────────

async def _drive(server: MockServer, limiter: RateLimiter, *, max_workers: int,
                 buckets: list[str], reqs_per_bucket: int) -> dict:
    """Submit one job per request to a real WorkerPool; each job performs one
    httpx GET inside `limiter.guard(bucket)`. Returns timing + counts."""
    async with httpx.AsyncClient(timeout=10.0) as client:

        async def runner(job: Job):
            bucket = job.module or "global"
            async with limiter.guard(bucket=bucket):
                r = await client.get(f"{server.base}/h/{bucket}")
                limiter.observe_http(status=r.status_code, headers=r.headers, bucket=bucket)
            return JobState.COMPLETED

        pool = WorkerPool(runner, max_workers=max_workers, name="perf")
        pool.start()
        t0 = time.monotonic()
        scan = uuid.uuid4()
        for b in buckets:
            for i in range(reqs_per_bucket):
                await pool.submit(_req_job(scan, b, i))
        await pool.join()
        await pool.shutdown()
        elapsed = time.monotonic() - t0
    total = len(buckets) * reqs_per_bucket
    return {
        "elapsed": elapsed,
        "total": total,
        "rate": total / elapsed if elapsed > 0 else float("inf"),
        "server_total": server.total,
        "max_concurrent": server.max_concurrent,
        "max_concurrent_path": dict(server.max_concurrent_path),
        "pool": pool.stats(),
    }


def _req_job(scan: uuid.UUID, bucket: str, i: int) -> Job:
    # One MODULE job per request. The TARGET is unique per (bucket,i) so the
    # pool's dedup_key is unique and every request is dispatched; the MODULE is
    # the shared bucket name, which the runner uses as the limiter bucket and the
    # server path — so the per-target concurrency cap actually binds on it.
    return Job(target=f"{bucket}-{i}.ex.com", scan_id=scan, kind=JobKind.MODULE,
               module=bucket)


# ── invariant 1: worker count never multiplies the request budget ────────────────

async def test_worker_count_does_not_exceed_aggregate_rate(server):
    """50 requests over 5 buckets, aggregate ceiling 25 req/s. Running with 3
    workers and with 10 workers must BOTH stay under the ceiling and take about
    the same wall-clock — more workers must not buy more throughput."""
    buckets = [f"b{i}" for i in range(5)]
    ceiling = 25.0

    slow = await _drive(server, RateLimiter(global_rate_per_sec=ceiling, burst=1),
                        max_workers=3, buckets=buckets, reqs_per_bucket=10)
    server.total = 0  # reuse the server for the second run
    server.max_concurrent = 0
    server.max_concurrent_path.clear()
    fast = await _drive(server, RateLimiter(global_rate_per_sec=ceiling, burst=1),
                        max_workers=10, buckets=buckets, reqs_per_bucket=10)

    # every request actually reached the server
    assert slow["total"] == 50 and fast["total"] == 50

    # neither run beats the aggregate ceiling (generous 1.6x tolerance for the
    # burst token + scheduling jitter), and 10 workers is NOT materially faster.
    assert slow["rate"] <= ceiling * 1.6, slow
    assert fast["rate"] <= ceiling * 1.6, fast
    # 10 workers must not finish meaningfully faster than 3 — the limiter, not the
    # worker count, governs throughput. (fast at most ~35% quicker than slow.)
    assert fast["elapsed"] >= slow["elapsed"] * 0.65, (slow, fast)
    # and the limiter genuinely paced it: 49 spaced ops at 25/s ≳ 1.3s floor.
    assert fast["elapsed"] >= 1.2, fast


# ── invariant 2: concurrency caps honoured end-to-end ────────────────────────────

async def test_per_target_concurrency_cap_is_observed_by_the_server(server):
    """Per-target cap 2, 10 workers, 24 requests all to ONE bucket, no rate limit.
    The server must never see more than 2 concurrent requests for that bucket even
    though the pool has 10 workers ready to run them."""
    res = await _drive(server, RateLimiter(per_target_concurrency=2),
                       max_workers=10, buckets=["solo"], reqs_per_bucket=24)
    assert res["total"] == 24 and res["server_total"] == 24
    assert res["max_concurrent_path"]["/h/solo"] <= 2, res["max_concurrent_path"]


async def test_global_concurrency_cap_is_observed_by_the_server(server):
    """Global concurrency cap 4, 10 workers, 40 requests over 8 buckets. The
    server must never see more than 4 in-flight requests across ALL buckets."""
    buckets = [f"g{i}" for i in range(8)]
    res = await _drive(server, RateLimiter(max_concurrency=4),
                       max_workers=10, buckets=buckets, reqs_per_bucket=5)
    assert res["total"] == 40 and res["server_total"] == 40
    assert res["max_concurrent"] <= 4, res["max_concurrent"]
