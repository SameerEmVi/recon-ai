"""
WorkerPool — the bounded asyncio worker pool that runs scheduler Jobs.

Design rules (from the spec):
  * Hard default of 10 concurrent workers; operator-configurable within a
    documented SAFETY_CEILING. Worker count gates JOB concurrency ONLY — every
    outbound request still queues on the shared RateLimiter, so N workers can
    never multiply the request budget.
  * Bounded priority queue with backpressure: submit() blocks when the queue is
    full rather than growing without limit.
  * Task priorities with FIFO tie-break (a monotonic sequence) so equal-priority
    jobs are fair and no job is starved.
  * Duplicate execution prevented by job.dedup_key.
  * Graceful shutdown (drain) and hard cancellation (in-flight → CANCELLED).
  * Live counters: queued / running / terminal tallies for the status command
    and the unified report.

The pool is generic: it is handed an async `runner(job)` that does the actual
work and returns the job's terminal JobState (optionally with a result dict).
The controller wiring that supplies that runner lands in a later increment, so
the pool is unit-testable in isolation with a mock runner.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
from collections import Counter
from collections.abc import Awaitable, Callable

from scheduler.jobs import Job, JobState

log = logging.getLogger("scheduler.pool")

#: Terminal states the runner may return (or the job may already be in).
_DEFAULT_TERMINAL = JobState.COMPLETED

# Outcome a runner may return: nothing (→ COMPLETED), a JobState, or (JobState, result).
Outcome = None | JobState | tuple[JobState, dict | None]
Runner = Callable[[Job], Awaitable[Outcome]]
OnUpdate = Callable[[Job], Awaitable[None]]


def _normalize_outcome(outcome) -> tuple[JobState, dict | None]:
    if outcome is None:
        return _DEFAULT_TERMINAL, None
    if isinstance(outcome, JobState):
        return outcome, None
    if isinstance(outcome, tuple) and outcome and isinstance(outcome[0], JobState):
        return outcome[0], (outcome[1] if len(outcome) > 1 else None)
    return _DEFAULT_TERMINAL, None


class WorkerPool:
    DEFAULT_MAX_WORKERS = 10
    #: Operators may raise --workers above the default, but never past this — a
    #: guardrail against accidentally launching a stampede. Documented in --help.
    SAFETY_CEILING = 50

    def __init__(
        self,
        runner: Runner,
        *,
        max_workers: int = DEFAULT_MAX_WORKERS,
        max_queue: int | None = None,
        default_timeout: float | None = None,
        on_update: OnUpdate | None = None,
        name: str = "pool",
    ) -> None:
        self._runner = runner
        self._max_workers = self._clamp_workers(max_workers)
        # Bounded queue → backpressure. Default is generous but finite.
        self._max_queue = max_queue if (max_queue and max_queue > 0) else max(self._max_workers * 100, 100)
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue(maxsize=self._max_queue)
        self._default_timeout = default_timeout
        self._on_update = on_update
        self._name = name

        self._seq = itertools.count()
        self._submitted: set[str] = set()      # dedup_key of every accepted job
        self._active: dict = {}                # job.id -> Job currently running
        self._terminal: Counter = Counter()    # terminal state value -> count
        self._accepted = 0
        self._deduped = 0
        self._workers: list[asyncio.Task] = []
        self._started = False
        self._closing = False
        self._lock = asyncio.Lock()

    @classmethod
    def _clamp_workers(cls, n: int) -> int:
        try:
            n = int(n)
        except (TypeError, ValueError):
            n = cls.DEFAULT_MAX_WORKERS
        return max(1, min(n, cls.SAFETY_CEILING))

    @property
    def max_workers(self) -> int:
        return self._max_workers

    # ── submission ────────────────────────────────────────────────────────────

    async def submit(self, job: Job) -> bool:
        """Queue a job. Returns False if a job with the same dedup_key was already
        accepted (duplicate execution prevented). Blocks (backpressure) when the
        bounded queue is full."""
        async with self._lock:
            if self._closing:
                return False
            if job.dedup_key in self._submitted:
                self._deduped += 1
                return False
            self._submitted.add(job.dedup_key)
            self._accepted += 1
        await self._queue.put((job.priority, next(self._seq), job))   # awaits if full
        await self._emit(job)                                          # QUEUED
        return True

    def start(self) -> None:
        """Spin up the workers (idempotent)."""
        if self._started:
            return
        self._started = True
        self._workers = [
            asyncio.create_task(self._worker(i), name=f"{self._name}-w{i}")
            for i in range(self._max_workers)
        ]

    # ── workers ─────────────────────────────────────────────────────────────

    async def _worker(self, wid: int) -> None:
        while True:
            _prio, _seq, job = await self._queue.get()
            try:
                await self._run_one(job)
            except asyncio.CancelledError:
                # Hard shutdown mid-job: the job was already marked CANCELLED in
                # _run_one. Re-raise so the worker task actually stops.
                self._queue.task_done()
                raise
            else:
                self._queue.task_done()

    async def _run_one(self, job: Job) -> None:
        self._active[job.id] = job
        try:
            if not job.is_terminal:
                job.transition(JobState.RUNNING)
            await self._emit(job)
            timeout = job.timeout if job.timeout is not None else self._default_timeout
            coro = self._runner(job)
            outcome = await (asyncio.wait_for(coro, timeout) if timeout else coro)
            state, result = _normalize_outcome(outcome)
            if not job.is_terminal:
                try:
                    job.transition(state, result=result)
                except Exception:
                    job.state = state           # runner asserted a terminal state
                    job.result = result
        except asyncio.TimeoutError:
            self._force_terminal(job, JobState.FAILED, error=f"timeout>{timeout}s")
        except asyncio.CancelledError:
            # The job stays in _active; shutdown(cancel=True) marks+emits it in a
            # non-cancelled context so the CANCELLED event is reliably published.
            raise
        except Exception as exc:               # noqa: BLE001 — isolate one job's failure
            self._force_terminal(job, JobState.FAILED, error=str(exc)[:200])
        self._finish(job)
        await self._emit(job)                  # publish the terminal state

    @staticmethod
    def _force_terminal(job: Job, state: JobState, *, error: str | None = None) -> None:
        if job.is_terminal:
            return
        try:
            job.transition(state, error=error)
        except Exception:
            job.state = state
            if error:
                job.error = error

    def _finish(self, job: Job) -> None:
        # Idempotent: only tally a job's terminal state once (guards the small
        # race between a job finishing normally and shutdown's cancel sweep).
        if self._active.pop(job.id, None) is None:
            return
        self._terminal[job.state.value] += 1

    async def _emit(self, job: Job) -> None:
        if self._on_update is None:
            return
        try:
            await self._on_update(job)
        except Exception as exc:               # observability must never break the pool
            log.debug("on_update hook failed for %s: %s", job.dedup_key, exc)

    # ── shutdown ────────────────────────────────────────────────────────────

    async def join(self) -> None:
        """Block until every queued job has been processed."""
        await self._queue.join()

    async def shutdown(self, *, cancel: bool = False) -> None:
        """Graceful (drain then stop) or hard (cancel in-flight + drain queued as
        CANCELLED). Idempotent."""
        self._closing = True
        if not cancel:
            await self._queue.join()
        # Snapshot in-flight jobs BEFORE cancelling the workers, so we can mark +
        # emit their CANCELLED state here (not inside the cancelled worker).
        inflight = list(self._active.values()) if cancel else []
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers = []
        if cancel:
            for job in inflight:
                self._force_terminal(job, JobState.CANCELLED, error="cancelled (shutdown)")
                self._finish(job)
                await self._emit(job)
            # Mark anything still queued as CANCELLED (it never ran).
            while not self._queue.empty():
                try:
                    _p, _s, job = self._queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                self._force_terminal(job, JobState.CANCELLED, error="cancelled (shutdown)")
                self._finish(job)
                await self._emit(job)
                self._queue.task_done()

    # ── introspection ─────────────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "max_workers": self._max_workers,
            "max_queue": self._max_queue,
            "accepted": self._accepted,
            "deduped": self._deduped,
            "queued": self._queue.qsize(),
            "running": len(self._active),
            "terminal": dict(self._terminal),
        }
