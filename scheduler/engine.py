"""
HybridScheduler — subdomain-level + module-level concurrency over the WorkerPool.

It orchestrates, it does not re-implement: scope is enforced through the SAME
ScopeEngine, requests are paced by the SAME shared RateLimiter (inside the
module runner), jobs persist through the SAME Persister, and the single
WorkerPool bounds total concurrency (worker count ≠ request budget).

Two levels of concurrency, both bounded by the one pool:
  * Subdomain level — every in-scope target is scheduled independently and
    concurrently; an out-of-scope target becomes an OUT_OF_SCOPE job and never
    runs; targets are de-duplicated after normalization.
  * Module level — per target, independent modules run concurrently while a
    module with prerequisites waits for them to finish first (a DAG, validated
    acyclic at construction). A failed prerequisite skips its dependents; an
    independent module failing leaves the target PARTIAL, not dead.

The actual "run module M against target T" work is a pluggable async
`module_runner(target, module) -> bool`, so the engine is testable in isolation;
the controller adapter that supplies the real runner lands with the CLI
integration increment.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field

from scheduler import events as ev
from scheduler.events import build_event
from scheduler.jobs import Job, JobKind, JobState
from scheduler.pool import WorkerPool

log = logging.getLogger("scheduler.engine")

ModuleRunner = Callable[[str, str], Awaitable[bool]]
EventHook = Callable[[str, dict], Awaitable[None]]


@dataclass(frozen=True)
class ModuleSpec:
    """One schedulable module and its same-target prerequisites (module names
    that must finish before it may start)."""
    name: str
    requires: frozenset[str] = frozenset()
    priority: int = 100
    timeout: float | None = None
    passive: bool = False


@dataclass
class SchedulerReport:
    targets_total: int = 0
    targets_completed: int = 0
    targets_partial: int = 0
    targets_failed: int = 0
    targets_out_of_scope: int = 0
    modules_run: int = 0
    modules_ok: int = 0
    modules_failed: int = 0
    duration_s: float = 0.0
    pool: dict = field(default_factory=dict)
    limiter: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return self.__dict__.copy()


def _validate_dag(specs: dict[str, ModuleSpec]) -> None:
    """Reject unknown prerequisites and cycles up front (fail-closed)."""
    for s in specs.values():
        for r in s.requires:
            if r not in specs:
                raise ValueError(f"module {s.name!r} requires unknown module {r!r}")
    # DFS cycle check
    WHITE, GREY, BLACK = 0, 1, 2
    color = {n: WHITE for n in specs}

    def visit(n: str, stack: tuple[str, ...]) -> None:
        if color[n] == GREY:
            raise ValueError(f"module dependency cycle: {' -> '.join(stack + (n,))}")
        if color[n] == BLACK:
            return
        color[n] = GREY
        for r in specs[n].requires:
            visit(r, stack + (n,))
        color[n] = BLACK

    for n in specs:
        visit(n, ())


class HybridScheduler:
    def __init__(
        self,
        *,
        scan_id: uuid.UUID,
        scope_engine,
        module_specs: Iterable[ModuleSpec],
        module_runner: ModuleRunner,
        max_workers: int = WorkerPool.DEFAULT_MAX_WORKERS,
        max_queue: int | None = None,
        default_timeout: float | None = None,
        persister=None,
        limiter=None,
        on_event: EventHook | None = None,
    ) -> None:
        self._scan_id = scan_id
        self._scope = scope_engine
        self._specs: dict[str, ModuleSpec] = {s.name: s for s in module_specs}
        _validate_dag(self._specs)
        self._module_runner = module_runner
        self._persister = persister
        self._limiter = limiter
        self._on_event = on_event

        self._pool = WorkerPool(
            self._pool_runner,
            max_workers=max_workers,
            max_queue=max_queue,
            default_timeout=default_timeout,
            on_update=self._on_job_update,
            name="hybrid",
        )
        # job.id -> Future[JobState] resolved when a MODULE job reaches a terminal
        # state (the DAG executor awaits these before releasing dependents).
        self._done: dict[uuid.UUID, asyncio.Future] = {}
        self._seen_targets: set[str] = set()
        self._report = SchedulerReport()

    # ── pool plumbing ─────────────────────────────────────────────────────────

    async def _pool_runner(self, job: Job):
        ok = await self._module_runner(job.target, job.module or "")
        return JobState.COMPLETED if ok else JobState.FAILED

    async def _on_job_update(self, job: Job) -> None:
        # Persist lifecycle + publish an event; never let either break scheduling.
        if self._persister is not None:
            try:
                await self._persister.save_job(job)
            except Exception as exc:
                log.debug("save_job failed: %s", exc)
        if self._on_event is not None:
            name = self._event_name(job)
            if name is not None:
                payload = build_event(name, scan_id=self._scan_id, job=job, error=job.error)
                try:
                    await self._on_event(name, payload)
                except Exception as exc:
                    log.debug("on_event failed: %s", exc)
        if job.is_terminal:
            fut = self._done.get(job.id)
            if fut is not None and not fut.done():
                fut.set_result(job.state)

    def _event_name(self, job: Job) -> str | None:
        if job.kind is JobKind.MODULE:
            return {
                JobState.RUNNING: ev.MODULE_STARTED,
                JobState.COMPLETED: ev.MODULE_COMPLETED,
                JobState.FAILED: ev.MODULE_FAILED,
                JobState.CANCELLED: ev.MODULE_FAILED,
            }.get(job.state)
        return {
            JobState.QUEUED: ev.SUBDOMAIN_JOB_QUEUED,
            JobState.OUT_OF_SCOPE: ev.TARGET_OUT_OF_SCOPE,
            JobState.RUNNING: ev.TARGET_STARTED,
            JobState.COMPLETED: ev.TARGET_COMPLETED,
            JobState.PARTIAL: ev.TARGET_COMPLETED,
            JobState.FAILED: ev.TARGET_COMPLETED,
        }.get(job.state)

    # ── public API ────────────────────────────────────────────────────────────

    async def run(self, targets: Iterable[str]) -> SchedulerReport:
        import time
        t0 = time.monotonic()
        self._pool.start()
        await self._maybe_event(ev.SCAN_STARTED)
        await self._maybe_event(ev.WORKERS_STARTED, count=self._pool.max_workers)

        target_coros = []
        for raw in targets:
            host = (raw or "").strip().lower().rstrip(".")
            if not host or host in self._seen_targets:
                continue                                  # dedup normalized targets
            self._seen_targets.add(host)
            await self._maybe_event(ev.TARGET_DISCOVERED, target=host)
            target_coros.append(self._run_target(host))

        self._report.targets_total = len(target_coros)
        await asyncio.gather(*target_coros, return_exceptions=True)
        await self._pool.shutdown()                       # graceful drain

        import time as _t
        self._report.duration_s = round(_t.monotonic() - t0, 2)
        self._report.pool = self._pool.stats()
        if self._limiter is not None and hasattr(self._limiter, "stats"):
            try:
                self._report.limiter = self._limiter.stats()
            except Exception:
                self._report.limiter = {}
        await self._maybe_event(ev.SCAN_COMPLETED, **self._report.as_dict())
        return self._report

    async def _run_target(self, host: str) -> None:
        target_job = Job(target=host, scan_id=self._scan_id, kind=JobKind.TARGET)

        # ── subdomain-level scope gate: the child never scans a target the scope
        #    engine rejects. (Per-request scope still applies inside the runner.)
        target_job.transition(JobState.VALIDATING)
        await self._on_job_update(target_job)
        decision = self._scope.evaluate(host)
        from scope.types import ScopeStatus
        if decision.status is not ScopeStatus.IN:
            target_job.transition(JobState.OUT_OF_SCOPE, error=decision.reason)
            await self._on_job_update(target_job)
            self._report.targets_out_of_scope += 1
            return

        target_job.transition(JobState.RUNNING)
        await self._on_job_update(target_job)

        # ── module-level DAG for this target ──────────────────────────────────
        jobs: dict[str, Job] = {}
        for name, spec in self._specs.items():
            j = Job(target=host, scan_id=self._scan_id, kind=JobKind.MODULE,
                    module=name, priority=spec.priority, timeout=spec.timeout,
                    parent_id=target_job.id)
            jobs[name] = j
            self._done[j.id] = asyncio.get_running_loop().create_future()

        async def gate(name: str) -> None:
            spec = self._specs[name]
            job = jobs[name]
            # wait for prerequisites (same target) to finish
            prereq_states = await asyncio.gather(
                *(self._done[jobs[r].id] for r in spec.requires)
            ) if spec.requires else []
            if any(st is not JobState.COMPLETED for st in prereq_states):
                # A dependent of a failed/cancelled prerequisite never runs →
                # CANCELLED (QUEUED→CANCELLED is the valid "never ran" transition).
                job.transition(JobState.CANCELLED, error="prerequisite not satisfied")
                await self._on_job_update(job)           # resolves its future too
                return
            await self._pool.submit(job)                 # pool runs it; future set on terminal
            await self._done[job.id]

        results = await asyncio.gather(
            *(gate(n) for n in self._specs), return_exceptions=True
        )
        del results

        # ── roll up the target state from its module jobs ─────────────────────
        states = [j.state for j in jobs.values()]
        self._report.modules_run += len(states)
        self._report.modules_ok += sum(1 for s in states if s is JobState.COMPLETED)
        self._report.modules_failed += sum(1 for s in states if s in (JobState.FAILED, JobState.CANCELLED))
        if not states or all(s is JobState.COMPLETED for s in states):
            target_job.transition(JobState.COMPLETED)
            self._report.targets_completed += 1
        elif any(s is JobState.COMPLETED for s in states):
            target_job.transition(JobState.PARTIAL)
            self._report.targets_partial += 1
        else:
            target_job.transition(JobState.FAILED)
            self._report.targets_failed += 1
        await self._on_job_update(target_job)

    async def _maybe_event(self, name: str, **metadata) -> None:
        if self._on_event is None:
            return
        try:
            await self._on_event(name, build_event(name, scan_id=self._scan_id, **metadata))
        except Exception as exc:
            log.debug("on_event(%s) failed: %s", name, exc)

    # ── runner-facing hooks (wired to the real limiter in the CLI increment) ──
    async def note_waf(self, job: Job, *, vendor: str, reason: str) -> None:
        """Emit a WAF-restriction event (evidence recorded; the shared limiter's
        per-target cooldown does the actual slow-down — we never rotate proxies
        or raise concurrency to bypass it)."""
        await self._maybe_event(ev.WAF_RESTRICTION_DETECTED, target=job.target,
                                module=job.module, vendor=vendor, reason=reason)

    async def note_rate_limited(self, job: Job, *, retry_after: float | None = None) -> None:
        await self._maybe_event(ev.RATE_LIMIT_REACHED, target=job.target,
                                module=job.module, retry_after=retry_after)

    async def note_target_paused(self, target: str, *, reason: str) -> None:
        await self._maybe_event(ev.TARGET_PAUSED, target=target, reason=reason)

    async def cancel(self) -> None:
        """Hard-cancel: stop in-flight + queued jobs and emit scan_cancelled."""
        await self._pool.shutdown(cancel=True)
        await self._maybe_event(ev.SCAN_CANCELLED)

    def pool_stats(self) -> dict:
        """Live worker-pool counters (for the web live monitor)."""
        return self._pool.stats()

    # ── reporting (spec §12) ──────────────────────────────────────────────────
    def report_text(self, *, proxy=None, diagnostics_dir: str | None = None) -> str:
        from scheduler.report import render_report_text
        return render_report_text(self._report, proxy=proxy, diagnostics_dir=diagnostics_dir)

    def report_dict(self, *, proxy=None, diagnostics_dir: str | None = None) -> dict:
        from scheduler.report import build_report_dict
        return build_report_dict(self._report, proxy=proxy, diagnostics_dir=diagnostics_dir)
