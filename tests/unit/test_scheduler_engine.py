"""
Tests for scheduler.engine.HybridScheduler: subdomain-level scope gating,
module-level dependency ordering (DAG), partial-result rollup, target dedup,
report accounting, event emission, and bounded concurrency — all over the real
ScopeEngine with a mock module runner.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from scheduler.engine import HybridScheduler, ModuleSpec
from scheduler.jobs import JobState
from scope.engine import ScopeEngine
from scope.types import Scope


def _scope(in_scope, out_scope=None):
    return ScopeEngine(Scope.from_strings(in_scope=in_scope, out_scope=out_scope or []))


def _record_runner():
    calls: list[tuple[str, str]] = []

    async def runner(target, module):
        calls.append((target, module))
        await asyncio.sleep(0)
        return True

    return runner, calls


# ── scope gating ────────────────────────────────────────────────────────────

async def test_out_of_scope_target_never_runs_modules():
    runner, calls = _record_runner()
    sch = HybridScheduler(
        scan_id=uuid.uuid4(),
        scope_engine=_scope(["*.example.com", "example.com"]),
        module_specs=[ModuleSpec("httpx")],
        module_runner=runner,
    )
    rep = await sch.run(["api.example.com", "evil.com"])   # evil.com is out of scope
    assert rep.targets_out_of_scope == 1
    assert rep.targets_completed == 1
    # the runner was only ever invoked for the in-scope target
    assert {t for t, _ in calls} == {"api.example.com"}


# ── module dependency ordering ────────────────────────────────────────────────

async def test_dependent_module_waits_for_prerequisite():
    order: list[str] = []

    async def runner(target, module):
        order.append(module)
        await asyncio.sleep(0.01)
        return True

    specs = [ModuleSpec("probe"), ModuleSpec("fuzz", requires=frozenset({"probe"}))]
    sch = HybridScheduler(
        scan_id=uuid.uuid4(), scope_engine=_scope(["example.com"]),
        module_specs=specs, module_runner=runner, max_workers=5,
    )
    await sch.run(["example.com"])
    assert order.index("probe") < order.index("fuzz")      # prerequisite ran first


async def test_failed_prerequisite_skips_dependents_but_target_is_partial():
    ran: list[str] = []

    async def runner(target, module):
        ran.append(module)
        return module != "probe"            # probe FAILS, others succeed

    specs = [
        ModuleSpec("probe"),
        ModuleSpec("fuzz", requires=frozenset({"probe"})),   # depends on the failing probe
        ModuleSpec("whois"),                                 # independent, succeeds
    ]
    sch = HybridScheduler(
        scan_id=uuid.uuid4(), scope_engine=_scope(["example.com"]),
        module_specs=specs, module_runner=runner,
    )
    rep = await sch.run(["example.com"])
    assert "fuzz" not in ran                 # dependent of a failed prereq never ran
    assert "whois" in ran and "probe" in ran
    assert rep.targets_partial == 1          # some ok (whois), some not → PARTIAL
    assert rep.modules_ok == 1 and rep.modules_failed == 2


# ── dedup + accounting ──────────────────────────────────────────────────────

async def test_targets_deduped_after_normalization():
    runner, calls = _record_runner()
    sch = HybridScheduler(
        scan_id=uuid.uuid4(), scope_engine=_scope(["*.example.com", "example.com"]),
        module_specs=[ModuleSpec("httpx")], module_runner=runner,
    )
    rep = await sch.run(["API.example.com", "api.example.com.", "api.example.com"])
    assert rep.targets_total == 1            # three spellings → one target
    assert len(calls) == 1


# ── events ────────────────────────────────────────────────────────────────────

async def test_emits_lifecycle_events():
    events: list[str] = []

    async def on_event(name, payload):
        events.append(name)

    runner, _ = _record_runner()
    sch = HybridScheduler(
        scan_id=uuid.uuid4(), scope_engine=_scope(["example.com"]),
        module_specs=[ModuleSpec("httpx")], module_runner=runner, on_event=on_event,
    )
    await sch.run(["example.com", "nope.org"])
    assert "scan_started" in events and "scan_completed" in events
    assert "module_completed" in events
    assert "target_out_of_scope" in events


# ── DAG validation ──────────────────────────────────────────────────────────

def test_cycle_rejected_at_construction():
    with pytest.raises(ValueError):
        HybridScheduler(
            scan_id=uuid.uuid4(), scope_engine=_scope(["x.com"]),
            module_specs=[
                ModuleSpec("a", requires=frozenset({"b"})),
                ModuleSpec("b", requires=frozenset({"a"})),
            ],
            module_runner=_record_runner()[0],
        )


def test_unknown_prerequisite_rejected():
    with pytest.raises(ValueError):
        HybridScheduler(
            scan_id=uuid.uuid4(), scope_engine=_scope(["x.com"]),
            module_specs=[ModuleSpec("a", requires=frozenset({"ghost"}))],
            module_runner=_record_runner()[0],
        )


# ── bounded concurrency across targets × modules ──────────────────────────────

async def test_concurrency_bounded_by_workers_across_all_jobs():
    peak = 0
    active = 0

    async def runner(target, module):
        nonlocal peak, active
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.02)
        active -= 1
        return True

    # 4 targets × 3 independent modules = 12 module jobs, cap 3
    sch = HybridScheduler(
        scan_id=uuid.uuid4(),
        scope_engine=_scope(["*.example.com", "example.com"]),
        module_specs=[ModuleSpec("a"), ModuleSpec("b"), ModuleSpec("c")],
        module_runner=runner, max_workers=3,
    )
    rep = await sch.run([f"h{i}.example.com" for i in range(4)])
    assert peak <= 3, f"{peak} module jobs ran at once under a 3-worker cap"
    assert rep.modules_run == 12 and rep.modules_ok == 12
    assert rep.targets_completed == 4
