"""
Controller integration for the hybrid engine — the ONLY place that couples the
scheduler to the live ScanController, kept thin so the core stays testable.

Two pieces:
  * derive_module_specs() — turn live module metadata (watched/produced events,
    flags) into a validated acyclic ModuleSpec DAG (producer → watcher edges,
    back-edges that would cycle are dropped).
  * build_subdomain_runner() — the real per-target runner for the opt-in
    `--hybrid` pass: it seeds one authorized subdomain into the EXISTING bus +
    module system (reusing the whole cascade), through the SAME scope chokepoint,
    so nothing is rewritten. The worker pool gives subdomain-level job tracking
    and concurrency; request concurrency stays governed by the shared limiter.
  * load_targets_file() — read an authorized-subdomain list (one host per line).
"""

from __future__ import annotations

import logging

from scheduler.engine import ModuleSpec

log = logging.getLogger("scheduler.integration")


def load_targets_file(path: str) -> list[str]:
    """Read an authorized-subdomain list: one host per line, '#' comments and
    blanks ignored, normalized (lower, no trailing dot), de-duplicated."""
    seen: set[str] = set()
    out: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            host = raw.split("#", 1)[0].strip().lower().rstrip(".")
            if host and host not in seen:
                seen.add(host)
                out.append(host)
    return out


def _break_cycles(raw: dict[str, set[str]]) -> dict[str, set[str]]:
    """Drop edges that would create a cycle so the result is a strict DAG.
    `raw[m]` = modules m depends on. Deterministic (sorted DFS)."""
    acyclic: dict[str, set[str]] = {m: set() for m in raw}
    WHITE, GREY, BLACK = 0, 1, 2
    color = {m: WHITE for m in raw}

    def visit(m: str) -> None:
        color[m] = GREY
        for dep in sorted(raw.get(m, set())):
            if dep not in raw:
                continue
            if color[dep] == GREY:
                # dep is an ancestor → this edge closes a cycle; drop it.
                log.debug("dropping cyclic module dep %s -> %s", m, dep)
                continue
            acyclic[m].add(dep)
            if color[dep] == WHITE:
                visit(dep)
        color[m] = BLACK

    for m in sorted(raw):
        if color[m] == WHITE:
            visit(m)
    return acyclic


def derive_module_specs(instances) -> list[ModuleSpec]:
    """Build a validated ModuleSpec DAG from live module instances: a module
    that *watches* an event another module *produces* depends on that producer.
    Passive modules get higher priority (run first); slow modules lower."""
    names = {m.name for m in instances}
    produces: dict[str, set[str]] = {}
    for m in instances:
        for e in (getattr(m, "produced_events", None) or []):
            produces.setdefault(e, set()).add(m.name)

    raw: dict[str, set[str]] = {}
    for m in instances:
        reqs: set[str] = set()
        for e in (getattr(m, "watched_events", None) or []):
            reqs |= (produces.get(e, set()) & names)
        reqs.discard(m.name)
        raw[m.name] = reqs

    acyclic = _break_cycles(raw)

    by_name = {m.name: m for m in instances}
    specs: list[ModuleSpec] = []
    for name in raw:
        flags = getattr(by_name[name], "flags", None) or []
        passive = "passive" in flags
        slow = "slow" in flags
        specs.append(ModuleSpec(
            name=name,
            requires=frozenset(acyclic[name]),
            priority=10 if passive else (200 if slow else 100),
            passive=passive,
        ))
    return specs


def build_subdomain_runner(controller):
    """Return `async runner(target, _module) -> bool` that seeds one authorized
    subdomain into the controller's existing bus + module system via the single
    scope chokepoint. Reuses the whole cascade — no module execution is
    reimplemented. Returns True if the seed was accepted (in-scope)."""
    import uuid as _uuid

    from events.types import Event, EventType, SubdomainData
    from scope.types import ScopeStatus

    async def runner(target: str, _module: str) -> bool:
        seed = Event.create(
            EventType.SUBDOMAIN,
            SubdomainData(hostname=target, source="hybrid-seed"),
            scan_job_id=controller.scan_id,
            source_tool="hybrid",
            distance=0,
        )
        # Pre-stamped IN: the scheduler already scope-validated this target, and
        # stamp_and_publish re-checks anyway (defence in depth). distance=1 so
        # discovered children are bounded exactly like the normal seed.
        seed.scope_status = ScopeStatus.IN
        seed.distance = 1
        accepted = await controller.stamp_and_publish(seed)
        return bool(accepted)

    return runner
