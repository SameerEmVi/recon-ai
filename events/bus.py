"""
EventBus — async pub/sub with a judgment queue for Mode B.

Design:
  - Deterministic handlers subscribe to event types and fire immediately
    (as asyncio tasks) when a matching event is published. These run in
    both Mode A and Mode B.
  - Events needing AI judgment go into `judgment_queue`. In Mode A this
    queue is never drained. In Mode B the controller drains it via the
    AI layer (Phase 3+).
  - Scope gate: only IN-scope events propagate. Publishing an OUT or PENDING
    event is a no-op — the bus never forwards it.
  - Dedup gate: each dedup_key is tracked. A repeated key is dropped silently.
    This bounds recursion: a cycle in the event graph collapses here.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Callable, Coroutine

from events.types import Event, EventType
from scope.types import ScopeStatus

log = logging.getLogger(__name__)


class EventBus:
    def __init__(self) -> None:
        self._handlers: dict[EventType, list[Callable[[Event], Coroutine]]] = defaultdict(list)
        self._seen: set[str] = set()
        # Every reactive handler runs as a fire-and-forget task; we keep strong
        # references so (a) the GC can't drop a running task, and (b) drain() can
        # wait for the whole reactive cascade to go quiescent before teardown.
        self._tasks: set[asyncio.Task] = set()
        # Mode B drains this; Mode A leaves it alone.
        self.judgment_queue: asyncio.Queue[Event] = asyncio.Queue()

    def subscribe(
        self,
        event_type: EventType,
        handler: Callable[[Event], Coroutine],
    ) -> None:
        self._handlers[event_type].append(handler)

    async def publish(self, event: Event) -> bool:
        """Publish a scope-stamped event. Returns True if accepted, False if dropped."""
        if event.scope_status is not ScopeStatus.IN:
            log.debug("drop (scope=%s): %s", event.scope_status.value, event.dedup_key)
            return False

        if event.dedup_key in self._seen:
            log.debug("drop (dup): %s", event.dedup_key)
            return False

        self._seen.add(event.dedup_key)
        log.debug("[%s] %s  dist=%d", event.type.value, event.dedup_key, event.distance)

        for handler in self._handlers.get(event.type, []):
            task = asyncio.create_task(handler(event))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

        return True

    async def drain(self, *, settle: float = 0.1, max_seconds: float | None = None) -> None:
        """Wait until the reactive cascade is quiescent.

        Handlers are spawned as tasks and may themselves publish events (which
        spawn further tasks). We repeatedly await the pending set until it stays
        empty across a short settle window — so a slow reactive module (e.g.
        ffuf/dirsearch) or a deep subdomain→resolve→probe→fuzz chain finishes
        before the scan tears down, instead of being cancelled by teardown.

        Termination is guaranteed by the existing bounds: dedup drops repeated
        keys and the scope distance cap bounds recursion, so the cascade stops
        producing new work. `max_seconds` is an optional wall-clock safety valve.
        """
        loop = asyncio.get_event_loop()
        start = loop.time()
        while True:
            pending = [t for t in self._tasks if not t.done()]
            if not pending:
                await asyncio.sleep(settle)
                if not any(not t.done() for t in self._tasks):
                    return
                continue
            await asyncio.gather(*pending, return_exceptions=True)
            if max_seconds is not None and (loop.time() - start) > max_seconds:
                still = sum(1 for t in self._tasks if not t.done())
                log.warning("bus.drain: max_seconds=%s reached, %d task(s) still pending",
                            max_seconds, still)
                return

    async def publish_for_judgment(self, event: Event) -> None:
        """Queue a stamped IN-scope event for AI reasoning (Mode B only)."""
        if event.scope_status is ScopeStatus.IN:
            await self.judgment_queue.put(event)

    @property
    def seen_count(self) -> int:
        return len(self._seen)
