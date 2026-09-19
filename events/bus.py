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
            asyncio.create_task(handler(event))

        return True

    async def publish_for_judgment(self, event: Event) -> None:
        """Queue a stamped IN-scope event for AI reasoning (Mode B only)."""
        if event.scope_status is ScopeStatus.IN:
            await self.judgment_queue.put(event)

    @property
    def seen_count(self) -> int:
        return len(self._seen)
