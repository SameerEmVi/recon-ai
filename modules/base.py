"""
BaseModule — the base class every recon module inherits from.

Two kinds of modules:

  Seed modules     — watched_events = []
                     Implement run(domain, scan_id).
                     Called once at scan start, run in parallel.
                     Examples: subfinder, crt_sh, certspotter

  Reactive modules — watched_events = ["SUBDOMAIN", ...]
                     Implement handle_event(event).
                     Subscribed to EventBus; fire on matching events.
                     Examples: dnsx, httpx_probe, naabu

Both kinds use emit() to publish events. All emitted events pass through
stamp_and_publish() — scope gate applies unconditionally.
"""

from __future__ import annotations

import logging
from abc import ABC
from typing import TYPE_CHECKING, Any, ClassVar
from uuid import UUID

from events.types import Event, EventData, EventType

if TYPE_CHECKING:
    from controller.controller import ScanController

log = logging.getLogger(__name__)


class BaseModule(ABC):
    # ── class-level declarations (set by each subclass) ───────────────────────

    name: ClassVar[str] = ""
    description: ClassVar[str] = ""

    # EventType VALUE strings — e.g. ["SUBDOMAIN", "IP"]
    # Empty list = seed module (called once at scan start, not event-driven).
    watched_events: ClassVar[list[str]] = []
    produced_events: ClassVar[list[str]] = []

    # Classification tags used by --flag selector.
    # Common values: "passive", "active", "slow", "fast", "web", "dns"
    flags: ClassVar[list[str]] = []

    # Default option values. Users override via module_config dict.
    options: ClassVar[dict[str, Any]] = {}

    # External binaries this module requires (checked in default setup()).
    deps_binary: ClassVar[list[str]] = []

    # ── instance ──────────────────────────────────────────────────────────────

    def __init__(
        self,
        controller: "ScanController",
        config: dict[str, Any] | None = None,
    ) -> None:
        self._ctrl = controller
        self._config: dict[str, Any] = {**self.options, **(config or {})}
        self._log = logging.getLogger(f"module.{self.name}")

    # ── lifecycle hooks ───────────────────────────────────────────────────────

    async def setup(self) -> bool:
        """
        Called once before scan starts.

        Return False to disable this module (e.g. required binary not found).
        The default implementation checks deps_binary via shutil.which.
        """
        import shutil
        for binary in self.deps_binary:
            if not shutil.which(binary):
                self._log.warning("%s not found — module disabled", binary)
                return False
        return True

    async def run(self, domain: str, scan_id: UUID) -> None:
        """
        Entry point for SEED modules (watched_events = []).

        Override this in seed modules. Default is a no-op so reactive modules
        don't need to override it.
        """

    async def handle_event(self, event: Event) -> None:
        """
        Called for each matching event for REACTIVE modules.

        Override this in reactive modules. Default is a no-op.
        """

    async def finish(self) -> None:
        """Called once after scan ends. Override for cleanup / final output."""

    # ── helpers ───────────────────────────────────────────────────────────────

    async def emit(
        self,
        event_type: EventType,
        data: EventData,
        source_event: Event | None = None,
        distance: int | None = None,
    ) -> bool:
        """Create an event and push it through the scope gate."""
        dist = distance if distance is not None else (
            source_event.distance if source_event else 0
        )
        event = Event.create(
            event_type,
            data,
            scan_job_id=self._ctrl.scan_id,
            source_tool=self.name,
            source_event_id=source_event.id if source_event else None,
            distance=dist,
        )
        return await self._ctrl.stamp_and_publish(event)

    def opt(self, name: str) -> Any:
        """Return the current value of a config option."""
        return self._config.get(name, self.options.get(name))

    # ── rate limiting / WAF backoff ───────────────────────────────────────────

    @property
    def rate_limiter(self):
        """The scan's shared, WAF-aware RateLimiter (NOOP under a mock controller)."""
        from ratelimit import get_limiter
        return get_limiter(self._ctrl)

    def guard(self, bucket: str | None = None):
        """Async context manager wrapping one network op with rate limiting.

        Usage:
            async with self.guard(f"http:{host}"):
                r = await client.get(url)
        """
        return self.rate_limiter.guard(bucket or f"mod:{self.name}")

    def inspect_response(self, resp: Any, *, body: str | None = None):
        """Feed an httpx response to WAF detection; auto-slows on block/challenge.

        Returns the WafSignal if a WAF was detected, else None. Defensive: a mock
        or partial response object is safely ignored.
        """
        sig = self.rate_limiter.observe_http(
            status=getattr(resp, "status_code", None),
            headers=getattr(resp, "headers", None),
            body=body,
        )
        if sig is not None and sig.blocking:
            self._log.warning(
                "WAF/block detected (%s: %s) — slowing down", sig.vendor, sig.reason
            )
        return sig

    async def run_proc(
        self, cmd: list[str], *, timeout: int = 60, bucket: str | None = None,
        input_text: str | None = None,
    ) -> str | None:
        """Run an external binary under the shared rate limiter and return its
        stdout as text, or None on missing binary / timeout / error.

        Centralizes the subprocess pattern every tool-wrapper module uses:
        warn-and-skip if the binary isn't installed, honor concurrency/rate
        limits via guard(), and never raise into the event loop.
        """
        import asyncio
        try:
            async with self.guard(bucket or f"proc:{self.name}"):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdin=asyncio.subprocess.PIPE if input_text else None,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                except FileNotFoundError:
                    self._log.warning("%s not found — module disabled", cmd[0])
                    return None
                try:
                    out, _ = await asyncio.wait_for(
                        proc.communicate(
                            input=input_text.encode() if input_text else None
                        ),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    self._log.warning("%s timed out", cmd[0])
                    return None
            return (out or b"").decode("utf-8", "replace")
        except Exception as exc:
            self._log.debug("%s failed: %s", cmd[0], exc)
            return None

    def __repr__(self) -> str:
        return f"<Module {self.name}>"
