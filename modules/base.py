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


def _set_cookie_list(headers: Any) -> tuple[str, ...]:
    """Each Set-Cookie header separately (httpx merges them in a plain dict).

    Falls back to the single (possibly merged) value for header objects without
    `get_list` — e.g. a plain mapping from a mocked response.
    """
    get_list = getattr(headers, "get_list", None)
    if callable(get_list):
        return tuple(get_list("set-cookie"))
    try:
        value = headers.get("set-cookie")
    except Exception:
        return ()
    return (value,) if value else ()


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

    # Capability declaration (central mode/capability policy — see policy/).
    # Classified by BEHAVIOUR (what the module does to the target), never by name
    # or flags. Empty = fall back to the authoritative policy.MODULE_CAPABILITIES
    # table; set this on a module to self-declare/override. A module only loads in
    # a mode whose allowed capabilities are a superset of these.
    capabilities: ClassVar[list[str]] = []

    # ── Adaptive Reconnaissance Planner metadata ──────────────────────────────
    # Consumed by planner.ReconPlanner to decide *whether* this module is worth
    # running for a given discovery, instead of blindly firing on every event.
    #
    #   estimated_cost         : relative execution cost. None => derived from
    #                            flags (slow=HIGH, passive=LOW, else MEDIUM).
    #   expected_value         : relative information value. None => MEDIUM.
    #   supported_technologies : if non-empty, the module is only useful when one
    #                            of these technologies is present on the host
    #                            (e.g. ["GraphQL"], ["WordPress"]). [] => agnostic.
    #   prerequisites          : EventType value-strings that must already have
    #                            been observed for a host before this module runs.
    estimated_cost: ClassVar[int | None] = None
    expected_value: ClassVar[int | None] = None
    supported_technologies: ClassVar[list[str]] = []
    prerequisites: ClassVar[list[str]] = []

    @property
    def is_passive(self) -> bool:
        """True if this module makes no active requests to the target."""
        return "passive" in self.flags

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

    @property
    def policy(self):
        """The scan's central CapabilityPolicy (ALLOW_ALL under a mock controller)."""
        from policy import get_policy
        return get_policy(self._ctrl)

    def guard(self, bucket: str | None = None):
        """Async context manager wrapping one network op with rate limiting.

        Usage:
            async with self.guard(f"http:{host}"):
                r = await client.get(url)
        """
        return self.rate_limiter.guard(bucket or f"mod:{self.name}")

    def capability_ok(self, capability: str, *, action: str = "") -> bool:
        """Call-time capability gate for modules that bypass `fetch`/`run_proc`.

        `fetch()` and `run_proc()` already re-check the mode policy at the moment
        of action (defence-in-depth on top of module-load filtering). Modules
        that keep their own network client — because they need bytes, custom
        headers, or a raw DNS lookup rather than the shared text cache — must get
        the same recheck instead of relying on the load filter alone. Returns
        True when the action is permitted; logs and returns False when the mode
        forbids it (never raises, so a denied probe degrades gracefully).
        Under a mock controller the policy is ALLOW_ALL, so this is a no-op.
        """
        from policy import CapabilityDenied
        try:
            self.policy.check(capability, who=f"module '{self.name}'{' ' + action if action else ''}")
            return True
        except CapabilityDenied as exc:
            self._log.warning("%s denied by mode policy: %s", action or capability, exc)
            return False

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

    async def fetch(
        self,
        url: str,
        *,
        timeout: int = 20,
        max_body_kb: int = 1024,
        follow_redirects: bool = True,
    ) -> "FetchResult":
        """GET `url` once per scan and share the result with every module.

        Centralizes the fetch pattern that every body-consuming web module used
        to repeat (own httpx client + guard() + inspect_response() + r.text).
        The scan's shared ResponseCache de-dups by URL: concurrent callers for
        the same URL trigger ONE real network op (one rate-limit slot, one WAF
        observation); later callers get the cached FetchResult.

        Never raises — a transport failure returns FetchResult(ok=False, error=…).
        `text` is populated for any response within the size cap regardless of
        status (secretfinder deliberately scans 4xx/5xx bodies — stack traces
        leak), and is None only for an oversized or failed body; status/headers
        are still populated on any real response so probing callers can reason
        about it.
        """
        from dataclasses import replace
        from recon.fetch import (
            CACHE_MAX_BODY_KB,
            FetchResult,
            ResponseCache,
            get_response_cache,
        )
        from urllib.parse import urlparse
        from policy import CAP_TARGET_HTTP_REQUEST, CapabilityDenied

        # Central mode gate (defence-in-depth on top of module-load filtering): a
        # direct HTTP request to a discovered target is only permitted when the
        # mode allows TARGET_HTTP_REQUEST. Deny gracefully (never crash a passive
        # module that tries, e.g., an optional verify step).
        try:
            self.policy.check(CAP_TARGET_HTTP_REQUEST, who=f"module '{self.name}' fetch")
        except CapabilityDenied as exc:
            self._log.warning("fetch denied by mode policy: %s", exc)
            return FetchResult(url=url, ok=False, error=f"capability denied: {exc}")

        async def _do_fetch() -> "FetchResult":
            try:
                import httpx
            except ImportError:
                self._log.warning("httpx not installed")
                return FetchResult(url=url, ok=False, error="httpx not installed")
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    async with self.guard(f"http:{urlparse(url).hostname or url}"):
                        r = await client.get(url, follow_redirects=follow_redirects)
                    self.inspect_response(r)
                    ctype = r.headers.get("content-type")
                    size_kb = len(r.content) / 1024
                    # Store the FULL body (up to the global ceiling); per-caller
                    # max_body_kb is applied below so the first fetcher's cap does
                    # not starve a later caller with a larger one.
                    text = r.text if size_kb <= CACHE_MAX_BODY_KB else None
                    return FetchResult(
                        url=url,
                        status_code=r.status_code,
                        text=text,
                        headers=dict(r.headers),
                        content_type=ctype,
                        ok=True,
                        size_kb=size_kb,
                        set_cookies=_set_cookie_list(r.headers),
                    )
            except Exception as exc:
                self._log.debug("fetch failed for %s: %s", url, exc)
                return FetchResult(url=url, ok=False, error=str(exc))

        def _apply_cap(res: "FetchResult") -> "FetchResult":
            # Hide the body from THIS caller if it exceeds the caller's cap; the
            # shared cache keeps the full body for callers with a larger cap.
            if res.text is not None and res.size_kb is not None and res.size_kb > max_body_kb:
                return replace(res, text=None)
            return res

        cache = get_response_cache(self._ctrl)
        if cache is None:  # mock controller / cache disabled → direct, uncached
            return _apply_cap(await _do_fetch())
        key = ResponseCache.key(url, follow_redirects=follow_redirects)
        return _apply_cap(await cache.get_or_fetch(key, _do_fetch))

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
        # Central mode gate: a subprocess is a module action, so re-verify the
        # module is permitted in this mode before launching a binary.
        ok, reason = self.policy.module_allowed(type(self))
        if not ok:
            self._log.warning("run_proc(%s) denied by mode policy: %s", cmd[0] if cmd else "?", reason)
            return None
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
