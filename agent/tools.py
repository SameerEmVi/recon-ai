"""
Agent tool wrappers — Phase 4 low-risk actions.

Every tool checks scope before touching any target. Tools return a tuple:
  (new_event_count: int, summary: str)

Available tools
---------------
ProbeUrlTool          — run httpx on a single URL already in scope
FetchHistoricalUrlsTool — run gau (passive, read-only) on a hostname
NucleiInfoTool        — run nuclei -severity info on a URL
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from uuid import UUID

from controller.controller import ScanController
from ratelimit import get_limiter
from events.types import Event, EventType
from scope.types import ScopeStatus

log = logging.getLogger(__name__)


@dataclass
class ToolResult:
    new_events: int
    summary: str


class AgentTool(ABC):
    """Base class for all agent tools."""

    name: str
    # Capability this tool exercises — the central policy must permit it, or the
    # tool is neither registered nor runnable (the AI cannot bypass the mode).
    required_capability: str = ""

    def __init__(self, controller: ScanController) -> None:
        self._controller = controller

    def _scope_ok(self, target: str) -> bool:
        """Pre-check: target must be IN scope. Refuses OUT/PENDING."""
        decision = self._controller.scope_engine.evaluate(target)
        if decision.status is not ScopeStatus.IN:
            log.warning("[tool:%s] %s is %s — skipping", self.name, target, decision.status)
            return False
        return True

    def _capability_ok(self) -> bool:
        """Pre-check: the selected mode must permit this tool's capability."""
        from policy import get_policy
        if not self.required_capability:
            return True
        if not get_policy(self._controller).allows(self.required_capability):
            log.warning("[tool:%s] %s not permitted in current mode — refusing",
                        self.name, self.required_capability)
            return False
        return True

    @abstractmethod
    async def run(self, target: str, scan_id: UUID) -> ToolResult: ...


# ── ProbeUrlTool ──────────────────────────────────────────────────────────────

class ProbeUrlTool(AgentTool):
    """
    Run httpx on a single URL.

    Injects the result back through the scan controller so scope is re-checked
    and dedup runs normally. The controller's existing httpx reflex handles
    technology fingerprinting.
    """

    name = "probe_url"
    required_capability = "TARGET_HTTP_REQUEST"

    async def run(self, target: str, scan_id: UUID) -> ToolResult:
        if not self._capability_ok():
            return ToolResult(0, f"capability denied: {self.required_capability}")
        # The target here is a URL — extract hostname for scope check.
        from urllib.parse import urlparse
        parsed = urlparse(target if "://" in target else f"https://{target}")
        hostname = parsed.hostname or target

        if not self._scope_ok(hostname):
            return ToolResult(0, f"scope denied: {hostname}")

        from recon.httpx_wrap import HttpxWrapper
        wrapper = HttpxWrapper(self._controller)

        before = self._controller.bus.seen_count
        await wrapper.probe_urls([target], self._controller.stamp_and_publish, scan_id)
        after = self._controller.bus.seen_count

        new = after - before
        return ToolResult(new, f"probed {target} → {new} new event(s)")


# ── FetchHistoricalUrlsTool ───────────────────────────────────────────────────

class FetchHistoricalUrlsTool(AgentTool):
    """
    Run gau (GetAllUrls) passively against a hostname.

    gau queries web archives and known indexes — no active requests to the
    target. Results are URL events which may lead to further reflex actions.
    """

    name = "fetch_historical_urls"
    required_capability = "PASSIVE_EXTERNAL"

    async def run(self, target: str, scan_id: UUID) -> ToolResult:
        if not self._capability_ok():
            return ToolResult(0, f"capability denied: {self.required_capability}")
        if not self._scope_ok(target):
            return ToolResult(0, f"scope denied: {target}")

        from recon.gau import GauWrapper
        wrapper = GauWrapper(limiter=get_limiter(self._controller))

        before = self._controller.bus.seen_count
        await wrapper.fetch(target, self._controller.stamp_and_publish, scan_id)
        after = self._controller.bus.seen_count

        new = after - before
        return ToolResult(new, f"gau {target} → {new} URL event(s)")


# ── NucleiInfoTool ────────────────────────────────────────────────────────────

class NucleiInfoTool(AgentTool):
    """
    Run nuclei with -severity info only — no exploit templates.

    Only info-severity templates are loaded so no active exploitation occurs.
    Results are emitted as FINDING_CANDIDATE events through the normal
    controller pipeline.
    """

    name = "nuclei_info"
    required_capability = "VULNERABILITY_CHECK"

    async def run(self, target: str, scan_id: UUID) -> ToolResult:
        if not self._capability_ok():
            return ToolResult(0, f"capability denied: {self.required_capability}")
        from urllib.parse import urlparse
        parsed = urlparse(target if "://" in target else f"https://{target}")
        hostname = parsed.hostname or target

        if not self._scope_ok(hostname):
            return ToolResult(0, f"scope denied: {hostname}")

        from recon.nuclei import NucleiWrapper
        wrapper = NucleiWrapper(limiter=get_limiter(self._controller))

        before = self._controller.bus.seen_count
        await wrapper.scan(target, self._controller.stamp_and_publish, scan_id)
        after = self._controller.bus.seen_count

        new = after - before
        return ToolResult(new, f"nuclei-info {target} → {new} finding(s)")


# ── tool registry ─────────────────────────────────────────────────────────────

def build_tool_registry(controller: ScanController) -> dict[str, AgentTool]:
    """Build the agent's tool registry, filtered by the selected mode's policy.

    A tool whose capability the mode forbids is NOT registered, so the AgentLoop
    (which looks actions up by name) cannot invoke it — an AI recommendation can
    never bypass the mode. Each tool also re-checks at call time (defence-in-depth).
    """
    from policy import get_policy
    policy = get_policy(controller)
    tools: list[AgentTool] = [
        ProbeUrlTool(controller),
        FetchHistoricalUrlsTool(controller),
        NucleiInfoTool(controller),
    ]
    registry: dict[str, AgentTool] = {}
    for t in tools:
        if not t.required_capability or policy.allows(t.required_capability):
            registry[t.name] = t
        else:
            log.info("[agent] tool %s disabled by mode '%s' (needs %s)",
                     t.name, getattr(policy, "mode", "?"), t.required_capability)
    return registry
