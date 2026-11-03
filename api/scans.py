"""
ScanManager — the control layer that launches and tracks scans for the API.

It is the API's analogue of mcpserver/context.py, but richer: it keeps the live
ScanController instance and the asyncio Task so a scan can be cancelled (clean
teardown is handled by the controller's own finally block — subprocess-tree kill
+ DB-engine dispose). It never reimplements scanning; it builds a ScanController
exactly as the CLI/MCP do and awaits controller.run().

Scope is re-validated here on the backend (ScopeEngine) before a scan starts —
the UI is never authoritative for scope. A seed that is not IN scope is rejected
and no background task is created.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from api.schemas import ScanCreate

log = logging.getLogger("api.scans")


class ScopeRejected(ValueError):
    """The requested seed is not IN scope — the scan must not start."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ScanEntry:
    scan_id: str
    domain: str
    mode: str
    status: str = "running"            # running | complete | failed | cancelled
    event_count: int = 0
    error: str | None = None
    created_at: datetime = field(default_factory=_now)
    completed_at: datetime | None = None
    task: asyncio.Task | None = None
    controller: object | None = None   # the live ScanController (for cancel/WS tap)
    monitor_task: asyncio.Task | None = None   # live-monitor sampler (WebSocket)


# A factory so tests can inject a fake controller instead of running a real scan.
ControllerFactory = Callable[[ScanCreate, object], object]


class ScanManager:
    def __init__(self, *, db_url: str | None = None,
                 controller_factory: ControllerFactory | None = None,
                 hub=None) -> None:
        self._db_url = db_url
        self._entries: dict[str, ScanEntry] = {}
        self._factory = controller_factory or self._default_controller_factory
        self._tasks: set[asyncio.Task] = set()
        self._hub = hub   # api.ws.LiveHub | None — live WebSocket monitor

    # ── scope (backend-authoritative) ──────────────────────────────────────────

    @staticmethod
    def build_scope(cfg: ScanCreate):
        """Build the Scope and FAIL CLOSED if the seed is not IN scope."""
        from scope.engine import ScopeEngine
        from scope.types import Scope, ScopeStatus
        in_scope = list(cfg.in_scope) if cfg.in_scope else [f"*.{cfg.domain}", cfg.domain]
        try:
            scope = Scope.from_strings(
                in_scope=in_scope, out_scope=list(cfg.out_scope),
                max_distance=cfg.max_distance, wildcard_includes_apex=cfg.wildcard_apex,
            )
        except ValueError as exc:
            raise ScopeRejected(f"invalid scope rule: {exc}") from exc
        decision = ScopeEngine(scope).evaluate(cfg.domain)
        if decision.status is not ScopeStatus.IN:
            raise ScopeRejected(f"seed {cfg.domain!r} is not in scope: {decision.reason}")
        return scope

    # ── controller construction (same as CLI/MCP; no new scan logic) ───────────

    def _default_controller_factory(self, cfg: ScanCreate, scope):
        from controller.controller import ScanController
        from net.proxy import ProxyConfig

        enabled = cfg.modules
        if not enabled:
            # Honour the mode's default module set, like the MCP server does.
            from modules.registry import ModuleRegistry
            from policy import CapabilityPolicy
            enabled = CapabilityPolicy(cfg.mode).default_module_names(ModuleRegistry.get)

        return ScanController(
            scope,
            mode=cfg.mode,
            enabled_modules=enabled,
            db_url=self._db_url,
            rate_limit=cfg.rate_limit,
            max_concurrency=cfg.max_concurrency,
            module_concurrency=cfg.module_concurrency,
            hybrid=cfg.hybrid,
            workers=cfg.workers,
            hybrid_targets=cfg.targets,
            browser_profile=cfg.browser_profile,
            proxy=ProxyConfig.from_sources(cli_proxy=cfg.proxy),
            results_enabled=True,
            live=False,
        )

    # ── lifecycle ──────────────────────────────────────────────────────────────

    async def launch(self, cfg: ScanCreate) -> ScanEntry:
        """Validate scope, build a controller, and run it as a background task.
        Raises ScopeRejected before any task is created if the seed is out of scope."""
        scope = self.build_scope(cfg)                 # fail-closed, no task yet
        controller = self._factory(cfg, scope)
        scan_id = str(getattr(controller, "scan_id", uuid.uuid4()))
        entry = ScanEntry(scan_id=scan_id, domain=cfg.domain, mode=cfg.mode,
                          controller=controller)
        self._entries[scan_id] = entry

        # Attach the live WebSocket monitor (read-only bus tap + stats sampler)
        # BEFORE the scan starts emitting, so no early events are missed.
        if self._hub is not None:
            try:
                from api.ws import start_live_monitor
                entry.monitor_task = start_live_monitor(self._hub, controller, scan_id)
                await self._hub.publish({"kind": "lifecycle", "scan_id": scan_id,
                                         "event": "scan_started", "domain": cfg.domain,
                                         "mode": cfg.mode})
            except Exception as exc:
                log.debug("live monitor attach failed: %s", exc)

        async def _run() -> None:
            try:
                await controller.run(cfg.domain)
                entry.status = "complete"
                try:
                    entry.event_count = controller.bus.seen_count
                except Exception:
                    pass
            except asyncio.CancelledError:
                entry.status = "cancelled"
                raise
            except Exception as exc:                   # isolate: one scan can't crash the server
                entry.status = "failed"
                entry.error = str(exc)[:500]
                log.error("scan %s failed: %s", scan_id, exc)
            finally:
                entry.completed_at = _now()
                if entry.monitor_task is not None:
                    entry.monitor_task.cancel()
                if self._hub is not None:
                    try:
                        await self._hub.publish({"kind": "lifecycle", "scan_id": scan_id,
                                                 "event": f"scan_{entry.status}"})
                    except Exception:
                        pass

        task = asyncio.create_task(_run(), name=f"scan-{scan_id}")
        entry.task = task
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return entry

    async def cancel(self, scan_id: str) -> bool:
        """Cancel a running scan. The controller's finally block tears down
        cleanly (kills tool subprocess trees, disposes the DB engine)."""
        entry = self._entries.get(scan_id)
        if entry is None or entry.task is None or entry.task.done():
            return False
        entry.task.cancel()
        try:
            await entry.task
        except (asyncio.CancelledError, Exception):    # noqa: BLE001 - teardown best-effort
            pass
        entry.status = "cancelled"
        return True

    def get(self, scan_id: str) -> ScanEntry | None:
        return self._entries.get(scan_id)

    def list(self) -> list[ScanEntry]:
        return sorted(self._entries.values(), key=lambda e: e.created_at, reverse=True)

    @property
    def active_count(self) -> int:
        return sum(1 for e in self._entries.values() if e.status == "running")

    async def shutdown(self) -> None:
        """Cancel any still-running scans (server shutdown)."""
        for sid in list(self._entries):
            if self._entries[sid].status == "running":
                await self.cancel(sid)
