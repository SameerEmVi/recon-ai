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
import json
import logging
import os
import sys
import tempfile
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


def build_scan_controller(cfg: ScanCreate, scope, *, db_url: str | None,
                          scan_id: str | None = None):
    """Construct a ScanController from a request, exactly as the CLI/MCP do.

    Shared by the in-process controller factory and the out-of-process scan
    worker (api/worker.py) so the two construction paths can never drift. No
    scan logic lives here — it only wires the request into the controller.
    """
    from controller.controller import ScanController
    from net.proxy import ProxyConfig

    enabled = cfg.modules
    if not enabled:
        # Honour the mode's default module set, like the MCP server does.
        from modules.registry import ModuleRegistry
        from policy import CapabilityPolicy
        enabled = CapabilityPolicy(cfg.mode).default_module_names(ModuleRegistry.get)

    # LLM in the loop is opt-in and needs a key. Read it from the environment
    # (never from the request/config file) so the secret is never serialised; the
    # out-of-process worker inherits the server's env, so it sees the same key.
    ai = bool(cfg.ai or cfg.agent)      # --agent implies --ai, as on the CLI
    api_key = os.environ.get("ANTHROPIC_API_KEY") if ai else None

    return ScanController(
        scope,
        mode=cfg.mode,
        enabled_modules=enabled,
        db_url=db_url,
        scan_id=scan_id,
        ai_enabled=ai,
        agent_enabled=bool(cfg.agent),
        anthropic_api_key=api_key,
        max_agent_iterations=cfg.max_iterations,
        rate_limit=cfg.rate_limit,
        max_concurrency=cfg.max_concurrency,
        module_concurrency=cfg.module_concurrency,
        hybrid=cfg.hybrid,
        workers=cfg.workers,
        hybrid_targets=cfg.targets,
        scan_resolved_ips=cfg.scan_resolved_ips,
        scan_cdn_ips=cfg.scan_cdn_ips,
        browser_profile=cfg.browser_profile,
        proxy=ProxyConfig.from_sources(cli_proxy=cfg.proxy),
        results_enabled=True,
        live=False,
    )


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
    controller: object | None = None   # in-process ScanController (for cancel/WS tap)
    monitor_task: asyncio.Task | None = None   # live-monitor sampler (WebSocket)
    # Out-of-process (default): the scan runs in its own subprocess so the web
    # server's event loop is never starved by scan work.
    proc: object | None = None                 # asyncio subprocess Process
    frames_path: str | None = None             # per-scan live-frames JSONL file
    config_path: str | None = None             # worker config file (cleaned up at end)
    pump_task: asyncio.Task | None = None       # tails frames_path → hub
    wait_task: asyncio.Task | None = None       # awaits process exit → final status


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
        # Run scans out-of-process by default (event-loop isolation). Tests inject
        # a controller_factory to run in-process with a fake controller instead.
        self._out_of_process = controller_factory is None

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
        return build_scan_controller(cfg, scope, db_url=self._db_url)

    # ── lifecycle ──────────────────────────────────────────────────────────────

    async def launch(self, cfg: ScanCreate) -> ScanEntry:
        """Validate scope (fail-closed) then launch the scan. By default the scan
        runs in its OWN process (event-loop isolation); with an injected
        controller_factory (tests) it runs in-process. No task/process is created
        if the seed is out of scope."""
        scope = self.build_scope(cfg)                 # fail-closed, nothing started yet
        if self._out_of_process:
            return await self._launch_subprocess(cfg, scope)
        return await self._launch_in_process(cfg, scope)

    # ── in-process (tests / injected factory) ──────────────────────────────────

    async def _launch_in_process(self, cfg: ScanCreate, scope) -> ScanEntry:
        controller = self._factory(cfg, scope)
        scan_id = str(getattr(controller, "scan_id", uuid.uuid4()))
        from policy import resolve_mode
        entry = ScanEntry(scan_id=scan_id, domain=cfg.domain,
                          mode=resolve_mode(cfg.mode)[0],   # canonical tier
                          controller=controller)
        self._entries[scan_id] = entry

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

    # ── out-of-process (default) ───────────────────────────────────────────────

    async def _launch_subprocess(self, cfg: ScanCreate, scope) -> ScanEntry:
        from recon.proc import new_session_kwargs

        scan_id = str(uuid.uuid4())
        entry = ScanEntry(scan_id=scan_id, domain=cfg.domain, mode=cfg.mode)
        self._entries[scan_id] = entry

        # Per-scan temp files: live frames (JSONL, tailed by the hub) + worker config.
        fd, frames_path = tempfile.mkstemp(prefix=f"scan-{scan_id[:8]}-", suffix=".frames.jsonl")
        os.close(fd)
        fd, config_path = tempfile.mkstemp(prefix=f"scan-{scan_id[:8]}-", suffix=".config.json")
        os.close(fd)
        entry.frames_path, entry.config_path = frames_path, config_path

        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump({"scan_id": scan_id, "db_url": self._db_url,
                           "frames_path": frames_path, "cfg": cfg.model_dump(mode="json")}, f)
        except Exception as exc:
            entry.status = "failed"
            entry.error = f"could not write worker config: {exc}"
            entry.completed_at = _now()
            self._cleanup_files(entry)
            return entry

        if self._hub is not None:
            try:
                await self._hub.publish({"kind": "lifecycle", "scan_id": scan_id,
                                         "event": "scan_started", "domain": cfg.domain,
                                         "mode": cfg.mode})
            except Exception:
                pass

        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "api.worker", config_path,
                cwd=repo_root, **new_session_kwargs(),
            )
        except Exception as exc:
            entry.status = "failed"
            entry.error = f"could not launch scan worker: {exc}"
            entry.completed_at = _now()
            self._cleanup_files(entry)
            log.error("scan %s: worker launch failed: %s", scan_id, exc)
            return entry

        entry.proc = proc
        entry.pump_task = asyncio.create_task(self._pump_frames(entry), name=f"pump-{scan_id}")
        entry.wait_task = asyncio.create_task(self._await_proc(entry), name=f"wait-{scan_id}")
        for t in (entry.pump_task, entry.wait_task):
            self._tasks.add(t)
            t.add_done_callback(self._tasks.discard)
        return entry

    async def _pump_frames(self, entry: ScanEntry) -> None:
        """Tail the worker's live-frames file and republish each frame to the hub.
        File reads run in a thread so the web loop is never blocked; stops once the
        process has exited and the file is fully drained."""
        path = entry.frames_path
        if path is None:
            return
        loop = asyncio.get_event_loop()
        offset, buf = 0, ""

        def _read(off: int):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    fh.seek(off)
                    return fh.read(), fh.tell()
            except FileNotFoundError:
                return "", off
            except Exception:
                return "", off

        while True:
            proc_done = entry.proc is not None and entry.proc.returncode is not None
            chunk, offset = await loop.run_in_executor(None, _read, offset)
            if chunk:
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        frame = json.loads(line)
                    except Exception:
                        continue
                    self._apply_frame(entry, frame)
                    if self._hub is not None:
                        try:
                            await self._hub.publish(frame)
                        except Exception:
                            pass
            if proc_done and not chunk:
                break
            await asyncio.sleep(0.2)

    @staticmethod
    def _apply_frame(entry: ScanEntry, frame: dict) -> None:
        """Update the entry's live counters/status from a relayed frame."""
        kind = frame.get("kind")
        if kind == "event":
            entry.event_count += 1
        elif kind == "lifecycle":
            ev = str(frame.get("event", ""))
            if ev.startswith("scan_") and ev != "scan_started":
                st = ev[len("scan_"):]
                if st in ("complete", "completed"):
                    entry.status = "complete"
                elif st in ("failed", "cancelled"):
                    entry.status = st

    async def _await_proc(self, entry: ScanEntry) -> None:
        """Await the worker process, drain its frames, and settle the final status."""
        proc = entry.proc
        try:
            rc = await proc.wait()
        except Exception:
            rc = -1
        if entry.pump_task is not None:
            try:
                await asyncio.wait_for(entry.pump_task, timeout=5)
            except Exception:
                entry.pump_task.cancel()
        # The worker writes a terminal lifecycle frame which the pump already
        # applied; only reconcile if it died without one.
        if entry.status == "running":
            entry.status = "complete" if rc == 0 else "failed"
            if rc not in (0,):
                entry.error = entry.error or f"worker exited with code {rc}"
        entry.completed_at = _now()
        self._cleanup_files(entry)

    @staticmethod
    def _cleanup_files(entry: ScanEntry) -> None:
        for p in (entry.frames_path, entry.config_path):
            if p:
                try:
                    os.unlink(p)
                except Exception:
                    pass
        entry.frames_path = entry.config_path = None

    async def cancel(self, scan_id: str) -> bool:
        """Cancel a running scan.

        Out-of-process: kill the worker's whole process tree (worker + its tool
        children) so nothing is left hitting the target, then mark the DB row
        cancelled (the hard-killed worker can't). In-process: cancel the task and
        let the controller's finally block tear down."""
        entry = self._entries.get(scan_id)
        if entry is None:
            return False

        if self._out_of_process:
            proc = entry.proc
            if proc is None or proc.returncode is not None:
                return False
            from recon.proc import terminate_tree
            await terminate_tree(proc)
            if entry.wait_task is not None:
                try:
                    await asyncio.wait_for(entry.wait_task, timeout=6)
                except Exception:
                    pass
            entry.status = "cancelled"
            entry.completed_at = _now()
            await self._mark_db_cancelled(scan_id)
            if self._hub is not None:
                try:
                    await self._hub.publish({"kind": "lifecycle", "scan_id": scan_id,
                                             "event": "scan_cancelled"})
                except Exception:
                    pass
            return True

        # in-process path
        if entry.task is None or entry.task.done():
            return False
        entry.task.cancel()
        try:
            await entry.task
        except (asyncio.CancelledError, Exception):    # noqa: BLE001 - teardown best-effort
            pass
        entry.status = "cancelled"
        return True

    async def _mark_db_cancelled(self, scan_id: str) -> None:
        """Best-effort: set the scan row to 'cancelled'. The killed worker left it
        'running', so DB-backed assemblers would otherwise show it running."""
        if not self._db_url:
            return
        try:
            from sqlalchemy import update

            from database.models import ScanJob
            from database.session import make_engine, make_session_factory

            engine = make_engine(self._db_url)
            try:
                async with make_session_factory(engine)() as s:
                    await s.execute(
                        update(ScanJob).where(ScanJob.id == uuid.UUID(scan_id))
                        .values(status="cancelled", completed_at=_now()))
                    await s.commit()
            finally:
                await engine.dispose()
        except Exception as exc:
            log.debug("mark db cancelled failed: %s", exc)

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
