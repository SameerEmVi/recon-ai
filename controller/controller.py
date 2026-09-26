"""
ScanController — owns the scan lifecycle.

Mode A (--no-ai, default): deterministic modules only.
Mode B (--ai):             same modules + AI triage after enumeration.
Mode B+agent:              same + constrained agent loop.

Modules are loaded via ModuleRegistry. Two kinds:
  Seed modules     (watched_events=[]) — run in parallel at scan start
  Reactive modules (watched_events=[...]) — subscribed to EventBus, fire on events

Scope is enforced for EVERY event via stamp_and_publish(). No module, tool,
or agent action can bypass it.
"""

from __future__ import annotations

import asyncio
import logging
import urllib.parse
import uuid
from typing import TYPE_CHECKING, Any
from uuid import UUID

from events.bus import EventBus
from events.types import Event, EventType, SubdomainData
from scope.engine import ScopeEngine
from ratelimit import RateLimiter
from scope.types import Scope, ScopeStatus

if TYPE_CHECKING:
    from database.knowledge_base import KnowledgeBase
    from database.persister import Persister
    from modules.base import BaseModule

log = logging.getLogger(__name__)


class ScanController:
    def __init__(
        self,
        scope: Scope,
        # AI / agent settings
        ai_enabled: bool = False,
        agent_enabled: bool = False,
        # Module selection
        enabled_modules: list[str] | None = None,   # explicit list; None = defaults
        enabled_flags: list[str] | None = None,     # add all modules with these flags
        module_config: dict[str, dict[str, Any]] | None = None,
        # Persistence
        db_url: str | None = None,
        # Anthropic
        anthropic_api_key: str | None = None,
        ai_model: str = "claude-sonnet-4-6",
        max_agent_iterations: int = 20,
        # Rate limiting (None = no static limit; adaptive WAF backoff still applies)
        rate_limit: float | None = None,
        max_concurrency: int | None = None,
        # Adaptive Reconnaissance Planner
        plan_mode: str = "default",          # passive-first | default | aggressive
        plan_budget: int = 0,                # max module executions; 0 = unlimited
        # Live CLI event stream (off for MCP/background runs).
        live: bool = False,
    ) -> None:
        self._scope_engine = ScopeEngine(scope)
        self._scope = scope
        self._bus = EventBus()
        self._rate_limiter = RateLimiter(rate_limit, max_concurrency, name="scan")
        from planner import PlannerConfig, ReconPlanner
        self._planner = ReconPlanner(
            PlannerConfig(mode=plan_mode, max_executions=plan_budget)
        )
        self._ai_enabled = ai_enabled
        self._agent_enabled = agent_enabled
        self._enabled_modules = enabled_modules
        self._enabled_flags = enabled_flags
        self._module_config = module_config or {}
        self._db_url = db_url
        self._anthropic_api_key = anthropic_api_key
        self._ai_model = ai_model
        self._max_agent_iterations = max_agent_iterations
        self._scan_id = uuid.uuid4()
        self._persister: Persister | None = None
        self._knowledge_base: "KnowledgeBase | None" = None
        self._summary: dict[str, list] = {}
        self._scan_domain: str | None = None
        self._live = live
        # Modules are loaded lazily in _do_run() (setup() is async).
        self._loaded_modules: list["BaseModule"] = []

    # ── public API ────────────────────────────────────────────────────────────

    async def stamp_and_publish(self, event: Event) -> bool:
        """
        Scope-check, stamp, and publish one event.

        Every event from every source (module, tool, agent action) must pass
        through here. This is the single scope-enforcement chokepoint.
        """
        candidate = self._candidate_from(event)
        decision = self._scope_engine.evaluate(
            candidate, source_distance=max(0, event.distance - 1)
        )
        event.scope_status = decision.status
        event.distance = decision.distance

        if decision.status is not ScopeStatus.IN:
            log.debug("out-of-scope (%s): %s", decision.reason, candidate)
            return False

        # Feed the planner this event's context BEFORE its handlers dispatch, so
        # technology/asset awareness reflects the event that triggered them.
        self._planner.observe(event)

        accepted = await self._bus.publish(event)

        if accepted:
            if self._live:
                from cli import ui
                print(ui.event_line(event))
            self._collect_for_summary(event)
            if self._persister is not None:
                asyncio.create_task(self._persister.save_event(event))

        return accepted

    # -- end-of-scan summary ------------------------------------------------

    def _collect_for_summary(self, event: Event) -> None:
        """Record accepted events so we can print a readable summary at the end."""
        t = event.type.value
        bucket = self._summary.setdefault(t, [])
        if len(bucket) < 5000:  # bounded
            bucket.append(event.data)

    def print_summary(self) -> None:
        """Print a compact, readable, colourful summary of what the scan found."""
        from cli import ui
        s = self._summary

        def _get(d, *names):
            for n in names:
                v = getattr(d, n, None)
                if v:
                    return v
            return None

        print()
        print(ui.rule("", fg="bcyan"))
        print("  " + ui.paint(f"SCAN SUMMARY", "bcyan", bold=True)
              + "  " + ui.paint(self._scan_domain or "", "bwhite", bold=True))
        print(ui.rule("", fg="bcyan"))

        # headline counts
        order = ["SUBDOMAIN", "DNS_RECORD", "IP", "OPEN_PORT", "HTTP_SERVICE",
                 "TECHNOLOGY", "URL", "ENDPOINT", "PARAMETER", "ANOMALY",
                 "FINDING_CANDIDATE"]
        fg_of = {
            "SUBDOMAIN": "cyan", "OPEN_PORT": "byellow", "HTTP_SERVICE": "bgreen",
            "TECHNOLOGY": "bmagenta", "URL": "blue", "ENDPOINT": "bcyan",
            "PARAMETER": "grey", "FINDING_CANDIDATE": "bred",
        }
        counts = {t: len(s.get(t, [])) for t in order if s.get(t)}
        if counts:
            chips = "   ".join(
                f"{ui.paint(t.lower(), fg_of.get(t, 'white'))}="
                f"{ui.paint(n, 'bwhite', bold=True)}"
                for t, n in counts.items()
            )
            print("  " + chips)

        # subdomains
        subs = sorted({_get(d, "hostname") for d in s.get("SUBDOMAIN", [])} - {None})
        if subs:
            print("\n" + ui.section("Subdomains", len(subs)))
            for h in subs:
                print(ui.bullet(h, "cyan"))

        # open ports grouped by host
        ports: dict[str, list[int]] = {}
        for d in s.get("OPEN_PORT", []):
            ports.setdefault(getattr(d, "host", "?"), []).append(getattr(d, "port", 0))
        if ports:
            print("\n" + ui.section("Open ports"))
            for host, plist in ports.items():
                pl = ", ".join(str(p) for p in sorted(set(plist)))
                print(ui.bullet(f"{host}: {ui.paint(pl, 'byellow')}"))

        # http services
        svcs = s.get("HTTP_SERVICE", [])
        if svcs:
            print("\n" + ui.section("HTTP services", len(svcs)))
            for d in svcs:
                title = _get(d, "title") or ""
                srv = _get(d, "server") or ""
                code = getattr(d, "status_code", "?")
                code_fg = "bgreen" if str(code).startswith("2") else (
                    "byellow" if str(code).startswith("3") else "bred")
                line = (f"{ui.paint('[' + str(code) + ']', code_fg, bold=True)} "
                        f"{ui.paint(_get(d, 'url'), 'bwhite')}"
                        f"{('  ' + srv) if srv else ''}"
                        f"{('  — ' + title) if title else ''}")
                print(ui.bullet(line))

        # technologies
        techs = sorted({f"{_get(d,'name')} {getattr(d,'version','') or ''}".strip()
                        for d in s.get("TECHNOLOGY", [])} - {""})
        if techs:
            print("\n" + ui.section("Technologies", len(techs)))
            print("  " + ", ".join(ui.paint(t, "bmagenta") for t in techs))

        # findings (the important bit)
        finds = s.get("FINDING_CANDIDATE", [])
        if finds:
            print("\n" + ui.warn(f"Findings ({len(finds)}):"))
            sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            for d in sorted(finds, key=lambda d: sev_rank.get((getattr(d, "severity_hint", "") or "info").lower(), 5)):
                sev = (getattr(d, "severity_hint", "") or "info").upper()
                badge = ui.paint(f"[{sev}]", ui.sev_color(sev), bold=True)
                print(ui.bullet(f"{badge} {getattr(d,'title','')}  "
                                f"{ui.paint('(' + str(getattr(d,'host','')) + ')', 'grey')}"))

        # url / endpoint / parameter counts
        extras = []
        for t, lbl in (("URL", "URLs"), ("ENDPOINT", "endpoints"), ("PARAMETER", "parameters")):
            if s.get(t):
                extras.append(f"{ui.paint(len(s[t]), 'bwhite', bold=True)} {lbl}")
        if extras:
            print("\n" + ui.info("discovered " + " · ".join(extras)
                                 + ui.paint("  (use --db-url to inspect)", "grey", dim=True)))
        print(ui.rule("", fg="bcyan"))

    async def run(self, seed_domain: str) -> None:
        self._scan_domain = seed_domain
        mode = "B — AI-assisted" if self._ai_enabled else "A — deterministic"
        log.info("scan %s | mode %s | seed %s", self._scan_id, mode, seed_domain)
        log.info("rate limiter: %s", self._rate_limiter.describe())
        from cli import ui
        print(ui.kv("scan-id", self._scan_id))
        print(ui.kv("mode", mode))
        print(ui.kv("seed", seed_domain))
        print(ui.kv("rate-lim", self._rate_limiter.describe()))

        if self._db_url:
            await self._init_db()

        try:
            await self._do_run(seed_domain)
        except Exception:
            if self._persister:
                await self._persister.scan_fail(self._scan_id)
            raise
        finally:
            if self._persister:
                await self._persister.scan_end(self._scan_id, self._bus.seen_count)

        self.print_summary()
        from cli import ui
        pstats = self._planner.stats
        if pstats["skipped"] or self._planner.config.mode != "default":
            print("\n" + ui.section("Planner", f"{pstats['mode']}"))
            print(ui.info(
                f"considered {pstats['considered']} · ran {pstats['ran']} · "
                f"skipped {pstats['skipped']} · cost {pstats['cost_spent']}"))
            for reason, n in sorted(pstats["skip_reasons"].items(), key=lambda kv: -kv[1])[:6]:
                print(ui.bullet(f"{ui.paint(str(n), 'byellow')} skipped — {reason}", "grey"))
        print(ui.ok(ui.paint(f"done — {self._bus.seen_count} events total", "bgreen", bold=True)))

    # ── properties ────────────────────────────────────────────────────────────

    @property
    def scan_id(self) -> UUID:
        return self._scan_id

    @property
    def bus(self) -> EventBus:
        return self._bus

    @property
    def scope_engine(self) -> ScopeEngine:
        return self._scope_engine

    @property
    def knowledge_base(self) -> "KnowledgeBase | None":
        """Persistent reconnaissance learning system (only when --db-url is given)."""
        return self._knowledge_base

    @property
    def scan_domain(self) -> str | None:
        """The seed domain of this scan (available once run() has started)."""
        return self._scan_domain

    @property
    def rate_limiter(self) -> RateLimiter:
        """Shared, WAF-aware rate limiter — used by every module, wrapper, and tool."""
        return self._rate_limiter

    @property
    def planner(self):
        """Adaptive Reconnaissance Planner deciding which modules run."""
        return self._planner

    @property
    def ai_enabled(self) -> bool:
        return self._ai_enabled

    @property
    def agent_enabled(self) -> bool:
        return self._agent_enabled

    # ── internals ─────────────────────────────────────────────────────────────

    async def _init_db(self) -> None:
        from database.persister import Persister
        from database.session import init_db, make_engine, make_session_factory
        engine = make_engine(self._db_url)  # type: ignore[arg-type]
        await init_db(engine)
        factory = make_session_factory(engine)
        session = factory()
        self._persister = Persister(session)
        # The knowledge base is cross-scan; give it its own session on the same
        # engine so its (lock-serialized) writes never interleave with the
        # persister's on a single shared AsyncSession.
        from database.knowledge_base import KnowledgeBase
        self._knowledge_base = KnowledgeBase(factory())
        scope_config = {
            "in_scope": [r.raw for r in self._scope.in_scope],
            "out_scope": [r.raw for r in self._scope.out_scope],
            "max_distance": self._scope.max_distance,
        }
        await self._persister.scan_start(
            self._scan_id,
            domain="",
            scope_config=scope_config,
            mode="B" if self._ai_enabled else "A",
        )

    async def _load_and_setup_modules(self) -> tuple[list["BaseModule"], list["BaseModule"]]:
        """
        Instantiate modules via registry, call setup(), subscribe reactive ones
        to the EventBus.

        Returns (seed_modules, reactive_modules).
        Modules whose setup() returns False are disabled and excluded.
        """
        from modules.registry import ModuleRegistry

        instances = ModuleRegistry.load_defaults(
            controller=self,
            extra_names=self._enabled_modules,
            extra_flags=self._enabled_flags,
            module_config=self._module_config,
        ) if self._enabled_modules is None and self._enabled_flags is None else (
            ModuleRegistry.load(
                names=self._enabled_modules,
                flags=self._enabled_flags,
                controller=self,
                module_config=self._module_config,
            )
        )

        active: list["BaseModule"] = []
        for module in instances:
            ok = await module.setup()
            if ok:
                active.append(module)
                log.debug("module enabled: %s", module.name)
            else:
                log.info("module disabled (setup returned False): %s", module.name)

        seed = [m for m in active if not m.watched_events]
        reactive = [m for m in active if m.watched_events]

        # Subscribe reactive modules to the bus.
        for module in reactive:
            for etype_str in module.watched_events:
                try:
                    etype = EventType(etype_str)
                except ValueError:
                    log.warning("module %s has unknown watched_event %r", module.name, etype_str)
                    continue

                async def _handler(event: Event, m: "BaseModule" = module) -> None:
                    # Adaptive planner decides whether this module is worth
                    # running for this event. Scope + rate limiting still apply
                    # to whatever it approves.
                    dec = self._planner.evaluate(m, event)
                    if not dec.run:
                        log.debug("[plan] skip %s", dec.explain())
                        return
                    try:
                        await m.handle_event(event)
                    except Exception as exc:
                        log.error("module %s raised on %s: %s", m.name, event.type, exc)

                self._bus.subscribe(etype, _handler)

        self._loaded_modules = active
        seed_names = [m.name for m in seed]
        reactive_names = [m.name for m in reactive]
        log.info("modules: seed=%s  reactive=%s", seed_names, reactive_names)
        from cli import ui
        print(ui.kv("seed mods", ", ".join(seed_names) or "(none)"))
        print(ui.kv("react mods", ", ".join(reactive_names) or "(none)"))
        return seed, reactive

    async def _do_run(self, seed_domain: str) -> None:
        # Load modules and subscribe reactive ones — MUST happen before any
        # events flow so reflexes are in place for the seed event.
        seed_modules, _reactive_modules = await self._load_and_setup_modules()

        if self._live:
            from cli import ui
            print("\n" + ui.rule("live events") + "\n")

        # Patch DB record with actual domain.
        if self._persister:
            from sqlalchemy import update
            from database.models import ScanJob
            await self._persister._scan_repo._s.execute(
                update(ScanJob)
                .where(ScanJob.id == self._scan_id)
                .values(target_domain=seed_domain)
            )
            await self._persister._scan_repo._s.commit()

        # Publish seed event (pre-stamped IN — it's the authorized starting point).
        seed = Event.create(
            EventType.SUBDOMAIN,
            SubdomainData(hostname=seed_domain, source="seed"),
            scan_job_id=self._scan_id,
            source_tool="seed",
            distance=0,
        )
        seed.scope_status = ScopeStatus.IN
        seed.distance = 1
        await self._bus.publish(seed)
        if self._persister:
            await self._persister.save_event(seed)

        # Run seed modules the planner approves for the selected mode, in parallel.
        approved_seeds = [m for m in seed_modules if self._planner.allow_seed(m).run]
        skipped = [m.name for m in seed_modules if m not in approved_seeds]
        if skipped:
            log.info("[plan] seed modules skipped (%s mode): %s",
                     self._planner.config.mode, ", ".join(skipped))
        if approved_seeds:
            await asyncio.gather(
                *[
                    asyncio.create_task(m.run(seed_domain, self._scan_id))
                    for m in approved_seeds
                ]
            )

        # Let in-flight reactive tasks settle.
        await asyncio.sleep(0.2)

        # Call finish() on every module.
        for module in self._loaded_modules:
            try:
                await module.finish()
            except Exception as exc:
                log.error("module %s finish() raised: %s", module.name, exc)

        # Phase 3: LLM triage.
        if self._ai_enabled and self._persister and self._anthropic_api_key:
            await self._run_triage(seed_domain)
        elif self._ai_enabled and not self._anthropic_api_key:
            log.warning("--ai set but ANTHROPIC_API_KEY not found — triage skipped")
        elif self._ai_enabled and not self._persister:
            log.warning("--ai requires --db-url for triage — skipped")

        # Phase 4: constrained agent loop.
        if self._agent_enabled and self._persister and self._anthropic_api_key:
            await self._run_agent(seed_domain)
        elif self._agent_enabled and not self._anthropic_api_key:
            log.warning("--agent set but ANTHROPIC_API_KEY not found — agent skipped")
        elif self._agent_enabled and not self._persister:
            log.warning("--agent requires --db-url — agent skipped")

    async def _run_triage(self, target_domain: str) -> None:
        from ai.triage import Triage
        assert self._persister is not None
        triage = Triage(
            api_key=self._anthropic_api_key,  # type: ignore[arg-type]
            host_repo=self._persister._host_repo,
            finding_repo=self._persister._finding_repo,
            assessment_repo=self._persister._assessment_repo,
            model=self._ai_model,
        )
        try:
            report = await triage.assess_scan(self._scan_id, target_domain)
            print(report.print_summary())
        except Exception as exc:
            log.error("triage failed: %s", exc)

    async def _run_agent(self, target_domain: str) -> None:
        import anthropic
        from agent.approval import ApprovalGate, ApprovalMode
        from agent.loop import AgentLoop
        from agent.stopping import StoppingConditions
        from agent.tools import build_tool_registry
        from ai.assessor import Assessor

        assert self._persister is not None
        client = anthropic.AsyncAnthropic(api_key=self._anthropic_api_key)
        assessor = Assessor(client, model=self._ai_model)

        loop = AgentLoop(
            controller=self,
            host_repo=self._persister._host_repo,
            finding_repo=self._persister._finding_repo,
            assessment_repo=self._persister._assessment_repo,
            assessor=assessor,
            stopping=StoppingConditions(max_iterations=self._max_agent_iterations),
            approval_gate=ApprovalGate(ApprovalMode.AUTO),
            tool_registry=build_tool_registry(self),
            max_iterations=self._max_agent_iterations,
        )

        from cli import ui
        print(ui.info(f"agent starting (max_iterations={self._max_agent_iterations})"))
        try:
            result = await loop.run(self._scan_id, target_domain)
            print(
                f"[recon-ai] agent stopped: reason={result.stop_reason}  "
                f"iterations={result.iterations}  new_events={result.total_new_events}"
            )
        except Exception as exc:
            log.error("agent loop failed: %s", exc)

    @staticmethod
    def _candidate_from(event: Event) -> str:
        d = event.data
        if hasattr(d, "hostname"):
            return d.hostname
        if hasattr(d, "address"):
            return d.address
        if hasattr(d, "host"):
            return d.host
        if hasattr(d, "url"):
            return urllib.parse.urlparse(d.url).hostname or ""
        return ""
