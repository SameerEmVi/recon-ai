"""
ReconPlanner — the Adaptive Reconnaissance Planner.

Recon-AI is event-driven: modules subscribe to event types and, by default,
fire on every matching event. That runs *everything against everything*. The
planner sits in front of module dispatch and decides, per (module, event),
whether running the module is actually worth it — considering the discovered
asset/technology, the module's cost and expected value, how many times it has
already run, a configurable budget, and the selected mode (passive-first /
default / aggressive).

What it does NOT do (by design — these stay exactly where they are):
  * Scope enforcement — still the ScopeEngine via ScanController.stamp_and_publish.
  * Rate limiting / WAF backoff — still the shared RateLimiter via guard().
The planner only gates *dispatch*; a module it approves still passes through both.

Guarantees:
  * Loop prevention — a per-(module, host) execution cap bounds re-firing, on top
    of the scope engine's distance bound and the bus's event dedup.
  * Dedup — the same module never runs twice for the same (host, event-type) past
    the cap; the bus already drops duplicate events upstream.
  * Explainability — every decision carries a human reason ("run graphql on
    api.x.com because technology GraphQL is present"), retrievable via explain().

Default mode is deliberately permissive so it changes nothing for existing
scans; passive-first and aggressive are opt-in.
"""

from __future__ import annotations

import logging
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field

log = logging.getLogger("planner")

# ── modes ─────────────────────────────────────────────────────────────────────

MODE_PASSIVE_FIRST = "passive-first"   # only passive modules run (safe recon)
MODE_DEFAULT = "default"               # run active + passive, bounded by budget
MODE_AGGRESSIVE = "aggressive"         # everything, high caps, high budget
MODES = (MODE_PASSIVE_FIRST, MODE_DEFAULT, MODE_AGGRESSIVE)

# ── relative cost / value scales ────────────────────────────────────────────

COST_LOW, COST_MEDIUM, COST_HIGH = 1, 3, 8
VALUE_LOW, VALUE_MEDIUM, VALUE_HIGH = 1, 3, 8

# Per-host execution cap by mode (loop prevention). 0 in config => this default.
_CAP_BY_MODE = {
    MODE_PASSIVE_FIRST: 25,
    MODE_DEFAULT: 60,
    MODE_AGGRESSIVE: 250,
}


@dataclass
class PlannerConfig:
    mode: str = MODE_DEFAULT
    max_executions: int = 0   # total module runs; 0 = unlimited
    max_cost: int = 0         # total cost budget; 0 = unlimited
    per_host_cap: int = 0     # per (module, host) run cap; 0 = mode default
    min_value: int = 0        # skip decisions whose score < this

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"unknown planner mode {self.mode!r}; expected one of {MODES}")


@dataclass(frozen=True)
class PlanDecision:
    module: str
    host: str
    event_type: str
    run: bool
    reason: str
    score: int = 0
    cost: int = 0

    def explain(self) -> str:
        verb = "run" if self.run else "skip"
        return f"{verb} {self.module} on {self.host} [{self.event_type}] — {self.reason}"


@dataclass
class _Counters:
    considered: int = 0
    ran: int = 0
    skipped: int = 0
    cost_spent: int = 0
    skip_reasons: dict[str, int] = field(default_factory=lambda: defaultdict(int))


class ReconPlanner:
    """Adaptive planner. Thread-compatible for asyncio single-loop use."""

    def __init__(self, config: PlannerConfig | None = None, *, max_decisions: int = 5000) -> None:
        self.config = config or PlannerConfig()
        self._counters = _Counters()
        self._decisions: list[PlanDecision] = []
        self._max_decisions = max_decisions

        # discovered context, keyed by host
        self._host_tech: dict[str, set[str]] = defaultdict(set)
        self._host_events: dict[str, set[str]] = defaultdict(set)
        self._host_assets: dict[str, set[str]] = defaultdict(set)
        self._all_tech: set[str] = set()

        # execution state
        self._runs: dict[tuple[str, str], int] = defaultdict(int)  # (module, host) -> count
        self._total_exec = 0

    # ── observation: build context from every accepted event ──────────────────

    def observe(self, event) -> None:
        """Record what a scope-accepted event tells us about a host.

        Called by the controller before an event's handlers are dispatched, so
        the planner's technology/asset context reflects this event too."""
        host = self._host_of(event)
        etype = getattr(getattr(event, "type", None), "value", "") or ""
        if host:
            self._host_events[host].add(etype)
        d = getattr(event, "data", None)

        if etype == "TECHNOLOGY":
            name = (getattr(d, "name", "") or "").lower()
            if name:
                self._all_tech.add(name)
                if host:
                    self._host_tech[host].add(name)
        elif etype == "HTTP_SERVICE":
            if host:
                self._host_assets[host].add("http")
        elif etype == "URL":
            url = getattr(d, "url", "") or ""
            if host and url.lower().split("?")[0].endswith(".js"):
                self._host_assets[host].add("js-app")

    # ── cost / value model ────────────────────────────────────────────────────

    @staticmethod
    def cost_of(module) -> int:
        c = getattr(module, "estimated_cost", None)
        if c is not None:
            return int(c)
        flags = set(getattr(module, "flags", []) or [])
        if "slow" in flags:
            return COST_HIGH
        if "passive" in flags:
            return COST_LOW
        return COST_MEDIUM

    @staticmethod
    def value_of(module, *, tech_matched: bool) -> int:
        v = getattr(module, "expected_value", None)
        base = int(v) if v is not None else VALUE_MEDIUM
        # A module that fired specifically because its target technology is
        # present is high-signal — boost it.
        if tech_matched:
            base = max(base, VALUE_HIGH)
        return base

    # ── the decision ──────────────────────────────────────────────────────────

    def evaluate(self, module, event) -> PlanDecision:
        """Decide whether `module` should handle `event`. Records + returns it."""
        host = self._host_of(event) or "(no-host)"
        etype = getattr(getattr(event, "type", None), "value", "") or ""
        passive = "passive" in set(getattr(module, "flags", []) or [])
        cost = self.cost_of(module)

        # 1. mode gate — passive-first defers all active modules.
        if self.config.mode == MODE_PASSIVE_FIRST and not passive:
            return self._record(module.name, host, etype, False,
                                 "passive-first mode: active module deferred", 0, cost)

        # 2. technology gate — only for modules that target specific technologies.
        techs = [t.lower() for t in (getattr(module, "supported_technologies", []) or [])]
        tech_matched = False
        matched_name = ""
        if techs:
            present = set(self._host_tech.get(host, set()))
            if etype == "TECHNOLOGY":
                nm = (getattr(getattr(event, "data", None), "name", "") or "").lower()
                if nm:
                    present.add(nm)
            hit = self._match_tech(techs, present)
            if not hit:
                return self._record(module.name, host, etype, False,
                                    f"no supported technology present (needs one of {techs})",
                                    0, cost)
            tech_matched = True
            matched_name = hit

        # 3. prerequisites — required event types must already exist for the host.
        for pre in (getattr(module, "prerequisites", []) or []):
            if pre not in self._host_events.get(host, set()):
                return self._record(module.name, host, etype, False,
                                    f"prerequisite {pre} not yet observed on {host}", 0, cost)

        # 4. loop prevention / dedup — per (module, host) cap.
        cap = self.config.per_host_cap or _CAP_BY_MODE.get(self.config.mode, 60)
        key = (module.name, host)
        if self._runs[key] >= cap:
            return self._record(module.name, host, etype, False,
                                f"per-host cap reached ({cap}) — loop prevention", 0, cost)

        # 5. budget gates.
        if self.config.max_executions and self._total_exec >= self.config.max_executions:
            return self._record(module.name, host, etype, False,
                                f"execution budget exhausted ({self.config.max_executions})", 0, cost)
        if self.config.max_cost and (self._counters.cost_spent + cost) > self.config.max_cost:
            return self._record(module.name, host, etype, False,
                                f"cost budget exhausted ({self.config.max_cost})", 0, cost)

        # 6. value threshold.
        value = self.value_of(module, tech_matched=tech_matched)
        score = value - cost
        if score < self.config.min_value:
            return self._record(module.name, host, etype, False,
                                f"below value threshold (score {score} < {self.config.min_value})",
                                score, cost)

        # → run. Commit execution state.
        self._runs[key] += 1
        self._total_exec += 1
        if tech_matched:
            reason = f"technology '{matched_name}' present on {host}"
        elif passive:
            reason = "passive module (safe, low cost)"
        else:
            reason = f"active {self._asset_hint(host)}module within budget"
        return self._record(module.name, host, etype, True, reason, score, cost, commit_cost=True)

    def allow_seed(self, module) -> PlanDecision:
        """Gate a seed module (run once at scan start; no triggering host)."""
        passive = "passive" in set(getattr(module, "flags", []) or [])
        cost = self.cost_of(module)
        if self.config.mode == MODE_PASSIVE_FIRST and not passive:
            return self._record(module.name, "(seed)", "SEED", False,
                                "passive-first mode: active seed module skipped", 0, cost)
        if self.config.max_executions and self._total_exec >= self.config.max_executions:
            return self._record(module.name, "(seed)", "SEED", False,
                                "execution budget exhausted", 0, cost)
        self._total_exec += 1
        return self._record(module.name, "(seed)", "SEED", True,
                            "seed module (enumeration entry point)", VALUE_MEDIUM, cost,
                            commit_cost=True)

    # ── explainability / introspection ────────────────────────────────────────

    @property
    def stats(self) -> dict:
        c = self._counters
        return {
            "mode": self.config.mode,
            "considered": c.considered,
            "ran": c.ran,
            "skipped": c.skipped,
            "cost_spent": c.cost_spent,
            "skip_reasons": dict(c.skip_reasons),
            "technologies_seen": sorted(self._all_tech),
        }

    @property
    def decisions(self) -> list[PlanDecision]:
        return list(self._decisions)

    def selected(self) -> list[PlanDecision]:
        return [d for d in self._decisions if d.run]

    def explain(self, *, limit: int = 25) -> str:
        c = self._counters
        lines = [
            f"planner [{self.config.mode}]: considered {c.considered}, "
            f"ran {c.ran}, skipped {c.skipped}, cost {c.cost_spent}",
        ]
        runs = self.selected()
        if runs:
            lines.append("selected:")
            for d in runs[:limit]:
                lines.append(f"  ✓ {d.explain()}")
        if c.skip_reasons:
            lines.append("skips by reason:")
            for reason, n in sorted(c.skip_reasons.items(), key=lambda kv: -kv[1]):
                lines.append(f"  ✗ {n:>4}  {reason}")
        return "\n".join(lines)

    # ── internals ─────────────────────────────────────────────────────────────

    def _record(self, module, host, etype, run, reason, score, cost, *, commit_cost=False) -> PlanDecision:
        self._counters.considered += 1
        if run:
            self._counters.ran += 1
            if commit_cost:
                self._counters.cost_spent += cost
        else:
            self._counters.skipped += 1
            self._counters.skip_reasons[reason.split(" (")[0].split(" —")[0]] += 1
        dec = PlanDecision(module, host, etype, run, reason, score, cost)
        if len(self._decisions) < self._max_decisions:
            self._decisions.append(dec)
        log.debug("[plan] %s", dec.explain())
        return dec

    @staticmethod
    def _match_tech(needles: list[str], present: set[str]) -> str:
        for n in needles:
            for p in present:
                if n == p or n in p or p in n:
                    return n
        return ""

    def _asset_hint(self, host: str) -> str:
        assets = self._host_assets.get(host, set())
        return (next(iter(sorted(assets))) + " ") if assets else ""

    @staticmethod
    def _host_of(event) -> str:
        d = getattr(event, "data", None)
        if d is None:
            return ""
        for attr in ("hostname", "address", "host"):
            v = getattr(d, attr, None)
            if v:
                return str(v).lower()
        url = getattr(d, "url", None)
        if url:
            try:
                return (urllib.parse.urlparse(url).hostname or "").lower()
            except Exception:
                return ""
        return ""
