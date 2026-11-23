"""
Agent plan model + deterministic plan validation.

The agent's "plan first, then work" mode asks the LLM once, up front, to
decompose the objective into an ordered list of concrete steps (PHASE 1). The
loop then executes those steps in order (PHASE 2).

The LLM only *proposes* an ordering. Everything security-relevant stays with
deterministic code:

  - `validate_steps()` drops any proposed step whose action is not a real
    registered tool or whose target was not already observed in the scan. The
    plan can never introduce a new action or a new target/scope.
  - Each step is still run through the approval gate, the tool registry, and the
    tool's own scope + capability checks at execution time (see AgentLoop).

So the plan is advisory structure; the invariants (scope decided by code,
capability ceiling, rate limiting) are untouched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

# Status values for a plan step.
PENDING = "pending"
DONE = "done"
SKIPPED = "skipped"   # dropped at execution (unknown tool / rejected / out of scope)
FAILED = "failed"     # tool raised


@dataclass
class PlanStep:
    action: str
    target: str
    rationale: str
    status: str = PENDING
    new_events: int = 0
    summary: str = ""

    @property
    def done(self) -> bool:
        return self.status != PENDING


@dataclass
class AgentPlan:
    goal: str = ""
    steps: list[PlanStep] = field(default_factory=list)
    # Reasons steps proposed by the LLM were rejected before execution (for
    # explainability / logging). Not security-load-bearing.
    dropped: list[str] = field(default_factory=list)

    @property
    def created(self) -> bool:
        return bool(self.steps)

    @property
    def pending_count(self) -> int:
        return sum(1 for s in self.steps if s.status == PENDING)

    def next_pending(self) -> PlanStep | None:
        for s in self.steps:
            if s.status == PENDING:
                return s
        return None

    def render(self) -> str:
        """Human-readable multi-line plan (for logs / observability)."""
        mark = {PENDING: "·", DONE: "✓", SKIPPED: "⤫", FAILED: "✗"}
        lines = [f"goal: {self.goal}" if self.goal else "goal: (unspecified)"]
        for i, s in enumerate(self.steps, 1):
            lines.append(f"  {i} {mark.get(s.status, '·')} {s.action}({s.target}) — {s.rationale}")
        return "\n".join(lines)


def _hostname(target: str) -> str:
    """Normalise a target (URL or bare host) to its hostname for comparison."""
    t = (target or "").strip()
    if not t:
        return ""
    parsed = urlparse(t if "://" in t else f"https://{t}")
    return (parsed.hostname or t).lower()


def observed_hostnames(hosts) -> set[str]:
    """The set of hostnames already observed in the scan — the only targets a
    plan step may act on. Includes host names and any service URL hostnames."""
    names: set[str] = set()
    for h in hosts or []:
        hn = getattr(h, "hostname", None)
        if hn:
            names.add(str(hn).lower())
        for svc in (getattr(h, "services", None) or []):
            url = svc.get("url") if isinstance(svc, dict) else None
            if url:
                hn2 = _hostname(url)
                if hn2:
                    names.add(hn2)
    return names


def validate_steps(
    raw_steps: list,
    *,
    known_actions: set[str],
    observed: set[str],
    max_steps: int = 8,
) -> tuple[list[PlanStep], list[str]]:
    """Deterministically filter LLM-proposed plan steps.

    A step survives only if:
      - its action is a currently-registered tool (mode-permitted), AND
      - its target's hostname was already observed in this scan.

    Duplicate (action, hostname) pairs collapse to the first. Returns the kept
    steps (capped) and a list of human-readable drop reasons.
    """
    kept: list[PlanStep] = []
    dropped: list[str] = []
    seen: set[tuple[str, str]] = set()

    for raw in (raw_steps or []):
        if not isinstance(raw, dict):
            dropped.append("malformed step (not an object)")
            continue
        action = str(raw.get("action", "")).strip()
        target = str(raw.get("target", "")).strip()
        rationale = str(raw.get("rationale", "")).strip()

        if action not in known_actions:
            dropped.append(f"{action or '(empty)'}({target}): unknown/forbidden action")
            continue
        host = _hostname(target)
        if not host:
            dropped.append(f"{action}: empty target")
            continue
        if host not in observed:
            dropped.append(f"{action}({target}): target '{host}' not observed — dropped")
            continue
        key = (action, host)
        if key in seen:
            dropped.append(f"{action}({target}): duplicate of an earlier step")
            continue

        seen.add(key)
        kept.append(PlanStep(action=action, target=target, rationale=rationale))
        if len(kept) >= max_steps:
            break

    return kept, dropped
