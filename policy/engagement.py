"""
Engagement policy file (`engagement.yaml`) — the per-target authorization record
(roadmap §"engagement policy file"; docs/pentest-section-design.md §7.3).

One file per target holds the engagement's ground truth: scope, pacing, the
allowed tier, banned tools, and — critically — an explicit **authorization**
statement that the pentest/intrusive tiers require. The deterministic-vs-LLM rule
extends here: *authorization is a precondition, not a flag*. The intrusive tier
refuses to unlock unless the file both authorizes it and carries an authorization
statement, so an out-of-scope or unauthorized intrusive request can never be the
result of a missing CLI flag.

Example `engagement.yaml`:

    target: example.com
    authorization: "Bug bounty program ACME, scope snapshot 2026-11-26, ref #123"
    tier: pentest                 # ceiling: osint | recon | pentest
    intrusive: false              # may the intrusive tier unlock?
    scope:
      in:  ["*.example.com", "example.com"]
      out: ["admin.example.com"]
      max_distance: 5
    rate_limit: 5                 # requests/sec (optional)
    max_concurrency: 10           # (optional)
    banned_tools: ["sqlmap"]      # modules/tools never to run

Fail-closed: a malformed file raises `EngagementError`; `intrusive: true` without
an `authorization` statement raises; an unknown `tier` raises.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from policy.policy import TIERS


class EngagementError(ValueError):
    """The engagement file is missing, malformed, or internally unauthorized."""


@dataclass(frozen=True)
class Engagement:
    target: str
    authorization: str = ""
    tier: str = "recon"
    intrusive: bool = False
    in_scope: list[str] = field(default_factory=list)
    out_scope: list[str] = field(default_factory=list)
    max_distance: int = 5
    rate_limit: float | None = None
    max_concurrency: int | None = None
    banned_tools: list[str] = field(default_factory=list)

    def authorizes_intrusive(self) -> bool:
        """Intrusive testing is authorized only when the file both opts in AND
        carries a non-empty authorization statement — never on `intrusive: true`
        alone."""
        return bool(self.intrusive and self.authorization.strip())

    def is_tool_banned(self, name: str) -> bool:
        return name.lower() in {t.lower() for t in self.banned_tools}

    def scope_dict(self) -> dict:
        return {"in_scope": list(self.in_scope), "out_scope": list(self.out_scope),
                "max_distance": self.max_distance}


def _as_list(v, field_name: str) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    raise EngagementError(f"'{field_name}' must be a list of strings")


def parse_engagement(data: dict) -> Engagement:
    """Validate a parsed mapping into an Engagement (fail-closed)."""
    if not isinstance(data, dict):
        raise EngagementError("engagement file must be a YAML mapping")

    target = str(data.get("target") or "").strip()
    if not target:
        raise EngagementError("engagement: 'target' is required")

    tier = str(data.get("tier") or "recon").strip().lower()
    if tier not in TIERS:
        raise EngagementError(
            f"engagement: unknown tier {tier!r} — use one of {', '.join(TIERS)}")

    authorization = str(data.get("authorization") or "").strip()
    intrusive = bool(data.get("intrusive", False))
    if intrusive and not authorization:
        raise EngagementError(
            "engagement: intrusive=true requires a non-empty 'authorization' "
            "statement — fail-closed (an unauthorized intrusive test is an incident)")

    scope = data.get("scope")
    if scope is None:
        scope = {}
    elif not isinstance(scope, dict):
        raise EngagementError("engagement: 'scope' must be a mapping")
    try:
        max_distance = int(scope.get("max_distance", 5))
    except (TypeError, ValueError):
        raise EngagementError("engagement: scope.max_distance must be an integer")

    def _num(key):
        v = data.get(key)
        if v is None:
            return None
        try:
            n = float(v)
        except (TypeError, ValueError):
            raise EngagementError(f"engagement: '{key}' must be a number")
        if n <= 0:
            raise EngagementError(f"engagement: '{key}' must be > 0")
        return n

    rate = _num("rate_limit")
    conc = _num("max_concurrency")

    return Engagement(
        target=target,
        authorization=authorization,
        tier=tier,
        intrusive=intrusive,
        in_scope=_as_list(scope.get("in"), "scope.in"),
        out_scope=_as_list(scope.get("out"), "scope.out"),
        max_distance=max_distance,
        rate_limit=rate,
        max_concurrency=int(conc) if conc is not None else None,
        banned_tools=_as_list(data.get("banned_tools"), "banned_tools"),
    )


def load_engagement(path: str) -> Engagement:
    """Load + validate an engagement.yaml. Raises EngagementError (fail-closed)."""
    import os

    import yaml

    if not os.path.isfile(path):
        raise EngagementError(f"engagement file not found: {path}")
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise EngagementError(f"engagement file is not valid YAML: {exc}") from exc
    return parse_engagement(data or {})
