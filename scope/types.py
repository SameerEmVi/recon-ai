"""
Data types for the scope engine.

The scope engine is the single deterministic gate every candidate target passes
through before any recon tool touches it. These types define its inputs
(the in/out scope rules) and its output (an IN/OUT decision with a reason).

Nothing in this module — or anywhere in the scope package — may depend on the
LLM/agent layer. Scope is decided by code, never by a model.
"""

from __future__ import annotations

import enum
import ipaddress
from dataclasses import dataclass, field


class ScopeStatus(str, enum.Enum):
    """The result of a scope evaluation.

    PENDING is the *birth* state of every event before the scope engine has
    stamped it. A tool must refuse to consume any candidate that is not IN.
    The absence of a decision is therefore itself a blocking state.
    """

    IN = "IN"
    OUT = "OUT"
    PENDING = "PENDING"


class RuleKind(str, enum.Enum):
    EXACT = "EXACT"        # api.example.com
    WILDCARD = "WILDCARD"  # *.example.com
    CIDR = "CIDR"          # 10.0.0.0/24  (also covers a single IP as /32 or /128)


@dataclass(frozen=True)
class ScopeRule:
    """A single normalized scope rule.

    Use ScopeRule.parse() to build one from a raw string — do not construct
    directly, so that normalization is always applied.
    """

    kind: RuleKind
    # For EXACT/WILDCARD: the normalized domain (wildcard stored WITHOUT the
    # leading "*.", e.g. "*.example.com" -> base_domain "example.com").
    # For CIDR: empty string; the network lives in `network`.
    base_domain: str = ""
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    raw: str = ""  # original string, kept for logging/audit

    @staticmethod
    def parse(raw_rule: str) -> "ScopeRule":
        """Parse and normalize a raw rule string into a ScopeRule.

        Accepts:
          - "*.example.com"      -> WILDCARD
          - "api.example.com"    -> EXACT
          - "10.0.0.0/24"        -> CIDR
          - "10.0.0.5"           -> CIDR (/32)
          - "2001:db8::/32"      -> CIDR
        Raises ValueError on empty/unparseable input (fail closed — a rule we
        can't understand must never silently become a permissive match).
        """
        if raw_rule is None:
            raise ValueError("scope rule cannot be None")
        original = raw_rule
        # Lowercase + strip whitespace, but do NOT strip trailing dots yet:
        # a malformed wildcard like "*." must be caught before normalization
        # rounds it off into something that looks valid.
        rule = raw_rule.strip().lower()
        if not rule:
            raise ValueError("scope rule cannot be empty")

        # Wildcard validation FIRST, on the un-dot-stripped string.
        # A "*" may appear only as a leading "*." prefix, and there must be a
        # real base domain after it. Anything else fails closed.
        if "*" in rule:
            if not rule.startswith("*."):
                raise ValueError(
                    f"'*' is only allowed as a leading '*.' wildcard: {original!r}"
                )
            base = _normalize_domain(rule[2:])
            if not base or "*" in base:
                raise ValueError(
                    f"wildcard rule missing a valid base domain: {original!r}"
                )
            return ScopeRule(kind=RuleKind.WILDCARD, base_domain=base, raw=original)

        # No wildcard involved — now safe to strip trailing FQDN dot.
        rule = rule.rstrip(".")
        if not rule:
            raise ValueError("scope rule cannot be empty")

        # CIDR / IP first — a value with "/" or that parses as an IP is a network.
        if "/" in rule:
            try:
                net = ipaddress.ip_network(rule, strict=False)
                return ScopeRule(kind=RuleKind.CIDR, network=net, raw=original)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR rule {original!r}: {exc}") from exc

        # Bare IP address -> single-host network.
        try:
            ip = ipaddress.ip_address(rule)
            net = ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False)
            return ScopeRule(kind=RuleKind.CIDR, network=net, raw=original)
        except ValueError:
            pass  # not an IP, fall through to domain handling

        base = _normalize_domain(rule)
        if not base:
            raise ValueError(f"could not parse scope rule: {original!r}")
        return ScopeRule(kind=RuleKind.EXACT, base_domain=base, raw=original)


@dataclass
class Scope:
    """The two-list scope for a target: an allow-list and a deny-list.

    Semantics (enforced by ScopeEngine, not here):
      - out_scope is a VETO: any match => OUT, regardless of in_scope.
      - in_scope is a PERMIT: a positive match is REQUIRED to be IN.
      - default is OUT: no permit => OUT.
      - empty in_scope => nothing is testable (safe default).
    """

    in_scope: list[ScopeRule] = field(default_factory=list)
    out_scope: list[ScopeRule] = field(default_factory=list)
    max_distance: int = 5  # recursion bound: hops from the seed target

    # If True, a wildcard "*.example.com" ALSO permits the apex "example.com".
    # Default False: apex must be listed explicitly (matches how bug bounty
    # scopes are usually written). Flag exists so it can be flipped per program.
    wildcard_includes_apex: bool = False

    @staticmethod
    def from_strings(
        in_scope: list[str] | None = None,
        out_scope: list[str] | None = None,
        max_distance: int = 5,
        wildcard_includes_apex: bool = False,
    ) -> "Scope":
        """Build a Scope from raw rule strings, parsing/normalizing each."""
        return Scope(
            in_scope=[ScopeRule.parse(r) for r in (in_scope or [])],
            out_scope=[ScopeRule.parse(r) for r in (out_scope or [])],
            max_distance=max_distance,
            wildcard_includes_apex=wildcard_includes_apex,
        )


@dataclass(frozen=True)
class ScopeDecision:
    """The engine's verdict on one candidate."""

    status: ScopeStatus
    distance: int
    reason: str          # human/audit-readable explanation
    matched_rule: str = ""  # the raw rule that decided it, if any


def _normalize_domain(domain: str) -> str:
    """Normalize a domain for comparison.

    - strip whitespace, lowercase
    - strip a single trailing dot (FQDN form)
    - IDN -> punycode (so unicode and ascii forms compare equal)

    Fails closed: if IDN encoding fails, we keep the lowercased ascii form
    rather than raising, but callers parsing rules will still get a usable
    string. Candidate normalization uses the same function for symmetry.
    """
    if domain is None:
        return ""
    d = domain.strip().lower().rstrip(".")
    if not d:
        return ""
    try:
        # encode each label to punycode; "idna" codec handles the whole name
        d = d.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        # leave as-is; comparison will simply not match unexpected unicode
        pass
    return d
