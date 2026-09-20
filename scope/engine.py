"""
The scope engine — the single deterministic gate for the whole platform.

Every candidate target (subdomain, IP, URL host) passes through
ScopeEngine.evaluate() before any recon tool is allowed to touch it. Both the
deterministic pipeline (Mode A) and the LLM agent (Mode B) are forced through
this same gate. The LLM may *propose* a target; only this code *decides* it.

Evaluation order is fixed and deny-first. Order is a security property, not a
style choice — see evaluate() for the rationale at each step.
"""

from __future__ import annotations

import ipaddress

from scope.types import (
    RuleKind,
    Scope,
    ScopeDecision,
    ScopeRule,
    ScopeStatus,
    _normalize_domain,
)


class ScopeEngine:
    """Holds a Scope and evaluates candidates against it.

    Stateless apart from the immutable Scope it wraps, so it is safe to share
    across goroutine-equivalents (threads/async tasks) for a given scan job.
    """

    def __init__(self, scope: Scope) -> None:
        self._scope = scope

    # -- public API --------------------------------------------------------

    def evaluate(self, candidate: str, source_distance: int = 0) -> ScopeDecision:
        """Return an IN/OUT decision for one candidate.

        `source_distance` is the distance of the event that produced this
        candidate; the candidate's own distance is source_distance + 1.

        Fixed evaluation order (deny-first):
          0. Parse/normalize the candidate. Unparseable => OUT (fail closed).
          1. DENY check. Any out_scope match => OUT immediately. Deny always
             wins, so a broad allow can never re-expose a specific carve-out.
          2. DISTANCE check. distance > max_distance => OUT, even if allowed.
             This is the recursion bound that stops the event graph wandering.
          3. ALLOW check. Must positively match an in_scope rule => IN.
          4. Default => OUT. Silence means no.
        """
        distance = source_distance + 1

        # Step 0: normalize candidate into either an IP or a domain.
        kind, ip_obj, domain = self._classify_candidate(candidate)
        if kind is None:
            return ScopeDecision(
                status=ScopeStatus.OUT,
                distance=distance,
                reason=f"candidate {candidate!r} is not a valid host or IP",
            )

        # Step 1: DENY wins. Checked first, before anything else. Deny matching
        # is intentionally broader than allow: an EXACT out-of-scope host also
        # carves out its whole subtree (out-scope x.abc.com => x.abc.com AND
        # *.x.abc.com are OUT). Erring toward denying more is the fail-safe
        # direction for an out-of-scope rule.
        deny = self._first_match(self._scope.out_scope, kind, ip_obj, domain, deny=True)
        if deny is not None:
            return ScopeDecision(
                status=ScopeStatus.OUT,
                distance=distance,
                reason=f"matched out-of-scope (deny) rule {deny.raw!r}",
                matched_rule=deny.raw,
            )

        # Step 2: distance bound. Enforced even for otherwise-allowed hosts.
        if distance > self._scope.max_distance:
            return ScopeDecision(
                status=ScopeStatus.OUT,
                distance=distance,
                reason=(
                    f"distance {distance} exceeds max_distance "
                    f"{self._scope.max_distance}"
                ),
            )

        # Step 3: require a positive allow match.
        allow = self._first_match(self._scope.in_scope, kind, ip_obj, domain)
        if allow is not None:
            return ScopeDecision(
                status=ScopeStatus.IN,
                distance=distance,
                reason=f"matched in-scope (allow) rule {allow.raw!r}",
                matched_rule=allow.raw,
            )

        # Step 4: default out.
        return ScopeDecision(
            status=ScopeStatus.OUT,
            distance=distance,
            reason="no in-scope rule matched (default deny)",
        )

    # -- internals ---------------------------------------------------------

    def _classify_candidate(self, candidate: str):
        """Return (kind, ip_obj, domain).

        kind is RuleKind.CIDR for IPs, RuleKind.EXACT for domains, or None if
        the candidate is unparseable/empty (caller treats None as OUT).
        """
        if candidate is None:
            return None, None, ""
        raw = candidate.strip().lower().rstrip(".")
        if not raw:
            return None, None, ""

        # IP?
        try:
            ip_obj = ipaddress.ip_address(raw)
            return RuleKind.CIDR, ip_obj, ""
        except ValueError:
            pass

        # Domain? Reject obviously invalid hostnames (spaces, empty labels).
        domain = _normalize_domain(raw)
        if not domain or not _looks_like_hostname(domain):
            return None, None, ""
        return RuleKind.EXACT, None, domain

    def _first_match(self, rules: list[ScopeRule], kind, ip_obj, domain, deny: bool = False):
        """Return the first rule in `rules` that matches the candidate, or None.

        `deny` is True when matching out-of-scope rules; it widens EXACT domain
        matching to include the host's subtree (see _rule_matches).
        """
        for rule in rules:
            if self._rule_matches(rule, kind, ip_obj, domain, deny=deny):
                return rule
        return None

    def _rule_matches(self, rule: ScopeRule, kind, ip_obj, domain, deny: bool = False) -> bool:
        # IP candidate only matches CIDR rules; domain candidate only matches
        # domain rules. No cross-type matching.
        if kind is RuleKind.CIDR:
            if rule.kind is not RuleKind.CIDR or rule.network is None:
                return False
            try:
                return ip_obj in rule.network
            except TypeError:
                # IPv4 candidate vs IPv6 network or vice versa
                return False

        # domain candidate
        if rule.kind is RuleKind.EXACT:
            if domain == rule.base_domain:
                return True
            # For a deny rule, an exact host also carves out its whole subtree.
            # Label-boundary compare (leading ".") — same defense the wildcard
            # branch uses against suffix/substring confusion. In-scope EXACT
            # rules stay strictly exact (deny=False).
            if deny and domain.endswith("." + rule.base_domain):
                return True
            return False

        if rule.kind is RuleKind.WILDCARD:
            base = rule.base_domain
            # Apex handling: "*.example.com" matches "example.com" only if the
            # flag is set. Otherwise apex must be listed explicitly.
            if domain == base:
                return self._scope.wildcard_includes_apex
            # Proper subdomain: must end with ".base" — the leading dot is what
            # defends against the suffix attack (example.com.evil.com) and
            # substring confusion (notexample.com). We compare on label
            # boundaries, never raw string suffix.
            return domain.endswith("." + base)

        return False


def _looks_like_hostname(domain: str) -> bool:
    """Cheap sanity check that a normalized string is a plausible hostname.

    Not a full RFC validator — just enough to reject whitespace-laden or
    empty-label garbage so it can't sneak through as a domain. Fails closed.
    """
    if not domain or len(domain) > 253:
        return False
    if " " in domain or "\t" in domain or "\n" in domain:
        return False
    labels = domain.split(".")
    if len(labels) < 2:  # require at least name.tld
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        # allow a-z 0-9 and hyphen (punycode already applied upstream)
        if not all(c.isalnum() or c == "-" for c in label):
            return False
    return True
