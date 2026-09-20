"""
Scope engine test suite.

This file IS the specification for the scope engine. The scope boundary is the
single most security-critical piece of the platform: a scope escape means
touching a target we were never authorized to touch. Every case below is a way
a naive scope check gets fooled, or a guarantee we promised.

Run: pytest tests/security/test_scope_engine.py -v
"""

from __future__ import annotations

import pytest

from scope.engine import ScopeEngine
from scope.types import Scope, ScopeStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def evaluate(candidate: str, in_scope=None, out_scope=None,
             source_distance: int = 0, max_distance: int = 5,
             wildcard_includes_apex: bool = False):
    """Convenience wrapper: build a Scope, evaluate one candidate."""
    scope = Scope.from_strings(
        in_scope=in_scope or [],
        out_scope=out_scope or [],
        max_distance=max_distance,
        wildcard_includes_apex=wildcard_includes_apex,
    )
    engine = ScopeEngine(scope)
    return engine.evaluate(candidate, source_distance=source_distance)


# ---------------------------------------------------------------------------
# Wildcard allow-list behaviour
# ---------------------------------------------------------------------------

def test_wildcard_matches_direct_subdomain():
    d = evaluate("api.example.com", in_scope=["*.example.com"])
    assert d.status is ScopeStatus.IN


def test_wildcard_matches_multi_level_subdomain():
    # *.example.com must match arbitrarily deep subdomains
    d = evaluate("a.b.c.example.com", in_scope=["*.example.com"])
    assert d.status is ScopeStatus.IN


def test_wildcard_does_not_match_apex_by_default():
    # Apex must be listed explicitly — this is the agreed default.
    d = evaluate("example.com", in_scope=["*.example.com"])
    assert d.status is ScopeStatus.OUT


def test_wildcard_matches_apex_when_flag_enabled():
    d = evaluate("example.com", in_scope=["*.example.com"],
                 wildcard_includes_apex=True)
    assert d.status is ScopeStatus.IN


def test_apex_listed_explicitly_is_in():
    d = evaluate("example.com", in_scope=["example.com", "*.example.com"])
    assert d.status is ScopeStatus.IN


# ---------------------------------------------------------------------------
# Scope-escape defenses (the cases that actually matter)
# ---------------------------------------------------------------------------

def test_unrelated_domain_is_out():
    d = evaluate("evil.com", in_scope=["*.example.com"])
    assert d.status is ScopeStatus.OUT


def test_no_substring_confusion():
    # "notexample.com" must NOT match scope "*.example.com"
    d = evaluate("notexample.com", in_scope=["*.example.com"])
    assert d.status is ScopeStatus.OUT


def test_suffix_attack_is_out():
    # THE classic scope escape: attacker-controlled domain that ends with the
    # in-scope domain as a left-anchored label. example.com.evil.com must be OUT.
    d = evaluate("example.com.evil.com", in_scope=["*.example.com"])
    assert d.status is ScopeStatus.OUT


def test_prefix_glued_label_is_out():
    # "xexample.com" shares a suffix but is a different registrable label.
    d = evaluate("xexample.com", in_scope=["*.example.com"])
    assert d.status is ScopeStatus.OUT


def test_lookalike_with_extra_tld_is_out():
    d = evaluate("api.example.com.attacker.net", in_scope=["*.example.com"])
    assert d.status is ScopeStatus.OUT


# ---------------------------------------------------------------------------
# Deny-list precedence (deny always wins)
# ---------------------------------------------------------------------------

def test_deny_beats_allow_exact():
    d = evaluate("payments.example.com",
                 in_scope=["*.example.com"],
                 out_scope=["payments.example.com"])
    assert d.status is ScopeStatus.OUT
    assert "payments.example.com" in d.matched_rule


def test_deny_wildcard_beats_allow_wildcard():
    d = evaluate("db.staging.example.com",
                 in_scope=["*.example.com"],
                 out_scope=["*.staging.example.com"])
    assert d.status is ScopeStatus.OUT


def test_allow_still_works_for_sibling_of_denied_host():
    # The deny carve-out must not accidentally remove sibling hosts.
    d = evaluate("api.example.com",
                 in_scope=["*.example.com"],
                 out_scope=["payments.example.com"])
    assert d.status is ScopeStatus.IN


# ---------------------------------------------------------------------------
# Out-of-scope EXACT host carves out its whole subtree (deny is broader)
# ---------------------------------------------------------------------------

def test_exact_deny_removes_the_host_itself():
    # abc.com in scope, x.abc.com out — the exact host is denied.
    d = evaluate("x.abc.com",
                 in_scope=["*.abc.com", "abc.com"],
                 out_scope=["x.abc.com"])
    assert d.status is ScopeStatus.OUT
    assert "x.abc.com" in d.matched_rule


def test_exact_deny_also_removes_subdomains_of_denied_host():
    # The whole subtree under the denied host is OUT, via the same exact rule.
    for host in ("api.x.abc.com", "deep.nested.x.abc.com"):
        d = evaluate(host,
                     in_scope=["*.abc.com"],
                     out_scope=["x.abc.com"])
        assert d.status is ScopeStatus.OUT, host


def test_exact_deny_keeps_apex_and_siblings_in():
    # abc.com stays IN, sibling subdomains stay IN — only x.abc.com's tree is out.
    for host in ("abc.com", "y.abc.com", "www.abc.com"):
        d = evaluate(host,
                     in_scope=["*.abc.com", "abc.com"],
                     out_scope=["x.abc.com"])
        assert d.status is ScopeStatus.IN, host


def test_exact_deny_no_suffix_confusion():
    # "notx.abc.com" must NOT be caught by an out-scope rule for "x.abc.com".
    d = evaluate("notx.abc.com",
                 in_scope=["*.abc.com"],
                 out_scope=["x.abc.com"])
    assert d.status is ScopeStatus.IN


def test_in_scope_exact_stays_exact_not_subtree():
    # Allow matching is unchanged: an EXACT in-scope rule does NOT grant the
    # subtree (only deny was widened).
    d = evaluate("api.abc.com", in_scope=["abc.com"])
    assert d.status is ScopeStatus.OUT
    d2 = evaluate("abc.com", in_scope=["abc.com"])
    assert d2.status is ScopeStatus.IN


# ---------------------------------------------------------------------------
# Default-out semantics
# ---------------------------------------------------------------------------

def test_empty_in_scope_means_nothing_is_testable():
    d = evaluate("api.example.com", in_scope=[])
    assert d.status is ScopeStatus.OUT


def test_no_positive_match_defaults_out():
    d = evaluate("api.other.com", in_scope=["*.example.com"])
    assert d.status is ScopeStatus.OUT


# ---------------------------------------------------------------------------
# Distance / recursion bound
# ---------------------------------------------------------------------------

def test_distance_within_bound_is_in():
    d = evaluate("api.example.com", in_scope=["*.example.com"],
                 source_distance=2, max_distance=5)
    assert d.status is ScopeStatus.IN
    assert d.distance == 3  # source + 1


def test_distance_over_bound_is_out_even_if_allowed():
    d = evaluate("api.example.com", in_scope=["*.example.com"],
                 source_distance=5, max_distance=5)
    assert d.status is ScopeStatus.OUT
    assert "distance" in d.reason.lower()


# ---------------------------------------------------------------------------
# Case / normalization
# ---------------------------------------------------------------------------

def test_uppercase_candidate_normalized():
    d = evaluate("API.Example.COM", in_scope=["*.example.com"])
    assert d.status is ScopeStatus.IN


def test_trailing_dot_fqdn_normalized():
    d = evaluate("api.example.com.", in_scope=["*.example.com"])
    assert d.status is ScopeStatus.IN


def test_uppercase_rule_normalized():
    d = evaluate("api.example.com", in_scope=["*.EXAMPLE.COM"])
    assert d.status is ScopeStatus.IN


# ---------------------------------------------------------------------------
# IP / CIDR
# ---------------------------------------------------------------------------

def test_ip_in_cidr_is_in():
    d = evaluate("10.0.0.5", in_scope=["10.0.0.0/24"])
    assert d.status is ScopeStatus.IN


def test_ip_outside_cidr_is_out():
    d = evaluate("10.0.1.5", in_scope=["10.0.0.0/24"])
    assert d.status is ScopeStatus.OUT


def test_single_ip_rule_matches_exact_ip():
    d = evaluate("10.0.0.5", in_scope=["10.0.0.5"])
    assert d.status is ScopeStatus.IN


def test_deny_cidr_beats_allow_cidr():
    d = evaluate("10.0.0.5",
                 in_scope=["10.0.0.0/16"],
                 out_scope=["10.0.0.0/24"])
    assert d.status is ScopeStatus.OUT


def test_ipv6_in_cidr():
    d = evaluate("2001:db8::1", in_scope=["2001:db8::/32"])
    assert d.status is ScopeStatus.IN


# ---------------------------------------------------------------------------
# Malformed / hostile input (fail closed)
# ---------------------------------------------------------------------------

def test_empty_candidate_is_out():
    d = evaluate("", in_scope=["*.example.com"])
    assert d.status is ScopeStatus.OUT


def test_whitespace_candidate_is_out():
    d = evaluate("   ", in_scope=["*.example.com"])
    assert d.status is ScopeStatus.OUT


def test_garbage_candidate_is_out():
    d = evaluate("not a domain!!", in_scope=["*.example.com"])
    assert d.status is ScopeStatus.OUT


def test_malformed_rule_raises_at_parse_time():
    # A rule we cannot understand must fail loudly at construction, never
    # silently become permissive.
    with pytest.raises(ValueError):
        Scope.from_strings(in_scope=["*."])


# ---------------------------------------------------------------------------
# Never IN by accident: a decision is always explicit
# ---------------------------------------------------------------------------

def test_decision_always_has_reason():
    d = evaluate("api.example.com", in_scope=["*.example.com"])
    assert d.reason  # non-empty explanation on every decision
