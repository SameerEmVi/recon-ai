"""Engagement policy file (policy/engagement.py) — authorization record + gating."""

from __future__ import annotations

import pytest

from policy import EngagementError, load_engagement, parse_engagement
from policy.engagement import Engagement


def test_valid_engagement_parses_all_fields():
    e = parse_engagement({
        "target": "example.com",
        "authorization": "Program ACME, ref #123",
        "tier": "pentest",
        "intrusive": True,
        "scope": {"in": ["*.example.com", "example.com"], "out": ["admin.example.com"],
                  "max_distance": 3},
        "rate_limit": 5,
        "max_concurrency": 10,
        "banned_tools": ["sqlmap", "Hydra"],
    })
    assert e.target == "example.com" and e.tier == "pentest"
    assert e.scope_dict() == {"in_scope": ["*.example.com", "example.com"],
                              "out_scope": ["admin.example.com"], "max_distance": 3}
    assert e.rate_limit == 5.0 and e.max_concurrency == 10
    assert e.authorizes_intrusive() is True
    assert e.is_tool_banned("SQLMAP") and e.is_tool_banned("hydra")
    assert not e.is_tool_banned("nuclei")


def test_intrusive_requires_authorization_statement():
    # intrusive=true alone is NOT enough — fail-closed.
    with pytest.raises(EngagementError, match="authorization"):
        parse_engagement({"target": "x.com", "intrusive": True})
    # with authorization, it's allowed.
    assert parse_engagement({"target": "x.com", "intrusive": True,
                             "authorization": "ok"}).authorizes_intrusive()


def test_authorizes_intrusive_is_false_without_optin():
    # authorization present but intrusive not opted in → still off.
    e = parse_engagement({"target": "x.com", "authorization": "ok", "intrusive": False})
    assert e.authorizes_intrusive() is False
    # blank authorization never authorizes.
    assert not Engagement(target="x", authorization="   ", intrusive=True).authorizes_intrusive()


@pytest.mark.parametrize("bad,match", [
    ({}, "target"),
    ({"target": "x", "tier": "nope"}, "tier"),
    ({"target": "x", "scope": []}, "scope"),
    ({"target": "x", "rate_limit": -1}, "rate_limit"),
    ({"target": "x", "banned_tools": 5}, "banned_tools"),
    ("not-a-mapping", "mapping"),
])
def test_invalid_engagements_fail_closed(bad, match):
    with pytest.raises(EngagementError, match=match):
        parse_engagement(bad)


def test_defaults_are_conservative():
    e = parse_engagement({"target": "x.com"})
    assert e.tier == "recon" and e.intrusive is False
    assert e.authorizes_intrusive() is False
    assert e.rate_limit is None and e.banned_tools == []


# ── file loading ─────────────────────────────────────────────────────────────────

def test_load_engagement_from_yaml(tmp_path):
    p = tmp_path / "engagement.yaml"
    p.write_text(
        "target: example.com\n"
        "authorization: Program ACME ref 123\n"
        "tier: pentest\n"
        "intrusive: true\n"
        "scope:\n  in: ['*.example.com']\n  max_distance: 2\n"
        "rate_limit: 3\n",
        encoding="utf-8")
    e = load_engagement(str(p))
    assert e.target == "example.com" and e.authorizes_intrusive()
    assert e.in_scope == ["*.example.com"] and e.max_distance == 2 and e.rate_limit == 3.0


def test_load_missing_file_fails_closed(tmp_path):
    with pytest.raises(EngagementError, match="not found"):
        load_engagement(str(tmp_path / "nope.yaml"))


def test_load_malformed_yaml_fails_closed(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("target: x\n  : : bad", encoding="utf-8")
    with pytest.raises(EngagementError):
        load_engagement(str(p))
