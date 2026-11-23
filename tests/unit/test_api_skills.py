"""Unit tests for the agent-skill library (agentskills/ + api/skills.py)."""

from __future__ import annotations

from agentskills import SkillLibrary, allowed_capabilities, is_valid_skill_name
from agentskills.loader import Skill
from api.skills import create_skill, get_skill, list_skills

_SKILL = """---
name: hunt-ssrf
description: Hunt SSRF on url-fetching endpoints.
version: 1.2.0
roles: [worker, retest]
capabilities: [TARGET_HTTP_REQUEST, VULNERABILITY_CHECK]
triggers:
  - a parameter takes a URL
tags: [ssrf, web]
allowed_tools: [httpx_probe, nuclei]
---

# Hunt SSRF

Goal: prove the server fetches an attacker-controlled destination.
"""


def _seed(tmp_path, name="hunt-ssrf", content=_SKILL):
    d = tmp_path / name
    d.mkdir()
    (d / "SKILL.md").write_text(content, encoding="utf-8")
    return str(tmp_path)


def test_name_validation():
    assert is_valid_skill_name("hunt-ssrf")
    assert is_valid_skill_name("hunt_ssrf.v2")
    assert not is_valid_skill_name("../evil")
    assert not is_valid_skill_name("has space")
    assert not is_valid_skill_name("")


def test_parse_frontmatter(tmp_path):
    root = _seed(tmp_path)
    sk = SkillLibrary(root).get("hunt-ssrf")
    assert sk is not None
    assert sk.description.startswith("Hunt SSRF")
    assert sk.version == "1.2.0"
    assert sk.roles == ["worker", "retest"]
    assert "TARGET_HTTP_REQUEST" in sk.capabilities
    assert sk.tags == ["ssrf", "web"]
    assert "httpx_probe" in sk.allowed_tools
    assert "# Hunt SSRF" in sk.body


def test_list_excludes_body_and_sorts(tmp_path):
    root = _seed(tmp_path)
    _seed(tmp_path, name="aaa-first", content="---\nname: aaa-first\ndescription: a\n---\nbody")
    out = list_skills(root)
    assert out["count"] == 2
    assert [s["name"] for s in out["skills"]] == ["aaa-first", "hunt-ssrf"]
    assert "body" not in out["skills"][0]
    assert out["skills"][0]["stats"]["total_calls"] == 0


def test_malformed_skill_does_not_break_listing(tmp_path):
    root = _seed(tmp_path)
    bad = tmp_path / "broken"
    bad.mkdir()
    (bad / "SKILL.md").write_text("---\n: : : not yaml\nname\n---\nbody", encoding="utf-8")
    out = list_skills(root)                       # must not raise
    assert out["count"] == 2


def test_no_frontmatter_uses_dirname(tmp_path):
    root = _seed(tmp_path, name="plain", content="just a body, no frontmatter")
    sk = SkillLibrary(root).get("plain")
    assert sk is not None and sk.name == "plain"
    assert sk.body.startswith("just a body")


def test_create_roundtrip_and_reject_bad_name(tmp_path):
    root = str(tmp_path)
    r = create_skill(root, {"name": "new-skill", "description": "d",
                            "body": "# body", "roles": ["worker"],
                            "capabilities": ["TARGET_HTTP_REQUEST"], "tags": ["x"]})
    assert r["ok"] is True
    got = get_skill(root, "new-skill")
    assert got is not None and got["roles"] == ["worker"]
    assert got["capabilities"] == ["TARGET_HTTP_REQUEST"]
    # duplicate rejected, traversal rejected
    assert create_skill(root, {"name": "new-skill"})["ok"] is False
    assert create_skill(root, {"name": "../escape"})["ok"] is False


def test_allowed_capabilities_intersection():
    sk = Skill(name="x", description="", path="x",
               capabilities=["TARGET_HTTP_REQUEST", "INTRUSIVE_TEST"])
    ceiling = {"PASSIVE_EXTERNAL", "TARGET_HTTP_REQUEST", "VULNERABILITY_CHECK"}
    # A skill can never widen the mode ceiling — INTRUSIVE_TEST is dropped.
    assert allowed_capabilities(sk, ceiling) == {"TARGET_HTTP_REQUEST"}
    # A skill that declares nothing rides the ceiling unchanged.
    assert allowed_capabilities(Skill(name="y", description="", path="y"), ceiling) == ceiling


def test_get_missing_returns_none(tmp_path):
    assert get_skill(str(tmp_path), "nope") is None
