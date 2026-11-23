"""Unit tests for phase-3 skill wiring: selection, stats, visibility, loop inject."""

from __future__ import annotations

from types import SimpleNamespace

from agentskills import (
    SkillLibrary, SkillStatsStore, context_terms, render_skill_context, select_skills,
)
from agentskills.loader import Skill

_IDOR = """---
name: hunt-idor
description: Hunt IDOR on endpoints with object ids.
roles: [worker, retest]
capabilities: [TARGET_HTTP_REQUEST, VULNERABILITY_CHECK]
tags: [idor, access-control]
triggers: [an endpoint takes an id]
---
# body
Method: swap the id.
"""
_WP = """---
name: wordpress-audit
description: Audit a WordPress install.
roles: [worker]
capabilities: [TARGET_HTTP_REQUEST]
tags: [wordpress, cms]
---
# body
Check wp-json.
"""
_INTRUSIVE = """---
name: intrusive-only
description: Needs intrusive.
roles: [worker]
capabilities: [INTRUSIVE_TEST]
tags: [danger]
---
# body
"""


def _lib(tmp_path):
    for name, content in [("hunt-idor", _IDOR), ("wordpress-audit", _WP),
                          ("intrusive-only", _INTRUSIVE)]:
        d = tmp_path / name
        d.mkdir()
        (d / "SKILL.md").write_text(content, encoding="utf-8")
    return SkillLibrary(str(tmp_path))


def test_context_terms_and_relevance(tmp_path):
    lib = _lib(tmp_path)
    terms = context_terms(technologies=["WordPress 6.4"], categories=[])
    sel = select_skills(lib.list(), role="worker",
                        mode_capabilities={"TARGET_HTTP_REQUEST", "VULNERABILITY_CHECK"},
                        terms=terms, limit=4)
    # wordpress-audit should rank first on the 'wordpress' match.
    assert sel[0]["skill"].name == "wordpress-audit"
    assert "wordpress" in sel[0]["matched"]


def test_role_visibility_filters(tmp_path):
    lib = _lib(tmp_path)
    # 'report' role sees none of these (all worker/retest).
    sel = select_skills(lib.list(), role="report",
                        mode_capabilities={"TARGET_HTTP_REQUEST", "VULNERABILITY_CHECK"},
                        terms=set())
    assert sel == []


def test_capability_ceiling_drops_infeasible(tmp_path):
    lib = _lib(tmp_path)
    # Under a ceiling WITHOUT intrusive, the intrusive-only skill is never offered.
    names = [s["skill"].name for s in select_skills(
        lib.list(), role="worker",
        mode_capabilities={"TARGET_HTTP_REQUEST", "VULNERABILITY_CHECK"}, terms=set(), limit=9)]
    assert "intrusive-only" not in names
    # With intrusive in the ceiling, it becomes available.
    names2 = [s["skill"].name for s in select_skills(
        lib.list(), role="worker",
        mode_capabilities={"TARGET_HTTP_REQUEST", "INTRUSIVE_TEST"}, terms=set(), limit=9)]
    assert "intrusive-only" in names2


def test_fallback_when_no_context(tmp_path):
    lib = _lib(tmp_path)
    sel = select_skills(lib.list(), role="worker",
                        mode_capabilities={"TARGET_HTTP_REQUEST", "VULNERABILITY_CHECK"},
                        terms=set(), limit=2)
    assert len(sel) == 2                                   # role methodology fallback
    assert all(s["reason"].startswith("general") for s in sel)


def test_render_context_includes_guardrail_note(tmp_path):
    lib = _lib(tmp_path)
    sel = select_skills(lib.list(), role="worker",
                        mode_capabilities={"TARGET_HTTP_REQUEST", "VULNERABILITY_CHECK"},
                        terms=context_terms(categories=["idor"]))
    block = render_skill_context(sel)
    assert "Loaded skills" in block
    assert "do NOT change scope" in block
    assert "hunt-idor" in block
    assert render_skill_context([]) == ""


def test_stats_record_and_snapshot(tmp_path):
    store = SkillStatsStore(str(tmp_path))
    store.record_load("hunt-idor", "scan-1")
    store.record_load("hunt-idor", "scan-1")              # same scan — tasks stays 1
    store.record_load("hunt-idor", "scan-2")
    snap = store.snapshot()["hunt-idor"]
    assert snap["total_calls"] == 3
    assert snap["tasks_covered"] == 2
    assert snap["last_called"] is not None
    assert store.for_skill("never")["total_calls"] == 0


def test_update_meta_toggles_visibility(tmp_path):
    lib = _lib(tmp_path)
    r = lib.update_meta("wordpress-audit", roles=["worker", "report"])
    assert r["ok"] and set(r["roles"]) == {"worker", "report"}
    again = lib.get("wordpress-audit")
    assert set(again.roles) == {"worker", "report"}
    assert again.body.strip().endswith("Check wp-json.")   # body preserved
    assert again.capabilities == ["TARGET_HTTP_REQUEST"]   # untouched field kept


def test_loop_inject_skills_is_additive_and_safe():
    """_inject_skills must fold context in, record a load, and never raise."""
    from agent.loop import AgentLoop

    class _FakeLib:
        def list(self):
            return [Skill(name="hunt-idor", description="Hunt IDOR", path="hunt-idor",
                          roles=["worker"], capabilities=["TARGET_HTTP_REQUEST"],
                          tags=["idor"], body="swap the id")]

    loads: list[str] = []
    stats = SimpleNamespace(record_load=lambda n, s=None: loads.append(n))
    loop = AgentLoop(
        controller=None, host_repo=None, finding_repo=None, assessment_repo=None,
        assessor=None, stopping=None, approval_gate=None, tool_registry={},
        skill_library=_FakeLib(), skill_stats=stats, agent_role="worker",
        mode_capabilities={"TARGET_HTTP_REQUEST"},
    )
    state = SimpleNamespace(
        hosts=[SimpleNamespace(technologies=["nginx"], services=[{"title": "IDOR test"}])],
        findings=[SimpleNamespace(category="idor")],
    )
    out = loop._inject_skills(state, "ORIGINAL PROMPT", "scan-9")
    assert "ORIGINAL PROMPT" in out
    assert "hunt-idor" in out
    assert loads == ["hunt-idor"]

    # No library → prompt is returned unchanged.
    bare = AgentLoop(controller=None, host_repo=None, finding_repo=None,
                     assessment_repo=None, assessor=None, stopping=None,
                     approval_gate=None, tool_registry={})
    assert bare._inject_skills(state, "P", "s") == "P"
