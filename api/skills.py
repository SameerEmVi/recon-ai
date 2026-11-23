"""Skill-library assembly for the GUI.

Thin read/write layer over `agentskills.SkillLibrary` (SKILL.md on disk). No scan
logic. Call-stats are a placeholder here (zeros) — the loop wiring that records
them lands in phase 3; the shape is already present so the UI is forward-compatible.
"""

from __future__ import annotations

from agentskills import AGENT_ROLES, SkillLibrary, SkillStatsStore

_ZERO = {"total_calls": 0, "tasks_covered": 0, "last_called": None}


def list_skills(skills_dir: str) -> dict:
    lib = SkillLibrary(skills_dir)
    stats = SkillStatsStore(skills_dir).snapshot()
    skills = [s.to_dict(with_body=False) for s in lib.list()]
    for s in skills:
        s["stats"] = stats.get(s["name"], dict(_ZERO))
    return {"root": skills_dir, "count": len(skills), "roles": list(AGENT_ROLES),
            "skills": skills}


def get_skill(skills_dir: str, name: str) -> dict | None:
    sk = SkillLibrary(skills_dir).get(name)
    if sk is None:
        return None
    d = sk.to_dict(with_body=True)
    d["stats"] = SkillStatsStore(skills_dir).for_skill(name)
    d["roles_all"] = list(AGENT_ROLES)
    return d


def update_skill(skills_dir: str, name: str, payload: dict) -> dict:
    """Edit a skill's metadata in place (visibility toggle, tags, caps). The
    markdown body is never touched."""
    return SkillLibrary(skills_dir).update_meta(
        name,
        roles=payload.get("roles"),
        description=payload.get("description"),
        allowed_tools=payload.get("allowed_tools"),
        linked_mcp=payload.get("linked_mcp"),
        capabilities=payload.get("capabilities"),
        tags=payload.get("tags"),
    )


def create_skill(skills_dir: str, payload: dict) -> dict:
    lib = SkillLibrary(skills_dir)
    return lib.create(
        name=str(payload.get("name", "")),
        description=str(payload.get("description", "")),
        body=str(payload.get("body", "")),
        roles=payload.get("roles") or None,
        allowed_tools=payload.get("allowed_tools") or None,
        linked_mcp=payload.get("linked_mcp") or None,
        capabilities=payload.get("capabilities") or None,
        tags=payload.get("tags") or None,
        overwrite=bool(payload.get("overwrite", False)),
    )
