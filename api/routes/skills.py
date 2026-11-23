"""Skill-library routes (token-gated).

Read/create SKILL.md skills on disk. The agent-loop wiring (visibility enforcement,
tool unlock, call-stats) is phase 3; these routes manage the library itself.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.auth import require_token
from api.skills import create_skill, get_skill, list_skills, update_skill

router = APIRouter(prefix="/api", tags=["skills"], dependencies=[Depends(require_token)])


def _dir(request: Request) -> str:
    return request.app.state.settings.skills_dir


@router.get("/skills")
async def skills(request: Request) -> dict:
    return list_skills(_dir(request))


@router.get("/skills/{name}")
async def skill_detail(request: Request, name: str) -> dict:
    sk = get_skill(_dir(request), name)
    if sk is None:
        raise HTTPException(status_code=404, detail="skill not found")
    return sk


class SkillCreate(BaseModel):
    name: str
    description: str = ""
    body: str = ""
    roles: list[str] | None = None
    allowed_tools: list[str] | None = None
    linked_mcp: list[str] | None = None
    capabilities: list[str] | None = None
    tags: list[str] | None = None
    overwrite: bool = False


@router.post("/skills")
async def skill_create(request: Request, body: SkillCreate) -> dict:
    result = create_skill(_dir(request), body.model_dump())
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "create failed"))
    return result


class SkillUpdate(BaseModel):
    roles: list[str] | None = None
    description: str | None = None
    allowed_tools: list[str] | None = None
    linked_mcp: list[str] | None = None
    capabilities: list[str] | None = None
    tags: list[str] | None = None


@router.patch("/skills/{name}")
async def skill_update(request: Request, name: str, body: SkillUpdate) -> dict:
    result = update_skill(_dir(request), name, body.model_dump(exclude_none=True))
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "update failed"))
    return result
