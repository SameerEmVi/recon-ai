"""Scan-configuration catalog: modules, modes, profiles (token-gated).

Feeds the scan-management form. Pure read of the existing registry/policy — no
scan logic.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from api.auth import require_token

router = APIRouter(prefix="/api", tags=["catalog"], dependencies=[Depends(require_token)])


@router.get("/catalog")
async def catalog() -> dict:
    from modules.registry import ModuleRegistry, SCAN_PROFILES
    from policy import MODES

    ModuleRegistry.discover()
    modules = [
        {"name": r["name"], "description": r["description"], "flags": r["flags"]}
        for r in ModuleRegistry.info()
    ]
    profiles = [{"name": n, "description": p.get("description", "")}
                for n, p in SCAN_PROFILES.items()]
    return {"modules": modules, "modes": list(MODES), "profiles": profiles}
