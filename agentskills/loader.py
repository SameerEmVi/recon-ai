"""SKILL.md discovery + parsing + a write path for the library.

Pure filesystem + parsing — no network, no DB. Safe to call from the web layer
and (phase 3) from the agent loop. Never raises on a malformed skill: a bad file
becomes a `Skill` with `.error` set, so one broken skill can't hide the rest.
"""

from __future__ import annotations

import glob
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

try:                                   # declared dep, but never hard-fail on import
    import yaml
    _HAVE_YAML = True
except Exception:                      # pragma: no cover
    _HAVE_YAML = False

# Canonical agent roles a skill can be made visible to (recon-ai's loop roles).
AGENT_ROLES = ("planner", "worker", "report", "retest")

# A skill name is a path segment we create/open — keep it a strict slug so it can
# never traverse out of the library root.
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)
_MAX_SKILL_BYTES = 1_000_000           # a SKILL.md over ~1MB is almost certainly wrong


def is_valid_skill_name(name: str) -> bool:
    return bool(_NAME_RE.match(name or ""))


@dataclass
class Skill:
    name: str
    description: str
    path: str                          # library-relative dir, e.g. "hunt-idor"
    version: str | None = None
    roles: list[str] = field(default_factory=list)       # visibility (empty = all)
    allowed_tools: list[str] = field(default_factory=list)
    linked_mcp: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)  # policy caps it may use
    triggers: list[str] = field(default_factory=list)      # when-to-use
    tags: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)     # sibling files
    body: str = ""                     # markdown instructions (full in get, trimmed in list)
    summary: str = ""                  # short preview for listings
    updated_at: float = 0.0
    error: str | None = None

    def to_dict(self, *, with_body: bool = True) -> dict:
        d = asdict(self)
        if not with_body:
            d.pop("body", None)
        return d


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        # allow "a, b" or "a b"
        parts = re.split(r"[,\n]", v) if "," in v else v.split()
        return [p.strip() for p in parts if p.strip()]
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [str(v)]


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    """Return (meta, body). Tolerant: no frontmatter → ({}, whole text)."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text
    raw, body = m.group(1), m.group(2)
    meta: dict = {}
    if _HAVE_YAML:
        try:
            loaded = yaml.safe_load(raw)
            if isinstance(loaded, dict):
                meta = loaded
        except Exception:
            meta = _parse_kv(raw)
    else:
        meta = _parse_kv(raw)
    return meta, body


def _parse_kv(raw: str) -> dict:
    """Minimal `key: value` fallback when YAML is unavailable/invalid."""
    out: dict = {}
    for line in raw.splitlines():
        if ":" not in line or line.lstrip().startswith("#"):
            continue
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip()
    return out


def _summary(body: str, cap: int = 240) -> str:
    for line in body.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            return s[:cap]
    # fall back to the first non-empty line even if it's a heading
    for line in body.splitlines():
        s = line.strip().lstrip("# ").strip()
        if s:
            return s[:cap]
    return ""


class SkillLibrary:
    def __init__(self, root: str) -> None:
        self.root = root

    # ── discovery ────────────────────────────────────────────────────────────
    def _skill_files(self) -> list[str]:
        if not os.path.isdir(self.root):
            return []
        found: set[str] = set()
        # <root>/<skill>/SKILL.md and one level deeper (categorised libraries).
        for pat in ("*/SKILL.md", "*/*/SKILL.md", "SKILL.md"):
            for p in glob.glob(os.path.join(self.root, pat)):
                if os.path.isfile(p):
                    found.add(os.path.normpath(p))
        return sorted(found)

    def _parse_file(self, md_path: str) -> Skill:
        rel_dir = os.path.relpath(os.path.dirname(md_path), self.root)
        dir_name = os.path.basename(os.path.dirname(md_path)) or "skill"
        try:
            size = os.path.getsize(md_path)
            if size > _MAX_SKILL_BYTES:
                return Skill(name=dir_name, description="", path=rel_dir,
                             error="SKILL.md too large")
            with open(md_path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            updated = os.path.getmtime(md_path)
        except OSError as exc:
            return Skill(name=dir_name, description="", path=rel_dir, error=str(exc))

        meta, body = _parse_frontmatter(text)
        name = str(meta.get("name") or dir_name).strip()
        roles = [r for r in _as_list(meta.get("roles") or meta.get("visibility"))
                 if r in AGENT_ROLES]
        resources = []
        try:
            for f in os.listdir(os.path.dirname(md_path)):
                if f.lower() != "skill.md" and os.path.isfile(
                        os.path.join(os.path.dirname(md_path), f)):
                    resources.append(f)
        except OSError:
            pass

        return Skill(
            name=name,
            description=str(meta.get("description") or "").strip(),
            path=rel_dir if rel_dir != "." else name,
            version=(str(meta["version"]) if meta.get("version") is not None else None),
            roles=roles,
            allowed_tools=_as_list(meta.get("allowed_tools") or meta.get("allowed-tools")),
            linked_mcp=_as_list(meta.get("linked_mcp") or meta.get("linked-mcp") or meta.get("mcp")),
            capabilities=_as_list(meta.get("capabilities")),
            triggers=_as_list(meta.get("triggers") or meta.get("when_to_use") or meta.get("when-to-use")),
            tags=_as_list(meta.get("tags")),
            resources=sorted(resources),
            body=body.strip(),
            summary=_summary(body),
            updated_at=updated,
        )

    # ── public API ───────────────────────────────────────────────────────────
    def list(self) -> list[Skill]:
        skills = [self._parse_file(p) for p in self._skill_files()]
        skills.sort(key=lambda s: s.name.lower())
        return skills

    def get(self, name: str) -> Skill | None:
        for p in self._skill_files():
            sk = self._parse_file(p)
            if sk.name == name or os.path.basename(os.path.dirname(p)) == name:
                return sk
        return None

    def create(self, *, name: str, description: str = "", body: str = "",
               roles: list[str] | None = None, allowed_tools: list[str] | None = None,
               linked_mcp: list[str] | None = None, capabilities: list[str] | None = None,
               tags: list[str] | None = None, overwrite: bool = False) -> dict:
        """Write a new SKILL.md. Returns {ok, name|error}. Name is slug-validated
        so it can never escape the library root."""
        if not is_valid_skill_name(name):
            return {"ok": False, "error": "invalid skill name (use a-z, 0-9, -, _, .)"}
        skill_dir = os.path.join(self.root, name)
        md_path = os.path.join(skill_dir, "SKILL.md")
        # Confinement guard (belt-and-suspenders beyond the slug).
        if os.path.abspath(skill_dir) != os.path.abspath(os.path.join(self.root, name)):
            return {"ok": False, "error": "path error"}
        if os.path.exists(md_path) and not overwrite:
            return {"ok": False, "error": "a skill with that name already exists"}
        meta = {"name": name, "description": description.strip()}
        if roles:
            meta["roles"] = [r for r in roles if r in AGENT_ROLES]
        if allowed_tools:
            meta["allowed_tools"] = list(allowed_tools)
        if linked_mcp:
            meta["linked_mcp"] = list(linked_mcp)
        if capabilities:
            meta["capabilities"] = list(capabilities)
        if tags:
            meta["tags"] = list(tags)
        try:
            os.makedirs(skill_dir, exist_ok=True)
            front = yaml.safe_dump(meta, sort_keys=False).strip() if _HAVE_YAML \
                else "\n".join(f"{k}: {v}" for k, v in meta.items())
            with open(md_path, "w", encoding="utf-8") as fh:
                fh.write(f"---\n{front}\n---\n\n{body.strip()}\n")
        except OSError as exc:
            return {"ok": False, "error": str(exc)[:200]}
        return {"ok": True, "name": name, "path": name}

    def update_meta(self, name: str, *, roles=None, description=None,
                    allowed_tools=None, linked_mcp=None, capabilities=None,
                    tags=None) -> dict:
        """Rewrite an existing skill's frontmatter in place (body preserved).
        Only the fields passed (non-None) are changed. Used by the visibility
        toggle and metadata edits — the markdown body is never touched."""
        sk = self.get(name)
        if sk is None:
            return {"ok": False, "error": "skill not found"}
        roles_v = sk.roles if roles is None else [r for r in roles if r in AGENT_ROLES]
        meta = {"name": sk.name,
                "description": sk.description if description is None else str(description).strip()}
        if sk.version:
            meta["version"] = sk.version
        if roles_v:
            meta["roles"] = roles_v
        at = sk.allowed_tools if allowed_tools is None else list(allowed_tools)
        lm = sk.linked_mcp if linked_mcp is None else list(linked_mcp)
        caps = sk.capabilities if capabilities is None else list(capabilities)
        tg = sk.tags if tags is None else list(tags)
        if at:
            meta["allowed_tools"] = at
        if lm:
            meta["linked_mcp"] = lm
        if caps:
            meta["capabilities"] = caps
        if sk.triggers:
            meta["triggers"] = sk.triggers
        if tg:
            meta["tags"] = tg
        md_path = self._path_for(sk)
        try:
            front = yaml.safe_dump(meta, sort_keys=False).strip() if _HAVE_YAML \
                else "\n".join(f"{k}: {v}" for k, v in meta.items())
            with open(md_path, "w", encoding="utf-8") as fh:
                fh.write(f"---\n{front}\n---\n\n{sk.body.strip()}\n")
        except OSError as exc:
            return {"ok": False, "error": str(exc)[:200]}
        return {"ok": True, "name": sk.name, "roles": roles_v}

    def _path_for(self, sk: Skill) -> str:
        """Resolve the on-disk SKILL.md path for a parsed skill."""
        for p in self._skill_files():
            if (self._parse_file(p).name == sk.name
                    or os.path.basename(os.path.dirname(p)) == sk.name):
                return p
        return os.path.join(self.root, sk.name, "SKILL.md")


def allowed_capabilities(skill: Skill, mode_capabilities: set[str]) -> set[str]:
    """Phase-3 gate: the capabilities a skill may actually exercise = what it
    declares INTERSECTED with the mode's ceiling. A skill that declares nothing is
    treated as declaring nothing extra (it rides the mode's own allowance). A skill
    can never widen the set — this is the deterministic invariant made explicit."""
    declared = {c.strip() for c in skill.capabilities if c.strip()}
    if not declared:
        return set(mode_capabilities)
    return declared & set(mode_capabilities)
