"""Deterministic skill selection + context rendering for the agent loop.

Progressive disclosure: given the agent's *role*, the mode's capability ceiling,
and the *observed context* of the scan (technologies, finding categories, host
text), pick the handful of skills worth loading and render their guidance into the
prompt. Pure and unit-tested — no network, no DB, no LLM.

Invariants (CLAUDE.md):
  * Role visibility is honoured — a skill not granted to the role is never offered.
  * A skill whose declared capabilities are ALL outside the mode ceiling is dropped
    (it couldn't do anything anyway). It never widens the ceiling.
  * Selection only decides what *context* the LLM sees. Scope, rate limits, policy
    and the tool registry remain the authoritative gates on any actual action.
"""

from __future__ import annotations

import re

from agentskills.loader import Skill

_WORD = re.compile(r"[a-z0-9]+")
_STOP = frozenset({
    "the", "a", "an", "and", "or", "to", "of", "for", "on", "in", "is", "use",
    "when", "with", "that", "this", "it", "its", "at", "by", "as", "be", "are",
    "hunt", "skill", "using", "via", "from", "into",
})


def _tokens(text: str) -> set[str]:
    return {w for w in _WORD.findall((text or "").lower()) if w not in _STOP and len(w) > 1}


def context_terms(*, technologies=None, categories=None, extra_text=None) -> set[str]:
    """Normalise observed scan signals into a bag of match terms."""
    terms: set[str] = set()
    for t in technologies or []:
        terms |= _tokens(str(t))
    for c in categories or []:
        terms |= _tokens(str(c))
    for x in extra_text or []:
        terms |= _tokens(str(x))
    return terms


def _skill_terms(s: Skill) -> set[str]:
    bag: set[str] = set()
    bag |= _tokens(s.name)
    bag |= {t.lower() for t in s.tags}
    for t in s.tags:
        bag |= _tokens(t)
    for tr in s.triggers:
        bag |= _tokens(tr)
    bag |= _tokens(s.description)
    return bag


def score_skill(s: Skill, terms: set[str]) -> tuple[int, list[str]]:
    """Relevance = overlap between the skill's vocabulary and the observed terms.
    Returns (score, matched_terms)."""
    matched = sorted(_skill_terms(s) & terms)
    return len(matched), matched


def select_skills(skills: list[Skill], *, role: str, mode_capabilities: set[str],
                  terms: set[str] | None = None, limit: int = 4) -> list[dict]:
    """Pick up to `limit` skills applicable to `role` under the mode ceiling,
    ranked by relevance to `terms`. Falls back to role-visible skills (by name)
    when nothing matches, so the agent always gets some methodology. Each entry:
    {skill, score, matched, reason}."""
    terms = terms or set()
    feasible: list[Skill] = []
    for s in skills:
        if s.error:
            continue
        if s.roles and role not in s.roles:          # visibility
            continue
        if s.capabilities and not (set(s.capabilities) & set(mode_capabilities)):
            continue                                  # can't act under this mode at all
        feasible.append(s)

    scored = []
    for s in feasible:
        score, matched = score_skill(s, terms)
        scored.append((s, score, matched))

    matching = [t for t in scored if t[1] > 0]
    matching.sort(key=lambda t: (-t[1], t[0].name.lower()))

    if matching:
        chosen = matching[:limit]
    else:
        # No context match yet (e.g. early in a scan) — offer role methodology.
        chosen = sorted(scored, key=lambda t: t[0].name.lower())[:limit]

    out = []
    for s, score, matched in chosen:
        if matched:
            reason = f"matches {', '.join(matched[:5])}"
        else:
            reason = f"general {role} methodology"
        out.append({"skill": s, "score": score, "matched": matched, "reason": reason})
    return out


def render_skill_context(selected: list[dict], *, max_body_chars: int = 1200) -> str:
    """Render the selected skills into a prompt section. Empty string when none."""
    if not selected:
        return ""
    lines = [
        "## Loaded skills (methodology for this role)",
        "These skills matched the current target context. Follow their method. "
        "They do NOT change scope, rate limits, or what you're authorized to do — "
        "those gates still apply to every action.",
    ]
    for item in selected:
        s: Skill = item["skill"]
        lines.append(f"\n### {s.name} — {s.description}")
        if item["matched"]:
            lines.append(f"_(relevant: {', '.join(item['matched'][:6])})_")
        body = s.body.strip()
        if len(body) > max_body_chars:
            body = body[:max_body_chars].rstrip() + "\n…(truncated)"
        if body:
            lines.append(body)
    return "\n".join(lines)
