"""Agent-skill library — SKILL.md discovery, parsing, and (phase 3) selection.

A *skill* is a folder with a `SKILL.md`: YAML frontmatter (name, description,
when-to-use triggers, visibility roles, linked tools/capabilities) plus a markdown
body of instructions. The format matches the agentskills.io / Claude Code spec, so
an existing skill library is reusable verbatim.

Design invariants (see CLAUDE.md deterministic-vs-LLM split):
  * A skill is *progressive-disclosure context* — the agent sees name+description
    cheaply and loads the body only when a task matches.
  * A skill may PROPOSE actions and UNLOCK tools, but its declared capabilities are
    an **upper bound intersected with the mode's capability ceiling** — never an
    escalation. Scope + policy stay authoritative. `allowed_capabilities()` applies
    that intersection; the loop (phase 3) consults it.
"""

from agentskills.loader import (
    AGENT_ROLES,
    Skill,
    SkillLibrary,
    allowed_capabilities,
    is_valid_skill_name,
)
from agentskills.selection import (
    context_terms,
    render_skill_context,
    select_skills,
)
from agentskills.stats import SkillStatsStore

__all__ = [
    "AGENT_ROLES",
    "Skill",
    "SkillLibrary",
    "SkillStatsStore",
    "allowed_capabilities",
    "context_terms",
    "is_valid_skill_name",
    "render_skill_context",
    "select_skills",
]
