"""
Goal decomposition engine (spec §4).

When an exploration starts, the operator objective is decomposed into a small
hierarchy of *verifiable outcome* goals — never tool calls. The LLM proposes the
hierarchy; deterministic code validates it against the GoalDecomposition schema
and persists it through the typed ExplorationStore.

The LLM is injected as a `propose(prompt, tool) -> dict` callable, so this module
has no hard dependency on an API key: production wires in the Assessor, tests (and
a keyless operator acting as the LLM) wire in a function returning the decision.
Scope is never widened here — goals describe outcomes, not targets.
"""

from __future__ import annotations

from typing import Awaitable, Callable

from exploration.schemas import GoalDecomposition
from exploration.store import ExplorationStore
from exploration.types import EdgeRel, GoalState, NodeKind

Proposer = Callable[[str, dict], Awaitable[dict]]

# Forced-tool schema mirroring GoalDecomposition (one nested sub-goal level).
_GOAL_PROPS = {
    "title": {"type": "string", "description": "A verifiable OUTCOME (not a tool call)."},
    "description": {"type": "string"},
    "success_criteria": {"type": "string", "description": "How we deterministically know this goal is met."},
    "priority": {"type": "integer", "minimum": 1, "maximum": 9},
}
DECOMPOSE_TOOL: dict = {
    "name": "decompose_goals",
    "description": (
        "Decompose the authorized objective into 3-8 verifiable OUTCOME goals. "
        "A goal states a desired result (e.g. 'Identify live HTTP services'), never "
        "a tool to run. Add a success_criteria for every goal. Only use sub-goals "
        "when they genuinely aid planning. Never expand the authorized scope."
    ),
    "input_schema": {
        "type": "object",
        "required": ["objective", "goals"],
        "properties": {
            "objective": {"type": "string"},
            "goals": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["title", "success_criteria"],
                    "properties": {
                        **_GOAL_PROPS,
                        "subgoals": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["title", "success_criteria"],
                                "properties": _GOAL_PROPS,
                            },
                        },
                    },
                },
            },
        },
    },
}


def build_decompose_prompt(objective: str, target: str, constraints: dict) -> str:
    in_scope = ", ".join(constraints.get("in_scope", []) or []) or f"*.{target}, {target}"
    out_scope = ", ".join(constraints.get("out_scope", []) or []) or "(none)"
    return (
        f"Authorized objective: {objective}\n"
        f"Primary target: {target}\n"
        f"In-scope (authorized): {in_scope}\n"
        f"Out-of-scope (never touch): {out_scope}\n"
        f"Mode: {constraints.get('mode', 'active')}  "
        f"Intrusive allowed: {bool(constraints.get('intrusive'))}\n\n"
        "Decompose this into verifiable OUTCOME goals with success criteria. "
        "Goals describe results to establish, not tools to run, and must stay "
        "within the authorized scope."
    )


async def decompose(objective: str, target: str, constraints: dict,
                    propose: Proposer) -> GoalDecomposition:
    """Ask the LLM for a goal hierarchy and validate it. Raises ValidationError if
    the proposed structure is malformed (caller logs + aborts decomposition)."""
    prompt = build_decompose_prompt(objective, target, constraints)
    raw = await propose(prompt, DECOMPOSE_TOOL)
    return GoalDecomposition.model_validate(raw or {})


async def persist_decomposition(store: ExplorationStore, run, decomp: GoalDecomposition) -> list:
    """Persist the goal tree + objective→goal / goal→sub-goal edges + activities.
    Returns the flat list of created Goal rows (parents before children)."""
    created: list = []

    async def _persist(goals, parent_id):
        for g in goals:
            goal = await store.create_goal(
                exploration_id=run.id, title=g.title,
                success_criteria={"text": g.success_criteria},
                description=g.description, parent_goal_id=parent_id,
                priority=g.priority, created_by="decomposer", state=GoalState.OPEN.value)
            created.append(goal)
            if parent_id is None:
                await store.add_edge(exploration_id=run.id, src_id=run.id, src_kind=NodeKind.OBJECTIVE.value,
                                     dst_id=goal.id, dst_kind=NodeKind.GOAL.value, rel=EdgeRel.SPAWNS.value)
            else:
                await store.add_edge(exploration_id=run.id, src_id=parent_id, src_kind=NodeKind.GOAL.value,
                                     dst_id=goal.id, dst_kind=NodeKind.GOAL.value, rel=EdgeRel.SPAWNS.value)
            await store.log_activity(exploration_id=run.id, activity_type="goal_created",
                                     summary=goal.title, node_id=goal.id, worker="decomposer")
            if g.subgoals:
                await _persist(g.subgoals, goal.id)

    await _persist(decomp.goals, None)
    return created
