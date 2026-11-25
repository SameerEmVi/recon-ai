"""
Typed planner I/O schemas (spec §6, §4).

These Pydantic models define the ONLY shapes the LLM may emit — for goal
decomposition and for each planner round. The deterministic layer validates
every operation against these schemas before anything touches the database:
the LLM proposes, typed application code disposes.

Hard rules encoded here:
  * String fields are length-capped (hostile-input / prompt-injection defense —
    tool output and page content can reach the planner's context).
  * Priorities are bounded.
  * Creating a goal REQUIRES success criteria (a goal is a verifiable outcome,
    not a tool call).
  * Referenced ids must be well-formed UUIDs.

Scope/capability are NOT decided here — they are re-checked deterministically at
execution by the ScopeEngine and CapabilityPolicy. These schemas only guarantee
the *shape* is safe to process.
"""

from __future__ import annotations

from typing import Annotated, Literal, Optional, Union
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from exploration.types import PlannerOp

_T = 200     # title cap
_D = 2000    # description/rationale cap
_MAX_OPS = 24
_MAX_GOALS = 32


def _uuid_str(v: str) -> str:
    """Validate a string is a UUID (raise otherwise). Ids always come from the
    engine's own records, never free text, so a bad id is a rejected op."""
    UUID(str(v))
    return str(v)


# ── Goal decomposition (spec §4) ────────────────────────────────────────────────

class DecomposedGoal(BaseModel):
    """One goal the decomposer proposes. Sub-goals nest one level via `subgoals`."""
    title: str = Field(min_length=1, max_length=_T)
    description: str = Field(default="", max_length=_D)
    success_criteria: str = Field(min_length=1, max_length=_D)   # required — outcomes, not tools
    priority: int = Field(default=5, ge=1, le=9)
    subgoals: list["DecomposedGoal"] = Field(default_factory=list, max_length=_MAX_GOALS)


class GoalDecomposition(BaseModel):
    """Full decomposer output: the objective restated + a goal tree."""
    objective: str = Field(min_length=1, max_length=_D)
    goals: list[DecomposedGoal] = Field(min_length=1, max_length=_MAX_GOALS)


# ── Planner operations (spec §6) ────────────────────────────────────────────────

class CreateGoalOp(BaseModel):
    op: Literal[PlannerOp.CREATE_GOAL.value] = PlannerOp.CREATE_GOAL.value
    title: str = Field(min_length=1, max_length=_T)
    description: str = Field(default="", max_length=_D)
    success_criteria: str = Field(min_length=1, max_length=_D)
    parent_goal_id: Optional[str] = None
    priority: int = Field(default=5, ge=1, le=9)
    rationale: str = Field(default="", max_length=_D)

    @field_validator("parent_goal_id")
    @classmethod
    def _pid(cls, v): return _uuid_str(v) if v else v


class UpdateGoalOp(BaseModel):
    op: Literal[PlannerOp.UPDATE_GOAL.value] = PlannerOp.UPDATE_GOAL.value
    goal_id: str
    title: Optional[str] = Field(default=None, max_length=_T)
    description: Optional[str] = Field(default=None, max_length=_D)
    success_criteria: Optional[str] = Field(default=None, max_length=_D)
    priority: Optional[int] = Field(default=None, ge=1, le=9)

    @field_validator("goal_id")
    @classmethod
    def _gid(cls, v): return _uuid_str(v)


class CreateIntentOp(BaseModel):
    op: Literal[PlannerOp.CREATE_INTENT.value] = PlannerOp.CREATE_INTENT.value
    goal_id: str
    title: str = Field(min_length=1, max_length=_T)
    description: str = Field(default="", max_length=_D)
    tool_name: str = Field(min_length=1, max_length=_T)
    target: str = Field(default="", max_length=_T)
    rationale: str = Field(default="", max_length=_D)
    expected_result: str = Field(default="", max_length=_D)
    priority: int = Field(default=5, ge=1, le=9)
    required_capability: Optional[str] = Field(default=None, max_length=_T)
    parent_intent_id: Optional[str] = None

    @field_validator("goal_id")
    @classmethod
    def _gid(cls, v): return _uuid_str(v)

    @field_validator("parent_intent_id")
    @classmethod
    def _pid(cls, v): return _uuid_str(v) if v else v


class CancelIntentOp(BaseModel):
    op: Literal[PlannerOp.CANCEL_INTENT.value] = PlannerOp.CANCEL_INTENT.value
    intent_id: str
    reason: str = Field(default="", max_length=_D)

    @field_validator("intent_id")
    @classmethod
    def _iid(cls, v): return _uuid_str(v)


class PrioritizeGoalOp(BaseModel):
    op: Literal[PlannerOp.PRIORITIZE_GOAL.value] = PlannerOp.PRIORITIZE_GOAL.value
    goal_id: str
    priority: int = Field(ge=1, le=9)

    @field_validator("goal_id")
    @classmethod
    def _gid(cls, v): return _uuid_str(v)


class RecordHintOp(BaseModel):
    op: Literal[PlannerOp.RECORD_HINT.value] = PlannerOp.RECORD_HINT.value
    title: str = Field(min_length=1, max_length=_T)
    content: str = Field(default="", max_length=_D)
    goal_id: Optional[str] = None
    asset: str = Field(default="", max_length=_T)
    confidence: float = Field(default=0.3, ge=0.0, le=1.0)

    @field_validator("goal_id")
    @classmethod
    def _gid(cls, v): return _uuid_str(v) if v else v


class RequestOperatorApprovalOp(BaseModel):
    op: Literal[PlannerOp.REQUEST_OPERATOR_APPROVAL.value] = PlannerOp.REQUEST_OPERATOR_APPROVAL.value
    intent_id: str
    reason: str = Field(default="", max_length=_D)

    @field_validator("intent_id")
    @classmethod
    def _iid(cls, v): return _uuid_str(v)


class SatisfyGoalOp(BaseModel):
    # The LLM only RECOMMENDS satisfaction — the deterministic completion engine
    # validates evidence before a goal is actually marked satisfied.
    op: Literal[PlannerOp.SATISFY_GOAL.value] = PlannerOp.SATISFY_GOAL.value
    goal_id: str
    reason: str = Field(default="", max_length=_D)

    @field_validator("goal_id")
    @classmethod
    def _gid(cls, v): return _uuid_str(v)


class BlockGoalOp(BaseModel):
    op: Literal[PlannerOp.BLOCK_GOAL.value] = PlannerOp.BLOCK_GOAL.value
    goal_id: str
    reason: str = Field(default="", max_length=_D)

    @field_validator("goal_id")
    @classmethod
    def _gid(cls, v): return _uuid_str(v)


class ContinueOp(BaseModel):
    op: Literal[PlannerOp.CONTINUE.value] = PlannerOp.CONTINUE.value


class StopOp(BaseModel):
    op: Literal[PlannerOp.STOP.value] = PlannerOp.STOP.value
    reason: str = Field(default="", max_length=_D)


Operation = Annotated[
    Union[
        CreateGoalOp, UpdateGoalOp, CreateIntentOp, CancelIntentOp, PrioritizeGoalOp,
        RecordHintOp, RequestOperatorApprovalOp, SatisfyGoalOp, BlockGoalOp,
        ContinueOp, StopOp,
    ],
    Field(discriminator="op"),
]


class PlannerDecision(BaseModel):
    """One planner round's structured output."""
    reasoning: str = Field(default="", max_length=_D)
    operations: list[Operation] = Field(default_factory=list, max_length=_MAX_OPS)
