"""
Job model + lifecycle state machine for the hybrid scanning engine.

Pure and dependency-free (no DB, no asyncio) so it is trivially unit-testable;
the DB projection lives in `database.models.JobRecord` and the worker pool that
drives these lives in `scheduler.pool` (later increment).

A Job is either a TARGET job (scan one authorized subdomain) or a MODULE job
(run one module against one target). MODULE jobs may declare a parent TARGET job;
a child never carries broader authorization than its parent — scope is still
enforced per outbound request by the ScopeEngine, this is only bookkeeping.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class JobKind(str, Enum):
    TARGET = "target"
    MODULE = "module"


class JobState(str, Enum):
    QUEUED = "QUEUED"
    VALIDATING = "VALIDATING"      # checking the target against scope
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"              # held (e.g. target in WAF cooldown)
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"            # finished, but an independent sub-step failed
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"  # rejected by the scope engine — never ran


#: Terminal states — a job in one of these never transitions again.
TERMINAL_STATES: frozenset[JobState] = frozenset({
    JobState.COMPLETED, JobState.PARTIAL, JobState.FAILED,
    JobState.CANCELLED, JobState.OUT_OF_SCOPE,
})

#: Allowed state transitions. Deliberately strict so a bug can't, say, resurrect a
#: cancelled job or mark an out-of-scope target as completed.
_ALLOWED: dict[JobState, frozenset[JobState]] = {
    JobState.QUEUED: frozenset({
        JobState.VALIDATING, JobState.RUNNING, JobState.PAUSED,
        JobState.CANCELLED, JobState.OUT_OF_SCOPE,
    }),
    JobState.VALIDATING: frozenset({
        JobState.RUNNING, JobState.OUT_OF_SCOPE, JobState.FAILED, JobState.CANCELLED,
    }),
    JobState.RUNNING: frozenset({
        JobState.COMPLETED, JobState.PARTIAL, JobState.FAILED,
        JobState.CANCELLED, JobState.PAUSED,
    }),
    JobState.PAUSED: frozenset({
        JobState.RUNNING, JobState.QUEUED, JobState.CANCELLED,
    }),
    # terminal states intentionally map to nothing
}


class InvalidTransition(ValueError):
    """An illegal job state transition was attempted."""


@dataclass
class Job:
    target: str
    scan_id: uuid.UUID
    kind: JobKind = JobKind.TARGET
    module: str | None = None
    #: Lower number = higher priority (so a PriorityQueue pops it first).
    priority: int = 100
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    parent_id: uuid.UUID | None = None
    state: JobState = JobState.QUEUED
    #: Per-job wall-clock timeout in seconds (None = inherit pool default).
    timeout: float | None = None
    correlation_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    error: str | None = None
    result: dict | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        self.target = (self.target or "").strip().lower().rstrip(".")
        if self.kind is JobKind.MODULE and not self.module:
            raise ValueError("a MODULE job requires a module name")

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def dedup_key(self) -> str:
        """Stable identity for de-duplication: a target job per (kind,target); a
        module job per (kind,target,module). Two jobs with the same key are the
        same unit of work and must never both run."""
        base = f"{self.kind.value}:{self.target}"
        return f"{base}:{self.module}" if self.module else base

    def can_transition(self, to: JobState) -> bool:
        return to in _ALLOWED.get(self.state, frozenset())

    def transition(self, to: JobState, *, error: str | None = None,
                   result: dict | None = None) -> "Job":
        """Move to a new state (strict). Same-state is an idempotent no-op; an
        illegal transition raises InvalidTransition. Returns self for chaining."""
        if to == self.state:
            if error is not None:
                self.error = error
            if result is not None:
                self.result = result
            return self
        if not self.can_transition(to):
            raise InvalidTransition(
                f"{self.kind.value} job {self.target!r}: {self.state.value} -> {to.value} not allowed"
            )
        self.state = to
        self.updated_at = datetime.now(UTC)
        if error is not None:
            self.error = error
        if result is not None:
            self.result = result
        return self
