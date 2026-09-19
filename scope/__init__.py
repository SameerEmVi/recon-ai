"""
scope — the deterministic scope engine.

The single gate every candidate target passes through before any recon tool
runs. Decided by code, never by the LLM/agent layer.

Public API:
    from scope import ScopeEngine, Scope, ScopeStatus, ScopeDecision
"""

from scope.engine import ScopeEngine
from scope.types import (
    RuleKind,
    Scope,
    ScopeDecision,
    ScopeRule,
    ScopeStatus,
)

__all__ = [
    "ScopeEngine",
    "Scope",
    "ScopeRule",
    "ScopeDecision",
    "ScopeStatus",
    "RuleKind",
]
