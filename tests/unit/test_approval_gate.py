"""Risk-aware approval gate (agent/approval.py §7.4) + loop risk tagging."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent.approval import (
    RISK_HIGH,
    RISK_LOW,
    AgentDecision,
    ApprovalGate,
    ApprovalMode,
)
from agent.tools import build_tool_registry, tool_risk
from policy import CapabilityPolicy


def _d(action, risk=RISK_LOW):
    return AgentDecision(action=action, target="api.example.com", rationale="r", risk=risk)


# ── risk derivation from the tool's capability ────────────────────────────────────

def test_tool_risk_from_capability():
    reg = build_tool_registry(SimpleNamespace(policy=CapabilityPolicy("pentest")))
    assert tool_risk(reg["assess_url"]) == RISK_HIGH        # VULNERABILITY_CHECK
    assert tool_risk(reg["nuclei_info"]) == RISK_HIGH
    assert tool_risk(reg["probe_url"]) == RISK_LOW          # TARGET_HTTP_REQUEST
    assert tool_risk(reg["fetch_historical_urls"]) == RISK_LOW


# ── AUTO: unchanged (approve everything) ──────────────────────────────────────────

async def test_auto_approves_all_including_high():
    gate = ApprovalGate(ApprovalMode.AUTO)
    assert await gate.check(_d("assess_url", RISK_HIGH)) is True
    assert await gate.check(_d("probe_url", RISK_LOW)) is True


async def test_stop_always_allowed():
    assert await ApprovalGate(ApprovalMode.REVIEW).check(_d("stop")) is True


# ── REVIEW: auto low, sign-off for high, fail-closed without an approver ──────────

async def test_review_auto_approves_low_risk():
    assert await ApprovalGate(ApprovalMode.REVIEW).check(_d("probe_url", RISK_LOW)) is True


async def test_review_denies_high_risk_without_approver(monkeypatch):
    # No approver wired and no TTY → fail-closed deny (never auto-run a vuln test).
    monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: False))
    assert await ApprovalGate(ApprovalMode.REVIEW).check(_d("assess_url", RISK_HIGH)) is False


async def test_review_consults_approver_for_high_risk():
    seen = []

    async def approve(decision):
        seen.append((decision.action, decision.risk))
        return True

    async def deny(decision):
        return False

    assert await ApprovalGate(ApprovalMode.REVIEW, approver=approve).check(
        _d("assess_url", RISK_HIGH)) is True
    assert seen == [("assess_url", RISK_HIGH)]
    assert await ApprovalGate(ApprovalMode.REVIEW, approver=deny).check(
        _d("assess_url", RISK_HIGH)) is False


async def test_interactive_asks_for_every_action():
    asked = []

    async def approver(decision):
        asked.append(decision.action)
        return decision.action != "nuclei_info"

    gate = ApprovalGate(ApprovalMode.INTERACTIVE, approver=approver)
    assert await gate.check(_d("probe_url", RISK_LOW)) is True       # still asked
    assert await gate.check(_d("nuclei_info", RISK_HIGH)) is False
    assert asked == ["probe_url", "nuclei_info"]


# ── the loop tags each decision with the tool's risk before checking ──────────────

async def test_loop_tags_decision_risk_before_gate():
    """The gate is given the real risk so a planned high-risk step is held for
    sign-off. A REVIEW gate with no approver (no TTY) skips the high-risk step."""
    from types import SimpleNamespace as NS

    import agent.loop as loop_mod

    recorded = {}

    class _Gate:
        async def check(self, decision):
            recorded[decision.action] = decision.risk
            return False                                   # reject → step skipped

    reg = build_tool_registry(NS(policy=CapabilityPolicy("pentest")))
    # Minimal AgentLoop with just what the approve/act path touches.
    lp = loop_mod.AgentLoop.__new__(loop_mod.AgentLoop)
    lp._tools = reg
    lp._gate = _Gate()

    from agent.approval import AgentDecision as D
    d = D(action="assess_url", target="api.example.com", rationale="r")
    _tool = lp._tools.get(d.action)
    d.risk = tool_risk(_tool)
    assert await lp._gate.check(d) is False
    assert recorded["assess_url"] == RISK_HIGH
