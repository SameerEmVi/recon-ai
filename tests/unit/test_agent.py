"""
Agent Phase 4 tests — mock-based; no real API key or external binaries needed.

Covers:
  - ApprovalGate (auto + interactive)
  - AgentState properties
  - StoppingConditions
  - build_agent_prompt (pure function)
  - AgentLoop (mocked Assessor + mocked tools)
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent.approval import AgentDecision, ApprovalGate, ApprovalMode
from agent.loop import AgentLoop, AgentResult
from agent.state import AgentState, CompletedAction
from agent.stopping import StopReason, StoppingConditions
from ai.prompts.agent import AGENT_DECISION_TOOL, build_agent_prompt
from database.models import AiAssessment, Host


# ── helpers ───────────────────────────────────────────────────────────────────

def _host(hostname: str) -> Host:
    h = Host(
        scan_job_id=uuid.uuid4(),
        hostname=hostname,
        ip_addresses=["1.2.3.4"],
        open_ports=[80, 443],
        technologies=["nginx"],
        services=[{"url": f"https://{hostname}/", "status_code": 200, "title": "Home"}],
    )
    h.id = uuid.uuid4()
    return h


def _state(
    hosts=None,
    iteration=0,
    max_iterations=20,
    completed_actions=None,
) -> AgentState:
    return AgentState(
        scan_id=uuid.uuid4(),
        target_domain="example.com",
        iteration=iteration,
        max_iterations=max_iterations,
        hosts=[_host("api.example.com")] if hosts is None else hosts,
        assessments=[],
        findings=[],
        completed_actions=[] if completed_actions is None else completed_actions,
    )


# ── ApprovalGate ──────────────────────────────────────────────────────────────

async def test_approval_gate_auto_approves_all():
    gate = ApprovalGate(ApprovalMode.AUTO)
    decision = AgentDecision(action="probe_url", target="https://api.example.com/", rationale="test")
    assert await gate.check(decision) is True


async def test_approval_gate_auto_approves_stop():
    gate = ApprovalGate(ApprovalMode.AUTO)
    decision = AgentDecision(action="stop", target="", rationale="done")
    assert await gate.check(decision) is True


async def test_approval_gate_interactive_approves_y(monkeypatch):
    gate = ApprovalGate(ApprovalMode.INTERACTIVE)
    monkeypatch.setattr("builtins.input", lambda _: "y")
    decision = AgentDecision(action="probe_url", target="https://example.com/", rationale="test")
    assert await gate.check(decision) is True


async def test_approval_gate_interactive_rejects_non_y(monkeypatch):
    gate = ApprovalGate(ApprovalMode.INTERACTIVE)
    monkeypatch.setattr("builtins.input", lambda _: "n")
    decision = AgentDecision(action="probe_url", target="https://example.com/", rationale="test")
    assert await gate.check(decision) is False


# ── AgentState ────────────────────────────────────────────────────────────────

def test_state_iterations_remaining():
    s = _state(iteration=5, max_iterations=20)
    assert s.iterations_remaining == 15


def test_state_consecutive_zero_event_actions():
    actions = [
        CompletedAction("probe_url", "x", "r", new_events=2, summary="s"),
        CompletedAction("probe_url", "y", "r", new_events=0, summary="s"),
        CompletedAction("probe_url", "z", "r", new_events=0, summary="s"),
    ]
    s = _state(completed_actions=actions)
    assert s.consecutive_zero_event_actions == 2


def test_state_consecutive_zero_resets_after_nonzero():
    actions = [
        CompletedAction("probe_url", "x", "r", new_events=0, summary="s"),
        CompletedAction("probe_url", "y", "r", new_events=3, summary="s"),  # reset
        CompletedAction("probe_url", "z", "r", new_events=0, summary="s"),
    ]
    s = _state(completed_actions=actions)
    assert s.consecutive_zero_event_actions == 1


def test_state_assessment_for_returns_none_if_no_host():
    s = _state()
    assert s.assessment_for("nonexistent.example.com") is None


# ── StoppingConditions ────────────────────────────────────────────────────────

def test_stopping_no_hosts():
    cond = StoppingConditions()
    s = _state(hosts=[])
    assert cond.check(s, 0) is StopReason.NO_HOSTS


def test_stopping_max_iterations():
    cond = StoppingConditions(max_iterations=3)
    s = _state(iteration=3)
    assert cond.check(s, 0) is StopReason.MAX_ITERATIONS


def test_stopping_timeout():
    cond = StoppingConditions(max_minutes=1.0)
    s = _state()
    assert cond.check(s, 65) is StopReason.TIMEOUT


def test_stopping_diminishing_returns():
    cond = StoppingConditions(zero_event_streak=3)
    actions = [
        CompletedAction("probe_url", f"t{i}", "r", new_events=0, summary="s")
        for i in range(3)
    ]
    s = _state(completed_actions=actions)
    assert cond.check(s, 0) is StopReason.DIMINISHING_RETURNS


def test_stopping_none_when_all_ok():
    cond = StoppingConditions(max_iterations=10)
    s = _state(iteration=5)
    assert cond.check(s, 30) is None


# ── build_agent_prompt ────────────────────────────────────────────────────────

def test_build_agent_prompt_includes_hostname():
    s = _state()
    prompt = build_agent_prompt(s)
    assert "api.example.com" in prompt
    assert "example.com" in prompt


def test_build_agent_prompt_includes_iteration():
    s = _state(iteration=3, max_iterations=20)
    prompt = build_agent_prompt(s)
    assert "3 / 20" in prompt


def test_build_agent_prompt_includes_completed_actions():
    actions = [
        CompletedAction("probe_url", "https://api.example.com/", "test", 2, "found 2"),
    ]
    s = _state(completed_actions=actions)
    prompt = build_agent_prompt(s)
    assert "probe_url" in prompt
    assert "found 2" in prompt


def test_build_agent_prompt_caps_hosts_at_30():
    hosts = [_host(f"sub{i}.example.com") for i in range(50)]
    s = _state(hosts=hosts)
    prompt = build_agent_prompt(s)
    # Should mention overflow
    assert "more hosts" in prompt


# ── AgentLoop (mocked) ────────────────────────────────────────────────────────

def _make_loop(
    *,
    llm_responses: list[dict],
    tool_results: dict[str, tuple[int, str]] | None = None,
    session=None,
) -> AgentLoop:
    """Build an AgentLoop with mocked assessor and fake tools."""
    from agent.approval import ApprovalGate, ApprovalMode
    from agent.stopping import StoppingConditions

    responses_iter = iter(llm_responses)

    mock_assessor = MagicMock()
    async def fake_call(prompt, tool, system=None):
        try:
            return next(responses_iter)
        except StopIteration:
            return {"action": "stop", "target": "", "rationale": "responses exhausted"}
    mock_assessor.call = fake_call

    # Build fake tools.
    from agent.tools import ToolResult

    class _FakeTool:
        def __init__(self, tool_name: str, count: int, summary: str) -> None:
            self.name = tool_name
            self._count = count
            self._summary = summary

        async def run(self, target, scan_id):
            return ToolResult(self._count, self._summary)

    fake_tools: dict = {}
    if tool_results:
        for tool_name, (count, summary) in tool_results.items():
            fake_tools[tool_name] = _FakeTool(tool_name, count, summary)

    # Mock repos that return empty lists.
    host_repo = MagicMock()
    host_repo.list_for_scan = AsyncMock(return_value=[_host("api.example.com")])
    finding_repo = MagicMock()
    finding_repo.list_for_scan = AsyncMock(return_value=[])
    assessment_repo = MagicMock()
    assessment_repo.list_for_scan = AsyncMock(return_value=[])

    loop = AgentLoop(
        controller=MagicMock(),
        host_repo=host_repo,
        finding_repo=finding_repo,
        assessment_repo=assessment_repo,
        assessor=mock_assessor,
        stopping=StoppingConditions(max_iterations=10, zero_event_streak=3),
        approval_gate=ApprovalGate(ApprovalMode.AUTO),
        tool_registry=fake_tools,
        max_iterations=10,
    )
    return loop


async def test_agent_loop_stops_on_agent_decision():
    loop = _make_loop(
        llm_responses=[
            {"action": "stop", "target": "", "rationale": "nothing left", "stop_reason": "all done"},
        ],
    )
    result = await loop.run(uuid.uuid4(), "example.com")
    assert result.stop_reason == StopReason.AGENT_DECIDED.value
    assert result.iterations == 0


async def test_agent_loop_runs_tool_and_records_action():
    loop = _make_loop(
        llm_responses=[
            {"action": "probe_url", "target": "https://api.example.com/", "rationale": "check it"},
            {"action": "stop", "target": "", "rationale": "done"},
        ],
        tool_results={"probe_url": (3, "found 3 events")},
    )
    result = await loop.run(uuid.uuid4(), "example.com")
    assert result.stop_reason == StopReason.AGENT_DECIDED.value
    assert result.iterations == 1
    assert result.total_new_events == 3
    assert len(result.completed_actions) == 1
    assert result.completed_actions[0].action == "probe_url"
    assert result.completed_actions[0].new_events == 3


async def test_agent_loop_stops_on_diminishing_returns():
    # 3 consecutive zero-event actions → diminishing returns
    loop = _make_loop(
        llm_responses=[
            {"action": "probe_url", "target": "https://t1.example.com/", "rationale": "r"},
            {"action": "probe_url", "target": "https://t2.example.com/", "rationale": "r"},
            {"action": "probe_url", "target": "https://t3.example.com/", "rationale": "r"},
            {"action": "stop", "target": "", "rationale": "done"},  # should never reach
        ],
        tool_results={"probe_url": (0, "nothing found")},
    )
    result = await loop.run(uuid.uuid4(), "example.com")
    assert result.stop_reason == StopReason.DIMINISHING_RETURNS.value
    assert result.iterations == 3


async def test_agent_loop_stops_on_max_iterations():
    responses = [
        {"action": "probe_url", "target": f"https://t{i}.example.com/", "rationale": "r"}
        for i in range(15)
    ] + [{"action": "stop", "target": "", "rationale": "done"}]

    loop = _make_loop(
        llm_responses=responses,
        tool_results={"probe_url": (1, "found 1")},
    )
    result = await loop.run(uuid.uuid4(), "example.com")
    assert result.stop_reason == StopReason.MAX_ITERATIONS.value
    assert result.iterations == 10


async def test_agent_loop_unknown_action_stops():
    loop = _make_loop(
        llm_responses=[
            {"action": "hack_mainframe", "target": "evil.com", "rationale": "because"},
        ],
    )
    result = await loop.run(uuid.uuid4(), "example.com")
    assert result.stop_reason == "unknown_action"
    assert result.iterations == 0


async def test_agent_loop_no_hosts_stops_immediately():
    from agent.stopping import StoppingConditions
    from agent.approval import ApprovalGate, ApprovalMode

    host_repo = MagicMock()
    host_repo.list_for_scan = AsyncMock(return_value=[])  # no hosts
    finding_repo = MagicMock()
    finding_repo.list_for_scan = AsyncMock(return_value=[])
    assessment_repo = MagicMock()
    assessment_repo.list_for_scan = AsyncMock(return_value=[])

    loop = AgentLoop(
        controller=MagicMock(),
        host_repo=host_repo,
        finding_repo=finding_repo,
        assessment_repo=assessment_repo,
        assessor=MagicMock(),
        stopping=StoppingConditions(),
        approval_gate=ApprovalGate(ApprovalMode.AUTO),
        tool_registry={},
        max_iterations=10,
    )
    result = await loop.run(uuid.uuid4(), "example.com")
    assert result.stop_reason == StopReason.NO_HOSTS.value
    assert result.iterations == 0
