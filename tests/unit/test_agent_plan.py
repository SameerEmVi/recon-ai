"""
Tests for the agent plan→execute mode.

Covers the deterministic plan validator (the security-relevant gate) and the
AgentLoop running with plan_first=True: it builds a plan once, executes the
valid steps in order, drops unobserved/unknown steps, and hands off to the
reactive tail when the plan is exhausted.

Mock-based — no API key or external binaries.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

from agent.approval import ApprovalGate, ApprovalMode
from agent.loop import AgentLoop
from agent.plan import (
    DONE,
    AgentPlan,
    PlanStep,
    observed_hostnames,
    validate_steps,
)
from agent.stopping import StopReason, StoppingConditions
from agent.tools import ToolResult
from ai.prompts.agent import AGENT_PLAN_TOOL, build_plan_prompt
from database.models import Host


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


class _RecordingTool:
    def __init__(self, name: str, order: list, count: int = 1) -> None:
        self.name = name
        self._order = order
        self._count = count

    async def run(self, target, scan_id):
        self._order.append((self.name, target))
        return ToolResult(self._count, f"{self.name} → {self._count}")


# ── observed_hostnames ─────────────────────────────────────────────────────────

def test_observed_hostnames_includes_hosts_and_service_urls():
    hosts = [_host("api.example.com"), _host("www.example.com")]
    observed = observed_hostnames(hosts)
    assert "api.example.com" in observed
    assert "www.example.com" in observed


# ── validate_steps (deterministic gate) ─────────────────────────────────────────

def test_validate_steps_keeps_valid_drops_invalid():
    observed = {"api.example.com", "www.example.com"}
    known = {"probe_url", "fetch_historical_urls", "nuclei_info"}
    raw = [
        {"action": "probe_url", "target": "https://api.example.com/", "rationale": "a"},
        {"action": "fetch_historical_urls", "target": "www.example.com", "rationale": "b"},
        {"action": "nuclei_info", "target": "https://evil.com/", "rationale": "c"},      # unobserved
        {"action": "hack_mainframe", "target": "api.example.com", "rationale": "d"},     # unknown action
        {"action": "probe_url", "target": "https://api.example.com/other", "rationale": "e"},  # dup host
    ]
    kept, dropped = validate_steps(raw, known_actions=known, observed=observed)

    assert [s.action for s in kept] == ["probe_url", "fetch_historical_urls"]
    assert kept[0].target == "https://api.example.com/"
    assert len(dropped) == 3  # unobserved + unknown + duplicate


def test_validate_steps_drops_unknown_action_even_if_target_observed():
    observed = {"api.example.com"}
    known = {"probe_url"}
    raw = [{"action": "nuclei_info", "target": "api.example.com", "rationale": "x"}]
    kept, dropped = validate_steps(raw, known_actions=known, observed=observed)
    assert kept == []
    assert len(dropped) == 1


def test_validate_steps_caps_at_max():
    observed = {f"h{i}.example.com" for i in range(20)}
    known = {"probe_url"}
    raw = [{"action": "probe_url", "target": f"h{i}.example.com", "rationale": "r"}
           for i in range(20)]
    kept, _ = validate_steps(raw, known_actions=known, observed=observed, max_steps=5)
    assert len(kept) == 5


# ── AgentPlan model ─────────────────────────────────────────────────────────────

def test_agent_plan_next_pending_advances():
    plan = AgentPlan(goal="g", steps=[
        PlanStep("probe_url", "a", "r"),
        PlanStep("probe_url", "b", "r"),
    ])
    assert plan.created
    assert plan.pending_count == 2
    first = plan.next_pending()
    first.status = DONE
    assert plan.pending_count == 1
    assert plan.next_pending().target == "b"


def test_empty_plan_not_created():
    assert AgentPlan().created is False


# ── build_plan_prompt ───────────────────────────────────────────────────────────

def test_build_plan_prompt_includes_hosts_and_asks_for_ordered_plan():
    from agent.state import AgentState
    s = AgentState(
        scan_id=uuid.uuid4(), target_domain="example.com",
        iteration=0, max_iterations=20,
        hosts=[_host("api.example.com")], assessments=[], findings=[],
    )
    prompt = build_plan_prompt(s)
    assert "api.example.com" in prompt
    assert "plan" in prompt.lower()
    assert "ordered" in prompt.lower() or "ORDERED" in prompt


# ── AgentLoop plan→execute ──────────────────────────────────────────────────────

def _plan_loop(*, plan_steps: list[dict], hosts: list[Host], tool_order: list):
    """Build an AgentLoop in plan_first mode. The fake assessor returns the plan
    on the agent_plan call, and 'stop' on any agent_decision call (reactive tail)."""
    mock_assessor = MagicMock()

    async def fake_call(prompt, tool, system=None):
        if tool["name"] == AGENT_PLAN_TOOL["name"]:
            return {"goal": "map the attack surface", "steps": plan_steps}
        return {"action": "stop", "target": "", "rationale": "plan done"}

    mock_assessor.call = fake_call

    tools = {
        "probe_url": _RecordingTool("probe_url", tool_order),
        "fetch_historical_urls": _RecordingTool("fetch_historical_urls", tool_order),
        "nuclei_info": _RecordingTool("nuclei_info", tool_order),
    }

    host_repo = MagicMock()
    host_repo.list_for_scan = AsyncMock(return_value=hosts)
    finding_repo = MagicMock()
    finding_repo.list_for_scan = AsyncMock(return_value=[])
    assessment_repo = MagicMock()
    assessment_repo.list_for_scan = AsyncMock(return_value=[])

    return AgentLoop(
        controller=MagicMock(),
        host_repo=host_repo,
        finding_repo=finding_repo,
        assessment_repo=assessment_repo,
        assessor=mock_assessor,
        stopping=StoppingConditions(max_iterations=10, zero_event_streak=5),
        approval_gate=ApprovalGate(ApprovalMode.AUTO),
        tool_registry=tools,
        max_iterations=10,
        plan_first=True,
    )


async def test_plan_first_executes_valid_steps_in_order():
    hosts = [_host("api.example.com"), _host("www.example.com")]
    plan_steps = [
        {"action": "probe_url", "target": "https://api.example.com/", "rationale": "a"},
        {"action": "fetch_historical_urls", "target": "www.example.com", "rationale": "b"},
        {"action": "nuclei_info", "target": "https://evil.com/", "rationale": "dropped"},  # unobserved
    ]
    order: list = []
    loop = _plan_loop(plan_steps=plan_steps, hosts=hosts, tool_order=order)
    result = await loop.run(uuid.uuid4(), "example.com")

    # Two valid steps ran, in order; the unobserved one never executed.
    assert order == [
        ("probe_url", "https://api.example.com/"),
        ("fetch_historical_urls", "www.example.com"),
    ]
    assert result.iterations == 2
    assert result.total_new_events == 2

    # The plan is attached, fully consumed, and marked done.
    assert result.plan is not None
    assert result.plan.created
    assert len(result.plan.steps) == 2          # the invalid step was dropped at validation
    assert result.plan.pending_count == 0
    assert all(s.status == DONE for s in result.plan.steps)

    # After the plan, the reactive tail chose stop.
    assert result.stop_reason == StopReason.AGENT_DECIDED.value


async def test_plan_first_with_no_valid_steps_falls_back_to_reactive_stop():
    hosts = [_host("api.example.com")]
    # Every proposed step targets an unobserved host → all dropped → empty plan.
    plan_steps = [
        {"action": "probe_url", "target": "https://nope.test/", "rationale": "x"},
    ]
    order: list = []
    loop = _plan_loop(plan_steps=plan_steps, hosts=hosts, tool_order=order)
    result = await loop.run(uuid.uuid4(), "example.com")

    assert order == []                           # nothing executed
    assert result.plan is not None
    assert result.plan.created is False          # no actionable steps
    assert result.stop_reason == StopReason.AGENT_DECIDED.value
