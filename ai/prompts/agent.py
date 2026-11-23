"""
Agent decision prompt + tool schema.

The LLM sees structured DB records only — no raw HTTP responses.
It must choose exactly one action per iteration via the forced tool call.
"""

from __future__ import annotations

from agent.state import AgentState

_MAX = 120  # field cap for all agent-prompt strings


def _cap(v: object, n: int = _MAX) -> str:
    s = str(v)[:n]
    return s


AGENT_DECISION_TOOL: dict = {
    "name": "agent_decision",
    "description": (
        "Choose exactly one action to perform on the target. "
        "Return 'stop' when no more useful work can be done."
    ),
    "input_schema": {
        "type": "object",
        "required": ["action", "target", "rationale"],
        "properties": {
            "action": {
                "type": "string",
                "enum": ["probe_url", "fetch_historical_urls", "nuclei_info", "stop"],
                "description": (
                    "probe_url — run httpx on a specific URL already seen. "
                    "fetch_historical_urls — passive gau lookup for a hostname. "
                    "nuclei_info — run nuclei info-severity scan on a URL. "
                    "stop — no more useful actions."
                ),
            },
            "target": {
                "type": "string",
                "description": (
                    "The URL or hostname to act on. "
                    "Must be a subdomain or URL already observed in this scan. "
                    "Use empty string '' when action is 'stop'."
                ),
            },
            "rationale": {
                "type": "string",
                "description": "One sentence: why this action is worth doing now.",
            },
            "stop_reason": {
                "type": "string",
                "description": "Only required when action='stop'. Brief explanation.",
            },
        },
    },
}


AGENT_PLAN_TOOL: dict = {
    "name": "agent_plan",
    "description": (
        "Decompose the reconnaissance objective into an ORDERED plan of concrete "
        "steps. Each step is a single action on a host or URL already observed in "
        "this scan. The plan is executed top-to-bottom; put the highest-value step "
        "first. Return 3-8 steps — no filler, no duplicates, no invented targets."
    ),
    "input_schema": {
        "type": "object",
        "required": ["goal", "steps"],
        "properties": {
            "goal": {
                "type": "string",
                "description": "One sentence: the overall objective for this target.",
            },
            "steps": {
                "type": "array",
                "description": "Ordered list of 3-8 steps, highest-value first.",
                "items": {
                    "type": "object",
                    "required": ["action", "target", "rationale"],
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["probe_url", "fetch_historical_urls", "nuclei_info"],
                            "description": (
                                "probe_url — httpx on a specific URL already seen. "
                                "fetch_historical_urls — passive gau lookup for a hostname. "
                                "nuclei_info — nuclei info-severity scan on a URL."
                            ),
                        },
                        "target": {
                            "type": "string",
                            "description": (
                                "A subdomain or URL already observed in this scan. "
                                "Never invent new hostnames."
                            ),
                        },
                        "rationale": {
                            "type": "string",
                            "description": "One sentence: why this step is worth doing.",
                        },
                    },
                },
            },
        },
    },
}


def _context_lines(state: AgentState) -> list[str]:
    """Shared host/finding/history context rendered for both the per-iteration
    decision prompt and the up-front planning prompt."""
    lines: list[str] = [
        f"Target domain : {_cap(state.target_domain)}",
        f"Iteration     : {state.iteration} / {state.max_iterations}  "
        f"({state.iterations_remaining} remaining)",
        "",
        "## Hosts discovered so far",
    ]

    for host in state.hosts[:30]:  # cap at 30 hosts in prompt
        importance = "?"
        env = "?"
        notes = ""
        assessment = state.assessment_for(host.hostname)
        if assessment:
            importance = assessment.importance or "?"
            env = assessment.environment or "?"
            notes = _cap(assessment.attack_surface_notes or "", 200)

        ips = ", ".join(str(ip) for ip in (host.ip_addresses or [])[:3])
        ports = ", ".join(str(p) for p in (host.open_ports or [])[:8])
        techs = ", ".join(_cap(t, 40) for t in (host.technologies or [])[:5])

        lines.append(f"\n### {host.hostname}  [importance={importance}  env={env}]")
        if ips:
            lines.append(f"  IPs   : {ips}")
        if ports:
            lines.append(f"  Ports : {ports}")
        if techs:
            lines.append(f"  Tech  : {techs}")
        if host.services:
            for svc in host.services[:4]:
                url = _cap(svc.get("url", ""), 100)
                code = svc.get("status_code", "?")
                title = _cap(svc.get("title", ""), 60)
                lines.append(f"  SVC   : {url}  [{code}]  {title}")
        if notes:
            lines.append(f"  Notes : {notes}")

    if len(state.hosts) > 30:
        lines.append(f"\n  ... and {len(state.hosts) - 30} more hosts (not shown)")

    if state.findings:
        lines.append("\n## Findings")
        for f in state.findings[:10]:
            lines.append(
                f"  [{f.severity_hint or '?'}] {_cap(f.title, 80)}  host={f.host}"
            )

    if state.completed_actions:
        lines.append("\n## Actions already taken this session")
        for ca in state.completed_actions[-10:]:  # last 10
            lines.append(
                f"  {ca.action}({_cap(ca.target, 60)})  → {ca.new_events} new events  "
                f"{_cap(ca.summary, 80)}"
            )

    return lines


def build_agent_prompt(state: AgentState) -> str:
    lines = _context_lines(state)
    lines.append(
        "\n## Instructions\n"
        "Choose the single most valuable action given the above.\n"
        "Prioritise hosts marked importance=high or importance=critical.\n"
        "Do not repeat an action+target pair already listed above.\n"
        "Use 'stop' when all high-value targets have been covered or "
        "the last 3 actions produced zero new events.\n"
        "All targets must be subdomains or URLs already observed above — "
        "do NOT invent new hostnames."
    )
    return "\n".join(lines)


def build_plan_prompt(state: AgentState) -> str:
    """Prompt for the up-front planning phase: ask the model for an ordered plan
    of concrete steps rather than a single next action."""
    lines = _context_lines(state)
    lines.append(
        "\n## Instructions\n"
        "Produce an ORDERED reconnaissance plan of 3-8 concrete steps.\n"
        "Each step is one action on a host or URL ALREADY listed above — "
        "do NOT invent new hostnames.\n"
        "Order the steps highest-value first: prioritise hosts marked "
        "importance=high or importance=critical, and surfaces most likely to "
        "yield new attack surface.\n"
        "Do not include duplicate action+target pairs. Each step must be real, "
        "useful work — there is no 'stop' step; simply return fewer steps if "
        "little is worth doing."
    )
    return "\n".join(lines)
