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


def build_agent_prompt(state: AgentState) -> str:
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
