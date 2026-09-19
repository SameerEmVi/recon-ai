"""Prompt builder for host prioritization.

Sends a compact summary of ALL discovered hosts in one call so the model can
rank them relative to each other. One LLM call regardless of host count.

All values come from the DB Host model — already sanitized at ingestion.
We apply additional length caps here as a belt-and-suspenders measure before
any string enters a prompt.
"""

from __future__ import annotations

from database.models import Host

# Belt-and-suspenders: cap anything that enters a prompt even though values
# are already sanitized in the DB. Prevents unexpectedly long fields from
# bloating the context window.
_MAX_FIELD = 120


def _s(v: object, max_len: int = _MAX_FIELD) -> str:
    return str(v or "")[:max_len]


def build_host_list_prompt(target_domain: str, hosts: list[Host]) -> str:
    lines = [
        f"Recon scan of: {_s(target_domain, 64)}",
        f"Total hosts discovered: {len(hosts)}",
        "",
        "HOST RECORDS (sanitized — these are the only facts available):",
    ]

    for i, h in enumerate(hosts, 1):
        ports = ", ".join(str(p) for p in (h.open_ports or [])[:20]) or "none"
        techs = ", ".join(_s(t) for t in (h.technologies or [])[:10]) or "none"
        ips = ", ".join(_s(ip, 45) for ip in (h.ip_addresses or [])[:5]) or "none"

        services = h.services or []
        svc_lines = []
        for svc in services[:8]:
            url = _s(svc.get("url", ""), 80)
            code = svc.get("status_code", "?")
            title = _s(svc.get("title") or "", 60)
            svc_lines.append(f"    {url} [{code}]{f' — {title}' if title else ''}")

        lines.append(f"{i}. {_s(h.hostname, 253)}")
        lines.append(f"   IPs: {ips}")
        lines.append(f"   Ports: {ports}")
        lines.append(f"   Technologies: {techs}")
        if svc_lines:
            lines.append("   Services:")
            lines.extend(svc_lines)
        lines.append("")

    lines.append(
        "Assess each host. Consider relative priority for bug bounty: "
        "which hosts are most likely to yield findings and why?"
    )
    return "\n".join(lines)


# ── tool schema ────────────────────────────────────────────────────────────────

HOST_ASSESSMENT_TOOL: dict = {
    "name": "record_host_assessments",
    "description": "Record prioritized assessments for all discovered hosts.",
    "input_schema": {
        "type": "object",
        "properties": {
            "assessments": {
                "type": "array",
                "description": "One entry per host, ordered from highest to lowest priority.",
                "items": {
                    "type": "object",
                    "properties": {
                        "hostname": {
                            "type": "string",
                            "description": "Exact hostname from the host record."
                        },
                        "importance": {
                            "type": "string",
                            "enum": ["low", "medium", "high", "critical"],
                            "description": "Bug bounty priority of this host."
                        },
                        "environment": {
                            "type": "string",
                            "enum": ["prod", "staging", "dev", "internal", "unknown"],
                            "description": "Best guess at the deployment environment."
                        },
                        "attack_surface_notes": {
                            "type": "string",
                            "description": "Brief (1-3 sentences) on what makes this host interesting or not."
                        },
                        "interesting_indicators": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Specific observations: unusual ports, old techs, admin paths, etc."
                        }
                    },
                    "required": [
                        "hostname", "importance", "environment",
                        "attack_surface_notes", "interesting_indicators"
                    ]
                }
            }
        },
        "required": ["assessments"]
    }
}
