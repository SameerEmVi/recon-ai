"""Prompt builder for individual finding assessment.

Each FINDING_CANDIDATE gets its own LLM call — findings need individual attention
because their context varies too much to batch meaningfully.

All values are from the DB Finding model — already sanitized at ingestion.
"""

from __future__ import annotations

from database.models import Finding

_MAX_FIELD = 256


def _s(v: object, max_len: int = _MAX_FIELD) -> str:
    return str(v or "")[:max_len]


def build_finding_prompt(finding: Finding) -> str:
    lines = [
        "FINDING CANDIDATE (sanitized record — reason about this only):",
        "",
        f"Host     : {_s(finding.host, 253)}",
        f"Category : {_s(finding.category, 64)}",
        f"Title    : {_s(finding.title, 256)}",
        f"Severity hint from tool: {_s(finding.severity_hint or 'none', 32)}",
        "",
        "Description:",
        _s(finding.description, 512),
        "",
        "Evidence (structured key-value, sanitized):",
    ]

    evidence = finding.evidence or {}
    for k, v in list(evidence.items())[:20]:
        lines.append(f"  {_s(k, 64)}: {_s(v, 256)}")

    lines.append("")
    lines.append(
        "Is this worth investigating further? Provide your reasoning and any "
        "investigation notes for the human analyst."
    )
    return "\n".join(lines)


# ── tool schema ────────────────────────────────────────────────────────────────

FINDING_ASSESSMENT_TOOL: dict = {
    "name": "record_finding_assessment",
    "description": "Record your assessment of a single finding candidate.",
    "input_schema": {
        "type": "object",
        "properties": {
            "confirmed_interesting": {
                "type": "boolean",
                "description": "True if this warrants further manual investigation."
            },
            "severity": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
                "description": "Estimated severity if the finding is real."
            },
            "reasoning": {
                "type": "string",
                "description": "1-3 sentences explaining your assessment."
            },
            "investigation_notes": {
                "type": "string",
                "description": "Concrete next steps for the human analyst (or empty string)."
            }
        },
        "required": ["confirmed_interesting", "severity", "reasoning", "investigation_notes"]
    }
}
