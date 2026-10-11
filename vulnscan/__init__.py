"""
vulnscan — evidence-based vulnerability assessment layer.

Consumes the reconnaissance intelligence recon-ai already produces (technologies,
HTTP services, URLs, endpoints, parameters, anomalies, finding candidates) and
turns it into structured, evidence-backed vulnerability results. It is a
*reasoning + light-verification* layer on top of recon, not a scanner bolt-on.

Design mirrors the rest of recon-ai:
  - deterministic code owns detection, verification, scope, and status; the LLM
    only annotates (via the existing triage pass), never invents or confirms;
  - a consistent `Check` interface (see `vulnscan.checks`) with id/name/tier/
    applicable-technologies/prerequisites/required-evidence/result-schema/
    verification-strategy, registered in an internal check registry;
  - results are emitted as the existing `FINDING_CANDIDATE` event (category
    `vuln:<check_id>`), so scope, dedup, persistence, history/diff, the result
    aggregator and the AI triage layer all apply unchanged.

The public surface is the `AssessmentEngine` (orchestration), the `Check` base
class + `register_check` (extensibility), `VulnResult`/`Status`/`Severity`
(schema) and `build_report` (reporting). The `modules/web/vulnassess.py` module
is the integration point that feeds recon events in and emits findings out.
"""

from __future__ import annotations

from vulnscan.schema import (
    CONFIDENCE_LABELS,
    SEVERITIES,
    STATUSES,
    Severity,
    Status,
    VulnResult,
)

__all__ = [
    "VulnResult",
    "Status",
    "Severity",
    "STATUSES",
    "SEVERITIES",
    "CONFIDENCE_LABELS",
]
