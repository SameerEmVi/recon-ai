"""
Canonical event taxonomy for the hybrid scanning engine (spec §11).

Every scheduler event carries a stable, SANITIZED shape — scan run id, target
job id, module, correlation id, UTC timestamp, status, and redacted metadata —
so the controller can fan them onto the existing EventBus / DiagnosticsLogger
without leaking secrets into the event stream.
"""

from __future__ import annotations

from datetime import UTC, datetime

from net.redact import redact_json

# ── the §11 event names ─────────────────────────────────────────────────────
SCAN_STARTED = "scan_started"
TARGET_DISCOVERED = "target_discovered"
SUBDOMAIN_JOB_QUEUED = "subdomain_job_queued"
WORKERS_STARTED = "workers_started"
MODULE_STARTED = "module_started"
MODULE_COMPLETED = "module_completed"
MODULE_FAILED = "module_failed"
RATE_LIMIT_REACHED = "rate_limit_reached"
WAF_RESTRICTION_DETECTED = "waf_restriction_detected"
TARGET_PAUSED = "target_paused"
TARGET_OUT_OF_SCOPE = "target_out_of_scope"
TARGET_STARTED = "target_started"
TARGET_COMPLETED = "target_completed"
SCAN_COMPLETED = "scan_completed"
SCAN_CANCELLED = "scan_cancelled"

EVENT_NAMES: frozenset[str] = frozenset({
    SCAN_STARTED, TARGET_DISCOVERED, SUBDOMAIN_JOB_QUEUED, WORKERS_STARTED,
    MODULE_STARTED, MODULE_COMPLETED, MODULE_FAILED, RATE_LIMIT_REACHED,
    WAF_RESTRICTION_DETECTED, TARGET_PAUSED, TARGET_OUT_OF_SCOPE, TARGET_STARTED,
    TARGET_COMPLETED, SCAN_COMPLETED, SCAN_CANCELLED,
})


def build_event(name: str, *, scan_id, job=None, correlation_id: str | None = None,
                status: str | None = None, **metadata) -> dict:
    """Assemble one sanitized event record. `job` (a scheduler.jobs.Job) fills
    job_id/target/module/correlation_id/status when present; extra kwargs become
    redacted `metadata`."""
    ev = {
        "event": name,
        "scan_id": str(scan_id),
        "job_id": str(job.id) if job is not None else None,
        "target": job.target if job is not None else metadata.pop("target", None),
        "module": job.module if job is not None else metadata.pop("module", None),
        "correlation_id": correlation_id or (job.correlation_id if job is not None else None),
        "status": status or (job.state.value if job is not None else None),
        "ts": datetime.now(UTC).isoformat(),
    }
    if metadata:
        # redact before anything downstream logs/persists it
        ev["metadata"] = redact_json(metadata)
    return ev
