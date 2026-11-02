"""
Tests for the hybrid engine's event taxonomy (scheduler.events) and unified
report (scheduler.report): sanitized event schema, the full §11 name set, and
the §12 report fields in both dict and text form.
"""

from __future__ import annotations

import uuid

from scheduler import events as ev
from scheduler.engine import SchedulerReport
from scheduler.events import build_event
from scheduler.jobs import Job, JobKind, JobState
from scheduler.report import build_report_dict, render_report_text


# ── event schema ──────────────────────────────────────────────────────────────

def test_build_event_has_the_required_fields():
    scan = uuid.uuid4()
    job = Job(target="a.com", scan_id=scan, kind=JobKind.MODULE, module="ffuf")
    job.transition(JobState.RUNNING)
    e = build_event(ev.MODULE_STARTED, scan_id=scan, job=job)
    for key in ("event", "scan_id", "job_id", "target", "module", "correlation_id", "status", "ts"):
        assert key in e, f"missing {key}"
    assert e["event"] == "module_started"
    assert e["target"] == "a.com" and e["module"] == "ffuf"
    assert e["status"] == "RUNNING"
    assert e["ts"].endswith("+00:00")                 # UTC


def test_event_metadata_is_redacted():
    e = build_event(
        ev.WAF_RESTRICTION_DETECTED, scan_id=uuid.uuid4(),
        target="a.com", authorization="Bearer sk-supersecret", note="blocked",
    )
    blob = str(e["metadata"])
    assert "sk-supersecret" not in blob               # secret scrubbed
    assert "blocked" in blob                           # benign metadata kept


def test_full_event_name_set_present():
    # the §11 taxonomy is all defined
    for name in ("scan_started", "target_discovered", "subdomain_job_queued",
                 "workers_started", "module_started", "module_completed",
                 "module_failed", "rate_limit_reached", "waf_restriction_detected",
                 "target_paused", "scan_completed", "scan_cancelled"):
        assert name in ev.EVENT_NAMES


# ── unified report ─────────────────────────────────────────────────────────────

def _report():
    r = SchedulerReport(
        targets_total=5, targets_completed=3, targets_partial=1, targets_failed=0,
        targets_out_of_scope=1, modules_run=20, modules_ok=18, modules_failed=2,
        duration_s=4.0,
        pool={"max_workers": 10, "max_queue": 1000, "accepted": 20, "deduped": 2,
              "queued": 0, "running": 0, "terminal": {"COMPLETED": 18, "FAILED": 2}},
        limiter={"requests": 200, "penalty": 1.0, "waf_vendors": ["Cloudflare"],
                 "targets_backed_off": ["b.com"], "targets_in_cooldown": []},
    )
    return r


def test_report_dict_has_all_section_fields():
    d = build_report_dict(_report())
    assert d["summary"]["targets_total"] == 5
    assert d["summary"]["targets_out_of_scope"] == 1
    assert d["modules"]["executed"] == 20 and d["modules"]["success_rate"] == 0.9
    assert d["requests"]["total"] == 200
    assert d["requests"]["avg_rate_per_sec"] == 50.0    # 200 req / 4s
    assert d["workers"]["max_workers"] == 10
    assert d["queue"]["max_queue"] == 1000
    assert d["waf"]["vendors"] == ["Cloudflare"]
    assert d["proxy"] == {"enabled": False}


def test_report_text_is_readable_and_covers_waf():
    text = render_report_text(_report(), diagnostics_dir="results/x/run-1/diagnostics")
    assert "Hybrid Scan Report" in text
    assert "Targets" in text and "out-of-scope 1" in text
    assert "Requests" in text and "req/s aggregate" in text
    assert "Cloudflare" in text                         # WAF section rendered
    assert "results/x/run-1/diagnostics" in text


def test_report_handles_empty_scan():
    text = render_report_text(SchedulerReport())
    assert "Hybrid Scan Report" in text                 # no crash on a zero scan
    d = build_report_dict(SchedulerReport())
    assert d["modules"]["success_rate"] is None
