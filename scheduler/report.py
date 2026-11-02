"""
Unified report for the hybrid scanning engine (spec §12).

Renders a SchedulerReport (+ live pool/limiter/proxy/diagnostics state) into a
structured dict and a human-readable text block. This is an ADDITIONAL report
section — it does not change the existing result formats; the controller attaches
it to the aggregator's single writer (like attach_vuln_report), in a later
increment.
"""

from __future__ import annotations


def build_report_dict(report, *, proxy=None, diagnostics_dir: str | None = None) -> dict:
    """Assemble the structured §12 report from a SchedulerReport."""
    pool = report.pool or {}
    lim = report.limiter or {}
    dur = max(report.duration_s, 0.0001)
    requests = int(lim.get("requests", 0) or 0)

    d: dict = {
        "summary": {
            "targets_total": report.targets_total,
            "targets_completed": report.targets_completed,
            "targets_partial": report.targets_partial,
            "targets_failed": report.targets_failed,
            "targets_out_of_scope": report.targets_out_of_scope,
            "duration_s": report.duration_s,
        },
        "modules": {
            "executed": report.modules_run,
            "ok": report.modules_ok,
            "failed": report.modules_failed,
            "success_rate": (round(report.modules_ok / report.modules_run, 3)
                             if report.modules_run else None),
        },
        "requests": {
            "total": requests,
            "avg_rate_per_sec": round(requests / dur, 2),
        },
        "workers": {
            "max_workers": pool.get("max_workers"),
            "accepted_jobs": pool.get("accepted"),
            "deduped_jobs": pool.get("deduped"),
            "jobs_per_worker": (round(pool.get("accepted", 0) / pool["max_workers"], 2)
                                if pool.get("max_workers") else None),
        },
        "queue": {
            "max_queue": pool.get("max_queue"),
            "queued_at_end": pool.get("queued"),
            "running_at_end": pool.get("running"),
            "terminal": pool.get("terminal", {}),
        },
        "waf": {
            "vendors": lim.get("waf_vendors", []),
            "targets_backed_off": lim.get("targets_backed_off", []),
            "targets_in_cooldown": lim.get("targets_in_cooldown", []),
            "penalty": lim.get("penalty"),
        },
        "proxy": _proxy_stats(proxy),
        "diagnostics": diagnostics_dir,
    }
    return d


def _proxy_stats(proxy) -> dict:
    if proxy is None:
        return {"enabled": False}
    try:
        return {"enabled": bool(getattr(proxy, "active", False)),
                "describe": proxy.describe()}
    except Exception:
        return {"enabled": False}


def render_report_text(report, *, proxy=None, diagnostics_dir: str | None = None) -> str:
    """Human-readable §12 report."""
    d = build_report_dict(report, proxy=proxy, diagnostics_dir=diagnostics_dir)
    s, m, r, w, q, waf = (d["summary"], d["modules"], d["requests"],
                          d["workers"], d["queue"], d["waf"])
    lines = [
        "Hybrid Scan Report",
        "==================",
        "",
        f"Targets        : {s['targets_total']} total  "
        f"(completed {s['targets_completed']}, partial {s['targets_partial']}, "
        f"failed {s['targets_failed']}, out-of-scope {s['targets_out_of_scope']})",
        f"Modules        : {m['executed']} executed  (ok {m['ok']}, failed {m['failed']}"
        + (f", success {int(m['success_rate'] * 100)}%" if m['success_rate'] is not None else "")
        + ")",
        f"Requests       : {r['total']} total  (~{r['avg_rate_per_sec']} req/s aggregate)",
        f"Workers        : max {w['max_workers']}  "
        f"(accepted {w['accepted_jobs']} jobs, deduped {w['deduped_jobs']}, "
        f"{w['jobs_per_worker']} jobs/worker)",
        f"Queue          : max {q['max_queue']}  (end queued {q['queued_at_end']}, "
        f"running {q['running_at_end']})",
        f"Duration       : {s['duration_s']}s",
        "",
        "WAF / access restrictions:",
    ]
    if waf["vendors"] or waf["targets_backed_off"] or waf["targets_in_cooldown"]:
        lines.append(f"  vendors seen        : {', '.join(waf['vendors']) or 'none'}")
        lines.append(f"  targets backed off  : {', '.join(waf['targets_backed_off']) or 'none'}")
        lines.append(f"  targets in cooldown : {', '.join(waf['targets_in_cooldown']) or 'none'}")
    else:
        lines.append("  none detected")
    lines += [
        "",
        f"Proxy          : {'on — ' + d['proxy'].get('describe', '') if d['proxy'].get('enabled') else 'off'}",
        f"Diagnostics    : {diagnostics_dir or '(none)'}",
    ]
    return "\n".join(lines) + "\n"
