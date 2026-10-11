"""
Vulnerability report rendering — structured JSON and a human-readable report.

Consumes `VulnResult`s (from the engine) or rows reconstructed from persisted
findings (the `report` CLI command) and renders:

  - executive summary
  - findings by severity and confidence
  - affected assets
  - evidence and verification status
  - remediation guidance
  - checks executed / skipped / failed
  - assessment limitations

Nothing here asserts more than the underlying results do: a POTENTIAL stays
POTENTIAL, a version match is never printed as a confirmed CVE.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from vulnscan.schema import SEVERITIES, Status, VulnResult, confidence_label, severity_rank

DEFAULT_LIMITATIONS = [
    "Version→CVE results are correlation only and never CONFIRMED — patched builds, "
    "vendor backports and spoofed banners can make them false positives.",
    "No full TLS cipher/certificate audit is performed; transport checks are limited to "
    "HSTS and scheme (integrate sslyze/testssl for a deep TLS assessment).",
    "Reflected-input results are non-destructive indicators (a benign canary echoed), "
    "not proof of XSS/injection — manual verification is required.",
    "Multiple Set-Cookie headers may collapse to one in the HTTP client layer; cookie "
    "analysis can under-report per-cookie attributes.",
    "The assessment reasons over in-scope recon evidence only; intrusive testing is "
    "disabled unless explicitly authorized.",
]


def result_from_finding(f) -> VulnResult | None:
    """Reconstruct a VulnResult from a persisted Finding (ORM row or dict).

    Only `vuln:` findings carry the structured evidence; others are rendered as
    best-effort normalized entries so the report still reflects the full picture.
    """
    def g(name, default=None):
        if isinstance(f, dict):
            return f.get(name, default)
        return getattr(f, name, default)

    ev = g("evidence") or {}
    category = g("category") or ""
    check_id = ev.get("check_id") or (category.split(":", 1)[1] if ":" in category else category) or "finding"
    status = ev.get("status") or Status.POTENTIAL
    if status not in (Status.OBSERVED, Status.POTENTIAL, Status.UNCONFIRMED, Status.CONFIRMED):
        status = Status.POTENTIAL
    try:
        confidence = float(ev.get("confidence", 0.5) or 0.5)
    except (TypeError, ValueError):
        confidence = 0.5
    severity = (g("severity_hint") or g("severity") or "info").lower()
    if severity not in SEVERITIES:
        severity = "info"
    refs = ev.get("references")
    references = [r.strip() for r in refs.split(",")] if isinstance(refs, str) and refs else []
    try:
        return VulnResult(
            asset=g("host") or "",
            check_id=check_id,
            check_name=(g("title") or check_id)[:200],
            category=category.split(":", 1)[-1] if ":" in category else category,
            status=status, severity=severity, confidence=confidence,
            detection_method=ev.get("detection_method", "persisted"),
            severity_rationale=(g("description") or "")[:400],
            remediation=ev.get("remediation", ""),
            url=ev.get("url"),
            references=references,
            tier=ev.get("tier", "passive"),
            evidence={k: v for k, v in ev.items() if not k.startswith(("check_id", "status"))} or {"persisted": True},
        )
    except Exception:
        return None


def build_report(
    target: str,
    results: list[VulnResult],
    *,
    outcome=None,
    scan_id=None,
    limitations: list[str] | None = None,
) -> dict:
    by_sev = {s: 0 for s in SEVERITIES}
    by_status: dict[str, int] = {}
    assets: dict[str, int] = {}
    items = []
    for r in sorted(results, key=lambda r: (-severity_rank(r.severity), -r.confidence)):
        by_sev[r.severity] = by_sev.get(r.severity, 0) + 1
        by_status[r.status] = by_status.get(r.status, 0) + 1
        assets[r.asset] = assets.get(r.asset, 0) + 1
        items.append({
            "asset": r.asset,
            "url": r.url,
            "check_id": r.check_id,
            "name": r.check_name,
            "category": r.category,
            "severity": r.severity,
            "confidence": round(r.confidence, 3),
            "confidence_label": confidence_label(r.confidence),
            "status": r.status,
            "severity_rationale": r.severity_rationale,
            "detection_method": r.detection_method,
            "remediation": r.remediation,
            "references": r.references,
            "evidence": r.evidence,
            "tier": r.tier,
            "source_module": r.source_module,
            "timestamp": r.timestamp,
        })
    report = {
        "target": target,
        "scan_id": str(scan_id) if scan_id else None,
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "total": len(results),
            "by_severity": by_sev,
            "by_status": by_status,
            "assets_affected": len(assets),
        },
        "findings": items,
        "coverage": {
            "checks_executed": sorted(getattr(outcome, "executed", []) or []),
            "checks_skipped": getattr(outcome, "skipped", {}) or {},
            "checks_failed": getattr(outcome, "failed", {}) or {},
        },
        "limitations": limitations or DEFAULT_LIMITATIONS,
    }
    return report


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def _bar(report: dict) -> str:
    s = report["summary"]["by_severity"]
    parts = [f"{k}={s[k]}" for k in reversed(SEVERITIES) if s.get(k)]
    return ", ".join(parts) or "none"


def render_text(report: dict) -> list[str]:
    s = report["summary"]
    lines = [
        "Recon-AI Vulnerability Assessment",
        "=================================",
        "",
        f"Target        : {report['target']}",
        f"Generated     : {report['generated_at']}",
        f"Scan          : {report.get('scan_id') or '(in-memory)'}",
        "",
        "Executive summary",
        "-----------------",
        f"{s['total']} assessment result(s) across {s['assets_affected']} asset(s).",
        f"Severity: {_bar(report)}",
        "Verification: " + (", ".join(f"{k}={v}" for k, v in s["by_status"].items()) or "none"),
        "All results are evidence-backed; CVE correlations are POTENTIAL/UNCONFIRMED, never",
        "assumed present from a version string alone.",
        "",
        "Findings (by severity, then confidence)",
        "---------------------------------------",
    ]
    if not report["findings"]:
        lines.append("(no vulnerability results)")
    for i, f in enumerate(report["findings"], 1):
        lines.append(
            f"{i:>3}. [{f['severity'].upper()}] [{f['status']}] "
            f"{f['name']}  (conf={f['confidence']:.2f}/{f['confidence_label']})"
        )
        lines.append(f"     asset   : {f['asset']}" + (f"   url: {f['url']}" if f['url'] else ""))
        lines.append(f"     check   : {f['check_id']}  ·  category: {f['category']}  ·  via: {f['detection_method']}")
        if f["severity_rationale"]:
            lines.append(f"     why     : {f['severity_rationale'][:200]}")
        if f["evidence"]:
            ev = ", ".join(f"{k}={v}" for k, v in list(f["evidence"].items())[:6])
            lines.append(f"     evidence: {ev[:300]}")
        if f["references"]:
            lines.append(f"     refs    : {', '.join(f['references'])}")
        if f["remediation"]:
            lines.append(f"     fix     : {f['remediation'][:200]}")
        lines.append("")

    cov = report["coverage"]
    lines += [
        "Assets affected",
        "---------------",
    ]
    assets = sorted({f["asset"] for f in report["findings"]})
    lines += [f"- {a}" for a in assets] or ["(none)"]
    lines += [
        "",
        "Coverage",
        "--------",
        f"Checks executed: {', '.join(cov['checks_executed']) or '(none)'}",
        f"Checks skipped : " + (", ".join(f"{k} ({v})" for k, v in cov["checks_skipped"].items()) or "(none)"),
        f"Checks failed  : " + (", ".join(f"{k} ({v})" for k, v in cov["checks_failed"].items()) or "(none)"),
        "",
        "Limitations",
        "-----------",
    ]
    lines += [f"- {l}" for l in report["limitations"]]
    return lines


def summary_sections(report: dict) -> list[str]:
    """Compact section appended to the aggregator's summary.txt."""
    s = report["summary"]
    out = ["", "Vulnerability Assessment", "------------------------",
           f"Results: {s['total']} across {s['assets_affected']} asset(s)  [{_bar(report)}]"]
    top = report["findings"][:8]
    for f in top:
        out.append(f"  [{f['severity'].upper()}/{f['status']}] {f['name']} ({f['asset']})")
    if s["total"] > len(top):
        out.append(f"  … and {s['total'] - len(top)} more (see vulnerabilities.txt)")
    return out
