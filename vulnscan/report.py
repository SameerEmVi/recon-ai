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

import html
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
    evidence: dict[str, list] | None = None,
) -> dict:
    """`evidence` maps a result's dedup_key (asset|check_id|url) → a list of
    captured-exchange display dicts (evidence.exchange_for_display), attached to
    each finding as `evidence_exchanges` so the report can show the proof."""
    evidence = evidence or {}
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
            "evidence_exchanges": evidence.get(r.dedup_key, []),
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


def _md_body(text: str | None, limit: int = 1200) -> str:
    """A fenced-code quote of a captured body (truncated, backticks neutralised)."""
    if not text:
        return ""
    body = text[:limit].replace("```", "ʼʼʼ")
    more = "\n… (truncated)" if len(text) > limit else ""
    return f"\n```\n{body}{more}\n```\n"


def render_markdown(report: dict) -> str:
    """Render the report as Markdown with per-finding request/response evidence —
    the operator-facing, shareable deliverable (docs §5)."""
    s = report["summary"]
    out: list[str] = [
        f"# Vulnerability Assessment — {report['target']}",
        "",
        f"- **Generated:** {report['generated_at']}",
        f"- **Scan:** `{report.get('scan_id') or '(in-memory)'}`",
        f"- **Results:** {s['total']} across {s['assets_affected']} asset(s)",
        f"- **Severity:** {_bar(report)}",
        "- **Verification:** "
        + (", ".join(f"{k}={v}" for k, v in s["by_status"].items()) or "none"),
        "",
        "> All results are evidence-backed. CVE correlations are POTENTIAL/UNCONFIRMED —"
        " never assumed present from a version string alone.",
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        out.append("_No vulnerability results._\n")
    for i, f in enumerate(report["findings"], 1):
        where = f["url"] or f["asset"]
        out.append(f"### {i}. {f['name']} — `{f['severity'].upper()}` · {f['status']}")
        out.append("")
        out.append(f"- **Asset:** `{where}`")
        out.append(f"- **Check:** `{f['check_id']}` · category `{f['category']}`"
                   f" · confidence {f['confidence']:.2f} ({f['confidence_label']})")
        if f["severity_rationale"]:
            out.append(f"- **Why:** {f['severity_rationale']}")
        if f["remediation"]:
            out.append(f"- **Remediation:** {f['remediation']}")
        if f["references"]:
            out.append(f"- **References:** {', '.join(f['references'])}")
        exchanges = f.get("evidence_exchanges") or []
        if exchanges:
            out.append("")
            out.append(f"**Evidence** ({len(exchanges)} captured exchange(s)):")
            for ex in exchanges:
                out.append("")
                out.append(f"- `{ex.get('method')} {ex.get('status_code')} "
                           f"{ex.get('url')}` · {ex.get('source_tool') or 'tool'}")
                resp = _md_body(ex.get("response_body"))
                if resp:
                    out.append("  Response body:" + resp)
                elif ex.get("bodies_dropped"):
                    out.append(f"  _{ex['bodies_dropped']}_")
        elif f["evidence"]:
            ev = ", ".join(f"{k}={v}" for k, v in list(f["evidence"].items())[:8])
            out.append(f"- **Evidence:** {ev}")
        out.append("")

    cov = report["coverage"]
    out += [
        "## Assets affected",
        "",
        *([f"- `{a}`" for a in sorted({f['asset'] for f in report['findings']})] or ["_none_"]),
        "",
        "## Coverage",
        "",
        f"- **Executed:** {', '.join(cov['checks_executed']) or '(none)'}",
        f"- **Skipped:** " + (", ".join(f"{k} ({v})" for k, v in cov["checks_skipped"].items()) or "(none)"),
        f"- **Failed:** " + (", ".join(f"{k} ({v})" for k, v in cov["checks_failed"].items()) or "(none)"),
        "",
        "## Limitations",
        "",
        *[f"- {l}" for l in report["limitations"]],
        "",
    ]
    return "\n".join(out)


_HTML_CSS = """
:root { color-scheme: light dark; --bg:#0d1117; --card:#161b22; --border:#30363d;
  --fg:#e6edf3; --muted:#8b949e; --crit:#f85149; --warn:#d29922; --ok:#3fb950;
  --sky:#58a6ff; }
* { box-sizing: border-box; }
body { margin:0; padding:2rem; background:var(--bg); color:var(--fg);
  font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
.wrap { max-width:960px; margin:0 auto; }
h1 { font-size:1.5rem; margin:0 0 .25rem; } h2 { font-size:1.1rem; margin:2rem 0 .75rem;
  border-bottom:1px solid var(--border); padding-bottom:.35rem; }
.meta { color:var(--muted); font-size:.85rem; margin-bottom:1rem; }
.meta code, code { background:rgba(110,118,129,.25); padding:.1em .35em; border-radius:4px;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.85em; }
.note { color:var(--muted); border-left:3px solid var(--border); padding:.25rem .75rem; margin:1rem 0; }
.finding { background:var(--card); border:1px solid var(--border); border-left-width:4px;
  border-radius:8px; padding:1rem 1.1rem; margin:.9rem 0; }
.sev-critical,.sev-high { border-left-color:var(--crit); }
.sev-medium { border-left-color:var(--warn); } .sev-low { border-left-color:var(--sky); }
.sev-info { border-left-color:var(--muted); }
.ftitle { font-weight:600; font-size:1rem; } .badge { font-size:.7rem; text-transform:uppercase;
  padding:.1em .5em; border-radius:4px; background:rgba(110,118,129,.25); margin-left:.4rem; }
.kv { color:var(--muted); font-size:.85rem; margin:.3rem 0; } .kv b { color:var(--fg); font-weight:600; }
.ev { margin-top:.6rem; } .ex { font-family:ui-monospace,monospace; font-size:.82rem; color:var(--sky); margin:.5rem 0 .2rem; }
pre { background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:.6rem .7rem;
  overflow:auto; max-height:22rem; white-space:pre-wrap; word-break:break-all; font-size:.78rem; margin:.2rem 0; }
ul { margin:.3rem 0; padding-left:1.2rem; } a { color:var(--sky); }
@media print { body { background:#fff; color:#000; } .finding,pre { background:#fff; } }
"""


def _h(x) -> str:
    return html.escape(str(x), quote=False)


def render_html(report: dict) -> str:
    """A self-contained, printable HTML report (print-to-PDF friendly) with each
    finding's captured request/response evidence — bodies HTML-escaped so a
    captured page renders as text, never injected."""
    s = report["summary"]
    status = ", ".join(f"{k}={v}" for k, v in s["by_status"].items()) or "none"
    out = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>Vulnerability Assessment — {_h(report['target'])}</title>",
        f"<style>{_HTML_CSS}</style></head><body><div class='wrap'>",
        f"<h1>Vulnerability Assessment — {_h(report['target'])}</h1>",
        f"<div class='meta'>Generated {_h(report['generated_at'])} · "
        f"Scan <code>{_h(report.get('scan_id') or '(in-memory)')}</code><br>"
        f"{s['total']} result(s) across {s['assets_affected']} asset(s) · "
        f"Severity: {_h(_bar(report))} · Verification: {_h(status)}</div>",
        "<div class='note'>All results are evidence-backed. CVE correlations are "
        "POTENTIAL/UNCONFIRMED — never assumed present from a version string alone.</div>",
        "<h2>Findings</h2>",
    ]
    if not report["findings"]:
        out.append("<p class='kv'>No vulnerability results.</p>")
    for i, f in enumerate(report["findings"], 1):
        where = f["url"] or f["asset"]
        out.append(f"<div class='finding sev-{_h(f['severity'])}'>")
        out.append(f"<div class='ftitle'>{i}. {_h(f['name'])}"
                   f"<span class='badge'>{_h(f['severity'])}</span>"
                   f"<span class='badge'>{_h(f['status'])}</span></div>")
        out.append(f"<div class='kv'><b>Asset:</b> <code>{_h(where)}</code></div>")
        out.append(f"<div class='kv'><b>Check:</b> <code>{_h(f['check_id'])}</code> · "
                   f"category <code>{_h(f['category'])}</code> · confidence "
                   f"{f['confidence']:.2f} ({_h(f['confidence_label'])})</div>")
        if f["severity_rationale"]:
            out.append(f"<div class='kv'><b>Why:</b> {_h(f['severity_rationale'])}</div>")
        if f["remediation"]:
            out.append(f"<div class='kv'><b>Remediation:</b> {_h(f['remediation'])}</div>")
        if f["references"]:
            refs = ", ".join(_h(r) for r in f["references"])
            out.append(f"<div class='kv'><b>References:</b> {refs}</div>")
        exchanges = f.get("evidence_exchanges") or []
        if exchanges:
            out.append(f"<div class='ev'><b class='kv'>Evidence ({len(exchanges)} "
                       "captured exchange(s)):</b>")
            for ex in exchanges:
                out.append(f"<div class='ex'>{_h(ex.get('method'))} "
                           f"{_h(ex.get('status_code'))} {_h(ex.get('url'))} · "
                           f"{_h(ex.get('source_tool') or 'tool')}</div>")
                if ex.get("response_body"):
                    out.append(f"<pre>{_h(ex['response_body'])}</pre>")
                elif ex.get("bodies_dropped"):
                    out.append(f"<div class='kv'><i>{_h(ex['bodies_dropped'])}</i></div>")
            out.append("</div>")
        elif f["evidence"]:
            ev = ", ".join(f"{_h(k)}={_h(v)}" for k, v in list(f["evidence"].items())[:8])
            out.append(f"<div class='kv'><b>Evidence:</b> {ev}</div>")
        out.append("</div>")

    cov = report["coverage"]
    assets = sorted({f["asset"] for f in report["findings"]})
    out.append("<h2>Assets affected</h2><ul>")
    out += [f"<li><code>{_h(a)}</code></li>" for a in assets] or ["<li>none</li>"]
    out.append("</ul><h2>Coverage</h2><ul>")
    out.append(f"<li><b>Executed:</b> {_h(', '.join(cov['checks_executed']) or '(none)')}</li>")
    out.append(f"<li><b>Skipped:</b> {_h(', '.join(f'{k} ({v})' for k, v in cov['checks_skipped'].items()) or '(none)')}</li>")
    out.append(f"<li><b>Failed:</b> {_h(', '.join(f'{k} ({v})' for k, v in cov['checks_failed'].items()) or '(none)')}</li>")
    out.append("</ul><h2>Limitations</h2><ul>")
    out += [f"<li>{_h(l)}</li>" for l in report["limitations"]]
    out.append("</ul></div></body></html>")
    return "".join(out)


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
