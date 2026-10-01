"""
LLM Correlation & Intelligence layer.

Runs after deterministic enumeration, over the central aggregator's in-memory
structured evidence (NOT the DB, NOT raw pages/files/JS). Flow:

    build_evidence(aggregator)      # deterministic: counts + capped samples + a
                                    #   `known` token set for the guardrail
        ↓
    IntelligenceAnalyst.analyze()   # one forced-schema LLM call (Assessor)
        ↓
    verify()                        # GUARDRAIL: drop any claim whose evidence
                                    #   isn't traceable to collected data, and
                                    #   any recommendation naming a non-existent
                                    #   module — enforces "never invent facts"
        ↓
    render()                        # intelligence.txt lines + summary.txt sections

The model only ever sees the sanitized bundle (values are already control-char
stripped + length capped upstream), and the system prompt tells it to treat all
values as data. Nothing here takes a recon action — it produces leads only.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlparse

log = logging.getLogger("ai.correlate")

DEFAULT_MODEL = "claude-sonnet-4-6"

# Existing modules the analyst may recommend as "next recon" (analysis-oriented).
# Kept as a curated set of real module names; verified against the registry when
# available so a recommendation can never name a non-existent capability.
_ANALYSIS_MODULES = [
    "js_intel", "apifinder", "linkfinder", "paramfinder", "dirsearch", "ffuf",
    "secretfinder", "trufflehog", "metascan", "nuclei", "katana", "fingerprint", "whatweb",
    "wayback", "cloud_intel", "takeover", "corscanner", "bypass403",
]


# ── result types ────────────────────────────────────────────────────────────

@dataclass
class IntelFinding:
    title: str
    interest: str          # HIGH / MEDIUM / LOW
    confidence: str        # LOW / MEDIUM / HIGH
    status: str            # OBSERVED / INFERRED / INTERESTING / POTENTIAL / CONFIRMED
    category: str
    evidence: list[str]
    reason: str
    next_action: str = ""


@dataclass
class UrlClass:
    url: str
    category: str
    confidence: str
    evidence: list[str]


@dataclass
class DataExposure:
    item: str
    kind: str
    confidence: str
    evidence: list[str]


@dataclass
class NextStep:
    module: str
    reason: str
    evidence: list[str]


@dataclass
class IntelligenceReport:
    target: str
    model: str
    findings: list[IntelFinding] = field(default_factory=list)
    url_classifications: list[UrlClass] = field(default_factory=list)
    data_exposure: list[DataExposure] = field(default_factory=list)
    recommended_next: list[NextStep] = field(default_factory=list)
    overall_notes: str = ""
    dropped: int = 0       # claims discarded by the guardrail (unverifiable)

    @property
    def is_empty(self) -> bool:
        return not (self.findings or self.url_classifications
                    or self.data_exposure or self.recommended_next)


# ── evidence packaging (deterministic, unit-tested) ───────────────────────────

_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _cap(seq, n: int) -> list:
    try:
        return sorted(seq)[:n]
    except TypeError:
        return list(seq)[:n]


def build_evidence(agg, *, diff_new: list[str] | None = None, sample: int = 40) -> tuple[dict, set[str]]:
    """Build the sanitized evidence bundle + a `known` token set for the guardrail.

    Reads only the aggregator's normalized, deduplicated, already-sanitized
    structured state. Returns (bundle_for_prompt, known_tokens_lowercased).
    """
    def call(name, default):
        fn = getattr(agg, name, None)
        try:
            return fn() if callable(fn) else default
        except Exception:
            return default

    urls = sorted(getattr(agg, "urls", set()))
    endpoints = sorted(getattr(agg, "endpoints", set()))
    param_names = sorted(getattr(agg, "params", {}).keys())
    techs = sorted({t for s in getattr(agg, "techs", {}).values() for t in s})
    api_eps = call("_api_endpoints", [])
    wayback = agg._urls_by_source("wayback") if hasattr(agg, "_urls_by_source") else []
    js_files = call("_js_files", [])
    js_endpoints = call("_js_endpoints", [])
    files = call("_files", [])
    interesting_params = call("_interesting_params", [])

    live_lines = []
    for host, info in list(getattr(agg, "live", {}).items())[:sample]:
        st = info.get("status") if isinstance(info, dict) else None
        srv = info.get("server") if isinstance(info, dict) else None
        live_lines.append(f"[{st}] {host}" + (f" {srv}" if srv else ""))

    findings = [
        {"title": f.get("title"), "host": f.get("host"),
         "category": f.get("category"), "severity": f.get("severity")}
        for f in getattr(agg, "findings", [])
    ]
    anomalies = [
        {"host": a.get("host"), "category": a.get("category"),
         "description": (a.get("description") or "")[:200]}
        for a in getattr(agg, "anomalies", [])
    ][:sample]

    bundle = {
        "counts": {
            "subdomains": len(getattr(agg, "domains", [])),
            "live_hosts": len(getattr(agg, "live", {})),
            "ips": len(getattr(agg, "ips", {})),
            "open_ports": len(getattr(agg, "ports", {})),
            "urls": len(urls),
            "endpoints": len(endpoints),
            "parameters": sum(len(v) for v in getattr(agg, "params", {}).values()),
            "technologies": len(techs),
            "api_endpoints": len(api_eps),
            "javascript_files": len(js_files),
            "wayback_urls": len(wayback),
            "files": len(files),
            "findings": len(findings),
        },
        "subdomains_sample": _cap(getattr(agg, "domains", set()), sample),
        "live_hosts": live_lines,
        "technologies": techs,
        "endpoints_sample": endpoints[:sample],
        "api_endpoints_sample": api_eps[:sample],
        "parameters_sample": param_names[:sample],
        "interesting_parameters_sample": interesting_params[:sample],
        "javascript_files_sample": js_files[:sample],
        "javascript_endpoints_sample": js_endpoints[:sample],
        "source_maps": _cap(getattr(agg, "source_maps", set()), sample),
        "wayback_sample": wayback[:sample],
        "files_sample": files[:sample],
        "document_metadata_sample": getattr(agg, "doc_metadata", [])[:sample],
        "emails": _cap(getattr(agg, "emails", set()), sample),
        "usernames": _cap(getattr(agg, "usernames", set()), sample),
        "findings": findings[:sample],
        "anomalies": anomalies,
        "new_since_last_scan": (diff_new or [])[:sample],
        "sources": sorted(getattr(agg, "sources", set())),
    }

    # Known-token set for the guardrail: every collected value the LLM may cite.
    known: set[str] = set()

    def add(*vals):
        for v in vals:
            if not v:
                continue
            s = str(v).lower().strip()
            if len(s) >= 4:
                known.add(s)

    for u in urls:
        add(u, urlparse(u).path)
    for e in endpoints:
        add(e, urlparse(e).path)
    add(*getattr(agg, "domains", set()))
    add(*techs, *param_names, *interesting_params)
    add(*js_files, *js_endpoints, *files, *wayback)
    add(*getattr(agg, "source_maps", set()))
    add(*getattr(agg, "emails", set()), *getattr(agg, "usernames", set()))
    add(*getattr(agg, "doc_metadata", []))
    add(*[a.replace(":", "") for a in getattr(agg, "ports", {}).keys()])
    add(*getattr(agg, "ips", {}).keys())
    for f in findings:
        add(f.get("title"), f.get("host"), f.get("category"))
    for a in anomalies:
        add(a.get("host"), a.get("category"), a.get("description"))
    for line in live_lines:
        add(line)
    return bundle, known


# ── guardrail: verify LLM output against collected evidence ───────────────────

def _supported(evidence: list, known: set[str]) -> list[str]:
    """Return the evidence items that trace to collected data (substring match
    either direction, min token length 4). Empty => nothing verifiable."""
    ok: list[str] = []
    for item in evidence or []:
        e = str(item).lower().strip()
        if len(e) < 4:
            continue
        if any(t in e or e in t for t in known):
            ok.append(str(item))
    return ok


def verify(raw: dict, known: set[str], allowed_modules: set[str], target: str, model: str) -> IntelligenceReport:
    """Filter the raw LLM output: drop any claim not grounded in collected
    evidence, and any recommendation naming a non-existent module."""
    report = IntelligenceReport(target=target, model=model)
    dropped = 0
    allowed_lc = {m.lower() for m in allowed_modules}

    for f in raw.get("findings", []) or []:
        supp = _supported(f.get("evidence", []), known)
        if not supp:
            dropped += 1
            log.debug("intel: dropped unverifiable finding %r", f.get("title"))
            continue
        report.findings.append(IntelFinding(
            title=str(f.get("title", ""))[:200],
            interest=str(f.get("interest", "LOW")).upper(),
            confidence=str(f.get("confidence", "LOW")).upper(),
            status=str(f.get("status", "INTERESTING")).upper(),
            category=str(f.get("category", "OTHER")).upper(),
            evidence=supp[:10],
            reason=str(f.get("reason", ""))[:500],
            next_action=str(f.get("next_action", ""))[:200],
        ))

    for u in raw.get("url_classifications", []) or []:
        url = str(u.get("url", "")).strip()
        if not url or url.lower() not in known:
            dropped += 1
            continue
        report.url_classifications.append(UrlClass(
            url=url,
            category=str(u.get("category", "OTHER")).upper(),
            confidence=str(u.get("confidence", "LOW")).upper(),
            evidence=_supported(u.get("evidence", []), known)[:6] or [url],
        ))

    for d in raw.get("data_exposure", []) or []:
        supp = _supported(d.get("evidence", []), known)
        if not supp:
            dropped += 1
            continue
        report.data_exposure.append(DataExposure(
            item=str(d.get("item", ""))[:200],
            kind=str(d.get("kind", ""))[:60],
            confidence=str(d.get("confidence", "LOW")).upper(),
            evidence=supp[:6],
        ))

    for n in raw.get("recommended_next", []) or []:
        mod = str(n.get("module", "")).strip().lower()
        if mod not in allowed_lc:
            dropped += 1
            log.debug("intel: dropped recommendation for unknown module %r", mod)
            continue
        report.recommended_next.append(NextStep(
            module=mod,
            reason=str(n.get("reason", ""))[:300],
            evidence=_supported(n.get("evidence", []), known)[:6],
        ))

    report.overall_notes = str(raw.get("overall_notes", ""))[:800]
    report.dropped = dropped

    report.findings.sort(key=lambda x: (_RANK.get(x.interest, 3), _RANK.get(x.confidence, 3)))
    return report


# ── rendering ─────────────────────────────────────────────────────────────────

def render_intelligence_txt(report: IntelligenceReport) -> list[str]:
    """Full intelligence.txt content."""
    L = [
        "Recon-AI — LLM Correlation & Intelligence",
        "=========================================",
        f"Target: {report.target}",
        f"Model: {report.model}",
        f"Generated: {datetime.now(UTC).isoformat()}",
        "",
        "Leads for authorized analysis only. Epistemic status: OBSERVED = present",
        "in the data; INFERRED = reasoned from it; INTERESTING/POTENTIAL = a lead/",
        "hypothesis; CONFIRMED = evidence proves it. No item asserts a vulnerability",
        "without cited evidence. Every claim is traced to collected data.",
        "",
        "INTERESTING FINDINGS",
        "--------------------",
    ]
    if report.findings:
        for f in report.findings:
            L.append(f"[{f.interest}] (confidence {f.confidence} · {f.status} · {f.category}) {f.title}")
            if f.reason:
                L.append(f"    reason: {f.reason}")
            for ev in f.evidence:
                L.append(f"    evidence: {ev}")
            if f.next_action:
                L.append(f"    next: {f.next_action}")
            L.append("")
    else:
        L += ["(none survived evidence verification)", ""]

    if report.url_classifications:
        L += ["URL CLASSIFICATION", "------------------"]
        for u in report.url_classifications:
            L.append(f"[{u.category}] ({u.confidence}) {u.url}")
            for ev in u.evidence:
                L.append(f"    evidence: {ev}")
        L.append("")

    if report.data_exposure:
        L += ["POTENTIAL DATA EXPOSURE", "-----------------------"]
        for d in report.data_exposure:
            kind = f"{d.kind}: " if d.kind else ""
            L.append(f"[{d.confidence}] {kind}{d.item}")
            for ev in d.evidence:
                L.append(f"    evidence: {ev}")
        L.append("")

    if report.recommended_next:
        L += ["RECOMMENDED NEXT RECON", "----------------------"]
        for i, n in enumerate(report.recommended_next, 1):
            L.append(f"{i}. {n.module} — {n.reason}")
            for ev in n.evidence:
                L.append(f"    evidence: {ev}")
        L.append("")

    if report.overall_notes:
        L += ["NOTES", "-----", report.overall_notes, ""]
    if report.dropped:
        L.append(f"# {report.dropped} unverifiable model claim(s) were discarded by the evidence guardrail.")
    return L


def render_summary_sections(report: IntelligenceReport) -> list[str]:
    """Sections appended to summary.txt (the final intelligence report tail)."""
    L = ["", "Interesting Findings", "--------------------"]
    if report.findings:
        for f in report.findings:
            L.append(f"[{f.interest}] {f.title}  ({f.status}/{f.confidence})")
    else:
        L.append("(none)")

    L += ["", "Potential Data Exposure", "-----------------------"]
    if report.data_exposure:
        for d in report.data_exposure:
            kind = f"{d.kind}: " if d.kind else ""
            L.append(f"- {kind}{d.item}")
    else:
        L.append("(none)")

    L += ["", "Recommended Next Recon", "-----------------------"]
    if report.recommended_next:
        for i, n in enumerate(report.recommended_next, 1):
            L.append(f"{i}. {n.module} — {n.reason}")
    else:
        L.append("(none)")
    return L


# ── analyst orchestration ─────────────────────────────────────────────────────

class IntelligenceAnalyst:
    def __init__(self, api_key: str, model: str = DEFAULT_MODEL, allowed_modules: list[str] | None = None) -> None:
        import anthropic
        from ai.assessor import Assessor
        self._assessor = Assessor(anthropic.AsyncAnthropic(api_key=api_key), model)
        self._model = model
        self._allowed = list(allowed_modules or _allowed_modules())

    async def analyze(self, agg, *, target: str, diff_new: list[str] | None = None) -> IntelligenceReport:
        from ai.prompts.intelligence import INTELLIGENCE_TOOL, build_intelligence_prompt

        bundle, known = build_evidence(agg, diff_new=diff_new)
        prompt = build_intelligence_prompt(bundle, self._allowed)
        raw = await self._assessor.call(prompt, INTELLIGENCE_TOOL)
        if not raw:
            log.warning("intel: LLM returned no structured output")
            return IntelligenceReport(target=target, model=self._model)
        report = verify(raw, known, set(self._allowed), target, self._model)
        log.info("intel: %d finding(s), %d url class, %d exposure, %d next (%d dropped)",
                 len(report.findings), len(report.url_classifications),
                 len(report.data_exposure), len(report.recommended_next), report.dropped)
        return report


def _allowed_modules() -> list[str]:
    """Curated analysis modules, intersected with what the registry actually has."""
    try:
        from modules.registry import ModuleRegistry
        registered = set(ModuleRegistry.all_names()) if hasattr(ModuleRegistry, "all_names") else set()
    except Exception:
        registered = set()
    if registered:
        keep = [m for m in _ANALYSIS_MODULES if m in registered]
        return keep or _ANALYSIS_MODULES
    return list(_ANALYSIS_MODULES)
