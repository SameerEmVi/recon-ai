"""
The native check library + the `Check` interface and check registry.

A `Check` is the consistent unit of assessment (requirement #3):

    id / name / category          — identity
    tier                          — passive | active | intrusive
    supported_technologies        — [] = agnostic; else gates on fingerprint
    prerequisites                 — informational: what context it needs
    required_evidence             — what must be present to produce a result
    verification                  — human description of the verification strategy
    applies(ctx) -> bool          — technology-aware selection
    run(ctx) -> list[VulnResult]  — the (async) detection, returning the schema

Checks never raise into the engine (the engine isolates them anyway), never
assume a 200 means a vulnerability, and consume existing recon evidence rather
than re-probing where another module already did the work.

All network I/O goes through `ctx.fetch` (the module's shared rate-limited,
WAF-aware, cached fetch) — checks never open their own client.
"""

from __future__ import annotations

import secrets
from abc import ABC, abstractmethod
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from vulnscan.cve import correlate
from vulnscan.schema import (
    TIER_ACTIVE,
    TIER_INTRUSIVE,
    TIER_PASSIVE,
    Severity,
    Status,
    VulnResult,
)

# ── keyword sets (paths/titles) — leads, not vuln claims ──────────────────────
_ADMIN_KW = ("admin", "administrator", "wp-admin", "wp-login", "dashboard",
             "console", "manage", "cpanel", "backoffice", "/phpmyadmin", "/pgadmin")
_DEBUG_KW = ("debug", "trace", "phpinfo", "actuator", "/server-status", "/metrics",
             "/_profiler", "/__debug__", "/telescope", "/_debugbar")
_DIAG_KW = ("/health", "/healthz", "/status", "/env", "/actuator/env", "/actuator/heapdump",
            "/debug/vars", "/jolokia")
_REACHABLE = frozenset({200, 201, 204, 301, 302, 307, 308, 401, 403})


# ── context ───────────────────────────────────────────────────────────────────

class CheckContext:
    """Everything a check may reason over for one host, plus the shared fetcher.

    Built and populated by the engine from accumulated, already-scope-gated recon
    events. `technologies` maps lowercased product name → version (or None).
    `headers`/`bodies`/`status`/`set_cookies` are populated by the engine's single
    low-impact GET per live service when active checks are enabled.
    """

    def __init__(self, host: str, *, fetch=None, active_enabled: bool = True,
                 intrusive_enabled: bool = False) -> None:
        self.host = host
        self.technologies: dict[str, str | None] = {}
        self.services: list[dict] = []           # {url,status,title,server}
        self.urls: set[str] = set()
        self.endpoints: set[str] = set()
        self.params: dict[str, set[str]] = {}    # base_url -> {param names}
        self.existing_findings: list[dict] = []  # normalized dicts from other modules
        # active-probe state (filled by engine)
        self.headers: dict[str, dict[str, str]] = {}
        self.bodies: dict[str, str] = {}
        self.status: dict[str, int | None] = {}
        self.set_cookies: dict[str, list[str]] = {}
        # services / fetch
        self.fetch = fetch
        self.active_enabled = active_enabled
        self.intrusive_enabled = intrusive_enabled

    @property
    def tech_names(self) -> set[str]:
        return set(self.technologies)

    def has_api(self) -> bool:
        if {"graphql", "swagger/openapi"} & self.tech_names:
            return True
        for u in self.urls | self.endpoints:
            p = urlparse(u).path.lower()
            if "/api/" in p or p == "/api" or "graphql" in p or "swagger" in p or "openapi" in p:
                return True
        return False

    def live_urls(self) -> list[str]:
        """HTTP service URLs to probe for header/cookie checks."""
        return [s["url"] for s in self.services if s.get("url")]


# ── Check interface + registry ────────────────────────────────────────────────

class Check(ABC):
    id: str = ""
    name: str = ""
    category: str = ""
    tier: str = TIER_PASSIVE
    supported_technologies: list[str] = []
    prerequisites: list[str] = []
    required_evidence: list[str] = []
    verification: str = ""

    def applies(self, ctx: CheckContext) -> bool:
        if self.supported_technologies:
            want = {t.lower() for t in self.supported_technologies}
            if not (want & ctx.tech_names):
                return False
        return True

    @abstractmethod
    async def run(self, ctx: CheckContext) -> list[VulnResult]: ...


_CHECKS: dict[str, Check] = {}


def register_check(cls):
    """Class decorator — instantiate and register a stateless Check."""
    inst = cls()
    if not inst.id:
        raise ValueError(f"{cls.__name__} must set a non-empty id")
    _CHECKS[inst.id] = inst
    return cls


def all_checks() -> list[Check]:
    return list(_CHECKS.values())


def get_check(check_id: str) -> Check | None:
    return _CHECKS.get(check_id)


def select_checks(ctx: CheckContext, *, active: bool, intrusive: bool):
    """Technology-aware selection. Returns (selected, skipped) where skipped is a
    list of (check_id, reason) so the report can explain coverage."""
    tiers = {TIER_PASSIVE}
    if active:
        tiers.add(TIER_ACTIVE)
    if intrusive:
        tiers.add(TIER_INTRUSIVE)
    selected, skipped = [], []
    for chk in _CHECKS.values():
        if chk.tier not in tiers:
            skipped.append((chk.id, f"tier '{chk.tier}' disabled"))
            continue
        try:
            if not chk.applies(ctx):
                skipped.append((chk.id, "not applicable to host"))
                continue
        except Exception as exc:  # applies() must never break selection
            skipped.append((chk.id, f"applies() error: {exc}"))
            continue
        selected.append(chk)
    return selected, skipped


# ── helpers ─────────────────────────────────────────────────────────────────

def _is_https(url: str) -> bool:
    return urlparse(url).scheme == "https"


def _with_param(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[name] = value
    return urlunparse(p._replace(query=urlencode(q)))


# ── native checks ──────────────────────────────────────────────────────────────

@register_check
class SecurityHeadersCheck(Check):
    id = "security-headers"
    name = "Missing security headers"
    category = "security-headers"
    tier = TIER_ACTIVE
    prerequisites = ["HTTP_SERVICE"]
    required_evidence = ["response headers"]
    verification = "Low-impact GET; inspect response headers directly."

    # header -> (label, severity, remediation)
    _WANT = {
        "strict-transport-security": ("HSTS (HTTPS only)", Severity.LOW,
                                      "Send Strict-Transport-Security with a long max-age."),
        "content-security-policy": ("Content-Security-Policy", Severity.LOW,
                                    "Define a restrictive Content-Security-Policy."),
        "x-content-type-options": ("X-Content-Type-Options: nosniff", Severity.LOW,
                                   "Set X-Content-Type-Options: nosniff."),
        "x-frame-options": ("X-Frame-Options / frame-ancestors", Severity.LOW,
                            "Set X-Frame-Options or a CSP frame-ancestors directive."),
        "referrer-policy": ("Referrer-Policy", Severity.INFO,
                            "Set a privacy-preserving Referrer-Policy."),
    }

    def applies(self, ctx):
        return bool(ctx.services)

    async def run(self, ctx):
        out = []
        for url in ctx.live_urls():
            hdrs = ctx.headers.get(url)
            if hdrs is None:
                continue  # no probe result (fetch failed / active disabled)
            missing = []
            for h, (label, sev, _rem) in self._WANT.items():
                if h == "strict-transport-security" and not _is_https(url):
                    continue
                if h == "x-frame-options":
                    csp = hdrs.get("content-security-policy", "")
                    if "frame-ancestors" in csp.lower():
                        continue
                if h not in hdrs:
                    missing.append((h, label, sev))
            # Only the genuinely security-relevant ones drive severity.
            sec = [m for m in missing if m[0] != "referrer-policy"]
            if not sec:
                continue
            worst = Severity.LOW if sec else Severity.INFO
            out.append(VulnResult(
                asset=ctx.host, url=url,
                check_id=self.id, check_name=self.name, category=self.category,
                status=Status.OBSERVED, severity=worst, confidence=0.9,
                detection_method="header-probe",
                severity_rationale=("Hardening headers absent; they reduce the impact of "
                                    "XSS, clickjacking, MIME-sniffing and protocol-downgrade."),
                remediation="; ".join(self._WANT[h][2] for h, _, _ in missing),
                tier=self.tier,
                evidence={"missing": ", ".join(label for _, label, _ in missing)},
            ))
        return out


@register_check
class CookieSecurityCheck(Check):
    id = "cookie-security"
    name = "Insecure cookie attributes"
    category = "session-config"
    tier = TIER_ACTIVE
    prerequisites = ["HTTP_SERVICE"]
    required_evidence = ["Set-Cookie header"]
    verification = "Low-impact GET; inspect Set-Cookie attributes (names only, never values)."

    def applies(self, ctx):
        return bool(ctx.services)

    async def run(self, ctx):
        out = []
        for url in ctx.live_urls():
            cookies = ctx.set_cookies.get(url) or []
            flagged = []
            for raw in cookies:
                name = raw.split("=", 1)[0].strip()[:64] or "cookie"
                low = raw.lower()
                missing = []
                if _is_https(url) and "secure" not in low:
                    missing.append("Secure")
                if "httponly" not in low:
                    missing.append("HttpOnly")
                if "samesite" not in low:
                    missing.append("SameSite")
                if missing:
                    flagged.append(f"{name}(-{'/'.join(missing)})")
            if not flagged:
                continue
            out.append(VulnResult(
                asset=ctx.host, url=url,
                check_id=self.id, check_name=self.name, category=self.category,
                status=Status.OBSERVED, severity=Severity.LOW, confidence=0.9,
                detection_method="header-probe",
                severity_rationale=("Cookies lack hardening attributes; raises session-theft / "
                                    "CSRF exposure. Impact depends on whether a cookie is a session token."),
                remediation="Set Secure + HttpOnly + SameSite on session cookies.",
                tier=self.tier,
                evidence={"cookies": ", ".join(flagged)[:480]},  # names + missing attrs only
            ))
        return out


@register_check
class InfoDisclosureCheck(Check):
    id = "info-disclosure"
    name = "Version/information disclosure in headers"
    category = "info-exposure"
    tier = TIER_ACTIVE
    prerequisites = ["HTTP_SERVICE"]
    required_evidence = ["Server / X-Powered-By header"]
    verification = "Low-impact GET; read banner headers."

    _LEAKY = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
              "x-generator", "x-runtime")

    def applies(self, ctx):
        return bool(ctx.services)

    async def run(self, ctx):
        import re
        out = []
        for url in ctx.live_urls():
            hdrs = ctx.headers.get(url)
            if not hdrs:
                continue
            leaks = {}
            for h in self._LEAKY:
                v = hdrs.get(h)
                if v and re.search(r"\d", v):   # only interesting if it carries a version
                    leaks[h] = v[:128]
            if not leaks:
                continue
            out.append(VulnResult(
                asset=ctx.host, url=url,
                check_id=self.id, check_name=self.name, category=self.category,
                status=Status.OBSERVED, severity=Severity.INFO, confidence=0.95,
                detection_method="header-probe",
                severity_rationale="Software/version banners aid an attacker in selecting known exploits.",
                remediation="Suppress or genericize version banners.",
                tier=self.tier,
                evidence={k: v for k, v in list(leaks.items())[:6]},
            ))
        return out


@register_check
class VersionCveCheck(Check):
    id = "known-cve"
    name = "Known-vulnerable software version"
    category = "known-vulnerability"
    tier = TIER_PASSIVE
    prerequisites = ["TECHNOLOGY with version"]
    required_evidence = ["technology name + version"]
    verification = ("Version-string correlation against a known-vuln dataset. Never CONFIRMED — "
                    "manual build verification required (patches/backports).")

    def applies(self, ctx):
        return any(v for v in ctx.technologies.values())

    async def run(self, ctx):
        out = []
        for name, version in ctx.technologies.items():
            if not version:
                continue
            for m in correlate(name, version):
                kv = m.vuln
                out.append(VulnResult(
                    asset=ctx.host,
                    check_id=self.id, check_name=f"{kv.cve} — {name} {version}",
                    category=self.category,
                    status=m.status, severity=kv.severity, confidence=m.confidence,
                    detection_method="version-correlation",
                    severity_rationale=kv.summary,
                    remediation=f"Upgrade {name} to {kv.fixed_in} or later; confirm the running build.",
                    references=[kv.cve, kv.cwe],
                    tier=self.tier,
                    evidence={"product": name, "version": version,
                              "fixed_in": kv.fixed_in, "note": m.rationale[:400]},
                ))
        return out


@register_check
class ExposedInterfaceCheck(Check):
    id = "exposed-interface"
    name = "Exposed admin/debug/diagnostic interface"
    category = "exposed-interface"
    tier = TIER_PASSIVE
    prerequisites = ["URL / HTTP_SERVICE with status"]
    required_evidence = ["reachable path matching an admin/debug/diagnostic signature"]
    verification = "Reasons over already-probed URLs; reachability taken from recorded status."

    def _status_of(self, ctx, url):
        for s in ctx.services:
            if s.get("url") == url:
                return s.get("status")
        return ctx.status.get(url)

    async def run(self, ctx):
        out, seen = [], set()
        candidates = ctx.urls | {s["url"] for s in ctx.services if s.get("url")}
        for url in candidates:
            path = urlparse(url).path.lower()
            kind = sev = None
            if any(k in path for k in _ADMIN_KW):
                kind, sev = "admin", Severity.MEDIUM
            elif any(k in path for k in _DEBUG_KW):
                kind, sev = "debug", Severity.MEDIUM
            elif any(k in path for k in _DIAG_KW):
                kind, sev = "diagnostic", Severity.LOW
            if not kind:
                continue
            st = self._status_of(ctx, url)
            # Only reachable things are interesting; an unknown status is still a lead.
            if st is not None and st not in _REACHABLE:
                continue
            if url in seen:
                continue
            seen.add(url)
            protected = st in (401, 403)
            out.append(VulnResult(
                asset=ctx.host, url=url,
                check_id=self.id, check_name=f"Exposed {kind} interface",
                category=self.category,
                status=Status.OBSERVED, severity=(Severity.LOW if protected else sev),
                confidence=0.6 if st is None else 0.85,
                detection_method="path-signature",
                severity_rationale=(f"A {kind} interface is reachable"
                                    + (" but appears auth-protected (401/403)." if protected
                                       else " and may expose privileged functionality.")),
                remediation="Restrict to trusted networks / require authentication; remove from production.",
                tier=self.tier,
                evidence={"path": path[:200], "http_status": st},
            ))
        return out


@register_check
class ApiExposureCheck(Check):
    id = "api-exposure"
    name = "API surface exposure"
    category = "api-security"
    tier = TIER_PASSIVE
    prerequisites = ["API endpoint / GraphQL / OpenAPI present"]
    required_evidence = ["API/GraphQL/OpenAPI URL or technology"]
    verification = "Reasons over discovered API endpoints; GraphQL introspection NOT sent (non-destructive)."

    def applies(self, ctx):
        return ctx.has_api()

    async def run(self, ctx):
        out, seen = [], set()
        for url in ctx.urls | ctx.endpoints:
            p = urlparse(url).path.lower()
            tag = None
            if "graphql" in p:
                tag = ("GraphQL endpoint present", Severity.LOW,
                       "Confirm introspection is disabled in production and the endpoint is authenticated.")
            elif "swagger" in p or "openapi" in p or "api-docs" in p:
                tag = ("API documentation/spec publicly reachable", Severity.LOW,
                       "Restrict API docs to trusted users; they enumerate the attack surface.")
            if not tag or url in seen:
                continue
            seen.add(url)
            label, sev, rem = tag
            out.append(VulnResult(
                asset=ctx.host, url=url,
                check_id=self.id, check_name=label, category=self.category,
                status=Status.OBSERVED, severity=sev, confidence=0.75,
                detection_method="endpoint-classification",
                severity_rationale="Information exposure that expands and documents the attack surface.",
                remediation=rem, tier=self.tier,
                evidence={"path": p[:200]},
            ))
        return out


@register_check
class ConsumeFindingsCheck(Check):
    """Normalize findings OTHER modules already emitted into the structured
    schema so the report is unified and the AI layer sees one evidence model.

    These results are included in the report but NOT re-emitted (emit=False) —
    the underlying FINDING_CANDIDATE already exists, so re-emitting would create
    a cross-check duplicate. This is how recon-ai 'reuses existing tools' (CORS,
    exposed-file/secret/source-map, cloud, takeover) in the assessment view.
    """

    id = "normalize-existing"
    name = "Normalized recon finding"
    category = "normalized"
    tier = TIER_PASSIVE
    prerequisites = ["an existing FINDING_CANDIDATE from another module"]
    required_evidence = ["the source finding's own evidence"]
    verification = "Inherits the source module's verification; status derived conservatively."

    # category-prefix -> (status, category_label)
    def _map(self, cat: str, sev: str, ev: dict):
        cat = (cat or "").lower()
        if cat.startswith("vuln:"):
            return None  # our own — don't recurse
        if cat.startswith("exposed-file"):
            try:
                conf = float(ev.get("confidence", ev.get("ev_confidence", 0)) or 0)
            except (TypeError, ValueError):
                conf = 0.0
            status = Status.CONFIRMED if conf >= 0.85 else Status.POTENTIAL
            return status, "exposed-file"
        if cat in ("cors",):
            return Status.POTENTIAL, "cors-misconfig"
        if cat == "exposed-secret":
            return Status.POTENTIAL, "exposed-secret"
        if cat in ("metadata-disclosure",):
            return Status.OBSERVED, "info-exposure"
        if cat == "subdomain-takeover":
            return Status.POTENTIAL, "subdomain-takeover"
        if cat in ("cloud-bucket", "exposed-cloud-storage"):
            return Status.POTENTIAL, "cloud-exposure"
        return None

    def applies(self, ctx):
        return bool(ctx.existing_findings)

    async def run(self, ctx):
        out = []
        for f in ctx.existing_findings:
            mapped = self._map(f.get("category"), f.get("severity"), f.get("evidence") or {})
            if not mapped:
                continue
            status, label = mapped
            ev = {"origin_category": (f.get("category") or "")[:64],
                  "origin_title": (f.get("title") or "")[:200]}
            if f.get("source"):
                ev["origin_module"] = str(f["source"])[:64]
            out.append(VulnResult(
                asset=f.get("host") or ctx.host,
                url=(f.get("evidence") or {}).get("url") or (f.get("evidence") or {}).get("ev_url"),
                check_id=self.id, check_name=f.get("title") or label, category=label,
                status=status, severity=(f.get("severity") or "info").lower(),
                confidence=0.6, detection_method=f"normalized:{f.get('source') or 'module'}",
                severity_rationale=(f.get("description") or "")[:300],
                tier=self.tier, emit=False,   # already an event — report-only
                evidence=ev or {"note": "normalized"},
            ))
        return out


@register_check
class ReflectedInputCheck(Check):
    id = "reflected-input"
    name = "Reflected parameter value"
    category = "injection-indicator"
    tier = TIER_ACTIVE
    prerequisites = ["URL with query parameter"]
    required_evidence = ["a benign canary echoed verbatim in the response"]
    verification = ("Sends ONE benign, non-executing canary token per parameter and checks for "
                    "verbatim reflection. Never sends payloads; result is only an indicator.")

    MAX_URLS = 10
    MAX_PARAMS = 5

    def applies(self, ctx):
        return ctx.active_enabled and bool(ctx.params) and ctx.fetch is not None

    async def run(self, ctx):
        out = []
        urls = [u for u in ctx.params if urlparse(u).scheme in ("http", "https")][: self.MAX_URLS]
        for base in urls:
            names = sorted(ctx.params[base])[: self.MAX_PARAMS]
            reflected = []
            for name in names:
                token = "rxc" + secrets.token_hex(6)   # benign, no metacharacters
                probe = _with_param(base, name, token)
                try:
                    res = await ctx.fetch(probe)
                except Exception:
                    continue
                if not getattr(res, "ok", False):
                    continue
                body = getattr(res, "text", None) or ""
                if token in body:
                    reflected.append(name)
            if reflected:
                out.append(VulnResult(
                    asset=ctx.host, url=base,
                    check_id=self.id, check_name=self.name, category=self.category,
                    status=Status.POTENTIAL, severity=Severity.LOW, confidence=0.5,
                    detection_method="benign-canary-reflection",
                    severity_rationale=("Input is reflected unencoded into the response — an indicator "
                                        "(not proof) of XSS/injection. Manual verification required."),
                    remediation="Context-encode output and validate input server-side.",
                    tier=self.tier,
                    evidence={"reflected_params": ", ".join(reflected)[:200]},
                ))
        return out
