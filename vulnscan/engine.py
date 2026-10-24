"""
AssessmentEngine — orchestration for the vulnerability assessment layer.

Flow (driven by `modules/web/vulnassess.py`):

  1. During the scan, every relevant recon event is fed to `AssessmentState`
     (pure accumulation — no I/O), grouped per host.
  2. At scan end, `build_contexts()` turns that into one `CheckContext` per host
     (so technology-aware selection sees the COMPLETE fingerprint, not a partial
     mid-scan view — "avoid running every check against every URL").
  3. `assess()` selects applicable checks per host (tier + technology gated),
     does ONE low-impact GET per live service to populate headers/cookies for the
     active header/cookie checks (shared limiter / cache), runs each check in
     isolation (a raised check never breaks the run), then de-duplicates results
     across checks and hosts.

The engine itself performs no emission and owns no scope logic — the module emits
each result through `self.emit` → `stamp_and_publish`, so scope, dedup and
persistence apply unchanged.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

from vulnscan.checks import CheckContext, select_checks
from vulnscan.schema import VulnResult, severity_rank

log = logging.getLogger(__name__)


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


class AssessmentState:
    """Per-host accumulation of recon signals. Pure; no network, no scope logic."""

    def __init__(self) -> None:
        self._tech: dict[str, dict[str, str | None]] = {}
        self._services: dict[str, list[dict]] = {}
        self._urls: dict[str, set[str]] = {}
        self._endpoints: dict[str, set[str]] = {}
        self._params: dict[str, dict[str, set[str]]] = {}
        self._findings: dict[str, list[dict]] = {}

    def _h(self, d, default=""):
        return (d or default)

    def observe(self, event) -> None:
        try:
            self._observe(event)
        except Exception as exc:
            log.debug("assessment state observe failed: %s", exc)

    def _observe(self, event) -> None:
        et = getattr(getattr(event, "type", None), "value", "")
        d = getattr(event, "data", None)
        if d is None:
            return

        if et == "TECHNOLOGY":
            host = (getattr(d, "host", "") or "").lower()
            name = (getattr(d, "name", "") or "").strip().lower()
            if host and name:
                ver = getattr(d, "version", None)
                cur = self._tech.setdefault(host, {})
                # prefer a version if we learn one later
                if name not in cur or (ver and not cur[name]):
                    cur[name] = ver

        elif et == "HTTP_SERVICE":
            url = getattr(d, "url", "") or ""
            host = _host_of(url)
            if not host:
                return
            self._services.setdefault(host, []).append({
                "url": url, "status": getattr(d, "status_code", None),
                "title": getattr(d, "title", None), "server": getattr(d, "server", None),
            })
            for t in getattr(d, "technologies", None) or []:
                nm, _, ver = t.partition(":")
                nm = nm.strip().lower()
                if nm:
                    cur = self._tech.setdefault(host, {})
                    if nm not in cur or (ver and not cur[nm]):
                        cur[nm] = ver or None

        elif et in ("URL", "ENDPOINT"):
            url = getattr(d, "url", "") or ""
            host = _host_of(url)
            if not host:
                return
            self._urls.setdefault(host, set()).add(url)
            if et == "ENDPOINT":
                self._endpoints.setdefault(host, set()).add(url)
            self._collect_params(host, url)

        elif et == "PARAMETER":
            url = getattr(d, "url", "") or ""
            host = _host_of(url)
            name = getattr(d, "name", "") or ""
            if host and name:
                base = url.split("?", 1)[0]
                self._params.setdefault(host, {}).setdefault(base, set()).add(name)

        elif et == "ANOMALY":
            host = (getattr(d, "host", "") or "").lower()
            if host:
                self._findings.setdefault(host, []).append({
                    "host": host, "title": getattr(d, "description", "")[:200],
                    "category": getattr(d, "category", None),
                    "severity": None, "evidence": {},
                    "description": getattr(d, "description", ""),
                    "source": getattr(event, "source_tool", None),
                })

        elif et == "FINDING_CANDIDATE":
            host = (getattr(d, "host", "") or "").lower()
            if host:
                self._findings.setdefault(host, []).append({
                    "host": host, "title": getattr(d, "title", ""),
                    "category": getattr(d, "category", None),
                    "severity": getattr(d, "severity_hint", None),
                    "evidence": getattr(d, "evidence", None) or {},
                    "description": getattr(d, "description", ""),
                    "source": getattr(event, "source_tool", None),
                })

    def _collect_params(self, host: str, url: str) -> None:
        q = urlparse(url).query
        if not q:
            return
        base = url.split("?", 1)[0]
        bucket = self._params.setdefault(host, {}).setdefault(base, set())
        for pair in q.split("&"):
            name = pair.split("=", 1)[0].strip()
            if name and len(name) <= 128:
                bucket.add(name)

    @property
    def hosts(self) -> set[str]:
        return (set(self._tech) | set(self._services) | set(self._urls)
                | set(self._endpoints) | set(self._params) | set(self._findings))

    def build_contexts(self, *, fetch=None, active: bool, intrusive: bool) -> dict[str, CheckContext]:
        contexts: dict[str, CheckContext] = {}
        for host in self.hosts:
            ctx = CheckContext(host, fetch=fetch, active_enabled=active,
                               intrusive_enabled=intrusive)
            ctx.technologies = dict(self._tech.get(host, {}))
            ctx.services = list(self._services.get(host, []))
            ctx.urls = set(self._urls.get(host, set()))
            ctx.endpoints = set(self._endpoints.get(host, set()))
            ctx.params = {k: set(v) for k, v in self._params.get(host, {}).items()}
            ctx.existing_findings = list(self._findings.get(host, []))
            contexts[host] = ctx
        return contexts


@dataclass
class AssessmentOutcome:
    results: list[VulnResult] = field(default_factory=list)
    executed: set[str] = field(default_factory=set)        # check ids that ran at least once
    skipped: dict[str, str] = field(default_factory=dict)  # check id -> last reason
    failed: dict[str, str] = field(default_factory=dict)   # check id -> error

    @property
    def emitted(self) -> list[VulnResult]:
        return [r for r in self.results if r.emit]


class AssessmentEngine:
    def __init__(self, *, active: bool = True, intrusive: bool = False) -> None:
        self._active = active
        self._intrusive = intrusive

    async def assess(self, contexts: dict[str, CheckContext]) -> AssessmentOutcome:
        outcome = AssessmentOutcome()
        raw: list[VulnResult] = []
        for host, ctx in contexts.items():
            selected, skipped = select_checks(ctx, active=self._active, intrusive=self._intrusive)
            for cid, reason in skipped:
                outcome.skipped.setdefault(cid, reason)
            if self._active and any(c.tier == "active" for c in selected):
                await self._prefetch_services(ctx)
            for chk in selected:
                try:
                    results = await chk.run(ctx)
                except Exception as exc:
                    outcome.failed[chk.id] = str(exc)
                    log.debug("vulnscan: check %s failed on %s: %s", chk.id, host, exc)
                    continue
                outcome.executed.add(chk.id)
                raw.extend(results or [])
        outcome.results = self._dedup(raw)
        # a check that failed somewhere but produced nothing shouldn't count executed
        return outcome

    async def _prefetch_services(self, ctx: CheckContext) -> None:
        """One low-impact GET per live service to feed header/cookie checks."""
        if ctx.fetch is None:
            return
        for url in ctx.live_urls():
            if url in ctx.headers:
                continue
            try:
                res = await ctx.fetch(url)
            except Exception:
                continue
            if not getattr(res, "ok", False):
                continue
            hdrs = {str(k).lower(): v for k, v in (getattr(res, "headers", {}) or {}).items()}
            ctx.headers[url] = hdrs
            ctx.status[url] = getattr(res, "status_code", None)
            ctx.bodies[url] = getattr(res, "text", None) or ""
            # Prefer the per-cookie list: the merged header value lets one
            # hardened cookie's flags hide another cookie that lacks them.
            cookies = list(getattr(res, "set_cookies", None) or ())
            if not cookies:
                sc = hdrs.get("set-cookie")
                cookies = [sc] if sc else []
            ctx.set_cookies[url] = cookies

    @staticmethod
    def _dedup(results: list[VulnResult]) -> list[VulnResult]:
        """Collapse by (asset, check, url); keep the strongest (severity, confidence)."""
        best: dict[str, VulnResult] = {}
        for r in results:
            cur = best.get(r.dedup_key)
            if cur is None:
                best[r.dedup_key] = r
                continue
            if (severity_rank(r.severity), r.confidence) > (severity_rank(cur.severity), cur.confidence):
                best[r.dedup_key] = r
        # stable order: severity desc, confidence desc, asset
        return sorted(best.values(),
                      key=lambda r: (-severity_rank(r.severity), -r.confidence, r.asset, r.check_id))
