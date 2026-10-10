"""
extfuzz — intelligent extension fuzzing (pure Python, no binary).

Ordinary directory fuzzing (ffuf) discovers *paths*. This module discovers the
files that sit *beside* paths recon-ai already knows: `/js/app.js` →
`/js/app.js.map`, `/js/app.js.bak`; `/download.php` → `/download.bak`,
`/download.old`; `/api/config.json` left in place. These are the files that leak
source maps, credentials, database dumps and backups, and a plain wordlist
fuzzer never reaches them because they aren't dictionary words.

Reactive. Watches:
  URL / ENDPOINT  — the seed paths from crawl / content-discovery / JS / history
  HTTP_SERVICE    — a live service (its own path + a baseline anchor)
  TECHNOLOGY      — per-host tech, used to prioritize extensions (php/aspx/jsp…)

For each in-scope seed path it:
  1. generates extension candidates (append / replace / extensionless), with the
     extension list prioritized by the host's technologies, augmented by any
     AI-proposed extensions (validated deterministically), and de-duplicated;
  2. learns the origin's catch-all baseline (random-path probes) so soft-404s
     are recognised;
  3. fetches each candidate through the shared rate limiter / WAF backoff /
     response cache (`BaseModule.fetch`) and classifies the response
     (`recon.extfuzz.classify`) — a bare 200 is NEVER called a file;
  4. emits a scope-gated `URL` for real/ambiguous/protected hits (re-entering the
     pipeline for secretfinder / jsintel / apifinder), and a
     `FINDING_CANDIDATE` for genuinely interesting confirmed files (backups,
     source maps, configs, archives, dumps, logs) with evidence + confidence —
     never claiming sensitive exposure, only a lead to verify.

Every emission goes through `self.emit → controller.stamp_and_publish →
ScopeEngine`, so candidates are scope-checked and dedup'd exactly like every
other event. All network I/O goes through the shared limiter; candidates only
ever target the same (already in-scope) host as their seed.

Watches:  URL, ENDPOINT, HTTP_SERVICE, TECHNOLOGY
Produces: URL, FINDING_CANDIDATE
"""

from __future__ import annotations

from urllib.parse import urlparse

from events.types import Event, EventType, FindingCandidateData, UrlData
from modules.base import BaseModule
from modules.registry import register
from recon.extfuzz import (
    V_AMBIGUOUS,
    V_AUTH,
    V_FILE,
    V_REDIRECT,
    Baseline,
    build_baseline,
    classify,
    generate_candidates,
    interesting_category,
    normalize_extensions,
    normalize_strategies,
    severity_for,
    tech_extensions,
)
from recon.ffuf import generate_random_string

_FOUND_VIA = "extension-fuzz"


@register
class ExtensionFuzzerModule(BaseModule):
    name = "extfuzz"
    description = "Intelligent extension fuzzing — finds backups, source maps, configs, dumps beside known paths"
    watched_events = ["URL", "ENDPOINT", "HTTP_SERVICE", "TECHNOLOGY"]
    produced_events = ["URL", "FINDING_CANDIDATE"]
    flags = ["active", "web", "content-discovery", "slow"]
    estimated_cost = 7          # active per-candidate GETs (COST_HIGH-ish)
    expected_value = 8          # high — the files ordinary fuzzing misses
    options = {
        # Base extension list (configurable). Technology-aware extensions are
        # prepended per host; AI-proposed extensions are appended (both validated).
        "extensions": "js,json,xml,txt,pdf,bak,old,zip,yaml,yml,conf,config,log,sql,map",
        "strategies": "append,replace,extensionless",
        "tech_aware": True,             # prioritize extensions by host technologies
        "use_learned": True,            # seed extra origin paths from the KB (prior scans)
        "ai_extensions": "",            # AI-proposed extensions — validated, then executed
        "calibration_probes": 2,        # random paths to learn the catch-all baseline
        "max_extensions": 40,           # cap the per-host extension list
        "max_candidates_per_path": 60,
        "max_candidates_per_host": 1500,
        "max_candidates_total": 6000,
        "max_learned_paths": 50,        # KB-seeded origin stems per host
        "timeout": 15,
        "max_body_kb": 1024,
        "follow_redirects": False,      # we want to SEE redirects, not chase them
        "emit_min_confidence": 0.4,     # emit URL at/above this confidence
        "finding_min_confidence": 0.6,  # emit FINDING_CANDIDATE at/above this (confirmed only)
    }

    def __init__(self, controller, config=None) -> None:
        super().__init__(controller, config)
        self._host_tech: dict[str, set[str]] = {}
        self._baselines: dict[str, Baseline | None] = {}
        self._tested: set[str] = set()
        self._seen_seed: set[str] = set()
        self._learned_seeded: set[str] = set()
        self._host_count: dict[str, int] = {}
        self._total = 0
        self._emitted_urls = 0
        self._findings = 0

    async def setup(self) -> bool:
        return True  # pure Python, no binary needed

    # ── extension selection (adaptive) ──────────────────────────────────────
    def _extensions_for(self, host: str) -> list[str]:
        """The per-host extension list: technology-aware first, then base, then
        AI-proposed — all passed through deterministic validation/dedup."""
        parts: list[str] = []
        if self.opt("tech_aware"):
            parts.extend(tech_extensions(self._host_tech.get(host, set())))
        base = self.opt("extensions")
        parts.extend(base.split(",") if isinstance(base, str) else list(base or []))
        ai = self.opt("ai_extensions")
        if ai:
            parts.extend(ai.split(",") if isinstance(ai, str) else list(ai))
        return normalize_extensions(parts, max_count=int(self.opt("max_extensions")))

    def _strategies(self) -> list[str]:
        return normalize_strategies(self.opt("strategies"))

    # ── event handling ──────────────────────────────────────────────────────
    async def handle_event(self, event: Event) -> None:
        if event.type is EventType.TECHNOLOGY:
            self._record_tech(getattr(event.data, "host", None), getattr(event.data, "name", None))
            return

        url = getattr(event.data, "url", None)
        if not url:
            return

        if event.type is EventType.HTTP_SERVICE:
            # Capture technologies the prober already attached to the service.
            host = urlparse(url).hostname or ""
            for tech in getattr(event.data, "technologies", None) or []:
                self._record_tech(host, tech.split(":", 1)[0] if ":" in tech else tech)
            if self.opt("use_learned"):
                await self._seed_from_learned(url, event)

        # Don't cascade on our own discoveries (bounded anyway by dedup/planner).
        if getattr(event.data, "found_via", None) == _FOUND_VIA:
            return

        await self._fuzz_from(url, event)

    def _record_tech(self, host: str | None, name: str | None) -> None:
        if host and name:
            self._host_tech.setdefault(host, set()).add(str(name).strip().lower())

    # ── fuzzing ───────────────────────────────────────────────────────────────
    async def _fuzz_from(self, url: str, event: Event) -> None:
        p = urlparse(url)
        host = p.hostname or ""
        if not host:
            return
        seed_key = f"{p.scheme}://{p.netloc}{p.path}"
        if seed_key in self._seen_seed:
            return
        self._seen_seed.add(seed_key)

        exts = self._extensions_for(host)
        if not exts:
            return
        candidates = generate_candidates(
            url, exts, self._strategies(),
            max_per_path=int(self.opt("max_candidates_per_path")),
        )
        await self._test_all(candidates, host, event)

    async def _seed_from_learned(self, service_url: str, event: Event) -> None:
        """Augment with origin-rooted stems learned from prior scans (the KB).

        Deterministic, bounded, and fully optional: without a `--db-url` there is
        no KnowledgeBase and this is a no-op. KB values are *candidates*, never
        assertions — each is still fetched and classified like any other.
        """
        p = urlparse(service_url)
        origin = f"{p.scheme}://{p.netloc}"
        if origin in self._learned_seeded:
            return
        self._learned_seeded.add(origin)
        kb = getattr(self._ctrl, "knowledge_base", None)
        if kb is None:
            return
        try:
            from recon.vocabulary import FILES, SCOPE_TARGET
            words = await kb.generate_wordlist(
                FILES,
                scope_type=SCOPE_TARGET,
                scope_key=(getattr(self._ctrl, "scan_domain", "") or "").lower(),
                min_confidence=0.5,
                limit=int(self.opt("max_learned_paths")),
            )
        except Exception as exc:  # KB optional / mock controller — never fatal
            self._log.debug("extfuzz: learned-seed skipped: %s", exc)
            return
        exts = self._extensions_for(p.hostname or "")
        strategies = self._strategies()
        for w in words or []:
            stem = str(w).strip().strip("/")
            if not stem or "/" in stem:
                continue
            seed = f"{origin}/{stem}"
            candidates = generate_candidates(
                seed, exts, strategies,
                max_per_path=int(self.opt("max_candidates_per_path")),
            )
            await self._test_all(candidates, p.hostname or "", event)

    async def _test_all(self, candidates: list[str], host: str, event: Event) -> None:
        per_host_cap = int(self.opt("max_candidates_per_host"))
        total_cap = int(self.opt("max_candidates_total"))
        for cand in candidates:
            if self._total >= total_cap:
                return
            if self._host_count.get(host, 0) >= per_host_cap:
                return
            if cand in self._tested:
                continue
            self._tested.add(cand)
            self._host_count[host] = self._host_count.get(host, 0) + 1
            self._total += 1
            await self._test(cand, event)

    async def _test(self, cand: str, event: Event) -> None:
        p = urlparse(cand)
        origin = f"{p.scheme}://{p.netloc}"
        baseline = await self._baseline_for(origin)

        res = await self.fetch(
            cand,
            timeout=int(self.opt("timeout")),
            max_body_kb=int(self.opt("max_body_kb")),
            follow_redirects=bool(self.opt("follow_redirects")),
        )
        if not res.ok:
            return

        ext = _ext_of(cand)
        redirect = None
        if res.headers:
            redirect = res.headers.get("location") or res.headers.get("Location")
        c = classify(
            ext=ext,
            status=res.status_code,
            body=res.text,
            content_type=res.content_type,
            redirect=redirect,
            baseline=baseline,
        )

        if c.confidence < float(self.opt("emit_min_confidence")):
            return
        if c.verdict not in (V_FILE, V_AMBIGUOUS, V_AUTH, V_REDIRECT):
            return

        emitted = await self.emit(
            EventType.URL,
            UrlData(
                url=cand,
                method="GET",
                status_code=res.status_code,
                content_type=res.content_type,
                found_via=_FOUND_VIA,
            ),
            source_event=event,
        )
        if emitted:
            self._emitted_urls += 1

        # Only a CONFIRMED (corroborated) interesting file becomes a finding.
        if (
            c.verdict == V_FILE
            and c.category is not None
            and c.confidence >= float(self.opt("finding_min_confidence"))
        ):
            await self._emit_finding(cand, ext, c, event)

    async def _emit_finding(self, url: str, ext: str, c, event: Event) -> None:
        host = urlparse(url).hostname or url
        category = c.category
        label = {
            "backup": "Backup / source file",
            "archive": "Exposed archive",
            "database-dump": "Database dump / backup",
            "config": "Configuration file",
            "source-map": "JavaScript source map",
            "log-file": "Log file",
        }.get(category, "Interesting file")
        severity = severity_for(category)
        ok = await self.emit(
            EventType.FINDING_CANDIDATE,
            FindingCandidateData(
                host=host,
                # URL in the title keeps distinct files on one host from
                # collapsing under the host:title:category finding dedup key.
                title=f"{label}: {url}",
                description=(
                    f"A publicly reachable {category} was discovered by extension "
                    f"fuzzing at {url} (HTTP {c.status}, {c.content_type or 'unknown type'}, "
                    f"{c.length if c.length is not None else '?'} bytes; {c.reason}). "
                    f"Confidence {c.confidence:.2f}. This is a candidate only — review "
                    f"the content to confirm whether it exposes sensitive data; do not "
                    f"assume exposure without verification."
                ),
                category=f"exposed-file:{category}",
                severity_hint=severity,
                evidence={
                    "url": url[:512],
                    "extension": ext,
                    "category": category,
                    "http_status": c.status,
                    "content_type": (c.content_type or "")[:128],
                    "content_length": c.length,
                    "confidence": round(c.confidence, 3),
                    "detection": c.reason,
                    "found_via": _FOUND_VIA,
                },
            ),
            source_event=event,
        )
        if ok:
            self._findings += 1
            self._log.warning("extfuzz: [%s] %s (%s)", severity.upper(), label, url)
            await self._learn_file(url)

    async def _learn_file(self, url: str) -> None:
        """Feed a confirmed file's stem back into the cross-scan learning system.

        Fully optional and never fatal (no KB / mock controller → swallowed).
        """
        kb = getattr(self._ctrl, "knowledge_base", None)
        if kb is None:
            return
        try:
            from recon.vocabulary import FILES, Candidate
            filename = urlparse(url).path.rsplit("/", 1)[-1]
            if not filename:
                return
            await kb.learn_many(
                [Candidate(value=filename, category=FILES, source_url=url)],
                scan_domain=getattr(self._ctrl, "scan_domain", None),
                source_scan_id=getattr(self._ctrl, "scan_id", None),
            )
        except Exception as exc:
            self._log.debug("extfuzz: KB learn skipped: %s", exc)

    async def _baseline_for(self, origin: str) -> Baseline | None:
        """Learn (and cache) the origin's catch-all baseline via random probes."""
        if origin in self._baselines:
            return self._baselines[origin]
        n = max(1, int(self.opt("calibration_probes")))
        probes: list[tuple[int | None, str | None]] = []
        for _ in range(n):
            rnd = f"{origin}/{generate_random_string()}-extfuzz-probe"
            res = await self.fetch(
                rnd,
                timeout=int(self.opt("timeout")),
                max_body_kb=int(self.opt("max_body_kb")),
                follow_redirects=bool(self.opt("follow_redirects")),
            )
            probes.append((res.status_code if res.ok else None, res.text if res.ok else None))
        baseline = build_baseline(probes)
        self._baselines[origin] = baseline
        return baseline

    async def finish(self) -> None:
        if self._total:
            self._log.info(
                "extfuzz: tested %d candidate(s) → %d URL(s), %d finding(s)",
                self._total, self._emitted_urls, self._findings,
            )


def _ext_of(url: str) -> str:
    filename = urlparse(url).path.rsplit("/", 1)[-1]
    dot = filename.rfind(".")
    return filename[dot + 1 :].lower() if dot > 0 else ""
