"""
katana — Active web crawling via the katana binary (ProjectDiscovery).

Reactive: fires on HTTP_SERVICE events and crawls the live site in **JSONL mode**
(`recon/katana.py`), which unlocks far more than plain URLs:

  * every crawled endpoint + method        → URL / ENDPOINT
  * XHR requests (`-xhr`)                    → ENDPOINT (real API calls, methods)
  * forms/inputs (`-fx`)                     → ENDPOINT (action) + PARAMETER (inputs)
  * technologies (`-td`)                     → TECHNOLOGY
  * knowledge-base page types (`-kb`)        → crawl classification (login/admin…)
  * known files (`-kf all`)                  → robots.txt / sitemap.xml coverage

Rate control: `-rl` is derived from the scan's shared RateLimiter (single rate
chokepoint), not hard-coded — mirroring ffuf's `-rate`. The whole crawl is one
guarded subprocess; on the overall `timeout` the entire process tree is killed +
reaped (`recon.proc`), so a stopped/timed-out crawl leaves no orphan.

Everything is emitted via `self.emit → stamp_and_publish → ScopeEngine`, so
crawled/JS-controlled URLs are scope-gated and re-enter the pipeline.

Watches:  HTTP_SERVICE
Produces: URL, ENDPOINT, PARAMETER, TECHNOLOGY
Requires: katana on PATH (warn-and-skips otherwise)
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from events.types import (
    EndpointData,
    Event,
    EventType,
    ParameterData,
    TechnologyData,
    UrlData,
)
from modules.base import BaseModule
from modules.registry import register
from recon.katana import build_command, parse_katana_jsonl


@register
class KatanaModule(BaseModule):
    name = "katana"
    description = "Active web crawling via katana binary (ProjectDiscovery, JSONL)"
    watched_events = ["HTTP_SERVICE"]
    produced_events = ["URL", "ENDPOINT", "PARAMETER", "TECHNOLOGY"]
    flags = ["active", "web", "crawl", "slow"]
    # Crawling feeds the whole discovery pipeline; without this the planner
    # (value MEDIUM vs "slow" cost HIGH → score -5) skips it by default.
    expected_value = 8
    deps_binary = ["katana"]
    options = {
        "timeout": 180,              # overall crawl subprocess timeout (s)
        "depth": 5,                  # -d
        "concurrency": 10,           # -c
        "parallelism": 3,            # -p
        "retry": 1,                  # -retry
        "req_timeout": 10,           # -timeout (per request, s)
        "rate_limit": None,          # -rl; None → derive from shared RateLimiter
        "js_crawl": True,            # -jc
        "xhr": True,                 # -xhr
        "form_extraction": True,     # -fx
        "tech_detect": True,         # -td
        "knowledge_base": True,      # -kb
        "known_files": "all",        # -kf (all|robotstxt|sitemapxml|None)
        "ignore_query_params": True, # -iqp
    }

    def _rate(self) -> int | None:
        """-rl value: explicit option, else the scan-wide rate (single rate
        chokepoint), else None (katana default)."""
        opt = self.opt("rate_limit")
        if opt:
            return int(opt)
        rps = getattr(self.rate_limiter, "rate_per_sec", None)
        return int(rps) if rps else None

    async def handle_event(self, event: Event) -> None:
        url = getattr(event.data, "url", None)
        if not url:
            return

        from recon.katana import KatanaError
        try:
            cmd = build_command(
                url,
                depth=int(self.opt("depth")),
                concurrency=int(self.opt("concurrency")),
                parallelism=int(self.opt("parallelism")),
                rate=self._rate(),
                retry=int(self.opt("retry")),
                timeout=int(self.opt("req_timeout")),
                js_crawl=bool(self.opt("js_crawl")),
                xhr=bool(self.opt("xhr")),
                form_extraction=bool(self.opt("form_extraction")),
                tech_detect=bool(self.opt("tech_detect")),
                knowledge_base=bool(self.opt("knowledge_base")),
                known_files=self.opt("known_files") or None,
                ignore_query_params=bool(self.opt("ignore_query_params")),
                proxy=self.proxy_url,
            )
        except KatanaError as exc:
            self._log.warning("katana: refusing to crawl %r: %s", url, exc)
            return

        self._log.info("katana crawling %s (depth=%s)", url, self.opt("depth"))

        from recon.proc import communicate, new_session_kwargs
        async with self.guard(f"katana:{urlparse(url).hostname or url}"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    **new_session_kwargs(),
                )
            except FileNotFoundError:
                self._log.warning("katana binary not found — module disabled")
                return
            try:
                stdout, _ = await communicate(proc, timeout=int(self.opt("timeout")))
            except asyncio.TimeoutError:
                # communicate() already killed the katana process tree + reaped.
                self._log.warning("katana timed out after %ds on %s — tree killed",
                                  self.opt("timeout"), url)
                return

        await self._emit(stdout.decode("utf-8", "replace"), event)

    async def _emit(self, out: str, event: Event) -> None:
        records = parse_katana_jsonl(out)
        urls = endpoints = params = techs = 0
        seen_url: set[str] = set()
        seen_tech: set[tuple[str, str]] = set()

        for r in records:
            host = urlparse(r.url).hostname or ""

            # Every crawled endpoint → URL (re-enters pipeline).
            if r.url not in seen_url:
                seen_url.add(r.url)
                if await self.emit(EventType.URL,
                                   UrlData(url=r.url, method=r.method, found_via="katana"),
                                   source_event=event):
                    urls += 1

            # XHR / non-GET requests are real API endpoints → ENDPOINT.
            if r.tag in ("xhr", "fetch") or r.method not in ("GET", ""):
                if await self.emit(EventType.ENDPOINT,
                                   EndpointData(url=r.url, method=r.method),
                                   source_event=event):
                    endpoints += 1

            # Forms → ENDPOINT (action + method) + PARAMETER (input names).
            for form in r.forms:
                action = form.action or r.url
                if await self.emit(EventType.ENDPOINT,
                                   EndpointData(url=action, method=form.method,
                                                parameters=list(form.parameters)),
                                   source_event=event):
                    endpoints += 1
                for name in form.parameters:
                    if await self.emit(EventType.PARAMETER,
                                       ParameterData(url=action, name=name,
                                                     location="body" if form.method == "POST" else "query"),
                                       source_event=event):
                        params += 1

            # Technologies (-td) → TECHNOLOGY.
            for tech in r.technologies:
                if host and (host, tech) not in seen_tech:
                    seen_tech.add((host, tech))
                    if await self.emit(EventType.TECHNOLOGY,
                                       TechnologyData(host=host, name=tech, source="katana"),
                                       source_event=event):
                        techs += 1

        self._log.info("katana: %d urls, %d endpoints, %d params, %d tech from %s",
                       urls, endpoints, params, techs,
                       getattr(event.data, "url", "?"))
