"""
js_intel — the JavaScript Intelligence Engine (event-driven front end).

Pipeline:
    HTTP_SERVICE / URL
      → fetch HTML or JS (shared rate limiter / WAF backoff)
      → dedup + cache (per-URL + per-body-hash)
      → recon.jsintel.analyze (inline + external JS, extensible extractors)
      → source-map / websocket / config / route / service / tech / API extraction
      → structured events (URL / ENDPOINT / PARAMETER / TECHNOLOGY / ANOMALY)
      → feed the persistent learning system (KnowledgeBase)

Everything emitted goes through `self.emit → stamp_and_publish → ScopeEngine`,
so JS-controlled strings are scope-gated and sanitized like any other input, and
newly discovered URLs/endpoints re-enter the pipeline. Complements apifinder
(generic URL/API mining) by adding the first-class JS-intel surface: source maps,
WebSocket endpoints, configuration indicators, routes, service names, richer
technology detection, plus a learning-system feed.

Watches:  HTTP_SERVICE, URL
Produces: URL, ENDPOINT, PARAMETER, TECHNOLOGY, ANOMALY
"""

from __future__ import annotations

import hashlib
import os
from urllib.parse import urlparse, urlunparse

from events.types import (
    AnomalyData,
    EndpointData,
    Event,
    EventType,
    ParameterData,
    TechnologyData,
    UrlData,
)
from modules.base import BaseModule
from modules.registry import register
from recon import jsintel, vocabulary

_JS_EXT = {".js", ".mjs", ".cjs"}
_FETCH_EXT = {"", ".js", ".mjs", ".cjs", ".json", ".html", ".htm"}
_TAG_TECH = {
    "graphql": ("GraphQL", "api"),
    "swagger": ("Swagger/OpenAPI", "api-docs"),
    "openapi": ("Swagger/OpenAPI", "api-docs"),
    "api-docs": ("Swagger/OpenAPI", "api-docs"),
}


def _norm_url(url: str) -> str:
    try:
        p = urlparse(url)
        return urlunparse(p._replace(query="", fragment=""))
    except Exception:
        return url


@register
class JsIntelModule(BaseModule):
    name = "js_intel"
    description = "JavaScript Intelligence Engine: endpoints, APIs, source maps, websockets, config & tech from JS/HTML"
    watched_events = ["HTTP_SERVICE", "URL"]
    produced_events = ["URL", "ENDPOINT", "PARAMETER", "TECHNOLOGY", "ANOMALY"]
    flags = ["active", "web", "js-analysis", "api-discovery"]
    # Planner metadata: medium cost, high value (rich structured surface).
    expected_value = 8
    options = {
        "timeout": 20,
        "max_body_kb": 2048,
        "max_emit": 400,        # cap emitted URLs/endpoints per analyzed body
        "follow_script_src": True,   # emit external <script src> URLs to re-enter pipeline
        "flag_source_maps": True,    # emit an ANOMALY for exposed source maps
    }

    def __init__(self, controller, config=None) -> None:
        super().__init__(controller, config)
        self._analyzed_urls: set[str] = set()     # dedup JS *resources* (per URL)
        self._body_hashes: set[str] = set()        # cache: skip identical bodies
        self._tech_seen: set[tuple[str, str]] = set()

    async def setup(self) -> bool:
        return True  # pure Python + httpx lib; no external binary

    # ── event handling ────────────────────────────────────────────────────────

    async def handle_event(self, event: Event) -> None:
        if event.type is EventType.HTTP_SERVICE:
            url = getattr(event.data, "url", None)
            if url:
                await self._analyze_url(url, event, is_html=True)
        elif event.type is EventType.URL:
            url = getattr(event.data, "url", None)
            if url and self._is_fetchable(url, getattr(event.data, "content_type", None)):
                await self._analyze_url(url, event, is_html=self._looks_html(url))

    def _is_fetchable(self, url: str, content_type: str | None) -> bool:
        if content_type:
            return any(k in content_type.lower() for k in ("javascript", "html", "json"))
        path = urlparse(url).path.lower()
        if path in ("", "/"):
            return True
        return os.path.splitext(path)[1] in _FETCH_EXT

    @staticmethod
    def _looks_html(url: str) -> bool:
        ext = os.path.splitext(urlparse(url).path)[1].lower()
        return ext in ("", ".html", ".htm")

    # ── fetch + analyze (with dedup / cache) ───────────────────────────────────

    async def _analyze_url(self, url: str, event: Event, *, is_html: bool) -> None:
        key = _norm_url(url)
        if key in self._analyzed_urls:           # dedup JS resource
            return
        self._analyzed_urls.add(key)

        text = await self._fetch(url)
        if not text:
            return

        digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        if digest in self._body_hashes:          # cache: identical body already analyzed
            self._log.debug("js_intel: %s body already analyzed (cache hit)", url)
            return
        self._body_hashes.add(digest)

        analysis = jsintel.analyze(text, url, is_html=is_html)

        # External <script src> → emit as URLs so they re-enter and get analyzed.
        if is_html and self.opt("follow_script_src"):
            for src in jsintel.script_srcs(text, url):
                await self.emit(EventType.URL, UrlData(url=src, method="GET",
                                found_via="js-intel"), source_event=event)

        await self._emit_analysis(analysis, event)

    async def _fetch(self, url: str) -> str | None:
        try:
            import httpx
        except ImportError:
            self._log.warning("httpx not installed")
            return None
        try:
            async with httpx.AsyncClient(timeout=self.opt("timeout")) as client:
                async with self.guard(f"http:{urlparse(url).hostname or url}"):
                    r = await client.get(url, follow_redirects=True)
                self.inspect_response(r)
                r.raise_for_status()
                if len(r.content) / 1024 > self.opt("max_body_kb"):
                    self._log.debug("js_intel: %s too large — skipping", url)
                    return None
                return r.text
        except Exception as exc:
            self._log.debug("js_intel: fetch failed for %s: %s", url, exc)
            return None

    # ── emission (single chokepoint: self.emit → scope gate) ───────────────────

    async def _emit_analysis(self, a: jsintel.JsAnalysis, event: Event) -> None:
        cap = int(self.opt("max_emit") or 400)
        origin = self._origin(a.source_url)
        primary_tech = a.technologies[0] if a.technologies else None

        # URLs + API endpoints
        for url in a.urls[:cap]:
            await self.emit(EventType.URL, UrlData(url=url, method="GET",
                            found_via="js-intel"), source_event=event)
        for url, tag in a.endpoints[:cap]:
            await self.emit(EventType.ENDPOINT, EndpointData(url=url, method="GET"),
                            source_event=event)
            await self._emit_tech_for_tag(tag, url, event)

        # Routes → resolve against origin → URL + ENDPOINT (structural, not arbitrary)
        for route in a.routes[:cap]:
            u = jsintel.resolve(route, origin) if origin else None
            if u:
                await self.emit(EventType.URL, UrlData(url=u, method="GET",
                                found_via="js-route"), source_event=event)

        # Parameters
        for name in a.params[:cap]:
            await self.emit(EventType.PARAMETER, ParameterData(url=a.source_url,
                            name=name, location="query"), source_event=event)

        # WebSocket endpoints → URL events (found_via records the channel)
        for ws in a.websockets[:cap]:
            await self.emit(EventType.URL, UrlData(url=ws, method="GET",
                            found_via="js-websocket"), source_event=event)

        # Source maps → URL + (optional) ANOMALY for exposed maps
        for smap in a.source_maps[:cap]:
            await self.emit(EventType.URL, UrlData(url=smap, method="GET",
                            found_via="js-sourcemap"), source_event=event)
            if self.opt("flag_source_maps"):
                host = urlparse(smap).hostname or self._host(a.source_url)
                if host:
                    await self.emit(EventType.ANOMALY, AnomalyData(host=host,
                                    description=f"source map referenced: {smap}",
                                    category="exposed-source-map"), source_event=event)

        # Configuration indicators → ANOMALY (informational; names only, no values)
        host = self._host(a.source_url)
        for name, kind in a.config_indicators[:cap]:
            if host:
                await self.emit(EventType.ANOMALY, AnomalyData(host=host,
                                description=f"JS config indicator: {name} ({kind})",
                                category="js-config-indicator"), source_event=event)

        # Technology indicators → TECHNOLOGY
        for tech in a.technologies:
            if host and (host, tech) not in self._tech_seen:
                self._tech_seen.add((host, tech))
                await self.emit(EventType.TECHNOLOGY, TechnologyData(host=host,
                                name=tech, source="js_intel"), source_event=event)

        self._log.info(
            "js_intel: %s → urls=%d endpoints=%d ws=%d maps=%d config=%d tech=%d routes=%d services=%d",
            a.source_url, len(a.urls), len(a.endpoints), len(a.websockets),
            len(a.source_maps), len(a.config_indicators), len(a.technologies),
            len(a.routes), len(a.services),
        )

        await self._feed_learning(a, primary_tech)

    async def _emit_tech_for_tag(self, tag: str, url: str, event: Event) -> None:
        tech = _TAG_TECH.get(tag)
        if not tech:
            return
        host = urlparse(url).hostname or ""
        if host and (host, tech[0]) not in self._tech_seen:
            self._tech_seen.add((host, tech[0]))
            await self.emit(EventType.TECHNOLOGY, TechnologyData(host=host,
                            name=tech[0], category=tech[1], source="js_intel"),
                            source_event=event)

    # ── learning-system feed ────────────────────────────────────────────────────

    async def _feed_learning(self, a: jsintel.JsAnalysis, context: str | None) -> None:
        kb = getattr(self._ctrl, "knowledge_base", None)
        if kb is None:
            return
        cands: list[vocabulary.Candidate] = []
        for url, _tag in a.endpoints:
            cands += vocabulary.extract_from_path(url, context)
        for route in a.routes:
            cands += vocabulary.extract_from_path(route, context)
        for name in a.params:
            cands += vocabulary.extract_from_parameter(name, None, a.source_url, context)
        for svc in a.services:
            cands.append(vocabulary.Candidate(svc, vocabulary.RESOURCE_NAMES, context, a.source_url))
        for ident in a.identifiers:
            cands.append(vocabulary.Candidate(ident, vocabulary.JS_IDENTIFIERS, context, a.source_url))
        for gql in a.graphql:
            cands.append(vocabulary.Candidate(gql, vocabulary.GRAPHQL_NAMES, context, a.source_url))
        for name, _kind in a.config_indicators:
            cands.append(vocabulary.Candidate(name, vocabulary.JS_IDENTIFIERS, context, a.source_url))
        if cands:
            await kb.learn_many(
                cands, scan_domain=self._ctrl.scan_domain,
                source_scan_id=self._ctrl.scan_id,
            )

    # ── helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _origin(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""

    @staticmethod
    def _host(url: str) -> str:
        try:
            return urlparse(url).hostname or ""
        except Exception:
            return ""
