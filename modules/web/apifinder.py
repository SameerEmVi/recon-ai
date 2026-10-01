"""
apifinder — JavaScript & API endpoint discovery (pure Python, no binary).

Improvement #3: application-layer attack-surface expansion. Consumes the
HTTP_SERVICE and URL events the existing pipeline already discovers, fetches the
JavaScript / HTML / JSON bodies through the shared rate limiter, and extracts —
deterministically, with regex, never the LLM — the additional surface:

  - JavaScript-referenced URLs (absolute, protocol-relative, root-relative,
    and path-relative, all resolved against the source URL)
  - API paths and versioned API paths (/api/, /api/v1/, /api/v2/, …)
  - GraphQL endpoints
  - OpenAPI / Swagger locations and common API-doc endpoints
  - request parameters (query string on discovered URLs)

Everything is converted into EXISTING event types and pushed through the normal
chokepoint (`self.emit` → `controller.stamp_and_publish` → ScopeEngine → bus):

  URL         — every discovered URL (found_via records the discovery method)
  ENDPOINT    — URLs classified as API/GraphQL/Swagger/OpenAPI/api-docs
  PARAMETER   — each query-string parameter (location="query")
  TECHNOLOGY  — GraphQL / Swagger-OpenAPI presence, keyed on the host

Because emission goes through `self.emit`, newly discovered URLs are scope-checked
by the same ScopeEngine as everything else (out-of-scope hosts are dropped by the
bus) and dedup'd by the EventBus. Target-controlled strings are sanitized/capped
by the Pydantic validators in events/types.py at construction — a JS-controlled
string can neither bypass validation nor bypass scope. Discovered URLs/endpoints
re-enter the pipeline so linkfinder / paramfinder / secretfinder / httpx_probe
react to them.

The well-known API/doc path list is configuration (options["well_known_paths"]),
not a hard-coded sole mechanism — JS/HTML extraction is the primary source.

Watches:  HTTP_SERVICE, URL
Produces: URL, ENDPOINT, PARAMETER, TECHNOLOGY
"""

from __future__ import annotations

import os
import re
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

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

# ── extraction patterns ───────────────────────────────────────────────────────

# A quoted reference that looks like a URL or a path. Two alternatives:
#   1. absolute / protocol-relative / root-relative  (starts with http(s):// // /)
#   2. path-relative multi-segment                    (foo/bar/baz)
# Bounded quantifiers throughout — no catastrophic backtracking.
_ABS_OR_ROOT = r"(?:https?://|//|/)[^\"'`\s<>{}|\\^]{1,512}"
_REL_MULTISEG = (
    r"[a-zA-Z0-9_\-]{1,64}"
    r"(?:/[A-Za-z0-9_.\-~%:@!$&'()*+,;=?#\[\]]{1,120}){1,12}"
)
_REF_RE = re.compile(r"[\"'`](" + _ABS_OR_ROOT + r"|" + _REL_MULTISEG + r")[\"'`]")

# Static assets we never treat as endpoints (checked on the resolved path).
_SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".scss", ".less", ".map",
    ".mp4", ".webm", ".mp3", ".pdf", ".zip", ".gz",
}

# A bare "type/subtype" string (e.g. "text/html", "application/json") is almost
# always a MIME type, not a relative path — drop it.
_MIME_RE = re.compile(r"^[a-z]+/[a-z0-9.+\-]+$")

# Fetchable content types / extensions.
_FETCH_EXT = {"", ".js", ".mjs", ".json", ".html", ".htm"}


# Statuses that positively confirm a well-known path is NOT there.
_ABSENT_STATUSES = frozenset({404, 410})

# Statuses that neither confirm nor deny existence — a WAF/CDN block, a rate
# limit, or an origin-unreachable edge error. A Cloudflare-fronted host answers
# these (not 404) to *every* path, so treating them as "something is here"
# fabricated phantom swagger/openapi endpoints. They confirm nothing → dropped.
# (Cloudflare 520-527 = origin errors; 429/503 = throttle/unavailable.)
_INCONCLUSIVE_STATUSES = frozenset(
    {429, 503, 520, 521, 522, 523, 524, 525, 526, 527}
)

# API-doc classifications whose *value* is a readable spec: we require the body
# to actually look like one before emitting, so a soft-404 / SPA index page
# served at /openapi.json is not reported as an OpenAPI doc.
_DOC_TAGS = frozenset({"swagger", "openapi", "api-docs"})


class _Baseline:
    """A host's learned catch-all response (status + body size).

    A CDN/WAF/SPA origin returns a uniform response to *any* path — the same
    status, and usually the same body (a block page or the SPA index). A
    well-known path whose response is indistinguishable from that baseline is
    noise, not a discovered endpoint, and is dropped.
    """

    __slots__ = ("status", "size")

    def __init__(self, status: int, size: int) -> None:
        self.status = status
        self.size = size

    def matches(self, status: int | None, text: str | None) -> bool:
        if status != self.status:
            return False
        size = len(text or "")
        return abs(size - self.size) <= max(64, int(self.size * 0.05))


def _looks_like_api_doc(text: str | None, url: str) -> bool:
    """True if `text` plausibly IS an OpenAPI/Swagger spec or Swagger-UI page.

    Deterministic, body-only. A 200 that returns the site's HTML shell (SPA
    catch-all) or a generic error page does not qualify.
    """
    if not text:
        return False
    sample = text[:8192].lower()
    if "swagger" in sample or "openapi" in sample or "redoc" in sample:
        return True
    # A JSON spec that omits the literal words but has the OpenAPI paths map.
    if sample.lstrip().startswith(("{", "[")) and '"paths"' in sample:
        return True
    return False


def _origin(url: str) -> str:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}"


def _is_candidate(ref: str) -> bool:
    """Cheap pre-filter before the (more expensive) resolve step."""
    ref = ref.strip()
    if not ref or " " in ref or "\t" in ref:
        return False
    if ref.startswith(("http://", "https://", "//", "/")):
        return True
    # relative multi-segment — reject obvious MIME types.
    if _MIME_RE.match(ref):
        return False
    return True


def resolve_ref(ref: str, base_url: str) -> str | None:
    """Resolve a raw reference against base_url into an absolute http(s) URL.

    Returns None for non-http(s), hostless, or unparseable references. The
    fragment is stripped; the query string is preserved (parameters live there).
    """
    ref = ref.strip()
    if not ref:
        return None
    # Protocol-relative → borrow the base scheme.
    if ref.startswith("//"):
        ref = (urlparse(base_url).scheme or "https") + ":" + ref
    try:
        resolved = urljoin(base_url, ref)
        p = urlparse(resolved)
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    return urlunparse(p._replace(fragment=""))


def _has_skip_ext(url: str) -> bool:
    ext = os.path.splitext(urlparse(url).path)[1].lower()
    return ext in _SKIP_EXT


def classify_api_url(url: str) -> str | None:
    """Classify a URL by API surface. Returns a tag or None.

    Tags: graphql | swagger | openapi | api-docs | api-version | api
    """
    path = urlparse(url).path.lower()
    if "graphql" in path or path.endswith("/graphiql"):
        return "graphql"
    if "swagger" in path:
        return "swagger"
    if "openapi" in path:
        return "openapi"
    if "api-docs" in path:
        return "api-docs"
    if re.search(r"/api/v\d+", path) or re.search(r"/v\d+/api", path):
        return "api-version"
    if path == "/api" or path.startswith("/api/") or "/api/" in path:
        return "api"
    return None


def _tech_for_tag(tag: str) -> tuple[str, str] | None:
    if tag == "graphql":
        return ("GraphQL", "api")
    if tag in ("swagger", "openapi", "api-docs"):
        return ("Swagger/OpenAPI", "api-docs")
    return None


def params_from_url(url: str) -> list[tuple[str, str]]:
    """Return (name, value) query-string parameters for a URL."""
    q = urlparse(url).query
    if not q:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, value in parse_qsl(q, keep_blank_values=True):
        name = name.strip()
        if not name or len(name) > 128 or name in seen:
            continue
        seen.add(name)
        out.append((name, value))
    return out


def discover(content: str, base_url: str, max_urls: int = 500) -> list[str]:
    """Extract and resolve all URL references from content (JS/HTML/JSON text).

    Pure and deterministic. Returns a de-duplicated, order-stable list of
    absolute http(s) URLs. Never raises on malformed input.
    """
    if not content or not base_url:
        return []
    urls: list[str] = []
    seen: set[str] = set()
    for m in _REF_RE.finditer(content):
        raw = m.group(1)
        if not _is_candidate(raw):
            continue
        resolved = resolve_ref(raw, base_url)
        if not resolved or _has_skip_ext(resolved):
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        urls.append(resolved)
        if len(urls) >= max_urls:
            break
    return urls


def _is_fetchable(url: str, content_type: str | None) -> bool:
    """True if this URL likely points to JS/HTML/JSON worth parsing."""
    if content_type:
        c = content_type.lower()
        return any(k in c for k in ("javascript", "html", "json"))
    path = urlparse(url).path.lower()
    if path in ("", "/"):
        return True
    return os.path.splitext(path)[1] in _FETCH_EXT


# ── module ─────────────────────────────────────────────────────────────────────

@register
class ApiFinderModule(BaseModule):
    name = "apifinder"
    description = "JavaScript & API endpoint discovery from web responses (no binary)"
    watched_events = ["HTTP_SERVICE", "URL"]
    produced_events = ["URL", "ENDPOINT", "PARAMETER", "TECHNOLOGY"]
    flags = ["active", "web", "js-analysis", "api-discovery", "fast"]
    options = {
        "timeout": 20,
        "max_body_kb": 1024,
        "max_urls": 500,
        # Emit configured well-known API/doc paths for each live HTTP service.
        # Config, not the sole mechanism — JS/HTML extraction is primary.
        "probe_well_known": True,
        # Verify each well-known path resolves to a real, distinct resource
        # before emitting it: drops 404/unreachable, WAF/CDN inconclusive
        # statuses, catch-all/soft-404 responses, and doc paths whose body is
        # not actually a spec. Off = the old blind behaviour (every path
        # emitted as a candidate, which fabricated N_paths × N_hosts phantoms).
        "verify_well_known": True,
        "well_known_paths": [
            "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
            "/graphql", "/graphiql", "/graphql/schema",
            "/swagger.json", "/swagger/v1/swagger.json", "/swagger-ui.html",
            "/openapi.json", "/.well-known/openapi.json",
            "/api-docs", "/v2/api-docs", "/v3/api-docs",
        ],
    }

    def __init__(self, controller, config=None) -> None:
        super().__init__(controller, config)
        # De-dup TECHNOLOGY emission per (host, tech) across events; the bus
        # dedups too, this just avoids the extra round-trips.
        self._tech_seen: set[tuple[str, str]] = set()

    async def setup(self) -> bool:
        return True  # pure Python, no binary needed

    async def handle_event(self, event: Event) -> None:
        if event.type is EventType.HTTP_SERVICE:
            base = getattr(event.data, "url", None)
            if not base:
                return
            # 1. Configured well-known API/doc candidates for this live service.
            if self.opt("probe_well_known"):
                origin = _origin(base)
                if origin:
                    # Learn the host's catch-all baseline first so a CDN/WAF/SPA
                    # that answers uniformly to every path can't fabricate
                    # endpoints (see _learn_catch_all / _Baseline).
                    baseline = (
                        await self._learn_catch_all(origin)
                        if self.opt("verify_well_known")
                        else None
                    )
                    for path in self.opt("well_known_paths") or []:
                        await self._probe_well_known(origin + path, event, baseline)
            # 2. Fetch the service's own HTML and extract references from it.
            await self._fetch_and_extract(base, event)

        elif event.type is EventType.URL:
            url = getattr(event.data, "url", None)
            if not url:
                return
            if not _is_fetchable(url, getattr(event.data, "content_type", None)):
                return
            await self._fetch_and_extract(url, event)

    # ── fetch + extract ────────────────────────────────────────────────────────

    async def _fetch_and_extract(self, url: str, event: Event) -> None:
        text = await self._fetch(url)
        if text:
            await self._process_text(text, url, event)

    async def _learn_catch_all(self, origin: str) -> _Baseline | None:
        """Probe two random non-existent paths to learn a host's catch-all.

        A well-behaved host 404s a random path (→ no baseline). A CDN/WAF/SPA
        answers uniformly (same 200 index / 403 block / 503) to everything; we
        capture that (status + body size) so identical well-known responses are
        recognised as noise. Returns None when no stable catch-all is seen.
        """
        import secrets

        samples: list[tuple[int, int]] = []
        for _ in range(2):
            rnd = f"{origin}/{secrets.token_hex(10)}-nonexistent-probe"
            status, text = await self._probe(rnd)
            if status is None or status in _ABSENT_STATUSES:
                return None  # a real 404 / unreachable → no catch-all problem
            samples.append((status, len(text or "")))
        (s0, l0), (s1, l1) = samples
        if s0 == s1 and abs(l0 - l1) <= max(64, int(l0 * 0.05)):
            return _Baseline(s0, (l0 + l1) // 2)
        return None

    async def _probe_well_known(
        self, url: str, event: Event, baseline: _Baseline | None
    ) -> None:
        """Confirm a well-known API/doc path exists before emitting it.

        Blindly emitting the configured path list turned every entry into a
        phantom endpoint on every host. We GET each path and emit only those
        that genuinely resolve to a distinct, real resource:

          - a 404/410 or unreachable host is dropped;
          - a WAF/CDN inconclusive status (429/503/520-527) confirms nothing;
          - a response indistinguishable from the host's catch-all baseline
            (CDN block page / SPA index) is dropped;
          - an API-doc path must return a body that actually looks like a spec,
            so a soft-404 HTML shell at /openapi.json is not called OpenAPI.

        A confirmed 2xx doc is additionally mined for real references.
        """
        if not self.opt("verify_well_known"):
            await self._emit_url_and_derived(url, event, "api-discovery")
            return
        status, text = await self._probe(url)
        if status is None or status in _ABSENT_STATUSES:
            return
        if status in _INCONCLUSIVE_STATUSES:
            return
        if baseline is not None and baseline.matches(status, text):
            return
        if classify_api_url(url) in _DOC_TAGS:
            # The value of a doc path is the readable spec — require it.
            if not (200 <= status < 300):
                return
            if text is not None and not _looks_like_api_doc(text, url):
                return
        await self._emit_url_and_derived(url, event, "api-discovery")
        if text:
            await self._process_text(text, url, event)

    async def _probe(self, url: str) -> tuple[int | None, str | None]:
        """GET `url` through the shared limiter; return (status_code, body|None).

        Body is returned only for a size-capped 2xx response. Returns
        (None, None) on any transport failure. Never raises.
        """
        try:
            import httpx
        except ImportError:
            self._log.warning("httpx not installed")
            return None, None
        try:
            async with httpx.AsyncClient(timeout=self.opt("timeout")) as client:
                async with self.guard(f"http:{urlparse(url).hostname or url}"):
                    r = await client.get(url, follow_redirects=True)
                self.inspect_response(r)
                text = None
                if 200 <= r.status_code < 300 and len(r.content) / 1024 <= self.opt("max_body_kb"):
                    text = r.text
                return r.status_code, text
        except Exception as exc:
            self._log.debug("apifinder: probe failed for %s: %s", url, exc)
            return None, None

    async def _fetch(self, url: str) -> str | None:
        """Fetch a body through the shared rate limiter / WAF backoff."""
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
                    self._log.debug("apifinder: %s too large — skipping", url)
                    return None
                return r.text
        except Exception as exc:
            self._log.debug("apifinder: fetch failed for %s: %s", url, exc)
            return None

    async def _process_text(self, text: str, base_url: str, event: Event) -> None:
        """Extract references from a body and emit them. No network I/O."""
        count = 0
        for url in discover(text, base_url, max_urls=self.opt("max_urls")):
            if await self._emit_url_and_derived(url, event, "js-analysis"):
                count += 1
        if count:
            self._log.info("apifinder: %d in-scope URLs from %s", count, base_url)

    # ── emission (single chokepoint: self.emit → scope gate) ───────────────────

    async def _emit_url_and_derived(
        self, url: str, event: Event, found_via: str
    ) -> bool:
        """Emit a discovered URL plus any ENDPOINT / PARAMETER / TECHNOLOGY it
        implies. Every emit goes through the scope engine; returns True if the
        URL itself was accepted (in-scope)."""
        accepted = await self.emit(
            EventType.URL,
            UrlData(url=url, method="GET", found_via=found_via),
            source_event=event,
        )

        params = params_from_url(url)
        tag = classify_api_url(url)

        if tag is not None:
            await self.emit(
                EventType.ENDPOINT,
                EndpointData(
                    url=url, method="GET", parameters=[n for n, _ in params]
                ),
                source_event=event,
            )
            tech = _tech_for_tag(tag)
            if tech is not None:
                host = urlparse(url).hostname or ""
                key = (host, tech[0])
                if host and key not in self._tech_seen:
                    self._tech_seen.add(key)
                    await self.emit(
                        EventType.TECHNOLOGY,
                        TechnologyData(host=host, name=tech[0], category=tech[1]),
                        source_event=event,
                    )

        for name, value in params:
            await self.emit(
                EventType.PARAMETER,
                ParameterData(
                    url=url, name=name, location="query", sample_value=value or None
                ),
                source_event=event,
            )

        return accepted
