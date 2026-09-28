"""
recon.jsintel — the pure core of the JavaScript Intelligence Engine.

Given a JavaScript / HTML / JSON body and its source URL, extract reconnaissance
signal deterministically, with an **extensible extractor architecture**: each
concern is a small `Extractor` that appends typed results to a shared
`JsAnalysis`. Adding a new signal (or swapping a regex extractor for an
AST-based one) is a matter of writing one `Extractor` and registering it — the
engine, the module and the tests stay unchanged.

Signals covered here (complementing modules/web/apifinder, which already mines
generic URLs / API paths / query params):

  * relative API paths + versions        (ApiPathExtractor)
  * absolute URLs                         (UrlExtractor)
  * GraphQL operation / type names        (via recon.vocabulary)
  * WebSocket URLs (ws:// / wss://)        (WebSocketExtractor)
  * source-map references (//# sourceMappingURL, .map)  (SourceMapExtractor)
  * configuration identifiers (apiBaseUrl, __CONFIG__, import.meta.env.X …)
                                          (ConfigIndicatorExtractor)
  * route names (path:"/x", @Get("/x"))    (RouteExtractor)
  * service / client names                (ServiceNameExtractor)
  * technology indicators (webpack/React/Vue/Angular/Next/Nuxt …)
                                          (TechnologyExtractor)
  * JS identifiers                         (via recon.vocabulary)

Design rules
------------
* Pure and deterministic: no network, no LLM, no DB. Never raises on bad input.
* Don't blindly treat arbitrary strings as endpoints — endpoints/paths come only
  from URL-shaped or structurally-declared contexts, then are normalized and
  filtered (static assets / MIME types dropped).
* All values are candidates/observations; nothing here asserts a resource exists.
"""

from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlunparse

from recon import vocabulary

# ── result container ──────────────────────────────────────────────────────────

@dataclass
class JsAnalysis:
    source_url: str
    urls: list[str] = field(default_factory=list)                 # absolute http(s)
    endpoints: list[tuple[str, str]] = field(default_factory=list)  # (url, api-tag)
    params: list[str] = field(default_factory=list)               # query param names
    websockets: list[str] = field(default_factory=list)           # ws:// wss://
    source_maps: list[str] = field(default_factory=list)          # resolved .map URLs
    config_indicators: list[tuple[str, str]] = field(default_factory=list)  # (name, kind)
    technologies: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    identifiers: list[str] = field(default_factory=list)
    graphql: list[str] = field(default_factory=list)

    def add(self, bucket: str, value, *, dedup: set | None = None) -> None:
        seq = getattr(self, bucket)
        if value in seq:
            return
        seq.append(value)


# ── shared helpers ─────────────────────────────────────────────────────────────

_STATIC_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".css", ".scss", ".less",
    ".mp4", ".webm", ".mp3", ".pdf", ".zip", ".gz",
}
_MIME_RE = re.compile(r"^[a-z]+/[a-z0-9.+\-]+$")


def resolve(ref: str, base_url: str) -> str | None:
    """Resolve a reference against base_url into an absolute http(s) URL (no
    fragment). Returns None for non-http(s)/hostless/unparseable refs."""
    ref = (ref or "").strip()
    if not ref:
        return None
    if ref.startswith("//"):
        ref = (urlparse(base_url).scheme or "https") + ":" + ref
    try:
        p = urlparse(urljoin(base_url, ref))
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    return urlunparse(p._replace(fragment=""))


def _has_static_ext(url: str) -> bool:
    return os.path.splitext(urlparse(url).path)[1].lower() in _STATIC_EXT


def classify_api(url: str) -> str | None:
    """Classify a URL's API surface: graphql|swagger|openapi|api-docs|api-version|api."""
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
    if path == "/api" or "/api/" in path:
        return "api"
    return None


# ── extractor architecture ───────────────────────────────────────────────────

class Extractor(ABC):
    """One JS-intelligence concern. Mutate `analysis` in place; never raise."""
    name: str = ""

    @abstractmethod
    def extract(self, content: str, base_url: str, analysis: JsAnalysis) -> None: ...


_QUOTE = r"""["'`]"""


class UrlExtractor(Extractor):
    name = "urls"
    _RE = re.compile(_QUOTE + r"((?:https?://|//)[^\"'`\s<>{}|\\^]{3,512})" + _QUOTE)

    def extract(self, content, base_url, analysis):
        for m in self._RE.finditer(content):
            u = resolve(m.group(1), base_url)
            if u and not _has_static_ext(u):
                analysis.add("urls", u)
                tag = classify_api(u)
                if tag:
                    if (u, tag) not in analysis.endpoints:
                        analysis.endpoints.append((u, tag))


class ApiPathExtractor(Extractor):
    name = "api_paths"
    # Root-relative and multi-segment relative paths (not just full URLs).
    _RE = re.compile(
        _QUOTE
        + r"(/[A-Za-z0-9_][A-Za-z0-9_./\-]{2,200}"
        + r"|[a-zA-Z0-9_\-]{1,64}(?:/[A-Za-z0-9_.\-]{1,64}){1,10})"
        + _QUOTE
    )

    def extract(self, content, base_url, analysis):
        for m in self._RE.finditer(content):
            raw = m.group(1)
            if _MIME_RE.match(raw):
                continue
            u = resolve(raw, base_url)
            if not u or _has_static_ext(u):
                continue
            tag = classify_api(u)
            if tag:                                   # only structural API paths
                analysis.add("urls", u)
                if (u, tag) not in analysis.endpoints:
                    analysis.endpoints.append((u, tag))
        # query params on any discovered URL
        for u in list(analysis.urls):
            q = urlparse(u).query
            if not q:
                continue
            for pair in q.split("&"):
                name = pair.split("=", 1)[0].strip()
                if name and len(name) <= 128:
                    analysis.add("params", name)


class WebSocketExtractor(Extractor):
    name = "websockets"
    _RE = re.compile(_QUOTE + r"(wss?://[^\"'`\s<>{}|\\^]{3,512})" + _QUOTE)
    _CTOR = re.compile(r"new\s+WebSocket\s*\(\s*" + _QUOTE + r"([^\"'`]{3,512})" + _QUOTE)

    def extract(self, content, base_url, analysis):
        for m in self._RE.finditer(content):
            analysis.add("websockets", m.group(1))
        for m in self._CTOR.finditer(content):
            ref = m.group(1)
            if ref.startswith(("ws://", "wss://")):
                analysis.add("websockets", ref)
            elif ref.startswith(("/", "//")):
                # resolve then swap scheme to ws(s)
                u = resolve(ref, base_url)
                if u:
                    analysis.add("websockets", u.replace("https://", "wss://").replace("http://", "ws://"))


class SourceMapExtractor(Extractor):
    name = "source_maps"
    _DIRECTIVE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")
    _QUOTED_MAP = re.compile(_QUOTE + r"([^\"'`\s]{2,300}\.map)" + _QUOTE)

    def extract(self, content, base_url, analysis):
        for m in self._DIRECTIVE.finditer(content):
            u = resolve(m.group(1), base_url) or m.group(1)
            analysis.add("source_maps", u)
        for m in self._QUOTED_MAP.finditer(content):
            u = resolve(m.group(1), base_url)
            if u:
                analysis.add("source_maps", u)


class ConfigIndicatorExtractor(Extractor):
    name = "config_indicators"
    # config-ish identifier assignments: apiBaseUrl, API_URL, graphqlEndpoint …
    _ASSIGN = re.compile(
        r"\b([A-Za-z_$][A-Za-z0-9_$]{2,48})\s*[:=]\s*" + _QUOTE
    )
    _KEY_HINT = re.compile(
        r"(url|uri|endpoint|base|host|api|graphql|ws|websocket|auth|oauth|cdn|"
        r"firebase|sentry|stripe|bucket|region|env|config|clientid|tenant)",
        re.I,
    )
    _GLOBALS = [
        (re.compile(r"window\.(__[A-Z0-9_]+__)"), "window-global"),
        (re.compile(r"import\.meta\.env\.([A-Za-z0-9_]+)"), "import-meta-env"),
        (re.compile(r"process\.env\.([A-Za-z0-9_]+)"), "process-env"),
    ]

    def extract(self, content, base_url, analysis):
        for m in self._ASSIGN.finditer(content):
            name = m.group(1)
            if self._KEY_HINT.search(name):
                if (name, "config-key") not in analysis.config_indicators:
                    analysis.config_indicators.append((name, "config-key"))
        for rx, kind in self._GLOBALS:
            for m in rx.finditer(content):
                pair = (m.group(1), kind)
                if pair not in analysis.config_indicators:
                    analysis.config_indicators.append(pair)


class RouteExtractor(Extractor):
    name = "routes"
    _PATH_KEY = re.compile(r"\b(?:path|route|url)\s*:\s*" + _QUOTE + r"(/[A-Za-z0-9_][A-Za-z0-9_/:\-]{1,120})" + _QUOTE)
    _DECORATOR = re.compile(r"@(?:Get|Post|Put|Delete|Patch|All)\s*\(\s*" + _QUOTE + r"(/[A-Za-z0-9_][A-Za-z0-9_/:\-]{0,120})" + _QUOTE, re.I)

    def extract(self, content, base_url, analysis):
        for rx in (self._PATH_KEY, self._DECORATOR):
            for m in rx.finditer(content):
                analysis.add("routes", m.group(1))


class ServiceNameExtractor(Extractor):
    name = "services"
    _RE = re.compile(r"\b(?:class|const|function)\s+([A-Za-z_$][A-Za-z0-9_$]{2,48}(?:Service|Client|Api|Repository|Controller|Gateway|Store))\b")

    def extract(self, content, base_url, analysis):
        for m in self._RE.finditer(content):
            analysis.add("services", m.group(1))


class TechnologyExtractor(Extractor):
    name = "technologies"
    _SIGNS = [
        (re.compile(r"webpackJsonp|__webpack_require__|webpackChunk"), "Webpack"),
        (re.compile(r"__NEXT_DATA__|/_next/"), "Next.js"),
        (re.compile(r"window\.__NUXT__|/_nuxt/"), "Nuxt.js"),
        (re.compile(r"\bReactDOM\b|react-dom|__REACT_DEVTOOLS"), "React"),
        (re.compile(r"\b__vue__\b|Vue\.config|/vue(?:\.runtime)?\."), "Vue.js"),
        (re.compile(r"\bng\.probe\b|angular\.module|platformBrowserDynamic"), "Angular"),
        (re.compile(r"\bSvelte\b|__svelte"), "Svelte"),
        (re.compile(r"\bgtag\(|googletagmanager"), "Google Tag Manager"),
        (re.compile(r"\bSentry\b|@sentry/"), "Sentry"),
        (re.compile(r"firebase(?:app|ase)?\.|firebaseio\.com"), "Firebase"),
        (re.compile(r"\bStripe\(|js\.stripe\.com"), "Stripe"),
        (re.compile(r"\bApolloClient\b|apollo-client"), "Apollo GraphQL"),
    ]

    def extract(self, content, base_url, analysis):
        for rx, name in self._SIGNS:
            if rx.search(content):
                analysis.add("technologies", name)


class VocabularyExtractor(Extractor):
    """Reuse the learning-system extractor for JS identifiers + GraphQL names."""
    name = "vocabulary"

    def extract(self, content, base_url, analysis):
        for c in vocabulary.extract_from_js(content):
            if c.category == vocabulary.JS_IDENTIFIERS:
                analysis.add("identifiers", c.value)
            elif c.category == vocabulary.GRAPHQL_NAMES:
                analysis.add("graphql", c.value)


# Default pipeline. Callers may pass their own list (extensibility point).
DEFAULT_EXTRACTORS: list[Extractor] = [
    UrlExtractor(),
    ApiPathExtractor(),
    WebSocketExtractor(),
    SourceMapExtractor(),
    ConfigIndicatorExtractor(),
    RouteExtractor(),
    ServiceNameExtractor(),
    TechnologyExtractor(),
    VocabularyExtractor(),
]


# ── inline-JS extraction from HTML ────────────────────────────────────────────

_SCRIPT_INLINE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)
_SCRIPT_SRC = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.I)


def inline_scripts(html: str) -> str:
    """Concatenate the bodies of inline <script> tags (no src)."""
    parts: list[str] = []
    for m in _SCRIPT_INLINE.finditer(html or ""):
        body = m.group(1)
        if body and body.strip():
            parts.append(body)
    return "\n".join(parts)


def script_srcs(html: str, base_url: str) -> list[str]:
    """Resolved src URLs of external <script> tags in an HTML document."""
    out: list[str] = []
    for m in _SCRIPT_SRC.finditer(html or ""):
        u = resolve(m.group(1), base_url)
        if u and u not in out:
            out.append(u)
    return out


# ── the engine entry point ────────────────────────────────────────────────────

def analyze(
    content: str,
    source_url: str,
    *,
    extractors: list[Extractor] | None = None,
    is_html: bool = False,
    max_len: int = 4_000_000,
) -> JsAnalysis:
    """Run all extractors over a JS/HTML/JSON body. Never raises.

    For HTML, inline <script> bodies are folded into the analyzed text so inline
    JavaScript is covered as first-class input (external <script src> URLs are
    returned separately via `script_srcs` for the caller to fetch)."""
    analysis = JsAnalysis(source_url=source_url)
    if not content:
        return analysis
    text = content[:max_len]
    if is_html:
        text = text + "\n" + inline_scripts(text)
    for ex in (extractors or DEFAULT_EXTRACTORS):
        try:
            ex.extract(text, source_url, analysis)
        except Exception:
            # An extractor must never break the pipeline.
            continue
    return analysis
