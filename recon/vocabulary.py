"""
recon.vocabulary — the deterministic core of the persistent reconnaissance
learning system.

Pure functions only: no LLM, no network, no DB. This module turns things the
scanner *observed* (URLs, endpoints, parameters, technologies, JS bodies) into
reusable reconnaissance **vocabulary candidates**, and provides the
normalization, quality-filtering, confidence-scoring and ranking primitives the
`KnowledgeBase` persists on top of.

Pipeline (this module owns the first four stages):

    discovery → normalization → classification → candidate extraction
             → [deduplication → scoring → persistence] (KnowledgeBase)
             → future wordlist generation (KnowledgeBase.generate_wordlist)

Design rules
------------
* A candidate is a *proposal*, never proof that an endpoint exists. Nothing here
  asserts existence; it only records "this token was seen, and looks reusable".
* All inputs arrive from Event data that has already been scope-gated and
  sanitized/length-capped at construction (events/types.py). We re-validate
  quality here to keep low-signal garbage out of generated wordlists.
* Parameter *values* are only ever learned when they look like safe, low-entropy
  enum tokens. Anything that resembles a secret / id / PII / high-entropy blob is
  dropped — we never persist a value that could be sensitive.
* Normalization is asymmetric and documented (see `_LOWER_CATEGORIES`): directory
  and API-path style tokens are case-folded (`/API/` == `api`); names that are
  case-significant in practice (files, endpoints, parameters, identifiers) keep
  their case (`exportCsv` != `ExportCSV`).
"""

from __future__ import annotations

import math
import re
import urllib.parse
from dataclasses import dataclass

# ── categories ──────────────────────────────────────────────────────────────

DIRECTORIES = "directories"
FILES = "files"
ENDPOINTS = "endpoints"
API_PATHS = "api_paths"
API_VERSIONS = "api_versions"
PARAMETERS = "parameters"
PARAM_VALUES = "param_values"
JS_IDENTIFIERS = "js_identifiers"
TECH_PATHS = "tech_paths"
CLOUD_PATTERNS = "cloud_patterns"
GRAPHQL_NAMES = "graphql_names"
OPENAPI_PATHS = "openapi_paths"
RESOURCE_NAMES = "resource_names"

CATEGORIES: tuple[str, ...] = (
    DIRECTORIES, FILES, ENDPOINTS, API_PATHS, API_VERSIONS, PARAMETERS,
    PARAM_VALUES, JS_IDENTIFIERS, TECH_PATHS, CLOUD_PATTERNS, GRAPHQL_NAMES,
    OPENAPI_PATHS, RESOURCE_NAMES,
)

# Categories folded to lowercase on normalize (case-insensitive in practice).
# Everything else preserves case.
_LOWER_CATEGORIES = frozenset({
    DIRECTORIES, API_PATHS, API_VERSIONS, OPENAPI_PATHS, CLOUD_PATTERNS,
})

# ── knowledge scopes ─────────────────────────────────────────────────────────
# One vocabulary table stores every scope; (scope_type, scope_key) partitions it.

SCOPE_GLOBAL = "global"          # scope_key = ""            — all targets, all tech
SCOPE_TECHNOLOGY = "technology"  # scope_key = tech name     — e.g. "wordpress"
SCOPE_TARGET = "target"          # scope_key = seed domain   — e.g. "example.com"
SCOPE_ORGANIZATION = "organization"  # scope_key = program/org label

SCOPES: tuple[str, ...] = (SCOPE_GLOBAL, SCOPE_TECHNOLOGY, SCOPE_TARGET, SCOPE_ORGANIZATION)

_MAX_TOKEN = 64  # a reconnaissance word longer than this is almost never useful

# ── regexes ───────────────────────────────────────────────────────────────────

_RE_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_RE_HEXBLOB = re.compile(r"^[0-9a-f]{16,}$", re.I)          # md5/sha/asset-hash
_RE_LONGNUM = re.compile(r"^\d{4,}$")                        # numeric id
_RE_IDENT = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")        # JS identifier
_RE_APIVER = re.compile(r"^v\d{1,3}$", re.I)                 # v1, v2, v03
_RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_RE_ASSET_HASH_CHUNK = re.compile(r"[.\-_][0-9a-f]{8,}(?=\.[a-z0-9]+$)", re.I)  # main.4f3a2b1c.js
_RE_JS_URL = re.compile(r"""["'`]((?:https?:)?//[^"'`\s]+|/[^"'`\s]{2,})["'`]""")
_RE_JS_IDENT_DECL = re.compile(r"\b(?:function|const|let|var|class)\s+([A-Za-z_$][A-Za-z0-9_$]{2,})")
_RE_GRAPHQL_FIELD = re.compile(r"\b(?:query|mutation|subscription|type|input|fragment)\s+([A-Za-z_][A-Za-z0-9_]{2,})", re.I)

# Static-asset extensions whose *filenames* are rarely reusable vocabulary.
_STATIC_EXT = frozenset({
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "woff", "woff2", "ttf",
    "eot", "otf", "mp4", "webm", "mp3", "css", "map", "pdf",
})

# Very common English/stop tokens that add no discriminating value to a wordlist.
_STOP_TOKENS = frozenset({
    "the", "and", "for", "with", "http", "https", "www", "com", "net", "org",
    "html", "index", "true", "false", "null", "none",
})

# API-doc / schema locations worth remembering as their own category.
_OPENAPI_HINTS = ("swagger", "openapi", "api-docs", "v3/api-docs", "graphql", "graphiql")

# Reserved JS words we never want as "identifiers" in a wordlist.
_JS_RESERVED = frozenset({
    "function", "return", "const", "class", "true", "false", "null", "undefined",
    "this", "super", "import", "export", "default", "typeof", "instanceof",
    "window", "document", "console", "length", "prototype", "value",
})


# ── candidate ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Candidate:
    """One extracted vocabulary proposal. Provenance travels with it."""
    value: str
    category: str
    context: str | None = None       # technology context, e.g. "wordpress"
    source_url: str | None = None    # path only, never a query string


# ── normalization ──────────────────────────────────────────────────────────────

def normalize(value: str, category: str) -> str:
    """Return the canonical stored form of a candidate value for a category.

    Directory/API-path style tokens are lower-cased and slash-stripped; other
    categories keep their case. Always trims surrounding whitespace and slashes.
    Returns "" for anything that normalizes away to nothing.
    """
    if not value:
        return ""
    v = value.strip().strip("/").strip()
    if not v:
        return ""
    if category in _LOWER_CATEGORIES:
        v = v.lower()
    return v[:_MAX_TOKEN]


# ── quality filtering ──────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def is_quality(value: str, category: str) -> bool:
    """True if `value` is worth persisting as reusable vocabulary.

    Rejects the usual pollutants: empty/oversized tokens, pure numeric ids,
    UUIDs, hash/hex blobs, hashed asset chunks, stop-words and (for names)
    single characters. This is the gate that keeps generated wordlists useful.
    """
    if category not in CATEGORIES:
        return False
    v = (value or "").strip()
    if not v or len(v) > _MAX_TOKEN:
        return False

    low = v.lower()
    if low in _STOP_TOKENS:
        return False
    if _RE_UUID.match(v) or _RE_HEXBLOB.match(v) or _RE_LONGNUM.match(v):
        return False
    if v.isdigit():
        return False
    # Reject tokens that are mostly digits (e.g. "12ab34") — usually ids.
    digits = sum(c.isdigit() for c in v)
    if len(v) >= 4 and digits / len(v) > 0.6:
        return False

    if category == API_VERSIONS:
        return bool(_RE_APIVER.match(v))

    if category == PARAM_VALUES:
        return is_safe_value(v)

    if category == JS_IDENTIFIERS:
        if len(v) < 3 or low in _JS_RESERVED or not _RE_IDENT.match(v):
            return False
        return True

    if category == FILES:
        ext = v.rsplit(".", 1)[-1].lower() if "." in v else ""
        if ext in _STATIC_EXT:
            return False
        if _RE_ASSET_HASH_CHUNK.search(v):   # main.4f3a2b1c.js style
            return False

    # Generic name-ish categories: require at least 2 chars and a letter.
    if len(v) < 2:
        return False
    if not any(c.isalpha() for c in v):
        return False
    return True


def is_safe_value(value: str) -> bool:
    """True only for parameter values that are safe to persist.

    We keep short, low-entropy enum-like tokens (``asc``, ``json``, ``en``,
    ``true``) and drop anything that looks like a secret, id, token, email or
    high-entropy blob. When in doubt, drop it — a learning system must never
    accumulate sensitive values.
    """
    v = (value or "").strip()
    if not v or len(v) > 32:
        return False
    if _RE_EMAIL.match(v):
        return False
    if _RE_UUID.match(v) or _RE_HEXBLOB.match(v) or v.isdigit() or _RE_LONGNUM.match(v):
        return False
    # Conservative charset: enum tokens don't contain separators/secrets chars.
    if not re.match(r"^[A-Za-z0-9._-]+$", v):
        return False
    # High-entropy → likely a token/secret, not an enum value.
    if len(v) >= 12 and _shannon_entropy(v) > 3.2:
        return False
    return True


# ── classification helpers ───────────────────────────────────────────────────

def classify_openapi(path: str) -> bool:
    """True if a path looks like an API-schema / docs location."""
    low = path.lower()
    return any(h in low for h in _OPENAPI_HINTS)


def _is_file_token(tok: str) -> bool:
    # A path segment with a dotted extension is treated as a file.
    return "." in tok and not tok.startswith(".")


# ── extraction ─────────────────────────────────────────────────────────────────

def _split_path(url_or_path: str) -> tuple[list[str], str]:
    """Return (segments, path). Accepts a full URL or a bare path."""
    try:
        parsed = urllib.parse.urlparse(url_or_path)
        path = parsed.path if parsed.scheme or parsed.netloc else url_or_path
    except Exception:
        path = url_or_path
    path = path or ""
    segs = [s for s in path.split("/") if s]
    return segs, path


def extract_from_path(url_or_path: str, context: str | None = None) -> list[Candidate]:
    """Extract directory / file / endpoint / api-version / api-path / openapi /
    resource candidates from a URL or path.

    Example: "/api/v3/internal/export.json"
        directories : api, internal
        api_versions: v3
        api_paths   : api, v3, internal, export
        files       : export.json
        endpoints   : export
        resources   : internal, export
    """
    segs, path = _split_path(url_or_path)
    out: list[Candidate] = []
    if not segs:
        return out

    src = path
    saw_api = classify_openapi(path) or any(s.lower() == "api" for s in segs)
    openapi = classify_openapi(path)

    for i, seg in enumerate(segs):
        seg = urllib.parse.unquote(seg)
        last = i == len(segs) - 1

        if _RE_APIVER.match(seg):
            out.append(Candidate(seg, API_VERSIONS, context, src))

        if saw_api:
            # every meaningful segment of an API path is an api_path token
            base = seg.rsplit(".", 1)[0] if _is_file_token(seg) else seg
            out.append(Candidate(base, API_PATHS, context, src))

        if last and _is_file_token(seg):
            out.append(Candidate(seg, FILES, context, src))
            stem = seg.rsplit(".", 1)[0]
            out.append(Candidate(stem, ENDPOINTS, context, src))
            out.append(Candidate(stem, RESOURCE_NAMES, context, src))
        elif last:
            # Terminal bare segment: the endpoint/resource itself, and also a
            # plausible directory (e.g. /admin, /api/users).
            out.append(Candidate(seg, ENDPOINTS, context, src))
            if not _RE_APIVER.match(seg):
                out.append(Candidate(seg, DIRECTORIES, context, src))
                out.append(Candidate(seg, RESOURCE_NAMES, context, src))
        else:
            out.append(Candidate(seg, DIRECTORIES, context, src))
            if not _RE_APIVER.match(seg):
                out.append(Candidate(seg, RESOURCE_NAMES, context, src))

    if openapi:
        out.append(Candidate(path, OPENAPI_PATHS, context, src))

    return out


def extract_from_parameter(
    name: str, value: str | None = None, url: str | None = None, context: str | None = None
) -> list[Candidate]:
    """Extract a PARAMETER name (always) and its value (only if safe)."""
    out: list[Candidate] = []
    if name:
        out.append(Candidate(name, PARAMETERS, context, url))
    if value:
        out.append(Candidate(value, PARAM_VALUES, context, url))
    return out


def extract_from_technology(name: str, host: str | None = None) -> list[Candidate]:
    """A TECHNOLOGY observation contributes the tech name as a resource token.

    The primary value of a technology event to the learner is *context* (used to
    tag path/param candidates from the same host) — the module supplies that.
    Here we just record the tech name itself as a low-weight resource token.
    """
    if not name:
        return []
    return [Candidate(name, RESOURCE_NAMES, name, None)]


def extract_from_js(body: str, context: str | None = None, *, max_items: int = 200) -> list[Candidate]:
    """Regex-extract JS identifiers, referenced paths and GraphQL type/field
    names from a JavaScript/HTML body. Deterministic, best-effort, bounded."""
    out: list[Candidate] = []
    if not body:
        return out

    for m in _RE_JS_IDENT_DECL.finditer(body):
        out.append(Candidate(m.group(1), JS_IDENTIFIERS, context, None))
        if len(out) >= max_items:
            return out

    for m in _RE_GRAPHQL_FIELD.finditer(body):
        out.append(Candidate(m.group(1), GRAPHQL_NAMES, context, None))
        if len(out) >= max_items:
            return out

    for m in _RE_JS_URL.finditer(body):
        ref = m.group(1)
        out.extend(extract_from_path(ref, context))
        if len(out) >= max_items:
            break
    return out[:max_items]


def extract_cloud_patterns(host_or_bucket: str, context: str | None = None) -> list[Candidate]:
    """Extract cloud naming tokens from a bucket/host name.

    e.g. "acme-prod-backups.s3.amazonaws.com" → acme, prod, backups
    """
    out: list[Candidate] = []
    if not host_or_bucket:
        return out
    label = host_or_bucket.split(".")[0]
    for tok in re.split(r"[-_]", label):
        if tok:
            out.append(Candidate(tok, CLOUD_PATTERNS, context, None))
    return out


# ── confidence scoring & ranking ────────────────────────────────────────────

def confidence(target_count: int, occurrence_count: int) -> float:
    """Deterministic confidence in [0,1] that a candidate is reusable vocabulary.

    Breadth (distinct targets) dominates frequency: a token seen across many
    targets is a far stronger reusable word than one seen many times on a single
    target. Confidence reflects candidate *quality/reusability*, never a claim
    that the resource exists on any host.
    """
    tc = max(0, int(target_count))
    oc = max(0, int(occurrence_count))
    breadth = 1.0 - 1.0 / (1 + tc)      # 0 → .5(1 target) → →1
    freq = 1.0 - 1.0 / (1 + oc)
    return round(min(1.0, 0.65 * breadth + 0.35 * freq), 4)


def order_for_wordlist(rows: list, *, limit: int | None = None) -> list[str]:
    """Rank vocabulary rows for wordlist emission (most reusable first).

    `rows` are objects/tuples exposing value/target_count/occurrence_count/
    confidence. Ordering: breadth, then frequency, then confidence, then value.
    """
    def key(r):
        return (
            -_attr(r, "target_count", 0),
            -_attr(r, "occurrence_count", 0),
            -_attr(r, "confidence", 0.0),
            _attr(r, "value", ""),
        )
    ordered = [(_attr(r, "value", "")) for r in sorted(rows, key=key) if _attr(r, "value", "")]
    # de-dup preserving order
    seen: set[str] = set()
    out: list[str] = []
    for v in ordered:
        if v not in seen:
            seen.add(v)
            out.append(v)
    if limit is not None:
        out = out[:limit]
    return out


def _attr(obj, name, default):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)
