"""
Extension-fuzzing engine — the pure, deterministic core of the `extfuzz` module.

The idea: ordinary directory fuzzing finds *paths*; it misses the file that sits
*beside* a path you already know. If `/js/app.js` exists, `/js/app.js.map`,
`/js/app.js.bak` and `/js/app.old` very often exist too and leak source, config
or secrets. This engine takes paths the rest of recon-ai already discovered
(crawl, content-discovery, JS, historical) and generates extension candidates
for them, then classifies the responses *intelligently* — never calling a 200 a
file on its own.

Everything here is pure (no I/O, no randomness except the explicitly-seeded probe
token helper that is reused from recon.ffuf) so it is directly unit-testable. The
`modules/web/extfuzz.py` module owns the network side (fetching through the shared
rate limiter / WAF backoff / response cache) and the scope-gated emission.

Three responsibilities:

  1. Extension handling — `normalize_extension` / `normalize_extensions`
     (hostile-input-safe) and `tech_extensions` (technology-aware prioritization).
  2. Candidate generation — `generate_candidates` implements the three strategies
     (append / replace / extensionless) and de-duplicates.
  3. Response analysis — `Baseline` (learned catch-all) + `classify` turn an HTTP
     response into a verdict (file / soft-404 / redirect / auth / waf / not-found)
     with a confidence and, for genuinely interesting files, a category.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

# ── extension handling ────────────────────────────────────────────────────────

# Hard caps — extensions are partly operator- and partly AI-supplied, so they are
# treated as hostile input: bounded count, bounded length, strict charset.
_MAX_EXT_LEN = 12
_MAX_EXT_COUNT = 64
_EXT_RE = re.compile(r"^[a-z0-9][a-z0-9.]{0,%d}$" % (_MAX_EXT_LEN - 1))


def normalize_extension(ext: str) -> str | None:
    """Normalize one extension to a bare, lowercased token (no leading dot).

    Returns None for anything that is not a plausible file extension — empty,
    too long, or containing a character outside ``[a-z0-9.]``. This is the
    deterministic validation gate every extension (operator- or AI-proposed)
    passes through before it is ever turned into a URL.
    """
    if ext is None:
        return None
    e = str(ext).strip().lower().lstrip(".")
    if not e or len(e) > _MAX_EXT_LEN:
        return None
    if not _EXT_RE.match(e):
        return None
    # reject a bare / trailing / doubled dot (".", "a.", "a..b")
    if e.startswith(".") or e.endswith(".") or ".." in e:
        return None
    return e


def normalize_extensions(raw, max_count: int = _MAX_EXT_COUNT) -> list[str]:
    """Normalize a list or comma-string of extensions → ordered, de-duped list.

    Order is preserved (callers prepend higher-priority, e.g. technology-aware,
    extensions first). Invalid tokens are dropped silently. Capped at
    ``max_count`` so a huge AI/operator list can't blow up the candidate count.
    """
    if raw is None:
        return []
    items: list[str]
    if isinstance(raw, str):
        items = raw.split(",")
    else:
        items = list(raw)
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        e = normalize_extension(item)
        if e and e not in seen:
            seen.add(e)
            out.append(e)
            if len(out) >= max_count:
                break
    return out


# Technology → extensions that are worth prioritizing when that tech is present
# on the host. Keys are matched case-insensitively against technology names.
_TECH_EXT = {
    "php": ["php", "php5", "php7", "phtml", "inc"],
    "wordpress": ["php"],
    "laravel": ["php", "env"],
    "drupal": ["php"],
    "joomla": ["php"],
    "asp.net": ["aspx", "asp", "ashx", "asmx", "config"],
    "asp": ["asp", "aspx"],
    "iis": ["aspx", "asp", "config"],
    "microsoft asp.net": ["aspx", "asp", "config"],
    "java": ["jsp", "do", "action", "jar", "war"],
    "jsp": ["jsp", "jspx"],
    "tomcat": ["jsp", "war"],
    "spring": ["jsp", "properties", "yml", "yaml"],
    "python": ["py", "wsgi"],
    "django": ["py"],
    "flask": ["py"],
    "ruby": ["rb"],
    "rails": ["rb", "yml"],
    "node.js": ["js", "json", "map", "env"],
    "express": ["js", "json", "map", "env"],
    "react": ["js", "map", "json"],
    "vue.js": ["js", "map", "json"],
    "angular": ["js", "map", "json"],
    "coldfusion": ["cfm", "cfc"],
    "perl": ["pl", "cgi"],
}


def tech_extensions(technologies) -> list[str]:
    """Extensions to prioritize for the given technology names (order-stable)."""
    out: list[str] = []
    seen: set[str] = set()
    for tech in technologies or []:
        key = str(tech).strip().lower()
        mapped = _TECH_EXT.get(key)
        if mapped is None:
            # tolerate "Microsoft ASP.NET:4.0" style — match on a known prefix.
            for k, v in _TECH_EXT.items():
                if key.startswith(k):
                    mapped = v
                    break
        for e in mapped or []:
            if e not in seen:
                seen.add(e)
                out.append(e)
    return out


# ── candidate generation ────────────────────────────────────────────────────

# Current extensions that make a poor *base* to fuzz from — fuzzing a `.png` for
# `.png.bak` is near-worthless, whereas `.js` → `.js.map/.js.bak` is gold, so JS
# and CSS are deliberately NOT here.
_SKIP_BASE_EXT = frozenset({
    "png", "jpg", "jpeg", "gif", "ico", "bmp", "webp", "svg",
    "woff", "woff2", "ttf", "eot", "otf",
    "mp4", "webm", "mp3", "avi", "mov",
})

# Strategy names.
APPEND = "append"
REPLACE = "replace"
EXTENSIONLESS = "extensionless"
_ALL_STRATEGIES = (APPEND, REPLACE, EXTENSIONLESS)


def normalize_strategies(raw) -> list[str]:
    """Validate a list/comma-string of strategy names → ordered subset."""
    if raw is None:
        return list(_ALL_STRATEGIES)
    items = raw.split(",") if isinstance(raw, str) else list(raw)
    out: list[str] = []
    for item in items:
        s = str(item).strip().lower()
        if s in _ALL_STRATEGIES and s not in out:
            out.append(s)
    return out or list(_ALL_STRATEGIES)


def _split_path(path: str) -> tuple[str, str, str, str]:
    """Return (dir_prefix, filename, stem, ext) for a URL path.

    `dir_prefix` keeps its trailing slash. `ext` is the lowercased extension
    without the dot ("" if none). `stem` is the filename without its extension.
    """
    slash = path.rfind("/")
    dir_prefix = path[: slash + 1] if slash >= 0 else ""
    filename = path[slash + 1 :] if slash >= 0 else path
    dot = filename.rfind(".")
    if dot > 0:  # dot>0 so a dotfile like ".env" is treated as a whole name
        stem, ext = filename[:dot], filename[dot + 1 :].lower()
    else:
        stem, ext = filename, ""
    return dir_prefix, filename, stem, ext


def generate_candidates(
    url: str,
    extensions: list[str],
    strategies: list[str] | None = None,
    *,
    max_per_path: int = 80,
) -> list[str]:
    """Generate extension-candidate URLs for one known URL/path. Pure.

    Strategies:
      append        — add `.ext` to the filename  (/a/app.js → /a/app.js.bak)
                       and, for an extensionless path, (/a/admin → /a/admin.php)
      replace       — swap the existing extension   (/a/app.js → /a/app.bak)
      extensionless — test the stem with no extension, then with each ext
                       (/a/download.php → /a/download, /a/download.bak …)

    Returns a de-duplicated, order-stable list of absolute URLs, excluding the
    original URL. Query string and fragment are dropped. Capped at
    ``max_per_path``.
    """
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.netloc:
        return []
    strategies = strategies or list(_ALL_STRATEGIES)
    dir_prefix, filename, stem, ext = _split_path(p.path or "/")

    # A pure directory ("/a/" or "/") has no filename to fuzz.
    if not filename:
        return []
    if ext in _SKIP_BASE_EXT:
        return []

    origin = f"{p.scheme}://{p.netloc}"
    original = f"{origin}{p.path}"
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(new_filename: str) -> None:
        if not new_filename:
            return
        new_url = origin + dir_prefix + new_filename
        if new_url == original or new_url in seen:
            return
        seen.add(new_url)
        candidates.append(new_url)

    for ex in extensions:
        if len(candidates) >= max_per_path:
            break
        if APPEND in strategies:
            _add(f"{filename}.{ex}")          # app.js -> app.js.bak ; admin -> admin.php
        if ext:  # only meaningful when there is an extension to replace/strip
            if REPLACE in strategies:
                _add(f"{stem}.{ex}")          # app.js -> app.bak
            if EXTENSIONLESS in strategies:
                _add(f"{stem}.{ex}")          # same family; dedup handles overlap

    # extensionless: also test the bare stem (no extension) once.
    if ext and EXTENSIONLESS in strategies:
        _add(stem)                             # download.php -> download

    return candidates[:max_per_path]


# ── response analysis ─────────────────────────────────────────────────────────

# Statuses that never indicate a discovered file (shared spirit with recon.ffuf).
NOISE_STATUS: frozenset[int] = frozenset({400, 404, 405, 410, 429, 500, 502, 503, 504})

# Verdicts.
V_FILE = "file"             # a real file very likely exists here
V_AMBIGUOUS = "ambiguous"   # 2xx with weak corroboration — a lead, NOT a confirmed file
V_SOFT404 = "soft-404"      # catch-all / SPA shell — drop
V_REDIRECT = "redirect"     # 3xx — record target, not a file
V_AUTH = "auth"             # 401/403 or a login page — exists but protected
V_WAF = "waf"               # block page / throttle — inconclusive, drop
V_NOT_FOUND = "not-found"   # 404 and friends — drop

# Interesting file categories and their (conservative, unverified) severity hint.
_INTERESTING = {
    "map": "source-map",
    "bak": "backup", "old": "backup", "orig": "backup", "save": "backup",
    "swp": "backup", "swo": "backup", "tmp": "backup", "backup": "backup", "bkp": "backup",
    "zip": "archive", "tar": "archive", "gz": "archive", "tgz": "archive",
    "rar": "archive", "7z": "archive", "war": "archive", "jar": "archive",
    "sql": "database-dump", "db": "database-dump", "sqlite": "database-dump", "dump": "database-dump",
    "conf": "config", "config": "config", "cfg": "config", "ini": "config",
    "env": "config", "properties": "config", "yaml": "config", "yml": "config", "toml": "config",
    "log": "log-file",
}
_SEVERITY = {
    "backup": "medium", "archive": "medium", "database-dump": "medium",
    "config": "low", "source-map": "low", "log-file": "low",
}

# Expected content-type substrings per extension. A match is corroborating
# evidence that the server served a real file (not an HTML page).
_EXT_CT = {
    "js": ("javascript",), "mjs": ("javascript",), "cjs": ("javascript",),
    "json": ("json",),
    "xml": ("xml",), "config": ("xml", "plain", "octet-stream"),
    "txt": ("plain",),
    "pdf": ("pdf",),
    "zip": ("zip", "octet-stream"), "tar": ("tar", "octet-stream"),
    "gz": ("gzip", "octet-stream"), "tgz": ("gzip", "octet-stream"),
    "rar": ("rar", "octet-stream"), "7z": ("7z", "octet-stream"),
    "war": ("octet-stream", "java-archive", "zip"), "jar": ("octet-stream", "java-archive", "zip"),
    "sql": ("sql", "plain", "octet-stream"),
    "db": ("octet-stream", "sqlite"), "sqlite": ("octet-stream", "sqlite"),
    "dump": ("plain", "octet-stream"),
    "map": ("json", "plain", "octet-stream"),
    "yaml": ("yaml", "plain", "octet-stream"), "yml": ("yaml", "plain", "octet-stream"),
    "toml": ("toml", "plain", "octet-stream"),
    "conf": ("plain", "octet-stream"), "cfg": ("plain", "octet-stream"),
    "ini": ("plain", "octet-stream"), "properties": ("plain", "octet-stream"),
    "env": ("plain", "octet-stream"),
    "log": ("plain", "octet-stream"),
    "bak": ("plain", "octet-stream"), "old": ("plain", "octet-stream"),
    "orig": ("plain", "octet-stream"), "save": ("plain", "octet-stream"),
}

_HTML_MARKERS = ("<!doctype html", "<html", "<head", "<body")
_LOGIN_MARKERS = (
    'type="password"', "type='password'", 'name="password"', "name='password'",
    "please log in", "please sign in", "sign in to", "authentication required",
    "login required",
)
_WAF_MARKERS = (
    "attention required", "cloudflare", "access denied", "request blocked",
    "web application firewall", "incapsula", "akamai", "you have been blocked",
    "captcha", "radware", "mod_security", "forbidden by administrative rules",
)


def looks_like_html(body: str | None) -> bool:
    if not body:
        return False
    head = body[:1024].lower()
    return any(m in head for m in _HTML_MARKERS)


def looks_like_login(body: str | None) -> bool:
    if not body:
        return False
    head = body[:4096].lower()
    return any(m in head for m in _LOGIN_MARKERS)


def looks_like_waf(body: str | None) -> bool:
    if not body:
        return False
    head = body[:4096].lower()
    return any(m in head for m in _WAF_MARKERS)


def signature_matches(ext: str, body: str | None) -> bool:
    """True if `body` carries a structural signature for `ext`. Conservative."""
    if not body:
        return False
    s = body.lstrip()[:8192]
    low = s.lower()
    if ext == "json":
        return s.startswith("{") or s.startswith("[")
    if ext in ("xml", "config"):
        return s.startswith("<?xml") or s.startswith("<")
    if ext == "pdf":
        return s.startswith("%PDF")
    if ext == "map":
        return '"mappings"' in low and ('"version"' in low or '"sources"' in low)
    if ext in ("yaml", "yml"):
        return bool(re.search(r"(?m)^[A-Za-z0-9_.-]+:\s", s)) and not looks_like_html(body)
    if ext in ("sql", "dump"):
        return bool(re.search(r"(?i)\b(insert\s+into|create\s+table|drop\s+table|-- mysql dump|pg_dump)\b", low))
    if ext in ("env", "properties", "ini", "conf", "cfg"):
        # key=value / [section] lines, and definitely not an HTML page.
        return bool(re.search(r"(?m)^\s*[\[A-Za-z0-9_.-]+\s*[=:]", s)) and not looks_like_html(body)
    return False


def interesting_category(ext: str) -> str | None:
    """The finding category for an extension, or None if it isn't worth a finding."""
    return _INTERESTING.get((ext or "").lower())


def severity_for(category: str | None) -> str:
    return _SEVERITY.get(category or "", "low")


@dataclass
class Baseline:
    """A host's learned catch-all response (status + body size).

    A CDN/WAF/SPA origin returns a uniform response to *any* path. A candidate
    whose response is indistinguishable from this baseline is a soft-404, not a
    discovered file. ``None`` baseline means the host 404s honestly.
    """

    status: int
    size: int

    def matches(self, status: int | None, body: str | None) -> bool:
        if status != self.status:
            return False
        size = len(body or "")
        return abs(size - self.size) <= max(64, int(self.size * 0.05))


def build_baseline(probes: list[tuple[int | None, str | None]]) -> Baseline | None:
    """Derive a catch-all Baseline from random-path probes.

    Each probe is (status, body). Returns a Baseline only when the host answers
    random paths *uniformly* with a non-absent status; a real 404/410 (or any
    failed probe) means the host distinguishes missing paths → no baseline.
    """
    if not probes:
        return None
    samples: list[tuple[int, int]] = []
    for status, body in probes:
        if status is None or status in (404, 410) or status in NOISE_STATUS:
            return None
        samples.append((status, len(body or "")))
    s0 = samples[0][0]
    if any(s != s0 for s, _ in samples):
        return None
    sizes = [ln for _, ln in samples]
    avg = sum(sizes) // len(sizes)
    if all(abs(ln - avg) <= max(64, int(avg * 0.05)) for ln in sizes):
        return Baseline(s0, avg)
    return None


@dataclass
class Classification:
    verdict: str
    confidence: float
    category: str | None = None          # interesting-file category (findings)
    status: int | None = None
    content_type: str | None = None
    length: int | None = None
    redirect: str | None = None
    reason: str = ""
    evidence: dict = field(default_factory=dict)

    @property
    def is_file(self) -> bool:
        return self.verdict == V_FILE


def _ct_ok(ext: str, content_type: str | None) -> bool:
    if not content_type:
        return False
    ct = content_type.lower()
    for sub in _EXT_CT.get(ext, ()):  # unknown ext → no expectation → False
        if sub in ct:
            return True
    return False


def classify(
    *,
    ext: str,
    status: int | None,
    body: str | None,
    content_type: str | None = None,
    redirect: str | None = None,
    baseline: Baseline | None = None,
) -> Classification:
    """Turn one HTTP response into a verdict + confidence. Pure, deterministic.

    The cardinal rule (requirement #3): a bare ``200`` is never enough to call
    something a file. A confirmed file (V_FILE) requires corroboration — a
    matching content-type or a structural body signature — and a response that
    merely 200s with a non-HTML, non-baseline body is only V_AMBIGUOUS (a lead).
    HTML served for a non-HTML extension, or a response matching the host's
    catch-all baseline, is a soft-404.
    """
    ext = (ext or "").lower()
    length = len(body) if body is not None else None
    base = dict(status=status, content_type=content_type, length=length)

    if status is None:
        return Classification(V_NOT_FOUND, 0.0, status=status, reason="no response", evidence=base)

    # 3xx — record the redirect target; not a file.
    if 300 <= status < 400:
        return Classification(
            V_REDIRECT, 0.3, status=status, content_type=content_type,
            length=length, redirect=redirect or None,
            reason=f"redirect {status} -> {redirect or '?'}", evidence=base,
        )

    # Block pages / throttling — inconclusive, let the limiter back off upstream.
    if status == 429 or looks_like_waf(body):
        return Classification(V_WAF, 0.0, status=status, reason="WAF/block/throttle", evidence=base)

    # Exists-but-protected.
    if status in (401, 403):
        return Classification(
            V_AUTH, 0.5, status=status, content_type=content_type, length=length,
            reason=f"protected ({status})", evidence=base,
        )

    if status in NOISE_STATUS or status >= 400:
        return Classification(V_NOT_FOUND, 0.0, status=status, reason=f"not found ({status})", evidence=base)

    # ── 2xx ────────────────────────────────────────────────────────────────
    if baseline is not None and baseline.matches(status, body):
        return Classification(V_SOFT404, 0.0, status=status, length=length,
                              reason="matches host catch-all baseline", evidence=base)

    # An HTML document served for a non-HTML extension is a soft-404 / SPA shell.
    if ext not in ("html", "htm", "") and looks_like_html(body):
        return Classification(V_SOFT404, 0.0, status=status, content_type=content_type,
                              length=length, reason="HTML page served for non-HTML extension",
                              evidence=base)

    if looks_like_login(body):
        return Classification(V_AUTH, 0.5, status=status, content_type=content_type,
                              length=length, reason="login/auth page", evidence=base)

    # Body unavailable (oversize) — decide on content-type alone, cautiously.
    if body is None:
        if _ct_ok(ext, content_type):
            return Classification(V_FILE, 0.7, interesting_category(ext), status=status,
                                  content_type=content_type, length=length,
                                  reason="content-type matches (body not inspected)", evidence=base)
        return Classification(V_AMBIGUOUS, 0.35, status=status, content_type=content_type,
                              length=length, reason="2xx, body not inspected", evidence=base)

    if length == 0:
        return Classification(V_SOFT404, 0.0, status=status, length=0,
                              reason="empty 2xx (catch-all stub)", evidence=base)

    sig = signature_matches(ext, body)
    ct_ok = _ct_ok(ext, content_type)
    if sig:
        return Classification(V_FILE, 0.9, interesting_category(ext), status=status,
                              content_type=content_type, length=length,
                              reason="body signature matches extension", evidence=base)
    if ct_ok:
        return Classification(V_FILE, 0.85, interesting_category(ext), status=status,
                              content_type=content_type, length=length,
                              reason="content-type matches extension", evidence=base)
    # 2xx, non-empty, not HTML, not baseline — a lead, but 200 alone is NOT a file.
    return Classification(V_AMBIGUOUS, 0.45, status=status, content_type=content_type,
                          length=length, reason="2xx non-HTML body, no corroboration", evidence=base)
