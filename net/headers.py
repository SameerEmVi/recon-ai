"""
HeaderProfile — a coherent, stock real-browser client fingerprint for outbound
requests, so authorized scans don't present the default python-httpx / httpx-binary
User-Agent that WAF/CDN rules filter on sight.

One profile is chosen per scan (owned by ScanController, exposed as
`controller.headers`) and applied by `BaseModule.http_client()` and the httpx-binary
prober to every outbound request. It changes how the client *presents*, never what
it is authorized to reach — this is complementary to `ratelimit/waf.py` (adaptive
backoff), not a replacement.

Design:
  * Coherence over randomness. A profile is ONE internally-consistent header set —
    the headers a real build of that browser actually sends together. One profile
    per scan, stable for the whole scan (per-request rotation reads as robotic).
  * `sec-ch-ua*` client-hint headers live ONLY in Chromium profiles; Firefox/Safari
    must not send them.
  * No `accept-encoding` on ANY profile: httpx only decodes codecs whose libs are
    installed (gzip/deflate always; brotli/zstd are NOT here). Advertising br/zstd
    we can't decode makes bodies arrive as undecodable bytes and silently breaks
    every downstream module — so we let httpx set its own Accept-Encoding.

Scope / non-goals: generic stock header sets only — no per-person identifiers, no
cookies, no auth/trust headers, and specifically NO X-Forwarded-For / X-Real-IP /
origin-IP spoofing. This never touches the scope engine or the capability policy.

Test-safety: `get_headers(obj)` returns `obj.headers` only when it is a real
HeaderProfile (mirrors `net.proxy.get_proxy`), else None — so a MagicMock controller
keeps sending httpx's default headers.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class HeaderProfile:
    """One internally-consistent browser header set. Header names are lowercased;
    `headers` is an ordered tuple of (name, value) pairs so the profile is frozen
    and hashable."""

    name: str
    headers: tuple[tuple[str, str], ...]

    def as_dict(self) -> dict[str, str]:
        """The headers as a plain dict (for httpx `headers=`)."""
        return {k: v for k, v in self.headers}

    def cli_args(self, flag: str = "-H") -> list[str]:
        """Flatten to repeated header flags, e.g. ['-H', 'user-agent: …', '-H', …]
        for the httpx-binary prober (`httpx -H …`)."""
        out: list[str] = []
        for k, v in self.headers:
            out += [flag, f"{k}: {v}"]
        return out

    def describe(self) -> str:
        return f"browser={self.name}"


def _profile(name: str, headers: dict[str, str]) -> HeaderProfile:
    """Build a HeaderProfile with lowercased header names, preserving order."""
    return HeaderProfile(name=name, headers=tuple((k.lower(), v) for k, v in headers.items()))


# ── profile registry ──────────────────────────────────────────────────────────
# Each set is the coherent bundle a real build of that browser sends on a top-level
# navigation GET. No accept-encoding anywhere; sec-ch-ua* only on Chromium.

_CHROME_VER = "131"

PROFILES: dict[str, HeaderProfile] = {
    "chrome-windows": _profile("chrome-windows", {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      f"(KHTML, like Gecko) Chrome/{_CHROME_VER}.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                  "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "sec-ch-ua": f'"Google Chrome";v="{_CHROME_VER}", "Chromium";v="{_CHROME_VER}", '
                     '"Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Upgrade-Insecure-Requests": "1",
    }),
    "chrome-mac": _profile("chrome-mac", {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                      f"(KHTML, like Gecko) Chrome/{_CHROME_VER}.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                  "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "sec-ch-ua": f'"Google Chrome";v="{_CHROME_VER}", "Chromium";v="{_CHROME_VER}", '
                     '"Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Upgrade-Insecure-Requests": "1",
    }),
    "chrome-android": _profile("chrome-android", {
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
                      f"(KHTML, like Gecko) Chrome/{_CHROME_VER}.0.0.0 Mobile Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                  "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "sec-ch-ua": f'"Google Chrome";v="{_CHROME_VER}", "Chromium";v="{_CHROME_VER}", '
                     '"Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Upgrade-Insecure-Requests": "1",
    }),
    "firefox-windows": _profile("firefox-windows", {
        # Firefox sends Sec-Fetch-* but NOT sec-ch-ua (those are Chromium-only).
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) "
                      "Gecko/20100101 Firefox/133.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                  "image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }),
    "safari-mac": _profile("safari-mac", {
        # Safari sends neither sec-ch-ua nor the Sec-Fetch-* client-hint set.
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                      "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }),
}

_DEFAULT = "chrome-windows"
_OFF = frozenset({"off", "none", ""})


def available() -> list[str]:
    """Selectable values for the CLI: the concrete profiles plus the selectors."""
    return list(PROFILES.keys()) + ["off", "random"]


def resolve(selection: str | None, seed: str | None = None) -> HeaderProfile | None:
    """Resolve a selection to a HeaderProfile, or None for 'off'/None.

    'random' picks ONE profile deterministically from `seed` (the scan id) so a
    scan stays on a single fingerprint and reruns reproduce. An unknown name
    raises ValueError — fail-closed, so a typo never silently falls back to the
    default or to no profile.
    """
    if selection is None:
        return None
    sel = selection.strip().lower()
    if sel in _OFF:
        return None
    if sel == "random":
        names = sorted(PROFILES)
        digest = hashlib.sha256((seed or "").encode("utf-8")).hexdigest()
        return PROFILES[names[int(digest, 16) % len(names)]]
    if sel in PROFILES:
        return PROFILES[sel]
    raise ValueError(
        f"unknown browser profile {selection!r}; choose from: {', '.join(available())}"
    )


def get_headers(obj) -> HeaderProfile | None:
    """Return obj.headers only when it's a real HeaderProfile, else None — so a
    MagicMock controller (tests) keeps sending httpx's default headers. Mirrors
    net.proxy.get_proxy."""
    h = getattr(obj, "headers", None)
    return h if isinstance(h, HeaderProfile) else None
