"""
csprecon — subdomain discovery from Content-Security-Policy headers (pure Python).

Reactive module: on each HTTP_SERVICE, fetches the URL, reads the
Content-Security-Policy header (and any CSP <meta> in the body), extracts host
sources and emits them as SUBDOMAIN events (scope-gated). No binary needed.

Watches:  HTTP_SERVICE
Produces: SUBDOMAIN
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from events.types import Event, EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register

# CSP keyword sources (not hosts).
_CSP_KEYWORDS = {
    "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'",
    "'unsafe-hashes'", "'report-sample'", "*", "data:", "blob:", "filesystem:",
    "mediastream:", "https:", "http:", "ws:", "wss:",
}

_META_CSP_RE = re.compile(
    r"""<meta[^>]+http-equiv=["']content-security-policy["'][^>]+content=["']([^"']+)["']""",
    re.I,
)


def extract_csp_hosts(csp: str) -> list[str]:
    """Extract hostnames from a Content-Security-Policy value.

    Handles bare hosts, scheme://host, wildcards (*.example.com -> example.com),
    ports and paths. Skips CSP keywords, nonces and hashes.
    """
    out: list[str] = []
    seen: set[str] = set()
    for token in re.split(r"[;\s]+", csp or ""):
        t = token.strip()
        if not t:
            continue
        low = t.lower()
        if low in _CSP_KEYWORDS or low.startswith(("'nonce-", "'sha")):
            continue
        # Strip scheme.
        if "://" in t:
            t = t.split("://", 1)[1]
        # Drop path and port.
        t = t.split("/", 1)[0].split(":", 1)[0]
        # Strip leading wildcard label.
        if t.startswith("*."):
            t = t[2:]
        t = t.strip(".").lower()
        if not t or t == "*" or "." not in t or " " in t:
            continue
        # crude hostname sanity
        if not re.fullmatch(r"[a-z0-9.\-]+", t):
            continue
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


@register
class CspReconModule(BaseModule):
    name = "csprecon"
    description = "Subdomain discovery from CSP headers (pure Python, no binary)"
    watched_events = ["HTTP_SERVICE"]
    produced_events = ["SUBDOMAIN"]
    flags = ["active", "web", "subdomain-enum", "fast"]
    options = {"timeout": 20, "max_body_kb": 512}

    async def setup(self) -> bool:
        return True  # pure Python

    async def handle_event(self, event: Event) -> None:
        url = getattr(event.data, "url", None)
        if not url:
            return
        csp_values = await self._fetch_csp(url)
        if not csp_values:
            return
        hosts: list[str] = []
        seen: set[str] = set()
        for csp in csp_values:
            for h in extract_csp_hosts(csp):
                if h not in seen:
                    seen.add(h)
                    hosts.append(h)
        count = 0
        for h in hosts:
            if await self.emit(
                EventType.SUBDOMAIN,
                SubdomainData(hostname=h, source="csprecon"),
                source_event=event,
            ):
                count += 1
        if count:
            self._log.info("csprecon: %d hosts from CSP on %s", count, url)

    async def _fetch_csp(self, url: str) -> list[str]:
        """Return the CSP header value(s) plus any CSP <meta> from the body."""
        try:
            import httpx
        except ImportError:
            self._log.warning("httpx not installed")
            return []
        try:
            async with httpx.AsyncClient(timeout=self.opt("timeout")) as client:
                async with self.guard(f"http:{urlparse(url).hostname or url}"):
                    r = await client.get(url, follow_redirects=True)
                self.inspect_response(r)
                values: list[str] = []
                hdr = r.headers.get("content-security-policy")
                if hdr:
                    values.append(hdr)
                if len(r.content) / 1024 <= self.opt("max_body_kb"):
                    for m in _META_CSP_RE.finditer(r.text):
                        values.append(m.group(1))
                return values
        except Exception as exc:
            self._log.debug("csprecon: fetch failed for %s: %s", url, exc)
            return []
