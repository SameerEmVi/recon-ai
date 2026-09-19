"""
linkfinder — JavaScript endpoint extraction (pure Python, no binary).

Reactive: fires on URL events where the URL likely points to a JavaScript
file (by extension or content-type). Fetches the JS content via httpx and
applies regex patterns to extract relative/absolute endpoint references.
Emits ENDPOINT events for discovered paths.

Watches:  URL
Produces: ENDPOINT
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from events.types import EndpointData, Event, EventType
from modules.base import BaseModule
from modules.registry import register

# Endpoint extraction pattern — adapted from the original LinkFinder tool.
_ENDPOINT_RE = re.compile(
    r"""(?:"|')                             # opening quote
    (
        (?:https?:)?//[^"'\s<>{}\[\]|]{4,256}  # absolute/protocol-relative URL
        |
        /[a-zA-Z0-9_.~%!*:@,;=+$?/#&\-]{2,200}  # relative path starting with /
        |
        [a-zA-Z0-9_\-]{1,64}
        (?:/[a-zA-Z0-9_.~%!*:@,;=+$?/#&\-]{1,64}){1,10}  # multi-segment path
    )
    (?:"|')                                 # closing quote
    """,
    re.VERBOSE,
)

# Skip obviously non-endpoint strings.
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".otf", ".map", ".css",
}

# Minimum path length to consider.
_MIN_PATH_LEN = 4


def _is_js_url(url: str, content_type: str | None) -> bool:
    """Return True if this URL likely points to JavaScript content."""
    path = urlparse(url).path.lower()
    if path.endswith(".js"):
        return True
    if content_type and "javascript" in content_type.lower():
        return True
    return False


def _filter_endpoint(path: str) -> bool:
    """Return True if the path looks like a real API/app endpoint worth emitting."""
    if len(path) < _MIN_PATH_LEN:
        return False
    lower = path.lower()
    if any(lower.endswith(ext) for ext in _SKIP_EXTENSIONS):
        return False
    if lower.startswith("//cdn.") or lower.startswith("//fonts."):
        return False
    return True


@register
class LinkFinderModule(BaseModule):
    name = "linkfinder"
    description = "JavaScript endpoint extraction via regex (no binary needed)"
    watched_events = ["URL"]
    produced_events = ["ENDPOINT"]
    flags = ["active", "web", "js-analysis", "fast"]
    options = {"timeout": 20, "max_js_size_kb": 512}

    async def setup(self) -> bool:
        return True  # pure Python, no binary needed

    async def handle_event(self, event: Event) -> None:
        url = event.data.url
        content_type = event.data.content_type

        if not _is_js_url(url, content_type):
            return

        try:
            import httpx
        except ImportError:
            self._log.warning("httpx not installed")
            return

        self._log.debug("linkfinder: fetching %s", url)

        try:
            async with httpx.AsyncClient(timeout=self.opt("timeout")) as client:
                async with self.guard(f"http:{urlparse(url).hostname or url}"):
                    r = await client.get(url, follow_redirects=True)
                self.inspect_response(r)
                r.raise_for_status()
                # Reject oversized responses.
                size_kb = len(r.content) / 1024
                if size_kb > self.opt("max_js_size_kb"):
                    self._log.debug("linkfinder: %s too large (%.0fKB) — skipping", url, size_kb)
                    return
                js_content = r.text
        except Exception as exc:
            self._log.debug("linkfinder: fetch failed for %s: %s", url, exc)
            return

        base_url = url
        parsed_base = urlparse(url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        seen: set[str] = set()
        count = 0
        for match in _ENDPOINT_RE.finditer(js_content):
            path = match.group(1).strip()
            if not path or not _filter_endpoint(path):
                continue

            # Resolve relative paths against the base URL.
            if path.startswith("//"):
                resolved = f"{parsed_base.scheme}:{path}"
            elif path.startswith("/"):
                resolved = f"{origin}{path}"
            elif path.startswith("http"):
                resolved = path
            else:
                resolved = urljoin(base_url, path)

            if resolved in seen:
                continue
            seen.add(resolved)

            # Only emit paths under the same origin to stay in scope.
            rp = urlparse(resolved)
            if rp.hostname and rp.hostname != parsed_base.hostname:
                continue

            if await self.emit(
                EventType.ENDPOINT,
                EndpointData(url=resolved, method="GET"),
                source_event=event,
            ):
                count += 1

        self._log.info("linkfinder: %d endpoints from %s", count, url)
