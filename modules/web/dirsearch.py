"""
dirsearch — native directory / file content discovery (pure Python, no binary).

recon-ai's own forced-browsing engine, ported from dirsearch
(https://github.com/maurosoria/dirsearch). This needs
**no external binary** — it fetches every candidate path itself through the
shared rate limiter / WAF backoff, and uses the ported `recon/dirsearch.py`
engine for dictionary generation and wildcard/false-positive filtering (the part
that makes forced browsing usable against dynamic apps that answer 200 for
everything).

Reactive: fires on HTTP_SERVICE events (the vhost-aware host+scheme). For each
live service it:
  1. builds the path dictionary from the bundled/seclists wordlist + extensions,
  2. probes two random paths to learn the site's wildcard baseline (Scanner),
  3. requests each path concurrently under `self.guard()` (rps + concurrency +
     WAF backoff), keeping only responses the Scanner and status/size filters
     accept,
  4. emits a scope-gated `URL` event per real find, and
  5. optionally recurses into discovered directories up to `max_recursion_depth`.

Every emission goes through `self.emit → controller.stamp_and_publish →
ScopeEngine`, so discovered URLs are scope-checked, dedup'd, and re-enter the
pipeline (paramfinder / secretfinder / apifinder / httpx_probe react to them).
Target-controlled strings are sanitized/capped by the `UrlData` validator.

Watches:  HTTP_SERVICE
Produces: URL
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from urllib.parse import urlparse

from events.types import Event, EventType, UrlData
from modules.base import BaseModule
from modules.registry import register
from recon.dirsearch import (
    DEFAULT_EXCLUDE_STATUS,
    Dictionary,
    DictionaryOptions,
    Response,
    Scanner,
    generate_random_string,
    is_valid_status,
    parse_sizes,
    parse_status_codes,
)

# Seclists locations searched before falling back to the bundled list.
_SECLISTS_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
    "/opt/seclists/Discovery/Web-Content/common.txt",
    "C:/tools/seclists/Discovery/Web-Content/common.txt",
]
_WORDLIST_DIR = Path(__file__).parent.parent.parent / "wordlists"
_BUNDLED_WORDLIST = _WORDLIST_DIR / "common.txt"
_BUNDLED_BIG_WORDLIST = _WORDLIST_DIR / "big.txt"

# Statuses that mark a discovered path as a directory worth recursing into.
_DIR_STATUSES = {200, 201, 301, 302, 307, 308, 401, 403}


def _resolve_wordlist(size: str = "common") -> str | None:
    """Return the best available wordlist path for the requested size."""
    if size == "big" and _BUNDLED_BIG_WORDLIST.exists():
        return str(_BUNDLED_BIG_WORDLIST)
    for candidate in _SECLISTS_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    if _BUNDLED_WORDLIST.exists():
        return str(_BUNDLED_WORDLIST)
    return None


@register
class DirsearchModule(BaseModule):
    name = "dirsearch"
    description = "Native directory/file content discovery (dirsearch port, no binary)"
    watched_events = ["HTTP_SERVICE"]
    produced_events = ["URL"]
    flags = ["active", "web", "content-discovery", "slow"]
    options = {
        "timeout": 10,                # per-request timeout (seconds)
        "concurrency": 20,            # in-module parallel requests (also bounded by the global limiter)
        "wordlist": "common",         # "common" | "big" | absolute path
        "extensions": "php,html,js,txt,json,bak,old,zip,config",
        "force_extensions": False,    # append .ext to extension-less words
        "overwrite_extensions": False,
        "exclude_extensions": "",     # comma list, e.g. "png,jpg"
        "prefixes": "",               # comma list
        "suffixes": "",               # comma list, e.g. "~,.bak"
        "include_status": "",         # comma/range list; wins over exclude when set
        "exclude_status": "404",      # comma/range list
        "exclude_sizes": "",          # comma list of byte sizes (0, 1024, 2k, ...)
        "max_paths": 5000,            # cap dictionary size per service
        "max_results": 1000,          # cap emitted URLs per service
        "max_body_kb": 512,           # skip bodies larger than this for the wildcard diff
        "recursive": True,
        "max_recursion_depth": 2,
        "user_agent": "recon-ai/dirsearch",
    }
    # No deps_binary — this is the whole point. httpx (Python lib) is required.
    deps_binary: list[str] = []

    async def setup(self) -> bool:
        try:
            import httpx  # noqa: F401
        except ImportError:
            self._log.warning("httpx (python lib) not installed — dirsearch disabled")
            return False
        return True

    # ── option parsing helpers ────────────────────────────────────────────────
    def _csv(self, name: str) -> list[str]:
        raw = self.opt(name) or ""
        return [p.strip() for p in str(raw).split(",") if p.strip()]

    def _build_dictionary(self) -> Dictionary | None:
        wl_opt = self.opt("wordlist")
        if os.path.isabs(str(wl_opt)) and Path(str(wl_opt)).exists():
            wl_path: str | None = str(wl_opt)
        else:
            wl_path = _resolve_wordlist(str(wl_opt))
        if not wl_path or not Path(wl_path).exists():
            self._log.warning("dirsearch: no wordlist found — skipping content discovery")
            return None

        try:
            text = Path(wl_path).read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            self._log.warning("dirsearch: could not read wordlist %s: %s", wl_path, exc)
            return None

        opt = DictionaryOptions(
            extensions=self._csv("extensions"),
            prefixes=self._csv("prefixes"),
            suffixes=self._csv("suffixes"),
            force_extensions=bool(self.opt("force_extensions")),
            overwrite_extensions=bool(self.opt("overwrite_extensions")),
            exclude_extensions=self._csv("exclude_extensions"),
        )
        dictionary = Dictionary.from_text(text, opt)
        self._log.info(
            "dirsearch: dictionary = %d paths (wordlist=%s)", len(dictionary), wl_path
        )
        return dictionary

    # ── HTTP ──────────────────────────────────────────────────────────────────
    async def _request(self, client, url: str) -> Response | None:
        """Fetch one URL through the shared limiter; return a Response or None."""
        max_bytes = int(self.opt("max_body_kb")) * 1024
        try:
            async with self.guard(f"http:{urlparse(url).hostname or url}"):
                r = await client.get(url, follow_redirects=False)
            self.inspect_response(r)
            body = ""
            content = r.content or b""
            if len(content) <= max_bytes:
                body = content.decode("utf-8", "replace")
            location = r.headers.get("location", "") if r.headers else ""
            return Response(
                status=r.status_code, body=body, redirect=location or "", url=url
            )
        except Exception as exc:
            self._log.debug("dirsearch: request failed for %s: %s", url, exc)
            return None

    async def _make_scanner(self, client, base: str) -> Scanner | None:
        """Probe two random paths under `base` to learn its wildcard baseline."""
        token1 = generate_random_string()
        token2 = generate_random_string()
        r1 = await self._request(client, f"{base}/{token1}")
        if r1 is None:
            return None
        r2 = await self._request(client, f"{base}/{token2}")
        return Scanner(r1, r2, token=token1)

    @staticmethod
    def _is_directory(path: str, status: int) -> bool:
        """Whether a found path is a directory worth recursing into."""
        if status not in _DIR_STATUSES:
            return False
        tail = path.rstrip("/").rsplit("/", 1)[-1]
        return path.endswith("/") or "." not in tail

    async def _scan_base(
        self,
        client,
        base_url: str,
        paths: list[str],
        include: set[int],
        exclude: set[int],
        exclude_sizes: set[int],
    ) -> list[tuple[str, Response]]:
        """Run the full dictionary against one base URL, returning real finds
        after wildcard/status/size filtering. Bounded concurrency; each request
        still passes through the global rate limiter via `_request`."""
        scanner = await self._make_scanner(client, base_url)
        sem = asyncio.Semaphore(int(self.opt("concurrency")))
        results: list[tuple[str, Response]] = []

        async def worker(path: str) -> None:
            target = f"{base_url}/{path}"
            async with sem:
                resp = await self._request(client, target)
            if resp is None:
                return
            if not is_valid_status(resp.status, include, exclude):
                return
            if exclude_sizes and resp.length in exclude_sizes:
                return
            if scanner is not None and not scanner.check(resp):
                return
            results.append((path, resp))

        await asyncio.gather(*(worker(p) for p in paths))
        return results

    # ── main handler ──────────────────────────────────────────────────────────
    async def handle_event(self, event: Event) -> None:
        url = event.data.url
        if not url:
            return
        try:
            import httpx
        except ImportError:
            return

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return
        root_base = f"{parsed.scheme}://{parsed.netloc}"

        dictionary = self._build_dictionary()
        if dictionary is None:
            return
        paths = dictionary.entries()[: int(self.opt("max_paths"))]

        include = parse_status_codes(self.opt("include_status"))
        exclude = parse_status_codes(self.opt("exclude_status")) or set(DEFAULT_EXCLUDE_STATUS)
        exclude_sizes = parse_sizes(self.opt("exclude_sizes"))

        headers = {"User-Agent": str(self.opt("user_agent"))}
        limits = httpx.Limits(max_connections=int(self.opt("concurrency")) + 5)
        max_results = int(self.opt("max_results"))
        max_depth = int(self.opt("max_recursion_depth")) if self.opt("recursive") else 0

        emitted = 0
        # BFS queue of (base_url, depth). dirsearch recurses INTERNALLY into
        # discovered directories rather than re-entering the event bus.
        queue: list[tuple[str, int]] = [(root_base, 0)]
        seen_bases: set[str] = {root_base}

        async with httpx.AsyncClient(
            timeout=float(self.opt("timeout")),
            headers=headers,
            verify=False,
            limits=limits,
        ) as client:
            while queue and emitted < max_results:
                base_url, depth = queue.pop(0)
                results = await self._scan_base(
                    client, base_url, paths, include, exclude, exclude_sizes
                )
                for path, resp in results:
                    if emitted >= max_results:
                        break
                    found_url = f"{base_url}/{path}"
                    if await self.emit(
                        EventType.URL,
                        UrlData(
                            url=found_url,
                            status_code=resp.status,
                            found_via="dirsearch",
                        ),
                        source_event=event,
                        distance=event.distance + depth,
                    ):
                        emitted += 1
                    if depth < max_depth and self._is_directory(path, resp.status):
                        sub_base = f"{base_url}/{path.rstrip('/')}"
                        if sub_base not in seen_bases:
                            seen_bases.add(sub_base)
                            queue.append((sub_base, depth + 1))

        self._log.info(
            "dirsearch: %d paths found under %s (bases scanned=%d)",
            emitted, root_base, len(seen_bases),
        )
