"""
jsluice — AST-based JavaScript URL/endpoint mining via the jsluice binary.

The binary-backed complement to the regex/heuristic JS miners (linkfinder,
js_intel, apifinder): jsluice (github.com/BishopFox/jsluice) parses JS with a
tree-sitter AST, so it recovers request URLs **with their method and query/body
parameter names** — including dynamically built ones that a regex misses.

Same trigger surface and fetch path as linkfinder: fires on URL events that look
like JavaScript, fetches the body through the shared limiter/WAF/cache
(`BaseModule.fetch`), writes it to a private temp file, and runs
`jsluice urls <file>` (one guarded subprocess via `run_proc`).

Emission (all scope-gated through `self.emit → stamp_and_publish → ScopeEngine`):
  * ENDPOINT per discovered request (method + param names) — re-enters the
    pipeline so paramfinder turns the params into PARAMETER events;
  * URL for each concrete http(s) target (no `EXPR` dynamic placeholder), so
    httpx_probe / secretfinder / js_intel re-process it;
  * optional FINDING_CANDIDATE from `jsluice secrets` — OFF by default and,
    when on, carries only the detector `kind` + severity (never the secret
    value; secretfinder/trufflehog own secret content).

Watches:  URL
Produces: ENDPOINT, URL, PARAMETER (via paramfinder), FINDING_CANDIDATE (opt-in)
Requires: jsluice on PATH (warn-and-skips otherwise)
"""

from __future__ import annotations

import os
import tempfile
from urllib.parse import urljoin, urlparse

from events.types import (
    EndpointData,
    Event,
    EventType,
    FindingCandidateData,
    UrlData,
)
from modules.base import BaseModule
from modules.registry import register
from modules.web.linkfinder import _is_js_url
from recon.jsluice import build_command, parse_secrets_json, parse_urls_json


@register
class JsluiceModule(BaseModule):
    name = "jsluice"
    description = "AST-based JS URL/endpoint mining via jsluice (tree-sitter)"
    watched_events = ["URL"]
    produced_events = ["ENDPOINT", "URL", "FINDING_CANDIDATE"]
    flags = ["active", "web", "js-analysis"]
    deps_binary = ["jsluice"]
    options = {
        "timeout": 20,          # per-fetch HTTP timeout (s)
        "max_js_size_kb": 512,  # skip JS bodies larger than this
        "proc_timeout": 120,    # per jsluice run (s)
        "secrets": False,       # also run `jsluice secrets` → redacted findings
    }

    async def handle_event(self, event: Event) -> None:
        url = event.data.url
        if not _is_js_url(url, getattr(event.data, "content_type", None)):
            return

        res = await self.fetch(
            url, timeout=int(self.opt("timeout")),
            max_body_kb=int(self.opt("max_js_size_kb")),
        )
        if not res.is_2xx or res.text is None:
            return

        await self._mine(url, res.text, event)

    async def _mine(self, js_url: str, body: str, event: Event) -> None:
        host = urlparse(js_url).hostname or "js"
        tmpdir = tempfile.mkdtemp(prefix="jsluice_")
        path = os.path.join(tmpdir, "body.js")
        try:
            with open(path, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(body)

            urls_out = await self.run_proc(
                build_command(path, mode="urls"),
                timeout=int(self.opt("proc_timeout")),
                bucket=f"jsluice:{host}",
            )
            if urls_out:
                await self._emit_urls(js_url, urls_out, event)

            if self.opt("secrets"):
                sec_out = await self.run_proc(
                    build_command(path, mode="secrets"),
                    timeout=int(self.opt("proc_timeout")),
                    bucket=f"jsluice:{host}",
                )
                if sec_out:
                    await self._emit_secrets(js_url, sec_out, event)
        finally:
            try:
                os.remove(path)
                os.rmdir(tmpdir)
            except OSError:
                pass

    async def _emit_urls(self, js_url: str, out: str, event: Event) -> None:
        endpoints = urls = 0
        seen: set[str] = set()
        for u in parse_urls_json(out):
            resolved = self._resolve(js_url, u.url)
            if not resolved:
                continue
            key = f"{u.method} {resolved}"
            if key in seen:
                continue
            seen.add(key)

            params = list(u.query_params) + list(u.body_params)
            if await self.emit(
                EventType.ENDPOINT,
                EndpointData(url=resolved, method=u.method, parameters=params),
                source_event=event,
            ):
                endpoints += 1

            # A concrete, fetchable URL (no dynamic EXPR placeholder) re-enters
            # the probing/secret pipeline. Endpoint patterns with EXPR stay as
            # ENDPOINT only — they aren't real fetchable URLs.
            p = urlparse(resolved)
            if p.scheme in ("http", "https") and "EXPR" not in resolved:
                if await self.emit(
                    EventType.URL,
                    UrlData(url=resolved, method=u.method, found_via="jsluice"),
                    source_event=event,
                ):
                    urls += 1
        self._log.info("jsluice: %d endpoint(s), %d url(s) from %s",
                       endpoints, urls, js_url)

    async def _emit_secrets(self, js_url: str, out: str, event: Event) -> None:
        count = 0
        for s in parse_secrets_json(out):
            # Only the detector kind + severity — never the secret value.
            if await self.emit(
                EventType.FINDING_CANDIDATE,
                FindingCandidateData(
                    host=urlparse(js_url).hostname or js_url,
                    title=f"jsluice secret indicator: {s.kind}",
                    description=(
                        f"jsluice flagged a '{s.kind}' secret-shaped literal in "
                        f"{js_url}. The value is NOT stored — verify manually, and "
                        f"cross-check secretfinder/trufflehog before reporting."
                    ),
                    category=f"exposed-secret:jsluice:{s.kind}",
                    severity_hint=s.severity if s.severity != "info" else "low",
                    evidence={"detector": s.kind, "severity": s.severity,
                              "source": js_url[:512], "verified": "no"},
                ),
                source_event=event,
            ):
                count += 1
        if count:
            self._log.info("jsluice: %d secret indicator(s) from %s", count, js_url)

    @staticmethod
    def _resolve(js_url: str, ref: str) -> str | None:
        ref = (ref or "").strip()
        if not ref or ref.startswith(("data:", "blob:", "javascript:")):
            return None
        if ref.startswith("//"):
            scheme = urlparse(js_url).scheme or "https"
            return f"{scheme}:{ref}"
        if ref.startswith(("http://", "https://", "/")):
            return urljoin(js_url, ref)
        # relative path
        return urljoin(js_url, ref)
