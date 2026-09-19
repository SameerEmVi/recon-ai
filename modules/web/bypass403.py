"""
bypass403 — HTTP 403 bypass detection (pure Python, no binary).

Reactive: fires on HTTP_SERVICE events where the status code is 403.
Tries a battery of common bypass techniques (path manipulation, header
injection, method overrides) and emits a FINDING_CANDIDATE if any
technique returns a 2xx response.

Watches:  HTTP_SERVICE
Produces: FINDING_CANDIDATE
"""

from __future__ import annotations

from urllib.parse import urlparse

from events.types import Event, EventType, FindingCandidateData
from modules.base import BaseModule
from modules.registry import register

# (technique_label, request_kwargs_overrides)
# Each entry describes one bypass attempt.
_TECHNIQUES: list[tuple[str, dict]] = [
    # Path variations
    ("path-double-slash",   {"path_prefix": "//"}),
    ("path-trailing-slash", {"path_suffix": "/"}),
    ("path-dot-slash",      {"path_prefix": "/./"}),
    ("path-semicolon",      {"path_suffix": ";/"}),
    # Header-based bypass
    ("header-x-original-url",     {"headers": {"X-Original-URL": "{path}"}}),
    ("header-x-rewrite-url",      {"headers": {"X-Rewrite-URL": "{path}"}}),
    ("header-x-custom-ip-local",  {"headers": {"X-Custom-IP-Authorization": "127.0.0.1"}}),
    ("header-x-forwarded-for",    {"headers": {"X-Forwarded-For": "127.0.0.1"}}),
    ("header-x-host-localhost",   {"headers": {"X-Host": "localhost"}}),
    # URL encoding
    ("path-url-encoded-slash",    {"path_prefix": "/%2f"}),
    # Method override
    ("method-post",               {"method": "POST"}),
    ("method-put",                {"method": "PUT"}),
]


@register
class Bypass403Module(BaseModule):
    name = "bypass403"
    description = "HTTP 403 bypass detection via path/header tricks (pure Python)"
    watched_events = ["HTTP_SERVICE"]
    produced_events = ["FINDING_CANDIDATE"]
    flags = ["active", "web", "bypass", "fast"]
    options = {"timeout": 10}

    async def setup(self) -> bool:
        return True  # pure Python

    async def handle_event(self, event: Event) -> None:
        if event.data.status_code != 403:
            return

        url = event.data.url
        if not url:
            return

        try:
            import httpx
        except ImportError:
            self._log.warning("httpx not installed")
            return

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        host = parsed.hostname or url

        bypasses: list[dict] = []

        try:
            async with httpx.AsyncClient(
                timeout=self.opt("timeout"),
                follow_redirects=False,
            ) as client:
                for label, spec in _TECHNIQUES:
                    result = await self._try(client, base, path, label, spec)
                    if result:
                        bypasses.append(result)
        except Exception as exc:
            self._log.debug("bypass403: error on %s: %s", url, exc)
            return

        if not bypasses:
            return

        best = sorted(bypasses, key=lambda b: b["status"])[0]
        all_techniques = ", ".join(b["technique"] for b in bypasses)

        await self.emit(
            EventType.FINDING_CANDIDATE,
            FindingCandidateData(
                host=host,
                title="403 Bypass Detected",
                description=(
                    f"Access control bypass on {url} via: {all_techniques}. "
                    f"Best result: HTTP {best['status']} using {best['technique']}."
                ),
                category="403-bypass",
                severity_hint="medium",
                evidence={
                    "original_url": url[:512],
                    "successful_techniques": all_techniques[:256],
                    "best_technique": best["technique"][:64],
                    "best_status": str(best["status"]),
                    "best_url": best["url"][:512],
                },
            ),
            source_event=event,
        )
        self._log.info("bypass403: bypass found on %s via [%s]", url, all_techniques)

    async def _try(
        self, client, base: str, path: str, label: str, spec: dict
    ) -> dict | None:
        try:
            method = spec.get("method", "GET")
            headers = {}

            # Build the target URL.
            prefix = spec.get("path_prefix", "")
            suffix = spec.get("path_suffix", "")
            if prefix:
                # Insert prefix after the leading scheme+host.
                target_url = f"{base}{prefix}{path.lstrip('/')}"
            elif suffix:
                target_url = f"{base}{path}{suffix}"
            else:
                target_url = f"{base}{path}"

            # Resolve header templates.
            for k, v in spec.get("headers", {}).items():
                headers[k] = v.replace("{path}", path)

            from urllib.parse import urlparse
            async with self.guard(f"http:{urlparse(base).hostname or base}"):
                r = await client.request(method, target_url, headers=headers)
            self.inspect_response(r)
            if 200 <= r.status_code < 300:
                return {"technique": label, "status": r.status_code, "url": target_url}
        except Exception:
            pass
        return None
