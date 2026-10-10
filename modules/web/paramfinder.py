"""
paramfinder — request-parameter discovery (pure Python, no binary).

Reactive: fires on URL and ENDPOINT events and extracts request parameters
deterministically from the material already in scope:

  - query-string parameters parsed from the event's URL (?a=1&b=2)
  - parameter names carried on ENDPOINT events (EndpointData.parameters)

Each distinct parameter becomes a PARAMETER event. This is the producer for
the PARAMETER event type — the dedup key (param:<url>:<location>:<name>) and
the ParameterData model already existed; nothing emitted them until now.

No network I/O: parameters are read out of URLs other modules already
discovered (crt_sh/wayback/gau/katana/ffuf/linkfinder), so this stays cheap
and fully deterministic.

Watches:  URL, ENDPOINT
Produces: PARAMETER
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

from events.types import Event, EventType, ParameterData
from modules.base import BaseModule
from modules.registry import register

# Query-string keys longer than this are almost certainly not real params
# (base64 blobs, encoded state, etc.) — skip to avoid noise.
_MAX_NAME_LEN = 128


@register
class ParamFinderModule(BaseModule):
    name = "paramfinder"
    description = "Request-parameter discovery from URLs and endpoints (no binary)"
    watched_events = ["URL", "ENDPOINT"]
    produced_events = ["PARAMETER"]
    flags = ["active", "web", "param-discovery", "fast"]

    async def setup(self) -> bool:
        return True  # pure Python, no binary needed

    async def handle_event(self, event: Event) -> None:
        url = getattr(event.data, "url", None)
        if not url:
            return

        count = 0
        seen: set[str] = set()

        # 1. Query-string parameters carried on the URL itself.
        query = urlparse(url).query
        if query:
            for name, value in parse_qsl(query, keep_blank_values=True):
                name = name.strip()
                if not name or len(name) > _MAX_NAME_LEN or name in seen:
                    continue
                seen.add(name)
                # sample_value is sanitized+capped by ParameterData's validator.
                if await self.emit(
                    EventType.PARAMETER,
                    ParameterData(
                        url=url,
                        name=name,
                        location="query",
                        sample_value=value or None,
                    ),
                    source_event=event,
                ):
                    count += 1

        # 2. Parameter names an ENDPOINT event already enumerated.
        if event.type == EventType.ENDPOINT:
            for name in getattr(event.data, "parameters", []) or []:
                name = (name or "").strip()
                if not name or len(name) > _MAX_NAME_LEN or name in seen:
                    continue
                seen.add(name)
                if await self.emit(
                    EventType.PARAMETER,
                    ParameterData(url=url, name=name, location="query"),
                    source_event=event,
                ):
                    count += 1

        if count:
            self._log.info("paramfinder: %d parameters from %s", count, url)
