"""
fingerprint — Technology detection from HTTP service metadata.

Reactive module: fires on HTTP_SERVICE events and derives TECHNOLOGY
events from the Server header, title, redirect patterns, and common
response signatures. No external binary needed.

This replaces the placeholder reflex_fingerprint.

Watches:  HTTP_SERVICE
Produces: TECHNOLOGY
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from events.types import Event, EventType, TechnologyData
from modules.base import BaseModule
from modules.registry import register

# (pattern_on_server_header, name, version_group)
_SERVER_SIGS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"nginx[/ ]([\d.]+)?", re.I),       "nginx"),
    (re.compile(r"apache[/ ]([\d.]+)?", re.I),      "Apache"),
    (re.compile(r"microsoft-iis[/ ]([\d.]+)?", re.I), "IIS"),
    (re.compile(r"litespeed", re.I),                 "LiteSpeed"),
    (re.compile(r"openresty[/ ]([\d.]+)?", re.I),   "OpenResty"),
    (re.compile(r"caddy[/ ]([\d.]+)?", re.I),       "Caddy"),
    (re.compile(r"gunicorn[/ ]([\d.]+)?", re.I),    "Gunicorn"),
    (re.compile(r"tomcat[/ ]([\d.]+)?", re.I),      "Tomcat"),
    (re.compile(r"jetty[/ ]([\d.]+)?", re.I),       "Jetty"),
]

_TITLE_SIGS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"wordpress", re.I),     "WordPress",  "cms"),
    (re.compile(r"drupal", re.I),        "Drupal",     "cms"),
    (re.compile(r"joomla", re.I),        "Joomla",     "cms"),
    (re.compile(r"confluence", re.I),    "Confluence",  "wiki"),
    (re.compile(r"jira", re.I),          "Jira",        "project-mgmt"),
    (re.compile(r"jenkins", re.I),       "Jenkins",     "ci-cd"),
    (re.compile(r"gitlab", re.I),        "GitLab",      "devops"),
    (re.compile(r"grafana", re.I),       "Grafana",     "monitoring"),
    (re.compile(r"kibana", re.I),        "Kibana",      "logging"),
    (re.compile(r"elastic", re.I),       "Elasticsearch", "database"),
    (re.compile(r"phpmy.?admin", re.I),  "phpMyAdmin",  "database-admin"),
    (re.compile(r"adminer", re.I),       "Adminer",     "database-admin"),
    (re.compile(r"django", re.I),        "Django",      "framework"),
    (re.compile(r"laravel", re.I),       "Laravel",     "framework"),
    (re.compile(r"next\.?js", re.I),     "Next.js",     "framework"),
    (re.compile(r"react", re.I),         "React",       "framework"),
]

_URL_PATH_SIGS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"/wp-content/|/wp-admin/", re.I), "WordPress", "cms"),
    (re.compile(r"/sites/default/|/misc/drupal", re.I), "Drupal", "cms"),
    (re.compile(r"/_next/static/", re.I), "Next.js", "framework"),
    (re.compile(r"/rails/|/assets/application-", re.I), "Rails", "framework"),
]


def _parse_version(pattern: re.Pattern, text: str) -> str | None:
    m = pattern.search(text)
    if m:
        return m.group(1) if m.lastindex else None
    return None


@register
class FingerprintModule(BaseModule):
    name = "fingerprint"
    description = "Technology detection from HTTP service metadata (no binary needed)"
    watched_events = ["HTTP_SERVICE"]
    produced_events = ["TECHNOLOGY"]
    flags = ["active", "http", "fast", "web"]
    options = {}

    async def setup(self) -> bool:
        return True  # No binary needed — always available.

    async def handle_event(self, event: Event) -> None:
        d = event.data
        url = d.url or ""
        server = d.server or ""
        title = d.title or ""

        host = urlparse(url).hostname or ""
        if not host:
            return

        emitted: set[str] = set()

        async def _emit(name: str, version: str | None = None, category: str | None = None) -> None:
            key = f"{name}:{version}"
            if key in emitted:
                return
            emitted.add(key)
            await self.emit(
                EventType.TECHNOLOGY,
                TechnologyData(host=host, name=name, version=version, category=category),
                source_event=event,
            )

        # Server header fingerprinting.
        for pattern, tech_name in _SERVER_SIGS:
            if pattern.search(server):
                version = _parse_version(pattern, server)
                await _emit(tech_name, version, "server")

        # Title-based fingerprinting.
        for pattern, tech_name, category in _TITLE_SIGS:
            if pattern.search(title):
                await _emit(tech_name, None, category)

        # URL path signatures.
        for pattern, tech_name, category in _URL_PATH_SIGS:
            if pattern.search(url):
                await _emit(tech_name, None, category)
