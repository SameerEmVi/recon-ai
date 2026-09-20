"""
Normalize parsers — pure functions that convert raw tool output into typed EventData.

These are the only place that touches raw bytes/text from external tools.
Input is untrusted. Output is a validated Pydantic model (or None if the line
is unparseable / empty).

The Pydantic models enforce the trust boundary: length caps and control-char
stripping happen in the model validators, not here. Parsers stay simple.
"""

from __future__ import annotations

import json
import logging

from events.types import DnsRecordData, HttpServiceData, IpData, SubdomainData

log = logging.getLogger(__name__)

_IP_RECORD_TYPES = frozenset({"A", "AAAA"})


def parse_subfinder_line(line: str) -> SubdomainData | None:
    """Parse one line of subfinder -silent output: just a bare hostname."""
    hostname = line.strip().lower()
    if not hostname:
        return None
    return SubdomainData(hostname=hostname, source="subfinder")


def parse_dnsx_line(
    line: str, hostname: str
) -> tuple[DnsRecordData, IpData | None] | None:
    """Parse one line of `dnsx -resp` output: 'hostname [RTYPE] value'.

    Returns a (DnsRecordData, IpData | None) pair, or None if unparseable.
    IpData is populated only for A/AAAA records.
    """
    parts = line.strip().split()
    if len(parts) < 3:
        return None

    record_type = parts[1].strip("[]").upper()
    value = parts[2].strip("[]")

    dns = DnsRecordData(hostname=hostname, record_type=record_type, value=value)
    ip = IpData(address=value, resolved_from=hostname) if record_type in _IP_RECORD_TYPES else None
    return dns, ip


def parse_httpx_json(line: str, fallback_host: str = "") -> HttpServiceData | None:
    """Parse one line of `httpx -json` output.

    Returns HttpServiceData or None if the line is blank or not valid JSON.
    """
    line = line.strip()
    if not line:
        return None
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        log.debug("httpx non-json line: %s", line[:128])
        return None

    # httpx renamed JSON keys from hyphens to underscores; accept both.
    status = record.get("status_code", record.get("status-code"))
    if status is None:
        return None

    # httpx -td emits a "tech" array (Wappalyzer). Accept "tech"/"technologies".
    techs = record.get("tech", record.get("technologies")) or []
    if not isinstance(techs, list):
        techs = []

    return HttpServiceData(
        url=record.get("url", f"http://{fallback_host}"),
        status_code=status,
        title=record.get("title"),
        server=record.get("webserver"),
        content_length=record.get("content_length", record.get("content-length")),
        redirect_location=record.get("location"),
        technologies=[str(t) for t in techs],
    )


# ── WhatWeb ─────────────────────────────────────────────────────────────────────

# WhatWeb plugins that are metadata, not technologies — skipped on normalization.
_WHATWEB_SKIP = {
    "country", "ip", "title", "uncommonheaders", "html5", "script",
    "meta-refresh-redirect", "cookies", "httponly", "email",
    "interestingstrings", "via-proxy", "index-of", "allow",
}


def parse_whatweb_json(text: str) -> list[dict]:
    """Parse `whatweb --log-json` output into normalized technology dicts.

    Accepts a JSON array, a single JSON object, or NDJSON. Returns a list of
    {"target": str, "name": str, "version": str | None}, de-duplicated and with
    metadata plugins (Country/IP/Title/…) filtered out. Never raises.
    """
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []

    out: list[dict] = []
    seen: set[tuple] = set()
    for rec in data:
        if not isinstance(rec, dict):
            continue
        target = str(rec.get("target", ""))
        plugins = rec.get("plugins", {})
        if not isinstance(plugins, dict):
            continue
        for name, info in plugins.items():
            if not name or name.lower() in _WHATWEB_SKIP:
                continue
            version = None
            if isinstance(info, dict):
                vers = info.get("version")
                if isinstance(vers, list) and vers:
                    version = str(vers[0])
                elif isinstance(vers, str) and vers:
                    version = vers
            key = (target, name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            out.append({"target": target, "name": str(name), "version": version})
    return out
