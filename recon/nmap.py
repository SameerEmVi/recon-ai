"""
nmap wrapper — service/version detection on already-discovered open ports.

This is the deep-dive half of the "naabu discovers, nmap identifies" combo:
naabu finds open ports fast; nmap runs `-sV` against those ports to name the
service and version. Output is parsed from nmap's XML (`-oX -`) which is the
stable, machine-readable format.

Safe by default: `-sV -Pn -n` only. No NSE scripts (`-sC`/`--script`), no OS
detection (`-O`, needs root), no aggressive `-A`. Callers may opt into scripts.

Runs through the shared RateLimiter like every other outbound tool.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET

log = logging.getLogger(__name__)

_NOT_FOUND_WARNED = False


@dataclass
class NmapService:
    port: int
    protocol: str
    state: str
    service: str                       # e.g. "ssh", "http"
    product: str | None = None         # e.g. "OpenSSH"
    version: str | None = None         # e.g. "8.4p1 Debian 5"
    extrainfo: str | None = None       # e.g. "protocol 2.0"
    cpe: list[str] = field(default_factory=list)

    @property
    def banner(self) -> str:
        """Human-readable 'product version (extrainfo)' summary."""
        parts = [p for p in (self.product, self.version) if p]
        s = " ".join(parts)
        if self.extrainfo:
            s = f"{s} ({self.extrainfo})" if s else self.extrainfo
        return s.strip()


class NmapWrapper:
    def __init__(self, timeout: int = 180, limiter=None) -> None:
        self._timeout = timeout
        from ratelimit import NOOP
        self._limiter = limiter if limiter is not None else NOOP

    async def scan(
        self,
        host: str,
        ports: str,
        *,
        scripts: str | None = None,
        version_intensity: int | None = None,
    ) -> list[NmapService]:
        """Run `nmap -sV` on `host` for `ports` (e.g. "22" or "22,80,443").

        Returns a list of NmapService. Empty list on any failure (fail-soft:
        recon must continue even if nmap is missing or errors).
        """
        global _NOT_FOUND_WARNED

        # Refuse a target that would be parsed as an nmap flag (arg-injection guard).
        if not host or host.startswith("-"):
            log.warning("[nmap] refusing suspicious target %r", host)
            return []

        cmd = ["nmap", "-sV", "-Pn", "-n", "-T4", "-p", str(ports)]
        if version_intensity is not None:
            cmd += ["--version-intensity", str(int(version_intensity))]
        if scripts:
            # Opt-in NSE. Caller owns the safety of whatever category/script it passes.
            cmd += ["--script", scripts]
        cmd += ["-oX", "-", "--", host]
        log.debug("[nmap] %s", " ".join(cmd))

        async with self._limiter.guard(f"nmap:{host}"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                if not _NOT_FOUND_WARNED:
                    log.warning("[nmap] binary not found — service detection skipped")
                    _NOT_FOUND_WARNED = True
                return []

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self._timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                log.warning("[nmap] timed out after %ds on %s", self._timeout, host)
                return []

        if stderr:
            log.debug("[nmap] stderr: %s", stderr.decode(errors="replace")[:512])

        return self._parse_xml(stdout.decode(errors="replace"))

    @staticmethod
    def _parse_xml(xml_text: str) -> list[NmapService]:
        if not xml_text.strip():
            return []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            log.debug("[nmap] XML parse error: %s", exc)
            return []

        services: list[NmapService] = []
        for port_el in root.iter("port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state != "open":
                continue
            try:
                port = int(port_el.get("portid", "0"))
            except (TypeError, ValueError):
                continue
            proto = port_el.get("protocol", "tcp")

            svc_el = port_el.find("service")
            if svc_el is not None:
                name = svc_el.get("name", "unknown")
                product = svc_el.get("product")
                version = svc_el.get("version")
                extrainfo = svc_el.get("extrainfo")
                cpe = [c.text for c in svc_el.findall("cpe") if c.text]
            else:
                name, product, version, extrainfo, cpe = "unknown", None, None, None, []

            services.append(
                NmapService(
                    port=port, protocol=proto, state=state, service=name,
                    product=product, version=version, extrainfo=extrainfo, cpe=cpe,
                )
            )
        return services
