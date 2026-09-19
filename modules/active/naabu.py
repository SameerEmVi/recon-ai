"""
naabu — Port scanning via the naabu binary.

Reactive module: fires on every IP event, scans for open ports, and
emits OPEN_PORT events.

Default ports: top-1000 ports via naabu's built-in list (same as nmap -F).
Can be overridden with the `ports` option.

Watches:  IP
Produces: OPEN_PORT
"""

from __future__ import annotations

import json
import asyncio
import logging

from events.types import Event, EventType, OpenPortData
from modules.base import BaseModule
from modules.registry import register

log = logging.getLogger(__name__)

_NOT_FOUND_WARNED = False


@register
class NaabuModule(BaseModule):
    name = "naabu"
    description = "Port scanning via naabu binary"
    watched_events = ["IP"]
    produced_events = ["OPEN_PORT"]
    flags = ["active", "port-scan", "slow"]
    options = {
        "ports": "top-1000",   # "top-100", "top-1000", or comma-separated like "80,443,8080"
        "timeout": 120,
    }
    deps_binary = ["naabu"]

    async def handle_event(self, event: Event) -> None:
        global _NOT_FOUND_WARNED
        import shutil
        if not shutil.which("naabu"):
            if not _NOT_FOUND_WARNED:
                self._log.warning("naabu not found — port scanning disabled")
                _NOT_FOUND_WARNED = True
            return

        host = event.data.address
        ports_arg = self.opt("ports")

        # naabu flag: -top-ports 1000, or -p 80,443,8080
        if ports_arg == "top-1000":
            port_flags = ["-top-ports", "1000"]
        elif ports_arg == "top-100":
            port_flags = ["-top-ports", "100"]
        else:
            port_flags = ["-p", str(ports_arg)]

        cmd = ["naabu", "-host", host, "-silent", "-json"] + port_flags
        self._log.debug("exec: %s", " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.opt("timeout")
            )
        except asyncio.TimeoutError:
            self._log.warning("naabu timed out for %s", host)
            return
        except Exception as exc:
            self._log.error("naabu failed: %s", exc)
            return

        count = 0
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = str(obj.get("ip", host))
            port = obj.get("port")
            if port is None:
                continue
            try:
                port = int(port)
            except (ValueError, TypeError):
                continue
            if await self.emit(
                EventType.OPEN_PORT,
                OpenPortData(host=ip, port=port, protocol="tcp"),
                source_event=event,
            ):
                count += 1

        self._log.info("naabu: %d open ports on %s", count, host)
