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
    # Port discovery is high-value recon. Without this the planner derives
    # value=MEDIUM(3) and (via the "slow" flag) cost=HIGH(8) → score -5, which is
    # below the default min_value(0), so the port scanner was being silently
    # skipped. HIGH value makes the score net-neutral so it runs by default.
    expected_value = 8
    options = {
        "ports": "top-1000",   # "top-100", "top-1000", "full", or "80,443,8080"
        "timeout": 120,
        # naabu's own default is CONNECT ("c"); SYN ("s") needs raw sockets
        # (Npcap + admin on Windows). Keep connect so it works unprivileged.
        "scan_type": "connect",   # "connect" | "syn"
    }
    deps_binary = ["naabu"]

    def _port_flags(self) -> list[str]:
        ports_arg = str(self.opt("ports") or "top-1000")
        if ports_arg == "top-1000":
            return ["-top-ports", "1000"]
        if ports_arg == "top-100":
            return ["-top-ports", "100"]
        if ports_arg == "full":
            return ["-p", "-"]   # naabu: full 1-65535
        return ["-p", ports_arg]

    def _scan_flag(self) -> str:
        return "s" if str(self.opt("scan_type") or "connect").lower() in ("s", "syn") else "c"

    async def handle_event(self, event: Event) -> None:
        global _NOT_FOUND_WARNED
        import shutil
        if not shutil.which("naabu"):
            if not _NOT_FOUND_WARNED:
                self._log.warning("naabu not found — port scanning disabled")
                _NOT_FOUND_WARNED = True
            return

        host = event.data.address
        # Arg-injection guard: a target that could parse as a naabu flag must
        # never reach the binary (hostnames/IPs come from target-controlled DNS).
        if not host or host.startswith("-"):
            self._log.warning("naabu: refusing suspicious target %r", host)
            return

        cmd = (["naabu", "-host", host, "-silent", "-json", "-s", self._scan_flag()]
               + self._port_flags())
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
