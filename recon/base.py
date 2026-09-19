"""Base class for subprocess-based recon tool wrappers."""

from __future__ import annotations

import asyncio
import logging
import shutil
from abc import ABC
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from controller.controller import ScanController

log = logging.getLogger(__name__)


class BaseReconTool(ABC):
    """Thin async wrapper around an external binary.

    Concrete subclasses set `binary` and implement their run/resolve/probe
    methods. If the binary is not on PATH, the wrapper warns and returns
    empty output — the scan continues without it.
    """

    binary: str = ""

    def __init__(self, controller: "ScanController") -> None:
        self._ctrl = controller

    def available(self) -> bool:
        return bool(shutil.which(self.binary))

    async def _run(
        self, args: list[str], timeout: int = 300, stdin_data: str | None = None
    ) -> list[str]:
        """Run `binary args`, return stdout lines. Stderr is debug-logged.

        If `stdin_data` is given, it is written to the process stdin — required
        by tools like dnsx that read their target list from stdin rather than a flag.
        """
        if not self.available():
            log.warning("%s not found — skipping (install it or add to PATH)", self.binary)
            return []

        cmd = [self.binary] + args
        log.debug("exec: %s", " ".join(cmd))
        from ratelimit import get_limiter
        limiter = get_limiter(self._ctrl)
        try:
            # Hold a concurrency slot for the whole subprocess and space starts
            # by the configured rate (and any active WAF backoff).
            async with limiter.guard(bucket=self.binary):
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                feed = stdin_data.encode() if stdin_data is not None else None
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=feed), timeout=timeout
                )
            if stderr:
                log.debug("%s stderr: %s", self.binary, stderr.decode(errors="replace")[:512])
            return stdout.decode(errors="replace").splitlines()
        except asyncio.TimeoutError:
            log.error("%s timed out after %ds", self.binary, timeout)
            return []
        except Exception as exc:
            log.error("%s failed: %s", self.binary, exc)
            return []
