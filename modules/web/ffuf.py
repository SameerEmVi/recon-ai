"""
ffuf — Directory and file content discovery via ffuf binary.

Reactive: fires on HTTP_SERVICE events. Runs ffuf against the target URL
with a bundled wordlist (or a user-specified one). Emits URL events for
every path that returns an interesting status code.

Watches:  HTTP_SERVICE
Produces: URL
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urljoin, urlparse

from events.types import Event, EventType, UrlData
from modules.base import BaseModule
from modules.registry import register

# Seclists locations searched in order before falling back to bundled list.
_SECLISTS_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
    "/opt/seclists/Discovery/Web-Content/common.txt",
    "C:/tools/seclists/Discovery/Web-Content/common.txt",
]
_BUNDLED_WORDLIST = Path(__file__).parent.parent.parent / "wordlists" / "common.txt"
_BUNDLED_BIG_WORDLIST = Path(__file__).parent.parent.parent / "wordlists" / "big.txt"

# Status codes considered interesting enough to emit as URL events.
_INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}


def _resolve_wordlist(size: str = "common") -> str:
    """Return the best available wordlist path for the requested size."""
    if size == "big":
        if _BUNDLED_BIG_WORDLIST.exists():
            return str(_BUNDLED_BIG_WORDLIST)
    for candidate in _SECLISTS_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return str(_BUNDLED_WORDLIST)


@register
class FfufModule(BaseModule):
    name = "ffuf"
    description = "Directory/file content discovery via ffuf binary"
    watched_events = ["HTTP_SERVICE"]
    produced_events = ["URL"]
    flags = ["active", "web", "content-discovery", "slow"]
    options = {
        "timeout": 300,
        "threads": 40,
        "wordlist": "common",     # "common" | "big" | absolute path
        "match_codes": "200,201,204,301,302,307,403,405,500",
        "max_results": 1000,
    }
    deps_binary = ["ffuf"]

    async def handle_event(self, event: Event) -> None:
        url = event.data.url
        if not url:
            return

        # Normalize: strip path so we fuzz from the root.
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        wordlist_opt = self.opt("wordlist")
        if os.path.isabs(wordlist_opt) and Path(wordlist_opt).exists():
            wordlist_path = wordlist_opt
        else:
            wordlist_path = _resolve_wordlist(wordlist_opt)

        if not Path(wordlist_path).exists():
            self._log.warning("ffuf: no wordlist found — skipping content discovery for %s", base_url)
            return

        # Write ffuf output to a temp file.
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp:
            output_file = tmp.name

        try:
            cmd = [
                "ffuf",
                "-u", f"{base_url}/FUZZ",
                "-w", wordlist_path,
                "-o", output_file,
                "-of", "json",
                "-mc", self.opt("match_codes"),
                "-t", str(self.opt("threads")),
                "-timeout", "10",
                "-s",            # silent — no progress bar
                "-maxtime", str(self.opt("timeout")),
            ]
            self._log.info("ffuf content discovery: %s (wordlist=%s)", base_url, wordlist_path)

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                self._log.warning("ffuf binary not found — module disabled")
                return

            try:
                _, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=self.opt("timeout") + 10
                )
            except asyncio.TimeoutError:
                proc.kill()
                self._log.warning("ffuf timed out on %s", base_url)
                return

            # Parse results.
            count = 0
            try:
                with open(output_file, encoding="utf-8") as f:
                    data = json.load(f)
                results = data.get("results") or []
                for result in results[: self.opt("max_results")]:
                    found_url = result.get("url", "")
                    status = result.get("status", 0)
                    if not found_url or status not in _INTERESTING_CODES:
                        continue
                    if await self.emit(
                        EventType.URL,
                        UrlData(url=found_url, status_code=status, found_via="ffuf"),
                        source_event=event,
                    ):
                        count += 1
            except (json.JSONDecodeError, OSError) as exc:
                self._log.debug("ffuf: could not parse output: %s", exc)

            self._log.info("ffuf: %d paths found on %s", count, base_url)
        finally:
            try:
                Path(output_file).unlink(missing_ok=True)
            except OSError:
                pass
