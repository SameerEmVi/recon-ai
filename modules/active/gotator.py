"""
gotator — permutation/mutation subdomain discovery (Josue87/gotator).

Reactive module: for each originally-discovered subdomain, gotator generates
permutation candidates which are then resolved with dnsx; hostnames that resolve
are emitted as SUBDOMAIN events. gotator is the permutation engine; the existing
pure-Python `permutations` module is the no-binary fallback.

Bounded: never permutes its own output (source_tool == self.name is skipped), so
the event graph stays finite. Warn-and-skips without `gotator` (and needs dnsx to
resolve). Watches: SUBDOMAIN · Produces: SUBDOMAIN
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

from events.types import Event, EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register

_BUNDLED_PERM = Path(__file__).parent.parent.parent / "wordlists" / "dns_names.txt"


def parse_resolved(text: str) -> list[str]:
    """dnsx -silent output — one resolved hostname per line."""
    out: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        h = line.strip().rstrip(".").lower()
        if h and " " not in h and "." in h and h not in seen:
            seen.add(h)
            out.append(h)
    return out


@register
class GotatorModule(BaseModule):
    name = "gotator"
    description = "Permutation subdomain discovery via gotator + dnsx"
    watched_events = ["SUBDOMAIN"]
    produced_events = ["SUBDOMAIN"]
    flags = ["active", "dns", "subdomain-enum", "permutation", "slow"]
    deps_binary = ["gotator", "dnsx"]
    options = {"perm_wordlist": "", "depth": 1, "numbers": 3,
               "timeout": 300, "max_candidates": 1000}

    async def handle_event(self, event: Event) -> None:
        # Bound recursion: don't permute permutation output.
        if getattr(event, "source_tool", "") == self.name:
            return
        host = event.data.hostname
        if not host:
            return

        perms = await self._generate(host)
        if not perms:
            return
        perms = perms[: self.opt("max_candidates")]

        resolved_out = await self.run_proc(
            ["dnsx", "-silent", "-nc"],
            input_text="\n".join(perms) + "\n",
            timeout=self.opt("timeout"),
            bucket=f"resolve:{host}",
        )
        if not resolved_out:
            return
        count = 0
        for h in parse_resolved(resolved_out):
            if h == host.lower():
                continue
            if await self.emit(
                EventType.SUBDOMAIN,
                SubdomainData(hostname=h, source="gotator"),
                source_event=event,
            ):
                count += 1
        if count:
            self._log.info("gotator: %d resolved permutations from %s", count, host)

    async def _generate(self, host: str) -> list[str]:
        """Run gotator to produce permutation candidates for one host."""
        wordlist = self.opt("perm_wordlist") or str(_BUNDLED_PERM)
        if not Path(wordlist).exists():
            self._log.warning("gotator: perm wordlist not found: %s", wordlist)
            return []
        tmp = tempfile.NamedTemporaryFile(prefix="gotator_", suffix=".txt", delete=False)
        try:
            tmp.write((host + "\n").encode())
            tmp.close()
            cmd = [
                "gotator", "-sub", tmp.name, "-perm", wordlist,
                "-depth", str(self.opt("depth")), "-numbers", str(self.opt("numbers")),
                "-mindup", "-adv", "-md", "-silent",
            ]
            out = await self.run_proc(cmd, timeout=self.opt("timeout"),
                                      bucket=f"perm:{host}")
            if not out:
                return []
            return [ln.strip() for ln in out.splitlines() if ln.strip()]
        except Exception as exc:
            self._log.debug("gotator generate failed for %s: %s", host, exc)
            return []
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
