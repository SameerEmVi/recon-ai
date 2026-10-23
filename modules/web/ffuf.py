"""
ffuf — smart directory/content fuzzing via the ffuf binary.

recon-ai's single content-discovery fuzzer. The distinguishing feature is
**smart calibration**: before fuzzing a
service, this module probes a few random, almost-certainly-nonexistent paths
through the shared rate limiter to learn the site's *catch-all baseline* — the
classic "the app returns **301** (or 401/403/404) for everything" case — then
tells ffuf to filter that noise so only real content comes back. A redirect/
error catch-all is filtered by **status code** (robust to CDN/error-page body
drift under load); a 2xx wildcard is filtered by **size**. When the baseline
can't be learned, it falls back to ffuf's own `-ac` auto-calibration.

Reactive: fires on HTTP_SERVICE events (the vhost-aware host+scheme). For each
live service it:
  1. probes N random paths → learns the catch-all baseline (`derive_calibration`),
  2. runs ffuf with `-mc all` minus the calibrated `-fc`/`-fs` noise filters,
  3. parses ffuf's JSON output and emits a scope-gated `URL` per real find.

Every emission goes through `self.emit → controller.stamp_and_publish →
ScopeEngine`, so discovered URLs are scope-checked, dedup'd, and re-enter the
pipeline. Target-controlled strings are sanitized/capped by the `UrlData`
validator. ffuf's own request rate honours the scan-wide limiter (`-rate`/`-t`
derived from the shared RateLimiter); the whole ffuf run is one guarded op.

Watches:  HTTP_SERVICE
Produces: URL
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from events.types import Event, EventType, UrlData
from modules.base import BaseModule
from modules.registry import register
from recon.ffuf import (
    FfufWrapper,
    build_command,
    derive_calibration,
    generate_random_string,
    is_real_find,
    parse_ffuf_json,
)

_WORDLIST_DIR = Path(__file__).parent.parent.parent / "wordlists"
_BUNDLED_WORDLIST = _WORDLIST_DIR / "combined.txt"   # deduped union of the former common/big/dirs/files lists
_BUNDLED_BIG_WORDLIST = _BUNDLED_WORDLIST
_SECLISTS_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
    "/opt/seclists/Discovery/Web-Content/common.txt",
    "C:/tools/seclists/Discovery/Web-Content/common.txt",
]


def _resolve_wordlist(size_or_path: str) -> str | None:
    """Return the best available wordlist path for the requested size/path."""
    if os.path.isabs(str(size_or_path)) and Path(str(size_or_path)).exists():
        return str(size_or_path)
    if size_or_path == "big" and _BUNDLED_BIG_WORDLIST.exists():
        return str(_BUNDLED_BIG_WORDLIST)
    for candidate in _SECLISTS_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    if _BUNDLED_WORDLIST.exists():
        return str(_BUNDLED_WORDLIST)
    return None


@register
class FfufModule(BaseModule):
    name = "ffuf"
    description = "Smart directory/content fuzzing via ffuf (catch-all calibration)"
    watched_events = ["HTTP_SERVICE"]
    produced_events = ["URL"]
    flags = ["active", "web", "content-discovery", "slow"]
    deps_binary = ["ffuf"]
    estimated_cost = 8          # HIGH — active fuzzing (COST_HIGH)
    expected_value = 8          # HIGH — content discovery (VALUE_HIGH)
    options = {
        "wordlist": "common",           # "common" | "big" | absolute path
        "extensions": "php,html,js,txt,json,bak,old,zip,config",
        "calibration_probes": 3,        # random paths to learn the baseline
        "threads": 40,                  # ffuf -t
        "rate": 0,                      # ffuf -rate (0 = derive from limiter, else unlimited)
        "req_timeout": 10,              # ffuf per-request -timeout (seconds)
        "run_timeout": 600,             # ffuf -maxtime: stop + write partial results after N s
        "max_results": 1000,            # cap emitted URLs per service
        "recursion": False,             # ffuf -recursion
        "recursion_depth": 1,
        "user_agent": "recon-ai/ffuf",
        "extra_filter_codes": "404",    # always-noise codes, merged with calibration
    }

    def __init__(self, controller, config=None) -> None:
        super().__init__(controller, config)
        self._seen_bases: set[str] = set()

    # ── helpers ────────────────────────────────────────────────────────────────
    def _derived_rate(self) -> int:
        """ffuf -rate: explicit option wins; else honour the scan-wide limiter."""
        opt = int(self.opt("rate") or 0)
        if opt > 0:
            return opt
        rl = self.rate_limiter
        rps = getattr(rl, "rate_per_sec", None)
        return int(rps) if rps else 0

    def _extensions(self) -> list[str]:
        raw = self.opt("extensions") or ""
        return [e.strip() for e in str(raw).split(",") if e.strip()]

    def _extra_filter_codes(self) -> list[int]:
        raw = self.opt("extra_filter_codes") or ""
        out: list[int] = []
        for tok in str(raw).split(","):
            tok = tok.strip()
            if tok.isdigit():
                out.append(int(tok))
        return out

    async def _probe(self, client, base: str) -> tuple[int | None, int]:
        """Request one random path; return (status, body_length) or (None, 0)."""
        token = generate_random_string()
        url = f"{base}/{token}"
        try:
            async with self.guard(f"http:{urlparse(base).hostname or base}"):
                r = await client.get(url, follow_redirects=False)
            self.inspect_response(r)
            return r.status_code, len(r.content or b"")
        except Exception as exc:
            self._log.debug("ffuf: calibration probe failed for %s: %s", url, exc)
            return None, 0

    async def _calibrate(self, client, base: str):
        n = max(1, int(self.opt("calibration_probes")))
        probes = [await self._probe(client, base) for _ in range(n)]
        calib = derive_calibration(probes)
        # Always fold in the operator's always-noise codes (default 404).
        merged_codes = sorted(set(calib.filter_codes) | set(self._extra_filter_codes()))
        calib.filter_codes = merged_codes
        return calib

    # ── main handler ────────────────────────────────────────────────────────────
    async def handle_event(self, event: Event) -> None:
        url = getattr(event.data, "url", "") or ""
        if not url:
            return
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base in self._seen_bases:
            return
        self._seen_bases.add(base)

        wordlist = _resolve_wordlist(str(self.opt("wordlist")))
        if not wordlist:
            self._log.warning("ffuf: no wordlist found — skipping")
            return

        # Calibration probes hit the target directly with our own client, so
        # recheck the mode policy here too (run_proc re-checks the ffuf binary
        # run separately). Defence-in-depth on top of module-load filtering.
        from policy import CAP_TARGET_HTTP_REQUEST
        if not self.capability_ok(CAP_TARGET_HTTP_REQUEST, action="ffuf calibration"):
            return

        try:
            import httpx
        except ImportError:
            self._log.warning("ffuf: httpx (python lib) needed for calibration — skipping")
            return

        # 1. Learn the catch-all baseline through the shared limiter.
        headers = {"User-Agent": str(self.opt("user_agent"))}
        async with httpx.AsyncClient(
            timeout=float(self.opt("req_timeout")), headers=headers, verify=False
        ) as client:
            calib = await self._calibrate(client, base)
        self._log.info("ffuf: calibrated %s — %s", base, calib.reason)

        # 2. Build + run ffuf with the calibrated noise filters.
        out_fd, out_path = tempfile.mkstemp(suffix=".json", prefix="ffuf_")
        os.close(out_fd)
        try:
            run_to = max(1, int(self.opt("run_timeout")))
            cmd = build_command(
                target_url=base,
                wordlist=wordlist,
                output_file=out_path,
                extensions=self._extensions(),
                filter_codes=calib.filter_codes,
                filter_sizes=calib.filter_sizes,
                auto_calibrate=calib.auto_calibrate,
                threads=int(self.opt("threads")),
                rate=self._derived_rate(),
                timeout=int(self.opt("req_timeout")),
                # ffuf self-terminates at -maxtime and writes partial JSON; a flat
                # subprocess kill would lose everything (ffuf only writes on exit).
                max_time=run_to,
                user_agent=str(self.opt("user_agent")),
                recursion=bool(self.opt("recursion")),
                recursion_depth=int(self.opt("recursion_depth")),
            )
            # Hard backstop sits *above* -maxtime so ffuf has a grace window to
            # flush its results file before we'd ever kill it.
            ok = await FfufWrapper(
                timeout=run_to + 30, limiter=self.rate_limiter
            ).run(cmd, bucket=f"ffuf:{parsed.hostname or base}")
            if not ok:
                return

            # 3. Parse results and emit scope-gated URLs.
            try:
                text = Path(out_path).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                return
            results = parse_ffuf_json(text)
        finally:
            try:
                os.remove(out_path)
            except OSError:
                pass

        max_results = int(self.opt("max_results"))
        emitted = 0
        dropped = 0
        for res in results:
            if emitted >= max_results:
                break
            # Final noise gate, independent of the per-host calibration filters:
            # drop statuses that never indicate a resource (400/404/429/5xx) and
            # empty-bodied 2xx catch-all stubs. `-mc all` surfaces these and a
            # mis-learned baseline can let them through, so filter unconditionally.
            if not is_real_find(res.status, res.length):
                dropped += 1
                continue
            if await self.emit(
                EventType.URL,
                UrlData(url=res.url, status_code=res.status, found_via="ffuf"),
                source_event=event,
            ):
                emitted += 1
        self._log.info("ffuf: %s → %d finds (%d emitted, %d noise)",
                       base, len(results), emitted, dropped)
