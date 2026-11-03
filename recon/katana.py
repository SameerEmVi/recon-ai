"""
katana wrapper — command construction + JSONL parsing (pure, unit-tested).

katana (ProjectDiscovery) is recon-ai's active web crawler. Driven in **JSONL
mode** (`-j`, written to stdout — verified on katana v1.8.0) so the richer
signals are available:

  * `-xhr`  — XHR request URLs + methods (real API calls the page makes)
  * `-fx`   — forms/inputs → endpoint actions + parameter names
  * `-td`   — technology detection
  * `-kb`   — knowledge-base page-type classification
  * `-kf`   — crawl known files (robots.txt / sitemap.xml)
  * `-iqp`  — ignore same path with differing query params (dedup)

The two pure pieces here keep the module thin and testable:
  - `build_command()`      — assemble the argv (no `-o`; JSONL goes to stdout).
  - `parse_katana_jsonl()` — tolerant line-by-line parse into KatanaRecord.

Rate control: `-rl` (requests/sec) is set by the module from the scan's shared
RateLimiter (single rate chokepoint), not hard-coded — mirroring ffuf's `-rate`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass(frozen=True)
class KatanaForm:
    method: str
    action: str                      # absolute URL (katana resolves it)
    parameters: tuple[str, ...] = ()


@dataclass(frozen=True)
class KatanaRecord:
    url: str                         # request.endpoint (absolute)
    method: str = "GET"
    status: int | None = None
    tag: str = ""                    # script / a / form / xhr / fetch / …
    source: str = ""                 # page the ref was found on
    technologies: tuple[str, ...] = ()
    forms: tuple[KatanaForm, ...] = field(default_factory=tuple)
    page_type: str = ""              # knowledgebase.PageType


class KatanaError(ValueError):
    """Invalid katana invocation (fail closed, never crawl)."""


def build_command(
    url: str,
    *,
    depth: int = 5,
    concurrency: int = 10,
    parallelism: int = 3,
    rate: int | None = 10,
    retry: int = 1,
    timeout: int = 10,
    js_crawl: bool = True,
    xhr: bool = True,
    form_extraction: bool = True,
    tech_detect: bool = True,
    knowledge_base: bool = True,
    known_files: str | None = "all",     # all | robotstxt | sitemapxml | None
    ignore_query_params: bool = True,
    proxy: str | None = None,
    error_log: str | None = None,
    binary: str = "katana",
) -> list[str]:
    """Assemble a katana JSONL crawl command for a single URL. Fail closed."""
    u = (url or "").strip()
    if not u:
        raise KatanaError("empty target")
    if u.startswith("-"):
        raise KatanaError(f"refusing flag-like target {url!r}")
    if known_files not in (None, "all", "robotstxt", "sitemapxml"):
        raise KatanaError(f"invalid known_files {known_files!r}")

    cmd = [
        binary,
        "-u", u,
        "-silent",
        "-j",                              # JSONL to stdout
        "-d", str(int(depth)),
        "-c", str(int(concurrency)),
        "-p", str(int(parallelism)),
        "-timeout", str(int(timeout)),
        "-retry", str(int(retry)),
    ]
    if rate and int(rate) > 0:
        cmd += ["-rl", str(int(rate))]
    if js_crawl:
        cmd += ["-jc"]
    if xhr:
        cmd += ["-xhr"]
    if form_extraction:
        cmd += ["-fx"]
    if tech_detect:
        cmd += ["-td"]
    if knowledge_base:
        cmd += ["-kb"]
    # -kf needs depth >= 3 to crawl known files reliably (katana's own note).
    if known_files and int(depth) >= 3:
        cmd += ["-kf", known_files]
    if ignore_query_params:
        cmd += ["-iqp"]
    if proxy:
        cmd += ["-proxy", proxy]
    if error_log:
        cmd += ["-elog", error_log]
    return cmd


def _str_tuple(v) -> tuple[str, ...]:
    if not isinstance(v, (list, tuple)):
        return ()
    out: list[str] = []
    for x in v:
        s = str(x).strip()[:256]
        if s and s not in out:
            out.append(s)
    return tuple(out)


def _parse_forms(resp: dict) -> tuple[KatanaForm, ...]:
    """Parse response.forms (present with -fx). Tolerant of key variations:
    parameters may be under 'parameters', 'fields', or 'inputs'."""
    raw = resp.get("forms")
    if not isinstance(raw, list):
        return ()
    forms: list[KatanaForm] = []
    for f in raw:
        if not isinstance(f, dict):
            continue
        params = (f.get("parameters") or f.get("fields") or f.get("inputs") or [])
        forms.append(KatanaForm(
            method=str(f.get("method") or "GET").upper()[:16],
            action=str(f.get("action") or "").strip()[:2048],
            parameters=_str_tuple(params),
        ))
    return tuple(forms)


def parse_katana_jsonl(text: str) -> list[KatanaRecord]:
    """Parse katana `-j` output (one JSON object per line). Tolerant of blank
    lines, katana's INF banner lines, and partial/garbage records. Never raises."""
    out: list[KatanaRecord] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        req = obj.get("request") or {}
        resp = obj.get("response") or {}
        kb = obj.get("knowledgebase") or {}
        endpoint = str(req.get("endpoint") or "").strip()[:2048]
        if not endpoint:
            continue
        status = resp.get("status_code")
        out.append(KatanaRecord(
            url=endpoint,
            method=str(req.get("method") or "GET").upper()[:16],
            status=int(status) if isinstance(status, int) else None,
            tag=str(req.get("tag") or "").strip()[:32],
            source=str(req.get("source") or "").strip()[:2048],
            technologies=_str_tuple(resp.get("technologies")),
            forms=_parse_forms(resp),
            page_type=str(kb.get("PageType") or "").strip()[:64],
        ))
    return out
