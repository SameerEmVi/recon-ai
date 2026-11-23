"""
Traffic assembler for the GUI — a proxy-style view of every HTTP exchange.

Surfaces the per-run `http.jsonl` the engine already writes under
`<results_dir>/<domain>/run-<id>/diagnostics/` (one metadata record per HTTP
exchange). Everything is read straight off disk — no scanning — and the records
were already redacted by `net.redact` at write time. Crucially, that stream holds
**metadata only, never request/response bodies**, so a body-keyword filter is not
possible here (and would be a privacy regression); we filter on the structured
fields the stream actually carries (host / method / status / URL / size / module).

Path safety: candidate run directories are discovered by globbing under the
configured `results_dir` only; the `domain` / `run_id` / `scan_id` params merely
filter that glob result, so a caller can never read a file outside `results_dir`.
Filtering and pagination are applied server-side so a huge scan (thousands of
flows) never ships its whole stream to the browser.
"""

from __future__ import annotations

import glob
import json
import os
from urllib.parse import urlsplit

# run_id == scan_id, so a scan's stream lives at results/*/run-<scan_id>/…
_HTTP = "http.jsonl"
_MAX_SCAN_LINES = 200_000          # hard read ceiling (matches the writer's cap)


def _host_of(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except Exception:
        return ""


def _path_of(url: str) -> str:
    try:
        p = urlsplit(url)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        return path
    except Exception:
        return ""


def _discover(results_dir: str) -> list[str]:
    pattern = os.path.join(results_dir, "*", "run-*", "diagnostics", _HTTP)
    return [f for f in glob.glob(pattern) if os.path.isfile(f)]


def _meta(http_file: str) -> dict:
    diag_dir = os.path.dirname(http_file)
    run_dir = os.path.dirname(diag_dir)
    domain = os.path.basename(os.path.dirname(run_dir))
    run_name = os.path.basename(run_dir)                       # "run-<id>"
    run_id = run_name[4:] if run_name.startswith("run-") else run_name
    return {"domain": domain, "run_id": run_id, "file": http_file,
            "modified": os.path.getmtime(http_file)}


def list_runs(results_dir: str, limit: int = 50) -> list[dict]:
    """Runs that have an http.jsonl, newest first (for the run selector)."""
    runs = [_meta(f) for f in _discover(results_dir)]
    runs.sort(key=lambda r: r["modified"], reverse=True)
    out = []
    for r in runs[:limit]:
        r = dict(r)
        r.pop("file", None)                                    # don't leak paths
        out.append(r)
    return out


def _resolve(results_dir: str, *, scan_id: str | None, run_id: str | None,
             domain: str | None) -> dict | None:
    files = _discover(results_dir)
    if not files:
        return None
    rid = (scan_id or run_id or "").strip()
    cands = [_meta(f) for f in files]
    if rid:
        cands = [c for c in cands if c["run_id"] == rid]
    if domain:
        cands = [c for c in cands if c["domain"] == domain]
    if not cands:
        return None
    return max(cands, key=lambda c: c["modified"])


def _to_flow(rec: dict) -> dict:
    url = rec.get("target") or ""
    err = rec.get("error_type")
    return {
        "time": rec.get("timestamp"),
        "module": rec.get("module"),
        "operation": rec.get("operation"),
        "host": _host_of(url),
        "method": (rec.get("method") or "").upper(),
        "url": url,
        "path": _path_of(url),
        "status": rec.get("status"),
        "size": rec.get("response_bytes"),
        "duration_ms": rec.get("duration_ms"),
        "tls_verify": rec.get("tls_verify"),
        "ok": err is None,
        "error_type": err,
        "error_message": rec.get("error_message"),
    }


def _status_matches(status, token: str) -> bool:
    """`token` is an exact code ("404"), a class ("2xx".."5xx"), or "error"."""
    token = token.strip().lower()
    if not token:
        return True
    if token == "error":
        return status is None
    if len(token) == 3 and token.endswith("xx") and token[0].isdigit():
        if status is None:
            return False
        return status // 100 == int(token[0])
    if token.isdigit():
        return status == int(token)
    return True


def build_traffic(results_dir: str, *, scan_id: str | None = None,
                  run_id: str | None = None, domain: str | None = None,
                  host: str | None = None, method: str | None = None,
                  status: str | None = None, q: str | None = None,
                  module: str | None = None, errors_only: bool = False,
                  size_min: int | None = None, size_max: int | None = None,
                  page: int = 1, page_size: int = 50) -> dict:
    """Resolve a run's http stream, filter + paginate it server-side, and return
    one page of flows plus facets (distinct methods/statuses/modules) and totals.
    Empty, well-formed payload when no stream matches (so the GUI degrades)."""
    page = max(page, 1)
    page_size = min(max(page_size, 1), 500)
    empty = {"run": None, "flows": [], "total": 0, "page": page,
             "page_size": page_size, "pages": 0,
             "facets": {"methods": [], "statuses": [], "modules": []},
             "available_runs": list_runs(results_dir)}

    chosen = _resolve(results_dir, scan_id=scan_id, run_id=run_id, domain=domain)
    if not chosen:
        return empty

    flows: list[dict] = []
    try:
        with open(chosen["file"], encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                if i >= _MAX_SCAN_LINES:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    flows.append(_to_flow(json.loads(line)))
                except ValueError:
                    continue
    except OSError:
        return empty

    # Facets over the whole run (populate the dropdowns before filtering).
    facets = {
        "methods": sorted({f["method"] for f in flows if f["method"]}),
        "statuses": sorted({f["status"] for f in flows if f["status"] is not None}),
        "modules": sorted({f["module"] for f in flows if f["module"]}),
    }

    host_n = (host or "").strip().lower()
    method_n = (method or "").strip().upper()
    q_n = (q or "").strip().lower()
    module_n = (module or "").strip()

    def keep(f: dict) -> bool:
        if host_n and host_n not in f["host"].lower():
            return False
        if method_n and f["method"] != method_n:
            return False
        if status and not _status_matches(f["status"], status):
            return False
        if module_n and f["module"] != module_n:
            return False
        if errors_only and f["ok"]:
            return False
        if q_n and q_n not in f["url"].lower():
            return False
        sz = f["size"]
        if size_min is not None and (sz is None or sz < size_min):
            return False
        if size_max is not None and (sz is None or sz > size_max):
            return False
        return True

    filtered = [f for f in flows if keep(f)]
    # Newest first.
    filtered.sort(key=lambda f: f["time"] or "", reverse=True)

    total = len(filtered)
    pages = (total + page_size - 1) // page_size
    start = (page - 1) * page_size
    page_rows = filtered[start:start + page_size]

    meta = dict(chosen)
    meta.pop("file", None)
    return {"run": meta, "flows": page_rows, "total": total, "page": page,
            "page_size": page_size, "pages": pages, "facets": facets,
            "available_runs": list_runs(results_dir)}
