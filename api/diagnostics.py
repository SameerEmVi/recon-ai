"""
Diagnostics reader for the GUI.

Surfaces the per-run structured JSONL the engine already writes under
`<results_dir>/<domain>/run-<id>/diagnostics/` (events / errors / http / summary).
Everything is read straight off disk — no scan logic — and the records were
already redacted by `net.redact` at write time (and the http stream never holds
bodies), so they are safe to return as-is.

Path safety: candidate run directories are discovered by globbing under the
configured `results_dir` only; the `domain` / `run_id` query params merely filter
that glob result, so a caller can never read a file outside `results_dir`.
"""

from __future__ import annotations

import glob
import json
import os

_STREAMS = ("events", "errors", "http")


def _run_meta(diag_dir: str) -> dict:
    run_dir = os.path.dirname(diag_dir)
    domain = os.path.basename(os.path.dirname(run_dir))
    run_name = os.path.basename(run_dir)                       # "run-<id>"
    run_id = run_name[4:] if run_name.startswith("run-") else run_name
    summary: dict = {}
    sp = os.path.join(diag_dir, "summary.json")
    if os.path.isfile(sp):
        try:
            summary = json.loads(open(sp, encoding="utf-8").read())
        except (OSError, ValueError):
            summary = {}
    return {
        "domain": domain,
        "run_id": run_id,
        "dir": diag_dir,
        "modified": os.path.getmtime(diag_dir),
        "total_errors": summary.get("total_errors", 0),
        "errors_by_category": summary.get("errors_by_category", {}),
        "errors_by_module": summary.get("errors_by_module", {}),
        "streams": summary.get("streams", {}),
    }


def _discover(results_dir: str) -> list[str]:
    pattern = os.path.join(results_dir, "*", "run-*", "diagnostics")
    return [d for d in glob.glob(pattern) if os.path.isdir(d)]


def list_runs(results_dir: str, limit: int = 50) -> list[dict]:
    """All diagnostics runs under results_dir, newest first."""
    runs = [_run_meta(d) for d in _discover(results_dir)]
    runs.sort(key=lambda r: r["modified"], reverse=True)
    out = []
    for r in runs[:limit]:
        r = dict(r)
        r.pop("dir", None)                                     # don't leak absolute paths
        out.append(r)
    return out


def _read_stream(diag_dir: str, stream: str, *, module: str | None, limit: int) -> list[dict]:
    path = os.path.join(diag_dir, f"{stream}.jsonl")
    if not os.path.isfile(path):
        return []
    records: list[dict] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if module and rec.get("module") != module:
                    continue
                records.append(rec)
    except OSError:
        return []
    # Newest first, capped.
    records.reverse()
    return records[:limit]


def read_run(results_dir: str, *, domain: str | None = None, run_id: str | None = None,
             stream: str = "events", module: str | None = None, limit: int = 100) -> dict:
    """Resolve a run (most recent unless domain/run_id narrow it) and return its
    summary + one stream's records. Empty payload when nothing matches."""
    if stream not in _STREAMS:
        stream = "events"
    dirs = _discover(results_dir)
    if domain:
        dirs = [d for d in dirs if os.path.basename(os.path.dirname(os.path.dirname(d))) == domain]
    if run_id:
        dirs = [d for d in dirs if f"run-{run_id}" in d]
    if not dirs:
        return {"run": None, "stream": stream, "records": [], "available_runs": list_runs(results_dir)}

    diag_dir = max(dirs, key=os.path.getmtime)
    meta = _run_meta(diag_dir)
    meta.pop("dir", None)
    return {
        "run": meta,
        "stream": stream,
        "records": _read_stream(diag_dir, stream, module=module, limit=limit),
        "available_runs": list_runs(results_dir),
    }


async def proxy_check(url: str) -> dict:
    """Standalone proxy-connectivity probe (no target traffic, no scan)."""
    from net.errors import ConfigurationError
    from net.proxy import ProxyConfig
    try:
        cfg = ProxyConfig.from_sources(cli_proxy=url)
    except ConfigurationError as exc:
        return {"ok": False, "target": url, "message": str(exc)}
    ok, msg = await cfg.probe()
    return {"ok": bool(ok), "target": cfg.describe(), "message": msg}
