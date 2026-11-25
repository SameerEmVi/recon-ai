"""
Out-of-process scan worker.

Run as:  python -m api.worker <config.json>

The web server (api/scans.py::ScanManager) launches one of these per scan so the
heavy, I/O-bound scan pipeline runs in its OWN process and never starves the web
server's event loop (a full scan otherwise monopolises the single shared loop,
making the UI crawl). This process:

  * rebuilds the Scope and re-validates it fail-closed (defence in depth — the
    launching side already validated, but the worker never trusts that),
  * builds a ScanController exactly as the in-process path does
    (api/scans.build_scan_controller), with the scan id pinned so the DB row and
    the web server agree,
  * attaches the same live monitor used in-process (api/ws.attach_live_monitor),
    but routes every frame to a per-scan JSONL file instead of the hub — the web
    server tails that file and republishes to connected WebSocket clients,
  * runs the scan to completion; status is persisted to the shared DB by the
    controller itself (scan_start → running, scan_end/scan_fail → complete/failed),
    so the web server reads status from the DB, not from this process.

Config JSON: {"scan_id", "cfg" (ScanCreate dict), "db_url", "frames_path"}.
Exit code 0 = completed, 1 = failed, 2 = scope-rejected / bad config.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys

log = logging.getLogger("api.worker")


class _FrameFile:
    """Append-only JSONL sink for live frames, serialised by a lock. Each frame
    is one line; the web server's tailer reads lines as they land. A write
    failure is swallowed — losing a live frame must never abort the scan."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = asyncio.Lock()
        self._fh = open(path, "a", encoding="utf-8", buffering=1)  # line-buffered

    async def publish(self, frame: dict) -> None:
        line = json.dumps(frame, default=str, ensure_ascii=False)
        async with self._lock:
            try:
                self._fh.write(line + "\n")
                self._fh.flush()
            except Exception as exc:
                log.debug("frame write failed: %s", exc)

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


async def _run(config: dict) -> int:
    from api.scans import ScanManager, ScopeRejected, build_scan_controller
    from api.schemas import ScanCreate

    scan_id = str(config["scan_id"])
    db_url = config.get("db_url")
    frames_path = config["frames_path"]
    cfg = ScanCreate(**config["cfg"])

    frames = _FrameFile(frames_path)

    async def lifecycle(event: str, **extra) -> None:
        await frames.publish({"kind": "lifecycle", "scan_id": scan_id,
                              "event": event, **extra})

    # Re-validate scope fail-closed inside the worker (never trust the caller).
    try:
        scope = ScanManager.build_scope(cfg)
    except ScopeRejected as exc:
        await lifecycle("scan_failed", error=str(exc))
        frames.close()
        log.error("scope rejected: %s", exc)
        return 2

    controller = build_scan_controller(cfg, scope, db_url=db_url, scan_id=scan_id)

    from api.ws import attach_live_monitor
    sampler = None
    status = "complete"
    try:
        sampler = attach_live_monitor(controller, scan_id, frames.publish)
        await lifecycle("scan_started", domain=cfg.domain, mode=cfg.mode)
        await controller.run(cfg.domain)
    except asyncio.CancelledError:
        status = "cancelled"
        raise
    except Exception as exc:
        status = "failed"
        log.error("scan %s failed: %s", scan_id, exc)
    finally:
        if sampler is not None:
            sampler.cancel()
        await lifecycle(f"scan_{status}")
        frames.close()
    return 0 if status == "complete" else 1


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)-8s %(name)s  %(message)s")
    if len(sys.argv) < 2:
        print("usage: python -m api.worker <config.json>", file=sys.stderr)
        sys.exit(2)
    try:
        with open(sys.argv[1], encoding="utf-8") as f:
            config = json.load(f)
    except Exception as exc:
        print(f"worker: bad config: {exc}", file=sys.stderr)
        sys.exit(2)
    try:
        sys.exit(asyncio.run(_run(config)))
    except KeyboardInterrupt:
        sys.exit(1)


if __name__ == "__main__":
    main()
