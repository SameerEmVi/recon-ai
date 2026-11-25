"""
Tests for out-of-process scan execution wiring (api/scans.py + api/worker.py).

The real subprocess path is verified live; these cover the deterministic seams:
  - ScanManager runs out-of-process by default, in-process when a factory is
    injected (tests),
  - the frame pump's status/count bookkeeping (_apply_frame),
  - build_scan_controller pins the scan id so DB + web + worker agree,
  - the worker's _FrameFile writes one JSON line per frame.
"""

from __future__ import annotations

import json
import uuid

from api.scans import ScanEntry, ScanManager, build_scan_controller
from api.schemas import ScanCreate


def test_manager_mode_flag():
    # No factory → production → out-of-process.
    assert ScanManager(db_url=None)._out_of_process is True
    # Injected factory (tests) → in-process.
    m = ScanManager(controller_factory=lambda cfg, scope: object())
    assert m._out_of_process is False


def test_apply_frame_counts_events_and_tracks_status():
    e = ScanEntry(scan_id="s", domain="x", mode="full")
    ScanManager._apply_frame(e, {"kind": "event", "type": "URL"})
    ScanManager._apply_frame(e, {"kind": "event", "type": "SUBDOMAIN"})
    ScanManager._apply_frame(e, {"kind": "stats"})                 # not an event
    assert e.event_count == 2
    assert e.status == "running"                                   # no terminal frame yet

    ScanManager._apply_frame(e, {"kind": "lifecycle", "event": "scan_started"})
    assert e.status == "running"                                   # 'started' is not terminal
    ScanManager._apply_frame(e, {"kind": "lifecycle", "event": "scan_complete"})
    assert e.status == "complete"


def test_apply_frame_failed_and_cancelled():
    for ev, want in [("scan_failed", "failed"), ("scan_cancelled", "cancelled")]:
        e = ScanEntry(scan_id="s", domain="x", mode="full")
        ScanManager._apply_frame(e, {"kind": "lifecycle", "event": ev})
        assert e.status == want


def test_build_scan_controller_pins_scan_id():
    cfg = ScanCreate(domain="example.com", mode="osint")
    from api.scans import ScanManager as SM
    scope = SM.build_scope(cfg)
    sid = str(uuid.uuid4())
    controller = build_scan_controller(cfg, scope, db_url=None, scan_id=sid)
    assert str(controller.scan_id) == sid
    # Omitting it still yields a valid (generated) id.
    c2 = build_scan_controller(cfg, scope, db_url=None)
    assert c2.scan_id is not None and str(c2.scan_id) != sid


def test_worker_frame_file_writes_json_lines(tmp_path):
    import asyncio

    from api.worker import _FrameFile

    path = tmp_path / "frames.jsonl"

    async def go():
        ff = _FrameFile(str(path))
        await ff.publish({"kind": "lifecycle", "event": "scan_started"})
        await ff.publish({"kind": "event", "type": "URL"})
        ff.close()

    asyncio.run(go())
    lines = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    assert len(lines) == 2
    assert lines[0]["event"] == "scan_started"
    assert lines[1]["type"] == "URL"
