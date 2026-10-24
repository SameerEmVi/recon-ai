"""Unit tests for the ffuf smart-fuzzing wrapper and module."""

from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from recon.ffuf import (
    build_command,
    derive_calibration,
    parse_ffuf_json,
)


# ── smart calibration (the interesting part) ──────────────────────────────────

def test_calibration_catchall_301_filters_status_code():
    # The app 301s every random path — the user's scenario. Filter the *code*
    # (robust to body-size drift), not a single size.
    calib = derive_calibration([(301, 162), (301, 162), (301, 162)])
    assert calib.filter_codes == [301]
    assert calib.filter_sizes == []
    assert not calib.auto_calibrate


def test_calibration_catchall_403_filters_status_even_with_constant_size():
    # CDN/S3 403-everything: filter the code so drifting body size (263→243)
    # can't leak false positives.
    calib = derive_calibration([(403, 263), (403, 263), (403, 263)])
    assert calib.filter_codes == [403]
    assert calib.filter_sizes == []


def test_calibration_2xx_catchall_filters_size():
    # A 200-for-everything SPA: can't filter all 2xx, so filter by size.
    calib = derive_calibration([(200, 5120), (200, 5120)])
    assert calib.filter_sizes == [5120]
    assert calib.filter_codes == []


def test_calibration_2xx_catchall_varying_size_autocalibrates():
    calib = derive_calibration([(200, 4000), (200, 6000)])
    assert calib.auto_calibrate is True


def test_calibration_no_baseline_enables_autocalibrate():
    calib = derive_calibration([(None, 0), (None, 0)])
    assert calib.auto_calibrate is True


def test_calibration_inconsistent_baseline_enables_autocalibrate():
    calib = derive_calibration([(301, 100), (403, 500)])
    assert calib.auto_calibrate is True


def test_calibration_mixed_status_shared_size_filters_size():
    calib = derive_calibration([(301, 200), (403, 200)])
    assert calib.filter_sizes == [200]
    assert not calib.auto_calibrate


# ── command building ──────────────────────────────────────────────────────────

def test_build_command_injects_fuzz_keyword_and_filters():
    cmd = build_command(
        target_url="https://x.com",
        wordlist="/wl/common.txt",
        output_file="/tmp/out.json",
        extensions=["php", ".bak"],
        filter_codes=[404, 301],
        filter_sizes=[162],
    )
    assert "-u" in cmd and cmd[cmd.index("-u") + 1] == "https://x.com/FUZZ"
    # extensions normalized to dot-prefixed, comma-joined
    assert cmd[cmd.index("-e") + 1] == ".php,.bak"
    # filters sorted + deduped
    assert cmd[cmd.index("-fc") + 1] == "301,404"
    assert cmd[cmd.index("-fs") + 1] == "162"
    assert cmd[cmd.index("-of") + 1] == "json"


def test_build_command_autocalibrate_flag_and_no_double_fuzz():
    cmd = build_command(
        target_url="https://x.com/app/FUZZ",
        wordlist="/wl.txt",
        output_file="/o.json",
        auto_calibrate=True,
    )
    # FUZZ already present → not appended twice
    assert cmd[cmd.index("-u") + 1] == "https://x.com/app/FUZZ"
    assert "-ac" in cmd
    # no filters passed → no -fc/-fs
    assert "-fc" not in cmd and "-fs" not in cmd


def test_build_command_maxtime_emitted_only_when_positive():
    # max_time > 0 → ffuf -maxtime so it stops gracefully and writes partial JSON
    cmd = build_command(
        target_url="https://x.com",
        wordlist="/wl.txt",
        output_file="/o.json",
        max_time=600,
    )
    assert "-maxtime" in cmd and cmd[cmd.index("-maxtime") + 1] == "600"

    # default (0) → no -maxtime (unbounded, rely on caller's subprocess timeout)
    cmd0 = build_command(
        target_url="https://x.com", wordlist="/wl.txt", output_file="/o.json"
    )
    assert "-maxtime" not in cmd0


# ── result parsing ────────────────────────────────────────────────────────────

def test_parse_ffuf_json_extracts_results():
    payload = json.dumps({
        "results": [
            {"input": {"FUZZ": "admin"}, "status": 200, "length": 1234,
             "words": 56, "lines": 12, "url": "https://x.com/admin"},
            {"input": {"FUZZ": "backup"}, "status": 403, "length": 12,
             "url": "https://x.com/backup", "redirectlocation": ""},
        ]
    })
    rows = parse_ffuf_json(payload)
    assert {r.fuzz for r in rows} == {"admin", "backup"}
    admin = next(r for r in rows if r.fuzz == "admin")
    assert admin.url == "https://x.com/admin" and admin.status == 200


def test_parse_ffuf_json_tolerates_garbage():
    assert parse_ffuf_json("") == []
    assert parse_ffuf_json("not json") == []
    assert parse_ffuf_json(json.dumps({"no_results": 1})) == []


# ── is_real_find: the unconditional noise gate ────────────────────────────────

def test_is_real_find_drops_noise_statuses():
    from recon.ffuf import is_real_find
    for st in (400, 404, 429, 500, 502, 503, 504):
        assert is_real_find(st, 1234) is False
    # genuine finds and "exists but protected / wrong method" are kept
    assert is_real_find(200, 1234) is True
    assert is_real_find(301, 162) is True
    assert is_real_find(401, 10) is True
    assert is_real_find(403, 10) is True
    assert is_real_find(405, 10) is True


def test_is_real_find_drops_empty_2xx_stub():
    from recon.ffuf import is_real_find
    # a 200 with no body is a CDN/S3 catch-all stub, not real content
    assert is_real_find(200, 0) is False
    assert is_real_find(204, 0) is False
    assert is_real_find(200, 1) is True


def test_is_real_find_tolerates_bad_input():
    from recon.ffuf import is_real_find
    assert is_real_find(None, 10) is False      # type: ignore[arg-type]
    assert is_real_find("x", 10) is False       # type: ignore[arg-type]
    assert is_real_find(0, 10) is False


# ── module: registered, reactive, drives ffuf and emits URLs ──────────────────

def _mock_controller():
    ctrl = MagicMock()
    ctrl.scan_id = uuid.uuid4()
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    return ctrl


def test_ffuf_module_registered_and_reactive():
    from modules.registry import ModuleRegistry, DISCOVERY_MODULES
    assert "ffuf" in DISCOVERY_MODULES
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["ffuf"], controller=ctrl)[0]
    assert m.watched_events == ["HTTP_SERVICE"]
    assert "ffuf" in m.deps_binary


async def test_ffuf_module_calibrates_and_emits(tmp_path):
    from events.types import EventType, HttpServiceData
    from modules.registry import ModuleRegistry

    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["ffuf"], controller=ctrl)[0]
    m._config["wordlist"] = str(tmp_path / "wl.txt")
    (tmp_path / "wl.txt").write_text("admin\nbackup\n")

    # Calibration probes: catch-all 301 at constant size.
    resp = MagicMock()
    resp.status_code = 301
    resp.content = b"x" * 162
    resp.headers = {}
    fake_client = AsyncMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(return_value=resp)

    # ffuf "run" writes a JSON result file; simulate that.
    ffuf_json = json.dumps({"results": [
        {"input": {"FUZZ": "admin"}, "status": 200, "length": 999,
         "url": "https://svc.x.com/admin"},
    ]})

    async def fake_run(self, cmd, *, bucket="ffuf"):
        out = cmd[cmd.index("-o") + 1]
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(ffuf_json)
        # sanity: the 301 catch-all must be filtered by CODE (merged with the
        # always-noise 404), robust to body-size drift.
        assert "-fc" in cmd and cmd[cmd.index("-fc") + 1] == "301,404"
        assert "-fs" not in cmd
        return True

    event = MagicMock()
    event.type = EventType.HTTP_SERVICE
    event.data = HttpServiceData(url="https://svc.x.com/", status_code=200)
    event.id = uuid.uuid4()
    event.distance = 1

    with patch("httpx.AsyncClient", return_value=fake_client), \
         patch("recon.ffuf.FfufWrapper.run", new=fake_run):
        await m.handle_event(event)

    calls = [c[0][0] for c in ctrl.stamp_and_publish.call_args_list]
    urls = {e.data.url for e in calls if hasattr(e.data, "url")}
    assert "https://svc.x.com/admin" in urls


async def test_ffuf_module_drops_noise_rows(tmp_path):
    # A 404 and an empty-bodied 200 that slip past calibration must NOT be
    # emitted as URLs — is_real_find is the final gate.
    from events.types import EventType, HttpServiceData
    from modules.registry import ModuleRegistry

    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["ffuf"], controller=ctrl)[0]
    m._config["wordlist"] = str(tmp_path / "wl.txt")
    (tmp_path / "wl.txt").write_text("admin\n")

    resp = MagicMock()
    resp.status_code = 200
    resp.content = b"x" * 100
    resp.headers = {}
    fake_client = AsyncMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(return_value=resp)

    ffuf_json = json.dumps({"results": [
        {"input": {"FUZZ": "admin"}, "status": 200, "length": 999,
         "url": "https://svc.x.com/admin"},
        {"input": {"FUZZ": "missing"}, "status": 404, "length": 44,
         "url": "https://svc.x.com/missing"},
        {"input": {"FUZZ": "stub"}, "status": 200, "length": 0,
         "url": "https://svc.x.com/stub"},
    ]})

    async def fake_run(self, cmd, *, bucket="ffuf"):
        out = cmd[cmd.index("-o") + 1]
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(ffuf_json)
        return True

    event = MagicMock()
    event.type = EventType.HTTP_SERVICE
    event.data = HttpServiceData(url="https://svc.x.com/", status_code=200)
    event.id = uuid.uuid4()
    event.distance = 1

    with patch("httpx.AsyncClient", return_value=fake_client), \
         patch("recon.ffuf.FfufWrapper.run", new=fake_run):
        await m.handle_event(event)

    urls = {c[0][0].data.url for c in ctrl.stamp_and_publish.call_args_list
            if hasattr(c[0][0].data, "url")}
    assert "https://svc.x.com/admin" in urls
    assert "https://svc.x.com/missing" not in urls   # 404 dropped
    assert "https://svc.x.com/stub" not in urls       # empty 2xx stub dropped
