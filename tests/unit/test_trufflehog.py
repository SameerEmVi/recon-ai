"""trufflehog wrapper (pure) + module tests."""

from __future__ import annotations

import dataclasses
import json
import shutil
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from events.types import EventType, HttpServiceData, UrlData
from modules.registry import DISCOVERY_MODULES, ModuleRegistry
from recon.trufflehog import (
    TruffleHogFinding,
    build_command,
    parse_trufflehog_json,
    severity_for,
)

_GH = "ghp_R4nd0mT0k3nV4lu3xYz9Qw8Er7Ty6Ui5Op4AS1"
_AWS_ID = "AKIA2E0A8F3B244C9986"
_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKY"


def _result(detector: str, raw: str, file: str, line: int = 1, *, verified=False, **extra) -> str:
    """One trufflehog --json result line, shaped like v3.97 output."""
    return json.dumps({
        "SourceMetadata": {"Data": {"Filesystem": {"file": file, "line": line}}},
        "SourceType": 15, "SourceName": "trufflehog - filesystem",
        "DetectorName": detector, "DecoderName": "PLAIN",
        "Verified": verified, "Raw": raw, "Redacted": raw,
        "ExtraData": {"rotation_guide": "https://howtorotate.com/docs/tutorials/x/"},
        "SecretParts": {"key": raw}, **extra,
    })


# ── pure wrapper ──────────────────────────────────────────────────────────────

def test_build_command_defaults_to_no_verification():
    cmd = build_command("/tmp/batch")
    assert cmd[:3] == ["trufflehog", "filesystem", "/tmp/batch"]
    assert "--json" in cmd and "--no-update" in cmd
    assert "--no-verification" in cmd


def test_build_command_verify_and_filters():
    cmd = build_command("/d", verify=True, results="verified,unknown", exclude_detectors="JWT")
    assert "--no-verification" not in cmd
    assert "--results=verified,unknown" in cmd
    assert "--exclude-detectors=JWT" in cmd


def test_parse_redacts_and_drops_raw_fields():
    out = "\n".join([
        _result("Github", _GH, r"C:\Temp\recon-trufflehog-x\batch-0001\000001.txt", 2),
        _result("AWS", _AWS_ID, "/tmp/b/000002.txt", 3,
                RawV2=f"{_AWS_ID}:{_AWS_SECRET}",
                SecretParts={"access_key_id": _AWS_ID, "secret_access_key": _AWS_SECRET}),
    ])
    findings = parse_trufflehog_json(out)
    assert [f.detector for f in findings] == ["Github", "AWS"]
    assert findings[0].file == "000001.txt" and findings[0].line == 2   # Windows path
    assert findings[1].file == "000002.txt"                             # POSIX path
    assert findings[0].rotation_guide.startswith("https://howtorotate.com")
    for f in findings:
        blob = repr(dataclasses.asdict(f))
        for secret in (_GH, _AWS_ID, _AWS_SECRET):
            assert secret not in blob           # full value never survives parsing
    assert findings[0].redacted.startswith("ghp_")


def test_parse_skips_logs_and_garbage():
    out = "\n".join([
        '{"level":"info-0","logger":"trufflehog","msg":"finished scanning"}',
        "not json at all",
        "{broken json",
        _result("Slack", "", "/x/1.txt"),     # empty Raw → nothing to report
    ])
    assert parse_trufflehog_json(out) == []
    assert parse_trufflehog_json("") == []


def test_severity_mapping():
    base = dict(decoder="PLAIN", verification_error=False, redacted="x", file="f", line=1)
    assert severity_for(TruffleHogFinding(detector="Mailchimp", verified=True, **base)) == "critical"
    assert severity_for(TruffleHogFinding(detector="AWS", verified=False, **base)) == "high"
    assert severity_for(TruffleHogFinding(detector="Mailchimp", verified=False, **base)) == "medium"


# ── module ────────────────────────────────────────────────────────────────────

def _mock_controller():
    ctrl = MagicMock()
    ctrl.scan_id = uuid.uuid4()
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    return ctrl


def _fake_client(bodies: dict[str, str], statuses: dict[str, int] | None = None):
    async def get(url, **_):
        body = bodies[url]
        resp = MagicMock()
        resp.text = body
        resp.content = body.encode()
        resp.status_code = (statuses or {}).get(url, 200)
        resp.headers = {}
        resp.raise_for_status = MagicMock()
        return resp
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.get = AsyncMock(side_effect=get)
    return client


def _event(etype: EventType, url: str):
    ev = MagicMock()
    ev.type = etype
    ev.data = (HttpServiceData(url=url, status_code=200) if etype is EventType.HTTP_SERVICE
               else UrlData(url=url, content_type="application/javascript"))
    ev.id = uuid.uuid4()
    ev.distance = 2
    return ev


async def _load(config: dict | None = None):
    ModuleRegistry.discover()
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["trufflehog"], controller=ctrl,
                            module_config={"trufflehog": config or {}})[0]
    with patch("shutil.which", return_value="/usr/bin/trufflehog"):
        assert await m.setup()
    return m, ctrl


def _fake_run_proc(detections: dict[str, tuple[str, str]]):
    """run_proc stand-in: 'scans' the batch dir, reporting `detections` by body marker."""
    calls: list[list[str]] = []

    async def run_proc(cmd, **_):
        calls.append(cmd)
        lines = []
        for p in sorted(Path(cmd[2]).iterdir()):
            body = p.read_text(encoding="utf-8")
            for marker, (detector, raw) in detections.items():
                if marker in body:
                    lines.append(_result(detector, raw, str(p)))
        return "\n".join(lines)
    return run_proc, calls


def test_registered_in_discovery_group():
    assert "trufflehog" in DISCOVERY_MODULES


async def test_setup_warn_and_skips_without_binary():
    ModuleRegistry.discover()
    m = ModuleRegistry.load(names=["trufflehog"], controller=_mock_controller())[0]
    with patch("shutil.which", return_value=None):
        assert await m.setup() is False


async def test_batches_and_emits_redacted_findings():
    m, ctrl = await _load({"batch_size": 2})
    bodies = {
        "https://app.example.com/": "<html>ok</html>",
        "https://app.example.com/main.js": f'var t="{_GH}"',
    }
    run_proc, calls = _fake_run_proc({"ghp_": ("Github", _GH)})
    with patch("httpx.AsyncClient", return_value=_fake_client(bodies)), \
         patch.object(m, "run_proc", side_effect=run_proc):
        await m.handle_event(_event(EventType.HTTP_SERVICE, "https://app.example.com/"))
        assert not calls                                     # batch not full yet
        await m.handle_event(_event(EventType.URL, "https://app.example.com/main.js"))

    assert len(calls) == 1 and "--no-verification" in calls[0]   # one run for the batch
    finding = ctrl.stamp_and_publish.call_args_list[0][0][0]
    assert finding.type is EventType.FINDING_CANDIDATE
    d = finding.data
    assert d.category == "exposed-secret" and d.severity_hint == "high"
    assert d.host == "app.example.com"
    assert d.evidence["location"] == "https://app.example.com/main.js"   # mapped back by file
    assert d.evidence["engine"] == "trufflehog"
    assert str(d.evidence["verified"]) == "False"      # evidence values are stringified
    assert _GH not in json.dumps(d.model_dump(), default=str)          # never the raw secret
    await m.finish()


async def test_finish_flushes_remainder_and_cleans_up():
    m, ctrl = await _load({"batch_size": 50})
    workdir = m._workdir
    bodies = {"https://app.example.com/a.js": f'k="{_GH}"'}
    run_proc, calls = _fake_run_proc({"ghp_": ("Github", _GH)})
    with patch("httpx.AsyncClient", return_value=_fake_client(bodies)), \
         patch.object(m, "run_proc", side_effect=run_proc):
        await m.handle_event(_event(EventType.URL, "https://app.example.com/a.js"))
        assert not calls
        await m.finish()
    assert len(calls) == 1
    assert ctrl.stamp_and_publish.called
    assert not workdir.exists()                              # temp bodies removed


async def test_identical_bodies_on_same_host_scanned_once():
    m, _ = await _load({"batch_size": 50})
    same = f'k="{_GH}"'
    bodies = {"https://app.example.com/a.js": same, "https://app.example.com/b.js": same}
    with patch("httpx.AsyncClient", return_value=_fake_client(bodies)):
        await m.handle_event(_event(EventType.URL, "https://app.example.com/a.js"))
        await m.handle_event(_event(EventType.URL, "https://app.example.com/b.js"))
    assert len(m._batch) == 1
    await m.finish()


async def test_skips_non_text_url():
    m, ctrl = await _load()
    ev = _event(EventType.URL, "https://app.example.com/logo.png")
    ev.data = UrlData(url="https://app.example.com/logo.png", content_type="image/png")
    with patch("httpx.AsyncClient") as p:
        await m.handle_event(ev)
    p.assert_not_called()
    assert m._batch == []
    await m.finish()


async def test_error_page_is_scanned_and_status_recorded():
    m, ctrl = await _load({"batch_size": 50})
    url = "https://app.example.com/debug"
    run_proc, _ = _fake_run_proc({"ghp_": ("Github", _GH)})
    with patch("httpx.AsyncClient",
               return_value=_fake_client({url: f"Stack trace GH_TOKEN={_GH}"}, {url: 500})),          patch.object(m, "run_proc", side_effect=run_proc):
        await m.handle_event(_event(EventType.HTTP_SERVICE, url))
        await m.finish()
    d = ctrl.stamp_and_publish.call_args_list[0][0][0].data
    assert str(d.evidence["http_status"]) == "500"
    assert "HTTP 500 error page" in d.description


# ── live binary (skipped when trufflehog is not installed) ────────────────────

@pytest.mark.skipif(not shutil.which("trufflehog"), reason="trufflehog binary not installed")
async def test_live_binary_output_parses(tmp_path):
    import asyncio
    (tmp_path / "000001.txt").write_text(
        f'const c={{gh:"{_GH}",\n aws_id:"{_AWS_ID}",\n aws_secret:"{_AWS_SECRET}"}};\n'
    )
    proc = await asyncio.create_subprocess_exec(
        *build_command(str(tmp_path)),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    out, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
    findings = parse_trufflehog_json(out.decode())
    detectors = {f.detector for f in findings}
    assert {"Github", "AWS"} <= detectors
    assert all(f.file == "000001.txt" and not f.verified for f in findings)
    for f in findings:
        assert _GH not in f.redacted and _AWS_SECRET not in f.redacted
