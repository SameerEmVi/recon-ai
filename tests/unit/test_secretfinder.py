"""secretfinder detector + module tests."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from events.types import EventType, HttpServiceData, UrlData
from modules.registry import ModuleRegistry
from recon.secrets import redact, scan_text, shannon_entropy


def _mock_controller():
    ctrl = MagicMock()
    ctrl.scan_id = uuid.uuid4()
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    return ctrl


# ── detector ──────────────────────────────────────────────────────────────────

def test_detects_provider_keys():
    text = (
        "AKIAIOSFODNN7EXAMPLE "
        "AIzaSyA1234567890abcdefghijklmnopqrstuv "
        "ghp_0123456789abcdefghijklmnopqrstuvwxyz "
        "sk_live_0123456789abcdef0123456789"
    )
    names = {m.name for m in scan_text(text)}
    assert "AWS Access Key ID" in names
    assert "Google API Key" in names
    assert "GitHub Token" in names
    assert "Stripe Live Secret Key" in names


def test_private_key_and_severity():
    m = scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
    assert any(x.name == "Private Key Block" and x.severity == "critical" for x in m)


def test_never_returns_raw_secret():
    raw = "AKIAIOSFODNN7EXAMPLE"
    for m in scan_text(raw):
        assert raw not in m.redacted           # full value must be masked
        assert m.redacted.startswith("AKIA")   # but recognizable


def test_low_entropy_not_flagged():
    # A dictionary-word "secret" must not trip the entropy pass.
    assert scan_text('password = "password123"') == []


def test_entropy_pass_can_be_disabled():
    text = 'api_key = "a9F3kLpQ7zXcV2bNmW8sYtR4uEjH6dG1"'
    assert scan_text(text, include_entropy=True)
    assert scan_text(text, include_entropy=False) == []


def test_redact_and_entropy_helpers():
    assert redact("ABCDEFGHIJKLMNOP").startswith("ABCD")
    assert "PRIVATE KEY" in redact("-----BEGIN RSA PRIVATE KEY-----")
    assert shannon_entropy("aaaa") < shannon_entropy("aZ9$xQ2m")


# ── module ────────────────────────────────────────────────────────────────────

def _fake_client(body: str):
    resp = MagicMock()
    resp.text = body
    resp.content = body.encode()
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.get = AsyncMock(return_value=resp)
    return client


async def test_module_emits_finding_on_http_service():
    ModuleRegistry.discover()
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["secretfinder"], controller=ctrl)[0]

    event = MagicMock()
    event.type = EventType.HTTP_SERVICE
    event.data = HttpServiceData(url="https://app.example.com/", status_code=200)
    event.id = uuid.uuid4()
    event.distance = 2

    body = 'var cfg={key:"AKIAIOSFODNN7EXAMPLE"};'
    with patch("httpx.AsyncClient", return_value=_fake_client(body)):
        await m.handle_event(event)

    assert ctrl.stamp_and_publish.called
    finding = ctrl.stamp_and_publish.call_args_list[0][0][0]
    assert finding.type is EventType.FINDING_CANDIDATE
    assert finding.data.category == "exposed-secret"
    # redacted, not raw, in stored evidence
    assert "AKIAIOSFODNN7EXAMPLE" not in finding.data.evidence["match_redacted"]


async def test_module_skips_non_text_url():
    ModuleRegistry.discover()
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["secretfinder"], controller=ctrl)[0]

    event = MagicMock()
    event.type = EventType.URL
    event.data = UrlData(url="https://app.example.com/logo.png", content_type="image/png")
    event.id = uuid.uuid4()
    event.distance = 2

    with patch("httpx.AsyncClient", return_value=_fake_client("ignored")) as p:
        await m.handle_event(event)
    # never even constructed a client for a non-text URL
    p.assert_not_called()
    assert not ctrl.stamp_and_publish.called
