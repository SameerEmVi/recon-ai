"""
Email discovery (Stage 3 of the shared-fetch / email feature).

Covers:
  - the pure jsintel EmailExtractor (mailto + inline, noise rejected, lowercased)
  - EmailData validation + EMAIL dedup key (by address)
  - scope wiring: an EMAIL is scoped by its domain, so the gate drops
    out-of-scope (third-party) addresses
  - jsintel module emits EMAIL events; metascan extracts emails from metadata
"""

from __future__ import annotations

import types
import uuid
from unittest.mock import AsyncMock, MagicMock

from controller.controller import ScanController
from events.dedup import derive_dedup_key
from events.types import EmailData, EventType
from modules.registry import ModuleRegistry
from recon.jsintel import JsAnalysis, analyze
from recon.metadata import sensitive  # noqa: F401  (ensures module import path ok)
from scope.engine import ScopeEngine
from scope.types import Scope, ScopeStatus


# ── pure extractor ─────────────────────────────────────────────────────────────

def test_email_extractor_mailto_and_inline():
    content = """
      <a href="mailto:security@example.com">report</a>
      reach us at info@example.com or sales@example.com
      <img src="/sprite@2x.png"> noise@2x.png
      sentryDsn = "https://abc@sentry.io/123"
    """
    a = analyze(content, "https://example.com/contact")
    assert "security@example.com" in a.emails
    assert "info@example.com" in a.emails
    assert "sales@example.com" in a.emails
    # shape-matches that are not contactable addresses are rejected
    assert not any("2x.png" in e for e in a.emails)
    assert not any("sentry" in e for e in a.emails)


def test_email_extractor_lowercases_and_dedups():
    a = analyze("mailto:Admin@Example.com then Admin@example.com again", "https://e.com/")
    assert a.emails.count("admin@example.com") == 1


# ── EmailData + dedup ──────────────────────────────────────────────────────────

def test_emaildata_normalizes_address():
    d = EmailData(address="  INFO@Example.COM ", source="web-body")
    assert d.address == "info@example.com"


def test_email_dedup_key_by_address_case_insensitive():
    k1 = derive_dedup_key(EventType.EMAIL, EmailData(address="a@x.com", source="web-body"))
    k2 = derive_dedup_key(
        EventType.EMAIL, EmailData(address="A@X.com", source="document-metadata")
    )
    assert k1 == k2 == "email:a@x.com"


# ── scope wiring: email scoped by its domain ───────────────────────────────────

def test_candidate_from_scopes_email_by_domain():
    ev = types.SimpleNamespace(
        data=EmailData(address="joe@sub.example.com", source="web-body")
    )
    assert ScanController._candidate_from(ev) == "sub.example.com"


def test_candidate_from_ip_address_unchanged():
    # IpData.address (no '@') must still be returned verbatim.
    ev = types.SimpleNamespace(data=types.SimpleNamespace(address="10.0.0.5"))
    assert ScanController._candidate_from(ev) == "10.0.0.5"


# ── module emission + scope gate ───────────────────────────────────────────────

def _mock_controller():
    ctrl = MagicMock()
    ctrl.scan_id = uuid.uuid4()
    ctrl.knowledge_base = None                      # skip the learning path
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    return ctrl


def _event(url, etype=EventType.HTTP_SERVICE):
    ev = types.SimpleNamespace()
    ev.id = uuid.uuid4()
    ev.distance = 1
    ev.type = etype
    ev.data = types.SimpleNamespace(url=url)
    return ev


def _emitted(ctrl, etype):
    return [
        c[0][0].data
        for c in ctrl.stamp_and_publish.call_args_list
        if c[0][0].type == etype
    ]


async def test_jsintel_module_emits_email():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["js_intel"], controller=ctrl)[0]
    a = JsAnalysis(source_url="https://example.com/app.js")
    a.emails = ["info@example.com"]

    await m._emit_analysis(a, _event("https://example.com/app.js"))

    addrs = {d.address for d in _emitted(ctrl, EventType.EMAIL)}
    assert "info@example.com" in addrs
    assert _emitted(ctrl, EventType.EMAIL)[0].source == "web-body"


class _ScopingController:
    def __init__(self, scope: Scope):
        self.scan_id = uuid.uuid4()
        self.knowledge_base = None
        self._engine = ScopeEngine(scope)
        self.accepted: list = []

    async def stamp_and_publish(self, event) -> bool:
        cand = ScanController._candidate_from(event)
        decision = self._engine.evaluate(cand, source_distance=max(0, event.distance - 1))
        event.scope_status = decision.status
        if decision.status is ScopeStatus.IN:
            self.accepted.append(event)
            return True
        return False


async def test_out_of_scope_email_domain_dropped_by_gate():
    scope = Scope.from_strings(in_scope=["*.example.com", "example.com"], out_scope=[])
    ctrl = _ScopingController(scope)
    m = ModuleRegistry.load(names=["js_intel"], controller=ctrl)[0]
    a = JsAnalysis(source_url="https://example.com/app.js")
    a.emails = ["sec@example.com", "attacker@evil.com"]

    await m._emit_analysis(a, _event("https://example.com/app.js"))

    accepted = {
        e.data.address for e in ctrl.accepted if e.type is EventType.EMAIL
    }
    assert "sec@example.com" in accepted
    assert "attacker@evil.com" not in accepted   # third-party domain dropped


# ── metascan: emails from document metadata ────────────────────────────────────

def test_metascan_emails_in_meta():
    from modules.web.metascan import _emails_in_meta
    meta = {
        "Author": "Jane Doe <jane.doe@example.com>",
        "Creator": "Microsoft Word",
        "Company": "contact: ops@example.com",
        "Pages": 12,                       # non-string ignored
    }
    found = _emails_in_meta(meta)
    assert "jane.doe@example.com" in found
    assert "ops@example.com" in found
