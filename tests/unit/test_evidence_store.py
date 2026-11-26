"""Evidence store: at-rest body encryption, redaction, finding link (§6)."""

from __future__ import annotations

import uuid

import pytest

from database.models import Finding, HttpExchange, ScanJob
from database.repository import FindingRepository, HttpExchangeRepository
from database.session import init_db, make_engine, make_session_factory
from evidence import (
    MAX_BODY_BYTES,
    CapturedExchange,
    build_exchange,
    exchange_for_display,
)
from evidence.crypto import EvidenceCipher, EvidenceKeyError, get_cipher

KEY = EvidenceCipher.generate_key()


def _cap(**kw) -> CapturedExchange:
    base = dict(
        host="api.example.com", method="get",
        url="https://user:pass@api.example.com/v1/users?token=secret123&page=2",
        status_code=200,
        request_headers={"Authorization": "Bearer abc", "Accept": "application/json"},
        response_headers={"Set-Cookie": "sid=xyz", "Content-Type": "application/json"},
        request_body="hello", response_body='{"ok": true}',
        duration_ms=12.5, source_tool="probe_url",
    )
    base.update(kw)
    return CapturedExchange(**base)


# ── crypto ───────────────────────────────────────────────────────────────────────

def test_cipher_roundtrip_and_disabled_state():
    c = EvidenceCipher(KEY)
    assert c.enabled
    assert c.decrypt(c.encrypt(b"secret body")) == b"secret body"

    off = EvidenceCipher(None)
    assert not off.enabled
    with pytest.raises(EvidenceKeyError):
        off.encrypt(b"x")


def test_bad_key_fails_closed():
    with pytest.raises(EvidenceKeyError):
        EvidenceCipher("not-a-valid-fernet-key")


def test_get_cipher_falls_back_to_disabled():
    from types import SimpleNamespace
    assert not get_cipher(SimpleNamespace()).enabled           # no attribute
    assert not get_cipher(SimpleNamespace(evidence_cipher=object())).enabled
    real = EvidenceCipher(KEY)
    assert get_cipher(SimpleNamespace(evidence_cipher=real)) is real


# ── redaction at capture ─────────────────────────────────────────────────────────

def test_url_and_headers_are_redacted_before_storage():
    ex = build_exchange(_cap(), EvidenceCipher(KEY), scan_id=uuid.uuid4())
    assert "user:pass@" not in ex.url                          # userinfo stripped
    assert "secret123" not in ex.url                           # secret query param masked
    assert ex.request_headers["Authorization"] == "***REDACTED***"
    assert ex.response_headers["Set-Cookie"] == "***REDACTED***"
    assert ex.request_headers["Accept"] == "application/json"  # ordinary header kept
    assert ex.method == "GET"


# ── bodies: encrypted when keyed, dropped when not (fail-closed) ──────────────────

def test_bodies_encrypted_with_key():
    cipher = EvidenceCipher(KEY)
    ex = build_exchange(_cap(), cipher, scan_id=uuid.uuid4())
    assert ex.body_encrypted and ex.bodies_dropped is None
    # Stored bytes are ciphertext, not the plaintext body.
    assert ex.response_body is not None and b'{"ok": true}' not in ex.response_body
    assert cipher.decrypt(ex.response_body) == b'{"ok": true}'
    assert ex.request_size == 5 and ex.response_size == 12


def test_bodies_dropped_without_key():
    ex = build_exchange(_cap(), EvidenceCipher(None), scan_id=uuid.uuid4())
    assert not ex.body_encrypted
    assert ex.request_body is None and ex.response_body is None
    assert ex.bodies_dropped and "not configured" in ex.bodies_dropped
    # Metadata is still captured (degrades to metadata-only, never plaintext).
    assert ex.request_size == 5 and ex.status_code == 200
    assert ex.request_headers["Authorization"] == "***REDACTED***"


def test_response_body_truncated_at_cap():
    big = "A" * (MAX_BODY_BYTES + 500)
    cipher = EvidenceCipher(KEY)
    ex = build_exchange(_cap(response_body=big), cipher, scan_id=uuid.uuid4())
    assert ex.response_truncated and ex.response_size == MAX_BODY_BYTES + 500
    assert len(cipher.decrypt(ex.response_body)) == MAX_BODY_BYTES


def test_no_bodies_is_not_a_drop():
    ex = build_exchange(_cap(request_body=None, response_body=None),
                        EvidenceCipher(None), scan_id=uuid.uuid4())
    assert ex.bodies_dropped is None and not ex.body_encrypted


# ── display view never leaks ciphertext ───────────────────────────────────────────

def test_display_decrypts_for_operator_and_hides_ciphertext():
    cipher = EvidenceCipher(KEY)
    ex = build_exchange(_cap(), cipher, scan_id=uuid.uuid4())
    view = exchange_for_display(ex, cipher)
    assert view["response_body"] == '{"ok": true}'            # decrypted for the operator
    assert view["bodies_available"] is True
    assert view["url"] and "secret123" not in view["url"]

    # Without the key, the operator view shows no body (never raw ciphertext).
    blind = exchange_for_display(ex, EvidenceCipher(None))
    assert blind["response_body"] is None and blind["bodies_available"] is False


# ── persistence + finding link ────────────────────────────────────────────────────

@pytest.fixture
async def session(tmp_path):
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'ev.db'}")
    await init_db(engine)
    factory = make_session_factory(engine)
    async with factory() as s:
        yield s
    await engine.dispose()


async def test_persist_and_link_to_finding(session):
    sid = uuid.uuid4()
    session.add(ScanJob(id=sid, target_domain="example.com", mode="pentest", status="running"))
    await session.commit()

    cipher = EvidenceCipher(KEY)
    repo = HttpExchangeRepository(session)
    ex = await repo.save(build_exchange(_cap(), cipher, scan_id=sid))
    assert ex.finding_id is None

    finding = await FindingRepository(session).save(Finding(
        scan_job_id=sid, host="api.example.com", title="t", description="",
        category="security-headers", severity_hint="low"))

    assert await repo.link_to_finding(ex.id, finding.id) is True
    # First claim wins: a second finding can't steal an already-linked exchange.
    other = await FindingRepository(session).save(Finding(
        scan_job_id=sid, host="api.example.com", title="t2", description="",
        category="info-disclosure", severity_hint="info"))
    assert await repo.link_to_finding(ex.id, other.id) is False

    linked = await repo.list_for_finding(finding.id)
    assert [e.id for e in linked] == [ex.id]
    assert len(await repo.list_for_scan(sid)) == 1
    # Stored body stays ciphertext at rest; only the display view decrypts it.
    stored = await repo.get(ex.id)
    assert b'{"ok": true}' not in (stored.response_body or b"")
    assert exchange_for_display(stored, cipher)["response_body"] == '{"ok": true}'
