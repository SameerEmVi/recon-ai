"""
evidence — the captured-exchange evidence store for the agent-driven pentest
section (docs/pentest-section-design.md §6).

A pentest finding is only reportable when it points at the verbatim request/
response that proves it. This package captures those exchanges safely:

  - `crypto.EvidenceCipher` — at-rest encryption of bodies (Fernet). The key
    comes from `RECON_AI_EVIDENCE_KEY`; **fail-closed** — with no key, bodies are
    not persisted at all (only redacted metadata is), so plaintext bodies never
    land on disk by accident.
  - `capture.CapturedExchange` — redacts the URL + headers (`net.redact`), caps
    the body size, and produces the `HttpExchange` row. The LLM never sees a raw
    body; it is decrypted only for the authorized operator's display.

The deterministic-vs-LLM split holds here too: code owns capture, redaction,
encryption and the finding↔exchange link; the agent only reasons about what the
(redacted) evidence means.
"""

from __future__ import annotations

from evidence.capture import (
    MAX_BODY_BYTES,
    CapturedExchange,
    build_exchange,
    exchange_for_display,
)
from evidence.crypto import EvidenceCipher, get_cipher

__all__ = [
    "EvidenceCipher",
    "get_cipher",
    "CapturedExchange",
    "build_exchange",
    "exchange_for_display",
    "MAX_BODY_BYTES",
]
