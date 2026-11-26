"""
At-rest encryption for captured evidence bodies.

Bodies can contain secrets and PII, so a pentest finding's proof must not sit on
disk in plaintext. `EvidenceCipher` wraps Fernet (AES-128-CBC + HMAC, from the
`cryptography` package, the `evidence` extra):

  - The key is a urlsafe-base64 Fernet key from `RECON_AI_EVIDENCE_KEY`.
  - **Fail-closed:** no key ⇒ `enabled` is False and the store keeps bodies out
    of the DB entirely (never a plaintext fallback). A key set without the
    `cryptography` package installed raises at construction, not silently off.
  - `cryptography` is imported lazily so importing this module (and the whole
    evidence package) never requires the extra; only *configuring a key* does.

Generate a key once and keep it with the engagement:

    python -c "from evidence.crypto import EvidenceCipher; print(EvidenceCipher.generate_key())"
"""

from __future__ import annotations

import os


class EvidenceKeyError(RuntimeError):
    """A key was configured but could not be used (bad key, or lib missing)."""


class EvidenceCipher:
    """Encrypt/decrypt evidence bodies. Disabled (no-op, bodies not stored) when
    no key is configured."""

    def __init__(self, key: str | bytes | None) -> None:
        self._fernet = None
        if not key:
            return
        try:
            from cryptography.fernet import Fernet
        except ImportError as exc:  # key set but the optional dep is absent
            raise EvidenceKeyError(
                "RECON_AI_EVIDENCE_KEY is set but the 'cryptography' package is not "
                "installed — install the evidence extra (pip install -e .[evidence]) "
                "or unset the key. Fail-closed: refusing to store bodies in plaintext."
            ) from exc
        try:
            self._fernet = Fernet(key if isinstance(key, bytes) else key.encode())
        except (ValueError, TypeError) as exc:
            raise EvidenceKeyError(
                "RECON_AI_EVIDENCE_KEY is not a valid Fernet key (generate one with "
                "EvidenceCipher.generate_key()). Fail-closed."
            ) from exc

    @property
    def enabled(self) -> bool:
        return self._fernet is not None

    def encrypt(self, data: bytes) -> bytes:
        if self._fernet is None:
            raise EvidenceKeyError("no evidence key configured — cannot encrypt")
        return self._fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        if self._fernet is None:
            raise EvidenceKeyError("no evidence key configured — cannot decrypt")
        return self._fernet.decrypt(token)

    @classmethod
    def from_env(cls) -> "EvidenceCipher":
        return cls(os.environ.get("RECON_AI_EVIDENCE_KEY"))

    @staticmethod
    def generate_key() -> str:
        """A fresh urlsafe-base64 Fernet key (store it with the engagement)."""
        from cryptography.fernet import Fernet
        return Fernet.generate_key().decode()


_DISABLED = EvidenceCipher(None)


def get_cipher(obj) -> EvidenceCipher:
    """Return obj.evidence_cipher if it is a real EvidenceCipher, else a disabled
    one — mirrors ratelimit.get_limiter / policy.get_policy so a MagicMock
    controller (or a caller with none) degrades to bodies-not-stored, never a
    crash and never plaintext."""
    cipher = getattr(obj, "evidence_cipher", None)
    return cipher if isinstance(cipher, EvidenceCipher) else _DISABLED
