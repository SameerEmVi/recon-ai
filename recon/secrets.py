"""
secrets — detect exposed credentials/keys in fetched web content.

Pure-Python (no binary). Given a blob of text (HTML, JS bundle, source map,
JSON config), `scan_text()` returns a list of SecretMatch, each with the secret
already REDACTED — the full value is never returned, logged, or stored.

Two detection layers:
  1. High-precision signatures (provider-specific key formats).
  2. Optional generic entropy pass: a key-ish assignment (api_key=..., token:...)
     whose value is long and high-entropy. Off unless include_entropy=True; low
     severity because it is the noisiest.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

# (name, severity, compiled-regex). Severity: low|medium|high|critical.
# Patterns are deliberately specific to keep false positives down.
_SIGNATURES: list[tuple[str, str, re.Pattern]] = [
    ("AWS Access Key ID", "high",
     re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16}\b")),
    ("AWS Secret Access Key", "critical",
     re.compile(r"""(?i)aws.{0,20}?(?:secret|sk).{0,20}?["'`]([A-Za-z0-9/+=]{40})["'`]""")),
    ("Google API Key", "high",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Google OAuth Access Token", "high",
     re.compile(r"\bya29\.[0-9A-Za-z\-_]{20,}")),
    ("GitHub Token", "high",
     re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b")),
    ("GitHub Fine-grained PAT", "high",
     re.compile(r"\bgithub_pat_[0-9A-Za-z_]{82}\b")),
    ("Slack Token", "high",
     re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,72}\b")),
    ("Slack Webhook", "medium",
     re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9_/]{40,}")),
    ("Stripe Live Secret Key", "critical",
     re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b")),
    ("Stripe Publishable Key", "low",
     re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b")),
    ("Twilio API Key", "high",
     re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("SendGrid API Key", "high",
     re.compile(r"\bSG\.[\w\-]{22}\.[\w\-]{43}\b")),
    ("Mailgun API Key", "medium",
     re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("npm Access Token", "high",
     re.compile(r"\bnpm_[0-9A-Za-z]{36}\b")),
    ("Facebook Access Token", "medium",
     re.compile(r"\bEAACEdEose0cBA[0-9A-Za-z]+")),
    ("Private Key Block", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JSON Web Token", "medium",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("Google (GCP) Service Account", "critical",
     re.compile(r'"type"\s*:\s*"service_account"')),
]

# Generic "<key-ish name> = <value>" for the entropy pass.
_GENERIC_ASSIGN = re.compile(
    r"""(?i)\b(api[_-]?key|apikey|secret|secret[_-]?key|password|passwd|pwd|
        access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b
        \s*[:=]\s*["'`]([^"'`\s]{16,80})["'`]""",
    re.VERBOSE,
)

_MIN_ENTROPY = 3.5   # Shannon bits/char; random base64/hex ~4.5-5.0
_MAX_MATCHES = 50    # cap per document to avoid flooding on a noisy file


@dataclass(frozen=True)
class SecretMatch:
    name: str
    severity: str
    redacted: str          # safe-to-store masked value
    index: int             # offset in the source text


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(value: str) -> str:
    """Mask a secret for safe display/storage: keep a few edge chars only."""
    v = value.strip()
    if "PRIVATE KEY" in v:
        return "-----BEGIN PRIVATE KEY----- [redacted]"
    if len(v) <= 8:
        return v[0] + "*" * (len(v) - 1) if v else ""
    keep = 4
    return f"{v[:keep]}{'*' * 8}{v[-keep:]} (len={len(v)})"


def scan_text(text: str, *, include_entropy: bool = True) -> list[SecretMatch]:
    """Return redacted SecretMatch list for `text`. Never returns raw secrets."""
    if not text:
        return []
    out: list[SecretMatch] = []
    seen: set[tuple[str, str]] = set()

    for name, severity, pat in _SIGNATURES:
        for m in pat.finditer(text):
            raw = m.group(0)
            red = redact(raw)
            key = (name, red)
            if key in seen:
                continue
            seen.add(key)
            out.append(SecretMatch(name=name, severity=severity, redacted=red, index=m.start()))
            if len(out) >= _MAX_MATCHES:
                return out

    if include_entropy:
        for m in _GENERIC_ASSIGN.finditer(text):
            var, val = m.group(1), m.group(2)
            if shannon_entropy(val) < _MIN_ENTROPY:
                continue
            red = redact(val)
            key = ("Generic High-Entropy Secret", red)
            if key in seen:
                continue
            seen.add(key)
            out.append(SecretMatch(
                name=f"High-Entropy Secret ({var})",
                severity="low",
                redacted=red,
                index=m.start(),
            ))
            if len(out) >= _MAX_MATCHES:
                break

    return out
