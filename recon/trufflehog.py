"""
trufflehog wrapper — secret detection via the trufflehog binary.

trufflehog (github.com/trufflesecurity/trufflehog) ships ~800 provider-specific
detectors — far more than the hand-written signatures in `recon/secrets.py` —
and can optionally *verify* a candidate against the provider's API.

Pure, unit-testable pieces:
  - `build_command()`        — the `trufflehog filesystem` invocation.
  - `parse_trufflehog_json()`— parse `--json` output (one object per line).
  - `severity_for()`         — severity hint for a parsed finding.

SECURITY: trufflehog's JSON carries the FULL secret (`Raw`, `RawV2`,
`SecretParts`, sometimes `Redacted`/`ExtraData`). The parser redacts `Raw` via
`recon.secrets.redact` the moment it reads a line and keeps nothing else from
those fields, so a full secret never leaves this module (never logged, stored,
put on an event, or shown to the LLM).

Verification (`verify=True`) sends each candidate credential to the *provider's*
API (AWS STS, GitHub, Slack, …) — third-party traffic that uses a leaked
credential, which many bug bounty programs prohibit. It is therefore OFF by
default (`--no-verification`) and must be opted into explicitly.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from recon.secrets import redact

# Unverified detectors whose hits are worth more than "medium" on their own.
_HIGH_IMPACT = frozenset({
    "aws", "awssessionkey", "gcp", "gcpapplicationdefaultcredentials", "azure",
    "azurestorage", "azure_entra_serviceprincipal", "privatekey", "github",
    "githubapp", "gitlab", "stripe", "slack", "sendgrid", "twilio", "npmtoken",
    "mongodb", "postgres", "jdbc", "uri", "okta", "shopify", "square",
})


@dataclass(frozen=True)
class TruffleHogFinding:
    detector: str
    decoder: str               # PLAIN / BASE64 / UTF16 / ESCAPED_UNICODE …
    verified: bool
    verification_error: bool   # verification attempted but inconclusive
    redacted: str              # safe-to-store masked value — never the raw secret
    file: str                  # basename of the scanned file (maps back to a URL)
    line: int
    rotation_guide: str = ""


def build_command(
    target: str,
    *,
    binary: str = "trufflehog",
    verify: bool = False,
    results: str | None = None,
    exclude_detectors: str | None = None,
) -> list[str]:
    """Build a `trufflehog filesystem` command over a file or directory."""
    cmd = [binary, "filesystem", target, "--json", "--no-update", "--no-color"]
    if not verify:
        cmd.append("--no-verification")
    if results:
        cmd.append(f"--results={results}")
    if exclude_detectors:
        cmd.append(f"--exclude-detectors={exclude_detectors}")
    return cmd


def _basename(path: str) -> str:
    # trufflehog reports OS-native absolute paths; split on either separator.
    return re.split(r"[\\/]", path)[-1]


def parse_trufflehog_json(text: str) -> list[TruffleHogFinding]:
    """Parse trufflehog `--json` stdout. Non-JSON / malformed lines are skipped."""
    out: list[TruffleHogFinding] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict) or "DetectorName" not in obj:
            continue  # a log line, not a result
        raw = str(obj.get("Raw") or "")
        if not raw:
            continue
        fs = (((obj.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
        extra = obj.get("ExtraData") or {}
        guide = extra.get("rotation_guide") if isinstance(extra, dict) else None
        try:
            line_no = int(fs.get("line") or 0)
        except (TypeError, ValueError):
            line_no = 0
        out.append(TruffleHogFinding(
            detector=str(obj.get("DetectorName") or "unknown"),
            decoder=str(obj.get("DecoderName") or ""),
            verified=bool(obj.get("Verified")),
            verification_error=bool(obj.get("VerificationError")),
            redacted=redact(raw),
            file=_basename(str(fs.get("file") or "")),
            line=line_no,
            rotation_guide=guide if isinstance(guide, str) else "",
        ))
    return out


def severity_for(f: TruffleHogFinding) -> str:
    """verified → critical; unverified high-impact detector → high; else medium."""
    if f.verified:
        return "critical"
    if f.detector.lower() in _HIGH_IMPACT:
        return "high"
    return "medium"
