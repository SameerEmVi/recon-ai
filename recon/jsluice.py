"""
jsluice wrapper — AST-based URL/endpoint (and optional secret) extraction from JS.

jsluice (github.com/BishopFox/jsluice) parses JavaScript with a tree-sitter AST
rather than regexes, so it recovers request URLs, their HTTP method, and — its
distinctive value over regex miners (linkfinder/jsintel) — the **query and body
parameter names** attached to each request, even when they're built dynamically.

Two subcommands are used:
  * `jsluice urls  <file>`  → one JSON object per discovered request.
  * `jsluice secrets <file>`→ one JSON object per secret-shaped literal.

Files are passed as positional args (we write each fetched body to a temp file
and pass its path — the same pattern the trufflehog wrapper uses, and portable
to Windows where stdin piping of content is awkward).

Pure, unit-tested pieces:
  - `build_command()`      — the invocation for a given mode.
  - `parse_urls_json()`    — parse `urls` JSONL into JsluiceUrl records.
  - `parse_secrets_json()` — parse `secrets` JSONL into JsluiceSecret records.

SECURITY: `jsluice secrets` JSON carries the raw secret in `data`/`context`.
`parse_secrets_json` keeps ONLY the detector `kind` and `severity` — never the
value — so a secret never leaves this module. (Secret *content* detection is
owned by secretfinder/trufflehog; jsluice secrets is an opt-in, redacted signal.)
"""

from __future__ import annotations

import json
from dataclasses import dataclass

_MAX = 2048


@dataclass(frozen=True)
class JsluiceUrl:
    url: str
    method: str = "GET"
    kind: str = ""                       # jsluice "type": fetch/xhr/location/script…
    query_params: tuple[str, ...] = ()
    body_params: tuple[str, ...] = ()


@dataclass(frozen=True)
class JsluiceSecret:
    kind: str                            # detector name only — never the value
    severity: str = "info"


_MODES = ("urls", "secrets")


def build_command(path: str, *, mode: str = "urls", binary: str = "jsluice") -> list[str]:
    """Build a `jsluice <mode> <path>` command. Fail closed on a bad mode/target."""
    if mode not in _MODES:
        raise ValueError(f"invalid jsluice mode {mode!r} (urls|secrets)")
    if not path or path.startswith("-"):
        raise ValueError(f"refusing suspicious jsluice target {path!r}")
    return [binary, mode, path]


def _iter_json(text: str):
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict):
            yield obj


def _str_list(v) -> tuple[str, ...]:
    if not isinstance(v, (list, tuple)):
        return ()
    out = []
    for item in v:
        s = str(item).strip()[:128]
        if s and s not in out:
            out.append(s)
    return tuple(out)


def parse_urls_json(text: str) -> list[JsluiceUrl]:
    """Parse `jsluice urls` JSONL. Tolerant of noise/blank/garbage lines."""
    out: list[JsluiceUrl] = []
    for obj in _iter_json(text):
        url = str(obj.get("url") or "").strip()[:_MAX]
        if not url:
            continue
        method = (str(obj.get("method") or "GET").strip() or "GET").upper()[:16]
        kind = str(obj.get("type") or "").strip()[:32]
        out.append(JsluiceUrl(
            url=url,
            method=method,
            kind=kind,
            query_params=_str_list(obj.get("queryParams")),
            body_params=_str_list(obj.get("bodyParams")),
        ))
    return out


def parse_secrets_json(text: str) -> list[JsluiceSecret]:
    """Parse `jsluice secrets` JSONL — keeping ONLY kind + severity (never data)."""
    out: list[JsluiceSecret] = []
    for obj in _iter_json(text):
        kind = str(obj.get("kind") or "").strip()[:64]
        if not kind:
            continue
        sev = str(obj.get("severity") or "info").strip().lower()[:16]
        if sev not in ("info", "low", "medium", "high", "critical"):
            sev = "info"
        out.append(JsluiceSecret(kind=kind, severity=sev))
    return out
