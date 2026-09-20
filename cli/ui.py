"""
cli/ui.py — zero-dependency ANSI colour output for the terminal.

Linux-first, no third-party deps. Colour auto-disables when stdout is not a TTY
(piped/redirected), when NO_COLOR is set, or when TERM=dumb — so logs, pipes and
tests stay plain text. Force it on/off with set_color(True/False).

Everything here returns strings (or prints); it never imports project modules, so
any layer can use it without creating an import cycle.
"""

from __future__ import annotations

import os
import sys
from typing import Any

# None = auto-detect; True/False = forced by --color / --no-color.
_ENABLED: bool | None = None

RESET = "\033[0m"

_FG = {
    "black": "30", "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "magenta": "35", "cyan": "36", "white": "37", "grey": "90",
    "bred": "91", "bgreen": "92", "byellow": "93", "bblue": "94",
    "bmagenta": "95", "bcyan": "96", "bwhite": "97",
}


def _auto() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def color_enabled() -> bool:
    return _auto() if _ENABLED is None else _ENABLED


def set_color(value: bool | None) -> None:
    """Force colour on (True), off (False), or back to auto-detect (None)."""
    global _ENABLED
    _ENABLED = value


def paint(text: Any, fg: str | None = None, *, bold: bool = False,
          dim: bool = False, under: bool = False) -> str:
    text = str(text)
    if not color_enabled():
        return text
    codes: list[str] = []
    if bold:
        codes.append("1")
    if dim:
        codes.append("2")
    if under:
        codes.append("4")
    if fg and fg in _FG:
        codes.append(_FG[fg])
    if not codes:
        return text
    return f"\033[{';'.join(codes)}m{text}{RESET}"


# ── banner ─────────────────────────────────────────────────────────────────────

_LOGO = r"""
   ___ ___ ___ ___  _  _    _   ___
  | _ \ __/ __/ _ \| \| |  /_\ |_ _|
  |   / _| (__| (_) | .` | / _ \ | |
  |_|_\___\___|\___/|_|\_|/_/ \_\___|
"""


def banner() -> str:
    """Colourful ASCII wordmark + tagline."""
    logo = paint(_LOGO.strip("\n"), "bcyan", bold=True)
    tag = paint("  AI-assisted reconnaissance", "grey", dim=True)
    warn = paint("· authorized targets only", "byellow")
    return f"{logo}\n{tag} {warn}\n"


# ── key/value + section helpers ─────────────────────────────────────────────────

def kv(label: str, value: Any) -> str:
    arrow = paint("▸", "bcyan")
    return f"{arrow} {paint(label.ljust(10), 'bwhite', bold=True)} {paint(value, 'white')}"


def rule(title: str = "", width: int = 62, fg: str = "bcyan") -> str:
    if not title:
        return paint("─" * width, fg)
    dashes = width - len(title) - 4
    left = "── "
    right = " " + "─" * max(0, dashes)
    return paint(left, fg) + paint(title, fg, bold=True) + paint(right, fg)


def section(title: str, count: int | None = None) -> str:
    label = title if count is None else f"{title} ({count})"
    return paint(f"◆ {label}", "bwhite", bold=True)


def bullet(text: str, fg: str | None = None) -> str:
    return f"  {paint('•', 'grey')} {paint(text, fg) if fg else text}"


def ok(text: str) -> str:
    return f"{paint('✔', 'bgreen', bold=True)} {text}"


def info(text: str) -> str:
    return f"{paint('ℹ', 'bblue')} {text}"


def warn(text: str) -> str:
    return f"{paint('⚠', 'byellow', bold=True)} {paint(text, 'byellow')}"


def sev_color(sev: str) -> str:
    return {
        "critical": "bred", "high": "red", "medium": "byellow",
        "low": "bblue", "info": "grey",
    }.get((sev or "info").lower(), "grey")


# ── live event line ─────────────────────────────────────────────────────────────

# (foreground, glyph) per event type value.
_EVENT_STYLE = {
    "SUBDOMAIN": ("cyan", "◈"),
    "DNS_RECORD": ("blue", "⋈"),
    "IP": ("bblue", "●"),
    "OPEN_PORT": ("byellow", "⊙"),
    "HTTP_SERVICE": ("bgreen", "⇄"),
    "TECHNOLOGY": ("bmagenta", "⚙"),
    "URL": ("blue", "→"),
    "ENDPOINT": ("bcyan", "⇢"),
    "PARAMETER": ("grey", "∴"),
    "ANOMALY": ("byellow", "△"),
    "FINDING_CANDIDATE": ("bred", "‼"),
}


def _describe(event: Any) -> str:
    d = event.data
    t = event.type.value

    def g(*names, default=""):
        for n in names:
            v = getattr(d, n, None)
            if v not in (None, ""):
                return v
        return default

    if t == "SUBDOMAIN":
        return str(g("hostname"))
    if t == "DNS_RECORD":
        return f"{g('hostname')} {g('record_type')} → {g('value')}"
    if t == "IP":
        return str(g("address"))
    if t == "OPEN_PORT":
        return f"{g('host')}:{g('port')}/{g('protocol', default='tcp')}"
    if t == "HTTP_SERVICE":
        srv = g("server")
        return f"[{g('status_code', default='?')}] {g('url')}" + (f"  {srv}" if srv else "")
    if t == "TECHNOLOGY":
        ver = g("version")
        src = g("source")
        name = f"{g('name')}{('/' + str(ver)) if ver else ''} on {g('host')}"
        return name + (f"  ({src})" if src else "")
    if t == "URL":
        return f"{g('method', default='GET')} {g('url')}"
    if t == "ENDPOINT":
        return f"{g('method', default='GET')} {g('url')}"
    if t == "PARAMETER":
        return f"{g('name')} ({g('location', default='query')}) @ {g('url')}"
    if t == "ANOMALY":
        return str(g("description", "host"))
    if t == "FINDING_CANDIDATE":
        sev = (g("severity_hint", default="info") or "info").upper()
        return f"[{sev}] {g('title')}  ({g('host')})"
    return str(getattr(d, "url", "") or getattr(d, "host", "") or "")


def event_line(event: Any) -> str:
    """Colourful one-line rendering of a discovered event for the live stream."""
    t = event.type.value
    fg, glyph = _EVENT_STYLE.get(t, ("white", "·"))
    tag = paint(f"{glyph} {t.lower():<13}", fg, bold=True)
    desc = _describe(event)
    if t == "FINDING_CANDIDATE":
        desc = paint(desc, "bred", bold=True)
    src = getattr(event, "source_tool", "")
    via = paint(f"  via {src}", "grey", dim=True) if src else ""
    return f"{tag} {desc}{via}"
