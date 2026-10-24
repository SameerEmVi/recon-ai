"""
retire.js wrapper — detect JavaScript libraries with known vulnerabilities.

retire.js (github.com/RetireJS/retire.js, npm `retire`) fingerprints front-end
JS libraries (jQuery, Angular, Bootstrap, lodash, Moment, …) by file
content/hash and maps the detected **version** to known vulnerabilities (CVE /
GHSA) from its maintained advisory database. It complements the recon-ai
fingerprint module (which names technologies) and the native `known-cve` vuln
check (version→CVE correlation) with a purpose-built, regularly-updated JS
advisory source.

We scan a directory of fetched JS bodies in one `retire --path <dir>
--outputformat json` run (the npm process start + DB load dwarfs per-file work),
then map each result back to its source URL by file name.

Pure, unit-tested pieces:
  - `build_command()`     — the invocation.
  - `parse_retire_json()` — parse the JSON report into RetireComponent records.

ACCURACY: a retire.js hit is a **version-range match** against the library's
advisory DB. The version is read from the actual served file (stronger evidence
than a server banner), but a backported/patched fork can still make it a false
positive — so findings are emitted as POTENTIAL, never confirmed-exploitable.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class RetireVuln:
    severity: str                       # info/low/medium/high/critical
    cves: tuple[str, ...] = ()
    summary: str = ""
    info: tuple[str, ...] = ()          # reference URLs
    cwe: tuple[str, ...] = ()
    below: str = ""                     # vulnerable below this version
    at_or_above: str = ""               # … and at/above this one (range)


@dataclass(frozen=True)
class RetireComponent:
    component: str                      # e.g. "jquery"
    version: str                        # e.g. "1.8.3"
    file: str                           # basename of the scanned file → maps to URL
    detection: str = ""                 # filename / filecontent / hash / uri
    vulns: tuple[RetireVuln, ...] = field(default_factory=tuple)


def build_command(path: str, *, binary: str = "retire") -> list[str]:
    """Build a `retire --path <dir> --outputformat json` command. Fail closed."""
    if not path or path.startswith("-"):
        raise ValueError(f"refusing suspicious retire path {path!r}")
    # --outputformat json prints the report to stdout. retire exits non-zero when
    # vulns are found; the caller (run_proc) ignores the exit code and reads stdout.
    return [binary, "--path", path, "--outputformat", "json"]


def _basename(path: str) -> str:
    return re.split(r"[\\/]", str(path))[-1]


def _str_tuple(v) -> tuple[str, ...]:
    if not isinstance(v, (list, tuple)):
        return ()
    out = []
    for x in v:
        s = str(x).strip()[:256]
        if s and s not in out:
            out.append(s)
    return tuple(out)


def _extract_json(text: str):
    """Load the retire JSON report, tolerating leading/trailing noise."""
    text = text or ""
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except (ValueError, TypeError):
            return None
    return None


def parse_retire_json(text: str) -> list[RetireComponent]:
    """Parse `retire --outputformat json` output into RetireComponent records.

    Tolerant of noise and partial/malformed reports. Components with no
    vulnerabilities are still returned (useful as a JS-library fingerprint).
    """
    doc = _extract_json(text)
    if not isinstance(doc, dict):
        return []
    out: list[RetireComponent] = []
    for entry in doc.get("data") or []:
        if not isinstance(entry, dict):
            continue
        fname = _basename(entry.get("file") or "")
        for res in entry.get("results") or []:
            if not isinstance(res, dict):
                continue
            component = str(res.get("component") or "").strip()[:128]
            version = str(res.get("version") or "").strip()[:64]
            if not component:
                continue
            vulns: list[RetireVuln] = []
            for v in res.get("vulnerabilities") or []:
                if not isinstance(v, dict):
                    continue
                ids = v.get("identifiers") or {}
                vulns.append(RetireVuln(
                    severity=str(v.get("severity") or "medium").strip().lower()[:16],
                    cves=_str_tuple(ids.get("CVE")),
                    summary=str(ids.get("summary") or "").strip()[:512],
                    info=_str_tuple(v.get("info")),
                    cwe=_str_tuple(v.get("cwe")),
                    below=str(v.get("below") or "").strip()[:64],
                    at_or_above=str(v.get("atOrAbove") or "").strip()[:64],
                ))
            out.append(RetireComponent(
                component=component, version=version, file=fname,
                detection=str(res.get("detection") or "").strip()[:32],
                vulns=tuple(vulns),
            ))
    return out
