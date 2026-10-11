"""
Version → known-vulnerability correlation, with uncertainty built in.

Requirement #4 is explicit: *do not* claim a CVE is present solely because a
version string matches. So this module never returns `CONFIRMED`. It returns
`POTENTIAL` when a detected version falls at/below a known-vulnerable ceiling,
and `UNCONFIRMED` when the fingerprint itself is uncertain — and every result
spells out the caveats (patched distributions, vendor backports, imprecise
fingerprints, missing version).

The bundled dataset below is a small, curated, *illustrative* set of well-known
client/server library issues — enough to demonstrate evidence-based correlation
and to unit-test it. In production you would point `load_dataset()` at a trusted,
regularly-updated vulnerability feed; the correlation logic here is the part that
matters and stays the same.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class KnownVuln:
    product: str          # lowercased technology name
    max_vulnerable: str   # highest version still affected (inclusive)
    fixed_in: str         # first fixed version
    cve: str
    cwe: str
    severity: str         # info/low/medium/high/critical
    summary: str


# Illustrative, conservative dataset. Keyed by lowercased product name.
_DATASET: list[KnownVuln] = [
    KnownVuln("jquery", "3.4.1", "3.5.0", "CVE-2020-11022", "CWE-79", "medium",
              "jQuery htmlPrefilter cross-site scripting via crafted HTML."),
    KnownVuln("jquery", "1.8.3", "1.9.0", "CVE-2012-6708", "CWE-79", "medium",
              "jQuery selector-based XSS (location.hash) in older 1.x."),
    KnownVuln("lodash", "4.17.11", "4.17.12", "CVE-2019-10744", "CWE-1321", "high",
              "lodash defaultsDeep prototype pollution."),
    KnownVuln("bootstrap", "3.4.0", "3.4.1", "CVE-2019-8331", "CWE-79", "medium",
              "Bootstrap XSS in data-template/tooltip/popover."),
    KnownVuln("angular.js", "1.7.9", "1.8.0", "CVE-2020-7676", "CWE-79", "medium",
              "AngularJS <1.8 sanitation bypass (xlink:href)."),
    KnownVuln("moment.js", "2.29.1", "2.29.2", "CVE-2022-24785", "CWE-22", "high",
              "moment.js path traversal in locale loading."),
    KnownVuln("nginx", "1.21.0", "1.21.1", "CVE-2021-23017", "CWE-193", "high",
              "nginx resolver off-by-one (DNS). Build/backport dependent."),
    KnownVuln("openssl", "1.0.1f", "1.0.1g", "CVE-2014-0160", "CWE-125", "critical",
              "OpenSSL Heartbleed memory disclosure."),
]


def load_dataset() -> list[KnownVuln]:
    return list(_DATASET)


# ── tolerant version comparison ─────────────────────────────────────────────

_VER_RE = re.compile(r"\d+")


def parse_version(v: str) -> tuple[int, ...]:
    """Parse a version string into a numeric tuple. Tolerant of 'v', suffixes,
    distro cruft ('1.2.3-ubuntu4'). Returns () when no numbers are present."""
    if not v:
        return ()
    # Cut at the first '-'/'+'/whitespace so distro/build suffixes don't skew it.
    head = re.split(r"[\s+\-~]", str(v).strip(), maxsplit=1)[0]
    nums = _VER_RE.findall(head)
    return tuple(int(n) for n in nums[:4])


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return (a > b) - (a < b)


def version_le(a: str, b: str) -> bool:
    """True if version a <= version b (tolerant). False if either unparseable."""
    pa, pb = parse_version(a), parse_version(b)
    if not pa or not pb:
        return False
    return _cmp(pa, pb) <= 0


@dataclass
class CveMatch:
    vuln: KnownVuln
    status: str          # POTENTIAL | UNCONFIRMED
    confidence: float
    rationale: str


def correlate(product: str, version: str | None, *, fingerprint_certain: bool = True) -> list[CveMatch]:
    """Correlate a detected product+version against known vulnerabilities.

    Never returns CONFIRMED. Rules:
      - version is None            → [] (we refuse to claim a CVE on name alone)
      - version <= max_vulnerable  → POTENTIAL (medium confidence) with caveats
      - uncertain fingerprint      → downgrade to UNCONFIRMED (low confidence)
    """
    if not product or not version:
        return []
    name = product.strip().lower()
    matches: list[CveMatch] = []
    for kv in _DATASET:
        if kv.product != name:
            continue
        if not version_le(version, kv.max_vulnerable):
            continue
        caveat = (
            "Version-string match only — a patched distribution, vendor backport, "
            "or spoofed banner can make this a false positive. Confirm the actual "
            "build before reporting."
        )
        if fingerprint_certain:
            matches.append(CveMatch(
                vuln=kv, status="POTENTIAL", confidence=0.5,
                rationale=f"Detected {product} {version} ≤ {kv.max_vulnerable} "
                          f"(fixed in {kv.fixed_in}). {caveat}",
            ))
        else:
            matches.append(CveMatch(
                vuln=kv, status="UNCONFIRMED", confidence=0.3,
                rationale=f"Uncertain fingerprint suggests {product} {version}; if "
                          f"accurate it is ≤ {kv.max_vulnerable} (fixed {kv.fixed_in}). {caveat}",
            ))
    return matches
