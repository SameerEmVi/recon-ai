"""
WAF / rate-limit-block detection from HTTP responses.

When a target is fronted by a WAF/CDN and starts challenging or blocking our
traffic, the polite (and stealthy) thing is to *slow down automatically* rather
than keep hammering it. This module turns one HTTP response (status + headers +
optional body snippet) into a WafSignal that the RateLimiter uses to back off.

Design notes:
  - Detection is best-effort and defensive: any unexpected input (including a
    unittest MagicMock) yields None instead of raising.
  - A bare WAF fingerprint on a 200 is *presence* (blocking=False) — a mild
    slowdown. A block/challenge status or block page is *blocking* (blocking=True)
    — an aggressive backoff.
"""

from __future__ import annotations

from dataclasses import dataclass

# (header-name-lower, needle-lower, vendor). needle "" => match on any value.
# A header-name ending in "-" is treated as a prefix match (e.g. "x-akamai-").
_HEADER_SIGNS: list[tuple[str, str, str]] = [
    ("server", "cloudflare", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("cf-mitigated", "", "Cloudflare"),
    ("server", "akamaighost", "Akamai"),
    ("x-akamai-", "", "Akamai"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-sucuri-block", "", "Sucuri"),
    ("server", "sucuri", "Sucuri"),
    ("x-iinfo", "", "Imperva Incapsula"),
    ("x-cdn", "incapsula", "Imperva Incapsula"),
    ("set-cookie", "incap_ses", "Imperva Incapsula"),
    ("set-cookie", "visid_incap", "Imperva Incapsula"),
    ("server", "awselb", "AWS ELB"),
    ("x-amzn-requestid", "", "AWS WAF"),
    ("x-amzn-waf-", "", "AWS WAF"),
    ("x-amz-cf-id", "", "AWS CloudFront"),
    ("server", "big-ip", "F5 BIG-IP"),
    ("set-cookie", "ts01", "F5 BIG-IP ASM"),
    ("set-cookie", "bigipserver", "F5 BIG-IP"),
    ("server", "mod_security", "ModSecurity"),
    ("server", "modsecurity", "ModSecurity"),
    ("x-mod-security", "", "ModSecurity"),
    ("server", "barracuda", "Barracuda"),
    ("x-datadome", "", "DataDome"),
    ("set-cookie", "datadome", "DataDome"),
    ("server", "fortiweb", "FortiWeb"),
    ("set-cookie", "fgd_icx", "FortiWeb"),
    ("server", "wallarm", "Wallarm"),
    ("server", "yunjiasu", "Baidu Yunjiasu"),
    ("server", "nsfocus", "NSFOCUS"),
    ("x-powered-by-anquanbao", "", "Anquanbao"),
]

# Case-insensitive body substrings that indicate a WAF block/challenge page.
_BODY_SIGNS: list[tuple[str, str]] = [
    ("attention required! | cloudflare", "Cloudflare"),
    ("cloudflare ray id", "Cloudflare"),
    ("checking your browser before accessing", "Cloudflare"),
    ("request unsuccessful. incapsula incident", "Imperva Incapsula"),
    ("the requested url was rejected", "F5 BIG-IP ASM"),
    ("sucuri website firewall", "Sucuri"),
    ("this request has been blocked", "Generic WAF"),
    ("you have been blocked", "Generic WAF"),
    ("access to this page has been denied", "Generic WAF"),
    ("web application firewall", "Generic WAF"),
]

# Status codes that (especially alongside a WAF fingerprint) indicate the target
# is actively blocking or throttling us.
_BLOCK_STATUS = frozenset({403, 406, 429, 503})


@dataclass(frozen=True)
class WafSignal:
    vendor: str          # best-guess vendor, or "Unknown WAF"
    reason: str          # short human-readable cause
    blocking: bool       # True => active block/challenge/throttle (aggressive backoff)
    status: int | None   # HTTP status if known


def _iter_headers(headers) -> list[tuple[str, str]]:
    """Flatten a headers object to lowercased (name, value) pairs.

    Returns [] for anything that isn't a real mapping (e.g. a test MagicMock),
    so detection degrades to a no-op instead of raising.
    """
    try:
        items = list(headers.items())
    except Exception:
        return []
    out: list[tuple[str, str]] = []
    for k, v in items:
        try:
            out.append((str(k).lower(), str(v).lower()))
        except Exception:
            continue
    return out


def detect(status=None, headers=None, body=None) -> WafSignal | None:
    """Return a WafSignal if the response shows WAF presence and/or blocking.

    All arguments are optional and defensively typed. Returns None when nothing
    WAF-like is found (the common, healthy case).
    """
    st: int | None = status if isinstance(status, int) else None

    vendor: str | None = None
    reasons: list[str] = []
    block_page = False

    for name, needle, vend in _HEADER_SIGNS:
        for hn, hv in _iter_headers(headers):
            name_match = hn == name or (name.endswith("-") and hn.startswith(name))
            if name_match and (needle == "" or needle in hv):
                vendor = vendor or vend
                reasons.append(f"header:{hn}")
                break

    if isinstance(body, str) and body:
        low = body.lower()
        for needle, vend in _BODY_SIGNS:
            if needle in low:
                vendor = vendor or vend
                block_page = True
                reasons.append("block-page")
                break

    dedup_reasons = list(dict.fromkeys(reasons))

    # 1. A real WAF/CDN fingerprint is present — trust it. A block status or a
    #    block page alongside it means active blocking.
    if vendor is not None:
        return WafSignal(
            vendor=vendor,
            reason=", ".join(dedup_reasons) or (f"status:{st}" if st else "waf"),
            blocking=block_page or (st in _BLOCK_STATUS),
            status=st,
        )

    # 2. No vendor fingerprint, but a block/challenge PAGE body — still a WAF.
    if block_page:
        return WafSignal(vendor="Generic WAF", reason="block-page", blocking=True, status=st)

    # 3. A bare 429 is an explicit "slow down" — honor it as a rate-limit signal
    #    (not a WAF), because the server is telling us to back off.
    if st == 429:
        return WafSignal(vendor="HTTP 429 rate-limit", reason="status:429",
                         blocking=True, status=st)

    # 4. A bare 403/406/503/5xx with NO WAF fingerprint is not a firewall signal.
    #    503 in particular is a transient/overloaded server (e.g. web.archive.org),
    #    so we do NOT back the whole scan off for it.
    return None
