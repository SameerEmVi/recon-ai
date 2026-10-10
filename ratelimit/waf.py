"""
WAF / rate-limit-block detection from HTTP responses.

When a target is fronted by a WAF/CDN and starts challenging or blocking our
traffic, the polite (and stealthy) thing is to *slow down automatically* rather
than keep hammering it. This module turns one HTTP response (status + headers +
optional body snippet) into a WafSignal that the RateLimiter uses to back off.

Design notes:
  - Detection is best-effort and defensive: any unexpected input (including a
    unittest MagicMock) yields None instead of raising.
  - Two fingerprint classes, because a CDN is not a firewall:
      * WAF PRODUCT (active=True) — a dedicated web-application-firewall /
        security product (Imperva, Sucuri block, AWS WAF, ModSecurity, DataDome,
        FortiWeb…). Its mere presence on a 200 is *presence* (blocking=False, a
        mild slowdown); alongside a block status or block page it is *blocking*
        (aggressive backoff).
      * CDN / LB PRESENCE (active=False) — CloudFront, Cloudflare, Akamai, AWS
        ELB/API-GW, F5 LB. These headers (e.g. `x-amz-cf-id`, `cf-ray`) are on
        *every* response the CDN serves, block or not. They are NOT, by
        themselves, a firewall signal: a 403/404/503 from a CDN is routine
        (missing S3 object, origin error, app-level auth). Treating them as a
        block makes content-discovery — which deliberately probes hundreds of
        non-existent paths — self-throttle every CDN-fronted target to a crawl.
        A CDN only drives backoff when there is REAL block evidence: a block
        page, a 429, or a WAF-product fingerprint.
"""

from __future__ import annotations

from dataclasses import dataclass

# (header-name-lower, needle-lower, vendor, active). needle "" => match on any
# value. A header-name ending in "-" is a prefix match (e.g. "x-akamai-").
# active=True  => dedicated WAF/security product (block status beside it = block).
# active=False => CDN/LB presence header (never a block signal on its own).
_HEADER_SIGNS: list[tuple[str, str, str, bool]] = [
    # ── CDN / load-balancer presence (not a firewall signal by itself) ──
    ("server", "cloudflare", "Cloudflare", False),
    ("cf-ray", "", "Cloudflare", False),
    ("server", "akamaighost", "Akamai", False),
    ("x-akamai-", "", "Akamai", False),
    ("server", "awselb", "AWS ELB", False),
    ("x-amzn-requestid", "", "AWS", False),      # API Gateway / ALB — on every response
    ("x-amz-cf-id", "", "AWS CloudFront", False),  # on every CloudFront response
    ("server", "big-ip", "F5 BIG-IP", False),
    ("set-cookie", "bigipserver", "F5 BIG-IP", False),
    # ── dedicated WAF / security products (block status beside = active block) ──
    ("cf-mitigated", "", "Cloudflare", True),    # Cloudflare challenge/mitigation
    ("x-sucuri-id", "", "Sucuri", True),
    ("x-sucuri-block", "", "Sucuri", True),
    ("server", "sucuri", "Sucuri", True),
    ("x-iinfo", "", "Imperva Incapsula", True),
    ("x-cdn", "incapsula", "Imperva Incapsula", True),
    ("set-cookie", "incap_ses", "Imperva Incapsula", True),
    ("set-cookie", "visid_incap", "Imperva Incapsula", True),
    ("x-amzn-waf-", "", "AWS WAF", True),
    ("set-cookie", "ts01", "F5 BIG-IP ASM", True),
    ("server", "mod_security", "ModSecurity", True),
    ("server", "modsecurity", "ModSecurity", True),
    ("x-mod-security", "", "ModSecurity", True),
    ("server", "barracuda", "Barracuda", True),
    ("x-datadome", "", "DataDome", True),
    ("set-cookie", "datadome", "DataDome", True),
    ("server", "fortiweb", "FortiWeb", True),
    ("set-cookie", "fgd_icx", "FortiWeb", True),
    ("server", "wallarm", "Wallarm", True),
    ("server", "yunjiasu", "Baidu Yunjiasu", True),
    ("server", "nsfocus", "NSFOCUS", True),
    ("x-powered-by-anquanbao", "", "Anquanbao", True),
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

    waf_vendor: str | None = None   # from a dedicated WAF/security product
    cdn_vendor: str | None = None   # from a CDN/LB presence header only
    reasons: list[str] = []
    block_page = False

    for name, needle, vend, active in _HEADER_SIGNS:
        for hn, hv in _iter_headers(headers):
            name_match = hn == name or (name.endswith("-") and hn.startswith(name))
            if name_match and (needle == "" or needle in hv):
                if active:
                    waf_vendor = waf_vendor or vend
                else:
                    cdn_vendor = cdn_vendor or vend
                reasons.append(f"header:{hn}")
                break

    if isinstance(body, str) and body:
        low = body.lower()
        for needle, vend in _BODY_SIGNS:
            if needle in low:
                waf_vendor = waf_vendor or vend
                block_page = True
                reasons.append("block-page")
                break

    reason = ", ".join(dict.fromkeys(reasons))

    # 1. A dedicated WAF/security product fingerprint — trust it. Presence alone
    #    (e.g. a 200) is a mild slowdown; a block status or block page alongside
    #    it means active blocking.
    if waf_vendor is not None:
        return WafSignal(
            vendor=waf_vendor,
            reason=reason or (f"status:{st}" if st else "waf"),
            blocking=block_page or (st in _BLOCK_STATUS),
            status=st,
        )

    # 2. No WAF product, but a block/challenge PAGE body — still a block.
    if block_page:
        return WafSignal(vendor="Generic WAF", reason="block-page", blocking=True, status=st)

    # 3. A bare 429 is an explicit "slow down" — honor it as a rate-limit signal.
    #    Name the fronting CDN if we saw one, else a generic rate-limit.
    if st == 429:
        return WafSignal(vendor=cdn_vendor or "HTTP 429 rate-limit",
                         reason=reason or "status:429", blocking=True, status=st)

    # 4. A CDN/LB fingerprint ALONE (CloudFront, Cloudflare, Akamai, ELB, API-GW…)
    #    is NOT a firewall signal: it is on every response the CDN serves. A
    #    403/404/503 from a CDN is routine (missing S3 object, origin error, app
    #    auth), and content-discovery deliberately probes many non-existent paths,
    #    so backing off here would self-throttle every CDN-fronted target. Real
    #    block evidence (block page / 429 / WAF product) is handled above.
    #
    #    Likewise a bare 403/406/503 with no fingerprint is not a block (503 is a
    #    transient/overloaded server, e.g. web.archive.org).
    return None
