"""
cdncheck — decide whether an IP / CNAME belongs to a shared CDN or cloud edge.

Used by the resolved-IP port-scanning path: a domain that resolves to a CDN
edge (CloudFront, Cloudflare, Fastly, Akamai, …) means the IP is the provider's
*shared* infrastructure, not the target's own host. Port-scanning it is out of
authorization (you don't own Amazon's edge) and banned by every bug-bounty
program — so by default those IPs are skipped.

Detection is deterministic and offline:
  * IP → a curated set of well-known CDN/cloud edge CIDRs (covers the common
    footguns: CloudFront incl. 2600:9000::/28, Cloudflare, Fastly). This is the
    strong signal.
  * CNAME → a suffix match against known CDN/cloud hostnames (covers CNAME-only
    CDNs like Akamai whose IP ranges are too large/volatile to enumerate).

The list is intentionally conservative (big, stable ranges). It is a *safety*
guard, not an inventory: a miss means an IP is treated as non-CDN and scanned
(the operator opted into resolved-IP scanning), never the reverse — so it can
only ever under-skip, and the `--scan-cdn-ips` override exists for that.
"""

from __future__ import annotations

import ipaddress

# ── CNAME suffixes (host is CDN/cloud-fronted) ────────────────────────────────
CDN_CNAME_SUFFIXES: dict[str, str] = {
    "cloudfront.net": "aws-cloudfront",
    "amazonaws.com": "aws",
    "elb.amazonaws.com": "aws-elb",
    "cloudflare.net": "cloudflare",
    "cloudflare.com": "cloudflare",
    "cdn.cloudflare.net": "cloudflare",
    "akamaiedge.net": "akamai",
    "akamai.net": "akamai",
    "akamaihd.net": "akamai",
    "edgekey.net": "akamai",
    "edgesuite.net": "akamai",
    "akadns.net": "akamai",
    "fastly.net": "fastly",
    "fastlylb.net": "fastly",
    "azureedge.net": "azure",
    "azurefd.net": "azure",
    "trafficmanager.net": "azure",
    "windows.net": "azure",
    "googlehosted.com": "google",
    "googleusercontent.com": "google",
    "ghs.google.com": "google",
    "stackpathdns.com": "stackpath",
    "stackpathcdn.com": "stackpath",
    "bunnycdn.com": "bunnycdn",
    "b-cdn.net": "bunnycdn",
    "kxcdn.com": "keycdn",
    "cdn77.org": "cdn77",
    "incapdns.net": "imperva",
    "impervadns.net": "imperva",
}

# ── CDN/cloud edge CIDRs (curated — big, stable ranges) ───────────────────────
_CDN_CIDR_STR: dict[str, list[str]] = {
    "aws-cloudfront": [
        # IPv6 — one prefix covers all CloudFront v6 (e.g. 2600:9000:...).
        "2600:9000::/28",
        # IPv4 — representative CloudFront edge ranges (incl. 65.8/65.9).
        "65.8.0.0/16", "65.9.0.0/16", "64.252.0.0/18",
        "13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15", "54.182.0.0/16",
        "54.192.0.0/16", "54.230.0.0/16", "54.239.128.0/18", "99.84.0.0/16",
        "108.138.0.0/16", "108.156.0.0/14", "205.251.192.0/19", "130.176.0.0/16",
        "3.160.0.0/14", "18.160.0.0/15", "18.164.0.0/15", "18.172.0.0/15",
    ],
    "cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
        "2a06:98c0::/29", "2c0f:f248::/32",
    ],
    "fastly": [
        "151.101.0.0/16", "199.232.0.0/16", "2a04:4e42::/32",
    ],
}


def _build_networks():
    nets = []
    for provider, cidrs in _CDN_CIDR_STR.items():
        for c in cidrs:
            try:
                nets.append((ipaddress.ip_network(c), provider))
            except ValueError:
                continue
    return nets


_CDN_NETWORKS = _build_networks()


def cdn_provider_for_ip(ip: str) -> str | None:
    """Return the CDN/cloud provider name if `ip` is in a known edge range, else None."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    for net, provider in _CDN_NETWORKS:
        try:
            if addr in net:
                return provider
        except TypeError:
            continue   # v4 addr vs v6 net or vice versa
    return None


def cdn_provider_for_cname(cname: str) -> str | None:
    """Return the CDN/cloud provider name if `cname` matches a known CDN suffix."""
    if not cname:
        return None
    host = cname.strip().lower().rstrip(".")
    for suffix, provider in CDN_CNAME_SUFFIXES.items():
        if host == suffix or host.endswith("." + suffix):
            return provider
    return None


def cdn_provider(ip: str | None = None, cname: str | None = None) -> str | None:
    """Best available CDN verdict from an IP and/or a CNAME target (IP wins)."""
    return cdn_provider_for_ip(ip or "") or cdn_provider_for_cname(cname or "")
