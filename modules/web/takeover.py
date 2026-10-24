"""
takeover — subdomain-takeover candidate detection (pure Python + HTTP verify).

Reactive module: on each DNS_RECORD CNAME, matches the target against a built-in
set of third-party service fingerprints (the can-i-take-over-xyz families). A
CNAME match alone is NOT a takeover — most CloudFront/S3/Netlify-fronted hosts
are perfectly claimed, live assets. So on a match we fetch the host and look for
the service's tell-tale *unclaimed* response fingerprint (e.g. S3's
"NoSuchBucket", GitHub Pages' "There isn't a GitHub Pages site here"):

  - fingerprint present            → HIGH  "Subdomain takeover ({service})"
  - resource is live / claimed     → no finding (this killed the CloudFront FP)
  - no reliable fingerprint for the
    service (e.g. CloudFront) or the
    host can't be fetched          → LOW   "Possible … — unverified" (keep lead)

A second, HTTP-independent signal is the state of the CNAME *target* itself: if
the target no longer resolves (NXDOMAIN), the alias is dangling to a removed /
unclaimed resource. This catches services that have no reliable body signature
(CloudFront is the classic case) which the body check alone can only mark LOW.
The two signals are combined conservatively:

  - unclaimed body fingerprint present   → HIGH   (confirmed)
  - target does not resolve (NXDOMAIN)    → MEDIUM (likely; provider-dependent)
    with no body proof
  - live / claimed resource               → no finding (kills the CloudFront FP)
  - otherwise (no fingerprint, host
    unreachable, resolution inconclusive) → LOW    (unverified lead)

Deterministic, no LLM. Verification can be disabled with options["verify"]=False
(restores the legacy CNAME-only behaviour, emitted at LOW).

Watches:  DNS_RECORD
Produces: FINDING_CANDIDATE
"""

from __future__ import annotations

import asyncio
import socket

from events.types import Event, EventType, FindingCandidateData
from modules.base import BaseModule
from modules.registry import register

# Signature DB version — recorded in each finding's evidence so a result can be
# traced to the fingerprint set that produced it (signatures change over time).
SIG_DB_VERSION = "2026.10"

# getaddrinfo errnos that mean "this name definitively does not exist" (as
# opposed to a temporary failure). Covers POSIX EAI_* and the Windows WSA codes
# (WSAHOST_NOT_FOUND=11001, WSANO_DATA=11004) so the dangling-target check is
# cross-platform. A temporary failure (EAI_AGAIN / WSATRY_AGAIN) is NOT here —
# it maps to "inconclusive", never to "dangling".
_NXDOMAIN_ERRNOS: set[int] = {11001, 11004}
for _name in ("EAI_NONAME", "EAI_NODATA"):
    _val = getattr(socket, _name, None)
    if isinstance(_val, int):
        _NXDOMAIN_ERRNOS.add(_val)

# (cname suffix/substring, service name). Non-exhaustive, high-signal subset.
_TAKEOVER_SIGS: list[tuple[str, str]] = [
    ("github.io", "GitHub Pages"),
    ("herokuapp.com", "Heroku"),
    ("herokudns.com", "Heroku"),
    ("s3.amazonaws.com", "AWS S3"),
    ("s3-website", "AWS S3"),
    ("cloudfront.net", "AWS CloudFront"),
    ("elasticbeanstalk.com", "AWS Elastic Beanstalk"),
    ("azurewebsites.net", "Azure App Service"),
    ("cloudapp.net", "Azure"),
    ("cloudapp.azure.com", "Azure"),
    ("trafficmanager.net", "Azure Traffic Manager"),
    ("blob.core.windows.net", "Azure Storage"),
    ("azureedge.net", "Azure CDN"),
    ("ghost.io", "Ghost"),
    ("pantheonsite.io", "Pantheon"),
    ("wpengine.com", "WP Engine"),
    ("zendesk.com", "Zendesk"),
    ("readthedocs.io", "Read the Docs"),
    ("surge.sh", "Surge.sh"),
    ("bitbucket.io", "Bitbucket"),
    ("netlify.app", "Netlify"),
    ("netlify.com", "Netlify"),
    ("myshopify.com", "Shopify"),
    ("statuspage.io", "Statuspage"),
    ("uservoice.com", "UserVoice"),
    ("helpjuice.com", "Helpjuice"),
    ("helpscoutdocs.com", "Help Scout"),
    ("tumblr.com", "Tumblr"),
    ("fastly.net", "Fastly"),
    ("firebaseapp.com", "Firebase"),
    ("wordpress.com", "WordPress.com"),
    ("gitbook.io", "GitBook"),
]

# service → substrings that appear ONLY when the backing resource is unclaimed
# (lower-cased match against the response body). Services absent here have no
# reliable body signature — a CNAME match to them cannot be auto-confirmed and
# is surfaced at LOW for manual verification (CloudFront is the classic case:
# a dangling CNAME is not claimable without additional conditions).
_UNCLAIMED_FINGERPRINTS: dict[str, list[str]] = {
    "AWS S3": ["nosuchbucket", "the specified bucket does not exist"],
    "GitHub Pages": ["there isn't a github pages site here"],
    "Heroku": ["no such app", "herokucdn.com/error-pages/no-such-app.html"],
    "Fastly": ["fastly error: unknown domain"],
    "Shopify": ["sorry, this shop is currently unavailable"],
    "Zendesk": ["help center closed", "this help center no longer exists"],
    "Ghost": ["the thing you were looking for is no longer here"],
    "WP Engine": ["the site you were looking for couldn't be found"],
    "Pantheon": ["the gods are wise, but do not know of the site which you seek"],
    "Surge.sh": ["project not found"],
    "Bitbucket": ["repository not found"],
    "Read the Docs": ["unknown to read the docs"],
    "Tumblr": ["whatever you were looking for doesn't currently exist at this address"],
    "Firebase": ["site not found"],
    "Statuspage": ["you are being redirected"],
    "Help Scout": ["no settings were found for this company"],
    "UserVoice": ["this uservoice subdomain is currently available"],
    "GitBook": ["if you need to create a new gitbook account"],
}


def classify_takeover(cname: str) -> str | None:
    """Return the service name if the CNAME target matches a known fingerprint."""
    c = (cname or "").strip().rstrip(".").lower()
    if not c:
        return None
    for sig, service in _TAKEOVER_SIGS:
        if sig in c:
            return service
    return None


def is_unclaimed(service: str, body: str | None) -> bool | None:
    """Decide from the HTTP body whether the backing resource looks unclaimed.

    True  — an unclaimed-service fingerprint is present (confirmed candidate).
    False — the service has a known fingerprint but the body doesn't match it,
            i.e. the resource is live/claimed (NOT a takeover).
    None  — no reliable fingerprint for this service, or no body to inspect;
            the caller should surface it as an unverified LOW candidate.
    """
    fps = _UNCLAIMED_FINGERPRINTS.get(service)
    if not fps:
        return None
    if body is None:
        return None
    text = body.lower()
    return any(fp in text for fp in fps)


def assess_takeover(
    service: str,
    body_unclaimed: bool | None,
    target_resolves: bool | None,
) -> tuple[bool, str, str]:
    """Pure takeover decision from the collected evidence.

    Inputs:
      body_unclaimed  — is_unclaimed() verdict (True/False/None)
      target_resolves — whether the CNAME target resolves (True/False/None)

    Returns ``(keep, severity, detection)`` where ``keep`` is False when the
    evidence shows a live/claimed resource (suppress the false positive), and
    ``detection`` names the deciding signal for the evidence record.

    Deny-order mirrors the scope engine's spirit — the strongest *positive*
    proof first, then the suppression of claimed resources, then the weaker
    dangling signal, then the unverified default.
    """
    # 1. HTTP body carries the service's unclaimed-resource fingerprint — the
    #    strongest signal we can get without claiming anything.
    if body_unclaimed is True:
        return True, "high", "unclaimed-fingerprint"
    # 2. Body proves a live / claimed resource behind a known service — this is
    #    the CloudFront/S3 false positive. Not a takeover.
    if body_unclaimed is False:
        return False, "", "claimed"
    # 3. Body inconclusive, but the CNAME target itself does not resolve
    #    (NXDOMAIN) — a dangling alias to a removed resource. Strong, but
    #    whether it is *claimable* is provider-dependent, so: MEDIUM, not HIGH.
    if target_resolves is False:
        return True, "medium", "cname-target-nxdomain"
    # 4. Nothing conclusive — keep as an unverified lead.
    return True, "low", "unverified"


@register
class TakeoverModule(BaseModule):
    name = "takeover"
    description = "Subdomain-takeover detection: dangling CNAME + HTTP fingerprint verify (no binary)"
    watched_events = ["DNS_RECORD"]
    produced_events = ["FINDING_CANDIDATE"]
    flags = ["active", "dns", "takeover", "fast"]
    options = {
        "verify": True,      # fetch the host and confirm the unclaimed fingerprint
        "timeout": 15,
        "max_body_kb": 512,
    }

    async def setup(self) -> bool:
        return True  # pure Python

    async def handle_event(self, event: Event) -> None:
        d = event.data
        if getattr(d, "record_type", "").upper() != "CNAME":
            return
        host = getattr(d, "hostname", "")
        target = getattr(d, "value", "")
        service = classify_takeover(target)
        if not service or not host:
            return

        body_unclaimed: bool | None = None
        target_resolves: bool | None = None
        status: int | None = None
        if self.opt("verify"):
            status, body = await self._fetch_body(host)
            body_unclaimed = is_unclaimed(service, body)
            # Only consult DNS resolution when the HTTP body didn't settle it:
            # a confirmed fingerprint needs no second signal, and a live/claimed
            # page already resolved. This also keeps the extra query off the
            # common cases.
            if body_unclaimed is None:
                target_resolves = await self._target_resolves(target)

        keep, severity, detection = assess_takeover(service, body_unclaimed, target_resolves)
        if not keep:
            # Live, claimed resource behind a known service — not a takeover.
            self._log.debug(
                "takeover: %s → %s is live/claimed (%s) — skipped",
                host, service, detection,
            )
            return

        if detection == "unclaimed-fingerprint":
            title = f"Subdomain takeover ({service})"
            description = (
                f"{host} has a dangling CNAME to {target} ({service}) and the host "
                f"returns {service}'s unclaimed-resource page — the backing resource "
                f"appears claimable. Verify by claiming a test resource before reporting."
            )
        elif detection == "cname-target-nxdomain":
            title = f"Likely subdomain takeover ({service}) — CNAME target does not resolve"
            description = (
                f"{host} has a CNAME to {target} ({service}), and {target} does not "
                f"resolve (NXDOMAIN) — a dangling alias to a removed or unclaimed "
                f"resource. If {service} allows re-registering this name, the "
                f"subdomain is claimable. Confirm the resource is actually claimable "
                f"with {service} before reporting; do not claim it on a live target."
            )
        else:
            title = f"Possible subdomain takeover ({service}) — unverified"
            description = (
                f"{host} has a CNAME to {target} ({service}). No reliable unclaimed "
                f"fingerprint could be confirmed automatically"
                + (" (service has no distinctive takeover signature)" if service not in _UNCLAIMED_FINGERPRINTS
                   else " (host was unreachable or returned a live page)")
                + ". Manually verify whether the resource is unclaimed before reporting."
            )
        evidence = {
            "cname": target,
            "service": service,
            "detection": detection,
            "sig_version": SIG_DB_VERSION,
        }
        if status is not None:
            evidence["http_status"] = str(status)
        if target_resolves is not None:
            evidence["cname_target_resolves"] = "true" if target_resolves else "false"

        await self.emit(
            EventType.FINDING_CANDIDATE,
            FindingCandidateData(
                host=host,
                title=title,
                description=description,
                category="subdomain-takeover",
                severity_hint=severity,
                evidence=evidence,
            ),
            source_event=event,
        )

    async def _target_resolves(self, target: str) -> bool | None:
        """Does the CNAME *target* resolve to an address?

        True  — resolves (the backing name exists).
        False — definitively does not exist (NXDOMAIN / host-not-found), checked
                twice to rule out a transient blip.
        None  — could not be determined (temporary failure, or check skipped).

        Read-only name lookup through the shared limiter; never raises.
        """
        name = (target or "").strip().rstrip(".")
        if not name:
            return None
        from policy import CAP_TARGET_DNS_QUERY
        if not self.capability_ok(CAP_TARGET_DNS_QUERY, action="CNAME-target resolve"):
            return None
        loop = asyncio.get_running_loop()
        nxdomain_seen = False
        # Two attempts: a single transient failure must not read as "dangling".
        for attempt in range(2):
            try:
                async with self.guard(f"dns:{name}"):
                    await loop.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
                return True
            except socket.gaierror as exc:
                if exc.errno in _NXDOMAIN_ERRNOS:
                    nxdomain_seen = True
                    continue  # re-observe before trusting an NXDOMAIN
                self._log.debug("takeover: resolve inconclusive for %s: %s", name, exc)
                return None
            except Exception as exc:  # pragma: no cover — defensive
                self._log.debug("takeover: resolve error for %s: %s", name, exc)
                return None
        return False if nxdomain_seen else None

    async def _fetch_body(self, host: str) -> tuple[int | None, str | None]:
        """GET the host (https then http) through the shared limiter; return
        (status, body|None). (None, None) on total failure. Never raises."""
        from policy import CAP_TARGET_HTTP_REQUEST
        if not self.capability_ok(CAP_TARGET_HTTP_REQUEST, action="takeover HTTP verify"):
            return None, None
        try:
            import httpx
        except ImportError:
            self._log.warning("httpx not installed — takeover verification skipped")
            return None, None
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            try:
                async with self.http_client(timeout=self.opt("timeout"), verify=False) as client:
                    async with self.guard(f"http:{host}"):
                        r = await client.get(url, follow_redirects=True)
                    self.inspect_response(r)
                    body = None
                    if len(r.content) / 1024 <= self.opt("max_body_kb"):
                        body = r.text
                    return r.status_code, body
            except Exception as exc:
                self._log.debug("takeover: fetch failed for %s: %s", url, exc)
                continue
        return None, None
