"""
takeover — subdomain-takeover candidate detection (pure Python + optional dnstake).

Reactive module: on each DNS_RECORD CNAME, matches the target against a built-in
set of third-party service fingerprints (the can-i-take-over-xyz families). A
dangling CNAME to an unclaimed service is emitted as a FINDING_CANDIDATE
(category "subdomain-takeover") for verification — deterministic, no LLM.

Watches:  DNS_RECORD
Produces: FINDING_CANDIDATE
"""

from __future__ import annotations

from events.types import Event, EventType, FindingCandidateData
from modules.base import BaseModule
from modules.registry import register

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


def classify_takeover(cname: str) -> str | None:
    """Return the service name if the CNAME target matches a known fingerprint."""
    c = (cname or "").strip().rstrip(".").lower()
    if not c:
        return None
    for sig, service in _TAKEOVER_SIGS:
        if sig in c:
            return service
    return None


@register
class TakeoverModule(BaseModule):
    name = "takeover"
    description = "Subdomain-takeover candidate detection from dangling CNAMEs (no binary)"
    watched_events = ["DNS_RECORD"]
    produced_events = ["FINDING_CANDIDATE"]
    flags = ["active", "dns", "takeover", "fast"]

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
        await self.emit(
            EventType.FINDING_CANDIDATE,
            FindingCandidateData(
                host=host,
                title=f"Possible subdomain takeover ({service})",
                description=(
                    f"{host} has a dangling CNAME to {target} ({service}). "
                    f"If the backing resource is unclaimed, the subdomain may be "
                    f"takeover-able. Verify before reporting."
                ),
                category="subdomain-takeover",
                severity_hint="high",
                evidence={"cname": target, "service": service},
            ),
            source_event=event,
        )
