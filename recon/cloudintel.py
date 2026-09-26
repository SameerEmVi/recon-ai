"""
recon.cloudintel — the pure core of the Cloud Asset Intelligence subsystem.

Evidence-based, deterministic (no LLM, no network, no destructive action)
fingerprinting and correlation of cloud infrastructure behind an authorized
target. Given evidence the pipeline already gathered — hostnames / CNAME targets
(DNS), HTTP response `server` headers and header names (HTTP), fingerprinted
technologies (from httpx/Wappalyzer), and cloud URLs referenced in JS/config —
it classifies which cloud providers and services a host uses, and correlates
multiple weak signals into a single asset with a combined confidence.

Providers/services covered: AWS (S3, CloudFront, ELB/ALB, API Gateway, Global
Accelerator), Azure (Blob/Storage, App Service, Front Door/CDN, Traffic Manager,
API Management, SQL, Key Vault), GCP (GCS, App Engine, Cloud Run, Cloud
Functions, Google APIs), Firebase (RTDB, Hosting, Storage), and CDNs (Cloudflare,
Fastly, Akamai, StackPath, BunnyCDN, KeyCDN, CDN77).

Nothing here accesses a cloud resource — it only interprets evidence. Active
verification (a benign existence check) is a separate, opt-in concern owned by
the module, never this engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

# ── weights ─────────────────────────────────────────────────────────────────

W_HIGH = 0.8      # a dedicated cloud endpoint / provider-specific header
W_MEDIUM = 0.5    # a fingerprinted technology / generic provider domain
W_LOW = 0.25      # a weak/ambiguous hint

# ── kinds ─────────────────────────────────────────────────────────────────────

STORAGE = "storage"
CDN = "cdn"
COMPUTE = "compute"
LB = "lb"
PAAS = "paas"
DATABASE = "database"
SECRETS = "secrets"
API = "api"
GENERIC = "generic"


@dataclass(frozen=True)
class CloudSignal:
    provider: str          # AWS | Azure | GCP | Firebase | Cloudflare | Fastly | Akamai | …
    service: str           # S3 | CloudFront | Blob Storage | GCS | …
    kind: str              # storage | cdn | compute | lb | paas | database | api | generic
    evidence: str          # short human-readable reason ("CNAME → …s3.amazonaws.com")
    weight: float          # confidence contribution 0..1
    source: str            # evidence channel: dns | http | tls | technology | js | hostname | ip


# ── hostname suffix signatures ────────────────────────────────────────────────
# (suffix, provider, service, kind, weight). Suffix matched on label boundary.

_HOST_SIGNS: list[tuple[str, str, str, str, float]] = [
    # AWS
    ("s3.amazonaws.com", "AWS", "S3", STORAGE, W_HIGH),
    ("s3-website", "AWS", "S3 Website", STORAGE, W_HIGH),
    (".s3.amazonaws.com", "AWS", "S3", STORAGE, W_HIGH),
    ("cloudfront.net", "AWS", "CloudFront", CDN, W_HIGH),
    ("elb.amazonaws.com", "AWS", "Elastic Load Balancer", LB, W_HIGH),
    ("execute-api", "AWS", "API Gateway", API, W_HIGH),
    ("awsglobalaccelerator.com", "AWS", "Global Accelerator", LB, W_HIGH),
    ("awsapprunner.com", "AWS", "App Runner", COMPUTE, W_HIGH),
    ("amazonaws.com", "AWS", "AWS", GENERIC, W_MEDIUM),
    # Azure
    ("blob.core.windows.net", "Azure", "Blob Storage", STORAGE, W_HIGH),
    ("file.core.windows.net", "Azure", "File Storage", STORAGE, W_HIGH),
    ("queue.core.windows.net", "Azure", "Queue Storage", STORAGE, W_HIGH),
    ("table.core.windows.net", "Azure", "Table Storage", STORAGE, W_HIGH),
    ("azurewebsites.net", "Azure", "App Service", COMPUTE, W_HIGH),
    ("azurefd.net", "Azure", "Front Door", CDN, W_HIGH),
    ("azureedge.net", "Azure", "CDN", CDN, W_HIGH),
    ("trafficmanager.net", "Azure", "Traffic Manager", LB, W_HIGH),
    ("azure-api.net", "Azure", "API Management", API, W_HIGH),
    ("database.windows.net", "Azure", "SQL Database", DATABASE, W_HIGH),
    ("vault.azure.net", "Azure", "Key Vault", SECRETS, W_HIGH),
    ("cloudapp.azure.com", "Azure", "Cloud Service", COMPUTE, W_MEDIUM),
    ("cloudapp.net", "Azure", "Cloud Service", COMPUTE, W_MEDIUM),
    # GCP
    ("storage.googleapis.com", "GCP", "Cloud Storage", STORAGE, W_HIGH),
    ("appspot.com", "GCP", "App Engine", COMPUTE, W_HIGH),
    ("run.app", "GCP", "Cloud Run", COMPUTE, W_HIGH),
    ("cloudfunctions.net", "GCP", "Cloud Functions", COMPUTE, W_HIGH),
    ("googleusercontent.com", "GCP", "Google", GENERIC, W_LOW),
    ("googleapis.com", "GCP", "Google APIs", API, W_MEDIUM),
    # Firebase
    ("firebaseio.com", "Firebase", "Realtime Database", DATABASE, W_HIGH),
    ("firebaseapp.com", "Firebase", "Hosting", COMPUTE, W_HIGH),
    ("web.app", "Firebase", "Hosting", COMPUTE, W_MEDIUM),
    ("firebasestorage.googleapis.com", "Firebase", "Storage", STORAGE, W_HIGH),
    # CDNs
    ("cloudflare.net", "Cloudflare", "CDN", CDN, W_HIGH),
    ("fastly.net", "Fastly", "CDN", CDN, W_HIGH),
    ("fastlylb.net", "Fastly", "CDN", CDN, W_HIGH),
    ("akamaiedge.net", "Akamai", "CDN", CDN, W_HIGH),
    ("akamaihd.net", "Akamai", "CDN", CDN, W_HIGH),
    ("akamai.net", "Akamai", "CDN", CDN, W_HIGH),
    ("edgekey.net", "Akamai", "CDN", CDN, W_HIGH),
    ("edgesuite.net", "Akamai", "CDN", CDN, W_HIGH),
    ("stackpathdns.com", "StackPath", "CDN", CDN, W_HIGH),
    ("b-cdn.net", "BunnyCDN", "CDN", CDN, W_HIGH),
    ("kxcdn.com", "KeyCDN", "CDN", CDN, W_HIGH),
    ("cdn77.org", "CDN77", "CDN", CDN, W_HIGH),
]

# ── HTTP header signatures ────────────────────────────────────────────────────
# (header-name-lower, needle-lower-or-"", provider, service, kind, weight)
# A header name ending in "-" is a prefix match.

_HEADER_SIGNS: list[tuple[str, str, str, str, str, float]] = [
    ("x-amz-request-id", "", "AWS", "S3", STORAGE, W_HIGH),
    ("x-amz-id-2", "", "AWS", "S3", STORAGE, W_HIGH),
    ("x-amz-cf-id", "", "AWS", "CloudFront", CDN, W_HIGH),
    ("x-amz-", "", "AWS", "AWS", GENERIC, W_MEDIUM),
    ("server", "amazons3", "AWS", "S3", STORAGE, W_HIGH),
    ("server", "awselb", "AWS", "Elastic Load Balancer", LB, W_HIGH),
    ("server", "cloudfront", "AWS", "CloudFront", CDN, W_HIGH),
    ("x-azure-ref", "", "Azure", "Front Door/CDN", CDN, W_HIGH),
    ("x-msedge-ref", "", "Azure", "Front Door/CDN", CDN, W_HIGH),
    ("x-ms-request-id", "", "Azure", "Storage", STORAGE, W_MEDIUM),
    ("x-ms-version", "", "Azure", "Storage", STORAGE, W_MEDIUM),
    ("server", "windows-azure-blob", "Azure", "Blob Storage", STORAGE, W_HIGH),
    ("x-goog-", "", "GCP", "Cloud Storage", STORAGE, W_HIGH),
    ("x-guploader-uploadid", "", "GCP", "Cloud Storage", STORAGE, W_HIGH),
    ("server", "uploadserver", "GCP", "Google", GENERIC, W_MEDIUM),
    ("server", "cloudflare", "Cloudflare", "CDN", CDN, W_HIGH),
    ("cf-ray", "", "Cloudflare", "CDN", CDN, W_HIGH),
    ("server", "akamaighost", "Akamai", "CDN", CDN, W_HIGH),
    ("x-akamai-", "", "Akamai", "CDN", CDN, W_HIGH),
    ("x-served-by", "cache-", "Fastly", "CDN", CDN, W_MEDIUM),
    ("x-fastly-", "", "Fastly", "CDN", CDN, W_HIGH),
    ("server", "fastly", "Fastly", "CDN", CDN, W_HIGH),
]

# ── technology-name signatures (Wappalyzer / fingerprint output) ───────────────
# (needle-lower, provider, service, kind, weight)

_TECH_SIGNS: list[tuple[str, str, str, str, float]] = [
    ("amazon s3", "AWS", "S3", STORAGE, W_HIGH),
    ("amazon cloudfront", "AWS", "CloudFront", CDN, W_HIGH),
    ("cloudfront", "AWS", "CloudFront", CDN, W_HIGH),
    ("amazon web services", "AWS", "AWS", GENERIC, W_MEDIUM),
    ("amazon", "AWS", "AWS", GENERIC, W_LOW),
    ("microsoft azure", "Azure", "Azure", GENERIC, W_MEDIUM),
    ("azure", "Azure", "Azure", GENERIC, W_LOW),
    ("google cloud", "GCP", "Google Cloud", GENERIC, W_MEDIUM),
    ("firebase", "Firebase", "Firebase", GENERIC, W_MEDIUM),
    ("cloudflare", "Cloudflare", "CDN", CDN, W_HIGH),
    ("fastly", "Fastly", "CDN", CDN, W_HIGH),
    ("akamai", "Akamai", "CDN", CDN, W_HIGH),
]

_RE_S3_LISTING = re.compile(r"<ListBucketResult|<Error><Code>(?:AccessDenied|NoSuchBucket)")


# ── classification (pure) ──────────────────────────────────────────────────────

def classify_hostname(hostname: str, *, source: str = "hostname") -> list[CloudSignal]:
    """Signals implied by a hostname or CNAME target."""
    h = (hostname or "").strip().lower().rstrip(".")
    if not h:
        return []
    out: list[CloudSignal] = []
    seen: set[tuple[str, str]] = set()
    for suffix, prov, svc, kind, w in _HOST_SIGNS:
        if _host_suffix_match(h, suffix):
            key = (prov, svc)
            if key in seen:
                continue
            seen.add(key)
            out.append(CloudSignal(prov, svc, kind, f"host matches *{suffix}", w, source))
    return out


def classify_headers(headers, *, server: str | None = None) -> list[CloudSignal]:
    """Signals implied by HTTP response headers (mapping) and/or a server string."""
    pairs = _iter_headers(headers)
    if server:
        pairs.append(("server", str(server).lower()))
    out: list[CloudSignal] = []
    seen: set[tuple[str, str, str]] = set()
    for hname, needle, prov, svc, kind, w in _HEADER_SIGNS:
        for hn, hv in pairs:
            name_ok = hn == hname or (hname.endswith("-") and hn.startswith(hname))
            if name_ok and (needle == "" or needle in hv):
                key = (prov, svc, "hdr")
                if key in seen:
                    break
                seen.add(key)
                out.append(CloudSignal(prov, svc, kind, f"header {hn}", w, "http"))
                break
    return out


def classify_technology(name: str) -> list[CloudSignal]:
    """Signals implied by a fingerprinted technology name."""
    n = (name or "").strip().lower()
    if not n:
        return []
    for needle, prov, svc, kind, w in _TECH_SIGNS:
        if needle in n:
            return [CloudSignal(prov, svc, kind, f"technology '{name}'", w, "technology")]
    return []


def classify_url(url: str, *, source: str = "js") -> list[CloudSignal]:
    """Signals implied by a URL referenced in JS / config / HTML."""
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return []
    return classify_hostname(host, source=source)


def looks_like_public_bucket_listing(body: str) -> bool:
    """True if a response body looks like an S3/GCS bucket XML listing/error.
    Used only by opt-in active verification — read-only, no enumeration."""
    return bool(body) and bool(_RE_S3_LISTING.search(body[:4096]))


# ── correlation ────────────────────────────────────────────────────────────────

@dataclass
class CloudAsset:
    host: str
    provider: str
    service: str
    kind: str
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    verified: bool = False

    def label(self) -> str:
        return f"{self.provider} {self.service}".strip()


class CloudCorrelator:
    """Accumulates CloudSignals per (host, provider, service) into assets, using
    a noisy-OR combine so multiple independent weak signals raise confidence
    without ever exceeding 1.0."""

    def __init__(self) -> None:
        self._assets: dict[tuple[str, str, str], CloudAsset] = {}

    def add(self, host: str, signals: list[CloudSignal]) -> list[CloudAsset]:
        """Fold signals into the host's assets; return the assets they touched."""
        host = (host or "").strip().lower()
        touched: dict[tuple[str, str, str], CloudAsset] = {}
        for s in signals:
            key = (host, s.provider, s.service)
            asset = self._assets.get(key)
            if asset is None:
                asset = CloudAsset(host, s.provider, s.service, s.kind)
                self._assets[key] = asset
            # noisy-OR: conf = 1 - (1-conf)*(1-w)
            asset.confidence = round(1.0 - (1.0 - asset.confidence) * (1.0 - s.weight), 4)
            if s.evidence not in asset.evidence:
                asset.evidence.append(s.evidence)
            asset.sources.add(s.source)
            touched[key] = asset
        return list(touched.values())

    def assets(self, *, min_confidence: float = 0.0) -> list[CloudAsset]:
        return [a for a in self._assets.values() if a.confidence >= min_confidence]


# ── internals ───────────────────────────────────────────────────────────────

def _host_suffix_match(host: str, suffix: str) -> bool:
    s = suffix.lstrip(".")
    if host == s or host.endswith("." + s):
        return True
    # An infix label token (e.g. "execute-api", "s3-website") — match if it
    # appears as, or within, one of the host's labels.
    if "." not in s:
        return any(s == label or s in label for label in host.split("."))
    return False


def _iter_headers(headers) -> list[tuple[str, str]]:
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
