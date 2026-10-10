"""
related_domains — horizontal discovery of sibling ROOT domains the target org owns.

Every other enumeration module is vertical (subdomains *under* the seed). This
one looks sideways: e.g. for oceaniahealthcare.co.nz it finds oceanialiving.nz,
waterfordvillage.co.nz, qualcare.co.nz, …

Candidate generators (deterministic, no LLM):
  brand-tld     seed label across TLDs              oceaniahealthcare.{com,nz,…}
  brand-keyword brand stem × keyword × TLD          oceania{living,village,care}.*
  sub-label     discovered subdomain labels → apex  waterford.<seed> → waterfordvillage.co.nz
  crt.sh        other roots sharing certificates with the seed
  securitytrails / reverse-whois   optional, need API keys

Validation (DNS-over-HTTPS, so no packets reach the candidate):
  identical NS set, same MX set, infra (NS/MX/SPF) hosted on the seed domain,
  shared TXT verification tokens. Optional `http_check` also GETs the candidate
  homepage once and scores a redirect into the seed domain — this DOES contact
  a host outside scope, so it is opt-in (CLI: --related-http).

Scope: candidates are NOT in scope and are never emitted as SUBDOMAIN, so
nothing downstream scans them. Each is reported as a FINDING_CANDIDATE
(category "related-domain", severity "info") attached to the in-scope seed
host, for a human to confirm ownership/program scope and add via --in-scope.

Watches:  SUBDOMAIN (collects labels; the work runs in finish())
Produces: FINDING_CANDIDATE
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass, field

from events.types import Event, EventType, FindingCandidateData
from modules.base import BaseModule
from modules.registry import register

# Multi-label public suffixes. Not the full PSL — the common registrable
# second-levels; anything else falls back to "last label is the suffix".
_MULTI_SUFFIXES = {
    # NZ
    "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz", "geek.nz", "gen.nz",
    "kiwi.nz", "maori.nz", "school.nz", "health.nz", "iwi.nz", "mil.nz",
    # AU
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    # UK
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "ac.uk", "gov.uk",
    # misc common
    "co.jp", "ne.jp", "or.jp", "co.za", "org.za", "com.br", "com.mx", "com.sg",
    "com.my", "com.hk", "com.cn", "com.tw", "co.in", "co.kr", "co.id", "com.ar",
    "com.tr", "com.ph", "co.il",
}

_DEFAULT_TLDS = ["com", "net", "org", "co", "io", "nz", "co.nz", "com.au", "au", "co.uk"]

# Words stripped off the seed label to find the brand stem, and recombined
# with the stem to build candidates. "" = the bare stem.
_DEFAULT_KEYWORDS = [
    "", "care", "healthcare", "health", "living", "village", "villages",
    "group", "holdings", "hq", "online", "app", "global", "nz",
]

# Subdomain labels that are infrastructure, not brands/sites.
_GENERIC_LABELS = {
    "www", "www2", "api", "app", "apps", "mail", "email", "smtp", "imap", "pop",
    "mx", "ns", "ns1", "ns2", "dns", "vpn", "remote", "portal", "login", "auth",
    "sso", "id", "admin", "cms", "dev", "test", "stage", "staging", "uat", "qa",
    "prod", "beta", "demo", "cdn", "static", "assets", "images", "img", "media",
    "files", "docs", "help", "support", "status", "blog", "news", "shop",
    "store", "careers", "jobs", "autodiscover", "lyncdiscover", "sip", "webmail",
    "owa", "exchange", "ftp", "sftp", "git", "gitlab", "jenkins", "jira",
    "confluence", "wiki", "intranet", "extranet", "internal", "citrix", "gateway",
    "proxy", "cpanel", "whm", "webdisk", "enterpriseenrollment",
    "enterpriseregistration", "selector1", "selector2", "_dmarc", "go", "link",
    "links", "track", "click", "email-marketing", "info", "secure", "my", "m",
    "mobile", "web", "server", "host", "cloud", "backup", "db", "sql", "search",
}

_CONF_RANK = {"low": 1, "medium": 2, "high": 3}


# ── pure helpers (unit-tested directly) ───────────────────────────────────────

def split_registrable(host: str) -> tuple[str, str] | None:
    """Return (label, suffix) of the registrable domain of `host`, or None.

    "a.b.oceaniahealthcare.co.nz" → ("oceaniahealthcare", "co.nz")
    """
    labels = [p for p in (host or "").strip().lower().rstrip(".").split(".") if p]
    if len(labels) < 2:
        return None
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        return labels[-3], ".".join(labels[-2:])
    if ".".join(labels[-2:]) in _MULTI_SUFFIXES:  # host IS a public suffix
        return None
    return labels[-2], labels[-1]


def registrable_domain(host: str) -> str | None:
    parts = split_registrable(host)
    return f"{parts[0]}.{parts[1]}" if parts else None


def tld_family(suffix: str) -> list[str]:
    """Suffixes 'near' the seed's: co.nz → [co.nz, nz]; com → [com]."""
    fam = [suffix]
    if "." in suffix:
        fam.append(suffix.rsplit(".", 1)[1])
    return fam


def brand_stems(label: str, keywords: list[str], extra: list[str] | None = None) -> list[str]:
    """The seed label plus that label with one trailing keyword stripped.

    "oceaniahealthcare" → ["oceaniahealthcare", "oceania"]
    """
    stems = [label]
    for kw in sorted((k for k in keywords if k), key=len, reverse=True):
        if label.endswith(kw) and len(label) - len(kw) >= 3:
            stems.append(label[: -len(kw)].rstrip("-"))
            break
    for b in extra or []:
        b = re.sub(r"[^a-z0-9-]", "", b.lower())
        if b:
            stems.append(b)
    return list(dict.fromkeys(stems))


def interesting_labels(hosts: list[str], seed: str, limit: int = 60) -> list[str]:
    """First labels of discovered subdomains of `seed` that look like brands/sites."""
    out: list[str] = []
    for h in hosts:
        h = h.strip().lower().rstrip(".")
        if not h.endswith("." + seed):
            continue
        lab = h[: -(len(seed) + 1)].split(".")[-1]  # label directly under the seed
        if (
            lab in _GENERIC_LABELS or len(lab) < 4 or len(lab) > 40
            or re.search(r"\d", lab) or not re.fullmatch(r"[a-z-]+", lab)
            or lab.startswith(("_", "-")) or lab.endswith("-")
        ):
            continue
        if lab not in out:
            out.append(lab)
        if len(out) >= limit:
            break
    return out


def generate_candidates(
    seed: str,
    sub_labels: list[str],
    *,
    keywords: list[str] | None = None,
    tlds: list[str] | None = None,
    brands: list[str] | None = None,
    max_candidates: int = 2000,
) -> dict[str, str]:
    """Build {candidate_root_domain: generator} for `seed`. Pure — no network."""
    parts = split_registrable(seed)
    if not parts:
        return {}
    label, suffix = parts
    seed_root = f"{label}.{suffix}"
    keywords = _DEFAULT_KEYWORDS if keywords is None else keywords
    tlds = list(dict.fromkeys(tld_family(suffix) + (_DEFAULT_TLDS if tlds is None else tlds)))
    family = tld_family(suffix)

    out: dict[str, str] = {}

    def add(name: str, tld: str, source: str) -> None:
        name = name.strip("-")
        if len(out) >= max_candidates or not name or len(name) > 63:
            return
        d = f"{name}.{tld}"
        if d != seed_root and d not in out:
            out[d] = source

    for tld in tlds:                                   # oceaniahealthcare.{com,nz,…}
        add(label, tld, "brand-tld")
    for stem in brand_stems(label, keywords, brands):  # oceania{living,care}.*
        for kw in keywords:
            for tld in tlds:
                add(stem + kw, tld, "brand-keyword")
    for lab in sub_labels:                             # waterford → waterfordvillage.co.nz
        for name in [lab, "the" + lab, lab.replace("-", "")] + [lab + kw for kw in keywords if kw]:
            for tld in family:
                add(name, tld, "sub-label")
    return out


def parse_doh(payload: dict) -> list[str] | None:
    """Answer data values from a DoH JSON response; None if NXDOMAIN."""
    if not isinstance(payload, dict) or payload.get("Status") == 3:
        return None
    return [
        str(a.get("data", "")).strip().strip('"').rstrip(".").lower()
        for a in payload.get("Answer") or []
        if a.get("data")
    ]


def roots_from_crtsh(entries: list, seed_root: str) -> set[str]:
    """Registrable domains other than the seed that appear on the seed's certs."""
    out: set[str] = set()
    for e in entries if isinstance(entries, list) else []:
        for raw in str(e.get("name_value", "")).split("\n"):
            root = registrable_domain(raw.strip().lstrip("*."))
            if root and root != seed_root:
                out.add(root)
    return out


def parse_securitytrails(payload: dict) -> list[str]:
    recs = payload.get("records") if isinstance(payload, dict) else None
    return [str(r["hostname"]).lower() for r in recs or [] if isinstance(r, dict) and r.get("hostname")]


def parse_reverse_whois(payload: dict) -> list[str]:
    lst = payload.get("domainsList") if isinstance(payload, dict) else None
    return [str(d).lower() for d in lst or [] if d]


@dataclass
class DomainProfile:
    exists: bool = False
    ns: set[str] = field(default_factory=set)
    mx: set[str] = field(default_factory=set)
    txt: set[str] = field(default_factory=set)
    redirect: str | None = None   # final URL, set only if it lands on the seed


def _mx_hosts(values: list[str]) -> set[str]:
    # DoH MX data is "priority host"
    return {v.split()[-1] for v in values if v.split()}


def _is_on(host: str, root: str) -> bool:
    return host == root or host.endswith("." + root)


def score_candidate(seed_root: str, seed: DomainProfile, cand: DomainProfile,
                    sources: set[str]) -> tuple[int, list[str]]:
    """Deterministic ownership score + human-readable signals."""
    pts, sig = 0, []
    if cand.redirect:
        pts += 3; sig.append("redirects-to-seed")
    if "crt.sh" in sources:
        pts += 3; sig.append("shares-certificate")
    if "reverse-whois" in sources:
        pts += 3; sig.append("same-registrant")
    if "securitytrails" in sources:
        pts += 2; sig.append("securitytrails-associated")
    if any(_is_on(h, seed_root) for h in cand.ns | cand.mx):
        pts += 3; sig.append("infra-on-seed-domain")
    elif any(seed_root in t for t in cand.txt if t.startswith("v=spf1")):
        pts += 3; sig.append("spf-references-seed")
    if cand.ns and cand.ns == seed.ns:
        pts += 2; sig.append("same-ns-set")
    elif cand.ns & seed.ns:
        pts += 1; sig.append("shared-ns")
    if cand.mx and cand.mx == seed.mx:
        pts += 1; sig.append("same-mx-set")
    shared = {t for t in cand.txt & seed.txt if not t.startswith("v=spf1") and len(t) >= 16}
    if shared:
        pts += 3; sig.append("shared-txt-token")
    return pts, sig


def confidence(points: int) -> str | None:
    if points >= 3:
        return "high"
    if points == 2:
        return "medium"
    if points == 1:
        return "low"
    return None


# ── module ────────────────────────────────────────────────────────────────────

@register
class RelatedDomainsModule(BaseModule):
    name = "related_domains"
    description = "Horizontal discovery: sibling root domains owned by the same org (reported, not scanned)"
    watched_events = ["SUBDOMAIN"]
    produced_events = ["FINDING_CANDIDATE"]
    flags = ["passive", "related-domains", "dns", "slow"]
    options = {
        "keywords": None,          # None = _DEFAULT_KEYWORDS
        "tlds": None,              # None = _DEFAULT_TLDS
        "brands": [],              # extra brand stems, e.g. ["oceania"]
        "max_candidates": 2000,
        "max_labels": 60,
        "concurrency": 20,
        "min_confidence": "medium",
        "doh_url": "https://cloudflare-dns.com/dns-query",
        "http_check": False,       # opt-in: one GET / per live candidate (out of scope!)
        "crtsh": True,
        "timeout": 10,
        "securitytrails_env": "SECURITYTRAILS_API_KEY",
        "whoisxml_env": "WHOISXML_API_KEY",
        "org": None,               # registrant org for reverse WHOIS
    }

    def __init__(self, controller, config=None) -> None:
        super().__init__(controller, config)
        self._seed_event: Event | None = None
        self._hosts: list[str] = []

    async def setup(self) -> bool:
        try:
            import httpx  # noqa: F401
        except ImportError:
            self._log.warning("httpx not installed — related_domains disabled")
            return False
        return True

    async def handle_event(self, event: Event) -> None:
        host = getattr(event.data, "hostname", "")
        if not host:
            return
        if self._seed_event is None and getattr(event.data, "source", "") == "seed":
            self._seed_event = event
        if len(self._hosts) < 20000:
            self._hosts.append(host)

    async def finish(self) -> None:
        if self._seed_event is None:
            return
        import httpx

        seed_host = self._seed_event.data.hostname
        seed_root = registrable_domain(seed_host)
        if not seed_root:
            return

        labels = interesting_labels(self._hosts, seed_root, self.opt("max_labels"))
        cands: dict[str, set[str]] = {
            d: {src} for d, src in generate_candidates(
                seed_root, labels,
                keywords=self.opt("keywords"), tlds=self.opt("tlds"),
                brands=self.opt("brands"), max_candidates=self.opt("max_candidates"),
            ).items()
        }

        async with httpx.AsyncClient(timeout=self.opt("timeout")) as client:
            for d, src in (await self._external_sources(client, seed_root)).items():
                cands.setdefault(d, set()).add(src)
            cands.pop(seed_root, None)

            self._log.info(
                "related_domains: checking %d candidate roots for %s (%d sub-labels)",
                len(cands), seed_root, len(labels),
            )
            seed_prof = await self._profile(client, seed_root, full=True)
            sem = asyncio.Semaphore(self.opt("concurrency"))

            async def check(d: str) -> tuple[str, DomainProfile]:
                async with sem:
                    return d, await self._profile(client, d, seed_root=seed_root)

            results = await asyncio.gather(*(check(d) for d in cands))

        min_rank = _CONF_RANK.get(self.opt("min_confidence"), 2)
        found = 0
        for d, prof in sorted(results):
            if not prof.exists:
                continue
            pts, sig = score_candidate(seed_root, seed_prof, prof, cands[d])
            conf = confidence(pts)
            if conf is None or _CONF_RANK[conf] < min_rank:
                continue
            if await self._report(seed_host, d, conf, pts, sig, cands[d], prof):
                found += 1
            elif found == 0:
                self._log.warning(
                    "related_domains: finding for %s rejected by scope — is the seed "
                    "%s itself in scope?", d, seed_host,
                )
                return
        self._log.info("related_domains: %d related root domains for %s", found, seed_root)

    # ── network ───────────────────────────────────────────────────────────────

    async def _doh(self, client, name: str, rtype: str) -> list[str] | None:
        try:
            async with self.guard("dns:doh"):
                r = await client.get(
                    self.opt("doh_url"), params={"name": name, "type": rtype},
                    headers={"accept": "application/dns-json"},
                )
            return parse_doh(r.json())
        except Exception as exc:
            self._log.debug("DoH %s %s failed: %s", rtype, name, exc)
            return []

    async def _profile(self, client, domain: str, *, full: bool = False,
                       seed_root: str | None = None) -> DomainProfile:
        ns = await self._doh(client, domain, "NS")
        if ns is None or (not ns and not full):
            return DomainProfile(exists=False)
        mx, txt = await asyncio.gather(
            self._doh(client, domain, "MX"), self._doh(client, domain, "TXT"),
        )
        prof = DomainProfile(exists=True, ns=set(ns), mx=_mx_hosts(mx or []), txt=set(txt or []))
        if seed_root and self.opt("http_check"):
            prof.redirect = await self._redirect_to(client, domain, seed_root)
        return prof

    async def _redirect_to(self, client, domain: str, seed_root: str) -> str | None:
        """GET / (https, then http) and return the final URL if any hop lands on the seed."""
        import httpx
        for scheme in ("https", "http"):
            try:
                async with self.guard(f"http:{domain}"):
                    r = await client.get(
                        f"{scheme}://{domain}/", follow_redirects=True,
                        headers={"user-agent": "Mozilla/5.0 recon-ai"},
                    )
            except (httpx.HTTPError, OSError):
                continue
            for u in [h.url for h in r.history] + [r.url]:
                if u.host and _is_on(u.host.lower(), seed_root):
                    return str(r.url)
            return None
        return None

    async def _external_sources(self, client, seed_root: str) -> dict[str, str]:
        out: dict[str, str] = {}
        if self.opt("crtsh"):
            try:
                async with self.guard("http:crt.sh"):
                    r = await client.get(
                        "https://crt.sh/", params={"q": seed_root, "output": "json"},
                        timeout=max(30, self.opt("timeout")),
                    )
                for d in roots_from_crtsh(r.json(), seed_root):
                    out[d] = "crt.sh"
            except Exception as exc:
                self._log.debug("crt.sh lookup failed: %s", exc)

        st_key = os.environ.get(self.opt("securitytrails_env") or "")
        if st_key:
            for page in range(1, 6):
                try:
                    async with self.guard("http:securitytrails"):
                        r = await client.get(
                            f"https://api.securitytrails.com/v1/domain/{seed_root}/associated",
                            params={"page": page}, headers={"APIKEY": st_key},
                        )
                    r.raise_for_status()
                    batch = parse_securitytrails(r.json())
                except Exception as exc:
                    self._log.warning("SecurityTrails associated lookup failed: %s", exc)
                    break
                for h in batch:
                    if root := registrable_domain(h):
                        out.setdefault(root, "securitytrails")
                if not batch:
                    break

        wx_key, org = os.environ.get(self.opt("whoisxml_env") or ""), self.opt("org")
        if wx_key and org:
            try:
                async with self.guard("http:whoisxml"):
                    r = await client.post(
                        "https://reverse-whois.whoisxmlapi.com/api/v2",
                        json={"apiKey": wx_key, "searchType": "current", "mode": "purchase",
                              "basicSearchTerms": {"include": [org]}},
                    )
                r.raise_for_status()
                for h in parse_reverse_whois(r.json()):
                    if root := registrable_domain(h):
                        out[root] = "reverse-whois"
            except Exception as exc:
                self._log.warning("WhoisXML reverse WHOIS failed: %s", exc)
        elif org and not wx_key:
            self._log.warning("--org given but %s not set — reverse WHOIS skipped",
                              self.opt("whoisxml_env"))
        return out

    async def _report(self, seed_host, domain, conf, pts, signals, sources, prof) -> bool:
        evidence = {
            "domain": domain,
            "confidence": conf,
            "score": pts,
            "signals": ", ".join(signals),
            "sources": ", ".join(sorted(sources)),
            "ns": ", ".join(sorted(prof.ns)),
            "mx": ", ".join(sorted(prof.mx)) or "-",
        }
        if prof.redirect:
            evidence["redirect"] = prof.redirect
        return await self.emit(
            EventType.FINDING_CANDIDATE,
            FindingCandidateData(
                host=seed_host,
                title=f"Related root domain: {domain}",
                description=(
                    f"{domain} appears to belong to the same organisation as "
                    f"{seed_host} ({', '.join(signals)}). It is NOT in scope and was "
                    f"not scanned — confirm ownership and program scope, then add it "
                    f"with --in-scope {domain}."
                ),
                category="related-domain",
                severity_hint="info",
                evidence=evidence,
            ),
            source_event=self._seed_event,
        )
