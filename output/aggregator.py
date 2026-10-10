"""
ResultAggregator — the Central Result Aggregator.

Every scope-accepted, deduplicated event (from every module/source) is observed
here via `observe()`, exactly once, at the same chokepoint the planner uses. The
aggregator normalizes and de-duplicates discoveries across ALL sources, retains
per-value provenance internally, correlates sources per value, and at scan
completion `write()`s a clean, categorized result directory:

    results/<domain>/
      ├── domains.txt dns.txt live.txt ips.txt ports.txt urls.txt endpoints.txt
      │   parameters.txt technologies.txt api-endpoints.txt interesting.txt
      │   interesting-parameters.txt login-pages.txt files.txt
      │   domain-sources.json provenance.jsonl summary.txt
      ├── javascript/   js-files.txt endpoints.txt parameters.txt sourcemaps.txt
      ├── wayback/      urls.txt interesting.txt parameters.txt
      ├── secrets/      findings.txt findings.json          (values already redacted)
      ├── file-analysis/ metadata.txt documents.txt interesting.txt
      ├── images/       images.txt metadata.txt ocr.txt
      ├── data-exposure/ summary.txt usernames.txt emails.txt internal-hostnames.txt
      │                  metadata.txt configuration.txt source-maps.txt interesting-files.txt
      ├── latest/  (mirror of the most recent scan)  · scans/<ts>/ (history) · diff/

Pipeline: events → aggregator → dedup + normalize → correlate → categorize →
writer. Text files stay simple; full metadata lives in provenance.jsonl + the DB.
Nothing here asserts a vulnerability — `interesting.txt` etc. are review leads.
Secrets are stored only as the already-redacted evidence secretfinder emits.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import time
from collections import defaultdict
from datetime import UTC, datetime
from urllib.parse import urlparse

log = logging.getLogger("output")

# ── heuristic keyword sets (paths/titles) — leads, never vuln claims ─────────

_LOGIN_KW = ("login", "signin", "sign-in", "log-in", "logon", "auth", "oauth",
             "sso", "session", "register", "signup", "sign-up", "account/login",
             "password", "forgot", "reset", "mfa", "2fa", "saml")
_ADMIN_KW = ("admin", "administrator", "wp-admin", "wp-login", "dashboard",
             "console", "manage", "cpanel", "backoffice", "internal")
_UPLOAD_KW = ("upload", "import", "attachment", "file-upload", "avatar", "media/upload")
_DEBUG_KW = ("debug", "trace", "phpinfo", "actuator", "/.git", "/.env", "test",
             "swagger-ui", "graphiql", "server-status", "metrics")
_DEV_KW = ("staging", "stage", "dev.", "-dev", "qa.", "uat", "sandbox", "preprod", "test.")
_INTERESTING_PARAMS = ("file", "path", "url", "redirect", "redirect_uri", "next",
                       "return", "returnurl", "callback", "dest", "id", "user",
                       "userid", "username", "account", "cmd", "exec", "token", "key",
                       "api_key", "template", "page", "doc", "download", "load",
                       "include", "query", "search", "format", "export")

# File-type buckets
_FILE_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt", ".json",
              ".xml", ".yaml", ".yml", ".zip", ".sql", ".log", ".config", ".conf",
              ".env", ".bak", ".old", ".backup", ".ini", ".tar", ".gz"}
_DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt", ".rtf", ".odt"}
_IMG_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".tif", ".tiff", ".bmp", ".webp", ".svg"}
_SENSITIVE_FILE_EXTS = {".sql", ".log", ".env", ".bak", ".old", ".backup", ".config",
                        ".conf", ".ini", ".yaml", ".yml", ".json"}
_CONFIG_HINTS = ("config", ".env", "settings", "appsettings", "web.config",
                 "credentials", ".yml", ".yaml", ".ini", "wp-config")
_INTERNAL_HOST_KW = ("intranet", "internal", "corp", "dev", "staging", "stage",
                     "qa", "uat", "vpn", "jenkins", "gitlab", "git.", "jira",
                     "confluence", "mail", "ns1", "ns2", "sso", "ldap", ".local",
                     "admin", "test", "backend", "db.", "sql")

_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_META_AUTHOR_RE = re.compile(r"\b(?:author|creator|last_modified_by|artist)=([^;]{1,64})", re.I)
_URL_IN_TEXT_RE = re.compile(r"(?:source map referenced:|referenced:)\s*(\S+)", re.I)


def _norm_url(url: str) -> str:
    try:
        p = urlparse(url.strip())
        if not p.scheme:
            return url.strip()
        base = f"{p.scheme.lower()}://{p.netloc.lower()}{(p.path or '/').rstrip('/') or '/'}"
        return base + (f"?{p.query}" if p.query else "")
    except Exception:
        return url.strip()


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _ext_of(url: str) -> str:
    return os.path.splitext(urlparse(url).path)[1].lower()


def classify_api(url: str) -> str | None:
    p = urlparse(url).path.lower()
    if "graphql" in p or p.endswith("/graphiql"):
        return "GraphQL"
    if "swagger" in p:
        return "Swagger"
    if "openapi" in p or "api-docs" in p:
        return "OpenAPI"
    if p == "/api" or "/api/" in p or re.search(r"/v\d+/", p):
        return "REST"
    return None


class ResultAggregator:
    def __init__(self, out_dir: str = "results", *, max_provenance: int = 200_000) -> None:
        self._out_dir = out_dir
        self._max_prov = max_provenance
        self._started = time.monotonic()
        self._started_at = datetime.now(UTC)

        self.domains: set[str] = set()
        self.live: dict[str, dict] = {}
        self.urls: set[str] = set()
        self.techs: dict[str, set[str]] = defaultdict(set)
        self.ips: dict[str, set[str]] = defaultdict(set)
        self.ports: dict[str, str] = {}
        self.endpoints: set[str] = set()
        self.params: dict[str, set[str]] = defaultdict(set)
        self.dns_records: list[tuple[str, str, str]] = []      # (host, type, value)
        self.findings: list[dict] = []
        self.anomalies: list[dict] = []
        self.emails: set[str] = set()
        self.usernames: set[str] = set()
        self.source_maps: set[str] = set()
        self.doc_metadata: list[str] = []                       # human lines from metascan
        self.sources: set[str] = set()

        self._provenance: list[dict] = []
        self._url_src: dict[str, set[str]] = defaultdict(set)   # norm_url -> {tool}
        self._domain_src: dict[str, set[str]] = defaultdict(set)
        # Optional LLM intelligence, attached before write() by the controller.
        self._intelligence: dict | None = None

    def new_domains_vs_latest(self, domain: str) -> list[str]:
        """Subdomains not present in the previous `latest/` scan — the current-vs-
        historical delta the intelligence layer correlates. [] if no prior scan."""
        base = os.path.join(self._out_dir, (domain or "unknown").lower().strip("/") or "unknown")
        prev = os.path.join(base, "latest", "domains.txt")
        if not os.path.isfile(prev):
            return []
        try:
            old = set(open(prev, encoding="utf-8").read().split())
        except OSError:
            return []
        return sorted(self.domains - old)

    def attach_intelligence(self, intel_lines: list[str], summary_sections: list[str]) -> None:
        """Attach the LLM correlation report so the single writer emits it as
        intelligence.txt and appends its sections to summary.txt. No module
        writes its own files — everything still flows through this writer."""
        self._intelligence = {"lines": list(intel_lines), "summary_sections": list(summary_sections)}

    # ── observation ────────────────────────────────────────────────────────────

    def observe(self, event) -> None:
        etype = getattr(getattr(event, "type", None), "value", "") or ""
        d = getattr(event, "data", None)
        if d is None:
            return
        tool = getattr(event, "source_tool", "") or "unknown"
        self.sources.add(tool)
        try:
            self._dispatch(etype, d, tool)
        except Exception as exc:
            log.debug("aggregator.observe failed on %s: %s", etype, exc)

    def _add_domain(self, host: str, tool: str) -> None:
        h = (host or "").lower().strip().rstrip(".")
        if h:
            self.domains.add(h)
            self._domain_src[h].add(tool)

    def _add_url(self, url: str, tool: str) -> str:
        u = _norm_url(url)
        if u:
            self.urls.add(u)
            self._url_src[u].add(tool)
            h = _host_of(u)
            if h:
                self._add_domain(h, tool)
        return u

    def _scan_emails(self, text: str) -> None:
        if text:
            for m in _EMAIL_RE.findall(text):
                self.emails.add(m.lower())

    def _dispatch(self, etype, d, tool) -> None:
        if etype == "SUBDOMAIN":
            h = (getattr(d, "hostname", "") or "").lower().strip().rstrip(".")
            self._add_domain(h, tool)
            self._prov(h, "domain", tool)

        elif etype == "DNS_RECORD":
            host = (d.hostname or "").lower()
            self._add_domain(host, tool)
            self.dns_records.append((host, d.record_type, d.value))
            if d.record_type in ("A", "AAAA") and d.value:
                self.ips[d.value].add(host)
                self._prov(d.value, "ip", tool, related=host)
            if d.record_type == "TXT":
                self._scan_emails(d.value)   # TXT is data, never instructions
            self._prov(f"{host} {d.record_type} {d.value}", "dns", tool)

        elif etype == "IP":
            if d.address:
                (self.ips[d.address].add(d.resolved_from.lower()) if d.resolved_from
                 else self.ips.setdefault(d.address, set()))
                self._prov(d.address, "ip", tool, related=getattr(d, "resolved_from", None))

        elif etype == "OPEN_PORT":
            self.ports[f"{d.host}:{d.port}"] = (d.banner or d.protocol or "tcp")
            self._prov(f"{d.host}:{d.port}", "port", tool)

        elif etype == "HTTP_SERVICE":
            u = self._add_url(d.url, tool)
            self.live[u] = {"status": getattr(d, "status_code", None),
                            "title": getattr(d, "title", None), "server": getattr(d, "server", None)}
            h = _host_of(d.url)
            for t in (getattr(d, "technologies", None) or []):
                self.techs[h].add(_clean_tech(t))
            self._prov(d.url, "live", tool)

        elif etype == "TECHNOLOGY":
            host = (d.host or "").lower()
            name = d.name + (f" {d.version}" if getattr(d, "version", None) else "")
            if host and name.strip():
                self.techs[host].add(name.strip())
                self._prov(name.strip(), "technology", tool, related=host)

        elif etype == "URL":
            u = self._add_url(d.url, tool)
            self._collect_params(u)
            self._prov(d.url, "url", tool, method=getattr(d, "found_via", None))

        elif etype == "ENDPOINT":
            u = self._add_url(d.url, tool)
            self.endpoints.add(u)
            self._collect_params(u)
            self._prov(d.url, "endpoint", tool, method=getattr(d, "method", None))

        elif etype == "PARAMETER":
            base = _norm_url(d.url).split("?")[0]
            if d.name:
                self.params[base].add(d.name)
                self._prov(d.name, "parameter", tool, related=base)

        elif etype == "ANOMALY":
            cat = getattr(d, "category", None)
            desc = getattr(d, "description", "") or ""
            self.anomalies.append({"host": d.host, "description": desc, "category": cat, "source": tool})
            self._scan_emails(desc)
            if cat == "exposed-source-map":
                m = _URL_IN_TEXT_RE.search(desc)
                if m:
                    self.source_maps.add(m.group(1))
            if cat == "document-metadata":
                self.doc_metadata.append(f"{d.host}: {desc}")
                for a in _META_AUTHOR_RE.findall(desc):
                    a = a.strip()
                    if a and " " not in a and 2 <= len(a) <= 64:
                        self.usernames.add(a)
            self._prov(desc[:120], "anomaly", tool, related=d.host, confidence=cat)

        elif etype == "EMAIL":
            addr = (getattr(d, "address", "") or "").lower().strip()
            if addr:
                self.emails.add(addr)
                self._prov(addr, "email", tool,
                           related=getattr(d, "found_in", None),
                           confidence=getattr(d, "source", None))

        elif etype == "FINDING_CANDIDATE":
            ev = getattr(d, "evidence", None) or {}
            self.findings.append({"host": d.host, "title": d.title, "category": d.category,
                                  "severity": getattr(d, "severity_hint", None),
                                  "evidence": ev, "source": tool,
                                  "description": getattr(d, "description", "")})
            self._scan_emails(getattr(d, "description", ""))
            self._prov(d.title, "finding", tool, related=d.host, confidence=getattr(d, "severity_hint", None))

    def _collect_params(self, url: str) -> None:
        p = urlparse(url)
        if not p.query:
            return
        base = _norm_url(url).split("?")[0]
        for pair in p.query.split("&"):
            name = pair.split("=", 1)[0].strip()
            if name and len(name) <= 128:
                self.params[base].add(name)

    def _prov(self, value, vtype, source, *, method=None, related=None, confidence=None) -> None:
        if len(self._provenance) >= self._max_prov:
            return
        self._provenance.append({"value": value, "type": vtype, "source": source,
                                 "method": method, "related": related,
                                 "confidence": confidence, "ts": datetime.now(UTC).isoformat()})

    # ── categorizers (top-level) ─────────────────────────────────────────────

    def _dns_lines(self):
        seen, out = set(), []
        for host, rtype, val in self.dns_records:
            line = f"{host}\t{rtype}\t{val}"
            if line not in seen:
                seen.add(line); out.append(line)
        return sorted(out)

    def _tech_lines(self):
        return [f"https://{h}\t{', '.join(sorted(self.techs[h]))}" for h in sorted(self.techs) if self.techs[h]]

    def _ip_lines(self):
        out = []
        for ip in sorted(self.ips):
            doms = sorted(x for x in self.ips[ip] if x)
            out.append(f"{ip}\t{', '.join(doms)}" if doms else ip)
        return out

    def _port_lines(self):
        return [f"{k}\t{v}" for k, v in sorted(self.ports.items())]

    def _api_endpoints(self):
        seen, out = set(), []
        for u in sorted(set(self.endpoints) | set(self.urls)):
            tag = classify_api(u)
            if tag and u not in seen:
                seen.add(u); out.append(f"{u}\t{tag}")
        return out

    def _login_pages(self):
        out = set()
        for u in set(self.urls) | set(self.live) | set(self.endpoints):
            if any(k in urlparse(u).path.lower() for k in _LOGIN_KW):
                out.add(u); continue
            meta = self.live.get(u)
            if meta and meta.get("title") and any(k in meta["title"].lower()
                    for k in ("sign in", "log in", "login", "sign-in", "authenticate", "account")):
                out.add(u)
        return sorted(out)

    def _files(self):
        return sorted(u for u in self.urls if _ext_of(u) in _FILE_EXTS)

    def _param_lines(self):
        return [base + "?" + "&".join(f"{n}=" for n in sorted(self.params[base])) for base in sorted(self.params)]

    def _interesting_params(self):
        out = []
        for base in sorted(self.params):
            hit = sorted(n for n in self.params[base] if n.lower() in _INTERESTING_PARAMS)
            if hit:
                out.append(base + "?" + "&".join(f"{n}=" for n in hit))
        return out

    def _interesting(self):
        sec = defaultdict(set)
        for u in set(self.urls) | set(self.live) | set(self.endpoints):
            path = urlparse(u).path.lower(); host = _host_of(u)
            if any(k in path for k in _LOGIN_KW): sec["LOGIN"].add(u)
            if any(k in path for k in _ADMIN_KW) or host.startswith(("admin.", "manage.")): sec["ADMIN"].add(u)
            if classify_api(u): sec["API"].add(u)
            if any(k in path for k in _UPLOAD_KW): sec["UPLOAD"].add(u)
            if any(k in path for k in _DEBUG_KW): sec["DEBUG"].add(u)
            if any(k in u.lower() for k in _DEV_KW): sec["DEV/STAGING"].add(u)
            if _ext_of(u) in _DOC_EXTS: sec["DOCUMENT"].add(u)
            if any(h in u.lower() for h in _CONFIG_HINTS): sec["CONFIGURATION"].add(u)
        for base, names in self.params.items():
            hit = sorted(n for n in names if n.lower() in _INTERESTING_PARAMS)
            if hit: sec["INTERESTING PARAMETER"].add(base + "?" + "&".join(f"{n}=" for n in hit))
        for h in self.domains:
            if any(k in h for k in _DEV_KW): sec["DEV/STAGING"].add(h)
        for a in self.anomalies:
            if a.get("category") in ("cloud-asset", "exposed-source-map", "subdomain-takeover", "host-org"):
                sec["NOTABLE"].add(f"[{a.get('category')}] {a['host']}: {a['description'][:100]}")
        for f in self.findings:
            sec["FINDING (review — not confirmed)"].add(f"[{(f.get('severity') or 'info').upper()}] {f['title']} ({f['host']})")
        order = ["LOGIN", "ADMIN", "API", "UPLOAD", "DOCUMENT", "CONFIGURATION",
                 "DEBUG", "DEV/STAGING", "INTERESTING PARAMETER", "NOTABLE",
                 "FINDING (review — not confirmed)"]
        out = []
        for s in order:
            if sec.get(s):
                out.append(f"[{s}]"); out += sorted(sec[s]); out.append("")
        return out

    # ── categorizers (subdirs, source-aware via provenance) ──────────────────

    def _urls_by_source(self, *sources):
        s = set(sources)
        return sorted(u for u, tools in self._url_src.items() if tools & s)

    def _js_files(self):
        return sorted(u for u in self.urls if _ext_of(u) in (".js", ".mjs", ".cjs"))

    def _js_endpoints(self):
        js_urls = set(self._urls_by_source("js_intel", "linkfinder", "apifinder"))
        return sorted((set(self.endpoints) & js_urls) | {u for u in js_urls if classify_api(u)})

    def _params_from_sources(self, *sources):
        js_urls = set(self._urls_by_source(*sources))
        out = []
        for base in sorted(self.params):
            if base in js_urls or any(base == u.split("?")[0] for u in js_urls):
                out.append(base + "?" + "&".join(f"{n}=" for n in sorted(self.params[base])))
        return out

    def _secrets(self):
        rows = [f for f in self.findings if "secret" in (f.get("category") or "").lower()
                or "credential" in (f.get("category") or "").lower()]
        txt, js = [], []
        for f in rows:
            ev = f.get("evidence") or {}
            txt += [f"{f['title']}",
                    f"  host      : {f['host']}",
                    f"  category  : {f['category']}",
                    f"  confidence: {(f.get('severity') or 'n/a').upper()}",
                    f"  source    : {f.get('source')}",
                    f"  evidence  : {json.dumps(ev, ensure_ascii=False)}",   # already redacted upstream
                    ""]
            js.append({"type": f["category"], "host": f["host"], "title": f["title"],
                       "confidence": f.get("severity"), "source": f.get("source"),
                       "evidence_redacted": ev})
        return txt, js

    def _file_analysis(self):
        docs = sorted(u for u in self.urls if _ext_of(u) in _DOC_EXTS)
        meta = sorted(set(self.doc_metadata))
        interesting = [m for m in meta if any(k in m.lower() for k in
                       ("author", "creator", "company", "producer", "gps", "internal"))]
        return docs, meta, interesting

    def _images(self):
        imgs = sorted(u for u in self.urls if _ext_of(u) in _IMG_EXTS)
        # metascan emits document-metadata for images too; surface those whose host/file is an image
        meta = sorted(m for m in set(self.doc_metadata) if any(e in m.lower() for e in _IMG_EXTS))
        return imgs, meta

    def _data_exposure(self):
        internal = sorted(h for h in self.domains if any(k in h for k in _INTERNAL_HOST_KW))
        config = sorted(u for u in self.urls if any(k in u.lower() for k in _CONFIG_HINTS)
                        or _ext_of(u) in {".env", ".config", ".conf", ".ini", ".yaml", ".yml"})
        interesting_files = sorted(u for u in self.urls if _ext_of(u) in _SENSITIVE_FILE_EXTS)
        return {
            "usernames.txt": sorted(self.usernames),
            "emails.txt": sorted(self.emails),
            "internal-hostnames.txt": internal,
            "metadata.txt": sorted(set(self.doc_metadata)),
            "configuration.txt": config,
            "source-maps.txt": sorted(self.source_maps),
            "interesting-files.txt": interesting_files,
        }

    def _data_exposure_summary(self, buckets) -> list[str]:
        def sev(name, n):
            if name in ("usernames.txt", "emails.txt", "source-maps.txt", "configuration.txt") and n:
                return "MEDIUM"
            if name == "interesting-files.txt" and n:
                return "MEDIUM"
            return "LOW"
        lines = ["Data Exposure Analysis", "======================", "",
                 "Classification reflects evidence/context, not mere string presence.", ""]
        for name, vals in buckets.items():
            n = len(vals)
            if n:
                lines.append(f"[{sev(name, n)}] {name[:-4]:<20} {n}")
        if not any(buckets.values()):
            lines.append("(no data-exposure evidence collected)")
        return lines

    # ── domain-sources / summary ─────────────────────────────────────────────

    def _domain_sources(self) -> dict:
        return {d: sorted(self._domain_src.get(d, set())) for d in sorted(self.domains)}

    def _source_categories(self):
        mapping = {"subfinder": "Subdomain enumeration", "crt_sh": "Certificate Transparency",
            "certspotter": "Certificate Transparency", "hackertarget": "Passive DNS",
            "wayback": "Wayback/archive", "dnsx": "DNS", "dnsbrute": "DNS brute force",
            "permutations": "Permutations", "httpx_probe": "HTTP probing",
            "fingerprint": "Technology detection", "whatweb": "Technology detection",
            "katana": "Crawler", "apifinder": "API discovery", "js_intel": "JavaScript analysis",
            "linkfinder": "JavaScript analysis",
            "paramfinder": "Parameter discovery", "cloud_intel": "Cloud asset intelligence",
            "censys": "Censys", "metascan": "File/metadata analysis", "secretfinder": "Secret detection",
            "trufflehog": "Secret detection",
            "naabu": "Port scanning", "nmap": "Service detection", "csprecon": "CSP recon", "seed": "Seed"}
        return sorted({mapping.get(s, s) for s in self.sources})

    def summary_text(self, domain: str) -> str:
        dur = time.monotonic() - self._started
        counts = [("Subdomains", len(self.domains)), ("Live Hosts", len(self.live)),
            ("IPs", len(self.ips)), ("Open Ports", len(self.ports)), ("URLs", len(self.urls)),
            ("Endpoints", len(self.endpoints)),
            ("Parameters", sum(len(v) for v in self.params.values())),
            ("Technologies", len({t for s in self.techs.values() for t in s})),
            ("API Endpoints", len(self._api_endpoints())),
            ("JavaScript files", len(self._js_files())),
            ("DNS records", len(self._dns_lines())),
            ("Files", len(self._files())),
            ("Secrets detected", len([f for f in self.findings if "secret" in (f.get("category") or "").lower()])),
            ("Login Pages", len(self._login_pages())),
            ("Interesting URLs", len([l for l in self._interesting() if l and not l.startswith("[")])),
            ("Interesting Parameters", len(self._interesting_params())),
            ("Emails", len(self.emails)), ("Usernames", len(self.usernames)),
            ("Source maps", len(self.source_maps)), ("Findings", len(self.findings))]
        lines = ["Recon-AI Scan Summary", "=====================", "",
                 f"Target: {domain}", f"Scan time: {self._started_at.isoformat()}",
                 f"Duration: {dur:.1f}s", ""]
        for label, n in counts:
            lines.append(f"{label + ':':<24}{n}")
        lines += ["", "Sources:"] + [f"- {s}" for s in self._source_categories()]
        if self._intelligence and self._intelligence.get("summary_sections"):
            lines += list(self._intelligence["summary_sections"])
        return "\n".join(lines) + "\n"

    # ── writing ───────────────────────────────────────────────────────────────

    def _tree(self, domain: str) -> dict[str, object]:
        secret_txt, secret_json = self._secrets()
        docs, meta, doc_int = self._file_analysis()
        imgs, img_meta = self._images()
        de = self._data_exposure()
        return {
            "domains.txt": sorted(self.domains),
            "dns.txt": self._dns_lines(),
            "live.txt": sorted(self.live.keys()),
            "ips.txt": self._ip_lines(),
            "ports.txt": self._port_lines(),
            "urls.txt": sorted(self.urls),
            "endpoints.txt": sorted(self.endpoints),
            "parameters.txt": self._param_lines(),
            "technologies.txt": self._tech_lines(),
            "api-endpoints.txt": self._api_endpoints(),
            "interesting.txt": self._interesting(),
            "interesting-parameters.txt": self._interesting_params(),
            "login-pages.txt": self._login_pages(),
            "files.txt": self._files(),
            "domain-sources.json": json.dumps(self._domain_sources(), indent=2, ensure_ascii=False),
            "summary.txt": self.summary_text(domain).splitlines(),
            "javascript/js-files.txt": self._js_files(),
            "javascript/endpoints.txt": self._js_endpoints(),
            "javascript/parameters.txt": self._params_from_sources("js_intel", "linkfinder", "apifinder"),
            "javascript/sourcemaps.txt": sorted(self.source_maps),
            "wayback/urls.txt": self._urls_by_source("wayback"),
            "wayback/interesting.txt": [u for u in self._urls_by_source("wayback")
                                        if classify_api(u) or any(k in urlparse(u).path.lower()
                                        for k in _LOGIN_KW + _ADMIN_KW)],
            "wayback/parameters.txt": self._params_from_sources("wayback"),
            "secrets/findings.txt": secret_txt,
            "secrets/findings.json": json.dumps(secret_json, indent=2, ensure_ascii=False),
            "file-analysis/documents.txt": docs,
            "file-analysis/metadata.txt": meta,
            "file-analysis/interesting.txt": doc_int,
            "images/images.txt": imgs,
            "images/metadata.txt": img_meta,
            "images/ocr.txt": ["# OCR is not implemented in this build; no OCR text extracted."],
            "data-exposure/summary.txt": self._data_exposure_summary(de),
            **{f"data-exposure/{k}": v for k, v in de.items()},
            **({"intelligence.txt": self._intelligence["lines"]} if self._intelligence else {}),
        }

    def write(self, domain: str) -> str:
        domain = (domain or "unknown").lower().strip("/") or "unknown"
        ts = self._started_at.strftime("%Y-%m-%d_%H%M%S")
        base = os.path.join(self._out_dir, domain)
        latest_dir = os.path.join(base, "latest")
        diff_dir = os.path.join(base, "diff")
        scan_dir = os.path.join(base, "scans", ts)
        n = 2
        while os.path.exists(scan_dir):
            scan_dir = os.path.join(base, "scans", f"{ts}_{n}"); n += 1
        os.makedirs(scan_dir, exist_ok=True)
        os.makedirs(diff_dir, exist_ok=True)

        diff_text = self._diff_vs_latest(latest_dir)

        for rel, content in self._tree(domain).items():
            path = os.path.join(scan_dir, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if isinstance(content, str):
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(content + ("\n" if not content.endswith("\n") else ""))
            else:
                self._write_lines(path, content)
        self._write_provenance(os.path.join(scan_dir, "provenance.jsonl"))

        if os.path.isdir(latest_dir):
            shutil.rmtree(latest_dir, ignore_errors=True)
        shutil.copytree(scan_dir, latest_dir)
        if diff_text:
            self._write_lines(os.path.join(diff_dir, f"{ts}.txt"), diff_text)

        log.info("results written to %s (mirrored to latest/)", scan_dir)
        return scan_dir

    def _diff_vs_latest(self, latest_dir: str):
        prev = os.path.join(latest_dir, "domains.txt")
        if not os.path.isfile(prev):
            return None
        try:
            old = set(open(prev, encoding="utf-8").read().split())
        except Exception:
            return None
        new, gone = self.domains - old, old - self.domains
        lines = [f"# domain diff vs previous latest ({len(old)} -> {len(self.domains)})", "",
                 f"[+ NEW {len(new)}]"] + sorted(new) + ["", f"[- REMOVED {len(gone)}]"] + sorted(gone)
        return lines

    @staticmethod
    def _write_lines(path: str, lines) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            for ln in lines:
                fh.write(str(ln) + "\n")

    def _write_provenance(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            for rec in self._provenance:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _clean_tech(raw: str) -> str:
    return raw.split(":")[0].strip() if ":" in raw else raw.strip()
