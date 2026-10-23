"""
Central capability policy.

A `CapabilityPolicy` is built once per scan from the selected mode (and whether
intrusive testing is authorized) and then consulted everywhere a potentially
active operation could start:

  - the controller filters which modules load/subscribe (strict, central);
  - `BaseModule.fetch` (target HTTP) and `BaseModule.run_proc` re-check at the
    moment of action, so a mis-declared/passive module, an event callback, a
    fallback path, or a scanner integration cannot exceed the mode;
  - the agent tool registry is filtered and each tool re-checks, so an AI
    recommendation cannot bypass the mode either.

Fail-closed:
  - an unknown/invalid mode raises at construction;
  - an unclassified module is permitted only in `full` (never in the restrictive
    modes), with a reason;
  - `check()` denies any capability not explicitly allowed.

Classification is by *behaviour*, not module name or flags — `MODULE_CAPABILITIES`
was hand-audited from each module's actual target I/O (which is why `subfinder`,
flagged "active", is correctly PASSIVE_EXTERNAL, and `metascan`/`csprecon`, which
contact the target directly, are not passive).
"""

from __future__ import annotations

# ── capabilities ──────────────────────────────────────────────────────────────

CAP_PASSIVE_EXTERNAL = "PASSIVE_EXTERNAL"      # third-party sources only; never contacts the target
CAP_TARGET_DNS_QUERY = "TARGET_DNS_QUERY"      # resolves/queries DNS about the target
CAP_TARGET_HTTP_REQUEST = "TARGET_HTTP_REQUEST"  # direct HTTP(S) request to the target
CAP_ACTIVE_DISCOVERY = "ACTIVE_DISCOVERY"      # active enumeration (brute/permute/crawl/zone-xfer)
CAP_FUZZING = "FUZZING"                        # directory / file / extension fuzzing
CAP_PORT_SCANNING = "PORT_SCANNING"            # naabu / nmap
CAP_VULNERABILITY_CHECK = "VULNERABILITY_CHECK"  # non-intrusive vuln assessment
CAP_INTRUSIVE_TEST = "INTRUSIVE_TEST"          # intrusive checks — off unless authorized

ALL_CAPABILITIES = frozenset({
    CAP_PASSIVE_EXTERNAL, CAP_TARGET_DNS_QUERY, CAP_TARGET_HTTP_REQUEST,
    CAP_ACTIVE_DISCOVERY, CAP_FUZZING, CAP_PORT_SCANNING,
    CAP_VULNERABILITY_CHECK, CAP_INTRUSIVE_TEST,
})

# ── modes → allowed capabilities ────────────────────────────────────────────────

MODE_OSINT = "osint"
MODE_VULN = "vuln"
MODE_ACTIVE = "active"
MODE_FULL = "full"
MODES = (MODE_OSINT, MODE_VULN, MODE_ACTIVE, MODE_FULL)

_ACTIVE_CAPS = frozenset({
    CAP_PASSIVE_EXTERNAL, CAP_TARGET_DNS_QUERY, CAP_TARGET_HTTP_REQUEST,
    CAP_ACTIVE_DISCOVERY, CAP_FUZZING, CAP_PORT_SCANNING, CAP_VULNERABILITY_CHECK,
})

MODE_CAPS: dict[str, frozenset[str]] = {
    MODE_OSINT: frozenset({CAP_PASSIVE_EXTERNAL}),
    MODE_VULN: frozenset({
        CAP_PASSIVE_EXTERNAL, CAP_TARGET_DNS_QUERY, CAP_TARGET_HTTP_REQUEST,
        CAP_VULNERABILITY_CHECK,
    }),
    MODE_ACTIVE: _ACTIVE_CAPS,
    MODE_FULL: _ACTIVE_CAPS,
}

# Which modes may additionally unlock the intrusive tier (only when authorized).
_INTRUSIVE_MODES = frozenset({MODE_ACTIVE, MODE_FULL})

# ── authoritative, behaviour-audited module classification ──────────────────────
# NOTE: classified by what each module actually does to the TARGET, not by its
# flags/name. A module is allowed only when ALL its capabilities are permitted.

MODULE_CAPABILITIES: dict[str, frozenset[str]] = {
    # passive external intelligence (no target contact) — note subfinder/amass/
    # cloud_intel are "active"/"web"-flagged but only query third parties.
    "subfinder": frozenset({CAP_PASSIVE_EXTERNAL}),
    "amass": frozenset({CAP_PASSIVE_EXTERNAL}),
    "assetfinder": frozenset({CAP_PASSIVE_EXTERNAL}),
    "findomain": frozenset({CAP_PASSIVE_EXTERNAL}),
    "crt_sh": frozenset({CAP_PASSIVE_EXTERNAL}),
    "certspotter": frozenset({CAP_PASSIVE_EXTERNAL}),
    "chaos": frozenset({CAP_PASSIVE_EXTERNAL}),
    "anubis": frozenset({CAP_PASSIVE_EXTERNAL}),
    "hackertarget": frozenset({CAP_PASSIVE_EXTERNAL}),
    "github_subdomains": frozenset({CAP_PASSIVE_EXTERNAL}),
    "censys": frozenset({CAP_PASSIVE_EXTERNAL}),
    "cloud_intel": frozenset({CAP_PASSIVE_EXTERNAL}),  # verify (active) forced off in osint
    "wayback": frozenset({CAP_PASSIVE_EXTERNAL}),
    "gau": frozenset({CAP_PASSIVE_EXTERNAL}),
    "urlfinder": frozenset({CAP_PASSIVE_EXTERNAL}),
    "waymore": frozenset({CAP_PASSIVE_EXTERNAL}),
    "related_domains": frozenset({CAP_PASSIVE_EXTERNAL}),
    "paramfinder": frozenset({CAP_PASSIVE_EXTERNAL}),   # pure analysis of discovered URLs; no target I/O
    "wordlist_learner": frozenset({CAP_PASSIVE_EXTERNAL}),  # learns from events; no network

    # target DNS resolution
    "dnsx": frozenset({CAP_TARGET_DNS_QUERY}),

    # active discovery (brute / permutation / zone-transfer / reverse / crawl / cloud probing)
    "dnsbrute": frozenset({CAP_ACTIVE_DISCOVERY}),
    "puredns": frozenset({CAP_ACTIVE_DISCOVERY}),
    "gotator": frozenset({CAP_ACTIVE_DISCOVERY}),
    "permutations": frozenset({CAP_ACTIVE_DISCOVERY}),
    "zonetransfer": frozenset({CAP_ACTIVE_DISCOVERY}),
    "tlsx": frozenset({CAP_ACTIVE_DISCOVERY}),
    "hakip2host": frozenset({CAP_ACTIVE_DISCOVERY}),
    "katana": frozenset({CAP_ACTIVE_DISCOVERY, CAP_TARGET_HTTP_REQUEST}),
    "s3scanner": frozenset({CAP_ACTIVE_DISCOVERY}),
    "cloud_enum": frozenset({CAP_ACTIVE_DISCOVERY}),

    # direct target HTTP
    "httpx_probe": frozenset({CAP_TARGET_HTTP_REQUEST}),
    "fingerprint": frozenset({CAP_TARGET_HTTP_REQUEST}),
    "whatweb": frozenset({CAP_TARGET_HTTP_REQUEST}),
    "apifinder": frozenset({CAP_TARGET_HTTP_REQUEST}),
    "js_intel": frozenset({CAP_TARGET_HTTP_REQUEST}),
    "linkfinder": frozenset({CAP_TARGET_HTTP_REQUEST}),
    "secretfinder": frozenset({CAP_TARGET_HTTP_REQUEST}),
    "trufflehog": frozenset({CAP_TARGET_HTTP_REQUEST}),
    "metascan": frozenset({CAP_TARGET_HTTP_REQUEST}),   # downloads files FROM the target
    "csprecon": frozenset({CAP_TARGET_HTTP_REQUEST}),   # reads the target's CSP header
    "gowitness": frozenset({CAP_TARGET_HTTP_REQUEST}),

    # fuzzing
    "ffuf": frozenset({CAP_FUZZING, CAP_TARGET_HTTP_REQUEST}),
    "extfuzz": frozenset({CAP_FUZZING, CAP_TARGET_HTTP_REQUEST}),

    # port scanning
    "naabu": frozenset({CAP_PORT_SCANNING}),
    "rustscan": frozenset({CAP_PORT_SCANNING}),
    "nmap": frozenset({CAP_PORT_SCANNING}),

    # vulnerability assessment (non-intrusive)
    "vulnassess": frozenset({CAP_VULNERABILITY_CHECK, CAP_TARGET_HTTP_REQUEST}),
    "nuclei": frozenset({CAP_VULNERABILITY_CHECK, CAP_TARGET_HTTP_REQUEST}),
    "corscanner": frozenset({CAP_VULNERABILITY_CHECK, CAP_TARGET_HTTP_REQUEST}),
    "bypass403": frozenset({CAP_VULNERABILITY_CHECK, CAP_TARGET_HTTP_REQUEST}),
    "takeover": frozenset({CAP_VULNERABILITY_CHECK, CAP_TARGET_HTTP_REQUEST}),
}

# Lean candidate set for `vuln` mode: minimum discovery to feed the assessment,
# then the assessment itself. Filtered by the vuln ceiling anyway.
VULN_MODE_MODULES = [
    "crt_sh", "certspotter", "hackertarget", "subfinder",   # passive hosts
    "dnsx", "httpx_probe", "fingerprint",                    # minimal resolve/probe/fingerprint
    "corscanner", "nuclei", "vulnassess",                    # assessment
]


class CapabilityDenied(Exception):
    """Raised when an operation requests a capability the mode does not allow."""


class CapabilityPolicy:
    def __init__(self, mode: str, *, intrusive_authorized: bool = False) -> None:
        if mode not in MODES:
            raise CapabilityDenied(
                f"invalid mode {mode!r} — fail-closed. Valid modes: {', '.join(MODES)}"
            )
        self.mode = mode
        self.intrusive_authorized = bool(intrusive_authorized)
        allowed = set(MODE_CAPS[mode])
        if self.intrusive_authorized and mode in _INTRUSIVE_MODES:
            allowed.add(CAP_INTRUSIVE_TEST)
        self._allowed = frozenset(allowed)

    # ── capability-level ──────────────────────────────────────────────────────
    @property
    def allowed_capabilities(self) -> frozenset[str]:
        return self._allowed

    def allows(self, capability: str) -> bool:
        return capability in self._allowed

    def check(self, capability: str, who: str = "") -> None:
        """Raise CapabilityDenied unless `capability` is allowed (fail-closed)."""
        if capability not in self._allowed:
            raise CapabilityDenied(
                f"{who or 'operation'} requires {capability}, not permitted in mode "
                f"'{self.mode}'"
            )

    # ── module-level ────────────────────────────────────────────────────────────
    @staticmethod
    def capabilities_of(module_cls) -> frozenset[str] | None:
        """Behaviour-audited capabilities for a module class.

        Precedence: an explicit non-empty `capabilities` ClassVar on the module
        (self-declaration) wins; otherwise the authoritative table; otherwise
        None (unclassified → fail-closed by the caller)."""
        declared = getattr(module_cls, "capabilities", None)
        if declared:
            return frozenset(declared)
        name = getattr(module_cls, "name", "") or ""
        return MODULE_CAPABILITIES.get(name)

    def module_allowed(self, module_cls) -> tuple[bool, str]:
        caps = self.capabilities_of(module_cls)
        name = getattr(module_cls, "name", "?")
        if caps is None:
            # Unclassified: fail-closed. Only permitted in full, with a warning.
            if self.mode == MODE_FULL:
                return True, "unclassified (permitted only in full mode)"
            return False, "unclassified capability — fail-closed (classify it in policy.MODULE_CAPABILITIES)"
        disallowed = caps - self._allowed
        if disallowed:
            return False, f"requires {', '.join(sorted(disallowed))} (blocked in mode '{self.mode}')"
        return True, "allowed"

    def module_caps_label(self, module_cls) -> str:
        caps = self.capabilities_of(module_cls)
        return ", ".join(sorted(caps)) if caps else "unclassified"

    def filter_modules(self, module_classes) -> tuple[list, list[tuple[str, str]]]:
        """Split classes into (allowed, rejected[(name, reason)])."""
        allowed, rejected = [], []
        for cls in module_classes:
            ok, reason = self.module_allowed(cls)
            (allowed if ok else rejected).append(cls if ok else (getattr(cls, "name", "?"), reason))
        return allowed, rejected

    # ── default candidate module set per mode ─────────────────────────────────
    def default_module_names(self, get_class) -> list[str]:
        """Candidate module names for this mode (before the user's own overrides).

        `get_class(name)` returns a module class or None. The set is still passed
        through module filtering, so it can only ever shrink from here.
        """
        from modules.registry import FULL_MODULES
        if self.mode in (MODE_ACTIVE, MODE_FULL):
            return list(FULL_MODULES)
        if self.mode == MODE_VULN:
            return list(VULN_MODE_MODULES)
        if self.mode == MODE_OSINT:
            # every module that is passive-external only
            names = []
            for name in sorted(MODULE_CAPABILITIES):
                cls = get_class(name)
                if cls is None:
                    continue
                if self.module_allowed(cls)[0]:
                    names.append(name)
            return names
        return []

    def describe(self) -> str:
        extra = " +intrusive" if CAP_INTRUSIVE_TEST in self._allowed else ""
        return f"mode={self.mode}{extra} caps={{{', '.join(sorted(self._allowed))}}}"


class _AllowAllPolicy(CapabilityPolicy):
    """A policy that permits everything — used for test-safety (mock controllers)
    and as a never-raising default where no policy was configured."""

    def __init__(self) -> None:
        self.mode = "unrestricted"
        self.intrusive_authorized = True
        self._allowed = ALL_CAPABILITIES

    def check(self, capability: str, who: str = "") -> None:  # never raises
        return None

    def module_allowed(self, module_cls) -> tuple[bool, str]:
        return True, "allowed (unrestricted)"


ALLOW_ALL = _AllowAllPolicy()


def get_policy(obj) -> CapabilityPolicy:
    """Return obj.policy if it's a real CapabilityPolicy, else ALLOW_ALL.

    Mirrors ratelimit.get_limiter / recon.fetch.get_response_cache: a MagicMock
    controller yields a MagicMock attribute (not a CapabilityPolicy), so unit
    tests that build modules with mock controllers are never gated."""
    pol = getattr(obj, "policy", None)
    return pol if isinstance(pol, CapabilityPolicy) else ALLOW_ALL
