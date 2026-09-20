"""
ModuleRegistry — discovers, stores, and loads recon modules.

Usage
-----
# Register a module (done by the @register decorator):
    from modules.registry import register

    @register
    class CrtShModule(BaseModule):
        name = "crt_sh"
        ...

# Load modules by name or flag:
    from modules.registry import ModuleRegistry

    # Trigger discovery (imports all module sub-packages).
    ModuleRegistry.discover()

    # Load by explicit name list.
    modules = ModuleRegistry.load(names=["crt_sh", "subfinder"], controller=ctrl)

    # Load all passive modules.
    modules = ModuleRegistry.load(flags=["passive"], controller=ctrl)

    # Load defaults.
    modules = ModuleRegistry.load_defaults(controller=ctrl)

    # Load a named scan profile.
    profile = SCAN_PROFILES["full"]
    modules = ModuleRegistry.load(
        names=profile["modules"],
        controller=ctrl,
        module_config=profile.get("module_config", {}),
    )
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import TYPE_CHECKING, Any

from modules.base import BaseModule

if TYPE_CHECKING:
    from controller.controller import ScanController

log = logging.getLogger(__name__)

_registry: dict[str, type[BaseModule]] = {}

# ── Module groups ─────────────────────────────────────────────────────────────

# Core active set — fast, always-on.
DEFAULT_MODULES = ["subfinder", "dnsx", "httpx_probe"]

# Pure-Python passive sources (no binary required).
PASSIVE_MODULES = ["crt_sh", "certspotter", "hackertarget", "wayback"]

# Extra passive sources backed by external APIs or optional binaries.
EXTRA_PASSIVE_MODULES = ["chaos", "anubis", "amass", "assetfinder", "findomain"]

# Active subdomain-depth modules: brute-force + permutation/mutation.
DEEP_DNS_MODULES = ["dnsbrute", "permutations"]

# Web analysis modules (require web services to be discovered first).
WEB_MODULES = ["gau", "nuclei", "fingerprint", "whatweb"]

# Active crawling and screenshot modules.
CRAWL_MODULES = ["katana", "gowitness"]

# Content discovery, JS analysis, and quick-win vuln checks.
DISCOVERY_MODULES = ["ffuf", "linkfinder", "paramfinder", "apifinder", "corscanner", "bypass403", "secretfinder"]

# Full module set — everything.
FULL_MODULES = (
    DEFAULT_MODULES
    + PASSIVE_MODULES
    + EXTRA_PASSIVE_MODULES
    + DEEP_DNS_MODULES
    + WEB_MODULES
    + ["naabu", "nmap"]
    + CRAWL_MODULES
    + DISCOVERY_MODULES
)

# ── Scan profiles ─────────────────────────────────────────────────────────────

SCAN_PROFILES: dict[str, dict[str, Any]] = {
    "fast": {
        "description": "Passive only — safe subdomain enumeration, no active probing",
        "modules": PASSIVE_MODULES + EXTRA_PASSIVE_MODULES + ["dnsx"],
        "module_config": {},
    },
    "default": {
        "description": "Standard active enumeration: subfinder + DNS + HTTP probing",
        "modules": None,  # uses load_defaults()
        "module_config": {},
    },
    "full": {
        "description": (
            "Comprehensive: all passive sources + active scanning + crawling + "
            "content discovery + CORS/403 checks + screenshots"
        ),
        "modules": FULL_MODULES,
        "module_config": {},
    },
    "paranoid": {
        "description": (
            "Maximum coverage: full + full port scan + all nuclei severities + "
            "larger content-discovery wordlist"
        ),
        "modules": FULL_MODULES,
        "module_config": {
            "naabu":   {"ports": "full"},
            "nuclei":  {"severity": "info,low,medium,high,critical"},
            "ffuf":    {"wordlist": "big", "threads": 50},
        },
    },
}


# ── Registry helpers ──────────────────────────────────────────────────────────

def register(cls: type[BaseModule]) -> type[BaseModule]:
    """Decorator — register a module class in the global registry."""
    if not cls.name:
        raise ValueError(f"{cls.__name__} must set a non-empty `name` class attribute")
    if cls.name in _registry:
        log.debug("module %r already registered — overwriting", cls.name)
    _registry[cls.name] = cls
    return cls


class ModuleRegistry:
    _discovered = False

    @classmethod
    def discover(cls) -> None:
        """
        Import every module in the modules/ sub-packages so that @register
        decorators fire and populate _registry.

        Safe to call multiple times — discovery only runs once.
        """
        if cls._discovered:
            return
        cls._discovered = True

        subpackages = ["modules.passive", "modules.active", "modules.web"]
        for pkg_name in subpackages:
            try:
                pkg = importlib.import_module(pkg_name)
            except ModuleNotFoundError:
                log.debug("sub-package %s not found — skipping", pkg_name)
                continue
            pkg_path = getattr(pkg, "__path__", [])
            for _, modname, _ in pkgutil.iter_modules(pkg_path):
                full = f"{pkg_name}.{modname}"
                try:
                    importlib.import_module(full)
                except Exception as exc:
                    log.warning("failed to import module %s: %s", full, exc)

        log.debug("discovered %d modules: %s", len(_registry), sorted(_registry))

    @classmethod
    def load(
        cls,
        names: list[str] | None = None,
        flags: list[str] | None = None,
        controller: "ScanController | None" = None,
        module_config: dict[str, dict[str, Any]] | None = None,
    ) -> list[BaseModule]:
        """
        Instantiate and return a list of modules.

        Resolution order:
          1. If `names` given — load exactly those modules.
          2. If `flags` given — load all modules whose flags intersect.
          3. If neither — load DEFAULT_MODULES.
        """
        cls.discover()
        module_config = module_config or {}

        if names:
            selected = list(names)
        elif flags:
            flag_set = set(flags)
            selected = [
                n for n, klass in _registry.items()
                if flag_set & set(klass.flags)
            ]
        else:
            selected = list(DEFAULT_MODULES)

        instances: list[BaseModule] = []
        for name in selected:
            klass = _registry.get(name)
            if klass is None:
                log.warning("unknown module %r — skipping", name)
                continue
            cfg = module_config.get(name, {})
            try:
                instances.append(klass(controller, cfg))  # type: ignore[arg-type]
            except Exception as exc:
                log.error("failed to instantiate module %r: %s", name, exc)

        return instances

    @classmethod
    def load_defaults(
        cls,
        controller: "ScanController | None" = None,
        extra_names: list[str] | None = None,
        extra_flags: list[str] | None = None,
        module_config: dict[str, dict[str, Any]] | None = None,
    ) -> list[BaseModule]:
        """Load default modules, optionally appending extras by name or flag."""
        cls.discover()
        names = list(DEFAULT_MODULES)

        if extra_names:
            for n in extra_names:
                if n not in names:
                    names.append(n)

        if extra_flags:
            flag_set = set(extra_flags)
            for n, klass in _registry.items():
                if flag_set & set(klass.flags) and n not in names:
                    names.append(n)

        return cls.load(names=names, controller=controller, module_config=module_config)

    @classmethod
    def all_names(cls) -> list[str]:
        cls.discover()
        return sorted(_registry)

    @classmethod
    def info(cls) -> list[dict]:
        """Return metadata for all registered modules — useful for --list-modules."""
        cls.discover()
        return [
            {
                "name": klass.name,
                "description": klass.description,
                "flags": klass.flags,
                "watched_events": klass.watched_events,
                "produced_events": klass.produced_events,
                "deps_binary": klass.deps_binary,
            }
            for klass in sorted(_registry.values(), key=lambda k: k.name)
        ]
