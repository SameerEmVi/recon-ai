"""
ProxyConfig — the single source of truth for outbound HTTP proxying + TLS trust.

One ProxyConfig is created per scan (owned by ScanController, exposed as
`controller.proxy`) and applied by `BaseModule.http_client()` / `.fetch()` to
every outbound request, so routing all traffic through Burp is one setting and
no module opens an unconfigured client.

Precedence (highest first): explicit CLI flag → environment variable → config
file → disabled default. TLS verification is NEVER silently disabled: `verify`
defaults True, and pointing it at Burp's CA bundle is an explicit opt-in.

Test-safety: `get_proxy(obj)` returns `obj.proxy` only when it is a real
ProxyConfig (mirrors ratelimit.get_limiter), else a disabled default — so a
MagicMock controller yields direct, unproxied transport.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

_ENV_URL = "RECON_AI_PROXY"
_ENV_CA = "RECON_AI_PROXY_CA"
_ENV_VERIFY = "RECON_AI_PROXY_VERIFY"


@dataclass(frozen=True)
class ProxyConfig:
    url: str | None = None          # e.g. http://127.0.0.1:8080
    enabled: bool = False
    verify: bool = True             # TLS verification — never silently off
    ca_bundle: str | None = None    # path to Burp's CA PEM (explicit interception)
    diagnostic: bool = False        # verbose request-lifecycle logging

    @property
    def active(self) -> bool:
        return bool(self.enabled and self.url)

    def verify_value(self):
        """The value to pass to httpx `verify=`: a CA bundle path or a bool.

        A CA bundle implies verification ON (against that bundle). Otherwise the
        boolean `verify` flag applies.
        """
        if self.ca_bundle:
            return self.ca_bundle
        return self.verify

    def client_kwargs(self) -> dict:
        """Keyword args to merge into an httpx.AsyncClient(...) construction."""
        kw: dict = {"verify": self.verify_value()}
        if self.active:
            kw["proxy"] = self.url      # httpx >=0.26 uses singular `proxy`
        return kw

    def describe(self) -> str:
        if not self.active:
            return "proxy=off"
        trust = f"ca={os.path.basename(self.ca_bundle)}" if self.ca_bundle else (
            "verify=on" if self.verify else "verify=OFF")
        return f"proxy={self.url} {trust}" + (" diag=on" if self.diagnostic else "")

    # ── construction from CLI/env/file ────────────────────────────────────────
    @classmethod
    def from_sources(
        cls,
        *,
        cli_proxy: str | None = None,
        cli_ca: str | None = None,
        cli_verify: bool | None = None,
        diagnostic: bool = False,
        config: dict | None = None,
        env: dict | None = None,
    ) -> "ProxyConfig":
        """Resolve a ProxyConfig: CLI flag > env var > config file > default.

        `config` is an already-parsed `[proxy]` mapping (url/ca_bundle/verify).
        Raises ConfigurationError on an invalid proxy URL or a missing CA file.
        """
        from net.errors import ConfigurationError
        env = env if env is not None else os.environ
        cfg = config or {}

        url = cli_proxy or env.get(_ENV_URL) or cfg.get("url")
        ca = cli_ca or env.get(_ENV_CA) or cfg.get("ca_bundle")

        if cli_verify is not None:
            verify = cli_verify
        elif _ENV_VERIFY in env:
            verify = env[_ENV_VERIFY].strip().lower() not in ("0", "false", "no", "off")
        elif "verify" in cfg:
            verify = bool(cfg["verify"])
        else:
            verify = True

        url = url.strip() if isinstance(url, str) else None
        if url:
            if not (url.startswith("http://") or url.startswith("https://")):
                raise ConfigurationError(
                    f"invalid proxy URL {url!r} — must start with http:// or https://")
        if ca:
            ca = os.path.expanduser(str(ca).strip())
            if not os.path.isfile(ca):
                raise ConfigurationError(f"proxy CA bundle not found: {ca}")

        return cls(url=url or None, enabled=bool(url), verify=verify,
                   ca_bundle=ca or None, diagnostic=diagnostic)

    async def probe(self, *, timeout: float = 5.0) -> tuple[bool, str]:
        """Check the proxy is reachable (no target traffic). Returns (ok, message).

        Does a single request to a benign endpoint THROUGH the proxy; a failure
        is classified (unreachable vs auth vs TLS) so the CLI can report clearly.
        Never raises.
        """
        if not self.active:
            return True, "proxy disabled (direct transport)"
        try:
            import httpx
        except ImportError:
            return False, "httpx not installed"
        from net.errors import classify_http_error
        try:
            async with httpx.AsyncClient(timeout=timeout, **self.client_kwargs()) as c:
                # A low-impact request routed via the proxy; example.com is a
                # neutral IANA-reserved documentation domain, not a scan target.
                r = await c.get("http://example.com/", follow_redirects=False)
            return True, f"proxy reachable (status {r.status_code})"
        except Exception as exc:  # noqa: BLE001 - classify, never raise
            info = classify_http_error(exc)
            return False, f"{info.category}: {info.message}"


# A disabled default, shared as the fallback for mock/unconfigured controllers.
DISABLED = ProxyConfig()


def get_proxy(obj) -> ProxyConfig:
    """Return obj.proxy if it's a real ProxyConfig, else the disabled default."""
    p = getattr(obj, "proxy", None)
    return p if isinstance(p, ProxyConfig) else DISABLED
