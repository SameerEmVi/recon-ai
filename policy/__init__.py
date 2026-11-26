"""
policy — central mode & capability enforcement for recon-ai.

The selected execution tier (osint → recon → pentest, each including the one
before; legacy active/full/vuln accepted as deprecated aliases) maps to a set of
*capabilities* a scan is allowed to exercise. Every module is classified by the
capabilities it actually uses (by behaviour, never by name), and the policy
rejects any module — or any runtime action — whose capability is not permitted by
the mode. This is enforced centrally (module loading + the network primitives +
the agent tools), not merely by CLI filtering, so a passive (`osint`) scan is
*technically unable* to launch active target probes.

The ScopeEngine remains the authoritative scope gate; the capability policy is an
orthogonal, additional gate and never widens scope.
"""

from __future__ import annotations

from policy.policy import (
    ALL_CAPABILITIES,
    ALLOW_ALL,
    CAP_ACTIVE_DISCOVERY,
    CAP_FUZZING,
    CAP_INTRUSIVE_TEST,
    CAP_PASSIVE_EXTERNAL,
    CAP_PORT_SCANNING,
    CAP_TARGET_DNS_QUERY,
    CAP_TARGET_HTTP_REQUEST,
    CAP_VULNERABILITY_CHECK,
    LEGACY_MODES,
    MODES,
    MODULE_CAPABILITIES,
    TIER_CAPS,
    TIERS,
    CapabilityDenied,
    CapabilityPolicy,
    get_policy,
    intrusive_capable,
    resolve_mode,
    tier_of_caps,
    tier_unlocked,
)

__all__ = [
    "CapabilityPolicy",
    "CapabilityDenied",
    "get_policy",
    "ALLOW_ALL",
    "MODES",
    "TIERS",
    "TIER_CAPS",
    "LEGACY_MODES",
    "resolve_mode",
    "intrusive_capable",
    "tier_of_caps",
    "tier_unlocked",
    "MODULE_CAPABILITIES",
    "ALL_CAPABILITIES",
    "CAP_PASSIVE_EXTERNAL",
    "CAP_TARGET_DNS_QUERY",
    "CAP_TARGET_HTTP_REQUEST",
    "CAP_ACTIVE_DISCOVERY",
    "CAP_FUZZING",
    "CAP_PORT_SCANNING",
    "CAP_VULNERABILITY_CHECK",
    "CAP_INTRUSIVE_TEST",
    "Engagement",
    "EngagementError",
    "load_engagement",
    "parse_engagement",
]

from policy.engagement import (  # noqa: E402
    Engagement,
    EngagementError,
    load_engagement,
    parse_engagement,
)
