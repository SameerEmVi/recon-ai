---
name: subdomain-enum
description: Enumerate a target's subdomains broadly, then resolve and probe to live hosts. Use at the start of a scan when scope is a root domain and the attack surface is unknown.
version: 1.0.0
roles: [planner, worker]
capabilities: [PASSIVE_EXTERNAL, TARGET_DNS_QUERY]
triggers:
  - scope is a bare root domain
  - "a host has few known subdomains and the surface is likely larger"
allowed_tools: [subfinder, crt_sh, certspotter, dnsx, httpx_probe]
tags: [recon, discovery, subdomains]
---

# Subdomain enumeration

Goal: turn a root domain into a validated set of live, in-scope hosts — without
ever leaving authorized scope.

## Method
1. **Passive sources first** (cheap, no target traffic): certificate transparency
   (`crt_sh`, `certspotter`), passive DNS (`hackertarget`), and `subfinder`.
   These are `PASSIVE_EXTERNAL` — allowed even in `osint` mode.
2. **Resolve** candidates with `dnsx` (A/AAAA/CNAME). Drop anything the scope
   engine marks OUT — co-tenant names on shared infrastructure are common noise.
3. **Probe** survivors with `httpx_probe` to find live HTTP services (name-based
   vhosts, correct Host header). Only live hosts are worth deeper modules.
4. **Permute** only if the surface looks larger than what passive found
   (`gotator` → `dnsx`); this is active and should respect the rate limiter.

## Guardrails
- Every candidate goes through `stamp_and_publish` → the scope engine. A skill
  never decides scope.
- Prefer passive breadth before active brute — it is quieter and usually enough.
- Stop expanding when new sources stop yielding novel in-scope names.
