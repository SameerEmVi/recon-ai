---
name: hunt-idor
description: Hunt Insecure Direct Object Reference (IDOR / BOLA) on endpoints that
  take an object identifier. Use once API endpoints and parameters are discovered
  and an authenticated or multi-tenant surface is in scope.
version: 1.0.0
roles:
- worker
- retest
allowed_tools:
- httpx_probe
capabilities:
- TARGET_HTTP_REQUEST
- VULNERABILITY_CHECK
triggers:
- "an endpoint takes a numeric/UUID/slug id (/users/123, ?account=\u2026)"
- two accounts or tenants exist and data is partitioned by id
- a discovered PARAMETER looks like an object reference
tags:
- access-control
- idor
- bola
- web
---

# Hunt IDOR / BOLA

An IDOR is a missing *authorization* check on an object the server trusts the
client to name. The bug is proven by reading or changing **another** principal's
object, never a theoretical one.

## Where to look
- Endpoints with an id in the path or query: `/api/users/{id}`, `?orderId=`,
  `?file=`, `?account=`.
- Numeric ids (increment/decrement), UUIDs (swap for a known other-tenant UUID),
  slugs, and base64/hashids (decode first).
- State-changing verbs too (PUT/PATCH/DELETE), not just GET.

## Method (proof-driven)
1. Capture a legitimate request as principal **A**.
2. Replay it substituting **B**'s object id, with **A**'s session.
3. A finding exists only if A receives or mutates B's data. A 200 alone is not
   proof — compare the body to B's real object.
4. Note the authorization model that failed (object-level vs function-level).

## Guardrails
- Only ever target already-in-scope hosts; all traffic through the shared limiter.
- Use benign reads before any write; never destroy another user's data to "prove"
  it — a successful read, or a reversible change, is enough.
- Respect program rules on account-to-account testing.
