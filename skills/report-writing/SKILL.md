---
name: report-writing
description: Turn a verified finding into a clear, reproducible vulnerability report with impact, steps, and remediation. Use at triage/submission time, after a finding is CONFIRMED or ready to submit.
version: 1.0.0
roles: [report]
capabilities: []
triggers:
  - a finding is verified and ready to write up
  - a report is being prepared for submission
tags: [reporting, triage, writeup]
---

# Vulnerability report writing

A good report lets the reader reproduce the issue in minutes and understand its
real impact. Claims without reproduction get downgraded or closed.

## Structure
1. **Title** — vuln class + asset + the concrete effect ("IDOR in
   /api/orders lets any user read others' orders").
2. **Severity & impact** — what an attacker gains, who is affected, under what
   preconditions. Map to CVSS only after stating impact in plain words.
3. **Steps to reproduce** — numbered, copy-pasteable, with the exact request(s)
   and the observed vs expected response. Redact secrets and other users' PII.
4. **Evidence** — minimal: the request/response pair (or diff) that proves it.
5. **Remediation** — the specific fix (enforce object-level authz here), not
   generic advice.
6. **References** — CWE/CVE where they apply.

## Discipline
- Report only what was reproduced. Match the engine's verification status —
  never promote POTENTIAL to CONFIRMED in prose.
- One finding per report unless a chain's whole is greater than its parts; then
  show the chain explicitly.
- Human, direct tone. No filler, no inflated severity.
