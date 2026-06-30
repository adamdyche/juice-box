# JuiceBox — Findings Report

> Copy this file to `FINDINGS.md` (or your own doc) and fill in one block per vulnerability you find.
> Aim for enough detail that someone else could reproduce the issue from your write-up alone.

**Tester:** Joshua Vadala
**Date:** 2026-06-27
**Target:** JuiceBox @ http://localhost:3000 (local)

---

## Summary

| # | Title | Category | Severity | Status |
|---|-------|----------|----------|--------|
| 1 |   XSS Injection    |     A03:2021 - Injection     |     Low     | Confirmed |
| 2 |       |          |          |  |
| 3 |       |          |          |  |

*(Severity: Critical / High / Medium / Low / Info. Use the rubric at the bottom.)*

---

## Finding 1 — _short title_

- **Category:** _e.g. Injection, Broken Access Control, XSS_
- **Severity:** _Critical / High / Medium / Low_  — _one line on why_
- **Location:** _URL / endpoint / parameter / file_

**Description**
_What's wrong and why it's a problem._

**Steps to reproduce**
1.
2.
3.

**Proof of concept**
```http
# the exact request / payload / URL you used
```
_(Screenshot or response snippet if useful.)_

**Impact**
_What an attacker gains — data exposed, accounts/funds affected, code executed, etc._

**Remediation**
_How you'd fix it. Be specific (parameterized query, output encoding, server-side authz check, allowlist, …)._

---

## Finding 2 — _short title_

- **Category:**
- **Severity:**
- **Location:**

**Description**

**Steps to reproduce**
1.

**Proof of concept**
```http
```

**Impact**

**Remediation**

---

<!-- Duplicate the block above for each additional finding. -->

---

## Severity guide (quick + dirty)

- **Critical** — full system/account compromise, RCE, mass data theft, auth bypass to admin.
- **High** — account takeover, access to other users' sensitive data, money/logic abuse with real impact.
- **Medium** — meaningful info disclosure, needs some precondition (e.g. a logged-in victim, social engineering).
- **Low** — limited-impact issues, best-practice gaps, things that help an attacker but don't directly hurt.
- **Info** — observations / hardening suggestions with no direct exploit.

When in doubt, think about **impact × likelihood** and write one sentence justifying your rating. Being able to *defend* the severity matters more than getting it "right."
