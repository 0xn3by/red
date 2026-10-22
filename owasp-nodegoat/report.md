# OWASP NodeGoat — Secure Code Review Report

> **Status:** v1.0 — 7 confirmed findings · **Assessor:** Akash Govind · **Date:** 2026-10-22
> **Target:** OWASP/NodeGoat @ [`c5cb68a`](https://github.com/OWASP/NodeGoat/tree/c5cb68a7084e4ae7dcc60e6a98768720a81841e8) · **Method:** manual source-to-sink review

---

## 1. Executive Summary

A manual secure code review of OWASP NodeGoat (commit `c5cb68a`) traced seven confirmed vulnerabilities from request source to dangerous sink: four High, three Medium. The two highest-impact issues are code execution reachable by any authenticated user — a server-side JavaScript `eval()` on three contribution fields (F-003) and a MongoDB `$where` injection on the allocations filter (F-002). A stored XSS whose payload executes in an administrator's session (F-004) rounds out the High-severity set alongside a missing function-level access-control check on the benefits page (F-007). The dominant root causes are a global template setting (`autoescape: false`), user input flowing into JavaScript-evaluating sinks (`eval`, `$where`), and authorization decisions keyed on client-supplied IDs rather than the session identity. Two findings — the IDOR (F-001) and the NoSQL injection (F-002) — were additionally confirmed by exploiting a local instance; the rest were confirmed against source but not exploited.

| Critical | High | Medium | Low | Info |
|:--------:|:----:|:------:|:---:|:----:|
| 0 | 4 | 3 | 0 | 0 |

---

## 2. Scope

| | |
|---|---|
| Target | OWASP NodeGoat, source at commit `c5cb68a` |
| Repository | `https://github.com/OWASP/NodeGoat` |
| Review type | Manual secure code review (source-to-sink), not a black-box pentest |
| Exploited locally | F-001 (IDOR), F-002 (NoSQL injection) |
| Confirmed vs. source only | F-003, F-004, F-005, F-006, F-007 |
| Framework | OWASP Top 10 (2021) for classification; CWE per finding |
| Assessor | Akash Govind (`0xn3by`) |

NodeGoat is OWASP's deliberately vulnerable Node.js/Express/MongoDB training app. Every finding below is a documented teaching vulnerability; the value here is the source-to-sink trace, the defensible severity, and the remediation, not the novelty of the bug. Out of scope: the training tutorial content, dependencies beyond those explicitly named, and any host other than a local instance.

---

## 3. Methodology

Each candidate issue moved through a fixed pipeline:

```text
Locate source   -> request-controlled input (req.params / req.query / req.body)
  -> Trace to sink -> the line that renders, queries, or evaluates it
  -> Check guards  -> validation / encoding / authz BETWEEN source and sink
  -> Classify      -> OWASP Top 10 (2021) + CWE
  -> Score         -> full CVSS 3.1 vector (production-deployment assumption)
  -> Root cause + remediation; exploit locally where practical
```

Two disciplines were applied deliberately and are worth calling out:

- **A missing config option is not a missing protection until the library default is checked.** `httpOnly` is *not* a NodeGoat finding here — express-session sets it to `true` by default — even though the hardening block for it is commented out. See [`notes.md`](./notes.md).
- **Each vulnerability class carries its own checklist.** CSRF is verified by route-level middleware *and* token validation, not by cookie flags; the presence of a `_csrf` form field is not evidence of protection (F-006).

CVSS vectors assume a production deployment and measure technical severity. All privileged-user findings assume an authenticated low-privilege account, which NodeGoat hands out via open self-registration — a free signup, not a real barrier.

Raw source-to-sink evidence with line-exact permalinks is in [`evidence.md`](./evidence.md); the verbatim vulnerable snippets are in [`code-reference.md`](./code-reference.md).

---

## 4. Findings Summary

| # | Title | Class (OWASP 2021) | CWE | CVSS 3.1 | Severity |
|---|-------|--------------------|-----|:--------:|:--------:|
| F-003 | SSJS injection — three contribution fields reach `eval()` | A03 Injection | CWE-95 | 8.8 | High |
| F-004 | Stored XSS → executes in admin session (autoescape off) | A03 Injection | CWE-79 | 8.7 | High |
| F-002 | NoSQL injection via `$where` on allocations filter | A03 Injection | CWE-943 | 8.1 | High |
| F-007 | Missing function-level access control on `/benefits` | A01 Broken Access Control | CWE-862 | 7.1 | High |
| F-001 | IDOR on `/allocations/:userId` (no ownership check) | A01 Broken Access Control | CWE-639 | 6.5 | Medium |
| F-006 | CSRF protection commented out on state-changing POSTs | A01 Broken Access Control | CWE-352 | 6.5 | Medium |
| F-005 | Session/cookie misconfiguration (hardcoded secret, HTTP) | A05 Security Misconfiguration | CWE-614 | 5.3 | Medium |

Severity bands (CVSS 3.1): Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9.

---

## 5. Detailed Findings

### F-003 · SSJS injection — contribution fields reach `eval()`

- **Class:** A03 Injection · **CWE-95** (eval injection) · **Severity:** 8.8 High
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Affected:** `POST /contributions` → `app/routes/contributions.js` L28-L34
- **What:** Three POST body fields (`preTax`, `afterTax`, `roth`) are each passed straight into `eval()`. The `isNaN`/`< 0` validation runs *after* `eval`, so the payload has already executed by the time it is checked.
- **Source → sink:** `req.body.preTax` → `eval(req.body.preTax)`. A `/*jslint evil: true */` comment immediately precedes the call — the linter warned and was overridden, so the risk was known, not missed.
- **Impact:** Arbitrary JavaScript in the Node process. A `while(true){}` payload proves DoS (the floor); the ceiling is remote code execution — filesystem read (`require('fs')`), shell commands (`require('child_process')`), and env/credential exfiltration. Reachable by any authenticated account.
- **Root cause:** Dangerous sink (`eval`) fed by request data; numeric parsing would suffice.
- **Fix:** Remove `eval` entirely; parse with `Number()` / `parseInt` and range-check. Validating input while still calling `eval` is not acceptable — delete the sink, don't sanitize into it.
- **Note:** Ceiling is full host compromise; scored S:U (same security authority as the app). With scope change counted (shelling out of the Node process), the vector reaches `S:C` → 9.9 Critical.

### F-004 · Stored XSS executes in an administrator's session

- **Class:** A03 Injection · **CWE-79** · **Severity:** 8.7 High
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N`
- **Affected:** source `app/routes/profile.js` → `profile-dao.js updateUser()`; sinks `layout.html` L75, `allocations.html` L35, `benefits.html` L51
- **What:** `req.body.firstName` is stored unmodified and rendered with `{{ }}` into the HTML body of other users' pages. The root cause is global: `server.js` L134-L142 sets `swig.setDefaults({ autoescape: false })`, so no `{{ }}` output is encoded anywhere.
- **Source → sink:** `req.body.firstName` → MongoDB → `{{user.firstName}}` in `benefits.html`, the admin-facing page that lists every user's first name.
- **Impact:** A payload stored in a regular user's first name executes in the admin's browser, in the admin's session — the attacker acts as the admin (e.g. rewrites every user's benefit data). Direct cookie theft is *not* the path: express-session sets the session cookie `HttpOnly`, so `document.cookie` cannot read it; impact comes from acting inside the session, not stealing it.
- **Root cause:** Template autoescaping disabled globally.
- **Fix:** Set `autoescape: true` so every `{{ }}` is HTML-encoded by default. For values in URL attributes, encode for that context and allowlist the scheme to `http:`/`https:` — HTML encoding alone does not stop a `javascript:` URL.
- **Caveat:** Not yet exploited on a local instance; confirmed against source. A secondary wrong-context encoding bug on `doc.website` (`profile.js` L24-L31) is noted but partly broken in this commit (upstream issue #239).

### F-002 · NoSQL injection via `$where` on the allocations filter

- **Class:** A03 Injection · **CWE-943** · **Severity:** 8.1 High
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H`
- **Affected:** `GET /allocations/:userId?threshold=` → `app/data/allocations-dao.js` L57-L86
- **What:** `req.query.threshold` is interpolated raw into a MongoDB `$where` clause: `` `this.userId == ${parsedUserId} && this.stocks > '${threshold}'` ``. `userId` goes through `parseInt()`; only `threshold` is injectable. MongoDB runs `$where` as JavaScript, so this is `eval()` reachable through a filter box.
- **Impact (exploited locally, two payloads):** `1'; return 1 == '1` returned every user's allocation records — full confidentiality breach across the user base. `0';while(true){}'` hung the MongoDB server — denial of service.
- **Root cause:** User input concatenated into a JavaScript-evaluating query operator.
- **Fix:** Never build `$where` from request data. Use standard query operators and parameterized filters.
- **Methodology note:** `$where` does not trigger on MongoDB Atlas M0 clusters — a test-environment mismatch can produce a false negative. Confirmed on a local self-hosted MongoDB.

### F-007 · Missing function-level access control on `/benefits`

- **Class:** A01 Broken Access Control · **CWE-862** · **Severity:** 7.1 High
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`
- **Affected:** `app/routes/index.js` L55-L59; `benefits.html` L56
- **What:** `/benefits` (GET and POST) is gated by `isLoggedIn` only — the `isAdmin` check is commented out. The update form also takes the target `userId` from a hidden field.
- **Source → sink:** any authenticated user → `POST /benefits` with an arbitrary `userId` → `updateBenefits` writes another user's benefits start date, with no role or ownership check.
- **Impact:** Any logged-in user reads and modifies every user's benefits data — a user-controlled admin function.
- **Root cause:** Authorization middleware (`isAdmin`) not applied; target ID trusted from the client.
- **Fix:** Add `isAdmin` to both routes; derive or verify the target `userId` server-side against the actor's role.

### F-001 · IDOR on `/allocations/:userId` (Broken Access Control)

- **Class:** A01 Broken Access Control · **CWE-639** · **Severity:** 6.5 Medium
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **Affected:** `app/routes/allocations.js` L11-L23; route `index.js` L63
- **What:** The handler reads the user ID from `req.params.userId` (the URL) instead of `req.session.userId`, with no ownership check. A commented-out line in the handler reads *"Fix for A4 Insecure DOR — take user id from session instead of from URL param"* — the correct fix was known and not applied. `isLoggedIn` checks authentication only.
- **Impact (exploited locally):** authenticated as one user, changing the numeric ID in the URL returned another user's allocations. Any account can enumerate and read every user's financial records.
- **Root cause:** Missing ownership check — not ID predictability.
- **Fix:** Derive the user ID from the verified session/token, or add an explicit owner-vs-session comparison. Switching to UUIDs or to JWT does **not** fix this — the bug is the absent check, not the ID format or the auth transport.

### F-006 · CSRF protection commented out on state-changing POSTs

- **Class:** A01 Broken Access Control · **CWE-352** · **Severity:** 6.5 Medium
- **CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`
- **Affected:** `server.js` L7 and L104-L113; forms `profile.html` L73, `contributions.html` L91; routes `/profile`, `/contributions`, `/benefits`
- **What:** `require('csurf')` and the `app.use(csrf())` block are both commented out. The forms still render `<input type="hidden" name="_csrf" value="{{csrftoken}}">`, but the token is never generated (renders empty) and never validated. This is the half-present case: a token field in the form is not evidence of protection.
- **Impact:** An attacker page can auto-submit a forged `POST /profile` that changes a logged-in victim's bank account and routing number. The browser attaches the session cookie automatically; with no token check and no `sameSite` (F-005), nothing blocks it. The victim only has to visit the page.
- **Root cause:** CSRF middleware disabled app-wide.
- **Fix:** Re-enable CSRF middleware before the routes. `csurf` is deprecated — use a maintained alternative (`csrf-csrf`, `csrf-sync`). Set `sameSite` on the session cookie as a second layer. Verify empirically by replaying a request with `_csrf` removed and confirming rejection.

### F-005 · Session and cookie misconfiguration

- **Class:** A05 Security Misconfiguration · **CWE-614 / CWE-522** · **Severity:** 5.3 Medium
- **CVSS:** `CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (cleartext-cookie-sniff scenario)
- **Affected:** `server.js` L77-L102 (session), L144-L147 (HTTP); `config/env/all.js` L8 (secret)
- **What:** The `session()` call passes only `secret`, `saveUninitialized`, `resave` — no `cookie` options. Ranked by severity:
  - **Hardcoded secret** `"session_cookie_secret_key_here"`, committed, no env override: anyone with the repo can produce validly signed cookies, removing signing as a defense. *Caveat:* with express-session's server-side store, a signed cookie must still name a session ID that exists in the store, so the secret alone does not mint an admin session from nothing.
  - **`secure` unset on a plain-HTTP app** (`http.createServer`): the session cookie travels in cleartext and can be sniffed on an untrusted network → full session hijack.
  - **`sameSite` unset:** removes a browser-level CSRF defense, which matters because CSRF tokens are also off (F-006).
  - **Default cookie name `connect.sid`:** fingerprints Express. Low on its own.
  - **Not a finding — `httpOnly`:** express-session defaults it to `true`; the cookie is already protected from `document.cookie`.
- **Root cause:** Session middleware configured without hardening; app served over HTTP.
- **Fix:** Serve over HTTPS; set `secure: true` and `sameSite: 'lax'`/`'strict'` explicitly. Move the secret to an env var and rotate it. Set a generic cookie name. Keep `httpOnly: true` explicit so protection doesn't depend on a default.

---

## 6. Appendix — Additional observations (reviewed, not scored as findings)

Visible in the same files, worth a line but not written up as full findings:

- **Vulnerable dependency:** `"marked": "0.3.5"` pinned exactly (no caret) in `package.json` L17 — never moves to a patched release.
- **ReDoS:** `const regexPattern = /([0-9]+)+\#/;` in `profile.js` L59 — nested quantifier applied to `req.body.bankRouting`.

Methodology refinements made during the review — where an initial answer was corrected against source — are in [`notes.md`](./notes.md).
