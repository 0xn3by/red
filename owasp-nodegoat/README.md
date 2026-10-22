<h1>OWASP NodeGoat — Secure Code Review</h1>

<p>
  A manual secure code review of OWASP NodeGoat, tracing seven vulnerabilities<br>
  from request source to dangerous sink, with line-exact permalinks and CVSS 3.1 scoring.
</p>

<p>
  <a href="#methodology"><img alt="OWASP Top 10 2021" src="https://img.shields.io/badge/methodology-OWASP%20Top%2010%20(2021)-58A6FF"></a>
  <a href="#scope"><img alt="Target OWASP NodeGoat" src="https://img.shields.io/badge/target-OWASP%20NodeGoat-3776AB"></a>
  <a href="#findings-summary"><img alt="7 findings: 4 High, 3 Medium" src="https://img.shields.io/badge/findings-7%20(4H%20%7C%203M)-F5A524"></a>
  <a href="#scope"><img alt="Source review" src="https://img.shields.io/badge/type-secure%20code%20review-F5A524"></a>
  <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-58A6FF"></a>
</p>

This repository documents a manual, source-to-sink secure code review of [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) at commit [`c5cb68a`](https://github.com/OWASP/NodeGoat/tree/c5cb68a7084e4ae7dcc60e6a98768720a81841e8). Every finding is traced from a request-controlled source to the line that renders, queries, or evaluates it, classified against the OWASP Top 10 (2021), and scored with a full CVSS 3.1 vector.

- Seven confirmed findings: four High, three Medium.
- Coverage across injection (SSJS `eval`, NoSQL `$where`, stored XSS), broken access control (IDOR, missing function-level authz, CSRF), and security misconfiguration.
- Line-exact permalinks for every source and sink; verbatim snippets kept alongside.
- Two findings (IDOR, NoSQL injection) additionally confirmed by exploiting a local instance.

> [!IMPORTANT]
> NodeGoat is OWASP's deliberately vulnerable training application. This is a source code review of that public teaching app, not a report against any third-party or production system. CVSS scores assume a hypothetical production deployment and measure technical severity, not the risk of a local training instance.

## Scope

| Item | Detail |
| --- | --- |
| Target | OWASP NodeGoat, source at commit `c5cb68a` |
| Repository | `https://github.com/OWASP/NodeGoat` |
| Stack | Node.js · Express · Swig templates · MongoDB |
| Review type | Manual secure code review (source-to-sink) |
| Exploited locally | F-001 (IDOR), F-002 (NoSQL injection) |
| Framework | OWASP Top 10 (2021); CWE per finding |
| Assessor | Akash Govind (`0xn3by`) |
| Date | 2026-10-22 |

In scope: the application source at the pinned commit. Out of scope: the training tutorial content, transitive dependencies beyond those explicitly named, and any live host other than a local instance.

## Methodology

Each candidate issue moves through a fixed pipeline before it becomes a finding.

```text
Locate source  -> request-controlled input (req.params / req.query / req.body)
  -> Trace to sink -> the line that renders, queries, or evaluates it
  -> Check guards  -> validation / encoding / authz BETWEEN source and sink
  -> Classify      -> OWASP Top 10 (2021) + CWE
  -> Score         -> full CVSS 3.1 vector (production assumption noted)
  -> Root cause + remediation; exploit locally where practical
```

Two disciplines ran throughout: a missing config option is not a missing protection until the library default is checked (`httpOnly` is *not* a finding — express-session defaults it on), and each vulnerability class carries its own checklist (CSRF is verified by middleware + token validation, not by cookie flags). Both are written up in [`notes.md`](notes.md).

Evidence is kept at three levels so each finding is auditable end to end:

```text
report.md          -- finding template, CVSS, root cause, remediation
      │
      ├── evidence.md ───── source-to-sink trace + line-exact permalinks
      ├── code-reference.md  verbatim vulnerable snippets
      └── notes.md ───────── methodology refinements & first-pass corrections
```

## Findings Summary

| # | Title | Class (OWASP 2021) | CWE | CVSS 3.1 | Severity |
| --- | --- | --- | --- | :---: | :---: |
| F-003 | SSJS injection — contribution fields reach `eval()` | A03 Injection | CWE-95 | 8.8 | High |
| F-004 | Stored XSS → executes in admin session | A03 Injection | CWE-79 | 8.7 | High |
| F-002 | NoSQL injection via `$where` on allocations filter | A03 Injection | CWE-943 | 8.1 | High |
| F-007 | Missing function-level access control on `/benefits` | A01 Broken Access Control | CWE-862 | 7.1 | High |
| F-001 | IDOR on `/allocations/:userId` | A01 Broken Access Control | CWE-639 | 6.5 | Medium |
| F-006 | CSRF protection commented out | A01 Broken Access Control | CWE-352 | 6.5 | Medium |
| F-005 | Session/cookie misconfiguration | A05 Security Misconfiguration | CWE-614 | 5.3 | Medium |

Full write-ups and remediation are in [`report.md`](report.md).

## Key Findings

- **F-003 · SSJS injection via `eval()` (High, 8.8)** — three POST fields (`preTax`, `afterTax`, `roth`) reach `eval()` before validation runs; a `/*jslint evil: true */` comment shows the warning was overridden. DoS is the floor, remote code execution the ceiling (`child_process`, `fs`, env exfiltration).
- **F-002 · NoSQL `$where` injection (High, 8.1)** — `req.query.threshold` is interpolated raw into a MongoDB `$where` clause. Exploited locally: one payload returned every user's financial allocations, another hung the database.
- **F-004 · Stored XSS to admin session (High, 8.7)** — `firstName` is stored unencoded and rendered into the admin-facing benefits page with `autoescape: false`; the payload runs in the admin's session. `HttpOnly` blocks cookie theft, so impact is acting *inside* the session, not stealing it.
- **F-007 · Missing function-level access control (High, 7.1)** — `/benefits` is gated by `isLoggedIn` only (`isAdmin` commented out) and trusts a client-supplied `userId`, so any user edits any user's benefits.
- **F-001 / F-006 / F-005 (Medium)** — IDOR from a URL-supplied user ID with no ownership check; CSRF middleware commented out while forms carry an empty token field; session cookie with a hardcoded secret, no `secure`, and plain HTTP.

## Repository Structure

```text
owasp-nodegoat/
├── report.md          # Full review — 7 findings, CVSS, root cause, remediation
├── evidence.md        # Source-to-sink trace + line-exact permalinks per finding
├── code-reference.md  # Verbatim vulnerable snippets from commit c5cb68a
├── notes.md           # Methodology refinements & first-pass corrections
├── LICENSE
└── README.md
```

## How to Read

- Start with [`report.md`](report.md) for the summary, findings table, and per-finding detail.
- For any finding, open [`evidence.md`](evidence.md) at the matching `F-00X` section for the source-to-sink trace and permalinks, then [`code-reference.md`](code-reference.md) for the verbatim snippet.
- [`notes.md`](notes.md) captures where first-pass conclusions were corrected against source — the reasoning, not just the result.

## Reproducing

- Clone NodeGoat and check out commit `c5cb68a`; follow its README to run locally with MongoDB (self-hosted, not Atlas M0 — see the F-002 note).
- For F-001 and F-002, register two accounts and replay the requests in `evidence.md`; the authorization finding needs a baseline as the owning account to prove cross-user access.
- The remaining findings are confirmed by reading the linked source; the permalinks resolve to the exact vulnerable lines.

## Limitations and Caveats

- This is a review of a public, intentionally vulnerable training app; the findings are documented teaching vulnerabilities. The value is the trace, the defensible severity, and the remediation.
- F-003, F-004, F-005, F-006, F-007 are confirmed against source but not exploited on a running instance.
- CVSS vectors assume a production deployment and do not reflect a local training instance.

## License

This project is licensed under the [MIT License](LICENSE).
