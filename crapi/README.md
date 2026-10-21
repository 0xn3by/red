<h1>crAPI API Penetration Test</h1>

<p>
  An authorized OWASP API Security Top 10 (2023) assessment of a self-hosted<br>
  OWASP crAPI instance, with reproducible evidence and CVSS 3.1 scoring.
</p>

<p>
  <a href="#methodology"><img alt="OWASP API Top 10 2023" src="https://img.shields.io/badge/methodology-OWASP%20API%20Top%2010%20(2023)-58A6FF"></a>
  <a href="#scope"><img alt="Target OWASP crAPI" src="https://img.shields.io/badge/target-OWASP%20crAPI-3776AB"></a>
  <a href="#findings-summary"><img alt="7 findings: 1 Critical, 2 High, 4 Medium" src="https://img.shields.io/badge/findings-7%20(1C%20%7C%202H%20%7C%204M)-F5A524"></a>
  <a href="#rules-of-engagement"><img alt="Authorized lab" src="https://img.shields.io/badge/status-authorized%20lab-F5A524"></a>
  <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-58A6FF"></a>
</p>

This repository documents a black-box and authenticated API penetration test of OWASP crAPI (Completely Ridiculous API), self-hosted in Docker. Every finding was confirmed by the tester with a reproducible request/response before write-up, classified against the OWASP API Security Top 10 (2023), and scored with a full CVSS 3.1 vector.

- Seven confirmed findings: one Critical, two High, four Medium.
- Coverage across five issue classes: BOLA, broken authentication, business-logic abuse, SSRF, and NoSQL injection.
- Raw request/response evidence and annotated screenshots for every finding.
- A maintained endpoint inventory mapping each route to its intended authorization model.

> [!IMPORTANT]
> This is an authorized test of a tester-owned, intentionally vulnerable lab application bound to `localhost`. It is not a report against any third-party or production system. CVSS scores assume a hypothetical production deployment and measure technical severity, not the risk of this isolated box.

## Scope

| Item | Detail |
| --- | --- |
| Target | OWASP crAPI, self-hosted Docker instance |
| Web / API base | `http://localhost:8888` |
| Mail capture | MailHog, `http://localhost:8025` |
| Accounts | Attacker and victim, both tester-controlled |
| Framework | OWASP API Security Top 10 (2023) |
| Assessor | Akash Govind (`0xn3by`) |
| Report date | 2026-10-21 |

In scope: the identity, workshop, and community API services, and supporting infrastructure endpoints observed from the running instance. Out of scope: any host other than `localhost`, the underlying Docker/host OS, and denial-of-service or destructive testing.

## Rules of Engagement

- Only the local, self-hosted instance was tested — no third-party or remote systems.
- Every finding is confirmed with a reproducible request/response captured with a timestamp before it is recorded.
- Findings claiming cross-user access include a baseline proving the object belongs to a different account.
- CVSS vectors are computed as though the API were internet-facing; the local lab lowers real-world risk.
- No denial-of-service and no destructive testing.

## Methodology

Testing follows the OWASP API Security Top 10 (2023) as the classification and coverage framework. Each candidate issue moves through a fixed pipeline before it becomes a finding.

```text
Inventory endpoints   -> method, path, ID type, intended authorization
  -> Confirm manually  -> reproducible request/response + timestamp
  -> Classify          -> OWASP API Top 10 (2023) category
  -> Score             -> full CVSS 3.1 vector (production assumption noted)
  -> Root cause + remediation
```

Evidence is kept at three levels so each finding is auditable end to end.

```text
report.md / report.pdf   -- finding template, CVSS, root cause, remediation
      │
      ├── evidence.md ──── raw curl / Burp request + response, timestamped
      └── evidence/F-00X/  annotated screenshots (baseline vs cross-account)
```

## Findings Summary

| # | Title | Class | CVSS 3.1 | Severity |
| --- | --- | --- | --- | --- |
| F-001 | IDOR on order details via `order_id` | API1 BOLA | 6.5 | Medium |
| F-002 | IDOR on mechanic service report via `report_id` | API1 BOLA | 6.5 | Medium |
| F-003 | JWT `alg:none` accepted — auth bypass / account takeover | API2 Broken Authentication | 9.1 | Critical |
| F-004 | Unauthorized report download via predictable `filename` | API1 BOLA | 6.5 | Medium |
| F-005 | Negative order quantity increases account credit | API6 Business Flows | 6.5 | Medium |
| F-006 | NoSQL operator injection in coupon validation | CWE-943 (API8:2019) | 8.1 | High |
| F-007 | SSRF via `mechanic_api` with bearer-token leak | API7 SSRF | 7.7 | High |

Full write-ups, evidence, and remediation are in [`report.md`](report.md) and the rendered [`report.pdf`](report.pdf).

## Key Findings

- **F-003 · JWT `alg:none` (Critical, 9.1)** — the identity service accepts unsigned `{"alg":"none"}` tokens and trusts the `sub` claim, so a forged token returns any user's account; demonstrated by minting a token for a victim email and reading their dashboard.
- **F-007 · SSRF (High, 7.7)** — `contact_mechanic` issues a server-side request to an attacker-supplied `mechanic_api` URL and forwards the caller's `Authorization` bearer token, confirmed by an out-of-band callback from the internal app container.
- **F-006 · NoSQL injection (High, 8.1)** — `coupon_code` reaches a MongoDB query without type validation; a `{"$ne":"x"}` operator bypasses exact match and returns a valid coupon.
- **F-001 / F-002 / F-004 · BOLA (Medium, 6.5 each)** — order details, mechanic reports, and report PDFs are returned by sequential integer ID or predictable filename with no ownership check, exposing other users' PII and VINs.
- **F-005 · Negative-quantity credit (Medium, 6.5)** — the order flow computes `charge = price × quantity` without rejecting non-positive quantities, so a negative quantity increases account credit.

## Tooling

- **Burp Suite Community** — Proxy history and Repeater for request capture and replay.
- **jwt_tool** — JWT decoding and `alg:none` token forgery.
- **curl** — request replay across the attacker and victim identities.
- **netcat** — out-of-band listener for the SSRF callback.
- **Python** — small base64/token manipulation helpers.
- **Browser DevTools** — endpoint discovery and UI-to-API mapping.

## Repository Structure

```text
crapi-assessment/
├── report.md          # Full assessment report — 7 findings, CVSS, remediation
├── report.pdf         # Rendered PDF deliverable
├── endpoints.md       # API endpoint inventory (21 routes, status per route)
├── evidence.md        # Raw request/response and screenshot index per finding
├── evidence/
│   ├── F-001/         # IDOR on order details
│   ├── F-002/         # IDOR on mechanic report
│   ├── F-003/         # JWT alg:none account takeover
│   ├── F-004/         # Unauthorized report download
│   ├── F-005/         # Negative-quantity credit
│   ├── F-006/         # NoSQL coupon injection
│   └── F-007/         # SSRF + bearer-token leak
└── README.md
```

## How to Read

- Start with [`report.md`](report.md) or [`report.pdf`](report.pdf) for the executive summary, findings table, and per-finding detail.
- For any finding, open [`evidence.md`](evidence.md) at the matching `F-00X` section for the exact request and trimmed response, then the screenshots in `evidence/F-00X/`.
- [`endpoints.md`](endpoints.md) is the inventory; the `Status` column flags every route confirmed vulnerable.

## Reproducing

- Stand up OWASP crAPI locally (Docker) and register two accounts.
- Follow the numbered `Steps to repro` in each finding, replaying the request shown in `evidence.md`.
- Authorization findings require a baseline request as the owning account to prove cross-user access.

## Limitations and Caveats

- Scoped to confirmed findings; this is not an exhaustive audit of every endpoint.
- F-007 demonstrates a callback to the tester's listener; reaching internal-only services was not demonstrated.
- Emails, phone numbers, VINs, and tokens in screenshots are crAPI's seeded lab data, not real user data.
- CVSS vectors assume a production deployment and do not reflect the isolated local lab.

## License

This project is licensed under the [MIT License](LICENSE).
