# crAPI API Penetration Test — Assessment Report

> **Status:** Draft — findings added as they are confirmed with evidence.
> **Assessor:** Akash Govind
> **Report date:** 2026-10-20

---

## 1. Executive Summary

_Written last. Max 5 sentences: posture, counts by severity, dominant themes._

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 0 |
| Medium   | 0 |
| Low      | 0 |
| Info     | 0 |

---

## 2. Scope & Rules of Engagement

**Target:** OWASP crAPI (Completely Ridiculous API), self-hosted lab instance.

| Item | Detail |
|------|--------|
| Web / API base | `http://localhost:8888` |
| Mail capture (MailHog) | `http://localhost:8025` |
| Deployment | Local Docker on Kali, single tester |
| Authorization | Self-owned instance; testing explicitly authorized by the operator (the tester) |
| Accounts | `attacker` account and `victim` account (both tester-controlled) |
| Test window | 2026-10-20 → _ongoing_ |

**In scope:** All API services of the local instance (identity, workshop,
community) and supporting infrastructure endpoints observed from the running
instance.

**Out of scope:** Any host other than `localhost`; the underlying Docker/host OS;
denial-of-service and destructive testing.

**Rules of engagement:**
- No testing against any system other than this local instance.
- Findings are confirmed by the tester with reproducible evidence before being
  recorded here.
- CVSS scores assume a hypothetical **production** deployment (see §3), so they
  reflect technical severity, not the risk of this isolated lab box.

---

## 3. Methodology

Testing follows the **OWASP API Security Top 10 (2023)** as the classification
and coverage framework:

| ID | Category |
|----|----------|
| API1:2023 | Broken Object Level Authorization (BOLA) |
| API2:2023 | Broken Authentication |
| API3:2023 | Broken Object Property Level Authorization |
| API4:2023 | Unrestricted Resource Consumption |
| API5:2023 | Broken Function Level Authorization (BFLA) |
| API6:2023 | Unrestricted Access to Sensitive Business Flows |
| API7:2023 | Server Side Request Forgery (SSRF) |
| API8:2023 | Security Misconfiguration |
| API9:2023 | Improper Inventory Management |
| API10:2023 | Unsafe Consumption of APIs |

**Process:**
1. **Inventory** — enumerate endpoints, methods, identifier types, and the
   intended authorization model (see `endpoints.md`).
2. **Confirm** — the tester manually confirms each candidate issue with a
   reproducible request/response, captured in `evidence.md` with a timestamp.
3. **Classify** — map each confirmed finding to an API Top 10 category.
4. **Score** — assign a full **CVSS 3.1** vector (not just a number), with the
   production-deployment assumption noted.
5. **Root cause & remediation** — one-line root cause and a concrete fix.

**Scoring note:** All CVSS vectors are computed as though the API were
internet-facing in production. The local lab (bound to `localhost`, no real
users or data) materially lowers real-world risk; scores here measure the
technical severity of the defect, not the exposure of this box.

---

## 4. Findings Summary Table

| # | Title | API Top 10 | CVSS 3.1 | Severity | Status |
|---|-------|-----------|----------|----------|--------|
| F-001 | IDOR on order details via `order_id` | API1 BOLA | 6.5 | Medium | Confirmed |

---

## 5. Detailed Findings

_Fixed template per finding. Nothing added until confirmed with evidence in
`evidence.md`._

### F-001

| Field | |
|-------|--|
| **Title** | IDOR on order details — any user reads any order via `order_id` |
| **API Top 10** | API1 Broken Object Level Authorization |
| **Severity** | 6.5 Medium — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Affected** | GET `/workshop/api/shop/orders/{id}` (UI route `/orders?order_id=`) |
| **Description** | The order-details endpoint returns any order by integer ID without checking ownership. IDs are sequential, so all orders are enumerable. |
| **Steps to repro** | 1. Log in as attacker (`ram`). 2. View own order `order_id=6` → billed to `ram123@gmail.com` (baseline). 3. Decrement to `order_id=5` → returns order billed to `admin@example.com`, a different user. |
| **Evidence** | UI screenshots (same `ram` session): `order_id=6` = ram's order; `order_id=5` = `admin@example.com`, phone `9010203040`, item Seat, $20. Raw API request/response: see `evidence.md` → F-001. |
| **Impact** | An authenticated user can read every customer's order details — email, phone, items, amounts — by enumerating IDs. |
| **Root cause** | No object-level authorization: the handler does not verify the order belongs to the requesting user. |
| **Remediation** | Enforce ownership server-side (`order.user == request.user`, else 403/404). Do not rely on sequential integer IDs for access control. |

<!--
### F-00X

| Field | |
|-------|--|
| **Title** | class + location, one line |
| **API Top 10** | APIx Name |
| **Severity** | CVSS 3.1 score + `CVSS:3.1/AV:/AC:/PR:/UI:/S:/C:/I:/A:` |
| **Affected** | METHOD path |
| **Description** | ≤2 sentences: what the flaw is |
| **Steps to repro** | numbered; attacker vs victim noted |
| **Evidence** | curl request + key response lines, trimmed (full in evidence.md) |
| **Impact** | 1 sentence, real consequence |
| **Root cause** | 1 line: the missing check |
| **Remediation** | 1–2 lines |
-->

---

## 6. Appendix: Endpoint Inventory

The authoritative, maintained inventory lives in [`endpoints.md`](./endpoints.md).
A snapshot may be pasted here for the final deliverable.
