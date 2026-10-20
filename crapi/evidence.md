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
Screenshot: `evidence/F-001/F-001-order6-baseline-ram.png`.

### Cross-account access — another user's order (order_id=5)
UI as `ram`: billed to **`admin@example.com`**, phone `9010203040`, item Seat,
qty 2, $20.
Screenshot: `evidence/F-001/F-001-order5-crossaccount-admin.png`.

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
