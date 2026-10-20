# API Endpoint Inventory — crAPI

Maintained inventory of observed endpoints. Keep this current as new routes are
discovered.

**Columns:**
- **Method** — HTTP method.
- **Path** — route (parameters in `{}`).
- **ID type** — identifier used (e.g. int, UUID, filename, VIN, email, none).
- **Auth** — is a valid token required to get a response? (Yes / No / Unknown)
- **Who should be allowed** — the *intended* authorization model (your hypothesis).
- **Status** — tracking state: `untested`, `testing`, `confirmed-ok`, `finding (F-00X)`.

---

## identity

| Method | Path | ID type | Auth | Who should be allowed | Status |
|--------|------|---------|------|-----------------------|--------|
| GET  | `/identity/api/v2/user/dashboard` | none | Yes | The authenticated user (self) | untested |
| GET  | `/identity/api/v2/vehicle/vehicles` | none | Yes | Owner of the vehicles | untested |
| GET  | `/identity/api/v2/vehicle/{uuid}/location` | UUID | Yes | Owner of the vehicle | untested |
| GET  | `/identity/api/v2/user/videos/0` | int | Yes | Owner of the video record | untested |
| POST | `/identity/api/v2/vehicle/add_vehicle` | none | Yes | Authenticated user (self) | untested |
| POST | `/identity/api/v2/vehicle/resend_email` | none | Yes | Authenticated user (self) | untested |

## workshop

| Method | Path | ID type | Auth | Who should be allowed | Status |
|--------|------|---------|------|-----------------------|--------|
| GET  | `/workshop/api/shop/orders/{id}` | int | Yes | Owner of the order | finding (F-001) |
| GET  | `/workshop/api/shop/orders/all` | none | Yes | Admin / privileged role | untested |
| POST | `/workshop/api/shop/orders/return_order?order_id={id}` | int | Yes | Owner of the order | untested |
| GET  | `/workshop/api/mechanic/mechanic_report?report_id={id}` | int | Yes | Mechanic assigned / owner | untested |
| GET  | `/workshop/api/mechanic/download_report?filename={name}` | filename | Yes | Authorized report recipient | untested |
| GET  | `/workshop/api/merchant/service_requests/{VIN}` | VIN | Yes | Merchant / vehicle owner | untested |
| POST | `/workshop/api/merchant/contact_mechanic` | none | Yes | Authenticated user | untested |

## community

| Method | Path | ID type | Auth | Who should be allowed | Status |
|--------|------|---------|------|-----------------------|--------|
| GET  | `/community/api/v2/community/posts/{id}` | int/string | Unknown | Any authenticated user (public read?) | untested |
| POST | `/community/api/v2/community/posts` | none | Yes | Authenticated user | untested |
| POST | `/community/api/v2/community/posts/{id}/comment` | int/string | Yes | Authenticated user | untested |

## infra

| Method | Path | ID type | Auth | Who should be allowed | Status |
|--------|------|---------|------|-----------------------|--------|
| GET  | `/static/js/main.*.js.map` | filename | No | (Source maps — should not ship to prod) | untested |
| GET  | MailHog `/api/v2/messages` (`http://localhost:8025`) | none | No | (Dev mail tool — should not be exposed) | untested |
