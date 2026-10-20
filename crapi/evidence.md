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

_No evidence recorded yet._
