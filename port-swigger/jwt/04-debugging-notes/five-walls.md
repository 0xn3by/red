# Five walls: the real failure modes

These are the actual dead ends hit while solving Lab 1, each with the symptom
seen and the fix that cleared it. They are worth more than the happy path:
most of the time spent on algorithm confusion is spent telling *auth failures*
apart from *transport failures* apart from *stale-state failures*.

## The one diagnostic that matters first

A `401 Unauthorized` with `Set-Cookie: session=;` (an empty, cleared cookie)
means the **signature was rejected**. The server could not verify the token, so
it treats you as unauthenticated and wipes the session.

That is **not** the same as an authorization failure. An authorization failure
would be: valid signature, server knows who you are, but your `sub` is not
allowed. Here the server never got that far — it threw the identity away at the
signature check.

| Observation | What it means |
|-------------|---------------|
| `401` + `Set-Cookie: session=;` (cleared) | Signature rejected → treated as unauthenticated. Wrong key or wrong alg handling. |
| `401`/`403` with the session cookie intact | Signature verified, identity known, but not authorized. Different problem. |
| `302` → `/login` | Session invalid/absent → bounced to log in. |

So when you see the cleared-cookie 401, stop tweaking the payload. The problem
is the **secret you HMAC'd with**, not the `sub` claim.

## Wall 1 — Signed with the RSA private key instead of the public key

**Symptom:** `401`, session cleared.

**Cause:** The forge step used the private key as the HMAC secret. The attack
requires the **public** key: that is the value both you and the server hold.
The server HMACs with its public key, so you must too.

**Fix:** HMAC-sign with the **public** key PEM. Confirm the PEM you feed the
forger is `-----BEGIN PUBLIC KEY-----`, not `PRIVATE KEY`.

## Wall 2 — Stale `key.pem` after a lab reset

**Symptom:** `401`, session cleared — even though the forge looked correct.

**Cause:** The lab was relaunched and issued a **new instance** with a new key
pair. The `kid` can look familiar but the modulus is different. The old
`key.pem` is now the wrong secret.

**Fix:** Re-fetch `/jwks.json` from the *current* instance and regenerate
`key.pem` before every solve attempt. In this repo the screenshots are from the
first instance (`kid: 37ff8d1f...`) while the text artifacts are from the final
instance (`kid: 34982dd3...`) — a concrete example of this exact drift.

![Forged sub=administrator still 401: the signature did not verify (wrong/stale key), not an authorization failure.](../01-lab-exposed-key/evidence/screenshots/02-wall-401-admin-rejected.png)

> Caption: Forged `sub=administrator` still `401`: the signature did not verify
> (wrong/stale key), **not** an authorization failure. Lab status "Not solved".

## Wall 3 — Trailing-newline byte mismatch in the PEM secret

**Symptom:** `401`, session cleared, with the *right* key.

**Cause:** HMAC is over raw bytes. `key.pem` with a trailing `\n` and the same
file without it are different secrets (see
[the trailing-newline note](../01-lab-exposed-key/README.md#the-trailing-newline-ambiguity-textbook)).
You guessed the wrong byte sequence.

**Fix:** Try both. [`forge_hs256.py`](../01-lab-exposed-key/scripts/forge_hs256.py)
emits variant A (with newline) and variant B (without); send each.

## Wall 4 — `curl: (16) expected SETTINGS frame`

**Symptom:**

```
curl: (16) Remote peer returned unexpected data while we expected SETTINGS frame. Perhaps, peer does not support HTTP/2 properly.
```

**Cause:** An HTTP/2 negotiation failure in the transport. This is **not** an
auth problem — the request never completed. Easy to misread as "my token is
broken".

**Fix:** Force HTTP/1.1:

```bash
curl -i --http1.1 "https://<lab-host>/admin/delete?username=carlos" \
  --cookie "session=<forged_token>"
```

## Wall 5 — `504 Gateway Timeout` on every path including `/`

**Symptom:**

```
HTTP/1.1 504 Gateway Timeout
<h1>Server Error: Gateway Timeout (0) connecting to <lab-host></h1>
```

**Cause:** The lab instance is asleep or expired. When even `/` times out, it is
not your token — the target is gone.

**Fix:** Relaunch the lab (which issues a new instance → see Wall 2, re-fetch
the key).

## Summary

| Wall | Symptom | Root cause | Fix |
|------|---------|-----------|-----|
| 1 | 401, cleared cookie | HMAC'd with private key | Use the public key PEM |
| 2 | 401, cleared cookie | Stale key after reset | Re-fetch `/jwks.json`, regenerate PEM |
| 3 | 401, cleared cookie | PEM newline byte mismatch | Try with- and without-newline variants |
| 4 | `curl (16)` SETTINGS frame | HTTP/2 negotiation, not auth | `--http1.1` |
| 5 | 504 on every path | Instance asleep/expired | Relaunch |
