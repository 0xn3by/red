# Algorithm Confusion: The Root Cause

## The one-sentence bug

A JWT library picks its verification algorithm from the token's own `alg`
header. That header is attacker-controlled. If the server accepts a swap from
`RS256` (asymmetric) to `HS256` (symmetric), it will HMAC the token with its
RSA **public** key — a value the attacker can read.

## What `verify(token, key)` actually does

Most naive verification looks like this:

```python
# Vulnerable: algorithm is read from the token header
jwt.decode(token, key, algorithms=['RS256', 'HS256'])
```

The library inspects `header.alg`, then:

| `alg` in header | What the library does with `key`                         |
|-----------------|----------------------------------------------------------|
| `RS256`         | Treat `key` as an **RSA public key**; verify an RSA signature. |
| `HS256`         | Treat `key` as a **symmetric secret**; recompute an HMAC.      |

The same `key` argument is interpreted two completely different ways. When the
server was designed for RS256, that `key` is the RSA public key. Under the
HS256 branch, the public key bytes become the HMAC secret.

## Legitimate RS256 path `[Textbook]`

```
sign:    signature = RSA_private_key.sign(header_b64 + "." + payload_b64)
verify:  RSA_public_key.verify(signature, header_b64 + "." + payload_b64)
```

The private key signs; the public key verifies. The attacker has the public
key but not the private key, so they cannot forge an RS256 signature. This is
sound.

## Attack HS256 path `[Textbook]`

```
forge:   signature = HMAC_SHA256(key = PEM_bytes_of_public_key,
                                 msg = header_b64 + "." + payload_b64)
verify:  server recomputes HMAC_SHA256(key = PEM_bytes_of_public_key, msg)
         and compares — it matches, because both sides used the same bytes.
```

HMAC is symmetric: the same key both produces and verifies the tag. Because
the attacker and the server both possess the public key PEM, the attacker can
produce a tag the server will accept.

### The signature equation

```
signature = HMAC_SHA256(key = PEM_bytes_of_public_key, msg = header_b64 + "." + payload_b64)
```

The subtle part: the HMAC key is the **exact byte sequence** of the public key
as the server holds it. Usually that is the PEM encoding (SubjectPublicKeyInfo,
base64 wrapped in `-----BEGIN PUBLIC KEY-----` lines). A one-byte difference —
for example a trailing `\n` — produces a different HMAC and the forgery fails.
See [the trailing-newline wall](../04-debugging-notes/five-walls.md).

## Key exposure is NOT the bug `[Textbook]`

This is the most misunderstood point.

- A public key is **meant** to be public. Publishing it at `/jwks.json` is
  normal and correct for RS256.
- The vulnerability is the server **accepting the algorithm swap**, not the
  key being reachable.
- Even if the key were not published, it can often be **recovered** from two
  signed tokens (see [Lab 2](../02-lab-no-exposed-key/README.md)). Secrecy of
  the public key is not a security control and was never supposed to be.

> Mental model: Public key means public. The moment a server HMACs with it,
> the secret is something the whole internet can read.

## Why the swap should be impossible

A correctly configured verifier pins the algorithm set to what the key is
for:

```python
# Safe: only RS256 is accepted, regardless of what the token claims
jwt.decode(token, public_key, algorithms=['RS256'])
```

Now a token with `alg: HS256` is rejected before any HMAC is attempted. The
defenses are detailed in [remediation](../03-defense/remediation.md).
