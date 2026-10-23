# Lab 2 — Algorithm confusion with no exposed key

**PortSwigger:** JWT authentication bypass via algorithm confusion with no
exposed key.

> **This lab was not performed live.** What follows is a *technique walkthrough*
> derived from study — **method, not a captured run**. Every concrete value
> (tokens, moduli, candidate keys, responses) is marked `TODO:` for when the
> lab is actually run. Do not treat anything here as captured evidence.

## Why this lab is harder than Lab 1

Lab 1 handed us the public key at `/jwks.json`. Here the server does **not**
expose it. But the public key is not a secret and does not need to be
published — it can be **recovered** from signed tokens. Once recovered, the
attack is identical to Lab 1: forge an `HS256` token using the public key PEM
as the HMAC secret.

This is the whole point of [the concept file](../00-concept/algorithm-confusion.md):
secrecy of the public key was never a control.

## The recovery, in one line

RSA signing/verification over a modulus `n` means a signature `s` and message
representative `m` satisfy `s^e ≡ m (mod n)`. So `n` divides `(s^e − m)`.
Collect two signed tokens and take the GCD of their `(s^e − m)` values; `n`
falls out (up to small cofactors). The math is in
[`scripts/derive_modulus_notes.md`](scripts/derive_modulus_notes.md).

## Procedure `[Textbook]`

| # | Step | Tool / action | Output |
|---|------|---------------|--------|
| 1 | Capture **two** distinct valid RS256 tokens from the lab. | Log in / refresh to get two tokens with different payloads. | `TODO:` |
| 2 | Run `sig2n` / `rsa_sign2n` on the two tokens to recover candidate public keys. | `docker run ...` (see notes) | `TODO:` candidate PEMs |
| 3 | For each candidate, forge an `HS256` `sub=administrator` token. | The tool pre-forges tokens; or reuse [Lab 1's forge script](../01-lab-exposed-key/scripts/forge_hs256.py). | `TODO:` |
| 4 | Test each candidate × each newline variant against `/admin`. | `curl --http1.1 ... --cookie "session=<token>"` | `TODO:` |
| 5 | With the working token, delete `carlos`. | `curl --http1.1 ".../admin/delete?username=carlos" --cookie ...` | `TODO:` 302 |

Expect **several candidates**, because the GCD can retain small cofactors, and
the tool emits one key per plausible factoring. Multiply that by the two
newline variants from Lab 1 and you may test a handful of tokens before one
verifies. This is normal, not a sign the method is wrong.

## What is verified vs explained

- `[Textbook]` The GCD recovery math and the `sig2n` workflow.
- `[Unverified]` Any statement about how many candidates *this* lab emits, or
  which one works — not run here.

See [`scripts/derive_modulus_notes.md`](scripts/derive_modulus_notes.md) for the
math, the tool invocation, and `TODO:` slots for real output.
