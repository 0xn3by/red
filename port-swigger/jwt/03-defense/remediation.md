# Remediation: preventing algorithm confusion

Algorithm confusion is a verification-configuration bug, not a key-management
bug. The fix is to stop letting the token choose how it is verified. Defenses
below are ordered strongest first.

## Defenses, strongest first

| # | Defense | What it does | Strength |
|---|---------|--------------|----------|
| 1 | **Algorithm allowlisting** | Pass an explicit `algorithms=[...]` to the verifier so a swapped `alg` is rejected before any crypto runs. | Primary fix. Closes the bug outright. |
| 2 | **Key-type binding** | Bind the key object to its algorithm family so an RSA public key can never be used as an HMAC secret, even if an allowlist is forgotten. | Strong defense-in-depth. |
| 3 | **Separate keys per algorithm** | Never reuse one key across RS256 and HS256. Different purposes, different keys. | Removes the shared-secret overlap. |
| 4 | **Modern, maintained libraries** | Current libraries require an explicit algorithm and reject `alg: none` by default. | Baseline hygiene. |
| 5 | **Short token TTL** | Limits the window of a forged token. | Defense-in-depth **only** — does not prevent forgery. |

### 1. Algorithm allowlisting (the actual fix)

Verify against a fixed algorithm set that matches the key:

```python
# PyJWT — only RS256 is accepted; a token claiming HS256 is rejected.
jwt.decode(token, public_key, algorithms=['RS256'])
```

```javascript
// jsonwebtoken (Node) — pin the algorithm.
jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

The demo [`../demo/vuln_vs_safe.py`](../demo/vuln_vs_safe.py) shows the exact
line that flips the server from exploitable to safe:
`algorithms=['RS256','HS256']` accepts the forgery; `algorithms=['RS256']`
rejects it.

### 2. Key-type binding

Load the verification key as a typed key object (an RSA public key object),
not as a raw string the library might feed to HMAC. If the library is handed
an `RSAPublicKey` object, the HS256 branch has nothing to HMAC with and the
confusion cannot occur. `[Unverified]` — depends on the library honoring the
key type; confirm per library.

### 3. Separate keys per algorithm

If a system genuinely needs both symmetric and asymmetric tokens, use distinct
keys and distinct key IDs so there is no byte sequence shared between the RS256
public key and any HMAC secret.

### 5. Short TTL is not a fix

A forged token is valid the moment it is minted. A short `exp` shrinks the
replay window but does nothing to stop the forgery itself. Treat it as
hygiene, never as the control that stops this attack.

## Historical context `[Unverified]`

This is a known CVE class. The widely cited example is the `jsonwebtoken`
library issue tracked as **CVE-2015-9235**, where tokens could be verified
under an attacker-chosen algorithm (including the RS256→HS256 confusion and
`alg: none`). Current popular JWT libraries have responded by **requiring an
explicit algorithm allowlist** and rejecting `none` by default.

> `[Unverified]` Version- and library-specific behavior changes over time.
> Check the current documentation and changelog of whatever library you use
> (PyJWT, jose, jsonwebtoken, etc.) rather than trusting a version claim here.

## Checklist

- [ ] Verifier passes an explicit `algorithms=[...]` allowlist.
- [ ] The allowlist contains only algorithms the key is actually for.
- [ ] `alg: none` is rejected.
- [ ] RSA keys and HMAC secrets are never the same bytes.
- [ ] Library is current and maintained.
- [ ] Short TTL is present — as defense-in-depth, not the primary control.
