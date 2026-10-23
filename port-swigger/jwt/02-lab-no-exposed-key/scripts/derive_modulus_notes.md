# Deriving the RSA modulus from two signed JWTs

> Method notes, `[Textbook]`. Not run live — every concrete value below is a
> `TODO:` placeholder.

## The math

RSA signature verification recovers a message representative from the signature
using the **public** exponent `e`:

```
s^e ≡ m (mod n)
```

- `s` — the signature, interpreted as a big integer.
- `e` — the public exponent, here `65537` (`0x10001`, the usual default).
- `m` — the "message representative": the PKCS#1 v1.5 padded, DER-encoded
  SHA-256 hash of the signing input (`header_b64 + "." + payload_b64`). The
  tool constructs this; you do not hand-build it.
- `n` — the RSA modulus (the unknown we want).

Rearranging:

```
s^e ≡ m (mod n)
s^e − m ≡ 0 (mod n)
=> n divides (s^e − m)
```

A single token gives one multiple of `n`: `k1 · n = s1^e − m1`. One multiple is
not enough to isolate `n`. With **two** tokens:

```
k1 · n = s1^e − m1
k2 · n = s2^e − m2
```

Their greatest common divisor is `n` times `gcd(k1, k2)`:

```
GCD(s1^e − m1, s2^e − m2) = n · gcd(k1, k2)
```

For random `k1, k2` the `gcd(k1, k2)` is usually 1 or a small integer, so:

```
n ≈ GCD(s1^e − m1, s2^e − m2)
```

then **strip small cofactors** (divide out factors of 2, 3, 5, …) to get the
true modulus. The tool does this cofactor stripping and emits each candidate.

### Why candidates, not one answer `[Textbook]`

- `gcd(k1, k2)` may not be 1, leaving a small spurious factor in the GCD.
- Stripping cofactors has to guess which small factors are spurious, so it
  emits several candidate moduli.
- Each candidate modulus yields a distinct public key PEM.

So the output is a *set* of candidate public keys. Test each.

## Tool: `rsa_sign2n` / `sig2n` (silentsignal)

Reference implementation:
`https://github.com/silentsignal/rsa_sign2n` (the `CVE-2017-11424` / JWT
"sign to n" tool). Run via Docker on two valid JWTs.

```bash
# TODO: confirm the current image name / build from the repo's Dockerfile.
# Typical invocation shape (verify against the repo README before running):
docker run --rm -it sig2n <JWT_1> <JWT_2>
```

What it emits:

1. One or more **candidate public keys** (PEM / JWK), one per plausible
   factoring of the recovered modulus.
2. For each candidate, often **pre-forged `HS256` tokens** ready to replay.

## Testing the candidates

For each candidate key × each newline variant (see
[Lab 1's trailing-newline note](../../01-lab-exposed-key/README.md#the-trailing-newline-ambiguity-textbook)):

```bash
# TODO: fill <lab-host> and <candidate_token>
curl -i --http1.1 "https://<lab-host>/admin" \
  --cookie "session=<candidate_token>"
```

A candidate that returns the admin page (not 401/302-to-login) is the correct
modulus. Then issue the delete:

```bash
# TODO: fill in and capture the real 302
curl -i --http1.1 "https://<lab-host>/admin/delete?username=carlos" \
  --cookie "session=<working_token>"
```

## TODO checklist for a live run

- [ ] `TODO:` token 1 (RS256)
- [ ] `TODO:` token 2 (RS256, different payload)
- [ ] `TODO:` tool image/version actually used
- [ ] `TODO:` candidate public keys emitted
- [ ] `TODO:` which candidate + newline variant verified
- [ ] `TODO:` captured 302 solve response
