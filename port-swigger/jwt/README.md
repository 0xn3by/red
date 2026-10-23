# JWT Algorithm Confusion — two PortSwigger labs, documented

**The bug in one line:** a JWT library picks its verification algorithm from
the attacker-controlled `alg` header, so flipping `RS256` to `HS256` makes the
server HMAC with its own public key — a value the whole internet can read.

This repo documents two [PortSwigger Web Security Academy](https://portswigger.net/web-security/jwt)
labs on JWT authentication bypass via algorithm confusion. It is a learning
artifact and a portfolio piece: accurate, reproducible, and honest about what
was captured versus what is explained.

> These are intentionally vulnerable training targets. Everything here is
> framed as defensive education. The [remediation](03-defense/remediation.md)
> is a first-class section, not an afterthought.

## Evidence honesty

Claims are tagged so you can tell verified facts from textbook theory:

| Tag | Meaning |
|-----|---------|
| `[Verified]` | Captured or reproduced in this repo. |
| `[Textbook]` | Standard, established crypto/fact. |
| `[Unverified]` | Plausible but not confirmed here. |

Specifics worth stating up front:

- **Lab 1** is backed by real captured artifacts. The two forged tokens in
  [`evidence/`](01-lab-exposed-key/evidence/) were reproduced byte-for-byte
  from `key.pem` during this write-up (`[Verified]`): token A = HMAC with the
  trailing newline, token B = HMAC without it.
- **The Lab 1 solve response (302) was not captured.** The walkthrough leaves a
  `TODO:` at the solve step for you to paste your own 302 after re-running the
  delete. No fake success transcript is shown.
- **Lab 2 was not performed live.** It is documented as a *technique
  walkthrough* (method, not a captured run); every concrete Lab 2 value is a
  `TODO:`.
- The lab hosts are **expired, dead PortSwigger instances**, kept only for
  authenticity.

## Repo map

```
.
├── README.md                          # You are here
├── 00-concept/
│   └── algorithm-confusion.md         # Root cause: RS256 vs HS256, why the public key becomes the HMAC secret
├── 01-lab-exposed-key/
│   ├── README.md                      # Lab 1 full walkthrough (key exposed at /jwks.json)
│   ├── evidence/                      # Real captured artifacts (jwks.json, key.pem, tokens, responses)
│   │   └── screenshots/               # Two real Burp captures (place PNGs here)
│   └── scripts/
│       ├── jwk_to_pem.py              # JWK (n,e) -> PEM
│       └── forge_hs256.py             # HMAC-sign a forged token with the PEM bytes
├── 02-lab-no-exposed-key/
│   ├── README.md                      # Lab 2 technique walkthrough (recover modulus via sig2n GCD)
│   └── scripts/
│       └── derive_modulus_notes.md    # The s^e - m GCD method and how rsa_sign2n works
├── 03-defense/
│   └── remediation.md                 # How real systems prevent this: allowlisting, key binding
├── 04-debugging-notes/
│   └── five-walls.md                  # The five real failure modes hit while solving
└── demo/
    └── vuln_vs_safe.py                # Minimal PyJWT demo: forged HS256 accepted vs rejected
```

## Where to start

- New to the attack? Read [`00-concept/algorithm-confusion.md`](00-concept/algorithm-confusion.md).
- Want to see it fail safely on your own machine? Run
  [`demo/vuln_vs_safe.py`](demo/vuln_vs_safe.py) (`pip install pyjwt cryptography`).
- Want the full lab? [`01-lab-exposed-key/README.md`](01-lab-exposed-key/README.md).
- Want the hard variant (no exposed key)? [`02-lab-no-exposed-key/README.md`](02-lab-no-exposed-key/README.md).
- Want the war stories? [`04-debugging-notes/five-walls.md`](04-debugging-notes/five-walls.md).
- Want to fix it? [`03-defense/remediation.md`](03-defense/remediation.md).

## Mental model

> Public key means public. The moment a server HMACs with it, the secret is
> something the whole internet can read.
