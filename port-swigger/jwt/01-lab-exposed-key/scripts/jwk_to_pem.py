#!/usr/bin/env python3
"""Convert an RSA JWK (n, e) into a SubjectPublicKeyInfo PEM.

Reads a JWK JSON object from a file or stdin and writes the reconstructed
RSA public key as PEM. Run isolated so a planted module cannot be imported:

    python3 -I jwk_to_pem.py jwks.json            # if the file is a single JWK
    python3 -I jwk_to_pem.py jwks.json --index 0  # if it is a {"keys":[...]} set
    cat jwks.json | python3 -I jwk_to_pem.py -

Requires: pip install cryptography
"""
import argparse
import base64
import json
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def b64url_to_int(value: str) -> int:
    """Decode a base64url-encoded big-endian unsigned integer (JWK field)."""
    padding = "=" * (-len(value) % 4)
    raw = base64.urlsafe_b64decode(value + padding)
    return int.from_bytes(raw, "big")


def jwk_to_pem(jwk: dict) -> bytes:
    if jwk.get("kty") != "RSA":
        raise ValueError(f"expected kty=RSA, got {jwk.get('kty')!r}")
    n = b64url_to_int(jwk["n"])
    e = b64url_to_int(jwk["e"])
    public_key = rsa.RSAPublicNumbers(e, n).public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="JWK (n,e) -> PEM")
    parser.add_argument("jwk_file", help="path to JWK JSON, or - for stdin")
    parser.add_argument("--index", type=int, default=None,
                        help="index into a {'keys':[...]} JWK Set")
    parser.add_argument("-o", "--out", default=None,
                        help="output PEM path (default: stdout)")
    args = parser.parse_args()

    text = sys.stdin.read() if args.jwk_file == "-" else open(args.jwk_file).read()
    data = json.loads(text)

    if "keys" in data:
        idx = args.index if args.index is not None else 0
        jwk = data["keys"][idx]
    else:
        jwk = data

    pem = jwk_to_pem(jwk)

    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(pem)
        sys.stderr.write(f"wrote {args.out}\n")
    else:
        sys.stdout.buffer.write(pem)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
