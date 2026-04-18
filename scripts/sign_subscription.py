#!/usr/bin/env python3
"""CLI: sign a subscription payload with an Ed25519 key.

Usage:
    scripts/sign_subscription.py --key KEY.pem --kid KID --payload payload.json
    scripts/sign_subscription.py --generate-key OUT.pem --kid KID
    scripts/sign_subscription.py --verify TOKEN --pubkey PUB.pem --kid KID

The key file is a PEM-encoded Ed25519 private or public key as produced by
``cryptography`` or ``openssl genpkey -algorithm ed25519``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from proto.bundle import SchemaError, validate_payload
from proto.subscription import (
    Pinset,
    SigningKey,
    SubscriptionError,
    TrustedKey,
    sign_subscription,
    verify_subscription,
)


def load_private(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(f"{path}: not an Ed25519 private key")
    return key


def load_public(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise SystemExit(f"{path}: not an Ed25519 public key")
    return key


def cmd_generate(out_path: Path, kid: str) -> int:
    priv = Ed25519PrivateKey.generate()
    out_path.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    out_path.chmod(0o600)
    pub_path = out_path.with_suffix(out_path.suffix + ".pub")
    pub_path.write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(f"generated: {out_path} (kid={kid}, mode 600)")
    print(f"public:    {pub_path}")
    return 0


def cmd_sign(key_path: Path, kid: str, payload_path: Path, ttl: int) -> int:
    payload = json.loads(payload_path.read_text())
    try:
        validate_payload(payload)
    except SchemaError as exc:
        print(f"payload schema error: {exc}", file=sys.stderr)
        return 2
    signer = SigningKey(kid=kid, private_key=load_private(key_path))
    token = sign_subscription(signer, payload, ttl_seconds=ttl)
    print(token)
    return 0


def cmd_verify(token: str, pub_path: Path, kid: str) -> int:
    pinset = Pinset()
    pinset.add(TrustedKey(kid=kid, public_key=load_public(pub_path)))
    try:
        result = verify_subscription(token, pinset)
    except SubscriptionError as exc:
        print(f"verify failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result.payload, indent=2, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Proto subscription signer / verifier")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("generate", help="Generate an Ed25519 keypair")
    p_gen.add_argument("--out", type=Path, required=True, help="private key output path")
    p_gen.add_argument("--kid", required=True)

    p_sign = sub.add_parser("sign", help="Sign a payload JSON file")
    p_sign.add_argument("--key", type=Path, required=True, help="private key PEM")
    p_sign.add_argument("--kid", required=True)
    p_sign.add_argument("--payload", type=Path, required=True, help="payload JSON file")
    p_sign.add_argument("--ttl", type=int, default=3600, help="exp - iat in seconds")

    p_ver = sub.add_parser("verify", help="Verify a token against a pinned key")
    p_ver.add_argument("token", help="the JWS Compact token")
    p_ver.add_argument("--pubkey", type=Path, required=True, help="public key PEM")
    p_ver.add_argument("--kid", required=True)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "generate":
        return cmd_generate(args.out, args.kid)
    if args.cmd == "sign":
        return cmd_sign(args.key, args.kid, args.payload, args.ttl)
    if args.cmd == "verify":
        return cmd_verify(args.token, args.pubkey, args.kid)
    return 2


if __name__ == "__main__":
    sys.exit(main())
