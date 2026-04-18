"""Proto subscription JWS Compact signer and verifier.

Implements the wire format defined in docs/subscription-format.md:
  - JWS Compact serialization: base64url(protected).base64url(payload).base64url(signature)
  - Fixed alg=EdDSA (Ed25519); any other alg is rejected on verify.
  - Payload v=1 with iss/sub/iat/nbf/exp/jti/endpoints/trust fields.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ALG = "EdDSA"
TYP = "proto-subscription+jws"
PAYLOAD_VERSION = 1
ALLOWED_ALGS = frozenset({ALG})


class SubscriptionError(Exception):
    """Base class for all subscription errors."""


class BadFormatError(SubscriptionError):
    """Token is not valid JWS Compact form or contains malformed JSON."""


class BadAlgError(SubscriptionError):
    """Token header declares an algorithm outside the allow-list."""


class UnknownKidError(SubscriptionError):
    """Token kid is not present in the trusted pinset."""


class BadSignatureError(SubscriptionError):
    """Signature failed to verify with the pinned key."""


class ExpiredError(SubscriptionError):
    """Token is past its exp, or has not yet reached its nbf."""


class ReplayError(SubscriptionError):
    """Token jti was already consumed — replay detected."""


class BadVersionError(SubscriptionError):
    """Token payload version is not supported by this client."""


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


@dataclass
class SigningKey:
    """An Ed25519 signing key bound to a kid."""

    kid: str
    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls, kid: str) -> "SigningKey":
        return cls(kid=kid, private_key=Ed25519PrivateKey.generate())

    def public(self) -> "TrustedKey":
        return TrustedKey(kid=self.kid, public_key=self.private_key.public_key())


@dataclass
class TrustedKey:
    """A pinned Ed25519 verification key."""

    kid: str
    public_key: Ed25519PublicKey


@dataclass
class Pinset:
    """Append-only set of trusted keys — current + next during rotation."""

    keys: dict[str, TrustedKey] = field(default_factory=dict)

    def add(self, key: TrustedKey) -> None:
        self.keys[key.kid] = key

    def get(self, kid: str) -> TrustedKey | None:
        return self.keys.get(kid)

    def remove(self, kid: str) -> None:
        self.keys.pop(kid, None)

    def kids(self) -> list[str]:
        return list(self.keys.keys())


def sign_subscription(
    key: SigningKey,
    payload: dict[str, Any],
    *,
    ttl_seconds: int = 3600,
    now: int | None = None,
) -> str:
    """Sign a subscription payload and return a JWS Compact token.

    If the payload omits v/iat/nbf/exp/jti they are filled with defaults
    matching the spec. `ttl_seconds` controls exp relative to iat.
    """
    now = int(time.time()) if now is None else int(now)
    payload = dict(payload)
    payload.setdefault("v", PAYLOAD_VERSION)
    payload.setdefault("iat", now)
    payload.setdefault("nbf", now)
    payload.setdefault("exp", now + ttl_seconds)
    payload.setdefault("jti", str(uuid.uuid4()))

    header = {"alg": ALG, "typ": TYP, "kid": key.kid}
    header_b64 = b64url_encode(_canonical_json(header))
    payload_b64 = b64url_encode(_canonical_json(payload))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = key.private_key.sign(signing_input)
    sig_b64 = b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


@dataclass
class VerifyResult:
    header: dict[str, Any]
    payload: dict[str, Any]
    kid: str


def verify_subscription(
    token: str,
    pinset: Pinset,
    *,
    seen_jtis: set[str] | None = None,
    now: int | None = None,
    clock_skew: int = 60,
) -> VerifyResult:
    """Verify a subscription token per the spec's 8-step procedure.

    Steps (numbered in comments):
      1. Parse three segments
      2. alg must be in the allow-list (EdDSA only)
      3. Look up kid in the pinset
      4. Verify Ed25519 signature over "header_b64.payload_b64"
      5. nbf/exp time window with clock skew
      6. jti replay check (if seen_jtis provided)
      7. kid consistency — header kid equals the verifying key's kid
      8. Payload version check

    Raises a SubscriptionError subclass on failure.
    """
    # Step 1 — parse segments
    segments = token.split(".")
    if len(segments) != 3:
        raise BadFormatError("token must have exactly 3 segments")
    header_b64, payload_b64, sig_b64 = segments
    try:
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
        signature = b64url_decode(sig_b64)
    except (ValueError, json.JSONDecodeError) as exc:
        raise BadFormatError(f"malformed segment: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise BadFormatError("header and payload must be JSON objects")

    # Step 2 — alg whitelist
    alg = header.get("alg")
    if alg not in ALLOWED_ALGS:
        raise BadAlgError(f"alg {alg!r} not allowed")

    # Step 3 — kid lookup
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise BadFormatError("header kid missing or not a string")
    trusted = pinset.get(kid)
    if trusted is None:
        raise UnknownKidError(f"kid {kid!r} not in pinset")

    # Step 4 — Ed25519 verify
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        trusted.public_key.verify(signature, signing_input)
    except InvalidSignature as exc:
        raise BadSignatureError("signature verification failed") from exc

    # Step 5 — time window
    now = int(time.time()) if now is None else int(now)
    nbf = payload.get("nbf")
    exp = payload.get("exp")
    if not isinstance(nbf, int) or not isinstance(exp, int):
        raise BadFormatError("nbf and exp must be integers")
    if now + clock_skew < nbf:
        raise ExpiredError(f"token not yet valid (nbf={nbf}, now={now})")
    if now - clock_skew >= exp:
        raise ExpiredError(f"token expired (exp={exp}, now={now})")

    # Step 6 — replay check
    jti = payload.get("jti")
    if seen_jtis is not None:
        if not isinstance(jti, str) or not jti:
            raise BadFormatError("payload jti missing for replay-protected verify")
        if jti in seen_jtis:
            raise ReplayError(f"jti {jti!r} already seen")
        seen_jtis.add(jti)

    # Step 7 — kid consistency (header kid already equals trusted.kid via lookup,
    # but double-check in case pinset ever indexes by alias)
    if trusted.kid != kid:
        raise BadFormatError("kid mismatch between header and pinset entry")

    # Step 8 — version
    if payload.get("v") != PAYLOAD_VERSION:
        raise BadVersionError(f"unsupported payload version: {payload.get('v')!r}")

    return VerifyResult(header=header, payload=payload, kid=kid)


def _canonical_json(obj: Any) -> bytes:
    """Stable JSON encoding — sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


__all__ = [
    "ALG",
    "TYP",
    "PAYLOAD_VERSION",
    "SubscriptionError",
    "BadFormatError",
    "BadAlgError",
    "UnknownKidError",
    "BadSignatureError",
    "ExpiredError",
    "ReplayError",
    "BadVersionError",
    "SigningKey",
    "TrustedKey",
    "Pinset",
    "VerifyResult",
    "sign_subscription",
    "verify_subscription",
    "b64url_encode",
    "b64url_decode",
]
