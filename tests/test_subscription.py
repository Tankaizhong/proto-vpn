"""Tests for proto.subscription — JWS Compact Ed25519 sign/verify."""

from __future__ import annotations

import json
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from proto.subscription import (  # noqa: E402
    BadAlgError,
    BadFormatError,
    BadSignatureError,
    BadVersionError,
    ExpiredError,
    PAYLOAD_VERSION,
    Pinset,
    ReplayError,
    SigningKey,
    UnknownKidError,
    b64url_decode,
    b64url_encode,
    sign_subscription,
    verify_subscription,
)


def _sample_payload() -> dict:
    return {
        "iss": "proto.example.com",
        "sub": "user-123",
        "policy": {"strategy": "hybrid"},
        "endpoints": [
            {"tag": "vless-a", "type": "vless", "host": "a.example.com"},
            {"tag": "hy2-a", "type": "hysteria2", "host": "a.example.com"},
        ],
        "trust": {"pubkey_pinset": ["kid-1"]},
        "next_refresh_after": 1800,
    }


class RoundTripTests(unittest.TestCase):
    def test_sign_and_verify_roundtrip(self) -> None:
        key = SigningKey.generate("kid-1")
        pinset = Pinset()
        pinset.add(key.public())

        token = sign_subscription(key, _sample_payload())
        result = verify_subscription(token, pinset)

        self.assertEqual(result.kid, "kid-1")
        self.assertEqual(result.payload["iss"], "proto.example.com")
        self.assertEqual(result.payload["v"], PAYLOAD_VERSION)
        self.assertIn("iat", result.payload)
        self.assertIn("jti", result.payload)

    def test_three_segment_compact_form(self) -> None:
        key = SigningKey.generate("kid-1")
        token = sign_subscription(key, _sample_payload())
        self.assertEqual(token.count("."), 2)
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(b64url_decode(header_b64))
        self.assertEqual(header["alg"], "EdDSA")
        self.assertEqual(header["kid"], "kid-1")
        self.assertTrue(header_b64 and payload_b64 and sig_b64)


class TamperDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = SigningKey.generate("kid-1")
        self.pinset = Pinset()
        self.pinset.add(self.key.public())
        self.token = sign_subscription(self.key, _sample_payload())

    def test_tampered_payload_fails(self) -> None:
        h, p, s = self.token.split(".")
        tampered_payload = dict(json.loads(b64url_decode(p)))
        tampered_payload["sub"] = "attacker"
        forged = f"{h}.{b64url_encode(json.dumps(tampered_payload).encode())}.{s}"
        with self.assertRaises(BadSignatureError):
            verify_subscription(forged, self.pinset)

    def test_tampered_header_fails(self) -> None:
        h, p, s = self.token.split(".")
        hdr = dict(json.loads(b64url_decode(h)))
        hdr["typ"] = "other"
        forged = f"{b64url_encode(json.dumps(hdr).encode())}.{p}.{s}"
        with self.assertRaises(BadSignatureError):
            verify_subscription(forged, self.pinset)

    def test_bit_flipped_signature_fails(self) -> None:
        h, p, s = self.token.split(".")
        raw = bytearray(b64url_decode(s))
        raw[0] ^= 0x01
        forged = f"{h}.{p}.{b64url_encode(bytes(raw))}"
        with self.assertRaises(BadSignatureError):
            verify_subscription(forged, self.pinset)


class AlgWhitelistTests(unittest.TestCase):
    def test_none_alg_rejected(self) -> None:
        key = SigningKey.generate("kid-1")
        pinset = Pinset()
        pinset.add(key.public())
        token = sign_subscription(key, _sample_payload())
        h, p, s = token.split(".")
        hdr = json.loads(b64url_decode(h))
        hdr["alg"] = "none"
        forged = f"{b64url_encode(json.dumps(hdr).encode())}.{p}.{s}"
        with self.assertRaises(BadAlgError):
            verify_subscription(forged, pinset)

    def test_hs256_alg_rejected(self) -> None:
        key = SigningKey.generate("kid-1")
        pinset = Pinset()
        pinset.add(key.public())
        token = sign_subscription(key, _sample_payload())
        h, p, s = token.split(".")
        hdr = json.loads(b64url_decode(h))
        hdr["alg"] = "HS256"
        forged = f"{b64url_encode(json.dumps(hdr).encode())}.{p}.{s}"
        with self.assertRaises(BadAlgError):
            verify_subscription(forged, pinset)


class KidLookupTests(unittest.TestCase):
    def test_unknown_kid_rejected(self) -> None:
        signer = SigningKey.generate("kid-unknown")
        pinset = Pinset()
        pinset.add(SigningKey.generate("kid-1").public())
        token = sign_subscription(signer, _sample_payload())
        with self.assertRaises(UnknownKidError):
            verify_subscription(token, pinset)

    def test_rotation_two_keys_in_pinset(self) -> None:
        """During rotation both K_old and K_new are in the pinset; both verify."""
        k_old = SigningKey.generate("kid-old")
        k_new = SigningKey.generate("kid-new")
        pinset = Pinset()
        pinset.add(k_old.public())
        pinset.add(k_new.public())

        tok_old = sign_subscription(k_old, _sample_payload())
        tok_new = sign_subscription(k_new, _sample_payload())

        self.assertEqual(verify_subscription(tok_old, pinset).kid, "kid-old")
        self.assertEqual(verify_subscription(tok_new, pinset).kid, "kid-new")


class TimeWindowTests(unittest.TestCase):
    def test_expired_token_rejected(self) -> None:
        key = SigningKey.generate("kid-1")
        pinset = Pinset()
        pinset.add(key.public())
        past = int(time.time()) - 7200
        token = sign_subscription(key, _sample_payload(), now=past, ttl_seconds=3600)
        with self.assertRaises(ExpiredError):
            verify_subscription(token, pinset)

    def test_not_yet_valid_rejected(self) -> None:
        key = SigningKey.generate("kid-1")
        pinset = Pinset()
        pinset.add(key.public())
        future = int(time.time()) + 7200
        token = sign_subscription(key, _sample_payload(), now=future, ttl_seconds=3600)
        with self.assertRaises(ExpiredError):
            verify_subscription(token, pinset)

    def test_clock_skew_allows_slight_past(self) -> None:
        key = SigningKey.generate("kid-1")
        pinset = Pinset()
        pinset.add(key.public())
        now = int(time.time())
        token = sign_subscription(key, _sample_payload(), now=now - 30, ttl_seconds=30)
        verify_subscription(token, pinset, clock_skew=60)


class ReplayTests(unittest.TestCase):
    def test_replay_detection(self) -> None:
        key = SigningKey.generate("kid-1")
        pinset = Pinset()
        pinset.add(key.public())
        token = sign_subscription(key, _sample_payload())

        seen: set[str] = set()
        verify_subscription(token, pinset, seen_jtis=seen)
        with self.assertRaises(ReplayError):
            verify_subscription(token, pinset, seen_jtis=seen)

    def test_different_jtis_accepted(self) -> None:
        key = SigningKey.generate("kid-1")
        pinset = Pinset()
        pinset.add(key.public())
        seen: set[str] = set()
        for _ in range(5):
            verify_subscription(sign_subscription(key, _sample_payload()), pinset, seen_jtis=seen)
        self.assertEqual(len(seen), 5)


class VersionTests(unittest.TestCase):
    def test_unsupported_version_rejected(self) -> None:
        key = SigningKey.generate("kid-1")
        pinset = Pinset()
        pinset.add(key.public())
        payload = _sample_payload() | {"v": 2}
        token = sign_subscription(key, payload)
        with self.assertRaises(BadVersionError):
            verify_subscription(token, pinset)


class MalformedTokenTests(unittest.TestCase):
    def test_wrong_segment_count(self) -> None:
        pinset = Pinset()
        with self.assertRaises(BadFormatError):
            verify_subscription("only.two", pinset)
        with self.assertRaises(BadFormatError):
            verify_subscription("a.b.c.d", pinset)

    def test_non_base64_segment(self) -> None:
        pinset = Pinset()
        with self.assertRaises(BadFormatError):
            verify_subscription("!!!.???.***", pinset)

    def test_non_object_header(self) -> None:
        key = SigningKey.generate("kid-1")
        pinset = Pinset()
        pinset.add(key.public())
        h = b64url_encode(b'"string-not-object"')
        p = b64url_encode(b"{}")
        s = b64url_encode(b"x")
        with self.assertRaises(BadFormatError):
            verify_subscription(f"{h}.{p}.{s}", pinset)


class Base64UrlTests(unittest.TestCase):
    def test_roundtrip_arbitrary_bytes(self) -> None:
        for raw in [b"", b"a", b"ab", b"abc", b"\x00\xff\x7f", bytes(range(256))]:
            self.assertEqual(b64url_decode(b64url_encode(raw)), raw)

    def test_no_padding_in_output(self) -> None:
        self.assertNotIn("=", b64url_encode(b"abc"))
        self.assertNotIn("=", b64url_encode(b"abcd"))


if __name__ == "__main__":
    unittest.main()
