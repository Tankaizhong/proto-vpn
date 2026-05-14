"""Verify that user-supplied utls.fingerprint passes through to the client config."""
from __future__ import annotations

import unittest

from proto.composer.config_builder import build_client_config, build_server_config


def _trojan_tls_utls_inbound(fingerprint: str) -> dict:
    return {
        "type": "trojan",
        "tag": "trojan-tcp-tls-utls",
        "users": [{"password": "placeholder"}],
        "tls": {
            "enabled": True,
            "server_name": "vpn.example.com",
            "certificate_path": "/tmp/cert.pem",
            "key_path": "/tmp/key.pem",
            "utls": {
                "enabled": True,
                "fingerprint": fingerprint,
            },
        },
    }


def _secrets() -> dict:
    return {
        "password": "pw",
        "cert_path": "/tmp/cert.pem",
        "key_path": "/tmp/key.pem",
    }


class UtlsFingerprintTests(unittest.TestCase):
    def test_custom_fingerprint_mirrored_to_client_config(self) -> None:
        cfg = build_client_config(_trojan_tls_utls_inbound("firefox"), _secrets())
        out_tls = cfg["outbounds"][0]["tls"]
        self.assertIn("utls", out_tls)
        self.assertEqual(out_tls["utls"]["fingerprint"], "firefox")
        self.assertTrue(out_tls["utls"]["enabled"])

    def test_utls_stripped_from_server_config(self) -> None:
        """Server-side TLS schema does not accept utls — it must be removed."""
        cfg = build_server_config(_trojan_tls_utls_inbound("chrome"), _secrets())
        server_tls = cfg["inbounds"][0]["tls"]
        self.assertNotIn("utls", server_tls)


if __name__ == "__main__":
    unittest.main()
