"""Verify that user-supplied Reality handshake server/port pass through verbatim."""
from __future__ import annotations

import unittest

from proto.composer.config_builder import build_client_config, build_server_config


def _vless_reality_inbound(handshake_server: str, handshake_port: int = 443) -> dict:
    return {
        "type": "vless",
        "tag": "vless-tcp-reality",
        "users": [{"uuid": "00000000-0000-0000-0000-000000000000"}],
        "tls": {
            "enabled": True,
            "server_name": handshake_server,
            "reality": {
                "enabled": True,
                "handshake": {"server": handshake_server, "server_port": handshake_port},
                "private_key": "REPLACE-REALITY-PRIV",
                "short_id": ["REPLACE-HEX"],
            },
        },
    }


def _secrets() -> dict:
    return {
        "uuid": "00000000-0000-0000-0000-000000000000",
        "reality_priv": "priv-key-placeholder",
        "reality_pub": "pub-key-placeholder",
        "short_id": "aabbccdd11223344",
    }


class RealityHandshakeTests(unittest.TestCase):
    def test_custom_handshake_server_in_server_config(self) -> None:
        cfg = build_server_config(_vless_reality_inbound("example.org", 8443), _secrets())
        tls = cfg["inbounds"][0]["tls"]
        self.assertEqual(tls["server_name"], "example.org")
        self.assertEqual(tls["reality"]["handshake"]["server"], "example.org")
        self.assertEqual(tls["reality"]["handshake"]["server_port"], 8443)

    def test_custom_handshake_server_mirrored_to_client_config(self) -> None:
        cfg = build_client_config(_vless_reality_inbound("example.org", 8443), _secrets())
        out_tls = cfg["outbounds"][0]["tls"]
        self.assertEqual(out_tls["server_name"], "example.org")
        self.assertIn("reality", out_tls)


if __name__ == "__main__":
    unittest.main()
