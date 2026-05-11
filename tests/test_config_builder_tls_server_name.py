"""Verify that user-supplied tls.server_name passes through to server/client JSON verbatim."""
from __future__ import annotations

import unittest

from proto.composer.config_builder import build_client_config, build_server_config


def _trojan_tls_inbound(server_name: str) -> dict:
    return {
        "type": "trojan",
        "tag": "trojan-tcp-tls",
        "users": [{"password": "placeholder"}],
        "tls": {
            "enabled": True,
            "server_name": server_name,
            "certificate_path": "/tmp/cert.pem",
            "key_path": "/tmp/key.pem",
        },
    }


def _secrets() -> dict:
    return {
        "password": "pw",
        "cert_path": "/tmp/cert.pem",
        "key_path": "/tmp/key.pem",
    }


class TlsServerNameTests(unittest.TestCase):
    def test_custom_server_name_preserved_in_server_config(self) -> None:
        cfg = build_server_config(_trojan_tls_inbound("my.custom.domain.com"), _secrets())
        tls = cfg["inbounds"][0]["tls"]
        self.assertEqual(tls["server_name"], "my.custom.domain.com")

    def test_custom_server_name_mirrored_to_client_config(self) -> None:
        cfg = build_client_config(_trojan_tls_inbound("my.custom.domain.com"), _secrets())
        out_tls = cfg["outbounds"][0]["tls"]
        self.assertEqual(out_tls["server_name"], "my.custom.domain.com")


if __name__ == "__main__":
    unittest.main()
